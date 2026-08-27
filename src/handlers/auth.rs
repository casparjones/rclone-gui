// Password hashing, password policy and session handling.
//
// The module-wide `#![allow(dead_code)]` that stood here is gone: it was there
// because the primitives had no callers yet, and `handlers::auth_web` is now
// that caller. What is left unused are two functions the user-management ticket
// will call, and those carry a narrow `#[allow(dead_code)]` each — a blanket
// allow would hide the next genuinely dead function in a 2000-line module.

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{
    rand_core::{OsRng, RngCore},
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Sqlite};
use subtle::ConstantTimeEq;

use crate::database::{self, Session, User};

// ---------------------------------------------------------------------------
// Argon2id parameters
//
// Source: OWASP Password Storage Cheat Sheet, "Argon2id" section. It lists
// several equivalent configurations and recommends, when Argon2id is used with
// a low degree of parallelism, m=19456 (19 MiB), t=2, p=1 as the minimum. That
// is the configuration chosen here.
//
// Why this one and not one of the higher-memory variants:
//   * The server is a small self-hosted Rust service that also spawns rclone
//     subprocesses; it may well run on a NAS or a Raspberry Pi. 19 MiB per
//     concurrent login keeps the peak memory bounded and predictable even if
//     several logins arrive at once, while still being far above what a GPU
//     attacker handles cheaply.
//   * p=1 because the axum handler that will call this runs inside a tokio
//     worker; spending several threads per password verification would compete
//     with request handling for no security gain (OWASP explicitly allows p=1
//     with the compensating memory value above).
//   * t=2 is the iteration count OWASP pairs with m=19456. Iterations are the
//     cheap knob for an attacker with lots of memory, so the memory cost is the
//     primary defence here and the iteration count follows the recommendation
//     rather than being tuned down.
//
// Argon2id (not Argon2i, not Argon2d) is the hybrid variant and the one
// recommended by both RFC 9106 and OWASP for password storage: it resists
// side-channel attacks in its first pass and GPU cracking in the later ones.
//
// Changing these constants does NOT invalidate existing hashes: the parameters
// are encoded in the PHC string, and `verify_password` reads them back from the
// stored hash. New hashes simply use the new values.
// ---------------------------------------------------------------------------

/// Memory cost in KiB (19 MiB), per OWASP's minimum for Argon2id with p=1.
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
/// Iterations (time cost).
const ARGON2_ITERATIONS: u32 = 2;
/// Degree of parallelism.
const ARGON2_PARALLELISM: u32 = 1;

// ---------------------------------------------------------------------------
// Upper bounds for *stored* cost parameters
//
// `verify_password` takes the cost parameters from the stored PHC string, which
// is what makes old hashes keep verifying after the constants above are raised.
// That also makes those parameters untrusted input: a row written by a bad
// backup restore, a corrupt page or anyone with write access to `data/tasks.db`
// can name a memory cost of up to 256 GiB (the maximum `Params` accepts).
// Argon2 then really tries to allocate it, and a failed allocation of that size
// is an `abort`, not a panic — neither `catch_unwind` nor `spawn_blocking`
// catches it, the whole server process dies. Measured: `m=268435455` →
// `memory allocation of 274877902848 bytes failed`, SIGABRT; `m=2097152`
// (2 GiB) → `false`, but only after really occupying 2.0 GiB (VmHWM
// 2 101 800 kB) and 1.6 s of CPU.
//
// So the parameters are checked before they are handed to Argon2. Preventing
// the abort is only half the job, though: the first version of these bounds
// (m<=256 MiB, t<=16, p<=16) let a stored hash cost **27.7 s** per verification
// — measured — while the comment here claimed "a few seconds". That is not a
// dead process, but it is still a weapon: anyone who can write one row into
// `data/tasks.db` can make every login attempt for that account occupy a
// blocking thread for half a minute.
//
// Argon2's total work is `m` x `t` (lanes do not add work, they only split it),
// so the ceiling on *time* is the ceiling on that product. The bounds below are
// picked to keep that product roughly a quarter of what it was, while staying
// generous in the direction we might grow:
//
//   * memory 128 MiB — 6.7x today's 19 MiB and ~2.8x the *largest* configuration
//     OWASP lists (m=47104). That leaves room for two more doublings of
//     `ARGON2_MEMORY_KIB` without locking out a single existing user, while a
//     peak of 128 MiB is something this server can survive even if it happens
//     on every login attempt at once. Memory is the knob that actually costs an
//     attacker, so this is the one to keep headroom on.
//   * iterations 6 — 3x today's t=2, and above the t=5 where OWASP's variants
//     stop, so no recommended configuration is out of reach.
//   * parallelism 8 — 8x today's p=1. Lanes do not add total work, so this one
//     is cheap to be generous with; it is bounded only so a hash cannot ask for
//     an absurd lane count.
//
// Worst case that still passes the check is therefore m=131072, t=6, p=8.
// Measured on the development machine, one verification of a hash carrying
// exactly those parameters:
//
//   * release build (what actually runs):  **0.28 s**
//   * debug build (what `cargo test` runs): **5.30 s**
//
// Down from the 27.7 s the previous bounds allowed. The measurement lives in
// `worst_accepted_cost_parameters_stay_under_ten_seconds`, which is `#[ignore]`d
// because it is a measurement and not a unit test — it fails above 10 s, and the
// 10 s is chosen so the *debug* figure above still has room; the number that
// matters operationally is the release one. Run it with
// `cargo test --release -- --ignored --nocapture` after touching these bounds.
//
// Everything above the bounds is refused outright: no allocation, no
// verification, `false`.
//
// These are limits on what is *accepted*, never on what is *produced*: raising
// the constants above beyond these bounds would be a bug, and the test
// `own_parameters_are_within_the_verification_limits` says so.
// ---------------------------------------------------------------------------

/// Largest memory cost (KiB) accepted from a stored hash: 128 MiB.
const MAX_VERIFY_MEMORY_KIB: u32 = 128 * 1024;
/// Largest iteration count accepted from a stored hash.
const MAX_VERIFY_ITERATIONS: u32 = 6;
/// Largest degree of parallelism accepted from a stored hash.
const MAX_VERIFY_PARALLELISM: u32 = 8;

/// Producing hashes the verifier would then refuse would lock every user out on
/// their next login, and a limit above ~1 GiB would defeat the purpose. Both
/// are checked at compile time, so raising a constant carelessly does not build.
const _: () = assert!(ARGON2_MEMORY_KIB <= MAX_VERIFY_MEMORY_KIB);
const _: () = assert!(ARGON2_ITERATIONS <= MAX_VERIFY_ITERATIONS);
const _: () = assert!(ARGON2_PARALLELISM <= MAX_VERIFY_PARALLELISM);
const _: () = assert!(MAX_VERIFY_MEMORY_KIB <= 1024 * 1024);
/// Room left to grow. A cap set to exactly today's memory cost would satisfy the
/// assertion above while making the next parameter bump impossible without
/// locking every existing user out, so the cap must allow at least one doubling.
const _: () = assert!(ARGON2_MEMORY_KIB * 2 <= MAX_VERIFY_MEMORY_KIB);

// ---------------------------------------------------------------------------
// Password policy
// ---------------------------------------------------------------------------

/// Minimum password length in characters.
///
/// NIST SP 800-63B requires at least 8; OWASP recommends going beyond that and
/// dropping composition rules (no "must contain a digit") in exchange. 12 is
/// the value used here: this is a self-hosted tool whose users pick their own
/// password once, so a slightly longer minimum costs little.
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Upper bound, to keep a hostile client from making the server hash megabytes.
/// Argon2 itself has no relevant length limit; this is a denial-of-service
/// guard, not a security property of the hash.
pub const MAX_PASSWORD_LENGTH: usize = 1024;

/// Obviously weak passwords that are rejected outright.
///
/// This is deliberately *not* a full breached-password corpus (that would be a
/// multi-hundred-megabyte dataset and a ticket of its own). It is the short
/// head of the well-known "most common passwords" lists — the entries that show
/// up in every credential-stuffing wordlist — plus terms specific to this
/// application, which is exactly what a bored attacker tries first. Matching is
/// case-insensitive and ignores surrounding whitespace.
const WEAK_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "passw0rd",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "12345678910",
    // The bare row stems. These matter more than the long variants below,
    // because `qwerty` is what people *prefix* — `qwerty123456` was reported as
    // slipping through precisely because only `qwertyuiop` was listed.
    "qwerty",
    "qwertz",
    "azerty",
    "asdfgh",
    "asdfghjkl",
    "zxcvbn",
    "zxcvbnm",
    "yxcvbn",
    "qwerty123",
    "qwerty1234",
    "qwertyui",
    "qwertyuiop",
    "qwertzuiop",
    "azertyuiop",
    "iloveyou",
    "letmein",
    "letmein123",
    "welcome",
    "welcome123",
    "admin",
    "administrator",
    "adminadmin",
    "admin1234",
    "administrator1",
    "changeme",
    "changeme123",
    "secret",
    "secret123",
    "superman",
    "sunshine",
    "princess",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "trustno1",
    "starwars",
    "whatever",
    "abc123456",
    "0123456789",
    "1qaz2wsx3edc",
    "zaq12wsx",
    // Application specific — the first thing anyone would try here.
    "rclone",
    "rclonerclone",
    "rclone123",
    "rclonegui",
    "rclone-gui",
    "syncsync",
    "backupbackup",
];

/// Why a password was rejected. Carries no copy of the password itself, so it
/// is safe to log and to return to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordPolicyError {
    /// Shorter than [`MIN_PASSWORD_LENGTH`].
    TooShort { min: usize },
    /// Longer than [`MAX_PASSWORD_LENGTH`].
    TooLong { max: usize },
    /// Only whitespace, or empty after trimming.
    Blank,
    /// On a list of obviously weak passwords, or a trivial pattern.
    TooCommon,
}

impl std::fmt::Display for PasswordPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordPolicyError::TooShort { min } => {
                write!(f, "Password must be at least {min} characters long")
            }
            PasswordPolicyError::TooLong { max } => {
                write!(f, "Password must be at most {max} characters long")
            }
            PasswordPolicyError::Blank => write!(f, "Password must not be blank"),
            // Read on a terminal as often as in the browser (the CLI password
            // reset uses the same validation), so it is a complete sentence,
            // names the reason and says what to do instead — without hinting at
            // which pattern matched, which would help nobody but a guesser.
            PasswordPolicyError::TooCommon => write!(
                f,
                "Password is too common or follows an obvious pattern \
                 (a keyboard walk, a counting sequence or a repeated block). \
                 Choose a longer passphrase of unrelated words instead."
            ),
        }
    }
}

impl std::error::Error for PasswordPolicyError {}

/// Check a candidate password against the policy.
///
/// Called before [`hash_password`] whenever a password is *set* (registration,
/// password change, admin reset). It is deliberately **not** called on login:
/// tightening the policy later must not lock out existing accounts, and the
/// rejection reason must not leak anything about a stored password.
pub fn validate_password(password: &str) -> std::result::Result<(), PasswordPolicyError> {
    if password.trim().is_empty() {
        return Err(PasswordPolicyError::Blank);
    }

    // Count characters, not bytes: a 12-character non-ASCII password is not
    // short just because it encodes to more than 12 bytes.
    let length = password.chars().count();

    // Length ceiling first, so nothing below has to walk a hostile megabyte.
    if length > MAX_PASSWORD_LENGTH {
        return Err(PasswordPolicyError::TooLong {
            max: MAX_PASSWORD_LENGTH,
        });
    }

    // Weakness before the minimum length: "password123" is eleven characters,
    // and telling the user to add one more would be actively bad advice.
    if is_weak_password(password) {
        return Err(PasswordPolicyError::TooCommon);
    }

    if length < MIN_PASSWORD_LENGTH {
        return Err(PasswordPolicyError::TooShort {
            min: MIN_PASSWORD_LENGTH,
        });
    }

    Ok(())
}

/// Keyboard walks, written out as the keyboard is traversed.
///
/// A password (or a segment of one, see [`is_weak_segment`]) is compared against
/// these and against their reverse, so `qwertyuiopas` — row one continued into
/// row two — and `poiuytrewq` are both caught. Only layouts that actually occur
/// here are listed: QWERTY, the German QWERTZ and the French AZERTY.
///
/// The last four entries are the *vertical* traversals, which the first version
/// of this list missed entirely: `qazwsxedcrfv` and `1q2w3e4r5t6y` are the two
/// shapes people actually type when they walk down the columns instead of along
/// the rows, and both were reported as accepted.
const KEYBOARD_ROWS: &[&str] = &[
    // Horizontal, row after row.
    "qwertyuiopasdfghjklzxcvbnm",
    "qwertzuiopasdfghjklyxcvbnm",
    "azertyuiopqsdfghjklmwxcvbn",
    "1234567890",
    // Vertical: each column top-to-bottom, columns left to right
    // (`qaz` `wsx` `edc` ...), for QWERTY and for QWERTZ.
    "qazwsxedcrfvtgbyhnujmikolp",
    "qaywsxedcrfvtgbzhnujmikolp",
    // The same columns, but starting on the number row — the `1qaz2wsx` shape.
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
    // Digit/letter zigzag across the top two rows: `1q2w3e4r`.
    "1q2w3e4r5t6y7u8i9o0p",
];

/// Shortest keyboard walk that counts as weak. Below this, ordinary words start
/// to match by accident ("as", "op").
const MIN_KEYBOARD_WALK: usize = 6;

/// Whether `password` is obviously weak.
///
/// The checks, in order of cost:
///   1. a known-weak word: exact match against [`WEAK_PASSWORDS`], the same with
///      digits appended (`password2024`), and either of those after undoing the
///      usual leetspeak substitutions (`P@ssw0rd` → `password`);
///   2. a single repeated character (`aaaaaaaaaaaa`) or a near-straight run of
///      consecutive characters (`abcdefghijkl`, `123456789012`);
///   3. a walk along the keyboard, horizontal or vertical, forwards or
///      backwards (`qwertyuiopas`, `qazwsxedcrfv`);
///   4. a repeated block (`abcabcabcabc`);
///   5. the same three checks again on the password with runs of identical
///      characters collapsed, which is what turns `112233445566` into the run
///      `123456`;
///   6. finally, whether the whole password is *assembled* from pieces of the
///      above — `qwerty123456` is a keyboard walk followed by a digit run, and
///      neither half covers the whole string, so nothing before this catches it.
///
/// Deliberately not attempted: completeness. A policy cannot replace a breach
/// corpus. The goal is the obvious patterns, and the property that matters more
/// than coverage is the absence of false positives — see the test
/// `policy_accepts_reasonable_passwords`.
fn is_weak_password(password: &str) -> bool {
    let normalized = password.trim().to_lowercase();

    if matches_weak_word(&normalized)
        || is_character_run(&normalized)
        || is_keyboard_walk(&normalized)
        || is_block_repetition(&normalized)
    {
        return true;
    }

    // `112233445566` and `aabbccddeeff` are runs wearing a disguise: collapse
    // the doubled characters and the run underneath shows.
    let collapsed = collapse_repeats(&normalized);
    if collapsed != normalized
        && (matches_weak_word(&collapsed)
            || is_character_run(&collapsed)
            || is_keyboard_walk(&collapsed)
            || is_block_repetition(&collapsed))
    {
        return true;
    }

    is_built_from_weak_segments(&normalized)
}

/// Leetspeak substitutions, in the direction that undoes them.
///
/// Only the unambiguous, widely used ones. `1` maps to `i` rather than `l`
/// because `passw1rd`-style leet is far rarer than `1` for `i`; the list is
/// applied to whole-word comparisons only, so a wrong guess here costs a missed
/// detection, never a false positive on a legitimate password.
const LEET_SUBSTITUTIONS: &[(char, char)] = &[
    ('@', 'a'),
    ('4', 'a'),
    ('8', 'b'),
    ('(', 'c'),
    ('3', 'e'),
    ('6', 'g'),
    ('9', 'g'),
    ('1', 'i'),
    ('!', 'i'),
    ('|', 'l'),
    ('0', 'o'),
    ('5', 's'),
    ('$', 's'),
    ('7', 't'),
    ('+', 't'),
    ('2', 'z'),
];

/// Undo the substitutions above. Characters not in the table are kept as they
/// are, so an already-plain word comes back unchanged.
fn unleet(normalized: &str) -> String {
    normalized
        .chars()
        .map(|c| {
            LEET_SUBSTITUTIONS
                .iter()
                .find_map(|(from, to)| (*from == c).then_some(*to))
                .unwrap_or(c)
        })
        .collect()
}

/// Whether `normalized` is a [`WEAK_PASSWORDS`] entry, possibly with trailing
/// digits and/or leetspeak on top.
///
/// The trailing digits are stripped *before* the leet substitution is applied,
/// because otherwise the appended year would be de-leeted too and
/// `p@ssw0rd1234` would turn into `passwordizea` instead of `password`.
fn matches_weak_word(normalized: &str) -> bool {
    let stem = normalized.trim_end_matches(|c: char| c.is_ascii_digit());

    for candidate in [normalized, stem] {
        if candidate.len() < 4 {
            continue;
        }
        if WEAK_PASSWORDS.contains(&candidate) {
            return true;
        }
        let plain = unleet(candidate);
        if plain != candidate && WEAK_PASSWORDS.contains(&plain.as_str()) {
            return true;
        }
    }

    false
}

/// Collapse runs of the same character to a single one: `112233` → `123`.
fn collapse_repeats(normalized: &str) -> String {
    let mut out = String::with_capacity(normalized.len());
    for c in normalized.chars() {
        if !out.ends_with(c) {
            out.push(c);
        }
    }
    out
}

/// Whether `normalized` is one block repeated at least three times:
/// `abcabcabcabc`, `123123123`, `xyxyxyxyxy`.
///
/// Three repetitions, not two: a password built from two halves is a common
/// enough shape in legitimate passphrases ("berlinberlin" is weak, but
/// "sommerregen" style halves are not reliably distinguishable), while three or
/// more identical blocks is only ever padding.
fn is_block_repetition(normalized: &str) -> bool {
    let chars: Vec<char> = normalized.chars().collect();
    let length = chars.len();
    if length < 6 {
        return false;
    }

    (1..=length / 3).any(|period| {
        length.is_multiple_of(period) && chars.chunks(period).all(|chunk| chunk == &chars[..period])
    })
}

/// Shortest piece that counts as a weak building block in
/// [`is_built_from_weak_segments`].
///
/// Four, not three: three-character alphabetical runs (`stu`, `hij`) occur
/// inside ordinary words often enough that a threshold of three would start
/// rejecting real passphrases, and the one pattern that needs three-character
/// blocks — `abcabcabcabc` — is caught by [`is_block_repetition`] instead.
const MIN_WEAK_SEGMENT: usize = 4;

/// Longest piece considered. The longest [`KEYBOARD_ROWS`] entry is 36
/// characters, so nothing above that can be a keyboard walk, and this keeps the
/// quadratic scan below bounded.
const MAX_WEAK_SEGMENT: usize = 40;

/// Passwords longer than this are not segmented at all. The scan is quadratic
/// in the password length, [`MAX_PASSWORD_LENGTH`] is 1024, and a 128-character
/// password that is *entirely* built from keyboard walks is not the case this
/// check exists for.
const MAX_SEGMENTED_LENGTH: usize = 128;

/// Whether `normalized` is essentially nothing but weak building blocks glued
/// together.
///
/// This is the check that catches `qwerty123456`, `1234567890qw` and
/// `0987654321ab`: each of them is a keyboard walk or a digit run plus a short
/// remainder, and every check above insists on covering the *whole* password.
///
/// The scan is greedy from the left, always taking the longest weak segment that
/// starts at the current position; anything that does not start a segment counts
/// as one uncovered character. A password is weak if almost all of it is covered
/// (at most two uncovered characters, or a fifth of its length for longer ones)
/// by at most a handful of segments. Requiring a *small* number of segments
/// matters: a long passphrase will accidentally contain the odd four-character
/// keyboard substring, but never enough of them, back to back, to tile itself.
fn is_built_from_weak_segments(normalized: &str) -> bool {
    let chars: Vec<char> = normalized.chars().collect();
    let length = chars.len();
    if !(MIN_WEAK_SEGMENT * 2..=MAX_SEGMENTED_LENGTH).contains(&length) {
        return false;
    }

    let mut position = 0;
    let mut segments = 0usize;
    let mut uncovered = 0usize;

    while position < length {
        let longest = (position + MIN_WEAK_SEGMENT..=length.min(position + MAX_WEAK_SEGMENT))
            .rev()
            .find(|&end| is_weak_segment(&chars[position..end]));

        match longest {
            Some(end) => {
                segments += 1;
                position = end;
            }
            None => {
                uncovered += 1;
                position += 1;
            }
        }
    }

    let tolerated = std::cmp::max(2, length / 5);
    segments > 0 && segments <= 5 && uncovered <= tolerated
}

/// Whether a single slice is one of the weak building blocks: a known-weak word,
/// a strictly straight run, or a keyboard walk.
///
/// The run test here is strict (every step exactly +1, -1 or 0), unlike
/// [`is_character_run`], which tolerates a few irregular steps. Tolerance is
/// right when judging a whole password and wrong here, where a sloppy match
/// would let arbitrary text count as "covered".
fn is_weak_segment(segment: &[char]) -> bool {
    debug_assert!(segment.len() >= MIN_WEAK_SEGMENT);

    let ascending = segment
        .windows(2)
        .all(|w| (w[1] as u32).checked_sub(w[0] as u32) == Some(1));
    let descending = segment
        .windows(2)
        .all(|w| (w[0] as u32).checked_sub(w[1] as u32) == Some(1));
    let identical = segment.windows(2).all(|w| w[0] == w[1]);
    if ascending || descending || identical {
        return true;
    }

    let text: String = segment.iter().collect();
    if WEAK_PASSWORDS.contains(&text.as_str()) {
        return true;
    }

    contains_keyboard_walk(&text)
}

/// Whether `text` appears, forwards or backwards, inside one of the
/// [`KEYBOARD_ROWS`].
fn contains_keyboard_walk(text: &str) -> bool {
    // Only single-byte input can be a keyboard walk; this also keeps the
    // substring search on character boundaries.
    if !text.is_ascii() {
        return false;
    }

    let reversed: String = text.chars().rev().collect();
    KEYBOARD_ROWS
        .iter()
        .any(|row| row.contains(text) || row.contains(reversed.as_str()))
}

/// A single repeated character, or an essentially straight ascending or
/// descending run.
///
/// "Essentially" is the point: an earlier version demanded that *every* step be
/// exactly +1, so `123456789012` slipped through — the single `9`→`0` wrap was
/// enough to make the whole password look irregular. A small budget of
/// off-by-anything steps is allowed instead: one, plus one more per six steps.
/// That still needs almost the entire password to be a run, so a real password
/// with a stray `xyz` in it is nowhere near the threshold.
fn is_character_run(normalized: &str) -> bool {
    let chars: Vec<char> = normalized.chars().collect();
    if chars.len() < 4 {
        return false;
    }

    if chars.windows(2).all(|w| w[0] == w[1]) {
        return true;
    }

    let steps = chars.len() - 1;
    let allowed_jumps = 1 + steps / 6;
    let required = steps - allowed_jumps.min(steps);

    let ascending = chars
        .windows(2)
        .filter(|w| (w[1] as u32).checked_sub(w[0] as u32) == Some(1))
        .count();
    let descending = chars
        .windows(2)
        .filter(|w| (w[0] as u32).checked_sub(w[1] as u32) == Some(1))
        .count();

    ascending >= required || descending >= required
}

/// A run of at least [`MIN_KEYBOARD_WALK`] characters along a keyboard row, in
/// either direction. Anything shorter than that is not judged here — the
/// wordlist above covers the short, well-known cases.
fn is_keyboard_walk(normalized: &str) -> bool {
    normalized.chars().count() >= MIN_KEYBOARD_WALK && contains_keyboard_walk(normalized)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Build the configured Argon2id hasher.
fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None, // default output length (32 bytes)
    )
    .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash `password` with Argon2id and a fresh random salt.
///
/// Returns a PHC string (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`) that is
/// stored verbatim in `users.password_hash`. The salt and the parameters travel
/// inside that string, so nothing else has to be persisted.
///
/// This is CPU- and memory-bound by design (see the parameter block above). In
/// an async request handler it must be moved off the runtime, e.g. with
/// `tokio::task::spawn_blocking`, so it does not stall other requests.
pub fn hash_password(password: &str) -> Result<String> {
    // A fresh salt per call. Two identical passwords therefore never produce
    // the same hash, which is what stops an attacker from spotting shared
    // passwords in a stolen database.
    let salt = SaltString::generate(&mut OsRng);

    let hash = argon2()?
        .hash_password(password.as_bytes(), &salt)
        // The error type carries no password material, but it is not `Send +
        // Sync`, so it is rendered to a string here.
        .map_err(|e| anyhow!("failed to hash password: {e}"))?;

    Ok(hash.to_string())
}

/// Whether the cost parameters encoded in a parsed hash are safe to run.
///
/// Pure and allocation-free: it only reads the numbers out of the PHC string
/// and compares them, so it can be called on a hash whose parameters would kill
/// the process if they were actually honoured. A hash that fails this check is
/// treated exactly like a malformed one — the login fails, nothing is
/// allocated, and the finding is logged (without the hash itself, which may
/// still contain a real salt and digest).
fn cost_params_are_acceptable(parsed: &PasswordHash<'_>) -> bool {
    let params = match Params::try_from(parsed) {
        Ok(params) => params,
        Err(e) => {
            tracing::warn!("stored password hash has unusable Argon2 parameters: {e}");
            return false;
        }
    };

    if params.m_cost() > MAX_VERIFY_MEMORY_KIB
        || params.t_cost() > MAX_VERIFY_ITERATIONS
        || params.p_cost() > MAX_VERIFY_PARALLELISM
    {
        // The numbers themselves are not secret and are the only thing that
        // makes this entry actionable, so they are logged; the hash is not.
        tracing::warn!(
            "refusing stored password hash with excessive Argon2 cost parameters \
             (m={}, t={}, p={}; limits m<={}, t<={}, p<={}) — treating the login as failed",
            params.m_cost(),
            params.t_cost(),
            params.p_cost(),
            MAX_VERIFY_MEMORY_KIB,
            MAX_VERIFY_ITERATIONS,
            MAX_VERIFY_PARALLELISM
        );
        return false;
    }

    true
}

/// Verify `password` against a stored PHC string.
///
/// Returns `Ok(false)` for a wrong password **and** for a stored hash that is
/// malformed, truncated or otherwise unparseable: a corrupt row must fail the
/// login, never panic and never let anyone in. The distinction is not exposed
/// to the caller on purpose, so a login handler cannot accidentally turn it
/// into an oracle; the malformed case is logged instead.
///
/// The comparison itself is constant-time — `argon2` compares via
/// `password_hash`'s `Output`, which uses a constant-time equality check.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(parsed) => parsed,
        Err(e) => {
            // No password material and no hash in the message, only the reason.
            tracing::warn!("stored password hash is not a valid PHC string: {e}");
            return false;
        }
    };

    // The cost parameters come from the stored string and are therefore input,
    // not configuration. Refuse anything above the bounds *before* Argon2 sees
    // it — see the comment block at the top of this file for why an unchecked
    // memory cost is not merely slow but fatal to the process.
    if !cost_params_are_acceptable(&parsed) {
        return false;
    }

    // `Argon2::default()` is fine here: the algorithm, version and cost
    // parameters are read from the PHC string, not from this instance, so old
    // hashes keep verifying after the constants above are raised.
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Whether a stored hash was produced with parameters weaker than the current
/// ones and should be re-hashed on the next successful login.
///
/// The re-hashing itself belongs to the login ticket; this module only supplies
/// the predicate.
pub fn needs_rehash(stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        // Unparseable: it cannot be verified either, so there is nothing to
        // upgrade. Reported as "no", the caller rejects the login anyway.
        return false;
    };

    if parsed.algorithm.as_str() != "argon2id" {
        return true;
    }

    match Params::try_from(&parsed) {
        Ok(params) => {
            params.m_cost() < ARGON2_MEMORY_KIB
                || params.t_cost() < ARGON2_ITERATIONS
                || params.p_cost() < ARGON2_PARALLELISM
        }
        Err(_) => true,
    }
}

// ---------------------------------------------------------------------------
// Session tokens
//
// The token is the only thing the client ever holds; the server stores nothing
// but its SHA-256 digest (`sessions.id`). Stealing the database therefore does
// not yield a usable cookie.
//
// Why SHA-256 and not Argon2 for the token — the two cases are not the same
// problem. A password is low-entropy and guessable, which is why it needs a
// deliberately slow hash. A session token is 32 bytes straight out of the
// OS CSPRNG (256 bits): there is nothing to guess, so the only job of the hash
// is to be one-way. A fast hash is the right tool here, and it has to be fast,
// because it runs on *every* authenticated request while Argon2 deliberately
// burns 19 MiB and a couple of milliseconds per call.
//
// No salt for the same reason: salts defend against precomputation over a small
// input space, and there is no precomputing a 256-bit random value.
// ---------------------------------------------------------------------------

/// Length of a raw session token in bytes. 32 bytes = 256 bits, which is the
/// usual floor for a bearer credential and well above OWASP's 128-bit minimum
/// for session identifiers.
pub const SESSION_TOKEN_BYTES: usize = 32;

/// The 32-byte floor is a requirement, not a preference — enforced at compile
/// time so nobody can shrink it in passing.
const _: () = assert!(SESSION_TOKEN_BYTES >= 32);

/// Length of a token in its hex form, which is what travels in the cookie.
pub const SESSION_TOKEN_HEX_LENGTH: usize = SESSION_TOKEN_BYTES * 2;

/// Default cookie name. Deliberately not `session`, so it cannot collide with
/// a cookie of a different app on the same host.
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "rclone_gui_session";

/// Default **idle** lifetime of a session: how long it survives without a
/// single request. Renewed on activity, see [`refresh_session`].
pub const DEFAULT_SESSION_TTL_HOURS: i64 = 24;

/// Default **absolute** lifetime of a session, counted from its creation and
/// never renewed.
///
/// Seven days. The reasoning for having the second limit at all is the one that
/// already cost this project a finding elsewhere: a share link that renewed its
/// own budget on every access stayed usable for 200 accesses over 16 simulated
/// hours because somebody knocked every five minutes. A sliding window without
/// a hard cap is not an expiry, it is a keep-alive — a stolen cookie in an open
/// tab would live forever. Seven days keeps a working week free of logins and
/// still forces a re-authentication that no amount of activity can defer.
pub const DEFAULT_SESSION_MAX_LIFETIME_HOURS: i64 = 24 * 7;

/// Bounds for the configured lifetime. A value outside this range is a typo,
/// not an intent, and is clamped rather than honoured.
const MIN_SESSION_TTL_HOURS: i64 = 1;
const MAX_SESSION_TTL_HOURS: i64 = 24 * 365;

/// How often the background cleanup runs. The tasks side does its housekeeping
/// opportunistically on every listing (`sync.rs::list_sync_jobs`, 24 h
/// threshold); sessions get the same treatment on every login *plus* this
/// timer, because an idle server must not keep expired rows around forever.
pub const SESSION_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Upper bound for the stored `User-Agent`. It comes from the client, so it is
/// truncated before it reaches the database.
const MAX_USER_AGENT_LENGTH: usize = 512;

/// A stand-in Argon2id hash, used to spend the same CPU time on a login for an
/// unknown user as on one for a known user. Without it, the response time alone
/// tells an attacker which usernames exist.
///
/// Computed once, over a token nobody knows and that is dropped immediately, so
/// it can never verify. Built at runtime rather than hardcoded so it always
/// carries the *current* parameters — a pasted constant would silently stop
/// matching the real cost the moment the constants above are raised.
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    DUMMY
        .get_or_init(|| {
            let throwaway =
                generate_session_token().map_or_else(|_| String::new(), |t| t.expose().to_string());
            // If hashing fails here the fallback is an unparseable string;
            // `verify_password` rejects it, which is the correct outcome — the
            // login fails either way, only the timing defence is lost.
            hash_password(&throwaway).unwrap_or_default()
        })
        .as_str()
}

/// A raw session token.
///
/// Wrapped in a newtype on purpose:
///   * it has no `Display`, no `Serialize` and a redacting `Debug`, so it
///     cannot end up in a `tracing` line or an API response by accident;
///   * reading the secret requires the explicit [`SessionToken::expose`], which
///     is greppable in review.
#[derive(Clone)]
pub struct SessionToken(String);

impl SessionToken {
    /// The token in its cookie form (lowercase hex). Only call this where the
    /// value is genuinely needed — building the `Set-Cookie` header.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The digest that is stored in `sessions.id`.
    pub fn hash(&self) -> String {
        hash_session_token(&self.0)
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the value, not even a prefix of it.
        f.write_str("SessionToken(<redacted>)")
    }
}

/// Length of a raw password-reset token in bytes. 32 bytes = 256 bits.
///
/// The reset link is redeemed on a **public** route — that is the whole point
/// of it, since the person using it is locked out — so the token is the only
/// thing between the world and an account takeover. It gets the same budget as
/// a session cookie, never less.
pub const RESET_TOKEN_BYTES: usize = 32;

/// The 32-byte floor is a requirement, not a preference — enforced at compile
/// time so nobody can shrink it in passing.
const _: () = assert!(RESET_TOKEN_BYTES >= 32);

/// Length of a reset token in the form that travels in the URL (lowercase hex).
pub const RESET_TOKEN_HEX_LENGTH: usize = RESET_TOKEN_BYTES * 2;

/// How long a reset token stays redeemable.
///
/// One hour: long enough for somebody who has just read it off a terminal —
/// possibly through an SSH tunnel — to open a browser and type a password,
/// short enough that a token forgotten in a scrollback buffer is worthless by
/// the time anyone finds it.
pub const RESET_TOKEN_TTL_MINUTES: i64 = 60;

/// How long a *spent* grant is kept before the cleanup removes it. It cannot be
/// redeemed again either way; keeping it briefly is what lets a second attempt
/// be recognised as "already used" rather than as a token that never existed.
const RESET_SPENT_GRACE_HOURS: i64 = 24;

/// A raw password-reset token.
///
/// Wrapped in a newtype on purpose, mirroring [`SessionToken`] and
/// `shares::ShareToken`:
///   * no `Display`, no `Serialize` and a redacting `Debug`, so it cannot reach
///     a `tracing` line, a log backup or a JSON response by accident;
///   * reading the secret takes the explicit [`ResetToken::expose`], which is
///     greppable in review — and there is exactly one legitimate caller: the
///     `println!` in `main.rs` that shows it to the operator once.
///
/// A derived `Debug` has already written a live token into a log once in this
/// project. That is what this type exists to prevent, and
/// `reset_token_debug_is_redacted` keeps it that way.
#[derive(Clone)]
pub struct ResetToken(String);

impl ResetToken {
    /// The token in its link form (lowercase hex). Only call this where the
    /// value is genuinely needed — the one terminal line that hands it over.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The digest that is stored in `password_resets.token_hash`.
    pub fn hash(&self) -> String {
        hash_reset_token(&self.0)
    }
}

impl std::fmt::Debug for ResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the value, not even a prefix of it.
        f.write_str("ResetToken(<redacted>)")
    }
}

/// Draw a fresh reset token from the operating system CSPRNG.
///
/// Same failure mode as [`generate_session_token`]: no entropy is an error,
/// never a guessable fallback.
pub fn generate_reset_token() -> Result<ResetToken> {
    let mut bytes = [0u8; RESET_TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow!("failed to draw a reset token from the system RNG: {e}"))?;

    Ok(ResetToken(to_hex(&bytes)))
}

/// SHA-256 of a reset token, lowercase hex. This is what
/// `password_resets.token_hash` holds — the plaintext is never stored.
pub fn hash_reset_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    to_hex(&digest)
}

/// Whether `candidate` has the shape of a reset token this server issued.
///
/// Lets the public route reject junk out of a URL before it costs a database
/// round trip. It says nothing about validity.
pub fn is_well_formed_reset_token(candidate: &str) -> bool {
    candidate.len() == RESET_TOKEN_HEX_LENGTH
        && candidate
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Draw a fresh session token from the operating system CSPRNG.
///
/// Fails instead of panicking when the OS entropy source is unavailable: that
/// is the one situation where generating a token anyway would be a security
/// bug, so it must be an error the caller has to handle.
pub fn generate_session_token() -> Result<SessionToken> {
    let mut bytes = [0u8; SESSION_TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow!("failed to draw session token from the system RNG: {e}"))?;

    Ok(SessionToken(to_hex(&bytes)))
}

/// A random password for the bootstrap administrator, when the operator did not
/// supply one.
///
/// 128 bits of OS entropy rendered as 32 hex characters — well past
/// [`MIN_PASSWORD_LENGTH`] and not something anyone is expected to remember:
/// it exists so that a first start is never blocked, and the account it opens
/// is meant to get a real password immediately.
///
/// Same failure mode as [`generate_session_token`]: no entropy means an error,
/// never a guessable fallback.
pub fn generate_initial_password() -> Result<String> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow!("failed to draw an initial password from the system RNG: {e}"))?;

    Ok(to_hex(&bytes))
}

/// SHA-256 of a token, lowercase hex. This is what `sessions.id` holds.
pub fn hash_session_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    to_hex(&digest)
}

/// Whether `candidate` has the shape of a token this server issued.
///
/// Used to reject junk cookies before they cost a database round trip. It says
/// nothing about validity — a well-formed token can still be unknown.
pub fn is_well_formed_token(candidate: &str) -> bool {
    candidate.len() == SESSION_TOKEN_HEX_LENGTH
        && candidate
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Constant-time comparison of two hex digests.
///
/// The database lookup already selects by hash, so this is belt and braces —
/// but a plain `==` on `String` short-circuits on the first differing byte, and
/// no secret in this module should ever be compared that way.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Lowercase hex, without pulling in a crate for sixteen characters.
fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Cookie
// ---------------------------------------------------------------------------

/// Everything about the session cookie that an operator may want to change.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Cookie name.
    pub cookie_name: String,
    /// **Idle** lifetime in hours; also the `expires_at` of the database row,
    /// so an attacker who keeps the cookie past its `Max-Age` gains nothing.
    /// Activity pushes it forward (see [`refresh_session`]).
    pub ttl_hours: i64,
    /// **Absolute** lifetime in hours, counted from `sessions.created_at` and
    /// never renewed. The ceiling the sliding window is clamped to.
    pub max_lifetime_hours: i64,
    /// Whether to set `Secure`. Defaults to `true`; only a deployment that
    /// deliberately serves plain HTTP on a trusted network turns it off.
    pub secure: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: DEFAULT_SESSION_COOKIE_NAME.to_string(),
            ttl_hours: DEFAULT_SESSION_TTL_HOURS,
            max_lifetime_hours: DEFAULT_SESSION_MAX_LIFETIME_HOURS,
            secure: true,
        }
    }
}

impl SessionConfig {
    /// Read the configuration from the environment, following the
    /// `RCLONE_GUI_*` convention the rest of the app uses.
    ///
    /// Every variable is optional and a malformed value falls back to the
    /// default with a warning — a typo in an env file must not stop the server
    /// from starting, and must never silently weaken the cookie.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(raw) = std::env::var("RCLONE_GUI_SESSION_TTL_HOURS") {
            match raw.trim().parse::<i64>() {
                Ok(hours) if (MIN_SESSION_TTL_HOURS..=MAX_SESSION_TTL_HOURS).contains(&hours) => {
                    config.ttl_hours = hours;
                }
                Ok(hours) => {
                    tracing::warn!(
                        "RCLONE_GUI_SESSION_TTL_HOURS={hours} is outside {MIN_SESSION_TTL_HOURS}..={MAX_SESSION_TTL_HOURS}, using {}",
                        config.ttl_hours
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "RCLONE_GUI_SESSION_TTL_HOURS is not a number ({e}), using {}",
                        config.ttl_hours
                    );
                }
            }
        }

        if let Ok(raw) = std::env::var("RCLONE_GUI_SESSION_MAX_LIFETIME_HOURS") {
            match raw.trim().parse::<i64>() {
                Ok(hours) if (MIN_SESSION_TTL_HOURS..=MAX_SESSION_TTL_HOURS).contains(&hours) => {
                    config.max_lifetime_hours = hours;
                }
                Ok(hours) => {
                    tracing::warn!(
                        "RCLONE_GUI_SESSION_MAX_LIFETIME_HOURS={hours} is outside {MIN_SESSION_TTL_HOURS}..={MAX_SESSION_TTL_HOURS}, using {}",
                        config.max_lifetime_hours
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "RCLONE_GUI_SESSION_MAX_LIFETIME_HOURS is not a number ({e}), using {}",
                        config.max_lifetime_hours
                    );
                }
            }
        }

        // An absolute lifetime below the idle window would be the idle window,
        // only harder to read. Raise it rather than let the two contradict.
        if config.max_lifetime_hours < config.ttl_hours {
            tracing::warn!(
                "RCLONE_GUI_SESSION_MAX_LIFETIME_HOURS={} is below the idle lifetime of {} h, using {} h",
                config.max_lifetime_hours,
                config.ttl_hours,
                config.ttl_hours
            );
            config.max_lifetime_hours = config.ttl_hours;
        }

        if let Ok(raw) = std::env::var("RCLONE_GUI_SESSION_COOKIE_SECURE") {
            match raw.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => config.secure = true,
                "0" | "false" | "no" | "off" => {
                    tracing::warn!(
                        "RCLONE_GUI_SESSION_COOKIE_SECURE is off — the session cookie will \
                         also be sent over plain HTTP. Only do this behind a trusted network."
                    );
                    config.secure = false;
                }
                other => {
                    tracing::warn!(
                        "RCLONE_GUI_SESSION_COOKIE_SECURE={other:?} is not a boolean, keeping Secure enabled"
                    );
                }
            }
        }

        if let Ok(raw) = std::env::var("RCLONE_GUI_SESSION_COOKIE_NAME") {
            let name = raw.trim();
            if is_valid_cookie_name(name) {
                config.cookie_name = name.to_string();
            } else {
                tracing::warn!(
                    "RCLONE_GUI_SESSION_COOKIE_NAME is not a valid cookie name, using {}",
                    config.cookie_name
                );
            }
        }

        config
    }

    /// The lifetime as a `chrono` duration, for `expires_at`.
    pub fn ttl(&self) -> ChronoDuration {
        ChronoDuration::hours(self.ttl_hours)
    }

    /// The absolute lifetime as a `chrono` duration.
    pub fn max_lifetime(&self) -> ChronoDuration {
        ChronoDuration::hours(self.max_lifetime_hours)
    }

    /// The instant a session dies no matter what, counted from its creation.
    ///
    /// Derived from `created_at` instead of stored in a column of its own: the
    /// creation time is already in the row, so there is nothing to migrate and
    /// nothing that can drift out of step with `expires_at`.
    pub fn absolute_deadline(&self, session: &Session) -> DateTime<Utc> {
        session.created_at + self.max_lifetime()
    }

    /// The idle deadline a session gets when it is renewed at `now` — the
    /// sliding window, clamped to the absolute one. Never beyond
    /// [`Self::absolute_deadline`].
    pub fn slid_expiry(&self, session: &Session, now: DateTime<Utc>) -> DateTime<Utc> {
        (now + self.ttl()).min(self.absolute_deadline(session))
    }

    /// Sessions whose idle deadline is at or before this instant are renewed;
    /// anything later is left alone.
    ///
    /// Half of the idle window. With the default 24 h that is one write per
    /// session every twelve hours instead of one per request — and the job
    /// poller alone would otherwise produce 43 200 writes a day. The
    /// counter-argument to renewing on every request is only cost, but the cost
    /// is a `UPDATE` on every poll of every open tab, and the benefit over a
    /// half-window threshold is nil: a client that is active at all is active
    /// somewhere in the second half of the window too.
    pub fn renewal_deadline(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now + ChronoDuration::seconds(self.ttl_hours.saturating_mul(3600) / 2)
    }

    /// `Max-Age` in seconds.
    pub fn max_age_seconds(&self) -> i64 {
        self.ttl_hours.saturating_mul(3600)
    }

    /// The `Set-Cookie` value that hands `token` to the browser.
    ///
    /// Attributes, and why:
    ///   * `HttpOnly` — JavaScript cannot read it, so an XSS bug in the static
    ///     frontend cannot exfiltrate the session.
    ///   * `Secure` — never sent over plain HTTP (configurable, on by default).
    ///   * `SameSite=Lax` — not sent on cross-site POSTs, which removes the
    ///     classic CSRF vector while keeping normal top-level navigation to the
    ///     UI working.
    ///   * `Path=/` — the whole app is behind the session.
    ///   * `Max-Age` — mirrors the server-side `expires_at`.
    ///
    /// The token is hex, so it needs no quoting or percent-encoding.
    pub fn build_session_cookie(&self, token: &SessionToken) -> String {
        self.build_cookie(token.expose(), self.max_age_seconds())
    }

    /// The `Set-Cookie` value that removes the cookie again, for logout.
    ///
    /// Same attributes as the original — a browser only replaces a cookie when
    /// name, path and domain match — with an empty value and `Max-Age=0`.
    pub fn build_clearing_cookie(&self) -> String {
        self.build_cookie("", 0)
    }

    /// The `Set-Cookie` value that gives the browser a longer `Max-Age` for the
    /// token it already holds.
    ///
    /// **The token is not rotated.** Handing out a new one on a sliding renewal
    /// would mean that any request racing the rotation carries the old cookie,
    /// and losing that race logs the user out — the exact failure this ticket
    /// is about. Only the deadline moves; the credential stays.
    ///
    /// `raw_token` comes from the request cookie and is re-checked here, so a
    /// malformed value can never be echoed back into a header.
    pub fn refresh_session_cookie(&self, raw_token: &str, max_age: i64) -> Option<String> {
        if !is_well_formed_token(raw_token) {
            tracing::warn!("refusing to refresh a cookie for a malformed token");
            return None;
        }
        Some(self.build_cookie(raw_token, max_age.max(0)))
    }

    fn build_cookie(&self, value: &str, max_age: i64) -> String {
        let mut cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            self.cookie_name, value, max_age
        );
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie
    }
}

/// Cookie names are HTTP tokens (RFC 6265 / RFC 7230). Anything else could
/// smuggle attributes into the header, so it is rejected outright.
fn is_valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        ..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
}

/// Pull the session token out of a raw `Cookie:` request header.
///
/// Returns `None` when the header is absent, the cookie is missing, or the
/// value does not have the shape of a token this server issues. Written by hand
/// because axum 0.7 gives us the header and nothing in the dependency tree
/// parses cookies — and the grammar needed here is one `split`.
pub fn session_token_from_cookie_header(header: &str, cookie_name: &str) -> Option<String> {
    for pair in header.split(';') {
        // A pair without `=` is a valueless flag cookie. Those are legal and do
        // occur, so skip them — aborting here would drop a perfectly good
        // session cookie that happens to come later in the header.
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if name.trim() != cookie_name {
            continue;
        }
        // Cookie values may be wrapped in double quotes.
        let value = value.trim().trim_matches('"');
        if is_well_formed_token(value) {
            return Some(value.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Login / logout / session check
// ---------------------------------------------------------------------------

/// Why a login was refused.
///
/// [`LoginError::InvalidCredentials`] covers unknown user *and* wrong password
/// on purpose: telling the two apart would turn the login form into a user
/// enumeration oracle.
#[derive(Debug)]
pub enum LoginError {
    /// Unknown username or wrong password.
    InvalidCredentials,
    /// Correct password, but the account is switched off.
    AccountDisabled,
    /// Database or RNG failure. The detail is for the log, not for the client.
    Internal(anyhow::Error),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::InvalidCredentials => write!(f, "Invalid username or password"),
            LoginError::AccountDisabled => write!(f, "This account is disabled"),
            LoginError::Internal(_) => write!(f, "Login failed, please try again"),
        }
    }
}

impl std::error::Error for LoginError {}

/// What a successful login produced.
///
/// `Debug` is written by hand, not derived. A derived one printed two secrets:
/// the raw token in clear text inside `set_cookie`, and the full Argon2 hash
/// through `user`. A single `tracing::debug!(?outcome)` in a login handler
/// would therefore write a *usable* session cookie into a log file, into a
/// backup and into every bug report built from it. Redacting [`SessionToken`]
/// is worth nothing while the surrounding struct carries the same token
/// unredacted.
pub struct LoginOutcome {
    /// The authenticated account.
    pub user: User,
    /// The stored session row. Its `id` is the token hash.
    pub session: Session,
    /// The raw token. Goes into the cookie and nowhere else.
    pub token: SessionToken,
    /// Ready-to-use `Set-Cookie` value.
    pub set_cookie: String,
}

impl std::fmt::Debug for LoginOutcome {
    /// Shows what is useful for debugging a login — who, which role, how long
    /// the session lasts — and nothing that could be replayed or cracked. The
    /// password hash, the `Set-Cookie` header and the session id (the token
    /// digest, i.e. the server-side session key) stay out.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginOutcome")
            .field("user_id", &self.user.id)
            .field("username", &self.user.username)
            .field("role", &self.user.role)
            .field("is_active", &self.user.is_active)
            .field("session_created_at", &self.session.created_at)
            .field("session_expires_at", &self.session.expires_at)
            .field("token", &self.token)
            .field("set_cookie", &"<redacted>")
            .finish()
    }
}

/// Verify credentials and open a session.
///
/// Runs the Argon2 work on `spawn_blocking`: a verification costs 19 MiB and a
/// couple of milliseconds, which would otherwise block a tokio worker and stall
/// unrelated requests.
///
/// `user_agent` and `ip` are stored with the session so the "active logins"
/// view of the user-management ticket has something to show; both are optional
/// and truncated.
pub async fn login(
    pool: &Pool<Sqlite>,
    config: &SessionConfig,
    username: &str,
    password: &str,
    user_agent: Option<&str>,
    ip: Option<&str>,
) -> std::result::Result<LoginOutcome, LoginError> {
    let username = username.trim();

    let user = database::get_user_by_username(pool, username)
        .await
        .map_err(LoginError::Internal)?;

    let Some(user) = user else {
        // Unknown user: spend the same CPU time anyway, then fail.
        let _ = verify_password_off_thread(password.to_string(), dummy_password_hash().to_string())
            .await;
        tracing::info!("login rejected: unknown username");
        return Err(LoginError::InvalidCredentials);
    };

    let password_ok =
        verify_password_off_thread(password.to_string(), user.password_hash.clone()).await;

    if !password_ok {
        tracing::info!(user_id = %user.id, "login rejected: wrong password");
        return Err(LoginError::InvalidCredentials);
    }

    // Checked only after the password, so a wrong password cannot reveal that
    // an account exists but is disabled.
    if !user.is_active {
        tracing::info!(user_id = %user.id, "login rejected: account disabled");
        return Err(LoginError::AccountDisabled);
    }

    // The password was correct, so the plaintext is available exactly here —
    // the only moment an outdated hash can be upgraded. Best effort: a failed
    // upgrade must not fail an otherwise valid login.
    if needs_rehash(&user.password_hash) {
        upgrade_password_hash(pool, &user.id, password).await;
    }

    let token = generate_session_token().map_err(LoginError::Internal)?;
    let now = Utc::now();
    let session = Session {
        id: token.hash(),
        user_id: user.id.clone(),
        created_at: now,
        // The idle window, but never past the absolute one — with a sane
        // configuration the first term wins; a configuration that sets the cap
        // below the idle window gets the cap.
        expires_at: now + config.ttl().min(config.max_lifetime()),
        user_agent: user_agent.map(truncate_metadata),
        ip: ip.map(truncate_metadata),
    };

    database::create_session(pool, &session)
        .await
        .context("failed to store the session")
        .map_err(LoginError::Internal)?;

    // Housekeeping, in the spirit of the tasks cleanup: piggyback on an event
    // that happens anyway. Neither of these may fail the login.
    if let Err(e) = database::set_user_last_login(pool, &user.id, now).await {
        tracing::warn!(user_id = %user.id, "could not record last_login_at: {e}");
    }
    if let Err(e) = database::delete_expired_sessions(pool, now).await {
        tracing::warn!("expired session cleanup on login failed: {e}");
    }

    tracing::info!(user_id = %user.id, "login succeeded");

    let set_cookie = config.build_session_cookie(&token);
    Ok(LoginOutcome {
        user,
        session,
        token,
        set_cookie,
    })
}

/// Resolve a raw token to its session and user.
///
/// Returns `None` for a malformed, unknown, expired or orphaned token, and for
/// a session whose account has since been disabled. `Err` is reserved for
/// database failures, which must surface as a 500 rather than as "logged out".
pub async fn authenticate_session(
    pool: &Pool<Sqlite>,
    token: &str,
) -> Result<Option<(Session, User)>> {
    // Cheap shape check first, so junk cookies never reach the database.
    if !is_well_formed_token(token) {
        return Ok(None);
    }

    let token_hash = hash_session_token(token);

    let Some(session) = database::get_valid_session(pool, &token_hash, Utc::now()).await? else {
        return Ok(None);
    };

    // The lookup already matched on the hash; re-check it without leaking
    // timing, so a future change to the query cannot quietly widen the match.
    if !constant_time_eq(&session.id, &token_hash) {
        tracing::warn!("session lookup returned a row with a different id");
        return Ok(None);
    }

    let Some(user) = database::get_user_by_id(pool, &session.user_id).await? else {
        // Should not happen (foreign key + cascade), but a session without a
        // user must not authenticate anything.
        tracing::warn!(user_id = %session.user_id, "session references a missing user, dropping it");
        let _ = database::delete_session(pool, &token_hash).await;
        return Ok(None);
    };

    if !user.is_active {
        tracing::info!(user_id = %user.id, "session rejected: account disabled");
        return Ok(None);
    }

    Ok(Some((session, user)))
}

/// What an authenticated request did to its session.
///
/// `Debug` is hand-written, and must stay that way: the `Renewed` arm carries
/// the complete `Set-Cookie` header, i.e. the **live session token** of a
/// request that has just authenticated. A derived `Debug` renders it in clear
/// text into the first `tracing` line or bug report that touches this value —
/// which is the sixth time that pattern has appeared in this project, and it
/// slipped through here precisely because the [`Session`] next to it *is*
/// correctly redacted, so the output looked clean.
///
/// The value is redacted, not dropped: knowing that a cookie was rebuilt (and
/// that it was not) is the useful part when debugging a renewal, and
/// `session_refresh_debug_is_redacted` keeps both properties.
pub enum SessionRefresh {
    /// Enough of the idle window is left — no database write at all. This is
    /// the case for the overwhelming majority of requests.
    Unchanged,
    /// The idle deadline was pushed forward. Carries the updated row and the
    /// `Set-Cookie` value that keeps the browser's `Max-Age` in step (the token
    /// itself is unchanged).
    Renewed {
        session: Session,
        set_cookie: Option<String>,
    },
    /// The absolute lifetime is up. The row has been deleted; the caller must
    /// reject the request as unauthenticated.
    Expired,
}

impl std::fmt::Debug for SessionRefresh {
    /// Shows which branch was taken and, for `Renewed`, the renewed row (whose
    /// own `Debug` already redacts the session key) — but never the
    /// `Set-Cookie` value, only whether one was built.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionRefresh::Unchanged => f.write_str("Unchanged"),
            SessionRefresh::Renewed {
                session,
                set_cookie,
            } => f
                .debug_struct("Renewed")
                .field("session", session)
                .field(
                    "set_cookie",
                    &match set_cookie {
                        Some(_) => "Some(<redacted>)",
                        None => "None",
                    },
                )
                .finish(),
            SessionRefresh::Expired => f.write_str("Expired"),
        }
    }
}

/// Apply the sliding expiration to a session that has just authenticated.
///
/// Two limits, and they do different jobs:
///
///   * the **idle** window ([`SessionConfig::ttl`]) is renewed on activity, so
///     somebody who works through the night is not thrown out mid-transfer;
///   * the **absolute** lifetime ([`SessionConfig::absolute_deadline`]) is
///     never renewed, so a session cannot be kept alive indefinitely by an open
///     tab that polls.
///
/// The absolute limit is enforced on both sides: the renewed deadline is
/// clamped to it (so `expires_at` alone stays a correct validity test for
/// `get_valid_session` and a correct deletion test for the cleanup), *and* it is
/// checked here on the read path. The second check is not redundant — lowering
/// `RCLONE_GUI_SESSION_MAX_LIFETIME_HOURS` on an existing database leaves rows
/// whose stored deadline is beyond the new cap, and those must stop working
/// immediately rather than at their old deadline.
///
/// `raw_token` is only used to rebuild the cookie; the row is addressed by
/// `session.id`, which is already the token digest.
pub async fn refresh_session(
    pool: &Pool<Sqlite>,
    config: &SessionConfig,
    raw_token: &str,
    session: &Session,
    now: DateTime<Utc>,
) -> Result<SessionRefresh> {
    let hard_deadline = config.absolute_deadline(session);

    if now >= hard_deadline {
        tracing::info!(
            user_id = %session.user_id,
            "session dropped: absolute lifetime reached"
        );
        // Best effort: the request is refused either way, and a failed delete
        // only means the row waits for the cleanup.
        if let Err(e) = database::delete_session(pool, &session.id).await {
            tracing::warn!("could not delete a session past its absolute lifetime: {e}");
        }
        return Ok(SessionRefresh::Expired);
    }

    // The cheap path, and the one nearly every request takes: more than the
    // threshold is left, so nothing is written and no statement is issued.
    if session.expires_at > config.renewal_deadline(now) {
        return Ok(SessionRefresh::Unchanged);
    }

    let renewed = database::renew_session(
        pool,
        &session.id,
        now,
        config.slid_expiry(session, now),
        config.renewal_deadline(now),
    )
    .await
    .context("failed to renew the session")?;

    // `None` means there was nothing left to do: a concurrent request renewed
    // it first, the absolute cap has already been reached, or the row is gone
    // because somebody logged out everywhere in the meantime. None of those is
    // an error for *this* request, which was already authenticated above.
    let Some(renewed) = renewed else {
        return Ok(SessionRefresh::Unchanged);
    };

    let set_cookie =
        config.refresh_session_cookie(raw_token, (renewed.expires_at - now).num_seconds());

    Ok(SessionRefresh::Renewed {
        session: renewed,
        set_cookie,
    })
}

/// Invalidate a single session server-side.
///
/// Returns whether a session was actually removed. Deleting the row is what
/// makes the logout real — dropping the cookie alone would leave a token that
/// still works if it was captured.
pub async fn logout(pool: &Pool<Sqlite>, token: &str) -> Result<bool> {
    if !is_well_formed_token(token) {
        return Ok(false);
    }

    let removed = database::delete_session(pool, &hash_session_token(token)).await?;
    if removed {
        tracing::info!("session logged out");
    }
    Ok(removed)
}

/// Invalidate every session of a user — "log out everywhere", and what a
/// password change or a deactivation has to call.
///
/// Called by [`redeem_password_reset`]; the screens that change a password from
/// inside the application belong to the user-management ticket and will call it
/// too.
pub async fn logout_all_sessions(pool: &Pool<Sqlite>, user_id: &str) -> Result<u64> {
    let removed = database::delete_sessions_for_user(pool, user_id).await?;
    tracing::info!(user_id = %user_id, removed, "all sessions dropped");
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Password reset
//
// The way back into an installation whose password was lost. `ensure_bootstrap_
// user` only fires on an *empty* `users` table, so without this there is no
// second chance: user management sits behind exactly the login that cannot be
// passed.
//
// The flow is cut so that a later e-mail version replaces the **delivery**
// only. Issuing, storage and redemption below know nothing about how the token
// reaches its owner — today `main.rs` prints it on the terminal.
// ---------------------------------------------------------------------------

/// Why `--reset-password` could not issue a token.
///
/// These distinctions are for the **CLI**, where somebody with server access is
/// already standing, and a clear message is worth more than hiding which
/// accounts exist. The web side never sees this type: it is handed a token, not
/// a user name, and therefore has nothing to disclose in the first place.
#[derive(Debug)]
pub enum ResetIssueError {
    NoSuchAccount,
    AccountDisabled,
    Internal(anyhow::Error),
}

impl std::fmt::Display for ResetIssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchAccount => f.write_str("no account with that user name"),
            Self::AccountDisabled => {
                f.write_str("the account is disabled; enable it before resetting its password")
            }
            Self::Internal(_) => f.write_str("could not issue a reset token"),
        }
    }
}

impl std::error::Error for ResetIssueError {}

/// A freshly issued grant, on its way to the operator's terminal.
///
/// `Debug` is hand-written even though [`ResetToken`] already redacts: this
/// struct is the one place the live token and the account it opens sit
/// together, and the next field somebody adds must not change that.
pub struct IssuedReset {
    pub token: ResetToken,
    pub username: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for IssuedReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedReset")
            .field("token", &"<redacted>")
            .field("username", &self.username)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Issue a one-shot reset grant for `username`.
///
/// The caller gets the raw token exactly once, in memory; only its SHA-256 goes
/// into the database. There is no way to read the token back afterwards — a
/// lost one is re-issued, not recovered.
pub async fn issue_password_reset(
    pool: &Pool<Sqlite>,
    username: &str,
) -> std::result::Result<IssuedReset, ResetIssueError> {
    let user = database::get_user_by_username(pool, username.trim())
        .await
        .map_err(ResetIssueError::Internal)?
        .ok_or(ResetIssueError::NoSuchAccount)?;

    if !user.is_active {
        // A disabled account must not be reachable through a reset either —
        // otherwise disabling somebody would be undone by one terminal command.
        return Err(ResetIssueError::AccountDisabled);
    }

    let token = generate_reset_token().map_err(ResetIssueError::Internal)?;
    let now = Utc::now();
    let expires_at = now + ChronoDuration::minutes(RESET_TOKEN_TTL_MINUTES);

    let reset = database::PasswordReset {
        id: uuid::Uuid::new_v4().to_string(),
        token_hash: token.hash(),
        user_id: user.id.clone(),
        created_at: now,
        expires_at,
        used_at: None,
    };
    database::create_password_reset(pool, &reset)
        .await
        .map_err(ResetIssueError::Internal)?;

    // Identity and expiry only. The token itself is never logged, at any level.
    tracing::info!(user_id = %user.id, %expires_at, "password reset token issued");

    Ok(IssuedReset {
        token,
        username: user.username,
        expires_at,
    })
}

/// What redeeming a token did.
///
/// `Rejected` deliberately merges "malformed", "unknown", "already used" and
/// "expired": the public page must not help anyone tell those apart.
#[derive(Debug)]
pub enum PasswordResetOutcome {
    Success { user_id: String, username: String },
    Rejected,
    WeakPassword(PasswordPolicyError),
}

/// Redeem a reset token and set a new password.
///
/// The order of the steps is the security-relevant part:
///
///  1. the password policy runs **first**, so a rejected password does not burn
///     a token the user then no longer has;
///  2. the shape check keeps junk out of the database round trip;
///  3. [`database::consume_password_reset`] claims the grant in a single atomic
///     `UPDATE ... WHERE used_at IS NULL ... RETURNING`. Two concurrent
///     redemptions of the same token therefore have exactly one winner — the
///     loser is indistinguishable from an unknown token, which is correct;
///  4. only then is the password written, and
///  5. **every session of the account is dropped**. Without that step a
///     password change leaves an attacker who already holds a session logged
///     in, which is the classic way this feature fails. Any other outstanding
///     grant for the account is closed too.
///
/// A failure between (3) and (4) burns the token without changing the password.
/// That is the safe direction: the operator issues a new one.
pub async fn redeem_password_reset(
    pool: &Pool<Sqlite>,
    token: &str,
    new_password: &str,
) -> Result<PasswordResetOutcome> {
    if let Err(policy) = validate_password(new_password) {
        return Ok(PasswordResetOutcome::WeakPassword(policy));
    }

    if !is_well_formed_reset_token(token) {
        spend_hash_time().await;
        return Ok(PasswordResetOutcome::Rejected);
    }

    let token_hash = hash_reset_token(token);
    let now = Utc::now();

    let Some(reset) = database::consume_password_reset(pool, &token_hash, now).await? else {
        // Spend roughly the Argon2 time a successful redemption would have
        // cost, so the response time does not separate "no such token" from
        // "token accepted". Same trick, and the same reason, as the login.
        spend_hash_time().await;
        return Ok(PasswordResetOutcome::Rejected);
    };

    let Some(user) = database::get_user_by_id(pool, &reset.user_id).await? else {
        // The claim already checked that the account exists and is enabled, so
        // this means it disappeared in between. The grant is spent either way.
        tracing::warn!(user_id = %reset.user_id, "reset token pointed at a missing account");
        return Ok(PasswordResetOutcome::Rejected);
    };

    let hash = hash_password_off_thread(new_password.to_string()).await?;
    if !database::update_user_password(pool, &user.id, &hash).await? {
        return Err(anyhow!("password update affected no row"));
    }

    // Everything that was open under the old password dies with it.
    let dropped = logout_all_sessions(pool, &user.id).await?;
    let closed = database::invalidate_password_resets_for_user(pool, &user.id, now).await?;

    tracing::info!(
        user_id = %user.id,
        username = %user.username,
        sessions_dropped = dropped,
        other_grants_closed = closed,
        "password reset redeemed"
    );

    Ok(PasswordResetOutcome::Success {
        user_id: user.id,
        username: user.username,
    })
}

/// Run Argon2 hashing off the async runtime. It is CPU- and memory-bound by
/// design; doing it inline would stall every other request on the worker.
async fn hash_password_off_thread(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .context("password hashing task failed")?
}

/// Burn the time a real hash would have taken, when there was nothing to hash.
/// Verifies an unknowable password against the dummy hash, which never matches.
async fn spend_hash_time() {
    let dummy = dummy_password_hash().to_string();
    let _ = tokio::task::spawn_blocking(move || verify_password("not-the-password", &dummy)).await;
}

/// Delete expired reset grants, and spent ones past their grace period.
pub async fn cleanup_expired_password_resets(pool: &Pool<Sqlite>) -> Result<u64> {
    let removed = database::delete_expired_password_resets(
        pool,
        Utc::now(),
        ChronoDuration::hours(RESET_SPENT_GRACE_HOURS),
    )
    .await?;
    if removed > 0 {
        tracing::info!("🧹 Auto-cleanup: removed {removed} finished password reset token(s)");
    }
    Ok(removed)
}

/// Delete every session whose `expires_at` has passed.
pub async fn cleanup_expired_sessions(pool: &Pool<Sqlite>) -> Result<u64> {
    let removed = database::delete_expired_sessions(pool, Utc::now()).await?;
    if removed > 0 {
        tracing::info!("🧹 Auto-cleanup: removed {removed} expired session(s)");
    }
    Ok(removed)
}

/// Run [`cleanup_expired_sessions`] every [`SESSION_CLEANUP_INTERVAL`].
///
/// Modelled on the 24-hour job cleanup in `sync.rs`, but on a timer instead of
/// on a request: an expired session must disappear even when nobody logs in.
/// The loop never terminates on an error — a temporarily locked database is not
/// a reason to stop housekeeping for the rest of the process lifetime.
pub fn spawn_session_cleanup(pool: Pool<Sqlite>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SESSION_CLEANUP_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(e) = cleanup_expired_sessions(&pool).await {
                tracing::warn!("periodic session cleanup failed: {e}");
            }
            // Same timer, same reason: an expired reset token must disappear
            // even when nobody logs in.
            if let Err(e) = cleanup_expired_password_resets(&pool).await {
                tracing::warn!("periodic password-reset cleanup failed: {e}");
            }
        }
    })
}

/// When a session expires, for callers that want to show it.
///
/// No caller yet: the "active logins" view that shows it is part of the
/// user-management ticket.
#[allow(dead_code)]
pub fn session_expires_at(session: &Session) -> DateTime<Utc> {
    session.expires_at
}

/// Argon2 verification, moved off the async runtime.
async fn verify_password_off_thread(password: String, stored_hash: String) -> bool {
    match tokio::task::spawn_blocking(move || verify_password(&password, &stored_hash)).await {
        Ok(result) => result,
        Err(e) => {
            // The blocking pool panicked or was shut down. Fail closed.
            tracing::error!("password verification task failed: {e}");
            false
        }
    }
}

/// Re-hash a password with the current Argon2 parameters and store it.
///
/// Best effort by design: this runs *after* a successful verification, so any
/// failure here leaves a working (if outdated) hash in place.
async fn upgrade_password_hash(pool: &Pool<Sqlite>, user_id: &str, password: &str) {
    let owned = password.to_string();
    let hashed = match tokio::task::spawn_blocking(move || hash_password(&owned)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => {
            tracing::warn!(user_id = %user_id, "could not re-hash outdated password: {e}");
            return;
        }
        Err(e) => {
            tracing::warn!(user_id = %user_id, "re-hash task failed: {e}");
            return;
        }
    };

    match database::update_user_password(pool, user_id, &hashed).await {
        Ok(true) => {
            tracing::info!(user_id = %user_id, "password hash upgraded to current Argon2 parameters")
        }
        Ok(false) => tracing::warn!(user_id = %user_id, "password hash upgrade found no such user"),
        Err(e) => tracing::warn!(user_id = %user_id, "could not store upgraded password hash: {e}"),
    }
}

/// Cut client-supplied metadata to a sane length, on a character boundary.
fn truncate_metadata(value: &str) -> String {
    if value.len() <= MAX_USER_AGENT_LENGTH {
        return value.to_string();
    }

    let mut end = MAX_USER_AGENT_LENGTH;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Long enough, not on any list.
    const GOOD_PASSWORD: &str = "korrekt-pferd-batterie-heftklammer";

    #[test]
    fn hash_password_produces_an_argon2id_phc_string() {
        let hash = hash_password(GOOD_PASSWORD).expect("hashing must succeed");

        assert!(
            hash.starts_with("$argon2id$"),
            "expected an Argon2id PHC string, got: {hash}"
        );
        // The chosen parameters must actually end up in the stored string,
        // otherwise `verify_password` would silently use different ones.
        assert!(
            hash.contains("m=19456,t=2,p=1"),
            "unexpected params: {hash}"
        );
        // The password must not appear anywhere in the output.
        assert!(!hash.contains(GOOD_PASSWORD));
    }

    #[test]
    fn verify_password_accepts_the_correct_password() {
        let hash = hash_password(GOOD_PASSWORD).expect("hashing must succeed");
        assert!(verify_password(GOOD_PASSWORD, &hash));
    }

    #[test]
    fn verify_password_rejects_a_wrong_password() {
        let hash = hash_password(GOOD_PASSWORD).expect("hashing must succeed");

        assert!(!verify_password(
            "korrekt-pferd-batterie-heftklammeR",
            &hash
        ));
        assert!(!verify_password("something-entirely-different", &hash));
        assert!(!verify_password("", &hash));
        // A prefix of the real password must not pass either.
        assert!(!verify_password("korrekt-pferd", &hash));
    }

    #[test]
    fn same_password_yields_different_hashes() {
        let first = hash_password(GOOD_PASSWORD).expect("hashing must succeed");
        let second = hash_password(GOOD_PASSWORD).expect("hashing must succeed");

        assert_ne!(
            first, second,
            "identical passwords must not produce identical hashes (missing salt?)"
        );
        // Both must still verify — different salt, same password.
        assert!(verify_password(GOOD_PASSWORD, &first));
        assert!(verify_password(GOOD_PASSWORD, &second));
    }

    #[test]
    fn tampered_hash_strings_are_rejected_without_panicking() {
        let hash = hash_password(GOOD_PASSWORD).expect("hashing must succeed");

        let broken = [
            String::new(),
            "not-a-hash".to_string(),
            "$argon2id$".to_string(),
            // Truncated after the parameters.
            "$argon2id$v=19$m=19456,t=2,p=1".to_string(),
            // Valid shape, garbage salt/hash.
            "$argon2id$v=19$m=19456,t=2,p=1$!!!!$!!!!".to_string(),
            // Unknown algorithm.
            hash.replace("argon2id", "argon2000"),
            // Absurd parameters — must not be honoured, must not allocate.
            "$argon2id$v=19$m=4294967295,t=4294967295,p=255$c29tZXNhbHQ$c29tZWhhc2g".to_string(),
            // The real hash with the digest flipped.
            {
                let mut h = hash.clone();
                let last = h.pop().unwrap_or('a');
                h.push(if last == 'A' { 'B' } else { 'A' });
                h
            },
            // The real hash with the salt cut short.
            hash.replacen('$', "$x", 1),
        ];

        for candidate in broken {
            assert!(
                !verify_password(GOOD_PASSWORD, &candidate),
                "tampered hash must not verify: {candidate:?}"
            );
        }
    }

    /// Rewrite the parameter field of a real PHC string. The digest no longer
    /// matches afterwards, which is exactly the point: the question is whether
    /// the parameters are *honoured* before anyone notices that.
    fn with_params(hash: &str, params: &str) -> String {
        hash.replace(
            &format!("m={ARGON2_MEMORY_KIB},t={ARGON2_ITERATIONS},p={ARGON2_PARALLELISM}"),
            params,
        )
    }

    #[test]
    fn excessive_cost_parameters_are_refused_before_any_allocation() {
        let hash = hash_password(GOOD_PASSWORD).expect("hashing must succeed");

        // The parameters that killed the process: 256 GiB, the maximum `Params`
        // accepts. This one is deliberately only run through the *predicate*,
        // never through `verify_password` — if the guard ever regressed, an
        // actual verification here would not fail the test, it would abort the
        // whole test binary, and an `abort` cannot be caught. Checking the pure
        // function proves the same thing and cannot allocate a byte.
        let lethal = with_params(&hash, "m=268435455,t=2,p=1");
        let parsed = PasswordHash::new(&lethal).expect("still a valid PHC string");
        assert!(
            !cost_params_are_acceptable(&parsed),
            "256 GiB memory cost must be refused"
        );

        // Everything else goes through the real entry point. The values are
        // above the limit but small enough that even a broken guard would only
        // be slow, not fatal — the test process stays alive either way.
        for params in [
            // Just over the memory bound.
            &format!("m={},t=2,p=1", MAX_VERIFY_MEMORY_KIB + 1) as &str,
            // Just over the iteration bound, memory at today's value.
            &format!("m={ARGON2_MEMORY_KIB},t={},p=1", MAX_VERIFY_ITERATIONS + 1),
            // Just over the parallelism bound.
            &format!("m={ARGON2_MEMORY_KIB},t=2,p={}", MAX_VERIFY_PARALLELISM + 1),
        ] {
            let tampered = with_params(&hash, params);
            assert_ne!(tampered, hash, "parameter rewrite must have taken effect");
            assert!(
                !verify_password(GOOD_PASSWORD, &tampered),
                "cost parameters above the limit must not verify: {params}"
            );
        }

        // The bound itself is inclusive, and staying inside it does not break
        // verification of a hash that is otherwise intact.
        let at_limit = with_params(
            &hash,
            &format!(
                "m={MAX_VERIFY_MEMORY_KIB},t={MAX_VERIFY_ITERATIONS},p={MAX_VERIFY_PARALLELISM}"
            ),
        );
        let parsed = PasswordHash::new(&at_limit).expect("still a valid PHC string");
        assert!(
            cost_params_are_acceptable(&parsed),
            "parameters exactly at the limit must be accepted"
        );
        assert!(verify_password(GOOD_PASSWORD, &hash));
    }

    /// A hash this server *produces* must be one it will later accept, and the
    /// caps must leave room for a future parameter bump. The arithmetic itself
    /// is enforced at compile time by the `const _: () = assert!(...)` block
    /// next to the constants — asserting it again here would be a constant
    /// expression and clippy rightly objects. What is checked here is the round
    /// trip through the real functions, which the compile-time assertions
    /// cannot see: parse a freshly produced PHC string and run it through the
    /// same predicate `verify_password` uses.
    #[test]
    fn own_parameters_are_within_the_verification_limits() {
        let hash = hash_password(GOOD_PASSWORD).expect("hashing must succeed");
        let parsed = PasswordHash::new(&hash).expect("own hash must parse");
        assert!(
            cost_params_are_acceptable(&parsed),
            "a freshly produced hash must pass the verification limits"
        );

        let params = Params::try_from(&parsed).expect("own hash must carry parameters");
        assert!(params.m_cost() <= MAX_VERIFY_MEMORY_KIB);
        assert!(params.t_cost() <= MAX_VERIFY_ITERATIONS);
        assert!(params.p_cost() <= MAX_VERIFY_PARALLELISM);
    }

    /// A PHC string produced with the parameters in use today (m=19456, t=2,
    /// p=1), frozen here on purpose: the point of this test is that lowering the
    /// *verification* caps does not invalidate hashes that are already stored in
    /// somebody's `data/tasks.db`. Re-generating it would defeat that.
    const STORED_HASH_TODAYS_PARAMS: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$5Bbg0pBNpV81OD6sqic0hg$smkTjAsFfvWL1rcIaAaGpacuMK9mL1ic+RK+srpL79U";

    #[test]
    fn a_hash_with_todays_parameters_still_verifies() {
        let parsed =
            PasswordHash::new(STORED_HASH_TODAYS_PARAMS).expect("frozen hash must still parse");
        let params = Params::try_from(&parsed).expect("frozen hash must carry parameters");
        assert_eq!(params.m_cost(), ARGON2_MEMORY_KIB);
        assert_eq!(params.t_cost(), ARGON2_ITERATIONS);
        assert_eq!(params.p_cost(), ARGON2_PARALLELISM);

        assert!(
            verify_password(GOOD_PASSWORD, STORED_HASH_TODAYS_PARAMS),
            "a hash stored before the caps were lowered must still verify"
        );
        assert!(!verify_password(
            "something else entirely",
            STORED_HASH_TODAYS_PARAMS
        ));
        assert!(
            !needs_rehash(STORED_HASH_TODAYS_PARAMS),
            "today's parameters must not be flagged for re-hashing"
        );
    }

    /// Measurement, not a unit test: it deliberately runs the most expensive
    /// hash the verifier still accepts, which takes seconds. `#[ignore]`d so a
    /// normal `cargo test` stays fast; run it with
    /// `cargo test --release -- --ignored --nocapture` when the caps change.
    ///
    /// The claim it defends is the one in the parameter comment at the top of
    /// this file: the worst case an attacker with database write access can
    /// force onto a login attempt stays in the single-digit seconds.
    #[test]
    #[ignore = "measurement: runs the most expensive accepted Argon2 configuration"]
    fn worst_accepted_cost_parameters_stay_under_ten_seconds() {
        let params = Params::new(
            MAX_VERIFY_MEMORY_KIB,
            MAX_VERIFY_ITERATIONS,
            MAX_VERIFY_PARALLELISM,
            None,
        )
        .expect("the caps must be a valid Argon2 configuration");

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(GOOD_PASSWORD.as_bytes(), &salt)
            .expect("hashing at the caps must succeed")
            .to_string();

        let started = std::time::Instant::now();
        assert!(verify_password(GOOD_PASSWORD, &hash));
        let elapsed = started.elapsed();

        println!(
            "worst accepted configuration m={MAX_VERIFY_MEMORY_KIB}, \
             t={MAX_VERIFY_ITERATIONS}, p={MAX_VERIFY_PARALLELISM} verified in {elapsed:.2?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "the most expensive accepted hash must verify in under 10 s, took {elapsed:.2?}"
        );
    }

    #[test]
    fn policy_accepts_reasonable_passwords() {
        for password in [
            GOOD_PASSWORD,
            "Tr0ubadour&3xtra",
            "ganz normale passphrase",
            "größere-passphrase-mit-umlauten",
            // Umlauts and sharp s, mixed case, a year at the end — the shape a
            // German-speaking user actually picks.
            "Schöne Grüße aus Köln 2026",
            "Wüstenrot-Bausparvertrag-12",
            "olivenöl-und-rosmarin-brot",
            // CJK and Hangul: non-ASCII must never be judged as a keyboard
            // walk, and the character count (not the byte count) decides the
            // length. Both of these are twelve characters.
            "日本語のパスワードです安全",
            "안녕하세요반갑습니다친구여",
            // Ordinary passphrases. `hijklmnop-...` is the interesting one: it
            // contains a nine-character alphabetical run and must still pass,
            // because the run does not carry the whole password.
            "mein hund heisst waldemar",
            "the quick brown fox jumps",
            "purple-tractor-mountain-97",
            "sommerregen-im-november",
            "hijklmnop-is-not-my-password",
            "abstractionlayer42",
            "defenestration-tuesday",
        ] {
            assert_eq!(
                validate_password(password),
                Ok(()),
                "should have been accepted: {password}"
            );
        }
    }

    #[test]
    fn policy_rejects_short_passwords() {
        assert_eq!(
            validate_password("short"),
            Err(PasswordPolicyError::TooShort {
                min: MIN_PASSWORD_LENGTH
            })
        );
        // Exactly one character below the limit.
        let almost = "a1B2c3D4e5!".to_string();
        assert_eq!(almost.chars().count(), MIN_PASSWORD_LENGTH - 1);
        assert_eq!(
            validate_password(&almost),
            Err(PasswordPolicyError::TooShort {
                min: MIN_PASSWORD_LENGTH
            })
        );
        // Exactly at the limit is fine.
        assert_eq!(validate_password(&format!("{almost}Z")), Ok(()));
    }

    #[test]
    fn policy_rejects_blank_and_overlong_passwords() {
        assert_eq!(validate_password(""), Err(PasswordPolicyError::Blank));
        assert_eq!(
            validate_password("               "),
            Err(PasswordPolicyError::Blank)
        );
        assert_eq!(
            validate_password(&"a".repeat(MAX_PASSWORD_LENGTH + 1)),
            Err(PasswordPolicyError::TooLong {
                max: MAX_PASSWORD_LENGTH
            })
        );
    }

    #[test]
    fn policy_rejects_obviously_weak_passwords() {
        for password in [
            "password123",
            "PASSWORD123",
            "  Password123  ",
            "1234567890",
            "administrator",
            "rclone-gui",
            "changeme123",
            // Weak stem plus a year.
            "rclone2024",
            "welcome2025",
            // Repeated single character / straight runs.
            "aaaaaaaaaaaaaa",
            "abcdefghijklmn",
            "nmlkjihgfedcba",
            // Digit runs that survive a wrap: the run detection must not fall
            // over a single irregular step.
            "123456789012",
            "1234567890123",
            "987654321098",
            // Keyboard walks, including one that continues into the next row,
            // and the same walks backwards.
            "qwertyuiopas",
            "qwertzuiopasd",
            "asdfghjklzxcv",
            "poiuytrewq",
            "mnbvcxzlkjhgf",
        ] {
            assert_eq!(
                validate_password(password),
                Err(PasswordPolicyError::TooCommon),
                "should have been rejected as weak: {password}"
            );
        }
    }

    /// The candidates a tester found still slipping through, verbatim from the
    /// ticket, plus the neighbouring shapes of the same four families. Each
    /// family is annotated with the check that is supposed to catch it, so a
    /// later regression points at a mechanism and not just at a string.
    #[test]
    fn policy_rejects_the_reported_weak_candidates() {
        for password in [
            // Reported verbatim.
            "qwerty123456",
            "qwerty1234567",
            "QWERTY123456",
            "1234567890qw",
            "0987654321ab",
            "qazwsxedcrfv",
            "1q2w3e4r5t6y",
            "abcabcabcabc",
            "112233445566",
            "P@ssw0rd1234",
            // A weak stem glued to a digit run — `is_built_from_weak_segments`.
            // No single check covers the whole string in any of these.
            "asdfghjkl123",
            "zxcvbnm12345",
            "letmein12345",
            "welcome12345",
            "adminadmin12",
            "qwertzuiop12",
            "poiuytrewq12",
            "0123456789ab",
            // Vertical keyboard traversals — the `KEYBOARD_ROWS` entries that
            // walk down the columns instead of along the rows.
            "1qaz2wsx3edc4rfv",
            "zaq1xsw2cde3",
            "1q2w3e4r5t",
            // Repeated blocks — `is_block_repetition`.
            "qwertyqwerty",
            "123123123123",
            "xxxxxxxxxxxx",
            // Doubled characters hiding a run — caught only after
            // `collapse_repeats`.
            "aabbccddeeff",
            // Leetspeak on a known-weak stem — `matches_weak_word` via
            // `unleet`, with the trailing digits stripped first.
            "p@ssw0rd",
            "P4ssword2024",
            "adm1n1strator",
        ] {
            assert_eq!(
                validate_password(password),
                Err(PasswordPolicyError::TooCommon),
                "should have been rejected as weak: {password}"
            );
        }
    }

    /// The mechanisms behind the test above, exercised directly. When a
    /// candidate above starts passing, these say which of the four checks broke.
    #[test]
    fn weak_pattern_detectors_recognise_their_own_shapes() {
        assert!(is_block_repetition("abcabcabcabc"));
        assert!(is_block_repetition("123123123"));
        assert!(is_block_repetition("xyxyxyxyxy"));
        // Two repetitions are not enough — see the note on the function.
        assert!(!is_block_repetition("berlinberlin"));

        assert_eq!(collapse_repeats("112233445566"), "123456");
        assert_eq!(collapse_repeats("aabbcc"), "abc");
        assert_eq!(collapse_repeats("abc"), "abc");

        assert!(is_keyboard_walk("qazwsxedcrfv"));
        assert!(is_keyboard_walk("1q2w3e4r5t6y"));
        assert!(is_keyboard_walk("vfrcdexswzaq"), "and backwards");

        assert!(is_built_from_weak_segments("qwerty123456"));
        assert!(is_built_from_weak_segments("1234567890qw"));
        // A passphrase must not tile itself out of accidental fragments.
        assert!(!is_built_from_weak_segments(
            "korrekt-pferd-batterie-heftklammer"
        ));
        assert!(!is_built_from_weak_segments("the quick brown fox jumps"));

        // Non-ASCII is never a keyboard walk, whatever its shape.
        assert!(!is_keyboard_walk("日本語のパスワードです安全"));
        assert!(!contains_keyboard_walk("größere"));
    }

    #[test]
    fn policy_errors_do_not_leak_the_password() {
        let err = validate_password("password123").expect_err("must be rejected");
        let rendered = format!("{err}");
        assert!(!rendered.contains("password123"));
        assert!(!format!("{err:?}").contains("password123"));
    }

    #[test]
    fn needs_rehash_flags_weaker_and_foreign_hashes() {
        let current = hash_password(GOOD_PASSWORD).expect("hashing must succeed");
        assert!(!needs_rehash(&current));

        // Same algorithm, but below the current memory cost.
        let weak_params = Params::new(8 * 1024, 1, 1, None).expect("valid params");
        let salt = SaltString::generate(&mut OsRng);
        let weak = Argon2::new(Algorithm::Argon2id, Version::V0x13, weak_params)
            .hash_password(GOOD_PASSWORD.as_bytes(), &salt)
            .expect("hashing must succeed")
            .to_string();
        assert!(needs_rehash(&weak));
        // ...and it must still verify, otherwise upgrading would lock users out.
        assert!(verify_password(GOOD_PASSWORD, &weak));

        // A different algorithm family must be flagged, not trusted.
        let argon2i = Argon2::new(
            Algorithm::Argon2i,
            Version::V0x13,
            Params::new(
                ARGON2_MEMORY_KIB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                None,
            )
            .expect("valid params"),
        )
        .hash_password(GOOD_PASSWORD.as_bytes(), &SaltString::generate(&mut OsRng))
        .expect("hashing must succeed")
        .to_string();
        assert!(needs_rehash(&argon2i));
    }

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------

    /// Minimal throwaway temp directory, mirroring the helper in
    /// `database.rs` — the crate has no dev dependency on `tempfile`.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rclone-gui-auth-test-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A migrated pool on a temporary on-disk database.
    async fn temp_pool() -> (Pool<Sqlite>, TempDir) {
        let dir = TempDir::new();
        let url = format!("sqlite:{}?mode=rwc", dir.0.join("test.db").display());
        let pool = database::connect(&url).await.expect("connect");
        database::run_migrations(&pool).await.expect("migrate");
        (pool, dir)
    }

    /// Store a user with `password`, hashed with the current parameters.
    async fn seed_user(pool: &Pool<Sqlite>, id: &str, username: &str, password: &str) -> User {
        seed_user_with_hash(
            pool,
            id,
            username,
            &hash_password(password).expect("hashing must succeed"),
        )
        .await
    }

    async fn seed_user_with_hash(
        pool: &Pool<Sqlite>,
        id: &str,
        username: &str,
        password_hash: &str,
    ) -> User {
        let user = User {
            id: id.to_string(),
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            role: "user".to_string(),
            home_path: format!("/data/home/{username}"),
            is_active: true,
            created_at: Utc::now(),
            last_login_at: None,
        };
        database::create_user(pool, &user)
            .await
            .expect("create user");
        user
    }

    #[test]
    fn tokens_are_long_unique_and_hex() {
        let mut seen = std::collections::HashSet::new();

        for _ in 0..256 {
            let token = generate_session_token().expect("RNG must work");
            let raw = token.expose();

            assert_eq!(
                raw.len(),
                SESSION_TOKEN_HEX_LENGTH,
                "token must encode {SESSION_TOKEN_BYTES} bytes"
            );
            assert!(is_well_formed_token(raw), "unexpected token shape: {raw}");
            assert!(seen.insert(raw.to_string()), "token repeated: {raw}");
        }
    }

    #[test]
    fn token_debug_output_does_not_leak_the_token() {
        let token = generate_session_token().expect("RNG must work");
        let rendered = format!("{token:?}");

        assert!(
            !rendered.contains(token.expose()),
            "token leaked: {rendered}"
        );
        assert_eq!(rendered, "SessionToken(<redacted>)");
    }

    /// The `Renewed` arm carries the whole `Set-Cookie` header, token included.
    /// A derived `Debug` printed it in clear text once; this test is what keeps
    /// somebody from re-deriving it.
    #[test]
    fn session_refresh_debug_is_redacted() {
        let config = SessionConfig::default();
        let token = generate_session_token().expect("RNG must work");
        let raw = token.expose().to_string();
        let set_cookie = config.build_session_cookie(&token);
        assert!(
            set_cookie.contains(&raw),
            "precondition: the cookie must actually carry the token"
        );

        let now = Utc::now();
        let session = database::Session {
            id: token.hash(),
            user_id: "user-1".to_string(),
            created_at: now,
            expires_at: now + ChronoDuration::hours(1),
            user_agent: None,
            ip: None,
        };

        let renewed = SessionRefresh::Renewed {
            session: session.clone(),
            set_cookie: Some(set_cookie.clone()),
        };
        let rendered = format!("{renewed:?}");

        assert!(!rendered.contains(&raw), "the token leaked: {rendered}");
        // Not even a prefix — a truncated token still identifies the session.
        assert!(!rendered.contains(&raw[..8]), "a token prefix leaked");
        // The session key (the digest) must not appear either.
        assert!(
            !rendered.contains(&session.id),
            "the session id leaked: {rendered}"
        );
        // Redacted, not dropped: whether a cookie was rebuilt is the part that
        // makes this output worth reading.
        assert!(
            rendered.contains("set_cookie: \"Some(<redacted>)\""),
            "the field must still be visible as redacted: {rendered}"
        );
        assert!(rendered.contains("user_id: \"user-1\""));

        // The other two arms are plain, and `None` must be distinguishable.
        let no_cookie = SessionRefresh::Renewed {
            session,
            set_cookie: None,
        };
        assert!(format!("{no_cookie:?}").contains("set_cookie: \"None\""));
        assert_eq!(format!("{:?}", SessionRefresh::Unchanged), "Unchanged");
        assert_eq!(format!("{:?}", SessionRefresh::Expired), "Expired");
    }

    #[test]
    fn token_hash_is_stable_one_way_and_distinct() {
        let a = generate_session_token().expect("RNG must work");
        let b = generate_session_token().expect("RNG must work");

        assert_eq!(a.hash(), a.hash(), "hashing must be deterministic");
        assert_ne!(a.hash(), b.hash());
        assert_eq!(a.hash().len(), 64, "SHA-256 in hex");
        // The hash must not contain (or be) the token.
        assert_ne!(a.hash(), a.expose());
        assert!(!a.hash().contains(a.expose()));
        // Known-answer check, so a future change of hash function is noticed.
        assert_eq!(
            hash_session_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn malformed_tokens_are_rejected_before_any_lookup() {
        for candidate in [
            "",
            "short",
            &"a".repeat(SESSION_TOKEN_HEX_LENGTH - 1),
            &"a".repeat(SESSION_TOKEN_HEX_LENGTH + 1),
            // Uppercase hex is not what we issue.
            &"A".repeat(SESSION_TOKEN_HEX_LENGTH),
            // Right length, not hex.
            &"z".repeat(SESSION_TOKEN_HEX_LENGTH),
            "../../etc/passwd",
        ] {
            assert!(
                !is_well_formed_token(candidate),
                "should have been rejected: {candidate:?}"
            );
        }
    }

    #[test]
    fn cookie_carries_all_required_attributes() {
        let config = SessionConfig::default();
        let token = generate_session_token().expect("RNG must work");
        let cookie = config.build_session_cookie(&token);

        assert!(cookie.starts_with(&format!("{}={}", config.cookie_name, token.expose())));
        for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
            assert!(
                cookie.contains(attribute),
                "missing {attribute} in: {cookie}"
            );
        }
        assert!(cookie.contains(&format!("Max-Age={}", 24 * 3600)));
    }

    #[test]
    fn cookie_expiry_follows_the_configuration() {
        let config = SessionConfig {
            ttl_hours: 2,
            ..SessionConfig::default()
        };

        assert_eq!(config.max_age_seconds(), 7200);
        assert_eq!(config.ttl().num_hours(), 2);
        let token = generate_session_token().expect("RNG must work");
        assert!(config.build_session_cookie(&token).contains("Max-Age=7200"));
    }

    #[test]
    fn clearing_cookie_expires_immediately_and_keeps_the_flags() {
        let config = SessionConfig::default();
        let cookie = config.build_clearing_cookie();

        assert!(cookie.starts_with(&format!("{}=;", config.cookie_name)));
        assert!(cookie.contains("Max-Age=0"));
        for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
            assert!(
                cookie.contains(attribute),
                "missing {attribute} in: {cookie}"
            );
        }
    }

    #[test]
    fn secure_can_be_switched_off_but_never_by_default() {
        assert!(SessionConfig::default().secure);

        let insecure = SessionConfig {
            secure: false,
            ..SessionConfig::default()
        };
        let token = generate_session_token().expect("RNG must work");
        let cookie = insecure.build_session_cookie(&token);
        assert!(!cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn cookie_header_parsing_finds_only_well_formed_tokens() {
        let token = generate_session_token().expect("RNG must work");
        let raw = token.expose();
        let name = DEFAULT_SESSION_COOKIE_NAME;

        assert_eq!(
            session_token_from_cookie_header(&format!("{name}={raw}"), name).as_deref(),
            Some(raw)
        );
        assert_eq!(
            session_token_from_cookie_header(&format!("theme=dark; {name}={raw}; foo=bar"), name)
                .as_deref(),
            Some(raw)
        );
        assert_eq!(
            session_token_from_cookie_header(&format!("theme=dark; {name}=\"{raw}\""), name)
                .as_deref(),
            Some(raw)
        );

        // A valueless flag cookie in front of ours must not swallow the token.
        assert_eq!(
            session_token_from_cookie_header(&format!("flag; {name}={raw}"), name).as_deref(),
            Some(raw)
        );
        assert_eq!(
            session_token_from_cookie_header(&format!("theme=dark; flag; {name}={raw}; x"), name)
                .as_deref(),
            Some(raw)
        );

        // Absent, malformed or a different cookie: nothing.
        assert!(session_token_from_cookie_header("theme=dark", name).is_none());
        assert!(session_token_from_cookie_header("flag; other-flag", name).is_none());
        assert!(session_token_from_cookie_header("", name).is_none());
        assert!(session_token_from_cookie_header(&format!("{name}=nonsense"), name).is_none());
        assert!(session_token_from_cookie_header(&format!("other={raw}"), name).is_none());
    }

    #[test]
    fn cookie_names_from_the_environment_are_validated() {
        assert!(is_valid_cookie_name(DEFAULT_SESSION_COOKIE_NAME));
        assert!(is_valid_cookie_name("my.session-1"));
        for bad in [
            "",
            "with space",
            "semi;colon",
            "eq=uals",
            "quote\"d",
            "nl\n",
        ] {
            assert!(!is_valid_cookie_name(bad), "should be invalid: {bad:?}");
        }
    }

    #[test]
    fn constant_time_comparison_still_compares_correctly() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }

    #[tokio::test]
    async fn login_stores_the_hash_and_never_the_token() {
        let (pool, dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let config = SessionConfig::default();
        let outcome = login(
            &pool,
            &config,
            "alice",
            GOOD_PASSWORD,
            Some("test-agent"),
            Some("127.0.0.1"),
        )
        .await
        .expect("login must succeed");

        let raw = outcome.token.expose().to_string();

        // The stored id is the hash of the token.
        let stored: Vec<(String,)> = sqlx::query_as("SELECT id FROM sessions")
            .fetch_all(&pool)
            .await
            .expect("read sessions");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, hash_session_token(&raw));
        assert_ne!(stored[0].0, raw);

        // Nothing anywhere in the database file holds the plaintext token.
        pool.close().await;
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir.0).expect("read temp dir") {
            let path = entry.expect("dir entry").path();
            let bytes = std::fs::read(&path).expect("read db file");
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&raw),
                "raw token found in {}",
                path.display()
            );
            checked += 1;
        }
        assert!(checked > 0, "no database file was inspected");

        // ...and it is in the cookie, with the flags.
        assert!(outcome.set_cookie.contains(&raw));
        assert!(outcome.set_cookie.contains("HttpOnly"));
        assert!(outcome.set_cookie.contains("Secure"));
        assert!(outcome.set_cookie.contains("SameSite=Lax"));

        // The whole outcome must be safe to hand to `tracing::debug!(?outcome)`:
        // no raw token (neither bare nor inside the Set-Cookie value), no
        // password hash, no session id.
        let rendered = format!("{outcome:?}");
        assert!(
            !rendered.contains(&raw),
            "raw session token leaked through Debug: {rendered}"
        );
        assert!(
            !rendered.contains(&outcome.user.password_hash),
            "password hash leaked through Debug: {rendered}"
        );
        assert!(
            !rendered.contains(&outcome.session.id),
            "session id leaked through Debug: {rendered}"
        );
        assert!(!rendered.contains("$argon2"), "hash prefix in: {rendered}");
        assert!(!rendered.contains("HttpOnly"), "cookie in: {rendered}");
        // What it *does* show is enough to identify the login.
        assert!(rendered.contains("alice"));
        assert!(rendered.contains("<redacted>"));
    }

    #[tokio::test]
    async fn login_opens_a_session_that_authenticates() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let config = SessionConfig::default();
        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login must succeed");

        let (session, user) = authenticate_session(&pool, outcome.token.expose())
            .await
            .expect("lookup must not fail")
            .expect("session must be valid");

        assert_eq!(user.id, "u1");
        assert_eq!(session.user_id, "u1");
        // The expiry follows the configuration (allowing a minute of slack).
        let expected = Utc::now() + config.ttl();
        assert!((session.expires_at - expected).num_seconds().abs() < 60);

        // last_login_at was recorded.
        let stored = database::get_user_by_id(&pool, "u1")
            .await
            .expect("read user")
            .expect("user exists");
        assert!(stored.last_login_at.is_some());
    }

    #[tokio::test]
    async fn login_rejects_wrong_password_unknown_user_and_disabled_account() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        assert!(matches!(
            login(
                &pool,
                &config,
                "alice",
                "wrong-password-entirely",
                None,
                None
            )
            .await,
            Err(LoginError::InvalidCredentials)
        ));
        assert!(matches!(
            login(&pool, &config, "mallory", GOOD_PASSWORD, None, None).await,
            Err(LoginError::InvalidCredentials)
        ));

        database::set_user_active(&pool, "u1", false)
            .await
            .expect("deactivate");
        assert!(matches!(
            login(&pool, &config, "alice", GOOD_PASSWORD, None, None).await,
            Err(LoginError::AccountDisabled)
        ));
        // A wrong password on a disabled account must not reveal the state.
        assert!(matches!(
            login(
                &pool,
                &config,
                "alice",
                "wrong-password-entirely",
                None,
                None
            )
            .await,
            Err(LoginError::InvalidCredentials)
        ));

        // No failed attempt created a session.
        assert!(database::get_sessions_for_user(&pool, "u1")
            .await
            .expect("read sessions")
            .is_empty());
    }

    #[tokio::test]
    async fn expired_sessions_are_not_accepted() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let token = generate_session_token().expect("RNG must work");
        let session = Session {
            id: token.hash(),
            user_id: "u1".to_string(),
            created_at: Utc::now() - ChronoDuration::hours(48),
            expires_at: Utc::now() - ChronoDuration::minutes(1),
            user_agent: None,
            ip: None,
        };
        database::create_session(&pool, &session)
            .await
            .expect("store session");

        assert!(authenticate_session(&pool, token.expose())
            .await
            .expect("lookup must not fail")
            .is_none());
        // The row is still there — rejecting and cleaning up are separate.
        assert!(database::get_session_by_hash(&pool, &token.hash())
            .await
            .expect("lookup")
            .is_some());
    }

    #[tokio::test]
    async fn unknown_and_malformed_tokens_are_not_accepted() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let unknown = generate_session_token().expect("RNG must work");
        assert!(authenticate_session(&pool, unknown.expose())
            .await
            .expect("lookup")
            .is_none());
        assert!(authenticate_session(&pool, "not-a-token")
            .await
            .expect("lookup")
            .is_none());
        assert!(authenticate_session(&pool, "")
            .await
            .expect("lookup")
            .is_none());
    }

    #[tokio::test]
    async fn deactivating_an_account_invalidates_its_sessions() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let outcome = login(
            &pool,
            &SessionConfig::default(),
            "alice",
            GOOD_PASSWORD,
            None,
            None,
        )
        .await
        .expect("login must succeed");

        database::set_user_active(&pool, "u1", false)
            .await
            .expect("deactivate");

        assert!(authenticate_session(&pool, outcome.token.expose())
            .await
            .expect("lookup")
            .is_none());
    }

    #[tokio::test]
    async fn logout_invalidates_the_session_server_side() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let config = SessionConfig::default();
        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login must succeed");
        let raw = outcome.token.expose().to_string();

        assert!(logout(&pool, &raw).await.expect("logout"));

        // Gone from the database, not just from the browser.
        assert!(
            database::get_session_by_hash(&pool, &hash_session_token(&raw))
                .await
                .expect("lookup")
                .is_none()
        );
        assert!(authenticate_session(&pool, &raw)
            .await
            .expect("lookup")
            .is_none());

        // Logging out twice is not an error, it just removes nothing.
        assert!(!logout(&pool, &raw).await.expect("logout"));
        assert!(!logout(&pool, "garbage").await.expect("logout"));

        // The clearing cookie carries the same attributes.
        let cleared = config.build_clearing_cookie();
        assert!(!cleared.contains(&raw));
        assert!(cleared.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn logout_all_sessions_drops_every_login_of_that_user() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        seed_user(&pool, "u2", "bob", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        let alice_a = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let alice_b = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let bob = login(&pool, &config, "bob", GOOD_PASSWORD, None, None)
            .await
            .expect("login");

        // Two logins of the same account must not share a token.
        assert_ne!(alice_a.token.expose(), alice_b.token.expose());

        assert_eq!(logout_all_sessions(&pool, "u1").await.expect("logout"), 2);

        for token in [&alice_a.token, &alice_b.token] {
            assert!(authenticate_session(&pool, token.expose())
                .await
                .expect("lookup")
                .is_none());
        }
        // Bob is untouched.
        assert!(authenticate_session(&pool, bob.token.expose())
            .await
            .expect("lookup")
            .is_some());
    }

    /// A session that is used all the way through the old hard limit stays
    /// alive — the point of the ticket. Twelve simulated hops of two hours each
    /// carry it past 24 h without a single re-login.
    #[tokio::test]
    async fn continuous_activity_carries_a_session_past_the_old_hard_limit() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let raw = outcome.token.expose().to_string();
        let created_at = outcome.session.created_at;

        let mut renewals = 0;
        for hop in 1..=12 {
            let now = created_at + ChronoDuration::hours(hop * 2);
            let session = database::get_valid_session(&pool, &outcome.token.hash(), now)
                .await
                .expect("lookup")
                .unwrap_or_else(|| panic!("session already gone after {} h", hop * 2));

            match refresh_session(&pool, &config, &raw, &session, now)
                .await
                .expect("refresh")
            {
                SessionRefresh::Renewed { session, .. } => {
                    renewals += 1;
                    assert!(session.expires_at > now);
                }
                SessionRefresh::Unchanged => {}
                SessionRefresh::Expired => panic!("expired after {} h of activity", hop * 2),
            }
        }

        // Still valid 26 hours in — the old behaviour logged out at 24.
        let after = created_at + ChronoDuration::hours(26);
        assert!(
            database::get_valid_session(&pool, &outcome.token.hash(), after)
                .await
                .expect("lookup")
                .is_some()
        );

        // And it cost a handful of writes, not one per request: with a 24 h
        // window renewed at half, twelve two-hour hops touch the row twice.
        assert!(
            renewals <= 2,
            "{renewals} writes for 12 requests — the threshold is not holding"
        );
    }

    /// The cheap path really is cheap: while more than half the window is left,
    /// no statement is issued and nothing changes.
    #[tokio::test]
    async fn an_early_request_does_not_write() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let raw = outcome.token.expose().to_string();

        for minutes in [0, 1, 60, 11 * 60] {
            let now = outcome.session.created_at + ChronoDuration::minutes(minutes);
            assert!(
                matches!(
                    refresh_session(&pool, &config, &raw, &outcome.session, now)
                        .await
                        .expect("refresh"),
                    SessionRefresh::Unchanged
                ),
                "a request {minutes} min into a 24 h window must not renew"
            );
        }

        let stored = database::get_session_by_hash(&pool, &outcome.token.hash())
            .await
            .expect("lookup")
            .expect("session");
        assert_eq!(stored.expires_at, outcome.session.expires_at);
    }

    /// The other half of the pair: without activity the session still dies.
    #[tokio::test]
    async fn an_idle_session_still_expires() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");

        let after = outcome.session.created_at + ChronoDuration::hours(25);
        assert!(
            database::get_valid_session(&pool, &outcome.token.hash(), after)
                .await
                .expect("lookup")
                .is_none()
        );
        // And the renewal path cannot bring it back.
        assert!(database::renew_session(
            &pool,
            &outcome.token.hash(),
            after,
            after + config.ttl(),
            config.renewal_deadline(after),
        )
        .await
        .expect("renew")
        .is_none());
    }

    /// The limit that makes the sliding window safe: no amount of activity gets
    /// a session past its absolute lifetime.
    #[tokio::test]
    async fn activity_cannot_push_a_session_past_its_absolute_lifetime() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        // Short windows so the arithmetic is readable; the shape is the same.
        let config = SessionConfig {
            ttl_hours: 2,
            max_lifetime_hours: 5,
            ..SessionConfig::default()
        };

        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let raw = outcome.token.expose().to_string();
        let created_at = outcome.session.created_at;
        let cap = created_at + ChronoDuration::hours(5);

        // Knock every half hour, the way an open tab with a poller would.
        let mut minutes = 30;
        let mut last_seen = outcome.session.expires_at;
        while minutes <= 4 * 60 + 30 {
            let now = created_at + ChronoDuration::minutes(minutes);
            let session = database::get_valid_session(&pool, &outcome.token.hash(), now)
                .await
                .expect("lookup")
                .unwrap_or_else(|| panic!("session gone after {minutes} min"));

            if let SessionRefresh::Renewed { session, .. } =
                refresh_session(&pool, &config, &raw, &session, now)
                    .await
                    .expect("refresh")
            {
                last_seen = session.expires_at;
            }
            assert!(
                last_seen <= cap,
                "renewal pushed the deadline past the absolute cap"
            );
            minutes += 30;
        }

        // Five hours in it is over, however busy the client was.
        let past_cap = created_at + ChronoDuration::hours(5) + ChronoDuration::minutes(1);
        assert!(
            database::get_valid_session(&pool, &outcome.token.hash(), past_cap)
                .await
                .expect("lookup")
                .is_none(),
            "a continuously used session outlived its absolute lifetime"
        );
    }

    /// Lowering the cap on a running database must take effect at once, not at
    /// the deadline the row was written with. This is the read-path check.
    #[tokio::test]
    async fn a_lowered_absolute_lifetime_ends_a_running_session() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let generous = SessionConfig::default();
        let outcome = login(&pool, &generous, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let raw = outcome.token.expose().to_string();

        let strict = SessionConfig {
            ttl_hours: 1,
            max_lifetime_hours: 1,
            ..SessionConfig::default()
        };
        let now = outcome.session.created_at + ChronoDuration::hours(2);

        assert!(matches!(
            refresh_session(&pool, &strict, &raw, &outcome.session, now)
                .await
                .expect("refresh"),
            SessionRefresh::Expired
        ));
        // Expiring it here also removes the row, so the stale deadline cannot
        // be found by anybody else either.
        assert!(database::get_session_by_hash(&pool, &outcome.token.hash())
            .await
            .expect("lookup")
            .is_none());
    }

    /// The security-relevant one: a renewable session must not survive
    /// `logout_all_sessions` — that call is what a password reset relies on.
    #[tokio::test]
    async fn logout_all_sessions_beats_a_pending_renewal() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let raw = outcome.token.expose().to_string();

        // A moment at which the session is due for renewal.
        let now = outcome.session.created_at + ChronoDuration::hours(13);
        let due = database::get_valid_session(&pool, &outcome.token.hash(), now)
            .await
            .expect("lookup")
            .expect("session");

        assert_eq!(logout_all_sessions(&pool, "u1").await.expect("logout"), 1);

        // The renewal now has nothing to renew, and above all it must not
        // recreate what the logout deleted.
        assert!(matches!(
            refresh_session(&pool, &config, &raw, &due, now)
                .await
                .expect("refresh"),
            SessionRefresh::Unchanged
        ));
        assert!(database::get_session_by_hash(&pool, &outcome.token.hash())
            .await
            .expect("lookup")
            .is_none());
        assert!(authenticate_session(&pool, &raw)
            .await
            .expect("lookup")
            .is_none());
    }

    /// The criterion the single-statement renewal exists for. Read-then-write
    /// passes every sequential test above and fails this one: it would produce
    /// one write per racing request instead of one in total.
    ///
    /// Built to actually race — several OS threads, a barrier so every task
    /// reaches the renewal at the same moment, and more tasks than the pool has
    /// connections, so they queue on SQLite's write lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_renew_a_session_exactly_once() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = std::sync::Arc::new(SessionConfig::default());

        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let raw = outcome.token.expose().to_string();
        let hash = outcome.token.hash();
        // Due for renewal: more than half the window has gone.
        let now = outcome.session.created_at + ChronoDuration::hours(13);
        let session = database::get_valid_session(&pool, &hash, now)
            .await
            .expect("lookup")
            .expect("session");

        const REQUESTS: usize = 24;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(REQUESTS));

        let mut handles = Vec::new();
        for _ in 0..REQUESTS {
            let pool = pool.clone();
            let config = config.clone();
            let raw = raw.clone();
            let session = session.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                matches!(
                    refresh_session(&pool, &config, &raw, &session, now).await,
                    Ok(SessionRefresh::Renewed { .. })
                )
            }));
        }

        let mut renewed = 0;
        for handle in handles {
            if handle.await.expect("join") {
                renewed += 1;
            }
        }

        assert_eq!(
            renewed, 1,
            "{REQUESTS} simultaneous requests produced {renewed} writes instead of one"
        );
        let stored = database::get_session_by_hash(&pool, &hash)
            .await
            .expect("lookup")
            .expect("session");
        assert_eq!(stored.expires_at, config.slid_expiry(&session, now));
        assert!(stored.expires_at <= config.absolute_deadline(&session));
    }

    /// The renewal hands the browser a fresh `Max-Age` for the token it already
    /// holds — and never a different token. Rotating on a sliding renewal would
    /// log out whichever parallel request still carried the old cookie.
    #[tokio::test]
    async fn a_renewal_refreshes_the_cookie_without_rotating_the_token() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        let outcome = login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
            .await
            .expect("login");
        let raw = outcome.token.expose().to_string();
        let now = outcome.session.created_at + ChronoDuration::hours(13);
        let session = database::get_valid_session(&pool, &outcome.token.hash(), now)
            .await
            .expect("lookup")
            .expect("session");

        let SessionRefresh::Renewed { set_cookie, .. } =
            refresh_session(&pool, &config, &raw, &session, now)
                .await
                .expect("refresh")
        else {
            panic!("a session past half its window must be renewed");
        };
        let cookie = set_cookie.expect("a renewal must refresh the cookie");

        assert!(
            cookie.contains(&raw),
            "the cookie must carry the same token"
        );
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
        // Roughly the full window again — computed from the stored deadline, so
        // the browser copy cannot outlive the server one.
        assert!(cookie.contains(&format!("Max-Age={}", 24 * 3600)));

        // A malformed token is never echoed back into a header.
        assert!(config.refresh_session_cookie("nope", 60).is_none());
    }

    #[tokio::test]
    async fn cleanup_removes_only_expired_sessions() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let live = generate_session_token().expect("RNG must work");
        let dead = generate_session_token().expect("RNG must work");

        for (token, expires_in) in [
            (&live, ChronoDuration::hours(1)),
            (&dead, ChronoDuration::minutes(-1)),
        ] {
            database::create_session(
                &pool,
                &Session {
                    id: token.hash(),
                    user_id: "u1".to_string(),
                    created_at: Utc::now(),
                    expires_at: Utc::now() + expires_in,
                    user_agent: None,
                    ip: None,
                },
            )
            .await
            .expect("store session");
        }

        assert_eq!(cleanup_expired_sessions(&pool).await.expect("cleanup"), 1);
        assert!(database::get_session_by_hash(&pool, &dead.hash())
            .await
            .expect("lookup")
            .is_none());
        assert!(database::get_session_by_hash(&pool, &live.hash())
            .await
            .expect("lookup")
            .is_some());

        // Idempotent: a second run finds nothing left to do.
        assert_eq!(cleanup_expired_sessions(&pool).await.expect("cleanup"), 0);
    }

    #[tokio::test]
    async fn login_upgrades_an_outdated_password_hash() {
        let (pool, _dir) = temp_pool().await;

        // A hash with parameters below the current ones.
        let weak_params = Params::new(8 * 1024, 1, 1, None).expect("valid params");
        let outdated = Argon2::new(Algorithm::Argon2id, Version::V0x13, weak_params)
            .hash_password(GOOD_PASSWORD.as_bytes(), &SaltString::generate(&mut OsRng))
            .expect("hashing must succeed")
            .to_string();
        assert!(needs_rehash(&outdated));

        seed_user_with_hash(&pool, "u1", "alice", &outdated).await;

        login(
            &pool,
            &SessionConfig::default(),
            "alice",
            GOOD_PASSWORD,
            None,
            None,
        )
        .await
        .expect("login must succeed");

        let stored = database::get_user_by_id(&pool, "u1")
            .await
            .expect("read user")
            .expect("user exists");

        assert_ne!(stored.password_hash, outdated, "hash was not rewritten");
        assert!(!needs_rehash(&stored.password_hash));
        // The upgrade must not lock the user out.
        assert!(verify_password(GOOD_PASSWORD, &stored.password_hash));
        assert!(!verify_password("something else", &stored.password_hash));

        // A current hash is left alone.
        let before = stored.password_hash.clone();
        login(
            &pool,
            &SessionConfig::default(),
            "alice",
            GOOD_PASSWORD,
            None,
            None,
        )
        .await
        .expect("login must succeed");
        let after = database::get_user_by_id(&pool, "u1")
            .await
            .expect("read user")
            .expect("user exists");
        assert_eq!(after.password_hash, before, "hash was rewritten needlessly");
    }

    #[tokio::test]
    async fn client_metadata_is_truncated_before_it_is_stored() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let long_agent = "ü".repeat(MAX_USER_AGENT_LENGTH);
        let outcome = login(
            &pool,
            &SessionConfig::default(),
            "alice",
            GOOD_PASSWORD,
            Some(&long_agent),
            Some("127.0.0.1"),
        )
        .await
        .expect("login must succeed");

        let stored = outcome.session.user_agent.expect("user agent stored");
        assert!(stored.len() <= MAX_USER_AGENT_LENGTH);
        assert!(long_agent.starts_with(&stored));
    }

    // -----------------------------------------------------------------------
    // Password reset
    // -----------------------------------------------------------------------

    /// The reason this type exists. A derived `Debug` has already written a
    /// live token into a log in this project; this test is what keeps somebody
    /// from re-deriving it.
    #[test]
    fn reset_token_debug_is_redacted() {
        let token = generate_reset_token().expect("RNG must work");
        let raw = token.expose().to_string();

        let rendered = format!("{token:?}");
        assert_eq!(rendered, "ResetToken(<redacted>)");
        assert!(
            !rendered.contains(&raw),
            "the Debug output must not contain the token"
        );
        // Not even a prefix of it — a truncated token is still a token.
        assert!(!rendered.contains(&raw[..8]));

        // The same must hold one level up, where the token sits next to the
        // account it opens.
        let issued = IssuedReset {
            token: token.clone(),
            username: "alice".to_string(),
            expires_at: Utc::now(),
        };
        let rendered = format!("{issued:?}");
        assert!(!rendered.contains(&raw), "IssuedReset leaked the token");
        assert!(!rendered.contains(&raw[..8]));
    }

    /// `ResetToken` must have neither `Display` nor `Serialize`: both are ways
    /// the value reaches a log line or a JSON response without anybody
    /// deciding to expose it, and only [`ResetToken::expose`] may do that.
    ///
    /// Absence of a trait cannot be asserted at runtime, so it is asserted at
    /// **compile time**: the blanket implementations below cover every type
    /// that is `Display` (resp. `Serialize`), so the explicit implementation
    /// for `ResetToken` compiles only while it is neither. Derive either one on
    /// the type and this stops building with a coherence error — which is the
    /// whole point, since the pattern has been broken in this project before.
    #[allow(dead_code)]
    mod reset_token_is_not_printable {
        use super::ResetToken;

        trait NotDisplay {}
        impl<T: std::fmt::Display> NotDisplay for T {}
        impl NotDisplay for ResetToken {}

        trait NotSerialize {}
        impl<T: serde::Serialize> NotSerialize for T {}
        impl NotSerialize for ResetToken {}

        // The same guard for the struct that carries it around.
        use super::IssuedReset;
        trait NotSerializable {}
        impl<T: serde::Serialize> NotSerializable for T {}
        impl NotSerializable for IssuedReset {}
    }

    #[test]
    fn reset_tokens_are_long_unique_and_hex() {
        let mut seen = std::collections::HashSet::new();

        for _ in 0..256 {
            let token = generate_reset_token().expect("RNG must work");
            let raw = token.expose();

            assert_eq!(raw.len(), RESET_TOKEN_HEX_LENGTH);
            assert!(is_well_formed_reset_token(raw), "bad shape: {raw}");
            assert!(seen.insert(raw.to_string()), "a token repeated: {raw}");

            // What is stored must not be what is handed out.
            assert_ne!(token.hash(), raw);
            assert_eq!(token.hash(), hash_reset_token(raw));
        }
    }

    #[test]
    fn malformed_reset_tokens_are_rejected_by_shape() {
        assert!(!is_well_formed_reset_token(""));
        assert!(!is_well_formed_reset_token(&"a".repeat(63)));
        assert!(!is_well_formed_reset_token(&"a".repeat(65)));
        assert!(!is_well_formed_reset_token(&"A".repeat(64)));
        assert!(!is_well_formed_reset_token(&"z".repeat(64)));
    }

    #[tokio::test]
    async fn issuing_stores_only_the_hash() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let issued = issue_password_reset(&pool, "alice")
            .await
            .expect("issuing must succeed");
        let raw = issued.token.expose().to_string();

        let stored = database::get_password_reset_by_hash(&pool, &issued.token.hash())
            .await
            .unwrap()
            .expect("the grant must be stored");
        assert_eq!(stored.user_id, "u1");
        assert!(stored.used_at.is_none());
        assert_ne!(stored.token_hash, raw, "the plaintext token was stored");

        // And nowhere else in the row either.
        let row: (String,) =
            sqlx::query_as("SELECT id || '|' || token_hash || '|' || user_id FROM password_resets")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !row.0.contains(&raw),
            "a plaintext token is in the database"
        );
    }

    #[tokio::test]
    async fn issuing_refuses_unknown_and_disabled_accounts() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        database::set_user_active(&pool, "u1", false).await.unwrap();

        assert!(matches!(
            issue_password_reset(&pool, "nobody").await,
            Err(ResetIssueError::NoSuchAccount)
        ));
        assert!(matches!(
            issue_password_reset(&pool, "alice").await,
            Err(ResetIssueError::AccountDisabled)
        ));
    }

    #[tokio::test]
    async fn a_reset_changes_the_password_and_drops_every_session() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let config = SessionConfig::default();

        // Two live sessions, as an attacker who was already inside would have.
        for _ in 0..2 {
            login(&pool, &config, "alice", GOOD_PASSWORD, None, None)
                .await
                .expect("login must succeed");
        }
        assert_eq!(
            database::get_sessions_for_user(&pool, "u1")
                .await
                .unwrap()
                .len(),
            2
        );

        let issued = issue_password_reset(&pool, "alice").await.expect("issue");
        const NEW_PASSWORD: &str = "ganz-anderes-langes-geheimnis";

        let outcome = redeem_password_reset(&pool, issued.token.expose(), NEW_PASSWORD)
            .await
            .expect("redeeming must not fail");
        assert!(matches!(outcome, PasswordResetOutcome::Success { .. }));

        // The old password is gone ...
        assert!(matches!(
            login(&pool, &config, "alice", GOOD_PASSWORD, None, None).await,
            Err(LoginError::InvalidCredentials)
        ));
        // ... the new one works ...
        login(&pool, &config, "alice", NEW_PASSWORD, None, None)
            .await
            .expect("the new password must work");
        // ... and the sessions that existed before the reset are gone. (The
        // login just above added one, so exactly one remains.)
        assert_eq!(
            database::get_sessions_for_user(&pool, "u1")
                .await
                .unwrap()
                .len(),
            1,
            "sessions from before the reset survived"
        );
    }

    #[tokio::test]
    async fn a_token_works_exactly_once() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let issued = issue_password_reset(&pool, "alice").await.expect("issue");

        assert!(matches!(
            redeem_password_reset(
                &pool,
                issued.token.expose(),
                "erstes-neues-langes-geheimnis"
            )
            .await
            .unwrap(),
            PasswordResetOutcome::Success { .. }
        ));
        assert!(matches!(
            redeem_password_reset(
                &pool,
                issued.token.expose(),
                "zweites-neues-langes-geheimnis"
            )
            .await
            .unwrap(),
            PasswordResetOutcome::Rejected
        ));

        // The second attempt must not have changed anything.
        let config = SessionConfig::default();
        login(
            &pool,
            &config,
            "alice",
            "erstes-neues-langes-geheimnis",
            None,
            None,
        )
        .await
        .expect("the first new password must still be the current one");
    }

    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        // Written directly, because issuing always dates the expiry into the
        // future — the point here is the check, not the clock.
        let token = generate_reset_token().expect("RNG");
        let reset = database::PasswordReset {
            id: "r1".to_string(),
            token_hash: token.hash(),
            user_id: "u1".to_string(),
            created_at: Utc::now() - ChronoDuration::hours(3),
            expires_at: Utc::now() - ChronoDuration::minutes(1),
            used_at: None,
        };
        database::create_password_reset(&pool, &reset)
            .await
            .unwrap();

        assert!(matches!(
            redeem_password_reset(&pool, token.expose(), "ein-neues-langes-geheimnis")
                .await
                .unwrap(),
            PasswordResetOutcome::Rejected
        ));
        // The old password still stands.
        login(
            &pool,
            &SessionConfig::default(),
            "alice",
            GOOD_PASSWORD,
            None,
            None,
        )
        .await
        .expect("the password must be unchanged");
    }

    #[tokio::test]
    async fn an_unknown_token_is_refused_without_saying_why() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let stranger = generate_reset_token().expect("RNG");
        assert!(matches!(
            redeem_password_reset(&pool, stranger.expose(), "ein-neues-langes-geheimnis")
                .await
                .unwrap(),
            PasswordResetOutcome::Rejected
        ));
        assert!(matches!(
            redeem_password_reset(&pool, "not-a-token", "ein-neues-langes-geheimnis")
                .await
                .unwrap(),
            PasswordResetOutcome::Rejected
        ));
    }

    /// A password the policy turns down must leave the grant open — otherwise
    /// one typo costs the locked-out user their only way in.
    #[tokio::test]
    async fn a_weak_password_does_not_burn_the_token() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;
        let issued = issue_password_reset(&pool, "alice").await.expect("issue");

        assert!(matches!(
            redeem_password_reset(&pool, issued.token.expose(), "password123")
                .await
                .unwrap(),
            PasswordResetOutcome::WeakPassword(_)
        ));

        let stored = database::get_password_reset_by_hash(&pool, &issued.token.hash())
            .await
            .unwrap()
            .expect("still there");
        assert!(
            stored.used_at.is_none(),
            "a rejected password spent the token"
        );

        // And it still works afterwards.
        assert!(matches!(
            redeem_password_reset(&pool, issued.token.expose(), "ein-neues-langes-geheimnis")
                .await
                .unwrap(),
            PasswordResetOutcome::Success { .. }
        ));
    }

    /// Issuing twice and redeeming one must close the other: after the password
    /// has changed, a second outstanding grant is a live back door.
    #[tokio::test]
    async fn redeeming_closes_the_other_outstanding_grants() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let first = issue_password_reset(&pool, "alice").await.expect("issue");
        let second = issue_password_reset(&pool, "alice").await.expect("issue");

        assert!(matches!(
            redeem_password_reset(&pool, second.token.expose(), "ein-neues-langes-geheimnis")
                .await
                .unwrap(),
            PasswordResetOutcome::Success { .. }
        ));
        assert!(matches!(
            redeem_password_reset(&pool, first.token.expose(), "noch-ein-langes-geheimnis")
                .await
                .unwrap(),
            PasswordResetOutcome::Rejected,
        ));
    }

    #[tokio::test]
    async fn cleanup_removes_expired_and_spent_grants() {
        let (pool, _dir) = temp_pool().await;
        seed_user(&pool, "u1", "alice", GOOD_PASSWORD).await;

        let live = issue_password_reset(&pool, "alice").await.expect("issue");

        let stale = generate_reset_token().expect("RNG");
        database::create_password_reset(
            &pool,
            &database::PasswordReset {
                id: "r-old".to_string(),
                token_hash: stale.hash(),
                user_id: "u1".to_string(),
                created_at: Utc::now() - ChronoDuration::hours(5),
                expires_at: Utc::now() - ChronoDuration::hours(4),
                used_at: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(cleanup_expired_password_resets(&pool).await.unwrap(), 1);
        assert!(database::get_password_reset_by_hash(&pool, &stale.hash())
            .await
            .unwrap()
            .is_none());
        assert!(
            database::get_password_reset_by_hash(&pool, &live.token.hash())
                .await
                .unwrap()
                .is_some()
        );
    }
}
