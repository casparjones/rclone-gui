// Generation of `rsyncd.conf` and `rsyncd.secrets` for the peer-to-peer rsync
// transport (epic "rsync-Transport", tickets db73d18e and ae12dcd1).
//
// db73d18e produced the files; ae12dcd1 added [`ModuleRegistry`], which creates
// and removes single modules while a daemon is running. This module still has
// no callers: starting the daemon and the audit log are separate tickets
// (3ed12cdd, 9f3d4888). Same `dead_code` workaround as in
// `src/handlers/auth.rs`, so that `-D warnings` stays usable in the meantime.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tokio::sync::Mutex as TokioMutex;

// ---------------------------------------------------------------------------
// Fixed daemon parameters
//
// The values below are decisions, not defaults; every one of them comes out of
// the spike documented in `docs/rsync-transport.md`. Changing one of them
// re-opens a security question that was already measured and answered, so the
// reasoning is recorded here rather than in a commit message.
//
//   * `address = 127.0.0.1` — the daemon never listens on a routable address.
//     The unencrypted direct mode was dropped; every peer arrives through
//     stunnel on port 874, which connects to 127.0.0.1:873 locally. There is
//     deliberately no branch for a direct mode: a configuration that cannot
//     express "listen on 0.0.0.0" cannot be talked into it by a bug either.
//
//   * no `auth digest` — Alpine builds rsync without `openssl-crypto`, so its
//     `Daemon auth list` is `md5 md4` on every version from 3.19 through 3.22.
//     Requiring `sha512` would make two instances of our own image reject each
//     other. MD5 challenge-response is accepted knowingly: the secret itself
//     never travels over the wire, and TLS protects the negotiation on top.
//     (In rsync 3.4.1 the parameter does not even exist and is silently
//     ignored, which would be worse than not setting it.)
//
//   * `refuse options = copy-links copy-dirlinks copy-unsafe-links` — without
//     it a client using `-L` reads straight through a symlink that was placed
//     inside the share by other means; the spike pulled the server's
//     `/etc/passwd` (1278 bytes) that way. `munge symlinks` does NOT help
//     here, it only rewrites links that rsync itself writes.
//
//   * `delete remove-source-files remove-sent-files force` in the same list —
//     a pairing carries write access, and without this a peer that may write
//     may also *destroy*: a push with `--delete` removed every file in the
//     share that the sender did not have, exit 0, measured.
//     `remove-source-files` and its old alias `remove-sent-files` are the same
//     weapon pointed the other way, they empty the *sender's* directory — and
//     when the module is the sender, that directory is the share.
//     `--force` destroys without any `--delete` at all: it lets a single
//     incoming file replace a non-empty directory. All of them are refused
//     unconditionally today; see [`REFUSED_OPTIONS`] for what has to happen
//     once the scope model knows `rsync:delete`, and for why the delete entry
//     is the bare word `delete` and emphatically not the wildcard `delete*`.
//
//   * `use chroot = yes` — usable since the base image moved to alpine:3.22
//     (ticket 3f276e8c); on musl 1.2.4 it broke every transfer with exit 23.
//     It is the second layer under `refuse options`.
//
//     The one deployment that does not get it is a daemon started by a user who
//     is neither root nor spawning a binary with `CAP_SYS_CHROOT`: `chroot()`
//     would fail and no transfer would run at all. That case renders `use
//     chroot = no`, drops `uid`/`gid`, moves to an unprivileged port and says
//     so at startup — see [`Hardening`], and
//     `module_boundaries_without_chroot_on_the_real_daemon` for what the
//     boundary is still worth there.
//
//   * one module per pairing, writable by default — only push is supported,
//     there is no second read-only module for pull.
// ---------------------------------------------------------------------------

/// The daemon listens on loopback only; stunnel on 874 is the sole entry point.
pub const DAEMON_ADDRESS: &str = "127.0.0.1";
/// Local rsync daemon port behind the TLS terminator, where the daemon can be
/// hardened. See [`Hardening`] for the port a rootless daemon takes instead.
pub const DAEMON_PORT: u16 = 873;
/// The port a rootless daemon binds instead of [`DAEMON_PORT`].
///
/// 873 is privileged (`net.ipv4.ip_unprivileged_port_start` is 1024 on an
/// ordinary host), so a daemon started by a normal user cannot have it. The
/// value keeps the 873 shape so that a `ss -ltnp` line stays recognisable, and
/// it is above 1024, which is all that is required of it. Override with
/// `RCLONE_GUI_RSYNCD_PORT`; the TLS terminator has to be pointed at the same
/// value (`RCLONE_GUI_RSYNC_BACKEND`, see `config/rsync-tls.sh`).
pub const ROOTLESS_DAEMON_PORT: u16 = 8873;
/// The one property the value has to have: an unprivileged process can bind it.
/// A compile error is the right place to find that out, not a start-up failure.
const _: () = assert!(
    ROOTLESS_DAEMON_PORT > 1023,
    "the rootless daemon port has to be outside the privileged range"
);
/// The environment variable that overrides the daemon port in either mode.
pub const PORT_ENV: &str = "RCLONE_GUI_RSYNCD_PORT";

/// How much of the daemon hardening this machine can actually provide.
///
/// # Why this is detected and not configured
///
/// Three of the hardening decisions in this module need privilege the process
/// may not have, and a start that walks into one of them fails with an error
/// that names the *symptom*: `Permission denied` on the run directory,
/// `chroot(...) failed: Operation not permitted`, `setgroups failed`. Ticket
/// `50c8ec48` came out of a user hitting the first of the three on the host and
/// asking whether the daemon needs root at all — it does not, but the generated
/// configuration did.
///
/// A switch would have been the smaller change and the wrong one: an operator
/// who sets `RCLONE_GUI_RSYNCD_ROOTLESS=1` in production silently loses the
/// chroot, and nothing about the running system says so. So the mode is read
/// off the machine, once, at startup, and announced (see
/// [`Hardening::warnings`]).
///
/// # What is asked, and why it is not just `geteuid() == 0`
///
/// The container is the case that makes the obvious question wrong. It runs as
/// `appuser` (uid 1001, `USER appuser` in the Dockerfile) and *still* gets the
/// full hardening, because `setcap cap_sys_chroot,cap_setgid=ep
/// /usr/bin/rsync` puts the two capabilities the daemon needs on the binary
/// itself. A euid check alone would therefore have downgraded the shipped
/// container to the rootless path — losing the chroot in exactly the
/// deployment the chroot was built for.
///
/// The question asked is thus "will the daemon we are about to spawn be able to
/// chroot": euid 0, or a file capability on the rsync binary. Both are read
/// from the system — `/proc/self/status` and `getcap` — and anything that
/// cannot be established counts as *not* privileged, which fails towards a
/// daemon that comes up rather than one that dies on `chroot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hardening {
    /// chroot, the uid/gid drop and the privileged port are all available.
    /// The container and any root deployment.
    Full,
    /// None of the three are. rsync's own path check is the only thing left
    /// holding the module boundary; see [`Hardening::warnings`].
    Rootless,
}

impl Hardening {
    /// What this machine can do, for the rsync binary at `binary`.
    ///
    /// `binary` is what [`DaemonSettings`] will spawn, which is why it is a
    /// parameter and not [`DEFAULT_RSYNC_BINARY`]: the capability sits on the
    /// file, so asking about a different file would answer a different
    /// question.
    pub fn detect(binary: &Path) -> Self {
        if effective_uid() == Some(0) {
            return Self::Full;
        }
        if binary_can_chroot(binary) {
            return Self::Full;
        }
        Self::Rootless
    }

    /// The daemon port for this mode, honouring [`PORT_ENV`].
    ///
    /// An unparsable or zero override is ignored rather than fatal: the port is
    /// not a security boundary here (`address = 127.0.0.1` and the loopback
    /// verdict are), and refusing to start over a typo in an optional variable
    /// costs more than it buys.
    pub fn port(self) -> u16 {
        self.port_with_override(std::env::var(PORT_ENV).ok().as_deref())
    }

    /// [`Hardening::port`] with the override handed in.
    ///
    /// Split out so that the table of accepted and rejected override values can
    /// be a test: `std::env::set_var` is process-wide, and a test that set it
    /// would decide the port of every other test running beside it.
    fn port_with_override(self, from_env: Option<&str>) -> u16 {
        if let Some(port) = from_env
            .and_then(|value| value.trim().parse::<u16>().ok())
            .filter(|port| *port != 0)
        {
            return port;
        }
        match self {
            Self::Full => DAEMON_PORT,
            Self::Rootless => ROOTLESS_DAEMON_PORT,
        }
    }

    /// Whether a module is served inside a chroot of its own root.
    pub fn uses_chroot(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Whether the daemon can drop to the module's uid/gid.
    pub fn drops_privileges(self) -> bool {
        matches!(self, Self::Full)
    }

    /// What the operator has to be told, in order, or empty for [`Self::Full`].
    ///
    /// Separate from the printing so that a test can assert the mode says what
    /// it costs — an announcement that only exists inside a `println!` is one
    /// nobody can check.
    pub fn warnings(self) -> Vec<String> {
        match self {
            Self::Full => Vec::new(),
            Self::Rootless => vec![
                "the rsync daemon runs ROOTLESS: no chroot, no uid/gid drop, and an unprivileged port"
                    .to_string(),
                "without `use chroot = yes` the module boundary rests on rsync's own path check alone — a second layer is missing, not a first one"
                    .to_string(),
                "without `uid`/`gid` the daemon serves every module as the user that started the application, so a module can reach whatever that user can reach"
                    .to_string(),
                format!(
                    "this is meant for development on a host; the container keeps the hardened path (chroot, uid/gid, port {DAEMON_PORT}) through the file capabilities on /usr/bin/rsync"
                ),
            ],
        }
    }
}

/// The effective uid of this process, or `None` if it cannot be read.
///
/// `/proc/self/status` rather than `geteuid()`: `libc` is not a declared
/// dependency of this crate, and everything else in this module that asks the
/// kernel something (`/proc/locks`, `/proc/net/tcp`, `/proc/<pid>/cmdline`)
/// already reads it out of `/proc`. The `Uid:` line is
/// `real  effective  saved  filesystem`.
fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("Uid:")?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    })
}

/// Whether the rsync binary carries `CAP_SYS_CHROOT` as a file capability.
///
/// This is what makes the shipped container privileged without running as root
/// (Dockerfile: `setcap cap_sys_chroot,cap_setgid=ep /usr/bin/rsync`). The
/// query goes through `getcap`, which the runtime image installs for exactly
/// this purpose (`libcap`), because reading the `security.capability` extended
/// attribute needs `getxattr` and thus `libc`.
///
/// Every negative outcome — no `getcap`, a non-zero exit, an unreadable path —
/// is reported as "no capability". That is the direction that fails safe in the
/// operational sense: the daemon comes up rootless and *says so*, rather than
/// promising a chroot and dying in it.
fn binary_can_chroot(binary: &Path) -> bool {
    let Some(path) = resolve_in_path(binary) else {
        return false;
    };
    let Ok(output) = std::process::Command::new("getcap")
        .arg(&path)
        .stdin(Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout).contains("cap_sys_chroot")
}

/// `binary` as a filesystem path, resolving a bare name through `PATH`.
///
/// [`DEFAULT_RSYNC_BINARY`] is the bare word `rsync`, which `getcap` cannot
/// take — it wants a file, not a command. Returns `None` when nothing on `PATH`
/// matches, which is also the case in which the daemon will not start at all.
fn resolve_in_path(binary: &Path) -> Option<PathBuf> {
    if binary.components().count() > 1 || binary.is_absolute() {
        return binary.exists().then(|| binary.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}
/// Options every module refuses, regardless of chroot. See the note above.
///
/// # Why the bare word `delete` and not `delete*`
///
/// The obvious way to catch every delete variant is a wildcard, and it is the
/// wrong one. Measured against a real daemon on both rsync versions in play —
/// 3.5.0 on the host and 3.4.3 in `alpine:3.22`, which is what the image ships
/// — with a writable module and a victim file in the share:
///
/// | `refuse options` entry | `--delete`, `-before`, `-during`, `-delay`, `-after`, `-excluded`, `--del` | `--delete-missing-args` |
/// |---|---|---|
/// | `delete*` | refused, exit 4 | **accepted, exit 0** |
/// | `delete` | refused, exit 4 | refused, exit 4 |
/// | `delete delete*` | refused, exit 4 | **accepted, exit 0** |
///
/// The bare word is a *group* refusal in rsync: it marks the whole delete
/// family, `--delete-missing-args` included. A wildcard entry switches the
/// matching to a plain name comparison over the option table, and
/// `--delete-missing-args` is not reached that way — it is refused only through
/// the group. Adding the wildcard next to the bare word does not add the two
/// behaviours together, it replaces the group refusal with the weaker one. So
/// the wildcard makes the rule *worse*, which is the opposite of what reading
/// it suggests, and it must not be "tidied up" into one.
///
/// `--delete-missing-args` is not a harmless corner either: it deletes files on
/// the *receiver* that correspond to arguments missing on the sender, so it
/// destroys existing content in the share exactly like `--delete` does.
///
/// `remove-source-files` has no group and is listed on its own. It points the
/// other way — it empties the *sender's* directory — and is refused for the
/// same reason: a pairing grants access to a share, not permission to clear out
/// whatever is pushed through it. Its deprecated alias `remove-sent-files` is
/// listed as well, because refusal matches the spelling the client sent and not
/// the option it resolves to: measured on 3.5.0 and 3.4.3, a *push* with
/// `--remove-sent-files` was **accepted, exit 0** while `--remove-source-files`
/// was refused. In the pull direction — the one that costs the share its
/// content — the alias falls into the delete group and was already refused, but
/// relying on that is relying on an asymmetry nobody wrote down.
///
/// # `--force` destroys without any `--delete`
///
/// The list above is about deleting. `--force` is not on that list and it does
/// not need to be there to be lethal: it makes rsync *make way* for an incoming
/// entry, which means removing a non-empty directory that stands where a file is
/// being written. Measured on both versions, against a writable module holding
/// `keep/precious.txt`, with a plain file named `keep` on the sender and **no
/// delete option whatsoever**:
///
/// | client | 3.5.0 (host) | 3.4.3 (`alpine:3.22`, the image) |
/// |---|---|---|
/// | `rsync -a` | exit 23, `cannot delete non-empty directory: keep` | exit 23, same |
/// | `rsync -a --force` | **exit 0, `precious.txt` gone** | **exit 0, `precious.txt` gone** |
/// | `rsync -a --force` with `force` refused | exit 4, file intact | exit 4, file intact |
///
/// The same holds one level deeper (`keep/sub/precious.txt`) and when the
/// incoming entry is a symlink rather than a file. So `force` is in the list,
/// and it is there for its own reason — not as a variant of `delete`.
///
/// # What was measured and is deliberately *not* refused
///
/// Ruled out at the daemon, not from the manual page, on 3.5.0 and 3.4.3:
///
/// * `--inplace`, `--partial`, `--delay-updates`, `--temp-dir=…`,
///   `--partial-dir=../../..` — they change how a file the peer is allowed to
///   write gets written, and they reached nothing outside the module. A peer
///   with write access can already overwrite that file with a plain `rsync -a`.
/// * `--append`, `--append-verify` — the existing longer file was left alone.
/// * `--backup`, `--backup-dir=…`, `--suffix=…` — they *add* a copy of the
///   previous version inside the module. Pointed at a directory that already
///   held a file of the same name, the transfer left both the original and the
///   would-be backup untouched; nothing was destroyed.
/// * `--keep-dirlinks` — writes through a directory symlink that already lies
///   in the share. Under `use chroot = yes` the module root *is* the chroot
///   root, so the target of such a link cannot be outside it; measured with a
///   link to a directory above the share, the file there was untouched.
/// * `--trust-sender`, `--relative ../..` — the sender refuses to build a file
///   list with a `..` component before anything reaches the daemon.
/// * `--write-devices` — refused by the daemon on its own (`write devices` is
///   off by default), so it needs no entry here. Listing it would only add a
///   line that cannot be shown to do anything.
/// * `--chmod=F000` — sets the mode of the file it transfers, which is a file
///   the peer just wrote. It denies access, it does not remove content.
///
/// # Once the scope model knows `rsync:delete`
///
/// Deleting is refused **unconditionally** today, for every pairing, because
/// there is no scope that could express "this peer may delete". The scope
/// `rsync:delete` does not exist in the model yet. When it does, this constant
/// becomes a function of the pairing's scopes — the delete entries drop out for
/// a pairing that holds it, and `remove-source-files` stays refused regardless,
/// because it destroys data on a side of the transfer the pairing says nothing
/// about. Until then a peer with write access can add and overwrite, never
/// destroy: that is the whole point, since a write-only peer being able to wipe
/// somebody else's share is data loss, not merely an excess of rights.
pub const REFUSED_OPTIONS: &str = "copy-links copy-dirlinks copy-unsafe-links delete \
     remove-source-files remove-sent-files force";

/// Literal marker at the front of every per-file line the daemon writes.
///
/// rsync's `log format` passes literal text through unchanged (measured on
/// 3.5.0 and 3.4.3), and without such a marker a transfer line is not reliably
/// distinguishable from the daemon's own prose: both are `[<pid>] <text>`, and
/// a file name can be anything at all. Anchoring on a string we chose means a
/// user cannot forge a transfer line by naming a file cleverly — the marker
/// sits *before* every field the client controls.
const AUDIT_SENTINEL: &str = "rclone-gui-audit";

/// The `log format` every module is rendered with.
///
/// `%a` the address the daemon sees (always loopback behind stunnel, kept so
/// that the proxy hop is on record), `%u` the authenticated user, `%m` the
/// module, `%o` the operation (`send`, `recv` or `del.`), `%l` the file's size,
/// `%b` the bytes actually transferred, `%f` the file name.
///
/// The file name is **last** on purpose: it is the only field that may contain
/// spaces, so every field before it can be split off without ambiguity.
const MODULE_LOG_FORMAT: &str = "rclone-gui-audit %a %u %m %o %l %b %f";

/// How many audit events are kept in memory for the status API.
const AUDIT_RING_CAPACITY: usize = 512;

/// How many stunnel connections are kept for correlation.
const STUNNEL_RING_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Size watch over the run directory (ticket 0cedda6f)
//
// The audit log is append-only and is **not** rotated from here; the reasoning
// is on [`DaemonSettings::audit_file`] and it stands. What was missing is the
// operational half of it: the image has neither logrotate nor a quota, and the
// pid and lock files of the daemon live in the same directory. A run directory
// that fills up therefore does not merely lose log lines, it stops the
// transport — and the failure then looks like a daemon fault
// (`failed to lock pid file`, `cannot create the daemon log`), not like a full
// disk.
//
// So the process watches and says so, and deletes nothing. Rotation happens
// from outside; `config/logrotate-rclone-gui.conf` is the snippet to install.
// ---------------------------------------------------------------------------

/// Warn once a single log in the run directory passes this many bytes. `0`
/// switches the check off.
///
/// Applies to each of the three files that grow there — the audit log, the
/// daemon's own log and the stunnel log — because any one of them alone can
/// fill the volume the pid and lock file live on.
///
/// 64 MiB is roughly 250'000 audit lines — far beyond any plausible retention
/// need for a single daemon lifetime, and still two orders of magnitude below
/// the size at which a small volume is in danger. Overridable with
/// `RCLONE_GUI_LOG_WARN_BYTES` (bytes), mainly so that the threshold can be
/// reproduced in a test without writing 64 MiB.
const DEFAULT_LOG_WARN_BYTES: u64 = 64 * 1024 * 1024;

/// Warn once everything in the run directory together passes this many bytes.
///
/// Catches what the per-file limits do not: the stunnel log, the daemon log and
/// the audit log each staying under their own threshold while the directory as
/// a whole grows. Overridable with `RCLONE_GUI_RUN_DIR_WARN_BYTES`.
const DEFAULT_RUN_DIR_WARN_BYTES: u64 = 256 * 1024 * 1024;

/// How often the run directory is measured.
///
/// Once a minute: the warning has to reach somebody who started the container
/// and left it running, so it cannot be a start-up-only check; and it must not
/// ride on every audit event either, or it drowns in the transfer it is
/// warning about. Measuring costs one `stat` per file plus one `read_dir`.
const RUN_DIR_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// How long a warning stays "already said" before it is repeated.
///
/// A file over its limit is over it on every subsequent check as well. Without
/// this the warning would repeat every minute for as long as the container
/// lives, which is the same as not warning at all. It is repeated when the
/// condition persists (every 15 minutes) or when the file has doubled since
/// the last warning, whichever comes first — growth is the part that matters.
const RUN_DIR_WARN_REPEAT: Duration = Duration::from_secs(15 * 60);

/// How far back a stunnel line may lie to still be matched by time alone.
///
/// Only used when the exact match over the port failed (see
/// [`peer_port_of_child`]). Thirty seconds is generous for a connection that is
/// being accepted and forwarded in the same instant, and short enough that an
/// unrelated earlier connection is not silently adopted.
const STUNNEL_MATCH_WINDOW: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// What stands between a peer and somebody else's share (ticket 4292d027)
//
// There are exactly three things, and it is worth writing down which, because
// the obvious fourth one does not exist here.
//
//   1. **The module name is unguessable and not enumerable.** 64 bits of
//      randomness behind a fixed prefix, derived from nothing about the share,
//      plus `list = no` in every module — without that line
//      `rsync rsync://host/` hands out every module name anonymously and
//      before any authentication, and then nobody has to guess.
//   2. **The secret is 256 bits.** rsync's challenge-response runs on md5 in
//      the image (`auth digest` needs an rsync built against openssl-crypto,
//      Alpine builds without), so the entropy of the secret is what carries
//      the authentication, together with TLS over the exchange.
//   3. **`max connections` per module**, which the daemon itself enforces and
//      which is measured in `secrets_and_limits_on_the_real_daemon`. It counts
//      connections open at the same time, not transfers over time, so a peer
//      pushing many small files in sequence cannot lock itself out with it.
//
// The fourth one — throttling a peer that keeps guessing — has **no place to
// live in this module**, and pretending otherwise would be worse than saying
// so. Every connection arrives from `127.0.0.1` through stunnel; the daemon
// never sees the peer address, so an address-based limit either matches nothing
// or matches everybody, and the second kind is a lever an attacker pulls on
// purpose to shut the transport for all peers. The real client address is only
// in the stunnel log, which the application reads *after* the fact (see
// `StunnelIndex`) — that is enough to record and to alert on, and not enough to
// refuse a connection with.
//
// Rate limits on an authorize and a token endpoint are the other half of the
// ticket. Those endpoints belong to the OAuth2 provider (ticket 8b1f4477) and
// do not exist yet; `ResetRateLimiter` in `handlers/auth_web.rs` is the shape
// they should take, including its note on why a global bucket is the one that
// actually bites.
// ---------------------------------------------------------------------------

/// Prefix of a generated module name. Carries no information about the share.
const MODULE_NAME_PREFIX: &str = "pair";
/// Random bytes behind the prefix, rendered as hex (16 characters, 64 bits).
const MODULE_NAME_RANDOM_BYTES: usize = 8;
/// Entropy of a module secret. The ticket requires at least 32 bytes.
///
/// 32 bytes from the OS CSPRNG, rendered as 64 hex characters (see
/// [`generate_secret`] for why hex and not base64). A secret this size is not
/// brute-forced offline whatever the daemon's challenge-response is built on —
/// which matters here, because `auth digest` is not available in the image and
/// rsync falls back to md5: the entropy of the secret is what carries that,
/// together with the TLS layer over the exchange.
const SECRET_BYTES: usize = 32;

/// The floor is a requirement, not a preference, so lowering it must not
/// compile. A `const` block is the cheapest way to say so — a test could be
/// deleted along with the change it was guarding.
const _: () = assert!(
    SECRET_BYTES >= 32,
    "a module secret must carry at least 32 bytes of entropy"
);
/// Mode for both generated files: owner read/write, nothing else.
const FILE_MODE: u32 = 0o600;

/// Directory inside a writable module that holds rsync's temporary files.
///
/// # Why the daemon is told where to put its temp files
///
/// By default rsync writes into `.<name>.XXXXXX` **next to the destination
/// file** and renames it when the transfer is complete. A daemon that is killed
/// hard never gets to the rename, so those files stay in the share for good —
/// 85 MB after one test run in the spike. Cleaning them up again meant looking
/// at the names in the share root and guessing which ones belonged to rsync,
/// and that guess cannot be made safely: `.ssh.config`, `.env.docker`,
/// `.bashrc.backup`, `.htaccess.backup`, `.gitlab.config` and `.npmrc.backup`
/// are all `.` + name + `.` + six alphanumeric characters, exactly like a temp
/// file of rsync's. A sweep built on that pattern deleted four ordinary user
/// files for every real leftover it found.
///
/// `temp dir` removes the guess. Measured on rsync 3.4.3 (alpine:3.22, the
/// image) and 3.5.0 (the host):
///
/// * with `temp dir = /.rsync-tmp` the partial of an interrupted transfer lands
///   in `<share>/.rsync-tmp/big.bin.DoPFFG` — the share root never sees a temp
///   file at all, so cleaning up means emptying one directory that belongs to
///   us instead of deleting other people's files on a hunch;
/// * the value is resolved **relative to the module root in both chroot
///   modes**. With `use chroot = yes` the module root is `/`; with
///   `use chroot = no` rsync prepends the module path itself (a `temp dir` of
///   `/probe/share/.rsync-tmp` under a module at `/probe/share` turned into
///   `/probe/share/probe/share/.rsync-tmp` and the daemon refused to start).
///   So the leading slash is right and stays right whichever way ticket
///   `33eeb98c` resolves the chroot question;
/// * the directory has to exist — `The temp-dir does not exist` is a fatal
///   error at connection time, which is why every write path creates it (see
///   [`ModuleConfig::ensure_temp_dir`]);
/// * the module parameter `exclude` would hide the directory from a client's
///   listing, but on 3.4.3 it makes the daemon reject the client's options
///   outright (`requested action not supported`, exit 4) and no transfer works
///   at all. So the directory is visible in the module, and that is the price.
const MODULE_TEMP_DIR: &str = ".rsync-tmp";

// ---------------------------------------------------------------------------
// Random material
// ---------------------------------------------------------------------------

/// `len` bytes from the operating system CSPRNG, hex encoded.
///
/// `OsRng::try_fill_bytes` is used rather than `fill_bytes` so that an
/// exhausted or unavailable entropy source turns into an error instead of a
/// panic — this runs on a request path once the pairing handler exists.
fn random_hex(len: usize) -> Result<String> {
    let mut buf = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| anyhow!("no entropy available from the operating system: {e}"))?;
    let mut out = String::with_capacity(len * 2);
    for byte in &buf {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// A module name that cannot be guessed and cannot be derived from the share.
///
/// The name is drawn from the CSPRNG and is deliberately *not* a function of
/// the directory being shared: knowing that a peer exports `/data/photos` must
/// not tell an attacker what to type after `rsync://host/`. Together with
/// `list = no` in the rendered module this is what keeps a module private.
pub fn generate_module_name() -> Result<String> {
    Ok(format!(
        "{MODULE_NAME_PREFIX}{}",
        random_hex(MODULE_NAME_RANDOM_BYTES)?
    ))
}

/// A module secret with [`SECRET_BYTES`] bytes of entropy, hex encoded.
///
/// Hex rather than base64 on purpose: the result is guaranteed to contain
/// neither `:` (the field separator of the secrets file) nor a line break, so
/// it cannot break the file format it is written into.
pub fn generate_secret() -> Result<String> {
    random_hex(SECRET_BYTES)
}

// ---------------------------------------------------------------------------
// Input validation
//
// Everything that ends up in the configuration file passes through here. rsync
// parses `rsyncd.conf` line by line, so a value containing a line break would
// let the next line act as a directive of its own — a share root named
// "photos\nread only = no" would silently turn a read-only module writable, and
// "photos\n[other]\npath = /" would add a module. The check is a reject, not an
// escape: rsyncd.conf has no quoting mechanism that could express such a value
// safely, so there is nothing to escape it to.
// ---------------------------------------------------------------------------

/// Reject a value that could not survive a round trip through `rsyncd.conf`.
///
/// Rejected are: empty values, any C0/C1 control character (which includes
/// `\n`, `\r`, `\t` and NUL), and leading or trailing whitespace, because rsync
/// trims those and would read back something other than what was written.
fn check_conf_value(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(anyhow!("{field} must not be empty"));
    }
    if let Some(bad) = value.chars().find(|c| c.is_control()) {
        return Err(anyhow!(
            "{field} contains the control character {:?}; such a value could inject an \
             additional directive into rsyncd.conf and is refused",
            bad
        ));
    }
    if value.trim() != value {
        return Err(anyhow!(
            "{field} has leading or trailing whitespace, which rsync would strip"
        ));
    }
    Ok(())
}

/// Reject anything that is not a plain lowercase alphanumeric module name.
///
/// The name appears twice in a place where a stray character changes meaning:
/// as `[name]` in the section header and as `name:secret` in the secrets file.
/// Generated names always pass; the check exists for the day someone feeds a
/// name in from the outside.
fn check_module_name(name: &str) -> Result<()> {
    check_conf_value("module name", name)?;
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(anyhow!(
            "module name {name:?} must consist of lowercase letters and digits only"
        ));
    }
    Ok(())
}

/// Canonicalise a share root and make sure it is representable in the file.
///
/// `fs::canonicalize` resolves `..` and every symlink on the way, so what lands
/// in `path =` is the directory the daemon will really serve — not a link that
/// points somewhere else by the time the daemon reads it. A share root that
/// does not exist is an error rather than something to create here: creating it
/// would be a side effect this function has no business having.
fn canonical_share_root(root: &Path) -> Result<String> {
    let canonical = fs::canonicalize(root)
        .with_context(|| format!("share root {} cannot be resolved", root.display()))?;
    if !canonical.is_dir() {
        return Err(anyhow!(
            "share root {} is not a directory",
            canonical.display()
        ));
    }
    let text = canonical
        .to_str()
        .ok_or_else(|| anyhow!("share root {} is not valid UTF-8", canonical.display()))?
        .to_string();
    check_conf_value("share root", &text)?;
    Ok(text)
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

/// One rsync module: exactly one pairing, exactly one shared directory.
///
/// `Debug` is implemented by hand rather than derived; see the impl below.
#[derive(Clone)]
pub struct ModuleConfig {
    /// Random, unguessable module name; also the `auth users` entry.
    name: String,
    /// Module secret. Never logged, never rendered into `rsyncd.conf`.
    secret: String,
    /// Canonicalised share root.
    path: String,
    /// `true` unless the pairing carries the `rsync:write` scope.
    read_only: bool,
    /// Numeric uid the daemon drops to for this module.
    uid: u32,
    /// Numeric gid the daemon drops to for this module.
    gid: u32,
    /// Concurrent connections allowed for this module.
    max_connections: u32,
}

/// Redacts the secret.
///
/// The field's doc comment says "never logged", but a derived `Debug` does not
/// enforce that — it prints every field, and one `tracing::debug!(?module)`
/// anywhere, now or in a year, would put a module secret into the application
/// log in plain text. The same derive reaches the secret through
/// [`DaemonConfig`], which contains the modules and derives `Debug` itself.
/// Redacting here is the only place that covers both, and it makes the promise
/// in the doc comment something the compiler keeps rather than something the
/// next author has to remember.
impl std::fmt::Debug for ModuleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleConfig")
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .field("path", &self.path)
            .field("read_only", &self.read_only)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

impl ModuleConfig {
    /// Build a module for `share_root`, deriving `read only` from the scope.
    ///
    /// `has_write_scope` is the answer to "does this pairing hold the
    /// `rsync:write` scope"; a pairing without it gets `read only = yes`.
    pub fn new(
        share_root: &Path,
        has_write_scope: bool,
        uid: u32,
        gid: u32,
        max_connections: u32,
    ) -> Result<Self> {
        if max_connections == 0 {
            return Err(anyhow!("max connections must be at least 1"));
        }
        let name = generate_module_name()?;
        check_module_name(&name)?;
        Ok(Self {
            name,
            secret: generate_secret()?,
            path: canonical_share_root(share_root)?,
            read_only: !has_write_scope,
            uid,
            gid,
            max_connections,
        })
    }

    /// The generated module name. Safe to store and to log.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The module secret. Handed to the peer once during pairing; it must not
    /// reach a log, a `tracing` field, `argv` or the UI.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The canonicalised share root as written into the configuration.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the module refuses writes.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Where this module's temp files live, or `None` for a read-only module.
    ///
    /// A read-only module never receives a file and therefore never writes a
    /// temp file, so it gets no `temp dir` and no directory is created in
    /// somebody's share for nothing.
    pub fn temp_dir(&self) -> Option<PathBuf> {
        if self.read_only {
            return None;
        }
        Some(Path::new(&self.path).join(MODULE_TEMP_DIR))
    }

    /// Create the module's temp directory if it does not exist yet.
    ///
    /// Called from every path that writes the configuration, because a module
    /// added while the daemon is running is usable with the very next
    /// connection and would otherwise fail it with `The temp-dir does not
    /// exist`. Creating it is not optional: without the directory the module is
    /// broken, and without `temp dir` the daemon would scatter temp files
    /// through the share again.
    fn ensure_temp_dir(&self) -> Result<()> {
        let Some(dir) = self.temp_dir() else {
            return Ok(());
        };
        fs::create_dir_all(&dir).with_context(|| {
            format!(
                "cannot create the temp directory {} for module {}",
                dir.display(),
                self.name
            )
        })
    }

    /// Render the `[module]` section. `secrets_file` is the path the *daemon*
    /// will read at runtime, which is not necessarily where we write it now.
    fn render(&self, secrets_file: &str, hardening: Hardening) -> Result<String> {
        check_module_name(&self.name)?;
        check_conf_value("share root", &self.path)?;
        check_conf_value("secrets file", secrets_file)?;
        // Read-only modules get no `temp dir`: they never receive a file, so
        // there is nothing to keep out of the share root. See `MODULE_TEMP_DIR`
        // for why the value is a module-relative absolute path.
        let temp_dir = if self.read_only {
            String::new()
        } else {
            format!("    temp dir = /{MODULE_TEMP_DIR}\n")
        };
        // Rootless: `chroot()` needs CAP_SYS_CHROOT and the uid/gid drop needs
        // CAP_SETGID, so both are rendered as what the daemon can actually do
        // rather than as what we would like. `munge symlinks` and `refuse
        // options` stay untouched — neither needs privilege, and with the
        // chroot gone they are what is left. See `Hardening`.
        let identity = if hardening.drops_privileges() {
            format!(
                "\x20   uid = {uid}\n\x20   gid = {gid}\n",
                uid = self.uid,
                gid = self.gid
            )
        } else {
            String::new()
        };
        Ok(format!(
            "[{name}]\n\
             \x20   path = {path}\n\
             \x20   auth users = {name}\n\
             \x20   secrets file = {secrets}\n\
             \x20   list = no\n\
             \x20   read only = {read_only}\n\
             \x20   use chroot = {chroot}\n\
             \x20   munge symlinks = yes\n\
             {identity}\
             \x20   max connections = {max_connections}\n\
             {temp_dir}\
             \x20   refuse options = {refused}\n\
             \x20   transfer logging = yes\n\
             \x20   log format = {log_format}\n",
            name = self.name,
            path = self.path,
            secrets = secrets_file,
            read_only = if self.read_only { "yes" } else { "no" },
            chroot = if hardening.uses_chroot() { "yes" } else { "no" },
            max_connections = self.max_connections,
            refused = REFUSED_OPTIONS,
            log_format = MODULE_LOG_FORMAT,
        ))
    }

    /// One `name:secret` line for `rsyncd.secrets`.
    fn render_secret_line(&self) -> Result<String> {
        check_module_name(&self.name)?;
        check_conf_value("module secret", &self.secret)?;
        if self.secret.contains(':') {
            return Err(anyhow!("module secret must not contain a colon"));
        }
        Ok(format!("{}:{}\n", self.name, self.secret))
    }
}

// ---------------------------------------------------------------------------
// Daemon configuration
// ---------------------------------------------------------------------------

/// The complete daemon configuration: globals plus every module.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Where the secrets file lives, both for us and for the daemon.
    secrets_file: PathBuf,
    /// Trusted proxy addresses, or `None` for "do not speak PROXY protocol".
    ///
    /// See the extensive note on [`DaemonConfig::with_proxy_protocol`]; `None`
    /// is the only setting that works with the rsync in the current image.
    proxy_protocol_hosts: Option<String>,
    /// Where the daemon writes its log, or `None` to leave it to syslog.
    ///
    /// See [`DaemonConfig::with_log_file`] for why this has to be in the file
    /// rather than on the command line.
    log_file: Option<PathBuf>,
    /// How much hardening the generated configuration may ask for.
    ///
    /// Defaults to [`Hardening::Full`] — the shipped deployment, and the value
    /// every test that does not say otherwise means. The one place that detects
    /// it is the startup in `src/main.rs`; see [`Hardening`] for why it is
    /// detected there and not configured here.
    hardening: Hardening,
    modules: Vec<ModuleConfig>,
}

impl DaemonConfig {
    /// A configuration whose secrets file lives at `secrets_file`.
    ///
    /// The path must lie outside every share root; that is enforced in
    /// [`DaemonConfig::write`], once the modules are known.
    pub fn new(secrets_file: impl Into<PathBuf>) -> Self {
        Self {
            secrets_file: secrets_file.into(),
            proxy_protocol_hosts: None,
            log_file: None,
            hardening: Hardening::Full,
            modules: Vec::new(),
        }
    }

    /// Render for `hardening` instead of [`Hardening::Full`].
    pub fn with_hardening(mut self, hardening: Hardening) -> Self {
        self.hardening = hardening;
        self
    }

    /// Set the hardening after construction. See
    /// [`DaemonConfig::with_hardening`].
    pub fn set_hardening(&mut self, hardening: Hardening) {
        self.hardening = hardening;
    }

    /// What the generated configuration asks for.
    pub fn hardening(&self) -> Hardening {
        self.hardening
    }

    /// Write the daemon log to `path` — from the configuration file, not from
    /// `--log-file`.
    ///
    /// # The measurement this exists for
    ///
    /// `--log-file=<path>` on the command line is what the lifecycle ticket
    /// started the daemon with, and it **suppresses per-file logging
    /// altogether**. Measured on rsync 3.5.0 (host) and 3.4.3 (alpine:3.22, the
    /// image), with `transfer logging = yes` in the module, the whole log of a
    /// completed transfer was:
    ///
    /// ```text
    /// [21] connect from localhost (127.0.0.1)
    /// [21] rsync allowed access on module m1 from localhost (127.0.0.1)
    /// ```
    ///
    /// and nothing else. That does not change with `%i` in the format, with
    /// `--log-file-format`, with `-v` or `-vv` on the daemon, or with `-v` on
    /// the client — six variants, all empty. With `log file = <path>` in
    /// `rsyncd.conf` instead, the same transfer writes:
    ///
    /// ```text
    /// [21] connect from localhost (127.0.0.1)
    /// [21] rsync allowed access on module m1 from localhost (127.0.0.1)
    /// [21] rsync to m1/ from m1@localhost (127.0.0.1)
    /// [21] rclone-gui-audit 127.0.0.1 m1 m1 recv 62914560 62922276 big.bin
    /// [21] sent 40 bytes  received 62930045 bytes  total size 62914560
    /// ```
    ///
    /// The reason is that the connection child re-opens its log from the
    /// configuration once it knows which module was asked for. Setting **both**
    /// therefore splits the log across two files — the startup line and
    /// `connect from` go to the `--log-file` one, everything from the module
    /// choice onwards to the configured one (measured on 3.4.3). So the switch
    /// is dropped from [`DaemonSettings::argv`] and the path is rendered here.
    ///
    /// This also corrects a claim of the lifecycle ticket: "rsync logs nothing
    /// when a connection ends" was a consequence of `--log-file`, not of the
    /// daemon. Each child now writes its own `sent … received … total size …`
    /// line. `/proc` stays the authority for the connection table all the same,
    /// because an aborted connection still writes nothing.
    pub fn with_log_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_file = Some(path.into());
        self
    }

    /// Set the log file after construction. See [`DaemonConfig::with_log_file`].
    pub fn set_log_file(&mut self, path: impl Into<PathBuf>) {
        self.log_file = Some(path.into());
    }

    /// Where the daemon has been told to write its log.
    pub fn log_file(&self) -> Option<&Path> {
        self.log_file.as_deref()
    }

    /// Make the daemon expect a PROXY protocol header from `hosts`.
    ///
    /// **Off by default, and the default is the measured one.** The ticket
    /// template carries `proxy protocol = true`, but with the rsync versions
    /// actually in play it does not do what the template assumes:
    ///
    /// | daemon | `proxy protocol = true` alone | plus `proxy protocol hosts` |
    /// |---|---|---|
    /// | 3.4.3 (alpine:3.22, our image) | starts clean, but **every** client is reset: `safe_read failed to read 1 bytes: Connection reset by peer (104)`, exit 12, nothing in the daemon log | `Unknown Parameter encountered: "proxy protocol hosts"` — silently ignored, so the reset stays |
    /// | 3.5.0 (host) | warns at startup: `"proxy protocol = true" but "proxy protocol hosts" is unset: all connections will be rejected as untrusted proxy peers` | accepted without warning |
    ///
    /// So there is no way to render `proxy protocol = true` that is both
    /// warning-free and functional across the two versions, and on the version
    /// we ship it breaks every transfer unless the TLS terminator is switched
    /// to sending a PROXY header (`protocol = proxy` on stunnel's connect
    /// side). The spike reached the same conclusion from the other direction:
    /// the header only supplies the real client IP for the log, while access
    /// control runs through `auth users`, so it buys nothing here.
    ///
    /// The knob stays available for the lifecycle ticket, which is where
    /// stunnel is configured and where the two ends can be changed together.
    pub fn with_proxy_protocol(mut self, hosts: impl Into<String>) -> Self {
        self.proxy_protocol_hosts = Some(hosts.into());
        self
    }

    /// Add a module.
    pub fn add_module(&mut self, module: ModuleConfig) {
        self.modules.push(module);
    }

    /// Remove the module called `name`, returning it if it was there.
    pub fn remove_module(&mut self, name: &str) -> Option<ModuleConfig> {
        let index = self.modules.iter().position(|m| m.name == name)?;
        Some(self.modules.remove(index))
    }

    /// The module called `name`, if it exists.
    pub fn module(&self, name: &str) -> Option<&ModuleConfig> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// The configured modules.
    pub fn modules(&self) -> &[ModuleConfig] {
        &self.modules
    }

    /// The secrets file path.
    pub fn secrets_file(&self) -> &Path {
        &self.secrets_file
    }

    /// The temp directory of every writable module.
    ///
    /// This is the complete list of places the daemon may leave a partial
    /// transfer behind, and therefore the complete list of places
    /// [`sweep_module_temp_dirs`] is allowed to delete anything.
    pub fn temp_dirs(&self) -> Vec<PathBuf> {
        self.modules.iter().filter_map(|m| m.temp_dir()).collect()
    }

    /// Render `rsyncd.conf`.
    pub fn render_conf(&self) -> Result<String> {
        let secrets = self.secrets_file_as_str()?;
        self.check_unique_module_names()?;

        let mut out = String::new();
        out.push_str("# Generated by rclone-gui. Do not edit, this file is overwritten.\n");
        out.push_str(
            "# No \"auth digest\": rsync on Alpine is built without openssl-crypto and\n\
             # offers md5/md4 only. See docs/rsync-transport.md.\n",
        );
        out.push_str(&format!("address = {DAEMON_ADDRESS}\n"));
        out.push_str(&format!("port = {}\n", self.hardening.port()));
        if let Some(log_file) = &self.log_file {
            let log_file = log_file
                .to_str()
                .ok_or_else(|| anyhow!("the daemon log path is not valid UTF-8"))?;
            check_conf_value("log file", log_file)?;
            // Not `--log-file` on the command line: that switch silences the
            // per-file audit lines entirely. See `with_log_file`.
            out.push_str("# \"log file\" here rather than --log-file: the command line switch\n\
                          # suppresses per-file transfer logging. See DaemonConfig::with_log_file.\n");
            out.push_str(&format!("log file = {log_file}\n"));
        }
        match &self.proxy_protocol_hosts {
            Some(hosts) => {
                check_conf_value("proxy protocol hosts", hosts)?;
                out.push_str("proxy protocol = true\n");
                out.push_str(&format!("proxy protocol hosts = {hosts}\n"));
            }
            // Deliberately omitted rather than written as "false": see
            // `with_proxy_protocol`. rsync 3.4.3 resets every connection when
            // it is on, rsync 3.5.0 warns when it is on without a host list.
            None => out.push_str(
                "# no \"proxy protocol\": rsync 3.4.3 resets every connection unless the\n\
                 # TLS terminator sends a PROXY header. See docs/rsync-transport.md.\n",
            ),
        }

        for module in &self.modules {
            out.push('\n');
            out.push_str(&module.render(secrets, self.hardening)?);
        }
        Ok(out)
    }

    /// Render `rsyncd.secrets`.
    ///
    /// Kept separate from [`DaemonConfig::render_conf`] so that a caller can
    /// never accidentally hand the secrets to something that expects the
    /// configuration — and so that a test can assert the configuration does not
    /// contain any secret at all.
    pub fn render_secrets(&self) -> Result<String> {
        self.check_unique_module_names()?;
        let mut out = String::new();
        for module in &self.modules {
            out.push_str(&module.render_secret_line()?);
        }
        Ok(out)
    }

    /// Write both files, then verify what actually landed on disk.
    ///
    /// The verification is not belt and braces. rsync's "strict modes" check
    /// makes a secrets file with the wrong mode fail authentication, and the
    /// client sees `@ERROR: auth failed` — byte for byte the same message as a
    /// wrong secret (measured in the spike). If the application does not set
    /// and check the mode itself, a permission problem is indistinguishable
    /// from an authentication problem in production. So the mode is set at
    /// creation time (via `OpenOptions::mode`, so the file is never briefly
    /// world-readable), enforced afterwards for a pre-existing file, and then
    /// read back.
    pub fn write(&self, conf_path: &Path) -> Result<()> {
        self.write_in_order(conf_path, ApplyOrder::SecretsFirst)
    }

    /// Write both files atomically, in the order that is safe for the change.
    ///
    /// Both files are replaced with `rename`, so a daemon reading them never
    /// sees a partial file — see [`write_private_file`]. But the two renames
    /// cannot be one operation, and between them the two files disagree. Which
    /// disagreement is harmless depends on the direction of the change, so the
    /// caller says what it is doing:
    ///
    /// * [`ApplyOrder::SecretsFirst`] for a module that is being added. In the
    ///   window the secrets file holds a line for a module that does not exist
    ///   yet — inert, nobody can name it. The other order would expose a module
    ///   whose secret is not readable yet, and the client would see
    ///   `@ERROR: auth failed`, which is the same message as a wrong secret.
    /// * [`ApplyOrder::ConfFirst`] for a revoke. The module disappears with the
    ///   first rename, which is the point of a revoke; the orphaned secret line
    ///   that survives for a moment names nothing.
    fn write_in_order(&self, conf_path: &Path, order: ApplyOrder) -> Result<()> {
        self.ensure_secrets_outside_shares()?;

        // Render both *before* writing either: a value that fails validation
        // must not leave one of the two files already replaced.
        let conf = self.render_conf()?;
        let secrets = self.render_secrets()?;

        // The daemon re-reads the configuration on every connection, so a
        // module becomes usable the moment the file is renamed into place. Its
        // temp directory has to exist by then, otherwise the first transfer
        // dies with `The temp-dir does not exist`.
        for module in &self.modules {
            module.ensure_temp_dir()?;
        }

        match order {
            ApplyOrder::SecretsFirst => {
                write_private_file(&self.secrets_file, &secrets)?;
                write_private_file(conf_path, &conf)?;
            }
            ApplyOrder::ConfFirst => {
                write_private_file(conf_path, &conf)?;
                write_private_file(&self.secrets_file, &secrets)?;
            }
        }

        verify_mode(&self.secrets_file, FILE_MODE)?;
        verify_mode(conf_path, FILE_MODE)?;

        // Module names are not secret enough to publish, but they are not the
        // secret either; the secret itself is never logged.
        tracing::info!(
            modules = self.modules.len(),
            conf = %conf_path.display(),
            "wrote rsync daemon configuration"
        );
        Ok(())
    }

    fn secrets_file_as_str(&self) -> Result<&str> {
        let text = self
            .secrets_file
            .to_str()
            .ok_or_else(|| anyhow!("secrets file path is not valid UTF-8"))?;
        check_conf_value("secrets file", text)?;
        if !self.secrets_file.is_absolute() {
            return Err(anyhow!("secrets file path must be absolute"));
        }
        Ok(text)
    }

    fn check_unique_module_names(&self) -> Result<()> {
        let mut seen = HashSet::new();
        for module in &self.modules {
            if !seen.insert(module.name.as_str()) {
                return Err(anyhow!("duplicate module name {:?}", module.name));
            }
        }
        Ok(())
    }

    /// The secrets file must not sit inside any shared directory.
    ///
    /// Otherwise a peer could simply pull it: the module serves its own share
    /// root, so every file below it is readable to whoever holds one secret —
    /// including the secrets of all other pairings.
    fn ensure_secrets_outside_shares(&self) -> Result<()> {
        let secrets = resolve_for_comparison(&self.secrets_file)?;
        for module in &self.modules {
            let root = Path::new(&module.path);
            if secrets.starts_with(root) {
                return Err(anyhow!(
                    "secrets file {} lies inside the share root {} and would be \
                     readable through the module",
                    secrets.display(),
                    module.path
                ));
            }
        }
        Ok(())
    }
}

/// Which of the two files is replaced first. See [`DaemonConfig::write_in_order`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyOrder {
    /// For a new module: the secret exists before the module is nameable.
    SecretsFirst,
    /// For a revoke: the module disappears before its secret does.
    ConfFirst,
}

// ---------------------------------------------------------------------------
// Runtime module registry (ticket ae12dcd1)
//
// A pairing that has just been granted must be usable without restarting the
// daemon, and a revoked one must stop working just as immediately. Both are
// possible because of a property of rsync that was verified rather than
// assumed — the measurement is written down at `mod real_rsync_probe` at the
// end of this file:
//
//   * rsync re-reads `rsyncd.conf` on **every incoming connection**, before it
//     decides which module was asked for. Adding a module makes it reachable
//     with the next connection; removing one turns the next attempt into
//     `@ERROR: Unknown module '<name>'`. No signal, no restart, no reload
//     command — rsync has none of those. Measured on 3.4.3 (the image) and
//     3.5.0 (the host), both behave the same.
//
//   * A transfer that is already running keeps the configuration it started
//     with, because the daemon forks a child per connection and that child has
//     read the module before the change. Rewriting the file therefore never
//     tears down a running transfer, not even a transfer on the module that is
//     being revoked. A revoke stops the *next* connection, not the current one
//     — anything that has to interrupt a transfer in flight needs to kill the
//     child, which belongs to the lifecycle ticket 3ed12cdd.
//
// The registry is the in-memory picture of what is on disk. Every change is
// written through immediately; if the write fails, the in-memory state is
// rolled back, so the two never drift apart.
// ---------------------------------------------------------------------------

/// Creates and removes daemon modules while the daemon is running.
#[derive(Debug, Clone)]
pub struct ModuleRegistry {
    conf_path: PathBuf,
    config: DaemonConfig,
}

impl ModuleRegistry {
    /// A registry over `conf_path` and `secrets_file`, without touching disk.
    ///
    /// Nothing is written here: an empty configuration would be written over an
    /// existing one, and a daemon that is already running would lose every
    /// module the moment the registry is constructed. Call
    /// [`ModuleRegistry::apply`] once the modules are restored from the
    /// database.
    pub fn new(conf_path: impl Into<PathBuf>, secrets_file: impl Into<PathBuf>) -> Self {
        Self {
            conf_path: conf_path.into(),
            config: DaemonConfig::new(secrets_file),
        }
    }

    /// The same registry, generating for `hardening`.
    ///
    /// The startup in `src/main.rs` detects the mode once and hands it to the
    /// registry and to [`DaemonSettings`] together; a registry that generated
    /// `use chroot = yes` while the daemon was told to use the unprivileged
    /// port would be the half-migrated state this exists to make impossible.
    pub fn with_hardening(mut self, hardening: Hardening) -> Self {
        self.config.set_hardening(hardening);
        self
    }

    /// How much hardening the generated configuration asks for.
    pub fn hardening(&self) -> Hardening {
        self.config.hardening()
    }

    /// The path of the generated `rsyncd.conf`.
    pub fn conf_path(&self) -> &Path {
        &self.conf_path
    }

    /// The configuration as it stands on disk.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Tell the daemon where to write its log. See
    /// [`DaemonConfig::with_log_file`] — it belongs in the configuration file,
    /// not on the command line, or the audit lines never appear.
    pub fn set_log_file(&mut self, path: impl Into<PathBuf>) {
        self.config.set_log_file(path);
    }

    /// The modules currently configured.
    pub fn modules(&self) -> &[ModuleConfig] {
        self.config.modules()
    }

    /// Whether a module of that name is configured.
    pub fn contains(&self, module_name: &str) -> bool {
        self.config.module(module_name).is_some()
    }

    /// Write the current set of modules out, replacing whatever is there.
    ///
    /// Used to publish the modules restored from the database at startup, and
    /// by the tests; the incremental paths are [`ModuleRegistry::add_pairing`]
    /// and [`ModuleRegistry::revoke`].
    pub fn apply(&self) -> Result<()> {
        self.config
            .write_in_order(&self.conf_path, ApplyOrder::SecretsFirst)
    }

    /// Restore a module that is already known, e.g. from the database.
    ///
    /// Unlike [`ModuleRegistry::add_pairing`] this does not write; a caller
    /// restoring many modules at startup writes once at the end.
    pub fn insert_module(&mut self, module: ModuleConfig) -> Result<()> {
        if self.contains(module.name()) {
            return Err(anyhow!("module {:?} is already configured", module.name()));
        }
        self.config.add_module(module);
        Ok(())
    }

    /// Add a module for a new pairing and publish it to the running daemon.
    ///
    /// Returns the module including its secret — the only moment the secret is
    /// available, since it is generated here and afterwards only lives in
    /// `rsyncd.secrets`. The caller hands it to the peer once and stores it;
    /// it must not reach a log or the UI.
    ///
    /// If the write fails, the module is dropped again, so the registry keeps
    /// describing what is really on disk.
    pub fn add_pairing(
        &mut self,
        share_root: &Path,
        has_write_scope: bool,
        uid: u32,
        gid: u32,
        max_connections: u32,
    ) -> Result<ModuleConfig> {
        let module = ModuleConfig::new(share_root, has_write_scope, uid, gid, max_connections)?;
        // A collision is astronomically unlikely with 64 bits of randomness,
        // but a duplicate section would silently shadow an existing pairing.
        if self.contains(module.name()) {
            return Err(anyhow!(
                "generated module name collides with an existing one"
            ));
        }
        self.config.add_module(module.clone());

        if let Err(e) = self
            .config
            .write_in_order(&self.conf_path, ApplyOrder::SecretsFirst)
        {
            self.config.remove_module(module.name());
            return Err(e);
        }

        tracing::info!(
            module = module.name(),
            read_only = module.read_only(),
            "added rsync module for a new pairing"
        );
        Ok(module)
    }

    /// Remove the module of a revoked pairing.
    ///
    /// Returns `false` if there was no such module — a revoke that arrives
    /// twice is not an error, the outcome is the one that was asked for.
    ///
    /// The rewritten configuration takes effect for the next connection; a
    /// transfer that is already running on this module finishes (see the note
    /// above the registry). Modules of other pairings are untouched.
    pub fn revoke(&mut self, module_name: &str) -> Result<bool> {
        let Some(removed) = self.config.remove_module(module_name) else {
            return Ok(false);
        };

        if let Err(e) = self
            .config
            .write_in_order(&self.conf_path, ApplyOrder::ConfFirst)
        {
            // Put it back: the module is still in the file on disk. It lands at
            // the end of the list, which changes the order of the sections but
            // nothing else — rsync looks modules up by name.
            self.config.add_module(removed);
            return Err(e);
        }

        tracing::info!(module = module_name, "removed rsync module after a revoke");
        Ok(true)
    }
}

/// Resolve a path far enough to compare it with a canonicalised share root.
///
/// Neither the file nor its directory has to exist yet, so this canonicalises
/// the deepest ancestor that does exist — which resolves every symlink and
/// `..` along the way — and appends the remaining components unchanged. Doing
/// it this way means the containment check runs *before* anything is created,
/// so a rejected configuration leaves no directory behind.
fn resolve_for_comparison(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(anyhow!("{} must be an absolute path", path.display()));
    }
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut current = path;
    loop {
        if let Ok(canonical) = fs::canonicalize(current) {
            let mut resolved = canonical;
            for component in rest.iter().rev() {
                resolved.push(component);
            }
            return Ok(resolved);
        }
        let name = current
            .file_name()
            .ok_or_else(|| anyhow!("{} cannot be resolved", path.display()))?;
        rest.push(name);
        current = current
            .parent()
            .ok_or_else(|| anyhow!("{} cannot be resolved", path.display()))?;
    }
}

/// Write `content` to `path` with mode 0600, atomically.
///
/// The content goes into a temporary file in the *same* directory (so that
/// `rename` stays within one filesystem and is therefore atomic), is flushed to
/// disk, and only then replaces `path`. Truncating `path` in place would be
/// visible to a daemon that reads the file at the same moment: rsync re-reads
/// `rsyncd.conf` on every incoming connection (measured, see the probe at the
/// end of this file), so a plain `write` has a window in which a connection
/// reads half a configuration — a truncated module section is not a parse
/// error, it is a module with different settings.
///
/// The directory is fsynced after the rename so that the replacement survives a
/// crash; without it the rename may still be in the page cache while the new
/// file's data is already durable, and the daemon could come back to the old
/// configuration.
///
/// The temporary name carries random bytes, so two writers cannot collide on
/// it, and it is removed again if anything between creation and rename fails.
fn write_private_file(path: &Path, content: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("cannot create directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?
        .to_string_lossy()
        .into_owned();
    let temp_path = parent.join(format!(".{file_name}.{}.tmp", random_hex(8)?));

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&temp_path)
            .with_context(|| format!("cannot create {}", temp_path.display()))?;
        file.write_all(content.as_bytes())
            .with_context(|| format!("cannot write {}", temp_path.display()))?;
        // `mode` above is masked by the umask, so set the mode explicitly
        // before the file becomes reachable under its final name.
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(FILE_MODE))
            .with_context(|| format!("cannot set permissions on {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("cannot flush {}", temp_path.display()))?;
        fs::rename(&temp_path, path)
            .with_context(|| format!("cannot replace {}", path.display()))?;
        Ok(())
    })();

    if result.is_err() {
        // Leave no half-written file behind; the rename is the only step that
        // is allowed to have an effect.
        let _ = fs::remove_file(&temp_path);
        return result;
    }
    sync_directory(parent);
    Ok(())
}

/// Flush a directory entry so a completed `rename` is durable.
///
/// A failure here is not fatal for the running daemon — the new file is already
/// in place for every reader — so it is logged rather than propagated; some
/// filesystems refuse `fsync` on a directory outright.
fn sync_directory(dir: &Path) {
    match fs::File::open(dir) {
        Ok(handle) => {
            if let Err(e) = handle.sync_all() {
                tracing::debug!(dir = %dir.display(), error = %e, "cannot fsync directory");
            }
        }
        Err(e) => tracing::debug!(dir = %dir.display(), error = %e, "cannot open directory"),
    }
}

/// Read the mode back and fail if it is not exactly `expected`.
fn verify_mode(path: &Path, expected: u32) -> Result<()> {
    let mode = fs::metadata(path)
        .with_context(|| format!("cannot stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != expected {
        return Err(anyhow!(
            "{} has mode {:04o}, expected {:04o}; rsync would report this as \
             \"auth failed\", indistinguishable from a wrong secret",
            path.display(),
            mode,
            expected
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Daemon process lifecycle (ticket 3ed12cdd)
//
// The daemon runs as a child of the application: started with it, stopped with
// it, restarted when it dies. Everything below is shaped by what a real daemon
// actually does rather than by what the manual page suggests; the measurements
// are recorded at each decision and reproduced by `mod real_rsync_probe`.
//
//   * `--no-detach` — without it rsync forks away and the application has no
//     child to wait on, no exit status and nothing to signal.
//
//   * **stdin must be `/dev/null`.** `rsync --daemon` inspects its standard
//     input and, if it looks like a connection, serves that one connection in
//     inetd mode instead of listening. Inheriting the parent's stdin was
//     measured to produce `connect from UNKNOWN` and a daemon that hangs
//     forever without ever binding the port — a failure mode with no error
//     message at all.
//
//   * **`--log-file` is not optional.** Without it the daemon logs to *syslog*,
//     not to stderr, so there is nothing to mirror: with stderr captured and no
//     log file the pipe stays empty. `--log-file=/dev/stderr` does not help
//     either, it was measured to produce an empty stream. So the daemon writes
//     a real file and [`mirror_log_file`] follows it. stdout and stderr are
//     still captured, because fatal startup errors go there and never reach the
//     log file.
//
//   * **`lock file` must be set.** `max connections` needs one and the built-in
//     default is `/var/run/rsyncd.lock`. If that path is not writable, *every*
//     transfer fails with `@ERROR: failed to open lock file` — not just the one
//     over the limit. It is passed as `--dparam` so that the generated
//     configuration stays a pure description of the modules.
//
//   * **"is one already running" is the pid file lock.** rsync holds an
//     exclusive `flock` on its pid file for its whole life. A second daemon on
//     the same pid file exits **11** and writes `failed to lock pid file
//     <path>: Resource temporarily unavailable`, both to the log file and to
//     stderr. That is the detection: it needs no `flock` of our own, it cannot
//     be fooled by a stale pid file, and it is the daemon's own answer rather
//     than a guess about one.
//
//   * **SIGTERM, never SIGKILL first.** A daemon killed hard leaves its
//     children's partial destination files behind, which rsync never cleans up
//     again (85 MB after one test run). SIGKILL stays as the escalation for a
//     daemon that ignores SIGTERM, and it is logged as the data-costing event
//     that it is. What it leaves behind is confined to the modules' own temp
//     directories (see [`MODULE_TEMP_DIR`]) and swept on the next start.
//
//   * **Reaping.** The supervisor `wait()`s on its own child on every path, so
//     the daemon itself is never left a zombie. Its per-connection children are
//     a different matter — they are grandchildren, and only their own parent
//     can reap them. Measured over 30 transfers against a daemon whose parent
//     is *not* pid 1, on rsync 3.4.3 and 3.5.0: zero zombies, the daemon reaps
//     its children itself. See [`DaemonStatus::zombie_children`], which counts
//     them so a regression shows up in the status rather than in a full process
//     table.
// ---------------------------------------------------------------------------

/// The rsync binary, when the caller does not name one.
pub const DEFAULT_RSYNC_BINARY: &str = "rsync";

/// Daemon parameters that must never be overridden from the command line.
///
/// See [`DaemonSettings::check_listen_is_not_overridden`] for what happens when
/// they are.
const LISTEN_PARAMS: &[&str] = &["address", "port"];

/// How long a daemon must survive before its restart counter is forgiven.
const RESTART_BACKOFF_RESET: Duration = Duration::from_secs(60);
/// First restart delay; doubles per consecutive failure up to the cap.
const RESTART_BACKOFF_MIN: Duration = Duration::from_millis(250);
/// Cap for the restart delay.
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long a daemon gets to act on SIGTERM before SIGKILL follows.
const SIGTERM_GRACE: Duration = Duration::from_secs(10);
/// Poll interval while following the daemon's log file.
const LOG_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long a start waits for the daemon to accept a connection.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Delay between connect attempts while waiting for the daemon to bind.
///
/// A refused connection on loopback comes back at once, so this is the whole
/// cost of a poll. Short, because the wait sits in the application's startup
/// path and the daemon usually binds within a few milliseconds.
const LISTEN_RETRY_INTERVAL: Duration = Duration::from_millis(25);
/// A file in a module temp directory younger than this is left alone.
///
/// The sweep only ever looks inside [`MODULE_TEMP_DIR`], so this is not a
/// safeguard against mistaking a user file for a temp file — that mistake is
/// no longer possible. It guards the one case the sweep cannot rule out by
/// construction: a second application instance on the same share, whose daemon
/// is writing into that temp file right now. rsync keeps writing, so an
/// in-flight temp file is never this old. Ten minutes is long enough for that
/// and short enough that a crashed daemon's remains are reclaimed on the next
/// start rather than an hour later.
const DEFAULT_TEMP_FILE_MIN_AGE: Duration = Duration::from_secs(600);

/// Where the daemon's files live and how it is invoked.
///
/// The paths are derived from one run directory rather than configured
/// individually: the pid file, the lock file and the log file always belong
/// together, and a deployment that gets one of them right and another wrong is
/// exactly the failure this is meant to prevent.
#[derive(Debug, Clone)]
pub struct DaemonSettings {
    binary: PathBuf,
    conf_path: PathBuf,
    run_dir: PathBuf,
    port: u16,
    extra_dparams: Vec<String>,
    temp_file_min_age: Duration,
    sweep_temp_files: bool,
    /// Where stunnel writes its log, the only source of the real client IP.
    stunnel_log: Option<PathBuf>,
    /// Whether the audit log is written to disk as well as to `tracing`.
    write_audit_file: bool,
    /// Size of the audit log at which the watchdog warns. `0` disables it.
    log_warn_bytes: u64,
    /// Size of the whole run directory at which the watchdog warns.
    run_dir_warn_bytes: u64,
    /// How long the start waits for the daemon to answer on its port.
    ///
    /// [`LISTEN_TIMEOUT`] in production. Configurable only so that the failure
    /// *after* a successful spawn can be provoked in an ordinary test instead of
    /// an `#[ignore]`d one — without it that test would sit out thirty seconds,
    /// and a thirty-second test is a test that gets deleted.
    listen_timeout: Duration,
}

impl DaemonSettings {
    /// Settings for the configuration at `conf_path`, with the pid, lock and
    /// log files under `run_dir`.
    pub fn new(conf_path: impl Into<PathBuf>, run_dir: impl Into<PathBuf>) -> Self {
        let conf_path = conf_path.into();
        let stunnel_log = default_stunnel_log(&conf_path);
        Self {
            binary: PathBuf::from(DEFAULT_RSYNC_BINARY),
            conf_path,
            run_dir: run_dir.into(),
            port: DAEMON_PORT,
            extra_dparams: Vec::new(),
            temp_file_min_age: DEFAULT_TEMP_FILE_MIN_AGE,
            sweep_temp_files: true,
            stunnel_log,
            write_audit_file: true,
            log_warn_bytes: size_limit_from_env(
                "RCLONE_GUI_LOG_WARN_BYTES",
                DEFAULT_LOG_WARN_BYTES,
            ),
            run_dir_warn_bytes: size_limit_from_env(
                "RCLONE_GUI_RUN_DIR_WARN_BYTES",
                DEFAULT_RUN_DIR_WARN_BYTES,
            ),
            listen_timeout: LISTEN_TIMEOUT,
        }
    }

    /// Read the real client addresses from the stunnel log at `path`.
    ///
    /// See [`StunnelIndex`] for what is read out of it and why there is no
    /// other source for the peer address.
    pub fn with_stunnel_log(mut self, path: impl Into<PathBuf>) -> Self {
        self.stunnel_log = Some(path.into());
        self
    }

    /// Do not try to correlate with stunnel at all. The audit log then records
    /// the client address as unavailable rather than guessing.
    pub fn without_stunnel_log(mut self) -> Self {
        self.stunnel_log = None;
        self
    }

    /// Keep the audit log in memory only, without the file next to the daemon's.
    pub fn without_audit_file(mut self) -> Self {
        self.write_audit_file = false;
        self
    }

    /// Warn once any single log in the run directory is larger than `bytes`.
    /// `0` turns it off.
    ///
    /// The watchdog only ever *reports*; see [`RunDirWatch`] for why it does
    /// not truncate anything it looks at.
    pub fn with_log_warn_bytes(mut self, bytes: u64) -> Self {
        self.log_warn_bytes = bytes;
        self
    }

    /// Warn once the whole run directory is larger than `bytes`. `0` turns it
    /// off.
    pub fn with_run_dir_warn_bytes(mut self, bytes: u64) -> Self {
        self.run_dir_warn_bytes = bytes;
        self
    }

    /// Use a different rsync binary, e.g. one inside a container.
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Listen on a different port. Only the probes need this; in production the
    /// port is [`DAEMON_PORT`] behind the TLS terminator.
    /// Spawn for `hardening`: the port moves with it.
    ///
    /// The port is the only thing in [`DaemonSettings`] the mode touches — the
    /// chroot and the uid/gid live in the generated configuration
    /// ([`DaemonConfig::with_hardening`]) — but it has to move at the same
    /// time, or the daemon binds a port nothing connects to.
    pub fn with_hardening(mut self, hardening: Hardening) -> Self {
        self.port = hardening.port();
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// How long the start waits for the daemon to answer on its port.
    ///
    /// The default is [`LISTEN_TIMEOUT`] and production has no reason to change
    /// it. See the field for why it can be changed at all.
    pub fn with_listen_timeout(mut self, timeout: Duration) -> Self {
        self.listen_timeout = timeout;
        self
    }

    /// Pass an extra `--dparam=<key>=<value>` to the daemon.
    ///
    /// Meant for the probes (`strict modes=no` when the configuration is
    /// bind-mounted from another user). Production settings belong in the
    /// generated configuration, not here.
    ///
    /// A dparam that names one of [`LISTEN_PARAMS`] is refused by
    /// [`DaemonSettings::check_listen_is_not_overridden`] at start; see there
    /// for the measurement.
    pub fn with_dparam(mut self, param: impl Into<String>) -> Self {
        self.extra_dparams.push(param.into());
        self
    }

    /// Refuse a dparam that would move the daemon off loopback.
    ///
    /// # The measurement this exists for
    ///
    /// `address = 127.0.0.1` in the generated configuration is the whole reason
    /// the plaintext daemon is unreachable and stunnel on 874 is the only way
    /// in. `--dparam` **overrides it**: measured on the host (rsync 3.5.0),
    /// the same generated configuration started with
    /// `--dparam=address=0.0.0.0` gave
    ///
    /// ```text
    /// LISTEN 0 5 0.0.0.0:18690 0.0.0.0:*
    /// ```
    ///
    /// — the rsync protocol, unauthenticated challenge-response over md5, on
    /// every interface, with no TLS anywhere near it. Nothing in the
    /// application noticed, because the configuration file still said
    /// `address = 127.0.0.1` and every existing test reads the file.
    ///
    /// So the escape hatch that exists for the probes is closed for these two
    /// keys. `port` is in the list as well: a daemon on a port the application
    /// does not know about is a daemon it cannot supervise, check or shut down
    /// — [`DaemonSettings::with_port`] is the way to move it.
    ///
    /// This is the cheap half. The other half does not trust the argument
    /// vector at all and looks at what the kernel says: see
    /// [`DaemonHandle::verify_it_listens_on_loopback_only`].
    fn check_listen_is_not_overridden(&self) -> Result<()> {
        for param in &self.extra_dparams {
            let key = param.split('=').next().unwrap_or(param).trim();
            if LISTEN_PARAMS.contains(&key) {
                return Err(anyhow!(
                    "refusing to start the rsync daemon with --dparam={param}: \"{key}\" \
                     decides where the plaintext daemon can be reached, and it must stay on \
                     {DAEMON_ADDRESS} behind the TLS terminator — there is no unencrypted \
                     peer path"
                ));
            }
        }
        Ok(())
    }

    /// How old a temp file has to be before the startup sweep removes it.
    pub fn with_temp_file_min_age(mut self, age: Duration) -> Self {
        self.temp_file_min_age = age;
        self
    }

    /// Turn the startup sweep for orphaned temp files off.
    pub fn without_temp_file_sweep(mut self) -> Self {
        self.sweep_temp_files = false;
        self
    }

    /// The generated configuration the daemon reads.
    pub fn conf_path(&self) -> &Path {
        &self.conf_path
    }

    /// The pid file — also the "is one already running" lock.
    pub fn pid_file(&self) -> PathBuf {
        self.run_dir.join("rsyncd.pid")
    }

    /// The lock file `max connections` needs.
    pub fn lock_file(&self) -> PathBuf {
        self.run_dir.join("rsyncd.lock")
    }

    /// The log file that gets mirrored into the application log.
    pub fn log_file(&self) -> PathBuf {
        self.run_dir.join("rsyncd.log")
    }

    /// The audit log: one JSON object per line, next to the daemon's own log.
    ///
    /// **This file is append-only and is never rotated or truncated here.** The
    /// in-memory ring behind [`DaemonHandle::audit_events`] is capped at
    /// [`AUDIT_RING_CAPACITY`], the file is not: it grows with every transferred
    /// file, for as long as the daemon runs.
    ///
    /// That is deliberate and it is stated rather than quietly fixed. Rotating
    /// an audit log from inside the process that writes it means the process
    /// can also delete evidence, and a size cap that silently drops the oldest
    /// lines turns "there is no record of it" into an ambiguous statement.
    /// Whoever operates this deployment rotates the file from outside
    /// (logrotate, a volume with a quota) — but they have to know that they
    /// must, which is what this note is for.
    ///
    /// Since ticket 0cedda6f they are also *told*: [`RunDirWatch`] measures
    /// this file and the rest of the run directory once a minute and warns
    /// when it passes [`DaemonSettings::log_warn_bytes`]. It still deletes
    /// nothing. `config/logrotate-rclone-gui.conf` is the rotation the warning
    /// points at; the sink opens this file per line (see [`AuditSink::record`]),
    /// so a plain rename-and-create rotation needs no signal and loses no line.
    pub fn audit_file(&self) -> PathBuf {
        self.run_dir.join("audit.log")
    }

    /// Where stunnel has been told to write its log, if anywhere.
    pub fn stunnel_log(&self) -> Option<&Path> {
        self.stunnel_log.as_deref()
    }

    /// The port the daemon listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The full argument vector, in the order the daemon sees it.
    ///
    /// Deliberately **without** `--log-file`: that switch silences the per-file
    /// audit lines, and the path is rendered into `rsyncd.conf` instead. The
    /// full measurement is on [`DaemonConfig::with_log_file`].
    fn argv(&self) -> Vec<String> {
        let mut args = vec![
            "--daemon".to_string(),
            "--no-detach".to_string(),
            format!("--config={}", self.conf_path.display()),
            format!("--port={}", self.port),
            format!("--dparam=pid file={}", self.pid_file().display()),
            format!("--dparam=lock file={}", self.lock_file().display()),
        ];
        for param in &self.extra_dparams {
            args.push(format!("--dparam={param}"));
        }
        args
    }
}

/// Where the stunnel log is expected when nobody says otherwise.
///
/// `config/rsync-tls.sh` renders `stunnel.conf` next to `rsyncd.conf` (both
/// under `$RSYNCD_DIR`), so the log belongs there too and no deployment has to
/// configure a path. `RCLONE_GUI_STUNNEL_LOG` overrides it for a deployment
/// that puts it elsewhere.
fn default_stunnel_log(conf_path: &Path) -> Option<PathBuf> {
    if let Ok(from_env) = std::env::var("RCLONE_GUI_STUNNEL_LOG") {
        let trimmed = from_env.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(PathBuf::from(trimmed));
    }
    Some(conf_path.parent()?.join("stunnel.log"))
}

// ---------------------------------------------------------------------------
// Audit log
//
// The question this answers is "who used which module, when, and with what
// effect" — and it is answered out of two log files, not one, because neither
// of them holds the whole answer.
//
// What the *daemon* log holds, all of it measured on rsync 3.5.0 (host) and
// 3.4.3 (alpine:3.22, the image), with `log file` in the configuration (see
// `DaemonConfig::with_log_file` for why that matters):
//
//   [21] connect from localhost (127.0.0.1)
//   [21] rsync allowed access on module m1 from localhost (127.0.0.1)
//   [21] rsync to m1/ from m1@localhost (127.0.0.1)          <- write session
//   [26] rsync on m1/ from m1@localhost (127.0.0.1)          <- read session
//   [21] rclone-gui-audit 127.0.0.1 m1 m1 recv 6 6 a.txt     <- one per file
//   [24] rsync: The server is configured to refuse --delete   <- refused option
//   [21] sent 40 bytes  received 62930045 bytes  total size 62914560
//   [45] auth failed on module m1 from localhost (127.0.0.1) for m1: password mismatch
//   [46] unknown module 'x' tried from localhost (127.0.0.1)
//
// What it does **not** hold, and what no amount of verbosity produces:
//
//   * the client's option list. `-v` and `-vv` on the daemon were measured and
//     add only `receiving file list` and a `./` line. rsync never logs the
//     arguments it was given. What is recorded instead is what is observable:
//     the direction of the session, the operation per file, and every option
//     the daemon *refused* — which is the interesting half anyway.
//   * the client's address. It is always loopback, because stunnel terminates
//     TLS there. Reporting it as the client would be a lie, so it is not
//     reported at all: see `ClientAddressSource`.
//
// The real address comes from the stunnel log, and the two are joined over the
// port — see `StunnelIndex` and `peer_port_of_child`.
// ---------------------------------------------------------------------------

/// What happened, in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// A connection reached the daemon, before any module was named.
    Connected,
    /// Authentication succeeded for a module.
    AccessGranted,
    /// Authentication failed, or a module that does not exist was asked for.
    AccessDenied,
    /// The session's direction became known: the client is writing.
    SessionWrite,
    /// The session's direction became known: the client is reading.
    SessionRead,
    /// One file was written into the module.
    FileReceived,
    /// One file was read out of the module.
    FileSent,
    /// One file was **deleted** in the module.
    FileDeleted,
    /// The daemon refused an option the client asked for.
    OptionRefused,
    /// The session ended with rsync's own summary.
    SessionEnd,
    /// The daemon reported an error inside a session.
    Error,
}

impl AuditAction {
    /// Whether this action destroyed data, or tried to.
    ///
    /// The two are deliberately in one flag: today `--delete` is refused
    /// unconditionally (see [`REFUSED_OPTIONS`]), so a real
    /// [`AuditAction::FileDeleted`] cannot occur through a generated module at
    /// all and the only visible destruction is the *attempt*. An audit log that
    /// only marked successful deletions would therefore mark nothing, ever,
    /// and would look identical whether or not anybody had tried. Both are
    /// marked, and the action says which of the two it was.
    fn is_destructive(self) -> bool {
        matches!(self, AuditAction::FileDeleted)
    }
}

/// Where the client address in an audit event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAddressSource {
    /// From the stunnel log, matched to this session over the backend port.
    /// The exact case: no guessing involved.
    StunnelPort,
    /// From the stunnel log, matched by time because the port lookup came up
    /// empty (a very short connection, or `/proc` not readable). One of
    /// several concurrent connections could in principle be confused this way,
    /// which is why it is a distinct value and not folded into the one above.
    StunnelTime,
    /// No address. Either stunnel does not write a log we can read, or nothing
    /// in it matched.
    ///
    /// **Not** filled in with the loopback address from the daemon log. That
    /// address is stunnel's, not the client's, and an audit log that records
    /// `127.0.0.1` for every peer on earth has failed at its one job while
    /// looking complete. Absent and honest beats present and wrong.
    Unavailable,
}

/// One line of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditEvent {
    /// The daemon's own timestamp for the line, `YYYY/MM/DD HH:MM:SS` local.
    /// Taken from the log rather than from the clock here, so it is the moment
    /// the daemon acted and not the moment we got round to reading it.
    pub at: String,
    /// The daemon child that served this connection.
    pub pid: u32,
    /// The module, once it is known.
    pub module: Option<String>,
    /// The authenticated user, once it is known. For a generated pairing this
    /// equals the module name (`auth users = <module>`).
    pub user: Option<String>,
    /// The real client address, or `None`. See [`ClientAddressSource`].
    pub client: Option<String>,
    /// The client's source port on the TLS side, when it is known.
    pub client_port: Option<u16>,
    /// How the address was established.
    pub client_source: ClientAddressSource,
    /// What happened.
    pub action: AuditAction,
    /// Whether data was destroyed. Attempts are recorded as
    /// [`AuditAction::OptionRefused`] with `refused_option` set.
    pub destructive: bool,
    /// The file, for the per-file actions.
    pub path: Option<String>,
    /// The file's size, for the per-file actions.
    pub size: Option<u64>,
    /// The option the daemon refused, for [`AuditAction::OptionRefused`].
    pub refused_option: Option<String>,
    /// The log line this was derived from, verbatim, minus the timestamp and
    /// pid. Keeping it means a reader is never left wondering what the daemon
    /// actually said.
    pub detail: String,
}

impl AuditEvent {
    /// Whether this event is a delete or an attempt at one.
    ///
    /// Both halves matter and they are easy to conflate: `destructive` says
    /// data was actually removed, this says the session was *about* removing
    /// data. With the shipped `refuse options` only the second can ever be
    /// true.
    pub fn concerns_deletion(&self) -> bool {
        self.destructive
            || self
                .refused_option
                .as_deref()
                .is_some_and(is_destructive_option)
    }
}

/// Whether a refused option name is one that destroys data.
///
/// The names are the ones rsync prints in `The server is configured to refuse
/// --<name>`, so they arrive without the leading dashes here. `delete` covers
/// the whole family (`--delete`, `--delete-before`, … `--delete-missing-args`),
/// `remove-source-files` empties the *sender's* directory. Both are in
/// [`REFUSED_OPTIONS`] and both are marked.
fn is_destructive_option(option: &str) -> bool {
    let option = option.trim_start_matches('-');
    option.starts_with("delete") || option == "remove-source-files" || option == "del"
}

/// What is known about one connection while it is running.
#[derive(Debug, Clone, Default)]
struct Session {
    module: Option<String>,
    user: Option<String>,
    client: Option<String>,
    client_port: Option<u16>,
    client_source: Option<ClientAddressSource>,
}

/// Writes audit events to their file and into the application log.
///
/// The in-memory ring lives on [`DaemonState`] so that the status API can read
/// it; this only owns the file. A failure to write is logged once and then
/// swallowed: an audit log that cannot be written is bad, a daemon that stops
/// serving because of it is worse, and the `tracing` copy still gets out.
#[derive(Debug)]
struct AuditSink {
    path: Option<PathBuf>,
    complained: bool,
}

impl AuditSink {
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            complained: false,
        }
    }

    /// Record one event. Never fails; see the note on the struct.
    fn record(&mut self, event: &AuditEvent) {
        tracing::info!(
            target: "rsync_audit",
            pid = event.pid,
            module = event.module.as_deref().unwrap_or("-"),
            user = event.user.as_deref().unwrap_or("-"),
            client = event.client.as_deref().unwrap_or("unavailable"),
            client_source = ?event.client_source,
            action = ?event.action,
            destructive = event.destructive,
            path = event.path.as_deref().unwrap_or("-"),
            "rsync audit: {}",
            event.detail
        );
        let Some(path) = &self.path else { return };
        let Ok(line) = serde_json::to_string(event) else {
            return;
        };
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(FILE_MODE)
            .open(path)
            .and_then(|mut file| writeln!(file, "{line}"));
        if let Err(e) = written {
            if !self.complained {
                self.complained = true;
                tracing::warn!(
                    audit_log = %path.display(),
                    error = %e,
                    "cannot write the rsync audit log; events stay in the application log"
                );
            }
        }
    }
}

/// One connection as stunnel saw it.
#[derive(Debug, Clone)]
struct StunnelConnection {
    /// stunnel's own timestamp, `YYYY.MM.DD HH:MM:SS` local.
    at: Option<chrono::NaiveDateTime>,
    /// The real client address.
    peer: String,
    /// The client's source port.
    peer_port: u16,
    /// stunnel's source port towards the daemon — the join key.
    backend_port: Option<u16>,
    /// Whether a daemon session has already taken this entry.
    claimed: bool,
}

/// Reads the stunnel log and answers "which client is behind this session".
///
/// # Why this file at all
///
/// The daemon log records `connect from localhost (127.0.0.1)` for every peer
/// on earth, because stunnel terminates TLS on the loopback interface. The
/// real address exists in exactly one place, stunnel's own log at `debug = 5`:
///
/// ```text
/// 2026.08.16 05:44:45 LOG5[0]: Service [rsyncd-tls] accepted connection from 192.168.224.3:51840
/// 2026.08.16 05:44:45 LOG5[0]: Service [rsyncd-tls] connected remote server from 127.0.0.1:38790
/// ```
///
/// `proxy protocol` would carry the address into the daemon instead, and it
/// was measured to work on 3.4.3 — it is off by choice, not by necessity.
/// `proxy protocol hosts` is unknown to 3.4.3 (`Unknown Parameter
/// encountered`), so the list of trusted proxies has no effect there and the
/// daemon would believe any PROXY header that reached it. The address in the
/// stunnel log cannot be forged that way. See
/// [`DaemonConfig::with_proxy_protocol`] and `docs/rsync-transport.md`.
///
/// # How the two logs are joined
///
/// The second stunnel line gives the **source port stunnel uses towards the
/// daemon**, and both lines carry the same thread id in `LOG5[<id>]`. On the
/// daemon side that same port is readable from `/proc` for the connection
/// child (see [`peer_port_of_child`]). Matching on it is exact.
///
/// Time is the fallback, not the method: with `max connections = 4` several
/// sessions can open inside one second, and rsync's log resolution is one
/// second. A match made that way is labelled [`ClientAddressSource::StunnelTime`]
/// so a reader can tell the two apart.
#[derive(Debug)]
struct StunnelIndex {
    path: PathBuf,
    offset: u64,
    pending: String,
    /// stunnel thread id -> index into `connections`, to join the two lines.
    by_thread: HashMap<String, usize>,
    connections: std::collections::VecDeque<StunnelConnection>,
    /// How many entries have been dropped off the front, so that the indices
    /// in `by_thread` stay meaningful.
    dropped: usize,
    /// Set once the missing log has been reported, so it is said once.
    complained: bool,
    /// Smallest observed `own local time - stunnel line time`, i.e. an upper
    /// bound estimate of how far the stunnel clock is behind ours. See
    /// [`StunnelIndex::clock_shift`] for what it is used for.
    skew: Option<chrono::TimeDelta>,
    /// Set once a non-zero clock shift has been reported, so it is said once.
    skew_reported: bool,
}

impl StunnelIndex {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            pending: String::new(),
            by_thread: HashMap::new(),
            connections: std::collections::VecDeque::new(),
            dropped: 0,
            complained: false,
            skew: None,
            skew_reported: false,
        }
    }

    /// Read whatever stunnel has appended since the last call.
    async fn refresh(&mut self) {
        match read_from(&self.path, self.offset).await {
            Ok((chunk, new_offset)) => {
                self.offset = new_offset;
                self.pending.push_str(&chunk);
                let seen_at = chrono::Local::now().naive_local();
                while let Some(index) = self.pending.find('\n') {
                    let line: String = self.pending.drain(..=index).collect();
                    let line = line.trim_end();
                    self.observe_clock(parse_stunnel_time(line), seen_at);
                    self.ingest(line);
                }
            }
            Err(e) => {
                if !self.complained {
                    self.complained = true;
                    tracing::warn!(
                        stunnel_log = %self.path.display(),
                        error = %e,
                        "cannot read the stunnel log, so the audit log cannot name the real \
                         client address; add `output = <path>` to the stunnel configuration \
                         (config/stunnel-rsyncd.conf.template) or set RCLONE_GUI_STUNNEL_LOG"
                    );
                }
            }
        }
    }

    /// Learn how far the stunnel clock is behind ours (ticket 33697f91).
    ///
    /// # Why this is needed at all
    ///
    /// Both logs carry *naive local* timestamps and neither names a zone. The
    /// daemon is this process' own child and therefore writes in this process'
    /// zone, but stunnel is started by `start.sh` and regularly lives in a
    /// container on `TZ=UTC` while the application runs on a host that is not.
    /// Comparing the two as written then misses by whole hours, every time
    /// match fails, and every audit event silently reads
    /// `client_source=unavailable` — it looks like a bug in this module. That
    /// is exactly what happened during the review of `88b8c455`.
    ///
    /// # How the offset is found without asking anybody
    ///
    /// A line cannot have been written after it was read, so
    /// `read time - line time` is never below the true offset; it is only ever
    /// *too large*, by however long the line sat in the file before we got to
    /// it. The smallest value ever seen is therefore the best estimate, and it
    /// improves on its own as fresh lines arrive (the log is polled every
    /// 100 ms, so a line seen in a chunk that just appeared is that fresh).
    /// The initial bulk read of an existing file contributes only old,
    /// too-large values and cannot corrupt the minimum.
    ///
    /// Rounding in [`StunnelIndex::clock_shift`] turns the estimate into an
    /// actual zone offset.
    fn observe_clock(
        &mut self,
        line_at: Option<chrono::NaiveDateTime>,
        seen_at: chrono::NaiveDateTime,
    ) {
        let Some(line_at) = line_at else {
            return;
        };
        let delta = seen_at - line_at;
        if self.skew.is_none_or(|current| delta < current) {
            self.skew = Some(delta);
        }
    }

    /// How many connections are known and how many of them carry the backend
    /// port the exact join needs. Only used to make a failed lookup explain
    /// itself; see [`AuditContext::resolve_client`].
    fn known(&self) -> (usize, usize) {
        (
            self.connections.len(),
            self.connections
                .iter()
                .filter(|c| c.backend_port.is_some())
                .count(),
        )
    }

    /// The estimate from [`StunnelIndex::observe_clock`] as a zone offset.
    ///
    /// Every real zone offset is a whole multiple of 15 minutes, so rounding
    /// there both removes the reading lag and refuses to invent a correction
    /// out of a few seconds of ordinary delay: two processes on the same clock
    /// keep a shift of exactly zero, and the behaviour is unchanged for them.
    /// The rounding also forgives up to 7.5 minutes of staleness in the
    /// smallest observation, which is what makes a single fresh line enough.
    fn clock_shift(&self) -> chrono::TimeDelta {
        let Some(skew) = self.skew else {
            return chrono::TimeDelta::zero();
        };
        let seconds = skew.num_seconds();
        let sign = if seconds < 0 { -1 } else { 1 };
        let rounded = (seconds.abs() + 450) / 900 * 900 * sign;
        chrono::TimeDelta::try_seconds(rounded).unwrap_or_else(chrono::TimeDelta::zero)
    }

    /// Parse one stunnel line, keeping only what a join needs.
    fn ingest(&mut self, line: &str) {
        let Some(thread) = stunnel_thread_id(line) else {
            return;
        };
        if let Some((peer, peer_port)) = stunnel_accepted_peer(line) {
            let connection = StunnelConnection {
                at: parse_stunnel_time(line),
                peer,
                peer_port,
                backend_port: None,
                claimed: false,
            };
            self.connections.push_back(connection);
            self.by_thread
                .insert(thread, self.dropped + self.connections.len() - 1);
            while self.connections.len() > STUNNEL_RING_CAPACITY {
                self.connections.pop_front();
                self.dropped += 1;
            }
            self.by_thread.retain(|_, index| *index >= self.dropped);
            return;
        }
        if let Some(backend_port) = stunnel_backend_port(line) {
            if let Some(index) = self.by_thread.get(&thread) {
                if let Some(entry) = index
                    .checked_sub(self.dropped)
                    .and_then(|i| self.connections.get_mut(i))
                {
                    entry.backend_port = Some(backend_port);
                }
            }
        }
    }

    /// The client behind a session, by port if possible, by time otherwise.
    fn lookup(
        &mut self,
        backend_port: Option<u16>,
        at: Option<chrono::NaiveDateTime>,
    ) -> Option<(String, u16, ClientAddressSource)> {
        if let Some(port) = backend_port {
            if let Some(entry) = self
                .connections
                .iter_mut()
                .rev()
                .find(|c| c.backend_port == Some(port))
            {
                entry.claimed = true;
                return Some((
                    entry.peer.clone(),
                    entry.peer_port,
                    ClientAddressSource::StunnelPort,
                ));
            }
        }
        let at = at?;
        let window = chrono::Duration::from_std(STUNNEL_MATCH_WINDOW).ok()?;
        // Both sides are brought onto this process' clock first; without that
        // the whole time path is a zone-offset lottery (ticket 33697f91).
        let shift = self.clock_shift();
        if !shift.is_zero() && !self.skew_reported {
            self.skew_reported = true;
            tracing::info!(
                stunnel_log = %self.path.display(),
                shift_seconds = shift.num_seconds(),
                "the stunnel log is written on a clock that differs from this process by \
                 {} seconds (a different TZ, typically a container on UTC beside an \
                 application that is not); its timestamps are normalised before they are \
                 matched against the daemon log",
                shift.num_seconds()
            );
        }
        let entry = self
            .connections
            .iter_mut()
            .rev()
            .filter(|c| !c.claimed)
            .find(|c| match c.at {
                // stunnel accepts before the daemon logs the connection, and
                // rsync's log resolution is whole seconds, so a line one second
                // "after" is still the same connection.
                Some(stunnel_at) => {
                    let stunnel_at = stunnel_at + shift;
                    stunnel_at <= at + chrono::Duration::seconds(1) && at - stunnel_at <= window
                }
                None => false,
            })?;
        entry.claimed = true;
        Some((
            entry.peer.clone(),
            entry.peer_port,
            ClientAddressSource::StunnelTime,
        ))
    }
}

/// The thread id stunnel puts in `LOG5[<id>]`.
fn stunnel_thread_id(line: &str) -> Option<String> {
    let start = line.find("LOG")?;
    let open = line[start..].find('[')? + start;
    let close = line[open..].find(']')? + open;
    Some(line[open + 1..close].to_string())
}

/// `accepted connection from <ip>:<port>` — the real client.
fn stunnel_accepted_peer(line: &str) -> Option<(String, u16)> {
    let marker = "accepted connection from ";
    split_host_port(line[line.find(marker)? + marker.len()..].trim())
}

/// `connected remote server from <ip>:<port>` — stunnel's port towards us.
fn stunnel_backend_port(line: &str) -> Option<u16> {
    let marker = "connected remote server from ";
    Some(split_host_port(line[line.find(marker)? + marker.len()..].trim())?.1)
}

/// Split `<host>:<port>`, tolerating the bracketed IPv6 form.
fn split_host_port(value: &str) -> Option<(String, u16)> {
    let value = value.split_whitespace().next()?;
    let colon = value.rfind(':')?;
    let host = value[..colon].trim_matches(['[', ']']);
    let port = value[colon + 1..].parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// The `YYYY.MM.DD HH:MM:SS` at the front of a stunnel line.
fn parse_stunnel_time(line: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(line.get(..19)?, "%Y.%m.%d %H:%M:%S").ok()
}

/// The `YYYY/MM/DD HH:MM:SS` at the front of an rsync log line.
fn parse_rsync_time(line: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(line.get(..19)?, "%Y/%m/%d %H:%M:%S").ok()
}

/// The port the other end of a connection child's socket is using.
///
/// The child inherits the accepted socket, so `/proc/<pid>/fd` holds exactly
/// one socket whose local port is the daemon's. Its remote port is stunnel's
/// source port, which is what the stunnel log's second line names — that is
/// the join. Measured against a running transfer:
///
/// ```text
/// fd=3 inode=10187486 local=0100007F:22A9 remote=0100007F:9A62
/// ```
///
/// (`0x22A9` = 8873, the probe's daemon port; `0x9A62` = 39522, stunnel's.)
///
/// `None` for a connection that has already ended, for a `/proc` this process
/// may not read, and on anything without `/proc`. Every one of those is a
/// fallback to the time match, not an error.
///
/// # In a container this path does not fire at all (measured, ticket 33697f91)
///
/// The connection child runs under the module's uid/gid. After that uid change
/// the process is no longer dumpable, and reading `/proc/<pid>/fd` of another
/// user needs `CAP_SYS_PTRACE`, which is not in Docker's default capability
/// set — the same run reads the link immediately with `--cap-add=SYS_PTRACE`.
/// Neither keeping the uid nor handing out that capability is worth a log
/// field, so both stay as they are (alpine:3.22, rsync 3.4.3).
///
/// So in the container the port path is structurally unavailable and the time
/// normalisation in [`StunnelIndex::observe_clock`] is load-bearing rather
/// than a convenience: it carries the whole join on its own.
fn peer_port_of_child(pid: u32, local_port: u16) -> Option<u16> {
    let mut inodes = HashSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd")).ok()?.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let Some(target) = target.to_str() else {
            continue;
        };
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inodes.insert(inode.to_string());
        }
    }
    if inodes.is_empty() {
        return None;
    }
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = fs::read_to_string(table) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // sl, local_address, rem_address, st, tx:rx, tr:when, retrnsmt,
            // uid, timeout, inode
            let (Some(local), Some(remote), Some(inode)) =
                (fields.get(1), fields.get(2), fields.get(9))
            else {
                continue;
            };
            if !inodes.contains(*inode) {
                continue;
            }
            if hex_port(local) != Some(local_port) {
                continue;
            }
            if let Some(port) = hex_port(remote) {
                return Some(port);
            }
        }
    }
    None
}

/// The port out of a `/proc/net/tcp` address, `<hex address>:<hex port>`.
fn hex_port(address: &str) -> Option<u16> {
    u16::from_str_radix(address.rsplit(':').next()?, 16).ok()
}

/// The address out of a `/proc/net/tcp` or `/proc/net/tcp6` field.
///
/// The kernel prints the address as hexadecimal 32-bit words in **host** byte
/// order, not in network order: `0100007F:0369` is `127.0.0.1:873`, not
/// `1.0.0.127`. Reading it the obvious way round turns loopback into a routable
/// address and back, which is precisely the mistake this parser exists to avoid
/// making — so the words are taken apart with `to_le_bytes` and reassembled.
fn hex_address(field: &str) -> Option<IpAddr> {
    let hex = field.rsplit_once(':')?.0;
    match hex.len() {
        8 => {
            let raw = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (word, slot) in hex.as_bytes().chunks(8).zip(bytes.chunks_mut(4)) {
                let word = std::str::from_utf8(word).ok()?;
                let raw = u32::from_str_radix(word, 16).ok()?;
                slot.copy_from_slice(&raw.to_le_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Whether `address` is one the outside world can reach us on.
///
/// An IPv4-mapped IPv6 address is unwrapped first: a socket on
/// `::ffff:127.0.0.1` is loopback, and `Ipv6Addr::is_loopback` says it is not.
fn is_reachable_from_outside(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => !v4.is_loopback(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => !v4.is_loopback(),
            None => !v6.is_loopback(),
        },
    }
}

/// The `st` value `/proc/net/tcp` uses for a listening socket.
const PROC_TCP_LISTEN: &str = "0A";

/// Every address something is *listening* on `port`, from the two tcp tables.
///
/// `None` when neither table could be read at all — a missing `/proc` is a
/// reason to say so, not to claim the check passed.
fn listening_addresses(port: u16) -> Option<Vec<IpAddr>> {
    let mut found = Vec::new();
    let mut read_one = false;
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = fs::read_to_string(table) else {
            continue;
        };
        read_one = true;
        found.extend(listeners_in_table(&content, port));
    }
    read_one.then_some(found)
}

/// Whether anything but loopback is listening on `port`.
///
/// The body of [`DaemonHandle::verify_it_listens_on_loopback_only`], split off
/// so that both answers can be produced in an ordinary test: a plain
/// `TcpListener` on `127.0.0.1:0` and one on `0.0.0.0:0` are enough, no rsync
/// and no `#[ignore]` needed. A check of this kind that is only ever exercised
/// on the passing side may as well be `Ok(())`.
fn loopback_only_verdict(port: u16) -> Result<()> {
    let Some(addresses) = listening_addresses(port) else {
        tracing::error!(
            port,
            "cannot read /proc/net/tcp, so it is unverified that the rsync daemon is \
             reachable on loopback only; the plaintext daemon must never be reachable \
             from outside — stunnel on the TLS port is the only peer path"
        );
        return Ok(());
    };
    let exposed: Vec<IpAddr> = addresses
        .into_iter()
        .filter(|address| is_reachable_from_outside(*address))
        .collect();
    if exposed.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "the rsync daemon is listening on {exposed:?} as well as {DAEMON_ADDRESS}, so the \
         plaintext rsync protocol is reachable without TLS; refusing to run it — the only \
         peer path is the TLS terminator, and port {port} does not belong outside the host"
    ))
}

/// The listeners on `port` in one `/proc/net/tcp`-shaped table.
///
/// Split out from [`listening_addresses`] so that the parsing can be tested
/// against a captured table instead of against whatever this machine happens to
/// have open.
fn listeners_in_table(content: &str, port: u16) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl, local_address, rem_address, st, ...
        let (Some(local), Some(state)) = (fields.get(1), fields.get(3)) else {
            continue;
        };
        if *state != PROC_TCP_LISTEN || hex_port(local) != Some(port) {
            continue;
        }
        if let Some(address) = hex_address(local) {
            found.push(address);
        }
    }
    found
}

/// What the application knows about the daemon right now.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DaemonStatus {
    /// Whether a daemon process is alive at this moment.
    pub running: bool,
    /// Its pid, while it is running.
    pub pid: Option<u32>,
    /// The address it listens on. Always loopback; see [`DAEMON_ADDRESS`].
    pub address: String,
    /// The port it listens on.
    pub port: u16,
    /// The modules currently published to it, by name.
    pub modules: Vec<String>,
    /// Modules with at least one connection in flight, by name.
    pub active_modules: Vec<String>,
    /// Connections in flight.
    pub connections: usize,
    /// How often it had to be restarted after dying unexpectedly.
    pub restarts: u32,
    /// Set when another daemon holds the pid file lock — the one case where
    /// restarting cannot help, because the port and the lock belong to somebody
    /// else. See the note above this section.
    pub already_running_elsewhere: bool,
    /// Children of the daemon that have exited and not been reaped. Expected to
    /// stay at zero; it is surfaced so that a regression is visible.
    pub zombie_children: usize,
    /// The last thing that went wrong, for the status display.
    pub last_error: Option<String>,
}

/// What a revoke actually achieved.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RevokeOutcome {
    /// Whether the module was there to be removed.
    pub module_removed: bool,
    /// Transfers that were interrupted to make the revoke take effect now.
    pub connections_terminated: usize,
}

/// Everything the supervision task and the handle share.
#[derive(Debug, Default)]
struct DaemonState {
    pid: Option<u32>,
    restarts: u32,
    already_running_elsewhere: bool,
    /// The process holding the pid file lock while `already_running_elsewhere`
    /// is set. Without it the operator is told that something blocks the start
    /// but not what, which is the dead end this exists to end. It reaches them
    /// through the start error and the application log; adding it to
    /// [`DaemonStatus`] as well belongs to whoever owns the status display.
    blocking_pid: Option<u32>,
    /// How often a daemon attempt has finished — exited, or failed to spawn at
    /// all — since the handle was created.
    ///
    /// [`DaemonHandle::wait_until_listening`] watches this so that a start
    /// which dies immediately is reported at once instead of sitting out the
    /// full timeout. Before it existed, a missing rsync binary delayed the
    /// whole web server by 30 seconds.
    exits: u32,
    last_error: Option<String>,
    /// Child pid of the daemon -> the module that connection is serving.
    connections: HashMap<u32, String>,
    /// Child pid -> what is known about that connection so far. Kept beside
    /// `connections` rather than inside it because `connections` is the set a
    /// revoke signals and must not grow entries for sessions that never named
    /// a module.
    sessions: HashMap<u32, Session>,
    /// The most recent audit events, newest last. Bounded by
    /// [`AUDIT_RING_CAPACITY`]; the file next to the daemon log is the complete
    /// record.
    audit: std::collections::VecDeque<AuditEvent>,
}

/// A running daemon, plus the modules it serves.
///
/// The handle owns the supervision task. Dropping it does *not* stop the
/// daemon — a `Drop` that has to await a process exit cannot do so from a
/// synchronous context, and one that only sends SIGTERM without waiting is the
/// hard-kill case this module goes out of its way to avoid. Call
/// [`DaemonHandle::shutdown`] from the application's shutdown path; it is
/// idempotent.
pub struct DaemonHandle {
    settings: DaemonSettings,
    registry: Arc<TokioMutex<ModuleRegistry>>,
    state: Arc<TokioMutex<DaemonState>>,
    stopping: Arc<AtomicBool>,
    supervisor: TokioMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Reports on the size of the run directory; see [`RunDirWatch`]. Separate
    /// from the supervisor because it has to keep talking while the supervisor
    /// is stuck in a start that fails — a full volume is one of the reasons a
    /// start fails. Like the supervision task it outlives a dropped handle and
    /// is ended by [`DaemonHandle::shutdown`], not by `Drop`.
    watchdog: TokioMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DaemonHandle {
    /// Start the daemon and keep it running until [`DaemonHandle::shutdown`].
    ///
    /// Publishes the registry's modules first — a daemon started against a
    /// configuration file that does not exist yet exits immediately — then
    /// sweeps orphaned partials out of the modules' temp directories and spawns
    /// the supervision task. Returns once the daemon has been observed listening,
    /// so a caller that starts serving requests afterwards can rely on the
    /// status being meaningful.
    pub async fn start(
        settings: DaemonSettings,
        registry: Arc<TokioMutex<ModuleRegistry>>,
    ) -> Result<Arc<Self>> {
        // Before anything is created or spawned: a daemon that would come up
        // reachable from outside must not come up at all.
        settings.check_listen_is_not_overridden()?;
        fs::create_dir_all(&settings.run_dir).with_context(|| {
            format!(
                "cannot create the daemon run directory {}",
                settings.run_dir.display()
            )
        })?;
        {
            let mut registry = registry.lock().await;
            // Has to happen before `apply`: the path goes into the generated
            // file, because `--log-file` on the command line would silence the
            // per-file audit lines. See `DaemonConfig::with_log_file`.
            registry.set_log_file(settings.log_file());
            registry
                .apply()
                .context("cannot publish the module configuration before starting the daemon")?;
        }
        if let Some(stunnel_log) = settings.stunnel_log() {
            tighten_stunnel_log(stunnel_log);
            if !stunnel_log.exists() {
                tracing::warn!(
                    stunnel_log = %stunnel_log.display(),
                    "the stunnel log is not there, so the audit log cannot name the real client \
                     address and will record it as unavailable — it will not fall back to the \
                     loopback address of the TLS terminator; add `output = <path>` to \
                     config/stunnel-rsyncd.conf.template or set RCLONE_GUI_STUNNEL_LOG"
                );
            }
        }

        let handle = Arc::new(Self {
            settings,
            registry,
            state: Arc::new(TokioMutex::new(DaemonState::default())),
            stopping: Arc::new(AtomicBool::new(false)),
            supervisor: TokioMutex::new(None),
            watchdog: TokioMutex::new(None),
        });

        let task = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.supervise().await }
        });
        *handle.supervisor.lock().await = Some(task);

        let watch = RunDirWatch::new(&handle.settings);
        *handle.watchdog.lock().await = Some(tokio::spawn(watch_run_dir(
            watch,
            Arc::clone(&handle.stopping),
        )));

        // Everything from here on can fail *after* a daemon is already alive,
        // so there is exactly one place that returns such a failure, and it
        // shuts the daemon down first. See `come_up` for why that is a rule and
        // not a courtesy.
        if let Err(error) = handle.come_up().await {
            handle.shutdown().await;
            return Err(error);
        }
        Ok(handle)
    }

    /// Everything between "the supervisor is running" and "the start succeeded".
    ///
    /// # Why this is one function and not two `?`s in `start`
    ///
    /// Both steps below can fail while a spawned daemon is alive and holding the
    /// pid file lock, and **a released `flock` without a live process does not
    /// exist** — the kernel frees the lock when the process dies, whatever kills
    /// it. So whoever holds the pid file is alive, and a failed start that walks
    /// away from its daemon leaves a living, no longer supervised process that
    /// blocks every later start with `failed to lock pid file: Resource
    /// temporarily unavailable`. The operator then sees a start-up error whose
    /// cause is a process the application has forgotten about.
    ///
    /// That is exactly what happened (ticket 48df8dc7): the loopback
    /// verification below shut the daemon down on a negative verdict, and the
    /// wait above it did not — a bare `?`. One path that cleans up and one that
    /// does not is worse than either, because the correct one makes the rule
    /// look established.
    ///
    /// Hence the shape: this function may return `Err` freely, and its single
    /// caller in [`DaemonHandle::start`] is the one place that decides what a
    /// post-spawn failure costs. A step added here inherits the cleanup instead
    /// of having to remember it.
    async fn come_up(&self) -> Result<()> {
        self.wait_until_listening().await?;
        // It answers on loopback — that says nothing about where else it
        // answers. Ask the kernel; a wrong answer takes the daemon down.
        self.verify_it_listens_on_loopback_only().await?;
        Ok(())
    }

    /// Refuse a daemon that is reachable from anywhere but loopback.
    ///
    /// TLS is not the default for a peer connection, it is the only one: the
    /// daemon speaks rsync's own challenge-response in the clear, stunnel on
    /// 874 terminates TLS in front of it, and port 873 is not published. The
    /// three things that hold that together are `address = 127.0.0.1` in the
    /// generated configuration, the absence of an `--dparam=address=…` (see
    /// [`DaemonSettings::check_listen_is_not_overridden`]) and the container not
    /// mapping the port.
    ///
    /// All three are statements about *inputs*. This one is about the outcome:
    /// `/proc/net/tcp` and `/proc/net/tcp6` are asked which addresses something
    /// is listening on our port, and anything that is not loopback aborts the
    /// start. It therefore also catches what the two checks above cannot — a
    /// future rsync that ignores `address`, a hand-edited configuration file, a
    /// second process squatting the port on a routable interface.
    ///
    /// A `/proc` that cannot be read at all is reported and let through. The
    /// alternative is refusing to run the transport wherever `/proc` is not
    /// mounted, which would break the deployment over a check rather than over
    /// a finding — and the two input-side guarantees still stand there.
    async fn verify_it_listens_on_loopback_only(&self) -> Result<()> {
        loopback_only_verdict(self.settings.port)
    }

    /// The current status, for the configuration display.
    pub async fn status(&self) -> DaemonStatus {
        let mut state = self.state.lock().await;
        prune_connections(&mut state);
        let state = &*state;
        let modules: Vec<String> = self
            .registry
            .lock()
            .await
            .modules()
            .iter()
            .map(|m| m.name().to_string())
            .collect();
        let mut active: Vec<String> = state.connections.values().cloned().collect();
        active.sort();
        active.dedup();
        DaemonStatus {
            running: state.pid.is_some(),
            pid: state.pid,
            address: DAEMON_ADDRESS.to_string(),
            port: self.settings.port,
            modules,
            active_modules: active,
            connections: state.connections.len(),
            restarts: state.restarts,
            already_running_elsewhere: state.already_running_elsewhere,
            zombie_children: state.pid.map(count_zombie_children).unwrap_or(0),
            last_error: state.last_error.clone(),
        }
    }

    /// The most recent audit events, oldest first.
    ///
    /// This is the in-memory tail for a status display, capped at
    /// [`AUDIT_RING_CAPACITY`]. The complete record is the file at
    /// [`DaemonSettings::audit_file`], one JSON object per line — the ring is
    /// for looking, the file is for keeping.
    pub async fn audit_events(&self, limit: usize) -> Vec<AuditEvent> {
        let state = self.state.lock().await;
        let skip = state.audit.len().saturating_sub(limit);
        state.audit.iter().skip(skip).cloned().collect()
    }

    /// The audit events that concern deletion — actual or attempted.
    ///
    /// Separate because that is the question an audit gets asked: with
    /// [`REFUSED_OPTIONS`] as it stands, every one of these is an *attempt*,
    /// and a caller that filtered on `destructive` alone would find nothing and
    /// conclude nothing had happened. See [`AuditEvent::concerns_deletion`].
    pub async fn deletion_events(&self, limit: usize) -> Vec<AuditEvent> {
        let state = self.state.lock().await;
        let mut events: Vec<AuditEvent> = state
            .audit
            .iter()
            .filter(|event| event.concerns_deletion())
            .cloned()
            .collect();
        let skip = events.len().saturating_sub(limit);
        events.drain(..skip);
        events
    }

    /// Where the audit log is written.
    pub fn audit_file(&self) -> PathBuf {
        self.settings.audit_file()
    }

    /// Remove a module *and* end the transfers that are already running on it.
    ///
    /// [`ModuleRegistry::revoke`] alone does not end access immediately, and
    /// that is not a shortcoming of the registry but of how rsync works: the
    /// daemon forks a child per connection and that child has already read its
    /// module before the file changes. Measured on 3.4.3 and 3.5.0, a transfer
    /// in flight runs to exit 0 across the revoke. The acceptance criterion of
    /// the pairing tickets is that a revoke ends access *now*, so the second
    /// half has to happen here, where the processes are: every child serving
    /// the revoked module gets SIGTERM.
    ///
    /// The module is removed first. If the order were the other way round, a
    /// connection could arrive between the kill and the rewrite and be served
    /// by a module that is supposed to be gone.
    ///
    /// The connection table comes from the daemon's own log (see
    /// [`mirror_log_file`]), so a pid in it is a pid the daemon reported. It is
    /// nevertheless checked against `/proc` before being signalled: a pid can
    /// be reused after the child exited and the closing log line was missed,
    /// and signalling an unrelated process would be considerably worse than
    /// missing a transfer that has already ended.
    pub async fn revoke_now(&self, module_name: &str) -> Result<RevokeOutcome> {
        let module_removed = self.registry.lock().await.revoke(module_name)?;

        let (daemon_pid, victims) = {
            let mut state = self.state.lock().await;
            // Entries for connections that have already ended would otherwise
            // be signalled; their pids may belong to somebody else by now.
            prune_connections(&mut state);
            let victims: Vec<u32> = state
                .connections
                .iter()
                .filter(|(_, name)| name.as_str() == module_name)
                .map(|(pid, _)| *pid)
                .collect();
            for pid in &victims {
                state.connections.remove(pid);
            }
            (state.pid, victims)
        };

        let mut terminated = 0usize;
        for pid in victims {
            let Some(daemon_pid) = daemon_pid else { break };
            if !is_child_of(pid, daemon_pid) {
                tracing::debug!(
                    pid,
                    module = module_name,
                    "connection is no longer a child of the daemon, not signalling it"
                );
                continue;
            }
            if send_signal(pid, "TERM").await {
                terminated += 1;
                tracing::warn!(
                    pid,
                    module = module_name,
                    "ended a transfer in flight so that the revoke takes effect immediately"
                );
            }
        }

        Ok(RevokeOutcome {
            module_removed,
            connections_terminated: terminated,
        })
    }

    /// Stop the daemon and the supervision task. Idempotent.
    ///
    /// SIGTERM first and a real wait for the exit: a daemon killed hard leaves
    /// its children's partial files behind in the modules' temp directories,
    /// and rsync never picks those up again. SIGKILL follows only after [`SIGTERM_GRACE`], and
    /// says in the log what it is going to cost.
    pub async fn shutdown(&self) {
        // Stopped first and by abort, not by waiting: it only reads file sizes,
        // so there is nothing to finish, and it would otherwise hold the
        // shutdown for up to one check interval.
        if let Some(task) = self.watchdog.lock().await.take() {
            task.abort();
        }
        if self.stopping.swap(true, Ordering::SeqCst) {
            // Somebody else is already doing it; wait for the task either way.
            self.join_supervisor(SIGTERM_GRACE * 2).await;
            return;
        }

        if let Some(pid) = self.state.lock().await.pid {
            tracing::info!(pid, "stopping the rsync daemon with SIGTERM");
            send_signal(pid, "TERM").await;
        }

        if self.join_supervisor(SIGTERM_GRACE).await {
            tracing::info!("rsync daemon stopped");
            return;
        }

        if let Some(pid) = self.state.lock().await.pid {
            tracing::warn!(
                pid,
                grace_seconds = SIGTERM_GRACE.as_secs(),
                "the rsync daemon did not exit on SIGTERM; sending SIGKILL. Partial \
                 destination files may be left behind in the modules' temp \
                 directories and will be swept on the next start"
            );
            send_signal(pid, "KILL").await;
        }
        self.join_supervisor(SIGTERM_GRACE).await;
    }

    /// Wait for the supervision task, at most `timeout`. `true` if it finished.
    async fn join_supervisor(&self, timeout: Duration) -> bool {
        let mut slot = self.supervisor.lock().await;
        let Some(task) = slot.take() else {
            return true;
        };
        match tokio::time::timeout(timeout, task).await {
            Ok(_) => true,
            Err(_) => {
                // Not finished: it stays gone from the slot, but the process is
                // still ours to kill, and the pid is still in the state.
                false
            }
        }
    }

    /// Block until the daemon accepts a connection, or give up.
    ///
    /// **Not** by waiting for the daemon's `listening on port` line: rsync
    /// writes that while parsing its configuration, *before* it binds. Waiting
    /// for it therefore reports readiness while there is no socket yet, and the
    /// first connection after a successful start can be refused. Two agents ran
    /// into it independently and a third reproduced it; on a fast machine it
    /// almost never shows, under load it shows regularly, which is how it ends
    /// up being written off as flaky.
    ///
    /// A TCP connect tests the property that is actually needed, so that is
    /// what is done here. The daemon binds loopback only ([`DAEMON_ADDRESS`]),
    /// so a refused connection comes back immediately and the poll costs
    /// nothing.
    ///
    /// A daemon that dies on the way — no rsync binary, port taken,
    /// unreadable configuration — is reported the moment it dies rather than
    /// after the full timeout: [`DaemonState::exits`] counts finished attempts,
    /// and one that finishes while this waits *is* the answer. Measured before:
    /// a missing rsync binary held the whole web server for 30 seconds.
    ///
    /// # Why the connect alone is not the answer either
    ///
    /// It asks "does anybody answer on the port", and the interesting case is
    /// the one where somebody *else* does: a second start against a run
    /// directory whose daemon is already running connects to that first daemon
    /// and reports success. The refusal in [`DaemonHandle::run_once`] then
    /// arrives too late — this loop is racing it, and which one wins decides
    /// whether a second start is refused or blessed. Measured three times out
    /// of three on the host as a *failing* refusal (ticket 466dc997), and once
    /// as a passing one, which is worse: it looked like flakiness.
    ///
    /// So readiness is bound to *our* child, not to the port: the pid file lock
    /// belongs to the daemon this handle spawned, or the connect does not
    /// count. That keeps the whole gain of the connect — a hopeless start still
    /// fails in milliseconds, not after the timeout — and takes the race out.
    async fn wait_until_listening(&self) -> Result<()> {
        let timeout = self.settings.listen_timeout;
        let deadline = tokio::time::Instant::now() + timeout;
        let address = format!("{DAEMON_ADDRESS}:{}", self.settings.port);
        loop {
            let (blocked, blocking_pid, exits, last_error) = {
                let state = self.state.lock().await;
                (
                    state.already_running_elsewhere,
                    state.blocking_pid,
                    state.exits,
                    state.last_error.clone(),
                )
            };
            if blocked {
                return Err(self.blocked_by_another_daemon(blocking_pid));
            }
            if exits > 0 {
                return Err(anyhow!(
                    "the rsync daemon did not survive its start{}",
                    last_error.map(|e| format!(": {e}")).unwrap_or_default()
                ));
            }
            // A connect proves that *something* listens on the port; the pid
            // file lock proves *whose* it is. Both are needed — see
            // `pid_file_is_held_by_a_stranger`.
            if TcpStream::connect(&address).await.is_ok()
                && !self.pid_file_is_held_by_a_stranger().await
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(LISTEN_RETRY_INTERVAL).await;
        }
        let last = self.state.lock().await.last_error.clone();
        Err(anyhow!(
            "the rsync daemon did not accept a connection on {address} within {:?}{}",
            timeout,
            last.map(|e| format!(": {e}")).unwrap_or_default()
        ))
    }

    /// Whether the pid file lock is provably held by somebody other than the
    /// daemon this handle spawned.
    ///
    /// The question a readiness check has to ask before it believes a TCP
    /// connect. rsync holds an exclusive `flock` on its pid file for its whole
    /// life, so the holder's pid is the identity of the daemon that owns this
    /// run directory right now — and [`pid_file_holder`] reads it from
    /// `/proc/locks`, i.e. from the kernel, not from the file's content.
    ///
    /// Deliberately *not* the stricter "the lock must already be ours":
    ///
    ///   * before the spawn there is no pid of ours at all, and every holder is
    ///     a stranger — which is exactly the case this exists for
    ///   * rsync takes the lock and binds the port in one startup, and nothing
    ///     in its documentation fixes the order of the two. A check that
    ///     required the lock first would turn a legal ordering into a start
    ///     failure
    ///   * an unreadable `/proc` or a run directory without a pid file yields
    ///     `None`, and refusing to come up over a check that cannot be
    ///     performed is the mistake
    ///     [`DaemonHandle::verify_it_listens_on_loopback_only`] avoids for the
    ///     same reason
    ///
    /// What remains is narrow and provable: somebody is holding the lock, and
    /// it is not us, so the socket that just answered is not ours either.
    async fn pid_file_is_held_by_a_stranger(&self) -> bool {
        let Some(holder) = pid_file_holder(&self.settings.pid_file()) else {
            return false;
        };
        holder.pid != self.state.lock().await.pid
    }

    /// The error for "somebody else holds the pid file lock", naming them.
    ///
    /// `known` is what the start already found out, if anything; when the
    /// daemon itself reported the lock failure first there is no pid yet and
    /// the pid file is asked again here. Naming the process is the whole point:
    /// the state is not repairable from inside the application (see
    /// [`pid_file_holder`]), so the message has to be enough for an operator to
    /// act on without going looking.
    fn blocked_by_another_daemon(&self, known: Option<u32>) -> anyhow::Error {
        let pid_file = self.settings.pid_file();
        let who = known
            .map(|pid| PidFileHolder {
                pid: Some(pid),
                command: process_command_line(pid),
            })
            .or_else(|| pid_file_blocker(&pid_file))
            .map(|holder| holder.to_string())
            .unwrap_or_else(|| "an unidentified process".to_string());
        anyhow!(
            "another rsync daemon already holds the pid file lock at {} ({who}); refusing to \
             run a second one — stop that process and the transport comes up by itself",
            pid_file.display()
        )
    }

    /// Start the daemon, wait for it, restart it, until told to stop.
    async fn supervise(self: Arc<Self>) {
        let mut consecutive_failures: u32 = 0;
        while !self.stopping.load(Ordering::SeqCst) {
            let started = tokio::time::Instant::now();
            match self.run_once().await {
                Ok(status) => {
                    // Counted before the shutdown check: a waiting start has to
                    // learn that this attempt is over either way.
                    self.state.lock().await.exits += 1;
                    if self.stopping.load(Ordering::SeqCst) {
                        tracing::info!(?status, "the rsync daemon exited during shutdown");
                        break;
                    }
                    tracing::warn!(?status, "the rsync daemon exited unexpectedly; restarting");
                    self.state.lock().await.restarts += 1;
                }
                Err(e) => {
                    tracing::error!(error = %e, "cannot start the rsync daemon");
                    {
                        let mut state = self.state.lock().await;
                        state.last_error = Some(e.to_string());
                        // After `last_error`, so that a start woken by the
                        // counter finds the cause already recorded.
                        state.exits += 1;
                    }
                    if self.stopping.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }

            if started.elapsed() >= RESTART_BACKOFF_RESET {
                consecutive_failures = 0;
            }
            let backoff = if self.state.lock().await.already_running_elsewhere {
                // Restarting cannot help while somebody else holds the lock, so
                // do not spin: check back at the slowest rate.
                RESTART_BACKOFF_MAX
            } else {
                restart_backoff(consecutive_failures)
            };
            consecutive_failures = consecutive_failures.saturating_add(1);
            self.sleep_unless_stopping(backoff).await;
        }
        self.state.lock().await.pid = None;
    }

    /// Sleep for `backoff`, but wake as soon as a shutdown has been asked for.
    ///
    /// A plain `sleep(backoff)` here is what turned a failed start into a
    /// ten-second one. Since [`DaemonHandle::start`] shuts the daemon down on
    /// every post-spawn failure (see [`DaemonHandle::come_up`]), and
    /// [`DaemonHandle::shutdown`] waits for this task to finish, the backoff sat
    /// between the operator and their error message — up to
    /// [`RESTART_BACKOFF_MAX`], and worst in the one case where the backoff is
    /// deliberately at its slowest: another daemon holds the pid file lock, so
    /// restarting cannot help anyway.
    ///
    /// Polling rather than a notification: `stopping` is the only thing being
    /// waited on, one `AtomicBool` load every 50 ms costs nothing measurable,
    /// and a channel would put a second synchronisation primitive next to the
    /// flag that already exists.
    async fn sleep_unless_stopping(&self, backoff: Duration) {
        const SLICE: Duration = Duration::from_millis(50);
        let deadline = tokio::time::Instant::now() + backoff;
        while tokio::time::Instant::now() < deadline {
            if self.stopping.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(SLICE.min(deadline - tokio::time::Instant::now())).await;
        }
    }

    /// One daemon lifetime: sweep, spawn, mirror, wait.
    async fn run_once(&self) -> Result<std::process::ExitStatus> {
        if self.settings.sweep_temp_files {
            let temp_dirs = self.registry.lock().await.config().temp_dirs();
            // Only the modules' own temp directories, never a share root: what
            // is in them is rsync's by construction, and nothing is in flight
            // before the daemon exists.
            sweep_module_temp_dirs(&temp_dirs, self.settings.temp_file_min_age);
        }

        // Is somebody else's daemon still on our pid file? Asking before the
        // spawn turns a dead end into a message: without it the attempt fails
        // with `failed to lock pid file: Resource temporarily unavailable`,
        // every 30 seconds, forever, and nothing says *which* process is in the
        // way. That is the state a hard kill of the application leaves behind —
        // the daemon outlives it and keeps the lock.
        //
        // This does not open a race. It refuses only when the lock is provably
        // held; when it looks free, the spawn goes ahead and rsync's own
        // `flock` remains the authority, so two applications starting at the
        // same instant still produce exactly one daemon and the loser reports
        // the lock failure as before.
        let pid_file = self.settings.pid_file();
        if let Some(holder) = pid_file_holder(&pid_file) {
            {
                let mut state = self.state.lock().await;
                state.already_running_elsewhere = true;
                state.blocking_pid = holder.pid;
            }
            return Err(anyhow!(
                "{} is locked by {holder}; refusing to start a second rsync daemon on it",
                pid_file.display()
            ));
        }

        // Start from an empty log: the mirror reads from the beginning and
        // would otherwise replay the previous daemon's life into the
        // application log, connection table included.
        let log_path = self.settings.log_file();
        write_truncated_log(&log_path)?;

        let mut child = TokioCommand::new(&self.settings.binary)
            .args(self.settings.argv())
            // Measured, and more precisely than the first note here claimed: a
            // *pipe* on stdin is harmless, the daemon listens normally. What
            // triggers rsync's inetd mode is a **socket** on stdin — it then
            // serves that "connection" (`connect from UNKNOWN`), never opens a
            // listener and hangs. Since a supervisor cannot know what it
            // inherited, null is the only setting that is right in every case.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false)
            .spawn()
            .with_context(|| {
                format!(
                    "cannot start {} — is rsync installed?",
                    self.settings.binary.display()
                )
            })?;

        let pid = child.id().ok_or_else(|| anyhow!("the daemon has no pid"))?;
        {
            let mut state = self.state.lock().await;
            state.pid = Some(pid);
            state.connections.clear();
            state.sessions.clear();
            state.already_running_elsewhere = false;
            state.blocking_pid = None;
        }
        tracing::info!(
            pid,
            port = self.settings.port,
            address = DAEMON_ADDRESS,
            conf = %self.settings.conf_path.display(),
            "rsync daemon started"
        );

        let finished = Arc::new(AtomicBool::new(false));
        let audit = AuditContext::new(
            AuditSink::new(
                self.settings
                    .write_audit_file
                    .then(|| self.settings.audit_file()),
            ),
            self.settings
                .stunnel_log()
                .map(|path| StunnelIndex::new(path.to_path_buf())),
            self.settings.port,
        );
        let mirror = tokio::spawn(mirror_log_file(
            log_path,
            Arc::clone(&self.state),
            Arc::clone(&finished),
            audit,
        ));
        let stdout = child
            .stdout
            .take()
            .map(|pipe| tokio::spawn(mirror_pipe(pipe, "stdout", Arc::clone(&self.state))));
        let stderr = child
            .stderr
            .take()
            .map(|pipe| tokio::spawn(mirror_pipe(pipe, "stderr", Arc::clone(&self.state))));

        // `wait` is what reaps the daemon: on every path out of this function
        // the child has been waited for, so it never becomes a zombie.
        //
        // The error case is the same class as the one `come_up` exists for — the
        // daemon is alive and this function is about to stop watching it — so it
        // does not get a bare `?` either. It is not reachable in practice (the
        // child is ours and has not been reaped elsewhere), which is precisely
        // why it must not be the one path that walks away: a rule with an
        // exception nobody ever sees is a rule the next author will not follow.
        let status = match child.wait().await {
            Ok(status) => status,
            Err(error) => {
                tracing::error!(
                    pid,
                    error = %error,
                    "cannot wait for the rsync daemon; killing it so that it does not keep \
                     the pid file lock unsupervised"
                );
                let _ = child.start_kill();
                let _ = child.wait().await;
                finished.store(true, Ordering::SeqCst);
                let _ = mirror.await;
                for task in [stdout, stderr].into_iter().flatten() {
                    let _ = task.await;
                }
                self.state.lock().await.pid = None;
                return Err(anyhow::Error::new(error).context("cannot wait for the daemon"));
            }
        };

        finished.store(true, Ordering::SeqCst);
        let _ = mirror.await;
        for task in [stdout, stderr].into_iter().flatten() {
            let _ = task.await;
        }

        {
            let mut state = self.state.lock().await;
            state.pid = None;
            state.connections.clear();
            state.sessions.clear();
            if !status.success() {
                state.last_error = Some(format!("the rsync daemon exited with {status}"));
            }
            // The daemon lost the race for the lock rather than this process
            // finding it taken beforehand: name the winner now, while it is
            // still there to be named.
            if state.already_running_elsewhere && state.blocking_pid.is_none() {
                state.blocking_pid = pid_file_blocker(&pid_file).and_then(|holder| holder.pid);
                tracing::warn!(
                    pid_file = %pid_file.display(),
                    blocking_pid = state.blocking_pid,
                    "the rsync daemon could not take the pid file lock; another daemon holds it"
                );
            }
        }
        Ok(status)
    }
}

/// Restart delay after `failures` consecutive failures, capped.
fn restart_backoff(failures: u32) -> Duration {
    let factor = 1u32.checked_shl(failures.min(16)).unwrap_or(u32::MAX);
    RESTART_BACKOFF_MIN
        .saturating_mul(factor)
        .min(RESTART_BACKOFF_MAX)
}

/// Take group and world off the stunnel log if it is there.
///
/// The file lists the address of every peer that connected, and it is written
/// by *stunnel*, a separate process started from `start.sh` with its own umask
/// — the default one produces a world-readable log. `config/rsync-tls.sh`
/// creates it with mode 0600, and this is the second belt: it also catches a
/// file that predates that change or was created by an operator by hand.
///
/// Deliberately does **not** create the file. A missing stunnel log is a
/// configuration problem worth reporting (the warning right after this), and
/// creating an empty one here would hide it while producing exactly nothing to
/// correlate against.
fn tighten_stunnel_log(path: &Path) {
    let Ok(meta) = fs::metadata(path) else { return };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        return;
    }
    match fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE)) {
        Ok(()) => tracing::warn!(
            stunnel_log = %path.display(),
            was = format!("{mode:04o}"),
            "the stunnel log was readable by others; tightened to 0600 — it holds every peer \
             address"
        ),
        Err(e) => tracing::warn!(
            stunnel_log = %path.display(),
            error = %e,
            "cannot restrict the stunnel log; it holds every peer address"
        ),
    }
}

/// Empty the log file so the mirror starts at the current daemon's first line.
fn write_truncated_log(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create directory {}", parent.display()))?;
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(path)
        .with_context(|| format!("cannot create the daemon log {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Run directory watchdog (ticket 0cedda6f)
// ---------------------------------------------------------------------------

/// A size limit from the environment, `default` if unset or unreadable.
///
/// An empty or non-numeric value is a configuration mistake, not a reason to
/// silently pick a different limit, so it is reported once and the default
/// stands. `0` is valid and means "do not watch this".
fn size_limit_from_env(var: &str, default: u64) -> u64 {
    let Ok(raw) = std::env::var(var) else {
        return default;
    };
    match raw.trim().parse::<u64>() {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                variable = var,
                value = %raw,
                error = %e,
                default_bytes = default,
                "cannot read the size limit from the environment; keeping the default"
            );
            default
        }
    }
}

/// One file the watchdog reports on, with the state that keeps it from
/// repeating itself.
#[derive(Debug)]
struct WatchedFile {
    path: PathBuf,
    /// What the file is, for the warning text.
    kind: &'static str,
    /// Bytes above which it is reported. `0` means it is not watched.
    limit: u64,
    /// When it was last reported and how large it was then.
    warned: Option<(std::time::Instant, u64)>,
}

/// What the watchdog found over its limit.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SizeWarning {
    kind: &'static str,
    path: PathBuf,
    bytes: u64,
    limit: u64,
}

/// Watches the daemon's run directory and **only** reports on it.
///
/// # Why it reports instead of rotating
///
/// The audit log must not be rotated by the process that writes it — a process
/// that can shorten its own audit trail can also remove evidence from it. That
/// decision is older than this type and is not reversed here (see
/// [`DaemonSettings::audit_file`]).
///
/// What is new is that the run directory is not only the audit log. The pid
/// file, the lock file and the daemon's own log live in it as well, so a
/// directory that fills up takes the transport down with it, and the symptom
/// (`failed to lock pid file`, a daemon that will not start) points at the
/// daemon rather than at the disk. Warning early makes the real cause visible
/// while there is still room to act.
///
/// # The stunnel log is treated the same way, deliberately
///
/// It is tempting to cap that one for real — it is a connection log, not an
/// audit trail, so the evidence argument seems not to apply. It does apply,
/// one step removed, and it was measured before deciding:
///
/// * the real peer address exists in **no other place**. The daemon log records
///   `127.0.0.1` for every client on earth because stunnel terminates TLS on
///   loopback, and `proxy protocol` is off by choice (see
///   [`DaemonConfig::with_proxy_protocol`]). Every `client` field in the audit
///   log is joined out of this file by [`StunnelIndex`], so truncating it turns
///   audit events into `client_source=unavailable` — it destroys audit content
///   without touching the audit file;
/// * [`StunnelIndex`] follows the file by byte offset. A rotation underneath a
///   running daemon drops whatever had not been read yet, which is precisely
///   the newest connections, i.e. the ones still being joined;
/// * the file belongs to *stunnel*, a separate process started from `start.sh`
///   with its own open descriptor. Truncating a file another process holds open
///   is a race this module has no way to win.
///
/// So both files are reported and neither is touched. `copytruncate` for the
/// stunnel log is a matter for the operator, and the shipped logrotate snippet
/// says when it is safe.
///
/// # What it never does
///
/// It opens nothing for writing, creates nothing and removes nothing. The only
/// operations are `metadata` and one `read_dir` of the run directory. In
/// particular it is unrelated to [`sweep_module_temp_dirs`], which stays
/// restricted to [`DaemonConfig::temp_dirs`].
#[derive(Debug)]
struct RunDirWatch {
    run_dir: PathBuf,
    files: Vec<WatchedFile>,
    /// Bytes above which the directory as a whole is reported. `0` disables.
    run_dir_limit: u64,
    warned: Option<(std::time::Instant, u64)>,
}

impl RunDirWatch {
    fn new(settings: &DaemonSettings) -> Self {
        let mut files = vec![
            WatchedFile {
                path: settings.audit_file(),
                kind: "audit log",
                limit: settings.log_warn_bytes,
                warned: None,
            },
            WatchedFile {
                path: settings.log_file(),
                kind: "daemon log",
                limit: settings.log_warn_bytes,
                warned: None,
            },
        ];
        if let Some(stunnel_log) = settings.stunnel_log() {
            files.push(WatchedFile {
                path: stunnel_log.to_path_buf(),
                kind: "stunnel log",
                limit: settings.log_warn_bytes,
                warned: None,
            });
        }
        Self {
            run_dir: settings.run_dir.clone(),
            files,
            run_dir_limit: settings.run_dir_warn_bytes,
            warned: None,
        }
    }

    /// Measure everything once and return what is due to be reported.
    ///
    /// `now` is passed in rather than read here so that the repeat interval can
    /// be tested without waiting a quarter of an hour.
    fn check(&mut self, now: std::time::Instant) -> Vec<SizeWarning> {
        let mut warnings = Vec::new();
        for file in &mut self.files {
            if file.limit == 0 {
                continue;
            }
            // A missing file is not a problem the watchdog has an opinion on:
            // the audit log does not exist before the first event, and the
            // stunnel log is already reported elsewhere when it is absent.
            let Ok(meta) = fs::metadata(&file.path) else {
                continue;
            };
            let bytes = meta.len();
            if bytes <= file.limit {
                continue;
            }
            if due(&mut file.warned, now, bytes) {
                warnings.push(SizeWarning {
                    kind: file.kind,
                    path: file.path.clone(),
                    bytes,
                    limit: file.limit,
                });
            }
        }

        if self.run_dir_limit > 0 {
            let total = directory_bytes(&self.run_dir);
            if total > self.run_dir_limit && due(&mut self.warned, now, total) {
                warnings.push(SizeWarning {
                    kind: "run directory",
                    path: self.run_dir.clone(),
                    bytes: total,
                    limit: self.run_dir_limit,
                });
            }
        }
        warnings
    }
}

/// Whether a condition that is still true should be reported again.
///
/// Repeats when it has persisted for [`RUN_DIR_WARN_REPEAT`] or when the file
/// has doubled since the last report, and records the decision in `state`.
fn due(state: &mut Option<(std::time::Instant, u64)>, now: std::time::Instant, bytes: u64) -> bool {
    let repeat = match state {
        None => true,
        Some((at, then)) => {
            now.saturating_duration_since(*at) >= RUN_DIR_WARN_REPEAT
                || bytes >= then.saturating_mul(2)
        }
    };
    if repeat {
        *state = Some((now, bytes));
    }
    repeat
}

/// Bytes held by the plain files directly in `dir`. Not recursive.
///
/// The run directory has no subdirectories of its own; anything mounted into it
/// is somebody else's accounting. Unreadable entries are skipped rather than
/// guessed at — an under-count delays a warning, an over-count invents one.
fn directory_bytes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|entry| entry.metadata().ok())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum()
}

/// Report the run directory's size for as long as the daemon is supervised.
///
/// Runs beside the supervision task rather than inside the log mirror on
/// purpose: the case worth warning about is a daemon that cannot start *because*
/// the directory is full, and in that case no mirror is running to notice.
///
/// The warnings go to `tracing` and therefore to the application log — never
/// into the audit log or anything else under the run directory. A warning about
/// a full directory that is written into that same directory would be the last
/// thing lost when it matters.
async fn watch_run_dir(mut watch: RunDirWatch, stopping: Arc<AtomicBool>) {
    while !stopping.load(Ordering::SeqCst) {
        for warning in watch.check(std::time::Instant::now()) {
            tracing::warn!(
                what = warning.kind,
                path = %warning.path.display(),
                bytes = warning.bytes,
                limit_bytes = warning.limit,
                "the rsync {} has passed its size limit and is NOT rotated by this process — the \
                 run directory also holds the daemon's pid and lock file, so a full volume stops \
                 the transport. Rotate from outside (config/logrotate-rclone-gui.conf) or give \
                 the run directory more room; nothing has been deleted",
                warning.kind
            );
        }
        tokio::time::sleep(RUN_DIR_CHECK_INTERVAL).await;
    }
}

/// Mirror one of the daemon's pipes into the application log.
///
/// Only fatal startup errors arrive here — everything operational goes to the
/// log file — so a line on either pipe is worth a warning.
async fn mirror_pipe<R>(pipe: R, which: &'static str, state: Arc<TokioMutex<DaemonState>>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(pipe).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim_end().to_string();
        if line.is_empty() {
            continue;
        }
        tracing::warn!(stream = which, "rsyncd: {line}");
        let mut state = state.lock().await;
        if line.contains("failed to lock pid file") {
            state.already_running_elsewhere = true;
        }
        state.last_error = Some(line);
    }
}

/// Follow the daemon's log file and mirror it into the application log.
///
/// The daemon writes to a file rather than to a pipe because it has to (see the
/// note at the top of this section), so this is a tail rather than a read on a
/// stream. It stops once `finished` is set and the file has been drained, so
/// the last lines of a dying daemon are not lost.
///
/// On the way past it maintains the connection table, which is what makes an
/// immediate revoke possible at all — see [`DaemonHandle::revoke_now`]. Exactly
/// one log line feeds it:
///
/// ```text
/// 2026/08/15 18:47:59 [749342] rsync allowed access on module pair1a2b from localhost (127.0.0.1)
/// ```
///
/// It says which child serves which module. There is deliberately no matching
/// line for the other direction: **rsync logs nothing when a connection ends.**
/// Measured over 30 transfers, the log holds `connect from` and `allowed access
/// on module` per connection and nothing afterwards; the `sent ... received ...
/// total size ...` summary belongs to the *daemon* at shutdown, not to the
/// child. Reading a closing line out of the log was tried and left 40 stale
/// entries out of 40 connections. So the table is closed from `/proc` instead
/// — see [`prune_connections`] — and the closing lines that some
/// configurations do produce are still honoured as an early hint.
async fn mirror_log_file(
    path: PathBuf,
    state: Arc<TokioMutex<DaemonState>>,
    finished: Arc<AtomicBool>,
    mut audit: AuditContext,
) {
    let mut offset: u64 = 0;
    let mut pending = String::new();
    let mut last_prune = tokio::time::Instant::now();
    loop {
        let done = finished.load(Ordering::SeqCst);
        audit.refresh_stunnel().await;
        match read_from(&path, offset).await {
            Ok((chunk, new_offset)) => {
                offset = new_offset;
                pending.push_str(&chunk);
                while let Some(index) = pending.find('\n') {
                    let line: String = pending.drain(..=index).collect();
                    handle_log_line(line.trim_end(), &state, &mut audit).await;
                }
            }
            Err(e) => {
                tracing::debug!(log = %path.display(), error = %e, "cannot read the daemon log");
            }
        }
        if done {
            if !pending.is_empty() {
                handle_log_line(pending.trim_end(), &state, &mut audit).await;
            }
            return;
        }
        // Connections that have ended leave no trace in the log, so the table
        // is closed against /proc rather than by reading. Once a second is
        // often enough: a revoke prunes again before it signals anything, this
        // only keeps the table from growing over a long-lived daemon.
        if last_prune.elapsed() >= Duration::from_secs(1) {
            prune_connections(&mut *state.lock().await);
            last_prune = tokio::time::Instant::now();
        }
        tokio::time::sleep(LOG_POLL_INTERVAL).await;
    }
}

/// Read whatever is in `path` beyond `offset`.
async fn read_from(path: &Path, offset: u64) -> std::io::Result<(String, u64)> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    if len <= offset {
        // Truncated or unchanged; a shrunk file means a new daemon's log.
        return Ok((String::new(), len.min(offset)));
    }
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = Vec::with_capacity((len - offset) as usize);
    file.read_to_end(&mut buf).await?;
    let read = buf.len() as u64;
    Ok((String::from_utf8_lossy(&buf).into_owned(), offset + read))
}

/// Everything the log reader needs besides the shared state.
///
/// Kept out of [`DaemonState`] on purpose: the stunnel index does blocking file
/// reads and only the mirroring task ever touches it, so putting it behind the
/// state mutex would make every status call wait for a file read it does not
/// care about.
#[derive(Debug)]
struct AuditContext {
    sink: AuditSink,
    stunnel: Option<StunnelIndex>,
    /// The port the daemon listens on, to pick the right socket out of `/proc`.
    daemon_port: u16,
    /// Set once a failed correlation has been explained, so it is said once
    /// instead of on every connection (ticket 33697f91).
    warned_unresolved: bool,
}

impl AuditContext {
    fn new(sink: AuditSink, stunnel: Option<StunnelIndex>, daemon_port: u16) -> Self {
        Self {
            sink,
            stunnel,
            daemon_port,
            warned_unresolved: false,
        }
    }

    /// Pull in whatever stunnel has logged since the last pass.
    async fn refresh_stunnel(&mut self) {
        if let Some(index) = &mut self.stunnel {
            index.refresh().await;
        }
    }

    /// Establish the real client behind a freshly opened session.
    ///
    /// The port comes from `/proc` and makes the match exact; the timestamp is
    /// the fallback. Returns the loopback-free answer — when nothing matches,
    /// the address stays absent rather than becoming `127.0.0.1`.
    fn resolve_client(
        &mut self,
        pid: u32,
        at: Option<chrono::NaiveDateTime>,
    ) -> (Option<String>, Option<u16>, ClientAddressSource) {
        let backend_port = peer_port_of_child(pid, self.daemon_port);
        let Some(index) = &mut self.stunnel else {
            return (None, None, ClientAddressSource::Unavailable);
        };
        match index.lookup(backend_port, at) {
            Some((peer, port, source)) => (Some(peer), Some(port), source),
            None => {
                // Without this the failure is completely silent: the audit log
                // is written, looks complete, and simply has no peer anywhere.
                // Said once, with what was actually observed, so the reader can
                // tell the three causes apart instead of guessing.
                if !self.warned_unresolved {
                    self.warned_unresolved = true;
                    let (known, with_port) = index.known();
                    tracing::warn!(
                        stunnel_log = %index.path.display(),
                        backend_port = ?backend_port,
                        stunnel_connections = known,
                        with_backend_port = with_port,
                        clock_shift_seconds = index.clock_shift().num_seconds(),
                        "cannot name the real client of an rsync connection; every audit event \
                         will read client_source=unavailable until this is fixed. Likely causes, \
                         in order: the stunnel log is empty or unreadable (`output = <path>` \
                         and `debug = 5` in config/stunnel-rsyncd.conf.template), no stunnel \
                         line falls into the match window for this connection, or stunnel does \
                         not front this daemon at all. The exact join over /proc is expected to \
                         be unavailable in a container (see peer_port_of_child), so the time \
                         match carries this on its own"
                    );
                }
                (None, None, ClientAddressSource::Unavailable)
            }
        }
    }
}

/// Turn one daemon log line into audit events, if it carries any.
///
/// The lines that are recognised are listed with an example each in the audit
/// section header above; every one of them was taken off a real daemon rather
/// than out of the rsync manual.
async fn record_audit(
    line: &str,
    body: &str,
    pid: u32,
    state: &Arc<TokioMutex<DaemonState>>,
    audit: &mut AuditContext,
) {
    let at = parse_rsync_time(line);
    let stamp = line.get(..19).unwrap_or("").to_string();

    // A new connection: this is the only moment the peer can still be looked
    // up in /proc, because the socket disappears with the child.
    if body.starts_with("connect from") {
        let (client, client_port, client_source) = audit.resolve_client(pid, at);
        let session = Session {
            module: None,
            user: None,
            client: client.clone(),
            client_port,
            client_source: Some(client_source),
        };
        state.lock().await.sessions.insert(pid, session);
        emit(
            state,
            audit,
            AuditEvent {
                at: stamp,
                pid,
                module: None,
                user: None,
                client,
                client_port,
                client_source,
                action: AuditAction::Connected,
                destructive: false,
                path: None,
                size: None,
                refused_option: None,
                detail: body.to_string(),
            },
        )
        .await;
        return;
    }

    if let Some(module) = module_from_access_line(body) {
        set_session(state, pid, |s| s.module = Some(module.clone())).await;
        emit_for(
            state,
            audit,
            pid,
            stamp,
            AuditAction::AccessGranted,
            body,
            None,
            None,
            None,
        )
        .await;
        return;
    }

    // `rsync to <module>/ from <user>@<host> (<ip>)` for a client that writes,
    // `rsync on <module>/ …` for one that reads. This is where the
    // authenticated user first appears.
    if let Some((module, user, writing)) = session_direction_line(body) {
        set_session(state, pid, |s| {
            s.module.get_or_insert(module.clone());
            s.user = Some(user.clone());
        })
        .await;
        let action = if writing {
            AuditAction::SessionWrite
        } else {
            AuditAction::SessionRead
        };
        emit_for(state, audit, pid, stamp, action, body, None, None, None).await;
        return;
    }

    if let Some(transfer) = parse_transfer_line(body) {
        set_session(state, pid, |s| {
            s.module.get_or_insert(transfer.module.clone());
            s.user.get_or_insert(transfer.user.clone());
        })
        .await;
        emit_for(
            state,
            audit,
            pid,
            stamp,
            transfer.action,
            body,
            Some(transfer.path),
            transfer.size,
            None,
        )
        .await;
        return;
    }

    if let Some(option) = refused_option(body) {
        emit_for(
            state,
            audit,
            pid,
            stamp,
            AuditAction::OptionRefused,
            body,
            None,
            None,
            Some(option),
        )
        .await;
        return;
    }

    if let Some((module, user)) = auth_failure_line(body) {
        set_session(state, pid, |s| {
            s.module = Some(module.clone());
            s.user = user.clone();
        })
        .await;
        emit_for(
            state,
            audit,
            pid,
            stamp,
            AuditAction::AccessDenied,
            body,
            None,
            None,
            None,
        )
        .await;
        return;
    }

    if body.contains("tried from") && body.contains("unknown module") {
        emit_for(
            state,
            audit,
            pid,
            stamp,
            AuditAction::AccessDenied,
            body,
            None,
            None,
            None,
        )
        .await;
        return;
    }

    if body.contains("rsync error:") {
        emit_for(
            state,
            audit,
            pid,
            stamp,
            AuditAction::Error,
            body,
            None,
            None,
            None,
        )
        .await;
        return;
    }

    // The per-connection summary. The daemon writes an identical line for
    // itself when it shuts down, but with its own pid, which never has a
    // session — so that one is dropped here rather than logged as a phantom
    // connection ending.
    if is_transfer_summary_line(body) && state.lock().await.sessions.contains_key(&pid) {
        emit_for(
            state,
            audit,
            pid,
            stamp,
            AuditAction::SessionEnd,
            body,
            None,
            None,
            None,
        )
        .await;
        state.lock().await.sessions.remove(&pid);
    }
}

/// Update what is known about a session, if it is still open.
async fn set_session(
    state: &Arc<TokioMutex<DaemonState>>,
    pid: u32,
    update: impl FnOnce(&mut Session),
) {
    let mut state = state.lock().await;
    update(state.sessions.entry(pid).or_default());
}

/// Emit an event, filling module, user and client in from the session.
#[allow(clippy::too_many_arguments)]
async fn emit_for(
    state: &Arc<TokioMutex<DaemonState>>,
    audit: &mut AuditContext,
    pid: u32,
    at: String,
    action: AuditAction,
    detail: &str,
    path: Option<String>,
    size: Option<u64>,
    refused_option: Option<String>,
) {
    let session = state.lock().await.sessions.get(&pid).cloned();
    let session = session.unwrap_or_default();
    let event = AuditEvent {
        at,
        pid,
        module: session.module.clone(),
        user: session.user.clone(),
        client: session.client.clone(),
        client_port: session.client_port,
        client_source: session
            .client_source
            .unwrap_or(ClientAddressSource::Unavailable),
        action,
        destructive: action.is_destructive(),
        path,
        size,
        refused_option,
        detail: detail.to_string(),
    };
    emit(state, audit, event).await;
}

/// Write an event to the sink and to the in-memory ring.
async fn emit(state: &Arc<TokioMutex<DaemonState>>, audit: &mut AuditContext, event: AuditEvent) {
    audit.sink.record(&event);
    let mut state = state.lock().await;
    state.audit.push_back(event);
    while state.audit.len() > AUDIT_RING_CAPACITY {
        state.audit.pop_front();
    }
}

/// One per-file line of the daemon's transfer log.
struct TransferLine {
    module: String,
    user: String,
    action: AuditAction,
    path: String,
    size: Option<u64>,
}

/// Parse a line rendered with [`MODULE_LOG_FORMAT`].
///
/// The shape is `<sentinel> <addr> <user> <module> <op> <len> <bytes> <file>`,
/// and the file name is last precisely so that it may contain spaces. `<op>` is
/// rsync's `%o`: `recv`, `send`, or `del.` for a deletion.
fn parse_transfer_line(body: &str) -> Option<TransferLine> {
    let rest = body.strip_prefix(AUDIT_SENTINEL)?.trim_start();
    let mut fields = rest.splitn(7, ' ');
    let _address = fields.next()?;
    let user = fields.next()?;
    let module = fields.next()?;
    let operation = fields.next()?;
    let size = fields.next()?;
    let _bytes = fields.next()?;
    let path = fields.next()?;
    let action = match operation {
        "recv" => AuditAction::FileReceived,
        "send" => AuditAction::FileSent,
        // rsync writes the operation for a deletion as `del.`, with the dot.
        "del." | "del" => AuditAction::FileDeleted,
        _ => return None,
    };
    if path.is_empty() {
        return None;
    }
    Some(TransferLine {
        module: module.to_string(),
        user: user.to_string(),
        action,
        path: path.to_string(),
        size: size.parse().ok(),
    })
}

/// `rsync to <module>/ from <user>@<host> (<ip>)` and its `on` counterpart.
///
/// `to` is a client that writes into the module, `on` one that reads from it.
/// Returns `(module, user, is_writing)`.
fn session_direction_line(body: &str) -> Option<(String, String, bool)> {
    let (rest, writing) = if let Some(rest) = body.strip_prefix("rsync to ") {
        (rest, true)
    } else {
        (body.strip_prefix("rsync on ")?, false)
    };
    let (module, rest) = rest.split_once(' ')?;
    let module = module.trim_end_matches('/');
    let user = rest.strip_prefix("from ")?.split('@').next()?;
    if module.is_empty() || user.is_empty() {
        return None;
    }
    Some((module.to_string(), user.to_string(), writing))
}

/// The option out of `rsync: The server is configured to refuse --<option>`.
///
/// This is the line that makes a delete *attempt* visible. Since `--delete` is
/// refused unconditionally today, it is the only trace a deletion ever leaves —
/// there is no successful deletion to log. Measured verbatim on 3.5.0 and
/// 3.4.3:
///
/// ```text
/// [24] rsync: The server is configured to refuse --delete
/// ```
fn refused_option(body: &str) -> Option<String> {
    let marker = "is configured to refuse ";
    let rest = &body[body.find(marker)? + marker.len()..];
    let option = rest.split_whitespace().next()?.trim_start_matches('-');
    if option.is_empty() {
        None
    } else {
        Some(option.to_string())
    }
}

/// `auth failed on module <m> from <host> (<ip>) for <user>: <reason>`.
fn auth_failure_line(body: &str) -> Option<(String, Option<String>)> {
    let rest = body.strip_prefix("auth failed on module ")?;
    let module = rest.split_whitespace().next()?;
    let user = rest
        .split(" for ")
        .nth(1)
        .and_then(|tail| tail.split(':').next())
        .map(|user| user.trim().to_string())
        .filter(|user| !user.is_empty());
    Some((module.to_string(), user))
}

/// rsync's `sent … received … total size …` summary.
fn is_transfer_summary_line(body: &str) -> bool {
    body.contains("sent ") && body.contains(" received ") && body.contains(" total size ")
}

/// Mirror one log line and update the connection table from it.
async fn handle_log_line(
    line: &str,
    state: &Arc<TokioMutex<DaemonState>>,
    audit: &mut AuditContext,
) {
    if line.is_empty() {
        return;
    }
    tracing::info!("rsyncd: {line}");

    // A failing chroot is not a transfer problem, it is a deployment problem,
    // and the daemon reports it once per connection instead of once at startup.
    // Without this it shows up as a client-side `@ERROR: chroot failed` and
    // nowhere in the application, which is how it stayed unnoticed until a
    // tester ran the shipped container (ticket 33eeb98c: the container runs as
    // `appuser` and `chroot()` needs CAP_SYS_CHROOT). Lifting it into
    // `last_error` puts it on `/api/rsyncd/status`.
    if is_chroot_failure_line(line) {
        tracing::error!(
            "the rsync daemon cannot chroot into a share root, so no transfer can \
             succeed — the process needs CAP_SYS_CHROOT (see ticket 33eeb98c): {line}"
        );
        state.lock().await.last_error = Some(line.to_string());
    }

    let Some(pid) = log_line_pid(line) else {
        return;
    };
    if let Some(module) = module_from_access_line(line) {
        state.lock().await.connections.insert(pid, module);
    } else if is_connection_closed_line(line) {
        state.lock().await.connections.remove(&pid);
    }

    // Everything after the pid, so the parsers below never have to care about
    // the timestamp or the bracketed pid again.
    let body = log_line_body(line);
    record_audit(line, body, pid, state, audit).await;
}

/// The part of a log line after `<timestamp> [<pid>] `.
fn log_line_body(line: &str) -> &str {
    match line.find("] ") {
        Some(index) => line[index + 2..].trim(),
        None => line.trim(),
    }
}

/// Whether a log line reports a chroot that did not work.
///
/// rsync writes both halves: `chroot("<path>") failed: Operation not permitted
/// (1)` from the child and `@ERROR: chroot failed` as the answer to the client.
/// Either one is enough to say the deployment is broken.
fn is_chroot_failure_line(line: &str) -> bool {
    (line.contains("chroot(") && line.contains("failed")) || line.contains("chroot failed")
}

/// The pid rsync puts in brackets at the start of every log line.
fn log_line_pid(line: &str) -> Option<u32> {
    let start = line.find('[')?;
    let end = line[start..].find(']')? + start;
    line[start + 1..end].trim().parse().ok()
}

/// The module name out of `rsync allowed access on module <name> from ...`.
fn module_from_access_line(line: &str) -> Option<String> {
    let marker = "allowed access on module ";
    let rest = &line[line.find(marker)? + marker.len()..];
    let name = rest.split_whitespace().next()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Whether a log line means that connection is over.
///
/// rsync closes a connection either with its transfer summary or with an error;
/// both end that child, so both remove it from the table. Getting this wrong in
/// the "still open" direction is the safe one — a stale entry is filtered by
/// the `/proc` check in [`DaemonHandle::revoke_now`] before anything is
/// signalled.
fn is_connection_closed_line(line: &str) -> bool {
    (line.contains(" sent ") && line.contains(" received ") && line.contains(" total size "))
        || line.contains("rsync error:")
        || line.contains("_exit_cleanup")
}

/// Send `signal` to `pid`. `true` if the signal was delivered.
///
/// Via `kill(1)` rather than `libc::kill`: `libc` is not a direct dependency of
/// this crate and the ticket rules out adding one. `kill` is in coreutils on the
/// host and in busybox in the image, so it is present wherever the application
/// runs — the same assumption the application already makes about `rsync`
/// itself. `tokio::process::Child::kill` is no substitute: it sends SIGKILL,
/// which is exactly the signal that costs 85 MB of orphaned temp files.
async fn send_signal(pid: u32, signal: &str) -> bool {
    match TokioCommand::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(e) => {
            tracing::warn!(pid, signal, error = %e, "cannot send a signal");
            false
        }
    }
}

/// The process holding the exclusive lock on the daemon's pid file.
///
/// `pid` is optional because "the lock is held" and "the holder can be named"
/// are two different findings: `/proc/locks` may be unreadable in a restricted
/// container, and the pid file's content is only a hint. A message that says
/// "held, owner unknown" is still true; one that omits the difference is not.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PidFileHolder {
    pid: Option<u32>,
    /// Its command line, so that an operator recognises what to stop.
    command: Option<String>,
}

impl std::fmt::Display for PidFileHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.pid, &self.command) {
            (Some(pid), Some(command)) => write!(f, "pid {pid}: {command}"),
            (Some(pid), None) => write!(f, "pid {pid}"),
            (None, _) => write!(f, "an unidentified process"),
        }
    }
}

/// Who holds the `flock` on `pid_file`, or `None` when nobody does.
///
/// This is the answer to the question a blocked start has to ask, and it is
/// asked of the kernel rather than of the file's content: rsync locks its pid
/// file for its whole life, and the lock is dropped by the kernel when that
/// process dies, however it dies. So a lock that is still held always belongs
/// to a *living* process — "orphaned lock" is not a state that exists. A
/// leftover pid file whose process is gone carries no lock and does not block
/// anything, which is why a stale file is deliberately not deleted here: it is
/// harmless, and removing a file another instance is about to lock is not.
///
/// **The holder is not killed, by design.** It cannot be proven to be ours: the
/// run directory can be shared, the pid may have been reused, and rsync
/// terminated mid-transfer leaves its children's partial files behind (85 MB in
/// the spike). Killing a process that only *looks* like our daemon is a worse
/// failure than refusing to start with a message that names it. The refusal is
/// reported as `already_running_elsewhere`, which the frontend already shows as
/// blocked rather than as a start failure.
///
/// `None` is also the answer when nothing can be determined — a missing pid
/// file, an unreadable `/proc`. The start then goes ahead and rsync's own lock
/// decides, which is where the authority belonged all along.
fn pid_file_holder(pid_file: &Path) -> Option<PidFileHolder> {
    let meta = fs::metadata(pid_file).ok()?;
    let locks = fs::read_to_string("/proc/locks").ok()?;
    let pid = flock_holder(&locks, meta.dev(), meta.ino())?;
    Some(PidFileHolder {
        pid: Some(pid),
        command: process_command_line(pid),
    })
}

/// Best effort answer for a message, once the lock is known to be taken.
///
/// [`pid_file_holder`] is the strict form: it must never claim a holder that is
/// not there, because a start is refused on its word. This one runs after the
/// daemon itself has already reported the lock failure, so the question is no
/// longer *whether* somebody holds it but *who*, and the pid file's content is
/// worth reading — as long as that process is still alive, which is checked.
fn pid_file_blocker(pid_file: &Path) -> Option<PidFileHolder> {
    if let Some(holder) = pid_file_holder(pid_file) {
        return Some(holder);
    }
    let pid: u32 = fs::read_to_string(pid_file).ok()?.trim().parse().ok()?;
    let command = process_command_line(pid)?;
    Some(PidFileHolder {
        pid: Some(pid),
        command: Some(command),
    })
}

/// The pid holding an `flock` on the file with `dev`/`inode`, per `/proc/locks`.
///
/// A line looks like
///
/// ```text
/// 3: FLOCK  ADVISORY  WRITE 1234 08:03:1310721 0 EOF
/// ```
///
/// The device is printed as hexadecimal `major:minor`, the inode as decimal.
/// Lines for processes *waiting* on a lock carry a `->` after the number and
/// are skipped: a waiter does not block us, the holder does. The columns before
/// the device triple differ between lock types, so the triple is located by
/// shape and the pid taken from the field in front of it, rather than counted
/// from the start of the line.
fn flock_holder(locks: &str, dev: u64, inode: u64) -> Option<u32> {
    let wanted = format!("{:02x}:{:02x}:{inode}", dev_major(dev), dev_minor(dev));
    for line in locks.lines() {
        if line.contains("->") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(index) = fields.iter().position(|field| *field == wanted) else {
            continue;
        };
        if index == 0 {
            continue;
        }
        if let Ok(pid) = fields[index - 1].parse::<u32>() {
            return Some(pid);
        }
    }
    None
}

/// Major device number, in the encoding `/proc/locks` prints.
fn dev_major(dev: u64) -> u64 {
    ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)
}

/// Minor device number, in the encoding `/proc/locks` prints.
fn dev_minor(dev: u64) -> u64 {
    (dev & 0xff) | ((dev >> 12) & !0xff)
}

/// The command line of `pid`, or `None` when that process is gone.
///
/// Doubles as the liveness check: `/proc/<pid>` disappears with the process, so
/// a `None` here is the difference between "somebody is holding it" and "the
/// pid file is a leftover". A kernel thread has an empty `cmdline`, so its name
/// is read from `comm` instead — otherwise a live process would look dead.
fn process_command_line(pid: u32) -> Option<String> {
    if let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) {
        let joined = raw
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join(" ");
        if !joined.is_empty() {
            return Some(joined);
        }
    }
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(comm.trim().to_string())
}

/// Whether `pid` is still a child of `parent`, according to `/proc`.
///
/// The guard before signalling a connection: a pid whose closing log line was
/// missed may have been reused by an unrelated process in the meantime, and
/// SIGTERM to the wrong process is worse than a transfer that is left alone.
/// The fourth field of `/proc/<pid>/stat` is the parent pid; the second field
/// is the command name in brackets and may itself contain spaces and brackets,
/// so the fields are counted from the *last* `)` rather than from the start.
fn is_child_of(pid: u32, parent: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(after_comm) = stat.rfind(')').map(|i| &stat[i + 1..]) else {
        return false;
    };
    // After the command: state, ppid, ...
    after_comm
        .split_whitespace()
        .nth(1)
        .and_then(|ppid| ppid.parse::<u32>().ok())
        .map(|ppid| ppid == parent)
        .unwrap_or(false)
}

/// Drop connections whose child is no longer there.
///
/// rsync writes nothing to its log when a connection ends, so the table cannot
/// be closed by reading — see [`mirror_log_file`]. `/proc` is the authority
/// instead: an entry whose pid is no longer a child of the daemon is a
/// connection that is over. This is also the guard that keeps a revoke from
/// signalling a pid that has been reused since.
fn prune_connections(state: &mut DaemonState) {
    let Some(daemon) = state.pid else {
        state.connections.clear();
        state.sessions.clear();
        return;
    };
    state.connections.retain(|pid, _| is_child_of(*pid, daemon));
    // The session table is closed the same way and for the same reason: an
    // aborted connection writes no closing line, so /proc is the authority.
    state.sessions.retain(|pid, _| is_child_of(*pid, daemon));
}

/// Count children of `parent` that have exited and not been reaped.
///
/// Zero on both rsync versions after 30 transfers, which is why the daemon's
/// children are not reaped here: they are grandchildren of this process, and
/// only their own parent can wait for them. Surfacing the count in the status
/// means a regression shows up as a number rather than as a process table
/// nobody looks at.
fn count_zombie_children(parent: u32) -> usize {
    let Ok(entries) = fs::read_dir("/proc") else {
        return 0;
    };
    let mut zombies = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.parse::<u32>().is_err() {
            continue;
        }
        let Ok(stat) = fs::read_to_string(format!("/proc/{name}/stat")) else {
            continue;
        };
        let Some(after_comm) = stat.rfind(')').map(|i| &stat[i + 1..]) else {
            continue;
        };
        let mut fields = after_comm.split_whitespace();
        let state = fields.next().unwrap_or("");
        let ppid = fields.next().and_then(|p| p.parse::<u32>().ok());
        if state == "Z" && ppid == Some(parent) {
            zombies += 1;
        }
    }
    zombies
}

// ---------------------------------------------------------------------------
// Orphaned temp files
// ---------------------------------------------------------------------------

/// Remove partial transfers a killed daemon left behind in its temp directories.
///
/// `roots` are module temp directories — nothing else. Every writable module is
/// rendered with `temp dir = /.rsync-tmp` (see [`MODULE_TEMP_DIR`]), so a
/// partial transfer can only ever be inside one of them, and everything inside
/// one of them was put there by rsync. There is no name pattern to match and no
/// user file to get wrong: the directory belongs to us.
///
/// That is the change this function exists to record. It used to walk the
/// **share roots** and delete every name shaped like `.<something>.XXXXXX`.
/// Measured against a directory of ordinary files, that pattern deleted
/// `.ssh.config`, `.env.docker`, `.bashrc.backup` and `.htaccess.backup` — four
/// user files for one real leftover. Share roots hold other people's data;
/// deleting from them on a guess is not a trade this application makes.
/// Temp files that a previous version of this application left lying in a share
/// root are deliberately **not** cleaned up: identifying them would mean making
/// the same guess again. Wasted disk space is recoverable, a deleted file is
/// not.
///
/// Only [`DaemonHandle::shutdown`]'s SIGKILL escalation and an outright crash
/// leave anything here — a child that is merely disconnected removes its own
/// partial (measured). Both are exactly the cases where nobody is left to clean
/// up, so the next start does it.
///
/// `min_age` is the one remaining guard, and it guards against a different
/// thing than it used to: this runs before *our* daemon exists, but two
/// application instances pointed at the same share would have two daemons, and
/// the second one's in-flight temp file must not be swept out from under it.
/// rsync writes to that file continuously, so its mtime stays fresh and
/// [`DEFAULT_TEMP_FILE_MIN_AGE`] keeps it. The second instance cannot in fact
/// start (the pid file lock stops it), so this is belt and braces.
///
/// Returns the number of bytes reclaimed. Failures are logged, never fatal: a
/// temp directory that cannot be read is not a reason to refuse to start.
pub fn sweep_module_temp_dirs(roots: &[PathBuf], min_age: Duration) -> u64 {
    let mut reclaimed = 0u64;
    for root in roots {
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let too_young = meta
                .modified()
                .ok()
                .and_then(|m| m.elapsed().ok())
                .map(|age| age < min_age)
                .unwrap_or(true);
            if too_young {
                continue;
            }
            let size = meta.len();
            match fs::remove_file(entry.path()) {
                Ok(()) => {
                    reclaimed += size;
                    tracing::warn!(
                        file = %entry.path().display(),
                        bytes = size,
                        "removed a partial transfer left behind by a daemon that was killed"
                    );
                }
                Err(e) => tracing::warn!(
                    file = %entry.path().display(),
                    error = %e,
                    "cannot remove an orphaned temp file"
                ),
            }
        }
    }
    if reclaimed > 0 {
        tracing::warn!(bytes = reclaimed, "reclaimed space from orphaned transfers");
    }
    reclaimed
}

/// Whether `name` is shaped like the temp file rsync builds by default.
///
/// **Never use this to decide a deletion.** It is a test and probe helper: it
/// answers "would rsync have produced this name", which is not the same
/// question as "is this file rsync's". `.ssh.config` and `.bashrc.backup`
/// answer `true` here and are ordinary user files. The sweep is built on
/// [`MODULE_TEMP_DIR`] instead, and this function is what the probes use to
/// assert that no such name ever appears in a share root again.
#[cfg(test)]
fn is_rsync_temp_name(name: &str) -> bool {
    const SUFFIX_LEN: usize = 6;
    if !name.starts_with('.') {
        return false;
    }
    let Some(dot) = name.rfind('.') else {
        return false;
    };
    if dot < 2 || name.len() - dot - 1 != SUFFIX_LEN {
        return false;
    }
    name[dot + 1..].chars().all(|c| c.is_ascii_alphanumeric())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique scratch directory per test; the ticket id keeps it apart from the
    /// directories of the agents working in parallel.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rsyncd-db73d18e-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn module_in(dir: &Path, writable: bool) -> ModuleConfig {
        ModuleConfig::new(dir, writable, 1001, 1001, 4).expect("module")
    }

    #[test]
    fn renders_the_documented_template() {
        let base = scratch("template");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let module = module_in(&share, true);

        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module.clone());
        let conf = cfg.render_conf().unwrap();

        let expected = format!(
            "# Generated by rclone-gui. Do not edit, this file is overwritten.\n\
             # No \"auth digest\": rsync on Alpine is built without openssl-crypto and\n\
             # offers md5/md4 only. See docs/rsync-transport.md.\n\
             address = 127.0.0.1\n\
             port = 873\n\
             # no \"proxy protocol\": rsync 3.4.3 resets every connection unless the\n\
             # TLS terminator sends a PROXY header. See docs/rsync-transport.md.\n\
             \n\
             [{name}]\n\
             \x20   path = {path}\n\
             \x20   auth users = {name}\n\
             \x20   secrets file = /etc/rsyncd/secrets\n\
             \x20   list = no\n\
             \x20   read only = no\n\
             \x20   use chroot = yes\n\
             \x20   munge symlinks = yes\n\
             \x20   uid = 1001\n\
             \x20   gid = 1001\n\
             \x20   max connections = 4\n\
             \x20   temp dir = /.rsync-tmp\n\
             \x20   refuse options = copy-links copy-dirlinks copy-unsafe-links delete \
             remove-source-files remove-sent-files force\n\
             \x20   transfer logging = yes\n\
             \x20   log format = rclone-gui-audit %a %u %m %o %l %b %f\n",
            name = module.name(),
            path = module.path(),
        );
        assert_eq!(conf, expected);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn proxy_protocol_is_off_unless_a_trusted_host_list_is_given() {
        let base = scratch("proxy");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module_in(&share, true));
        // Off by default: neither directive appears, only the explanation.
        let conf = cfg.render_conf().unwrap();
        assert!(!conf.contains("proxy protocol = true"));
        assert!(!conf.contains("proxy protocol hosts"));

        // Enabled: rsync 3.5.0 warns unless both lines are present, so both
        // are always written together.
        let cfg = cfg.clone().with_proxy_protocol("127.0.0.1");
        let conf = cfg.render_conf().unwrap();
        assert!(conf.contains("proxy protocol = true\nproxy protocol hosts = 127.0.0.1\n"));

        // And the host list is validated like every other value.
        let cfg = cfg.with_proxy_protocol("127.0.0.1\nread only = no");
        assert!(cfg.render_conf().is_err());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn read_only_follows_the_write_scope() {
        let base = scratch("scope");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        let writable = module_in(&share, true);
        let readonly = module_in(&share, false);
        assert!(!writable.read_only());
        assert!(readonly.read_only());

        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(writable);
        cfg.add_module(readonly);
        let conf = cfg.render_conf().unwrap();
        assert!(conf.contains("    read only = no\n"));
        assert!(conf.contains("    read only = yes\n"));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn every_module_refuses_the_symlink_dereferencing_options() {
        let base = scratch("refuse");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module_in(&share, true));
        let conf = cfg.render_conf().unwrap();
        assert!(conf.contains(
            "    refuse options = copy-links copy-dirlinks copy-unsafe-links delete \
             remove-source-files remove-sent-files force\n"
        ));
        assert!(conf.contains("    use chroot = yes\n"));
        assert!(conf.contains("    munge symlinks = yes\n"));
        // The parameter is not supported by the rsync in our image and would be
        // ignored silently while suggesting protection that is not there.
        assert!(!conf.contains("auth digest ="));
        // No direct mode: the daemon must never be reachable from outside.
        assert!(conf.contains("address = 127.0.0.1\n"));
        assert!(!conf.contains("0.0.0.0"));
        fs::remove_dir_all(&base).ok();
    }

    /// Whether a rendered configuration mentions `insecure links` at all.
    ///
    /// Written as a function rather than inlined so that the test below can
    /// point it at a configuration that *does* set the parameter and show that
    /// it says so. A check that has never been seen to fire is not a check —
    /// and "the string is absent" is exactly the shape of assertion that stays
    /// green after somebody renames the thing it was looking for.
    fn mentions_insecure_links(conf: &str) -> bool {
        conf.lines()
            .any(|line| line.trim_start().starts_with("insecure links"))
    }

    /// `insecure links` must not appear in a generated configuration.
    ///
    /// # What the parameter does, measured
    ///
    /// rsync 3.5.0 resolves the paths of a served module with a symlink-race
    /// defence that is on by default: it follows a symlink component only when
    /// that component belongs to uid 0 or to the module's own uid, and refuses
    /// one planted by anybody else. `insecure links = yes` turns that off for
    /// the module and restores the pre-hardening behaviour (the man page names
    /// CVE-2026-53797 and CVE-2026-53801).
    ///
    /// Measured on the host (rsync 3.5.0) with a module whose share held
    /// `passwd.link -> /etc/passwd`, `use chroot = no`, `munge symlinks = no`
    /// and no `refuse options` — so nothing but this one parameter separated the
    /// two runs:
    ///
    /// | `insecure links` | `rsync -aL <module>/ dst/` |
    /// |---|---|
    /// | not set (default) | `failed to open "passwd.link": Too many levels of symbolic links (40)`, nothing leaked |
    /// | `yes` | **2597 bytes of `/etc/passwd` in `dst/passwd.link`** |
    ///
    /// The parameter does not exist in rsync 3.4.3, which is what the image
    /// ships: setting it there would produce `Unknown Parameter encountered`
    /// and protect nothing. Not setting it is therefore right on both versions,
    /// and this test is what keeps it that way.
    ///
    /// The end-to-end half of this — the leak actually happening once the
    /// parameter is set — is `module_boundaries_on_the_real_daemon`.
    #[test]
    fn no_module_ever_carries_insecure_links() {
        let base = scratch("insecure-links");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        for writable in [true, false] {
            let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
            cfg.add_module(module_in(&share, writable));
            cfg.set_log_file(base.join("daemon.log"));
            let conf = cfg.render_conf().unwrap();
            assert!(
                !mentions_insecure_links(&conf),
                "a generated module carries \"insecure links\" (writable={writable}):\n{conf}"
            );
            // The whole `refuse options` list is what stops a client from
            // asking for the same effect from the outside.
            assert!(conf.contains(&format!("    refuse options = {REFUSED_OPTIONS}\n")));
        }

        // The counter-proof: the same check, aimed at a configuration that does
        // set the parameter, has to notice.
        assert!(
            mentions_insecure_links("[m]\n    path = /srv\n    insecure links = yes\n"),
            "the check cannot see the parameter it exists to forbid"
        );
        fs::remove_dir_all(&base).ok();
    }

    // -----------------------------------------------------------------------
    // Rootless operation (ticket 50c8ec48)
    // -----------------------------------------------------------------------

    /// The rootless configuration, byte for byte.
    ///
    /// The hardened counterpart is
    /// `the_generated_configuration_matches_the_reviewed_template`, and the two
    /// together are the whole of what the mode changes on paper: `use chroot`
    /// flips, `uid`/`gid` disappear, the port moves. Written as a full
    /// comparison rather than a handful of `contains` for the same reason as
    /// that one — a `contains` cannot see a line that was *added*.
    #[test]
    fn a_rootless_configuration_drops_the_chroot_and_the_identity() {
        let base = scratch("rootless-template");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let module = module_in(&share, true);

        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets").with_hardening(Hardening::Rootless);
        cfg.add_module(module.clone());
        let conf = cfg.render_conf().unwrap();

        let expected = format!(
            "# Generated by rclone-gui. Do not edit, this file is overwritten.\n\
             # No \"auth digest\": rsync on Alpine is built without openssl-crypto and\n\
             # offers md5/md4 only. See docs/rsync-transport.md.\n\
             address = 127.0.0.1\n\
             port = {port}\n\
             # no \"proxy protocol\": rsync 3.4.3 resets every connection unless the\n\
             # TLS terminator sends a PROXY header. See docs/rsync-transport.md.\n\
             \n\
             [{name}]\n\
             \x20   path = {path}\n\
             \x20   auth users = {name}\n\
             \x20   secrets file = /etc/rsyncd/secrets\n\
             \x20   list = no\n\
             \x20   read only = no\n\
             \x20   use chroot = no\n\
             \x20   munge symlinks = yes\n\
             \x20   max connections = 4\n\
             \x20   temp dir = /.rsync-tmp\n\
             \x20   refuse options = copy-links copy-dirlinks copy-unsafe-links delete \
             remove-source-files remove-sent-files force\n\
             \x20   transfer logging = yes\n\
             \x20   log format = rclone-gui-audit %a %u %m %o %l %b %f\n",
            port = ROOTLESS_DAEMON_PORT,
            name = module.name(),
            path = module.path(),
        );
        assert_eq!(conf, expected);

        // What must survive the mode: the two layers that are left once the
        // chroot is gone, and the parameter that would undo them.
        assert!(conf.contains("    munge symlinks = yes\n"));
        assert!(conf.contains(&format!("    refuse options = {REFUSED_OPTIONS}\n")));
        assert!(!mentions_insecure_links(&conf));
        assert!(conf.contains("address = 127.0.0.1\n"));
        fs::remove_dir_all(&base).ok();
    }

    /// The default is the hardened mode, everywhere.
    ///
    /// A [`DaemonConfig`] built without saying anything renders the container's
    /// configuration; only the startup, which detects the mode, moves it. If
    /// this ever flips, every hardening assertion in this module starts
    /// measuring the weaker path without saying so.
    #[test]
    fn hardening_defaults_to_the_container_path() {
        assert_eq!(
            DaemonConfig::new("/etc/rsyncd/secrets").hardening(),
            Hardening::Full
        );
        assert_eq!(
            ModuleRegistry::new("/etc/rsyncd/rsyncd.conf", "/etc/rsyncd/secrets").hardening(),
            Hardening::Full
        );
        assert_eq!(
            DaemonSettings::new("/etc/rsyncd/rsyncd.conf", "/etc/rsyncd/run").port,
            DAEMON_PORT
        );
        assert_eq!(
            DaemonSettings::new("/etc/rsyncd/rsyncd.conf", "/etc/rsyncd/run")
                .with_hardening(Hardening::Rootless)
                .port,
            ROOTLESS_DAEMON_PORT
        );
        assert!(Hardening::Full.uses_chroot() && Hardening::Full.drops_privileges());
        assert!(!Hardening::Rootless.uses_chroot() && !Hardening::Rootless.drops_privileges());
    }

    /// The port follows the mode, and the override is validated.
    ///
    /// `0` and anything unparsable fall back rather than abort: the port is not
    /// the boundary here (`address = 127.0.0.1` and the loopback verdict are),
    /// and a start that dies over a typo in an optional variable costs more
    /// than it buys. Fixed as a table so the choice is visible.
    #[test]
    fn the_daemon_port_follows_the_mode_and_a_checked_override() {
        for (mode, default) in [
            (Hardening::Full, DAEMON_PORT),
            (Hardening::Rootless, ROOTLESS_DAEMON_PORT),
        ] {
            assert_eq!(mode.port_with_override(None), default);
            assert_eq!(mode.port_with_override(Some("9137")), 9137);
            assert_eq!(mode.port_with_override(Some("  9137  ")), 9137);
            for bad in ["", "0", "abc", "-1", "70000", "873 874"] {
                assert_eq!(
                    mode.port_with_override(Some(bad)),
                    default,
                    "{bad:?} must not become a port"
                );
            }
        }
    }

    /// The rootless mode says what it costs, and the hardened one says nothing.
    ///
    /// The announcement is the whole reason the mode is detected instead of
    /// switched: an operator who is not told has lost the chroot without
    /// knowing. Asserted here rather than trusted to a `println!` in
    /// `src/main.rs`, which no test can see.
    #[test]
    fn the_rootless_mode_announces_what_it_gives_up() {
        assert!(Hardening::Full.warnings().is_empty());
        let said = Hardening::Rootless.warnings().join("\n").to_lowercase();
        assert!(!said.is_empty());
        for term in ["rootless", "chroot", "uid", "port", "development"] {
            assert!(
                said.contains(term),
                "the warning never mentions {term:?}: {said}"
            );
        }
    }

    /// What the detection reads, and that it fails towards a daemon that runs.
    ///
    /// The verdict itself depends on the machine — root, a file capability, or
    /// neither — so what is asserted is the two inputs and the direction of the
    /// fallback. `getcap` on a path that is not there, or no `getcap` at all,
    /// has to mean "no capability": that yields [`Hardening::Rootless`], a
    /// daemon that comes up and *says* what it lacks, rather than one that
    /// promises a chroot and dies in it.
    #[test]
    fn hardening_detection_reads_the_machine_and_fails_towards_running() {
        // The uid comes out of /proc and agrees with what the filesystem says
        // about a file this process has just created.
        let base = scratch("hardening-uid");
        fs::create_dir_all(&base).unwrap();
        let probe = base.join("mine");
        fs::write(&probe, "x").unwrap();
        let owner = fs::metadata(&probe).unwrap().uid();
        assert_eq!(
            effective_uid(),
            Some(owner),
            "the uid read from /proc/self/status has to be the one the kernel              stamps on a file this process creates"
        );

        // A bare command name is resolved through PATH; a path that does not
        // exist resolves to nothing and can therefore carry no capability.
        assert_eq!(
            resolve_in_path(Path::new("/definitely/not/here/rsync")),
            None
        );
        assert!(!binary_can_chroot(Path::new("/definitely/not/here/rsync")));
        assert!(!binary_can_chroot(&base.join("mine")));
        if let Some(found) = resolve_in_path(Path::new("sh")) {
            assert!(
                found.is_absolute() && found.is_file(),
                "{}",
                found.display()
            );
        }

        // And the verdict is one of the two, for a binary that is not there as
        // well — nothing about an unanswerable question may panic.
        let verdict = Hardening::detect(Path::new("/definitely/not/here/rsync"));
        assert_eq!(verdict, Hardening::Rootless);
        // On this machine, whatever it is: root gets the full path, and so does
        // a binary carrying cap_sys_chroot. Nothing else does.
        let here = Hardening::detect(Path::new(DEFAULT_RSYNC_BINARY));
        let privileged =
            effective_uid() == Some(0) || binary_can_chroot(Path::new(DEFAULT_RSYNC_BINARY));
        assert_eq!(here == Hardening::Full, privileged);
        fs::remove_dir_all(&base).ok();
    }

    /// The TLS terminator computes the same default port as the application.
    ///
    /// The rule lives twice — `Hardening::port` here and `rsyncd_default_port`
    /// in `config/rsync-tls.sh` — because stunnel cannot ask the application
    /// what it decided. Two copies of a rule drift, and the drift is invisible:
    /// the daemon runs, stunnel connects to a closed port, and the peer sees a
    /// TLS handshake that leads nowhere. So the shell function is executed here
    /// and its answer compared with this module's.
    #[test]
    fn the_tls_script_computes_the_same_daemon_port() {
        use std::process::Command;
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join("rsync-tls.sh");
        assert!(script.is_file(), "{} is missing", script.display());

        let ask = |port_env: Option<&str>| -> String {
            let mut command = Command::new("bash");
            command
                .arg("-c")
                .arg(
                    "set -u; . \"$1\" >/dev/null 2>&1; \
                     printf '%s|%s' \"$(rsyncd_default_port)\" \"$RCLONE_GUI_RSYNC_BACKEND\"",
                )
                .arg("bash")
                .arg(&script)
                // Never inherited: the backend override would make the second
                // half of the answer say nothing about the port rule.
                .env_remove("RCLONE_GUI_RSYNC_BACKEND")
                .env_remove(PORT_ENV);
            if let Some(value) = port_env {
                command.env(PORT_ENV, value);
            }
            let out = command.output().expect("cannot run bash");
            assert!(
                out.status.success(),
                "the script could not be sourced: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        // Without an override the script has to agree with the mode this
        // machine is actually in — that is the value stunnel would use.
        let mine = Hardening::detect(Path::new(DEFAULT_RSYNC_BINARY)).port_with_override(None);
        assert_eq!(
            ask(None),
            format!("{mine}|127.0.0.1:{mine}"),
            "the script and this module disagree about the daemon port"
        );
        // With one, both sides read the same variable.
        assert_eq!(ask(Some("9137")), "9137|127.0.0.1:9137");
    }

    // -----------------------------------------------------------------------
    // Secrets, rate limits and the TLS obligation (ticket 4292d027)
    // -----------------------------------------------------------------------

    /// No `Debug` or `Serialize` in this module may print a module secret.
    ///
    /// # Why this is a test and not a code review
    ///
    /// `derive(Debug)` on a type that holds a secret has been found in this
    /// project **six** times (`LoginOutcome`, `ModuleConfig`, `RcloneConfig`,
    /// `ConfigRequest`, `NewShare`, `SessionRefresh`). Twice the series was
    /// declared closed after somebody searched `src/**` by hand, and twice the
    /// next ticket added another one: a hand search cannot cover a type that
    /// does not exist yet.
    ///
    /// So this does not search, it *asks*. Every type in this module that
    /// carries a secret, or carries something that carries one, is formatted
    /// here with a secret whose value the test knows, and the output has to not
    /// contain it. A new field on any of them is covered the moment it is
    /// added; a new type is one line here.
    ///
    /// The counter-proof is at the end: the same check, aimed at a type that
    /// really does print its secret, has to notice.
    #[test]
    fn nothing_in_this_module_can_print_a_module_secret() {
        let base = scratch("no-secret-in-debug");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        let module = module_in(&share, true);
        let secret = module.secret().to_string();
        assert_eq!(
            secret.len(),
            SECRET_BYTES * 2,
            "the fixture is the real thing"
        );

        let mut config = DaemonConfig::new(base.join("etc").join("secrets"));
        config.add_module(module.clone());
        config.set_log_file(base.join("daemon.log"));

        let settings = DaemonSettings::new(base.join("etc").join("rsyncd.conf"), base.join("run"));
        let status = DaemonStatus {
            running: true,
            pid: Some(1),
            address: DAEMON_ADDRESS.to_string(),
            port: DAEMON_PORT,
            modules: vec![module.name().to_string()],
            active_modules: vec![module.name().to_string()],
            connections: 1,
            restarts: 0,
            already_running_elsewhere: false,
            zombie_children: 0,
            last_error: None,
        };
        let event = AuditEvent {
            at: "2026/08/25 17:00:00".to_string(),
            pid: 1,
            module: Some(module.name().to_string()),
            user: Some(module.name().to_string()),
            client: Some("192.0.2.7".to_string()),
            client_port: Some(4711),
            client_source: ClientAddressSource::StunnelPort,
            action: AuditAction::AccessGranted,
            destructive: false,
            path: None,
            size: None,
            refused_option: None,
            detail: "rsync allowed access on module".to_string(),
        };
        let session = Session {
            module: Some(module.name().to_string()),
            user: Some(module.name().to_string()),
            client: Some("192.0.2.7".to_string()),
            client_port: Some(4711),
            client_source: Some(ClientAddressSource::StunnelPort),
        };

        // `{:?}` for everything, and `serde_json` on top for the types that are
        // serialised into the status API — a redacted `Debug` and a derived
        // `Serialize` on the same type would still put the secret on the wire.
        // The flag says whether this rendering is *about* a module. Where it
        // is, the module name has to show up: "no secret in it" would otherwise
        // also hold for an empty string, and two of these renderings really do
        // not mention a module at all.
        let rendered: Vec<(&str, String, bool)> = vec![
            ("ModuleConfig", format!("{module:?}"), true),
            ("DaemonConfig", format!("{config:?}"), true),
            ("DaemonStatus", format!("{status:?}"), true),
            ("AuditEvent", format!("{event:?}"), true),
            ("Session", format!("{session:?}"), true),
            // ... and the configuration file, which the secret is deliberately
            // kept out of — it lives in the secrets file next to it.
            ("render_conf", config.render_conf().unwrap(), true),
            (
                "DaemonStatus as json",
                serde_json::to_string(&status).unwrap(),
                true,
            ),
            (
                "AuditEvent as json",
                serde_json::to_string(&event).unwrap(),
                true,
            ),
            ("DaemonSettings", format!("{settings:?}"), false),
            (
                "RevokeOutcome",
                format!(
                    "{:?}",
                    RevokeOutcome {
                        module_removed: true,
                        connections_terminated: 1,
                    }
                ),
                false,
            ),
            // `argv` is world-readable through `/proc/<pid>/cmdline` for every
            // user on the host, which is why the secret travels in a 0600 file
            // and never on the command line.
            ("DaemonSettings::argv", settings.argv().join(" "), false),
        ];

        for (what, output, about_a_module) in &rendered {
            assert!(
                !output.contains(&secret),
                "{what} printed the module secret: {output}"
            );
            if *about_a_module {
                assert!(
                    output.contains(module.name()),
                    "{what} does not mention the module at all, so finding no secret \
                     in it says nothing: {output}"
                );
            }
        }

        // The secret is in exactly one rendering, and that one is written to a
        // 0600 file and to nothing else.
        assert!(config.render_secrets().unwrap().contains(&secret));

        // The counter-proof: a type that does print its secret has to be
        // caught by the same test.
        #[derive(Debug)]
        struct Leaky {
            name: String,
            secret: String,
        }
        let leaky = format!(
            "{:?}",
            Leaky {
                name: module.name().to_string(),
                secret: secret.clone(),
            }
        );
        assert!(
            leaky.contains(&secret),
            "the check cannot see a secret even when it is printed"
        );

        fs::remove_dir_all(&base).ok();
    }

    /// `max connections` is per module, is always rendered, and is the one
    /// number the daemon itself enforces.
    ///
    /// The enforcement is measured against a real daemon in
    /// `secrets_and_limits_on_the_real_daemon`; what is checked here is that
    /// the value reaches the configuration at all and cannot be zero — a module
    /// without the parameter has no limit, and `max connections = 0` means
    /// *unlimited* in rsync, not "closed".
    #[test]
    fn every_module_carries_a_connection_limit() {
        let base = scratch("conn-limit");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        for limit in [1u32, 4, 64] {
            let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
            cfg.add_module(ModuleConfig::new(&share, true, 1001, 1001, limit).unwrap());
            let conf = cfg.render_conf().unwrap();
            assert!(
                conf.contains(&format!("    max connections = {limit}\n")),
                "the limit {limit} did not reach the configuration:\n{conf}"
            );
        }
        // Zero is refused rather than written: rsync reads it as "no limit".
        assert!(ModuleConfig::new(&share, true, 1001, 1001, 0).is_err());
        fs::remove_dir_all(&base).ok();
    }

    /// A `--dparam` must not be able to move the daemon off loopback.
    ///
    /// Measured before this check existed: the shipped configuration started
    /// with `--dparam=address=0.0.0.0` listened on `0.0.0.0:<port>` — the
    /// plaintext rsync protocol on every interface — while the configuration
    /// file still said `address = 127.0.0.1` and every test that read the file
    /// stayed green. See
    /// [`DaemonSettings::check_listen_is_not_overridden`].
    #[test]
    fn a_dparam_cannot_move_the_daemon_off_loopback() {
        let base = scratch("dparam-listen");
        let conf = base.join("rsyncd.conf");
        let run = base.join("run");

        for param in [
            "address=0.0.0.0",
            "address = 0.0.0.0",
            "address=::",
            "port=8873",
        ] {
            let settings = DaemonSettings::new(&conf, &run).with_dparam(param);
            let error = settings
                .check_listen_is_not_overridden()
                .expect_err(&format!("--dparam={param} was accepted"));
            assert!(
                error.to_string().contains("TLS terminator"),
                "the refusal has to say why: {error}"
            );
        }

        // And the one the probes actually need is still allowed, or the check
        // would have closed the door on the tests that measure everything else.
        let settings = DaemonSettings::new(&conf, &run)
            .with_dparam("strict modes=no")
            .with_dparam("lock file=/tmp/x");
        assert!(settings.check_listen_is_not_overridden().is_ok());
        fs::remove_dir_all(&base).ok();
    }

    /// `/proc/net/tcp` prints addresses in host byte order, and reading them the
    /// other way round turns loopback into a routable address.
    ///
    /// The two tables are real captures: `0100007F` is `127.0.0.1` and
    /// `00000000` is `0.0.0.0`; in the v6 table the all-zero address is `::`
    /// and the trailing `01000000` word is `::1`.
    #[test]
    fn a_proc_net_tcp_address_is_read_in_host_byte_order() {
        assert_eq!(
            hex_address("0100007F:0369"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            "127.0.0.1 was misread; a byte-swapped loopback address reads as routable"
        );
        assert_eq!(
            hex_address("00000000:0369"),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            hex_address("0000000000000000FFFF00000100007F:0369"),
            Some(IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()))
        );
        assert_eq!(hex_address("nonsense"), None);
        assert_eq!(hex_address("0100007F"), None);

        assert!(!is_reachable_from_outside(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_reachable_from_outside(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // The one `Ipv6Addr::is_loopback` gets wrong on its own.
        assert!(!is_reachable_from_outside(IpAddr::V6(
            "::ffff:127.0.0.1".parse().unwrap()
        )));
        assert!(is_reachable_from_outside(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_reachable_from_outside(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(is_reachable_from_outside(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 7
        ))));

        // Only sockets in state 0A are listeners; an established connection to
        // the same port must not be mistaken for one.
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                      0: 0100007F:0369 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n\
                      1: 00000000:0369 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1\n\
                      2: 0100007F:1F90 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1\n";
        let found = listeners_in_table(table, 873);
        assert_eq!(
            found,
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            ],
            "the table was parsed wrongly: {found:?}"
        );
        assert!(
            listeners_in_table(table, 8080).is_empty(),
            "a connection in state 01 was counted as a listener"
        );
    }

    /// The loopback check against the kernel, with both answers.
    ///
    /// No rsync involved: a plain `TcpListener` is enough to show that the check
    /// says "loopback only" for a loopback socket and "reachable from outside"
    /// for one on `0.0.0.0`. Without the second half the check could be
    /// hard-wired to `Ok(())` and this test would not notice.
    #[test]
    fn the_loopback_check_reads_the_real_listening_socket() {
        let loopback = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let port = loopback.local_addr().unwrap().port();
        let found = listening_addresses(port).expect("/proc/net/tcp is readable here");
        assert!(
            !found.is_empty(),
            "the check found no listener on a port that is definitely open"
        );
        assert!(
            !found.iter().copied().any(is_reachable_from_outside),
            "a socket bound to 127.0.0.1 was reported as reachable: {found:?}"
        );
        assert!(
            loopback_only_verdict(port).is_ok(),
            "a loopback-only port was refused, which would stop every start"
        );
        drop(loopback);

        // The counter-proof, on a fresh port so the one above cannot linger.
        let anywhere = std::net::TcpListener::bind("0.0.0.0:0").expect("wildcard listener");
        let port = anywhere.local_addr().unwrap().port();
        let found = listening_addresses(port).expect("/proc/net/tcp is readable here");
        assert!(
            found.iter().copied().any(is_reachable_from_outside),
            "a socket bound to 0.0.0.0 was reported as loopback-only, so the check \
             cannot detect an exposed daemon: {found:?}"
        );
        // The verdict the start actually asks for, on the same port.
        let error = loopback_only_verdict(port)
            .expect_err("a wildcard socket on the daemon port has to abort the start");
        assert!(
            error.to_string().contains("without TLS"),
            "the refusal has to say what is wrong with it: {error}"
        );
        drop(anywhere);
    }

    /// The third bolt against plaintext leaving the machine: `config/rsync-tls.sh`.
    ///
    /// # Why a Rust test shells out to bash
    ///
    /// The bolt lives in a shell function, `tls_backend_is_loopback`, and it had
    /// **no test at all** — a tester ran a table of thirteen values by hand and
    /// found the hole with value fourteen. `bash -n` was the only automated
    /// check in place, and it cannot see logic: the broken version was
    /// syntactically perfect.
    ///
    /// The repository has no shell test runner and no test CI, so the cheapest
    /// place where this table runs on every `cargo test` is here. The script is
    /// sourced, not executed: it only assigns defaults and defines functions at
    /// the top level, so sourcing has no side effects.
    ///
    /// # The hole
    ///
    /// The check was `case "$host" in 127.*|::1|localhost|...)`, and `127.*`
    /// globs **names**, not just addresses:
    /// `RCLONE_GUI_RSYNC_BACKEND=127.0.0.1.evil.com:873` counted as loopback,
    /// so stunnel would have forwarded plaintext rsync — md5 challenge and all —
    /// off the machine, while the connection still looked like TLS from outside.
    /// It is now a positive check: three spelled-out names, or an IPv4 address
    /// decomposed field by field and required to sit in 127.0.0.0/8.
    ///
    /// # Two values that are refused although they are loopback
    ///
    /// `127.1:873` (the octet shorthand) and anything with an inner space. The
    /// bolt fails **closed** on purpose: a refused loopback shorthand costs a
    /// start-up error the operator can read, an accepted hostname costs
    /// plaintext on the wire. Neither form is ever produced by the application —
    /// `DAEMON_ADDRESS` is the literal `127.0.0.1`.
    #[test]
    fn every_backend_form_is_judged_by_the_tls_script() {
        use std::process::Command;
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join("rsync-tls.sh");
        assert!(script.is_file(), "{} is missing", script.display());

        // The tester's table, plus the value that got past the glob and the
        // shapes the ticket asks for: bracketed IPv6, no port at all, spaces.
        let table: &[(&str, bool)] = &[
            // --- loopback, must keep working -----------------------------
            ("127.0.0.1:873", true),
            ("127.0.0.1", true),
            ("127.0.0.2:873", true),
            ("[::1]:874", true),
            ("[::1]", true),
            ("::1", true),
            ("0:0:0:0:0:0:0:1", true),
            ("localhost:873", true),
            ("localhost", true),
            ("localhost.localdomain:873", true),
            ("  127.0.0.1:873  ", true),
            // --- the finding, and the family it belongs to ----------------
            ("127.0.0.1.evil.com:873", false),
            ("127.0.0.1.evil.com", false),
            ("localhost.evil.com:873", false),
            ("::1.evil.com", false),
            ("127.0.0.1@evil.com:873", false),
            ("127.0.0.1x:873", false),
            ("127.0.0.1.", false),
            // --- plain non-loopback --------------------------------------
            ("evil.com:873", false),
            ("rsyncd.internal:873", false),
            ("10.0.0.5:873", false),
            ("192.168.1.10:873", false),
            ("0.0.0.0:873", false),
            ("[2001:db8::1]:874", false),
            // --- malformed: refused rather than guessed at ----------------
            ("1270.0.0.1:873", false),
            ("127.0.0.256:873", false),
            ("127.0.0.1 evil.com:873", false),
            ("127.0.0.1:873:9999", false),
            ("127.0.0.1:abc", false),
            ("[::1]x:874", false),
            ("", false),
        ];

        let mut wrong = Vec::new();
        for (value, expected_loopback) in table {
            let out = Command::new("bash")
                .arg("-c")
                .arg(
                    "set -u; . \"$1\" >/dev/null 2>&1; \
                     if tls_backend_is_loopback \"$2\"; then echo loopback; else echo refused; fi",
                )
                .arg("bash")
                .arg(&script)
                .arg(value)
                .output()
                .expect("cannot run bash");
            assert!(
                out.status.success(),
                "the script could not be sourced for {value:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let verdict = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let got = match verdict.as_str() {
                "loopback" => true,
                "refused" => false,
                other => panic!("unexpected verdict {other:?} for {value:?}"),
            };
            if got != *expected_loopback {
                wrong.push(format!(
                    "{value:?}: expected {}, got {}",
                    if *expected_loopback {
                        "loopback"
                    } else {
                        "refused"
                    },
                    verdict
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "the backend check judged {} of {} values wrongly:\n  {}",
            wrong.len(),
            table.len(),
            wrong.join("\n  ")
        );

        // The counter-proof for the table itself: the broken pattern has to
        // come out the other way round on the value that found it. Without
        // this, the table above would still pass against a check hard-wired to
        // "refused" for everything, which would break every start.
        let out = Command::new("bash")
            .arg("-c")
            .arg("case \"$1\" in 127.*|::1|localhost) echo loopback ;; *) echo refused ;; esac")
            .arg("bash")
            .arg("127.0.0.1.evil.com")
            .output()
            .expect("cannot run bash");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "loopback",
            "the old glob does not accept the hostname any more, so this table \
             is no longer testing what it says it is"
        );
    }

    /// Every option *measured* to destroy content is on the refusal list.
    ///
    /// # The name of this test used to promise more than it delivered
    ///
    /// It was called `every_module_refuses_every_way_of_deleting`, and it read
    /// the constant — a string — so the only thing it could ever establish is
    /// which words are in a list. It said "every way", a tester went looking for
    /// the ways it did not name, and found `--force`: a peer with nothing but
    /// write access replaced a non-empty directory with a file and took
    /// `precious.txt` with it, exit 0, empty stderr, no `--delete` anywhere.
    ///
    /// A test that claims completeness it cannot check is worse than one that
    /// lists what was checked, because the claim is what stops the next person
    /// from looking. So the name now says what this is: the *ledger* of the
    /// options that were measured against a real daemon. The measuring itself
    /// happens in [`module_boundaries_on_the_real_daemon`], where every entry
    /// below is fired at a live module and the [`WeakDaemon`] counter-proof
    /// shows the same option destroying content when the refusal is absent.
    ///
    /// Adding a spelling here without measuring it first is the failure mode
    /// this comment exists to prevent: `remove-sent-files` looked redundant
    /// next to `remove-source-files` and was not — a push carrying the alias
    /// came back exit 0 on both versions.
    ///
    /// The exact spelling matters and is measured, not assumed: see the note on
    /// [`REFUSED_OPTIONS`]. A wildcard `delete*` lets `--delete-missing-args`
    /// through on both rsync 3.4.3 and 3.5.0, so the constant must carry the
    /// bare word — and must keep carrying it after somebody decides the list
    /// looks repetitive.
    #[test]
    fn every_module_refuses_the_options_measured_to_destroy_content() {
        let base = scratch("refuse-delete");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module_in(&share, true));
        let conf = cfg.render_conf().unwrap();

        let refused: Vec<&str> = REFUSED_OPTIONS.split_whitespace().collect();
        assert!(
            refused.contains(&"delete"),
            "the bare word \"delete\" is the only entry that also refuses \
             --delete-missing-args; measured on rsync 3.4.3 and 3.5.0"
        );
        assert!(
            !REFUSED_OPTIONS.contains('*'),
            "a wildcard entry replaces rsync's delete group refusal with a plain \
             name match and lets --delete-missing-args through: {REFUSED_OPTIONS}"
        );
        // The ledger. Every line names what the option did to a live module
        // when it was *not* refused; nothing is on the list on the strength of
        // the manual page alone.
        for (option, measured) in [
            (
                "remove-source-files",
                "empties the sender's directory, which is the share when the \
                 module is the sender; has no group",
            ),
            (
                "remove-sent-files",
                "deprecated alias of --remove-source-files that the refusal for \
                 the modern spelling does not cover: a push carrying it came \
                 back exit 0 on 3.5.0 and 3.4.3",
            ),
            (
                "force",
                "lets an incoming file replace a non-empty directory with no \
                 delete option present at all: exit 0, empty stderr, the file \
                 inside the directory gone, on 3.5.0 and 3.4.3",
            ),
        ] {
            assert!(
                refused.contains(&option),
                "--{option} is missing from the refusal list; measured: it {measured}"
            );
        }
        // A read-only module gets the same list; refusing deletes is not a
        // consequence of the write scope, it is unconditional until the scope
        // model knows `rsync:delete`.
        let mut ro = DaemonConfig::new("/etc/rsyncd/secrets");
        ro.add_module(module_in(&share, false));
        let ro_conf = ro.render_conf().unwrap();
        for section in [&conf, &ro_conf] {
            assert!(section.contains(&format!("    refuse options = {REFUSED_OPTIONS}\n")));
        }
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn secrets_file_is_written_with_mode_0600() {
        let base = scratch("modes");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let secrets = base.join("etc").join("secrets");
        let conf_path = base.join("etc").join("rsyncd.conf");

        let mut cfg = DaemonConfig::new(&secrets);
        cfg.add_module(module_in(&share, true));
        cfg.write(&conf_path).unwrap();

        for path in [&secrets, &conf_path] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} has mode {mode:04o}", path.display());
        }
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_pre_existing_world_readable_secrets_file_is_tightened() {
        let base = scratch("tighten");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let secrets = base.join("secrets");
        fs::write(&secrets, "stale\n").unwrap();
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o644)).unwrap();

        let mut cfg = DaemonConfig::new(&secrets);
        cfg.add_module(module_in(&share, true));
        cfg.write(&base.join("rsyncd.conf")).unwrap();

        let mode = fs::metadata(&secrets).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!fs::read_to_string(&secrets).unwrap().contains("stale"));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn the_secret_never_appears_in_the_configuration() {
        let base = scratch("nosecret");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let module = module_in(&share, true);
        let secret = module.secret().to_string();

        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module.clone());
        assert!(!cfg.render_conf().unwrap().contains(&secret));
        assert_eq!(
            cfg.render_secrets().unwrap(),
            format!("{}:{}\n", module.name(), secret)
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn secret_has_at_least_32_bytes_of_entropy_and_is_never_repeated() {
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let secret = generate_secret().unwrap();
            // hex encoded, so two characters per random byte
            assert_eq!(secret.len(), SECRET_BYTES * 2);
            assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(seen.insert(secret), "CSPRNG returned a duplicate secret");
        }
    }

    #[test]
    fn module_name_is_not_derivable_from_the_path() {
        let base = scratch("naming");
        let share = base.join("holiday-photos-2026");
        fs::create_dir_all(&share).unwrap();

        let mut names = HashSet::new();
        for _ in 0..32 {
            let module = module_in(&share, true);
            let name = module.name().to_string();
            // Nothing of the directory or its ancestors shows up in the name.
            for component in share.iter() {
                let component = component.to_string_lossy().to_lowercase();
                if component.len() > 2 {
                    assert!(
                        !name.contains(&component),
                        "module name {name} leaks the path component {component}"
                    );
                }
            }
            assert!(name.starts_with("pair"));
            assert_eq!(name.len(), "pair".len() + MODULE_NAME_RANDOM_BYTES * 2);
            // Same path, different name every time: the name is random, not a
            // hash of the directory.
            assert!(names.insert(name), "module name repeated for the same path");
        }
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_share_root_containing_a_newline_is_refused() {
        let base = scratch("injection");
        // A directory whose name carries a second directive. Legal on Linux.
        let evil = base.join("share\nread only = no\n[backdoor]\npath = /");
        fs::create_dir_all(&evil).unwrap();

        let err = ModuleConfig::new(&evil, false, 1001, 1001, 4)
            .expect_err("a share root with a line break must be refused");
        assert!(
            err.to_string().contains("control character"),
            "unexpected error: {err}"
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn injected_directives_are_refused_at_render_time_too() {
        let base = scratch("render-injection");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        // Simulates a value that got past construction, e.g. because a future
        // caller sets the field directly.
        let mut module = module_in(&share, false);
        module.path = format!("{}\nread only = no", module.path);
        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module);
        assert!(cfg.render_conf().is_err());

        // Same for a name that is not plain alphanumeric.
        let mut module = module_in(&share, false);
        module.name = "pair]\n[backdoor".to_string();
        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module);
        assert!(cfg.render_conf().is_err());
        assert!(cfg.render_secrets().is_err());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_secrets_file_inside_a_share_root_is_refused() {
        let base = scratch("inside");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let secrets = share.join("sub").join("secrets");

        let mut cfg = DaemonConfig::new(&secrets);
        cfg.add_module(module_in(&share, true));
        let err = cfg
            .write(&base.join("rsyncd.conf"))
            .expect_err("secrets inside a share root must be refused");
        assert!(err.to_string().contains("inside the share root"));
        assert!(
            !secrets.exists(),
            "the secrets file must not have been written"
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_symlinked_secrets_location_cannot_hide_inside_a_share_root() {
        let base = scratch("symlink");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let link = base.join("etc");
        std::os::unix::fs::symlink(&share, &link).unwrap();

        let mut cfg = DaemonConfig::new(link.join("secrets"));
        cfg.add_module(module_in(&share, true));
        assert!(cfg.write(&base.join("rsyncd.conf")).is_err());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn share_root_is_canonicalised_before_it_reaches_the_file() {
        let base = scratch("canonical");
        let real = base.join("real");
        fs::create_dir_all(real.join("sub")).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let module = module_in(&link.join("sub").join("..").join("sub"), true);
        let expected = fs::canonicalize(real.join("sub")).unwrap();
        assert_eq!(module.path(), expected.to_str().unwrap());
        assert!(!module.path().contains(".."));
        assert!(!module.path().contains("/link/"));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_missing_share_root_is_an_error_not_a_created_directory() {
        let base = scratch("missing");
        let share = base.join("does-not-exist");
        assert!(ModuleConfig::new(&share, true, 1001, 1001, 4).is_err());
        assert!(!share.exists());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn duplicate_module_names_and_zero_connections_are_refused() {
        let base = scratch("dupes");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        assert!(ModuleConfig::new(&share, true, 1001, 1001, 0).is_err());

        let module = module_in(&share, true);
        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(module.clone());
        cfg.add_module(module);
        assert!(cfg.render_conf().is_err());
        fs::remove_dir_all(&base).ok();
    }

    // -----------------------------------------------------------------
    // Runtime registry (ticket ae12dcd1)
    // -----------------------------------------------------------------

    /// `base/etc/rsyncd.conf` + `base/etc/secrets` plus a share directory.
    fn registry_in(base: &Path) -> ModuleRegistry {
        ModuleRegistry::new(
            base.join("etc").join("rsyncd.conf"),
            base.join("etc").join("secrets"),
        )
    }

    fn share(base: &Path, name: &str) -> PathBuf {
        let dir = base.join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_new_pairing_appears_in_both_files() {
        let base = scratch("registry-add");
        let mut reg = registry_in(&base);
        let module = reg
            .add_pairing(&share(&base, "a"), true, 1001, 1001, 4)
            .unwrap();

        let conf = fs::read_to_string(reg.conf_path()).unwrap();
        let secrets = fs::read_to_string(reg.config().secrets_file()).unwrap();
        assert!(conf.contains(&format!("[{}]", module.name())));
        assert!(secrets.contains(&format!("{}:{}\n", module.name(), module.secret())));
        // The secret is in exactly one of the two files.
        assert!(!conf.contains(module.secret()));
        assert!(reg.contains(module.name()));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_revoke_removes_the_module_and_its_secret_and_leaves_the_rest_alone() {
        let base = scratch("registry-revoke");
        let mut reg = registry_in(&base);
        let gone = reg
            .add_pairing(&share(&base, "a"), true, 1001, 1001, 4)
            .unwrap();
        let kept = reg
            .add_pairing(&share(&base, "b"), false, 1001, 1001, 4)
            .unwrap();

        assert!(reg.revoke(gone.name()).unwrap());

        let conf = fs::read_to_string(reg.conf_path()).unwrap();
        let secrets = fs::read_to_string(reg.config().secrets_file()).unwrap();
        assert!(!conf.contains(gone.name()));
        assert!(!secrets.contains(gone.name()));
        assert!(!secrets.contains(gone.secret()));
        // The other pairing keeps working, unchanged.
        assert!(conf.contains(&format!("[{}]", kept.name())));
        assert_eq!(secrets, format!("{}:{}\n", kept.name(), kept.secret()));
        assert!(!reg.contains(gone.name()));
        assert!(reg.contains(kept.name()));

        // A revoke that arrives twice is not an error.
        assert!(!reg.revoke(gone.name()).unwrap());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn both_files_are_replaced_by_rename_never_truncated_in_place() {
        let base = scratch("registry-atomic");
        let mut reg = registry_in(&base);
        let first = reg
            .add_pairing(&share(&base, "a"), true, 1001, 1001, 4)
            .unwrap();

        use std::os::unix::fs::MetadataExt as _;
        let inode = |p: &Path| fs::metadata(p).unwrap().ino();
        let conf_before = inode(reg.conf_path());
        let secrets_before = inode(reg.config().secrets_file());

        reg.add_pairing(&share(&base, "b"), true, 1001, 1001, 4)
            .unwrap();
        // A different inode is the signature of "written elsewhere, then
        // renamed over" — an in-place rewrite would keep it. That is what
        // makes a concurrent reader see either the whole old or the whole new
        // file, never a half-written one.
        assert_ne!(conf_before, inode(reg.conf_path()));
        assert_ne!(secrets_before, inode(reg.config().secrets_file()));

        reg.revoke(first.name()).unwrap();

        // And nothing is left lying around next to them.
        let leftovers: Vec<_> = fs::read_dir(base.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary files left behind: {leftovers:?}"
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_rejected_change_leaves_the_registry_and_the_files_untouched() {
        let base = scratch("registry-rollback");
        let mut reg = registry_in(&base);
        let kept = reg
            .add_pairing(&share(&base, "a"), true, 1001, 1001, 4)
            .unwrap();
        let conf_before = fs::read_to_string(reg.conf_path()).unwrap();
        let secrets_before = fs::read_to_string(reg.config().secrets_file()).unwrap();

        // A share root that contains the secrets file: refused, because the
        // peer could otherwise pull every secret through the module.
        let bad = base.join("etc");
        assert!(reg.add_pairing(&bad, true, 1001, 1001, 4).is_err());

        // A share root that does not exist at all.
        assert!(reg
            .add_pairing(&base.join("nope"), true, 1001, 1001, 4)
            .is_err());

        assert_eq!(reg.modules().len(), 1);
        assert!(reg.contains(kept.name()));
        assert_eq!(fs::read_to_string(reg.conf_path()).unwrap(), conf_before);
        assert_eq!(
            fs::read_to_string(reg.config().secrets_file()).unwrap(),
            secrets_before
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn the_registry_does_not_touch_disk_before_it_is_told_to() {
        let base = scratch("registry-lazy");
        let reg = registry_in(&base);
        // Constructing a registry over a daemon that is already running must
        // not wipe its modules.
        assert!(!reg.conf_path().exists());
        assert!(!reg.config().secrets_file().exists());
        assert!(reg.modules().is_empty());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn restored_modules_are_published_by_one_apply() {
        let base = scratch("registry-restore");
        let mut reg = registry_in(&base);
        let a = module_in(&share(&base, "a"), true);
        let b = module_in(&share(&base, "b"), false);
        reg.insert_module(a.clone()).unwrap();
        reg.insert_module(b.clone()).unwrap();
        // The same module twice would shadow a pairing in the file.
        assert!(reg.insert_module(a.clone()).is_err());

        reg.apply().unwrap();
        let conf = fs::read_to_string(reg.conf_path()).unwrap();
        assert!(conf.contains(&format!("[{}]", a.name())));
        assert!(conf.contains(&format!("[{}]", b.name())));
        assert_eq!(
            fs::metadata(reg.config().secrets_file())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn several_modules_are_rendered_in_order() {
        let base = scratch("multi");
        let a = base.join("a");
        let b = base.join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();

        let ma = module_in(&a, true);
        let mb = module_in(&b, false);
        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.add_module(ma.clone());
        cfg.add_module(mb.clone());

        let conf = cfg.render_conf().unwrap();
        let pos_a = conf.find(&format!("[{}]", ma.name())).unwrap();
        let pos_b = conf.find(&format!("[{}]", mb.name())).unwrap();
        assert!(pos_a < pos_b);

        let secrets = cfg.render_secrets().unwrap();
        assert_eq!(secrets.lines().count(), 2);
        assert!(secrets.starts_with(&format!("{}:", ma.name())));
        fs::remove_dir_all(&base).ok();
    }

    // -----------------------------------------------------------------------
    // Lifecycle (ticket 3ed12cdd)
    // -----------------------------------------------------------------------

    #[test]
    fn the_daemon_is_invoked_with_every_setting_that_was_measured_to_be_required() {
        let settings = DaemonSettings::new("/etc/rsyncd/rsyncd.conf", "/run/rsyncd");
        let argv = settings.argv();

        // Without --no-detach there is no child to wait on or signal.
        assert!(argv.contains(&"--no-detach".to_string()));
        // Without a lock file, *every* transfer fails with "failed to open
        // lock file" as soon as `max connections` is set, because the built-in
        // default /var/run/rsyncd.lock is not writable for us.
        assert!(argv
            .iter()
            .any(|a| a == "--dparam=lock file=/run/rsyncd/rsyncd.lock"));
        // The pid file is the "already running" lock.
        assert!(argv
            .iter()
            .any(|a| a == "--dparam=pid file=/run/rsyncd/rsyncd.pid"));
        // And emphatically **without** --log-file. The log path is real and
        // required — without it the daemon logs to syslog and there is nothing
        // to mirror — but it belongs in the configuration file: measured on
        // 3.5.0 and 3.4.3, the command line switch suppresses every per-file
        // audit line, and setting both splits the log across two files. See
        // `DaemonConfig::with_log_file`.
        assert!(!argv.iter().any(|a| a.starts_with("--log-file")));
        let mut cfg = DaemonConfig::new("/etc/rsyncd/secrets");
        cfg.set_log_file(settings.log_file());
        assert!(cfg
            .render_conf()
            .unwrap()
            .contains("\nlog file = /run/rsyncd/rsyncd.log\n"));
        assert!(argv.iter().any(|a| a == "--config=/etc/rsyncd/rsyncd.conf"));
        assert!(argv.iter().any(|a| a == &format!("--port={DAEMON_PORT}")));

        let probe = settings.with_port(18873).with_dparam("strict modes=no");
        let argv = probe.argv();
        assert!(argv.iter().any(|a| a == "--port=18873"));
        assert!(argv.iter().any(|a| a == "--dparam=strict modes=no"));
    }

    #[test]
    fn the_connection_table_is_built_from_the_lines_rsync_really_writes() {
        let open = "2026/08/15 18:47:59 [749342] rsync allowed access on module pair1a2b3c4d5e6f from localhost (127.0.0.1)";
        let close = "2026/08/15 18:48:04 [749342] sent 0 bytes  received 0 bytes  total size 0";
        let connect = "2026/08/15 18:47:59 [749342] connect from localhost (127.0.0.1)";

        assert_eq!(log_line_pid(open), Some(749342));
        assert_eq!(
            module_from_access_line(open).as_deref(),
            Some("pair1a2b3c4d5e6f")
        );
        assert!(is_connection_closed_line(close));

        // A plain connect line names no module and closes nothing.
        assert_eq!(module_from_access_line(connect), None);
        assert!(!is_connection_closed_line(connect));
        assert!(!is_connection_closed_line(open));

        // An error ends the child just as surely as a summary does.
        assert!(is_connection_closed_line(
            "2026/08/15 18:48:04 [749342] rsync error: requested action not supported (code 4)"
        ));
        // The startup line has a pid but is neither.
        let start =
            "2026/08/15 18:47:59 [749342] rsyncd version 3.4.3 starting, listening on port 873";
        assert_eq!(log_line_pid(start), Some(749342));
        assert_eq!(module_from_access_line(start), None);
        assert!(!is_connection_closed_line(start));
        // And a line without brackets does not panic.
        assert_eq!(log_line_pid("no brackets here"), None);
        assert_eq!(log_line_pid("[notanumber] x"), None);
    }

    #[test]
    fn a_failing_chroot_is_recognised_in_the_daemon_log() {
        // Both halves rsync writes when the process lacks CAP_SYS_CHROOT — the
        // shipped container runs as `appuser` and hits exactly this (ticket
        // 33eeb98c). Without this the only symptom is on the client side.
        assert!(is_chroot_failure_line(
            "2026/08/16 04:12:01 [42] chroot(\"/data/modA\") failed: Operation not permitted (1)"
        ));
        assert!(is_chroot_failure_line(
            "2026/08/16 04:12:01 [42] @ERROR: chroot failed"
        ));
        assert!(!is_chroot_failure_line(
            "2026/08/16 04:12:01 [42] rsync allowed access on module pair1a2b from localhost"
        ));
        assert!(!is_chroot_failure_line(
            "2026/08/16 04:12:01 [42] rsyncd version 3.4.3 starting, listening on port 873"
        ));
    }

    // -----------------------------------------------------------------------
    // Audit log (ticket 9f3d4888)
    //
    // Every literal below was copied out of a real daemon's log — 3.5.0 on the
    // host and 3.4.3 in alpine:3.22 — not out of the manual. That matters:
    // the previous attempt at reading this log assumed a closing line the
    // daemon does not write, and was wrong for all 40 of 40 connections.
    // -----------------------------------------------------------------------

    /// Drive a batch of log lines through the reader and return the events.
    async fn audit_from(lines: &[&str]) -> Vec<AuditEvent> {
        let state = Arc::new(TokioMutex::new(DaemonState {
            pid: Some(std::process::id()),
            ..DaemonState::default()
        }));
        // No file and no stunnel log: this exercises the parsing, and the
        // client column is asserted to be honestly empty as a result.
        let mut audit = AuditContext::new(AuditSink::new(None), None, DAEMON_PORT);
        for line in lines {
            handle_log_line(line, &state, &mut audit).await;
        }
        let state = state.lock().await;
        state.audit.iter().cloned().collect()
    }

    /// One complete session as the daemon really logs it.
    fn a_session() -> Vec<&'static str> {
        vec![
            "2026/08/16 07:37:44 [21] connect from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [21] rsync allowed access on module pair2ef0d77e70d831e0 from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [21] rsync to pair2ef0d77e70d831e0/ from pair2ef0d77e70d831e0@localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [21] receiving file list",
            "2026/08/16 07:37:44 [21] rclone-gui-audit 127.0.0.1 pair2ef0d77e70d831e0 pair2ef0d77e70d831e0 recv 62914560 62922276 urlaub 2026/bild 1.jpg",
            "2026/08/16 07:37:45 [21] sent 40 bytes  received 62930045 bytes  total size 62914560",
        ]
    }

    #[tokio::test]
    async fn a_module_access_is_recorded_with_module_user_time_and_operation() {
        let events = audit_from(&a_session()).await;

        let granted = events
            .iter()
            .find(|e| e.action == AuditAction::AccessGranted)
            .expect("the access must be in the audit log");
        assert_eq!(granted.at, "2026/08/16 07:37:44");
        assert_eq!(granted.module.as_deref(), Some("pair2ef0d77e70d831e0"));
        assert_eq!(granted.pid, 21);

        // The direction is the only statement about the client's options the
        // daemon ever makes: `rsync to` is a client that writes.
        let session = events
            .iter()
            .find(|e| e.action == AuditAction::SessionWrite)
            .expect("the direction must be recorded");
        assert_eq!(session.user.as_deref(), Some("pair2ef0d77e70d831e0"));

        // The per-file line, including a name with spaces and a slash — which
        // is why the file name is the last field of the format.
        let file = events
            .iter()
            .find(|e| e.action == AuditAction::FileReceived)
            .expect("the transferred file must be recorded");
        assert_eq!(file.path.as_deref(), Some("urlaub 2026/bild 1.jpg"));
        assert_eq!(file.size, Some(62914560));
        assert_eq!(file.module.as_deref(), Some("pair2ef0d77e70d831e0"));
        assert_eq!(file.user.as_deref(), Some("pair2ef0d77e70d831e0"));
        assert!(!file.destructive);

        assert!(events.iter().any(|e| e.action == AuditAction::SessionEnd));
    }

    #[tokio::test]
    async fn without_the_stunnel_log_the_client_column_is_empty_and_not_the_proxy() {
        let events = audit_from(&a_session()).await;
        // The daemon log says `127.0.0.1` on every one of these lines. That is
        // stunnel, not the peer, and writing it into the audit log would make
        // every client on earth look like it came from the loopback interface.
        for event in &events {
            assert_eq!(event.client, None, "{:?} carried a client address", event);
            assert_eq!(event.client_source, ClientAddressSource::Unavailable);
            let rendered = serde_json::to_string(event).unwrap();
            assert!(
                !rendered.contains("\"client\":\"127.0.0.1\""),
                "the proxy address must never be reported as the client: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn a_delete_attempt_is_marked_even_though_the_delete_itself_is_refused() {
        // Measured verbatim: with `refuse options` as shipped, this is the
        // *only* trace a deletion leaves, because there is no deletion. An
        // audit log that waited for a successful delete would show nothing at
        // all and look identical to a peer that never tried.
        let events = audit_from(&[
            "2026/08/16 07:37:44 [24] connect from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [24] rsync allowed access on module pairaaaa from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [24] rsync to pairaaaa/ from pairaaaa@localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [24] rsync: The server is configured to refuse --delete",
            "2026/08/16 07:37:44 [24] rsync error: requested action not supported (code 4) at clientserver.c(1185) [Receiver=3.4.3]",
        ])
        .await;

        let refused = events
            .iter()
            .find(|e| e.action == AuditAction::OptionRefused)
            .expect("a refused option must be recorded");
        assert_eq!(refused.refused_option.as_deref(), Some("delete"));
        assert!(refused.concerns_deletion());
        // Nothing was destroyed, so `destructive` stays false — the two
        // questions are kept apart on purpose.
        assert!(!refused.destructive);
        assert_eq!(refused.module.as_deref(), Some("pairaaaa"));
        assert_eq!(refused.user.as_deref(), Some("pairaaaa"));

        // The other way of destroying data through a pairing.
        let events = audit_from(&[
            "2026/08/16 07:37:44 [25] connect from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [25] rsync: The server is configured to refuse --remove-source-files",
        ])
        .await;
        let refused = events
            .iter()
            .find(|e| e.action == AuditAction::OptionRefused)
            .unwrap();
        assert_eq!(
            refused.refused_option.as_deref(),
            Some("remove-source-files")
        );
        assert!(refused.concerns_deletion());
    }

    #[tokio::test]
    async fn a_real_deletion_is_marked_destructive() {
        // Not reachable through a generated module today, because `delete` is
        // in `REFUSED_OPTIONS`. It becomes reachable the day `rsync:delete`
        // exists, and these are the lines rsync writes then — measured against
        // a module with the refusals removed, not guessed from the format
        // string. A deletion carries `0 0` for size and bytes, so the file name
        // still begins at the seventh field.
        let events = audit_from(&[
            "2026/08/16 07:37:44 [48] connect from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [48] rsync allowed access on module m1 from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [48] rclone-gui-audit 127.0.0.1 m1 m1 del. 0 0 victim.txt",
            "2026/08/16 07:37:44 [48] rclone-gui-audit 127.0.0.1 m1 m1 del. 0 0 mit leer zeichen.txt",
            "2026/08/16 07:37:44 [48] rclone-gui-audit 127.0.0.1 m1 m1 recv 6 46 a.txt",
        ])
        .await;
        let deleted: Vec<_> = events
            .iter()
            .filter(|e| e.action == AuditAction::FileDeleted)
            .collect();
        assert_eq!(deleted.len(), 2, "both deletions must be recorded");
        assert!(deleted.iter().all(|e| e.destructive));
        assert!(deleted.iter().all(|e| e.concerns_deletion()));
        assert_eq!(deleted[0].path.as_deref(), Some("victim.txt"));
        assert_eq!(deleted[1].path.as_deref(), Some("mit leer zeichen.txt"));
        // The write in the same session is not swept up as destructive.
        assert!(events
            .iter()
            .any(|e| e.action == AuditAction::FileReceived && !e.destructive));
    }

    #[tokio::test]
    async fn a_rejected_connection_is_recorded_too() {
        let events = audit_from(&[
            "2026/08/16 07:37:45 [93] connect from localhost (127.0.0.1)",
            "2026/08/16 07:37:45 [93] auth failed on module m1 from localhost (127.0.0.1) for m1: password mismatch",
            "2026/08/16 07:37:45 [94] connect from localhost (127.0.0.1)",
            "2026/08/16 07:37:45 [94] unknown module 'gibtsnicht' tried from localhost (127.0.0.1)",
        ])
        .await;
        let denied: Vec<_> = events
            .iter()
            .filter(|e| e.action == AuditAction::AccessDenied)
            .collect();
        assert_eq!(denied.len(), 2, "both refusals must be recorded");
        assert_eq!(denied[0].module.as_deref(), Some("m1"));
        assert_eq!(denied[0].user.as_deref(), Some("m1"));
    }

    #[tokio::test]
    async fn a_file_name_cannot_forge_an_audit_line() {
        // The sentinel sits in front of every field the client controls, so a
        // file called like a log line cannot inject one. The daemon writes the
        // name into the *last* field.
        let events = audit_from(&[
            "2026/08/16 07:37:44 [21] connect from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [21] rsync allowed access on module m1 from localhost (127.0.0.1)",
            "2026/08/16 07:37:44 [21] rclone-gui-audit 127.0.0.1 m1 m1 recv 6 6 rclone-gui-audit 9.9.9.9 root evil del. 0 0 boese.txt",
        ])
        .await;
        let file = events
            .iter()
            .find(|e| e.action == AuditAction::FileReceived)
            .expect("the file must be recorded as received, not as a deletion");
        assert!(!events.iter().any(|e| e.destructive));
        assert_eq!(file.module.as_deref(), Some("m1"));
        assert_eq!(
            file.path.as_deref(),
            Some("rclone-gui-audit 9.9.9.9 root evil del. 0 0 boese.txt")
        );
    }

    #[tokio::test]
    async fn the_daemons_own_shutdown_summary_is_not_a_session() {
        // `sent … received … total size …` is written twice: by each child at
        // the end of its transfer, and by the daemon itself when it stops. The
        // second one has the daemon's pid and no session — mistaking it for a
        // connection ending is exactly the error that produced 40 stale
        // entries out of 40 in an earlier attempt.
        let events =
            audit_from(&["2026/08/16 07:37:46 [18] sent 0 bytes  received 0 bytes  total size 0"])
                .await;
        assert!(events.is_empty(), "got {events:?}");
    }

    #[test]
    fn the_stunnel_log_is_read_for_the_peer_address() {
        // Copied from a real stunnel 5.75 at `debug = 5`. Both lines carry the
        // same thread id; the second names the port stunnel uses towards the
        // daemon, and that port is what makes the join exact.
        let accepted =
            "2026.08.16 05:44:45 LOG5[0]: Service [rsyncd-tls] accepted connection from 192.168.224.3:51840";
        let connected =
            "2026.08.16 05:44:45 LOG5[0]: Service [rsyncd-tls] connected remote server from 127.0.0.1:38790";

        assert_eq!(stunnel_thread_id(accepted).as_deref(), Some("0"));
        assert_eq!(
            stunnel_accepted_peer(accepted),
            Some(("192.168.224.3".to_string(), 51840))
        );
        assert_eq!(stunnel_backend_port(connected), Some(38790));
        // The "accepted" line must not be read as a backend port and vice
        // versa, or every address would be the loopback one again.
        assert_eq!(stunnel_backend_port(accepted), None);
        assert_eq!(stunnel_accepted_peer(connected), None);
        assert!(parse_stunnel_time(accepted).is_some());
        // stunnel's own startup chatter carries a non-numeric thread id and no
        // connection at all.
        let startup = "2026.08.16 05:44:44 LOG5[ui]: Configuration successful";
        assert_eq!(stunnel_thread_id(startup).as_deref(), Some("ui"));
        assert_eq!(stunnel_accepted_peer(startup), None);
    }

    #[test]
    fn the_two_logs_are_joined_over_the_port_and_only_then_over_the_time() {
        let mut index = StunnelIndex::new(PathBuf::from("/nonexistent"));
        for line in [
            "2026.08.16 05:44:45 LOG5[0]: Service [rsyncd-tls] accepted connection from 192.168.224.3:51840",
            "2026.08.16 05:44:45 LOG5[0]: Service [rsyncd-tls] connected remote server from 127.0.0.1:38790",
            "2026.08.16 05:44:45 LOG5[1]: Service [rsyncd-tls] accepted connection from 10.0.0.9:2222",
            "2026.08.16 05:44:45 LOG5[1]: Service [rsyncd-tls] connected remote server from 127.0.0.1:38791",
        ] {
            index.ingest(line);
        }

        let at = parse_rsync_time("2026/08/16 05:44:45 [21] connect from localhost (127.0.0.1)");
        // Two connections in the same second: only the port tells them apart,
        // and it does so exactly. This is the case `max connections = 4` makes
        // ordinary and that a time-only match would get wrong half the time.
        assert_eq!(
            index.lookup(Some(38791), at),
            Some((
                "10.0.0.9".to_string(),
                2222,
                ClientAddressSource::StunnelPort
            ))
        );
        // Without a port the newest unclaimed entry within the window wins,
        // and it is labelled as the weaker match it is.
        let (peer, _, source) = index.lookup(None, at).expect("a time match");
        assert_eq!(peer, "192.168.224.3");
        assert_eq!(source, ClientAddressSource::StunnelTime);
        // Claimed entries are not handed out twice by the time path.
        assert_eq!(index.lookup(None, at), None);
        // A connection from long before the window is not adopted.
        let much_later =
            parse_rsync_time("2026/08/16 06:44:45 [21] connect from localhost (127.0.0.1)");
        assert_eq!(index.lookup(None, much_later), None);
    }

    #[test]
    fn a_stunnel_log_on_another_timezone_is_still_matched() {
        // The constellation that made a reviewer reject 88b8c455 by mistake:
        // stunnel in a container on TZ=UTC, the application (and therefore the
        // daemon, its child) two hours ahead on CEST. The stunnel lines then
        // read 03:44:45 for a connection the daemon logs at 05:44:45.
        let mut index = StunnelIndex::new(PathBuf::from("/nonexistent"));
        let lines = [
            "2026.08.16 03:44:45 LOG5[0]: Service [rsyncd-tls] accepted connection from 192.168.224.3:51840",
        ];
        // What refresh() does with a chunk that has just appeared: the line was
        // read at 05:44:45 local, half a second after it was written.
        let seen_at = parse_rsync_time("2026/08/16 05:44:45 x").expect("a time");
        for line in lines {
            index.observe_clock(parse_stunnel_time(line), seen_at);
            index.ingest(line);
        }
        assert_eq!(index.clock_shift().num_seconds(), 7200);

        let at = parse_rsync_time("2026/08/16 05:44:45 [21] connect from localhost (127.0.0.1)");
        let (peer, port, source) = index
            .lookup(None, at)
            .expect("the peer must be found across the zone difference");
        assert_eq!(peer, "192.168.224.3");
        assert_eq!(port, 51840);
        assert_eq!(source, ClientAddressSource::StunnelTime);
    }

    #[test]
    fn the_clock_estimate_ignores_old_lines_and_ordinary_delay() {
        let mut index = StunnelIndex::new(PathBuf::from("/nonexistent"));
        let fresh = parse_stunnel_time("2026.08.16 05:44:45 LOG5[0]: x");
        let stale = parse_stunnel_time("2026.08.16 04:10:00 LOG5[0]: x");
        let seen_at = parse_rsync_time("2026/08/16 05:44:47 x").expect("a time");
        // The bulk read of an existing file delivers old lines first. They only
        // ever produce a too-large delta and must not become the estimate.
        index.observe_clock(stale, seen_at);
        index.observe_clock(fresh, seen_at);
        // Two seconds of reading lag on the same clock stay a shift of zero,
        // so nothing changes for the ordinary single-host case.
        assert_eq!(index.clock_shift().num_seconds(), 0);
        assert_eq!(index.skew.map(|d| d.num_seconds()), Some(2));

        // A clock that is ahead of ours is corrected the other way.
        let mut ahead = StunnelIndex::new(PathBuf::from("/nonexistent"));
        ahead.observe_clock(
            parse_stunnel_time("2026.08.16 06:44:45 LOG5[0]: x"),
            seen_at,
        );
        assert_eq!(ahead.clock_shift().num_seconds(), -3600);

        // No line seen at all: no correction, and no panic.
        let untouched = StunnelIndex::new(PathBuf::from("/nonexistent"));
        assert!(untouched.clock_shift().is_zero());
    }

    #[test]
    fn the_audit_file_is_json_lines_with_mode_0600() {
        let base = scratch("audit-9f3d4888");
        fs::create_dir_all(&base).unwrap();
        let path = base.join("audit.log");
        let mut sink = AuditSink::new(Some(path.clone()));
        let event = AuditEvent {
            at: "2026/08/16 07:37:44".to_string(),
            pid: 21,
            module: Some("pairaaaa".to_string()),
            user: Some("pairaaaa".to_string()),
            client: Some("192.168.224.3".to_string()),
            client_port: Some(51840),
            client_source: ClientAddressSource::StunnelPort,
            action: AuditAction::FileReceived,
            destructive: false,
            path: Some("bild.jpg".to_string()),
            size: Some(6),
            refused_option: None,
            detail: "rclone-gui-audit …".to_string(),
        };
        sink.record(&event);
        sink.record(&event);

        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written.lines().count(), 2, "one JSON object per line");
        let parsed: serde_json::Value = serde_json::from_str(written.lines().next().unwrap())
            .expect("every line must be valid JSON on its own");
        assert_eq!(parsed["module"], "pairaaaa");
        assert_eq!(parsed["client"], "192.168.224.3");
        assert_eq!(parsed["client_source"], "stunnel_port");
        assert_eq!(parsed["action"], "file_received");
        // The audit log names who connected from where; it is not world
        // readable, for the same reason the secrets file is not.
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, FILE_MODE, "audit log mode is {mode:o}");
        fs::remove_dir_all(&base).ok();
    }

    /// The one failure mode that would make this audit log worse than none.
    ///
    /// A log that records who accessed what is useful; a log that records the
    /// credential alongside it hands an attacker every pairing at once, in a
    /// file that exists precisely so it can be read later. So: drive a full
    /// session for a *real* module through the reader, with the sink writing to
    /// disk, and assert the secret is in none of it — not in an event, not in
    /// the serialised JSON, not in the file, and not in a `Debug` rendering of
    /// the configuration that holds it.
    #[tokio::test]
    async fn the_module_secret_reaches_neither_the_audit_log_nor_a_debug_rendering() {
        let base = scratch("audit-secret-9f3d4888");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();
        let module = module_in(&share, true);
        let name = module.name().to_string();
        let secret = module.secret().to_string();
        assert!(!secret.is_empty());

        let audit_path = base.join("audit.log");
        let state = Arc::new(TokioMutex::new(DaemonState {
            pid: Some(std::process::id()),
            ..DaemonState::default()
        }));
        let mut audit =
            AuditContext::new(AuditSink::new(Some(audit_path.clone())), None, DAEMON_PORT);
        // A whole session for this module, including the failed-auth line —
        // the one place where a daemon could conceivably echo a credential.
        for line in [
            "2026/08/16 07:37:44 [21] connect from localhost (127.0.0.1)".to_string(),
            format!(
                "2026/08/16 07:37:44 [21] auth failed on module {name} from localhost (127.0.0.1) for {name}: password mismatch"
            ),
            format!(
                "2026/08/16 07:37:44 [21] rsync allowed access on module {name} from localhost (127.0.0.1)"
            ),
            format!(
                "2026/08/16 07:37:44 [21] rsync to {name}/ from {name}@localhost (127.0.0.1)"
            ),
            format!("2026/08/16 07:37:44 [21] rclone-gui-audit 127.0.0.1 {name} {name} recv 6 6 a.txt"),
            "2026/08/16 07:37:45 [21] sent 40 bytes  received 62 bytes  total size 6".to_string(),
        ] {
            handle_log_line(&line, &state, &mut audit).await;
        }

        let events: Vec<AuditEvent> = state.lock().await.audit.iter().cloned().collect();
        assert!(
            !events.is_empty(),
            "the session must have produced audit events at all"
        );
        // The access is attributable: module and peer-source are on record.
        assert!(events
            .iter()
            .any(|e| e.module.as_deref() == Some(name.as_str())));
        for event in &events {
            let rendered = serde_json::to_string(event).unwrap();
            assert!(
                !rendered.contains(&secret),
                "the module secret leaked into an audit event: {rendered}"
            );
            assert!(
                !format!("{event:?}").contains(&secret),
                "the module secret leaked into an audit event's Debug output"
            );
        }

        let written = fs::read_to_string(&audit_path).unwrap();
        assert!(!written.is_empty(), "the audit file must have been written");
        assert!(
            !written.contains(&secret),
            "the module secret leaked into the audit file on disk"
        );

        // And the derive that would have leaked it: `ModuleConfig` redacts, and
        // `DaemonConfig` inherits that through it.
        let mut cfg = DaemonConfig::new(base.join("secrets"));
        cfg.add_module(module);
        assert!(!format!("{cfg:?}").contains(&secret));
        assert!(format!("{cfg:?}").contains("<redacted>"));

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_temp_file_name_is_not_evidence_and_is_not_used_as_such() {
        // What rsync writes by default: `.` + destination name + `.` + six
        // characters. The helper recognises it...
        for name in [
            ".big.bin.aB3xZ9",
            ".f.txt.abcdef",
            ".x.000000",
            ".a.b.c.QQQQQQ",
        ] {
            assert!(is_rsync_temp_name(name), "{name} is rsync's shape");
        }
        // ...and so does it for these, which are ordinary user files. That is
        // the whole point: the shape proves nothing. A sweep built on it
        // deleted four user files for every real leftover, which is why
        // `sweep_module_temp_dirs` does not consult this function at all.
        for name in [
            ".ssh.config",
            ".env.docker",
            ".bashrc.backup",
            ".htaccess.backup",
            ".gitlab.config",
            ".npmrc.backup",
        ] {
            assert!(
                is_rsync_temp_name(name),
                "{name} is indistinguishable by name — that is the finding"
            );
        }
    }

    /// The literal proof this ticket asks for: a share with real user files
    /// and one real rsync temp file, swept — only the temp file may be gone.
    ///
    /// The six names below are the ones a tester lost out of a share. Every one
    /// of them is `.` + name + `.` + six alphanumeric characters, which is also
    /// what rsync's temp files look like, which is why the sweep no longer
    /// looks at names at all.
    #[test]
    fn the_sweep_removes_the_temp_file_and_nothing_else() {
        let base = scratch("sweep-share-root");
        let share = base.join("share");
        fs::create_dir_all(share.join("sub")).unwrap();

        let user_files: Vec<PathBuf> = [
            ".ssh.config",
            ".env.docker",
            ".bashrc.backup",
            ".htaccess.backup",
            ".gitlab.config",
            ".npmrc.backup",
            "big.bin",
        ]
        .iter()
        .map(|n| share.join(n))
        .collect();
        // A name that really is rsync's, but in the share root. It is not swept
        // either: there is no way to tell it apart from the six above, and an
        // unreclaimed megabyte is cheaper than a lost file.
        let looks_like_rsync = share.join("sub").join(".big.bin.aB3xZ9");
        for path in user_files.iter().chain(std::iter::once(&looks_like_rsync)) {
            fs::write(path, vec![b'x'; 1024]).unwrap();
        }

        // The real one, where the daemon is configured to put it.
        let temp_dir = share.join(MODULE_TEMP_DIR);
        fs::create_dir_all(&temp_dir).unwrap();
        let orphan = temp_dir.join("big.bin.DoPFFG");
        fs::write(&orphan, vec![b'x'; 4096]).unwrap();

        let reclaimed = sweep_module_temp_dirs(std::slice::from_ref(&temp_dir), Duration::ZERO);

        assert_eq!(reclaimed, 4096, "only the real temp file was reclaimed");
        assert!(!orphan.exists(), "the orphaned partial must be gone");
        for path in &user_files {
            assert!(path.exists(), "the sweep deleted {}", path.display());
        }
        assert!(
            looks_like_rsync.exists(),
            "in a share root even an rsync-shaped name survives"
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn the_sweep_empties_the_temp_directory_and_respects_the_minimum_age() {
        let base = scratch("sweep-temp-dir");
        let share = base.join("share");
        let temp_dir = share.join(MODULE_TEMP_DIR);
        fs::create_dir_all(&temp_dir).unwrap();

        // Whatever is in here was put there by the daemon, so the name does not
        // matter — including a name that no heuristic would ever have matched.
        let orphan = temp_dir.join("big.bin.DoPFFG");
        let odd_name = temp_dir.join("plain-name");
        for path in [&orphan, &odd_name] {
            fs::write(path, vec![b'x'; 1024]).unwrap();
        }
        let neighbour = share.join("keep-me.txt");
        fs::write(&neighbour, "keep\n").unwrap();

        // A file younger than the minimum age belongs to a transfer that may
        // still be running under another instance's daemon.
        let reclaimed =
            sweep_module_temp_dirs(std::slice::from_ref(&temp_dir), Duration::from_secs(3600));
        assert_eq!(reclaimed, 0, "nothing is old enough yet");
        assert!(orphan.exists());

        let reclaimed = sweep_module_temp_dirs(std::slice::from_ref(&temp_dir), Duration::ZERO);
        assert_eq!(reclaimed, 2 * 1024, "the temp directory is emptied");
        assert!(!orphan.exists());
        assert!(!odd_name.exists());
        assert!(temp_dir.is_dir(), "the directory itself has to stay");
        assert!(neighbour.exists(), "nothing outside the temp directory");
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_writable_module_gets_a_temp_directory_and_a_read_only_one_does_not() {
        let base = scratch("temp-dir-render");
        let share = base.join("share");
        fs::create_dir_all(&share).unwrap();

        let writable = ModuleConfig::new(&share, true, 1000, 1000, 4).unwrap();
        let read_only = ModuleConfig::new(&share, false, 1000, 1000, 4).unwrap();

        let rendered = writable
            .render("/etc/rsyncd/secrets", Hardening::Full)
            .unwrap();
        assert!(
            rendered.contains(&format!("temp dir = /{MODULE_TEMP_DIR}")),
            "a writable module must keep its temp files out of the share root: {rendered}"
        );
        // Measured on 3.4.3 and 3.5.0: the value is resolved against the module
        // root in both chroot modes, so it is a leading slash and no path.
        assert!(!rendered.contains(&format!("temp dir = {}", share.display())));
        assert!(
            !read_only
                .render("/etc/rsyncd/secrets", Hardening::Full)
                .unwrap()
                .contains("temp dir"),
            "a read-only module never receives a file and needs no temp directory"
        );

        assert_eq!(writable.temp_dir(), Some(share.join(MODULE_TEMP_DIR)));
        assert_eq!(read_only.temp_dir(), None);

        // Writing the configuration creates the directory, because a module is
        // usable with the next connection and would otherwise fail it.
        let mut config = DaemonConfig::new(base.join("secrets"));
        config.add_module(writable);
        config.add_module(read_only);
        config.write(&base.join("rsyncd.conf")).unwrap();
        assert!(share.join(MODULE_TEMP_DIR).is_dir());
        assert_eq!(config.temp_dirs().len(), 1, "only the writable module");
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn the_restart_delay_backs_off_and_is_capped() {
        assert_eq!(restart_backoff(0), RESTART_BACKOFF_MIN);
        assert_eq!(restart_backoff(1), RESTART_BACKOFF_MIN * 2);
        assert_eq!(restart_backoff(2), RESTART_BACKOFF_MIN * 4);
        // No overflow, no runaway: a daemon that cannot start is retried at the
        // cap forever rather than in a tight loop.
        assert_eq!(restart_backoff(30), RESTART_BACKOFF_MAX);
        assert_eq!(restart_backoff(u32::MAX), RESTART_BACKOFF_MAX);
    }

    #[test]
    fn a_process_is_only_signalled_when_proc_agrees_it_is_a_child() {
        let me = std::process::id();
        // This process is not its own child, and a pid that cannot exist is
        // nobody's child. Both answers have to be "no" — the check guards a
        // SIGTERM to a possibly reused pid.
        assert!(!is_child_of(me, me));
        assert!(!is_child_of(u32::MAX, me));
        assert_eq!(count_zombie_children(u32::MAX), 0);
    }

    // -----------------------------------------------------------------------
    // Start-up: readiness and a blocked pid file (tickets e3e971ee, f581f435)
    // -----------------------------------------------------------------------

    #[test]
    fn the_lock_holder_is_read_out_of_proc_locks_by_device_and_inode() {
        // Real shape, including a waiter line (`->`) and a foreign file. The
        // waiter does not hold anything and must never be reported as the
        // blocker; the columns before the device triple differ per lock type,
        // which is why the pid is taken from in front of the triple.
        let locks = "\
1: POSIX  ADVISORY  WRITE 411 08:03:1310721 0 EOF
2: FLOCK  ADVISORY  WRITE 4242 08:03:1310722 0 EOF
2: -> FLOCK  ADVISORY  WRITE 4243 08:03:1310722 0 EOF
3: FLOCK  ADVISORY  WRITE 99 fd:00:22 0 EOF
";
        let dev = 0x0803_u64;
        assert_eq!(flock_holder(locks, dev, 1310722), Some(4242));
        assert_eq!(flock_holder(locks, dev, 1310721), Some(411));
        // Same inode on a different device is a different file.
        assert_eq!(flock_holder(locks, 0xfd00, 1310722), None);
        assert_eq!(flock_holder(locks, dev, 999), None);
    }

    #[test]
    fn the_device_numbers_are_encoded_the_way_proc_locks_prints_them() {
        // st_dev for major 8, minor 3 — the usual sda3.
        let dev = (8u64 << 8) | 3;
        assert_eq!(dev_major(dev), 8);
        assert_eq!(dev_minor(dev), 3);
    }

    #[test]
    fn a_pid_file_nobody_holds_does_not_block_a_start() {
        let base = scratch("free-pid-file");
        let pid_file = base.join("rsyncd.pid");
        // Not there at all.
        assert_eq!(pid_file_holder(&pid_file), None);
        assert_eq!(pid_file_blocker(&pid_file), None);
        // There, but nothing locks it, and its content names a pid that cannot
        // exist: a leftover from a daemon that was killed. The kernel dropped
        // the lock with the process, so this must not read as "running".
        fs::write(&pid_file, format!("{}\n", u32::MAX)).unwrap();
        assert_eq!(pid_file_holder(&pid_file), None);
        assert_eq!(pid_file_blocker(&pid_file), None);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn a_live_process_named_in_the_pid_file_is_reported_with_its_command() {
        let base = scratch("stale-pid-file");
        let pid_file = base.join("rsyncd.pid");
        // The fallback path: the lock could not be attributed, but the file
        // names a process that is still there — this one.
        fs::write(&pid_file, format!("{}\n", std::process::id())).unwrap();
        let holder = pid_file_blocker(&pid_file).expect("a live pid must be reported");
        assert_eq!(holder.pid, Some(std::process::id()));
        assert!(holder
            .to_string()
            .contains(&format!("pid {}", std::process::id())));
        assert!(
            holder.command.is_some(),
            "the command line belongs in the message"
        );
        fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn a_daemon_that_cannot_be_spawned_fails_at_once_instead_of_after_the_timeout() {
        // The measurement behind the ticket: with the old log-line wait a
        // missing rsync binary delayed the whole application by the full 30
        // seconds, because nothing was watching the child. It has to be over
        // in well under a second now.
        let base = scratch("no-binary");
        let conf = base.join("rsyncd.conf");
        let registry = Arc::new(TokioMutex::new(ModuleRegistry::new(
            &conf,
            base.join("secrets"),
        )));
        let settings = DaemonSettings::new(&conf, base.join("run"))
            .with_binary(base.join("no-such-rsync"))
            .with_port(free_port())
            .without_stunnel_log()
            .without_audit_file();

        let started = std::time::Instant::now();
        let error = match DaemonHandle::start(settings, registry).await {
            Err(e) => e,
            Ok(_) => panic!("a daemon whose binary does not exist cannot start"),
        };
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "a failed start took {elapsed:?}; it must not sit out the {}s timeout",
            LISTEN_TIMEOUT.as_secs()
        );
        let message = error.to_string();
        assert!(
            message.contains("did not survive its start"),
            "the cause has to be in the message: {message}"
        );
        assert!(
            message.contains("is rsync installed"),
            "the underlying spawn error has to be in the message: {message}"
        );
        fs::remove_dir_all(&base).ok();
    }

    /// A start that fails *after* the spawn must not leave the daemon behind.
    ///
    /// # The state this is about
    ///
    /// `wait_until_listening` used to be called with a bare `?`, so a daemon
    /// that came up but never answered on its port was abandoned alive. **There
    /// is no such thing as an orphaned `flock`** — the kernel releases it with
    /// the process — so the abandoned daemon keeps the pid file lock, and every
    /// later start dies with `failed to lock pid file: Resource temporarily
    /// unavailable`, naming a process the application no longer knows about.
    ///
    /// # Why a stub and not rsync
    ///
    /// The ticket's reproduction was `--dparam=address=::`, which
    /// [`DaemonSettings::check_listen_is_not_overridden`] now refuses *before*
    /// the spawn — so it cannot produce this state any more, and a test built on
    /// it would be green for the wrong reason. What matters is the shape, not
    /// the trigger: a child that spawns successfully, lives, holds the pid file
    /// lock and never binds the port. A five-line shell script is that shape
    /// exactly, and it is the same trick the rest of this file uses for the
    /// missing-binary case (`with_binary`).
    ///
    /// The stub takes a real `flock` on the pid file, because without it the
    /// second half of this test — an immediate restart must work — could not
    /// fail even with the bug present.
    #[tokio::test]
    async fn a_start_that_fails_after_the_spawn_leaves_no_daemon_behind() {
        use std::process::Command;
        /// `/proc/<pid>` is the whole check; the probe module has the same
        /// one-liner but is not in scope from here.
        fn stub_alive(pid: u32) -> bool {
            Path::new(&format!("/proc/{pid}")).exists()
        }
        let base = scratch("listen-timeout-leak");
        let run_dir = base.join("run");
        fs::create_dir_all(&run_dir).unwrap();
        let conf = base.join("rsyncd.conf");

        // The stub cannot read its paths from `argv`: it is invoked with the
        // daemon's own argument vector. They are baked into the script instead.
        let pid_echo = base.join("stub.pid");
        let stub = base.join("stub-daemon.sh");
        fs::write(
            &stub,
            format!(
                "#!/bin/sh\n\
                 # A daemon that starts, lives and never listens.\n\
                 echo $$ > {pid_echo}\n\
                 exec 9>{pid_file}\n\
                 flock -x 9 || exit 1\n\
                 trap 'exit 0' TERM\n\
                 while :; do sleep 0.1; done\n",
                pid_echo = pid_echo.display(),
                pid_file = run_dir.join("rsyncd.pid").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

        if Command::new("sh")
            .args(["-c", "command -v flock >/dev/null"])
            .status()
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            // Announced, never silent: a skipped test that says nothing is a
            // test that has stopped existing.
            eprintln!(
                "SKIPPED a_start_that_fails_after_the_spawn_leaves_no_daemon_behind: \
                 flock(1) is not installed, so the pid file lock cannot be held by a stub"
            );
            fs::remove_dir_all(&base).ok();
            return;
        }

        let settings = || {
            DaemonSettings::new(&conf, &run_dir)
                .with_binary(&stub)
                .with_port(free_port())
                .with_listen_timeout(Duration::from_millis(400))
                .without_stunnel_log()
                .without_audit_file()
                .without_temp_file_sweep()
        };
        let registry = || {
            Arc::new(TokioMutex::new(ModuleRegistry::new(
                &conf,
                base.join("secrets"),
            )))
        };

        let error = match DaemonHandle::start(settings(), registry()).await {
            Err(e) => e,
            Ok(_) => panic!("a daemon that never listens cannot start successfully"),
        };
        assert!(
            error.to_string().contains("did not accept a connection"),
            "the failure has to be the listen timeout, not something else: {error}"
        );

        // 1. The stub is gone. Measured against the process, not assumed from
        //    the fact that `start` returned.
        let stub_pid: u32 = fs::read_to_string(&pid_echo)
            .expect("the stub must have written its pid")
            .trim()
            .parse()
            .expect("the stub pid");
        let mut alive_for = Duration::ZERO;
        while stub_alive(stub_pid) && alive_for < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            alive_for += Duration::from_millis(50);
        }
        assert!(
            !stub_alive(stub_pid),
            "the daemon (pid {stub_pid}) is still running {alive_for:?} after a failed \
             start; it holds the pid file lock and blocks every later start"
        );

        // 1b. And the supervisor stopped with it — no restart in the
        //     background. This is the link to ticket cea66259 ("the restart runs
        //     in an endless loop"): the loop had no way out because nothing ever
        //     set `stopping` after a failed start, so the abandoned supervisor
        //     kept respawning and logging `restarting` for as long as the
        //     process lived. If a new stub appeared here, that loop is back.
        let after_failure = fs::read_to_string(&pid_echo).unwrap_or_default();
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(
            fs::read_to_string(&pid_echo).unwrap_or_default(),
            after_failure,
            "a new daemon was spawned after the failed start; the supervisor is still \
             looping (ticket cea66259)"
        );
        assert!(
            !stub_alive(stub_pid),
            "the daemon came back after the failed start"
        );

        // 2. Nobody holds the pid file any more, so the next start is not
        //    refused for the wrong reason.
        let holder = pid_file_holder(&run_dir.join("rsyncd.pid"));
        assert!(
            holder.is_none(),
            "the pid file is still locked after a failed start: {holder:?}"
        );

        // 3. An immediate second start reaches the same honest failure instead
        //    of the lock error. This is the half the operator feels.
        let _ = fs::remove_file(&pid_echo);
        let second = match DaemonHandle::start(settings(), registry()).await {
            Err(e) => e,
            Ok(_) => panic!("the stub cannot start successfully the second time either"),
        };
        let message = second.to_string();
        assert!(
            !message.contains("holds the pid file lock"),
            "the second start was blocked by the first one's leftovers: {message}"
        );
        assert!(
            message.contains("did not accept a connection"),
            "the second start failed for an unexpected reason: {message}"
        );
        if let Ok(pid) = fs::read_to_string(&pid_echo) {
            if let Ok(pid) = pid.trim().parse::<u32>() {
                let mut waited = Duration::ZERO;
                while stub_alive(pid) && waited < Duration::from_secs(5) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    waited += Duration::from_millis(50);
                }
                assert!(
                    !stub_alive(pid),
                    "the second failed start left pid {pid} behind as well"
                );
            }
        }

        fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn readiness_is_a_connection_and_not_a_log_line() {
        // The old wait read the daemon's log file, which rsync writes *before*
        // it binds — a wait that returns while nothing listens is exactly the
        // bug. Here nothing ever writes a log line at all, and the wait still
        // has to succeed, but not one moment before the port answers.
        let base = scratch("connect-readiness");
        let conf = base.join("rsyncd.conf");
        let port = free_port();
        let registry = Arc::new(TokioMutex::new(ModuleRegistry::new(
            &conf,
            base.join("secrets"),
        )));
        let settings = DaemonSettings::new(&conf, base.join("run"))
            .with_port(port)
            .without_stunnel_log()
            .without_audit_file();

        // Bind after a delay, from outside: the wait must not return before.
        let opened = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            tokio::net::TcpListener::bind(format!("{DAEMON_ADDRESS}:{port}"))
                .await
                .expect("the stand-in listener")
        });

        let started = std::time::Instant::now();
        // What is under test is the wait itself, so it runs on a handle that
        // supervises nothing: no process, no log, only the socket.
        let handle = DaemonHandle {
            settings,
            registry,
            state: Arc::new(TokioMutex::new(DaemonState::default())),
            stopping: Arc::new(AtomicBool::new(false)),
            supervisor: TokioMutex::new(None),
            watchdog: TokioMutex::new(None),
        };
        handle
            .wait_until_listening()
            .await
            .expect("the wait must return once the port answers");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(250),
            "the wait returned after {elapsed:?}, before anything was listening"
        );
        let _listener = opened.await.expect("the listener task");
        fs::remove_dir_all(&base).ok();
    }

    /// A foreign daemon answering on the port must not bless our start.
    ///
    /// # The state this is about (ticket 466dc997)
    ///
    /// `wait_until_listening` proved readiness with a TCP connect, which is the
    /// right question with the wrong subject: in step 6 of
    /// `daemon_lifecycle_on_the_host_rsync` a *second* handle starts against a
    /// run directory whose daemon is already running, and the connect reaches
    /// that first daemon. The start then reports success and the refusal in
    /// `run_once` never gets to speak. It was a race between the two, measured
    /// three times out of three as lost — and once, earlier, as won, which is
    /// how it got written off as a flaky test.
    ///
    /// # Why the stranger is a stub and not a second rsync
    ///
    /// The property under test is "somebody else holds the port and the lock",
    /// and nothing about it needs the rsync protocol. A listener opened in this
    /// test plus a five-line script holding a real `flock` reproduce that state
    /// exactly, deterministically, and without a port rsync could bind to here
    /// (873 is not bindable for an unprivileged process on this host). The same
    /// reasoning as in `a_start_that_fails_after_the_spawn_leaves_no_daemon_behind`.
    ///
    /// The second half is the counter-check that matters just as much: with the
    /// *same* socket and the *same* lock, but the lock held by the pid this
    /// handle calls its own, the wait has to succeed. Without it the riegel
    /// could be "never return Ok" and still pass.
    /// # Status (Ticket 466dc997 behoben)
    ///
    /// Der Test lief unter `#[ignore]`, weil er vor dem Fix geschrieben wurde.
    /// Der Fix ist da: `wait_until_listening` verlangt zum TCP-Connect zusaetzlich,
    /// dass die PID-Datei **nicht** von einem Fremden gehalten wird
    /// (`pid_file_is_held_by_a_stranger`). Das Attribut ist entfernt; der Test ist
    /// jetzt der Waechter darueber, dass die Bereitschaft am eigenen Kind haengt und
    /// nicht am Port.
    #[tokio::test]
    async fn a_stranger_on_the_port_cannot_bless_our_start() {
        use std::process::Command;
        let base = scratch("466dc997-stranger");
        let run_dir = base.join("run");
        fs::create_dir_all(&run_dir).unwrap();
        let conf = base.join("rsyncd.conf");
        let pid_file = run_dir.join("rsyncd.pid");
        let pid_echo = base.join("stranger.pid");
        let port = free_port();

        let stub = base.join("stranger.sh");
        fs::write(
            &stub,
            format!(
                "#!/bin/sh\n\
                 # Somebody else's daemon: holds the pid file lock, never dies.\n\
                 echo $$ > {pid_echo}\n\
                 exec 9>{pid_file}\n\
                 flock -x 9 || exit 1\n\
                 trap 'exit 0' TERM\n\
                 while :; do sleep 0.1; done\n",
                pid_echo = pid_echo.display(),
                pid_file = pid_file.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

        if Command::new("sh")
            .args(["-c", "command -v flock >/dev/null"])
            .status()
            .map(|s| !s.success())
            .unwrap_or(true)
        {
            // Announced, never silent.
            eprintln!(
                "SKIPPED a_stranger_on_the_port_cannot_bless_our_start: flock(1) is not \
                 installed, so a foreign pid file lock cannot be held by a stub"
            );
            fs::remove_dir_all(&base).ok();
            return;
        }

        // The stranger's socket. Answering on the port is all it has to do.
        let _listener = tokio::net::TcpListener::bind(format!("{DAEMON_ADDRESS}:{port}"))
            .await
            .expect("the stranger's listener");
        let mut stranger = Command::new(&stub).spawn().expect("the stranger");

        let handle = DaemonHandle {
            settings: DaemonSettings::new(&conf, &run_dir)
                .with_port(port)
                .with_listen_timeout(Duration::from_millis(400))
                .without_stunnel_log()
                .without_audit_file(),
            registry: Arc::new(TokioMutex::new(ModuleRegistry::new(
                &conf,
                base.join("secrets"),
            ))),
            state: Arc::new(TokioMutex::new(DaemonState::default())),
            stopping: Arc::new(AtomicBool::new(false)),
            supervisor: TokioMutex::new(None),
            watchdog: TokioMutex::new(None),
        };

        // Wait for the lock to be really held; otherwise the first half could
        // pass because the check ran before the stranger got there.
        let mut waited = Duration::ZERO;
        while pid_file_holder(&pid_file).is_none() && waited < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += Duration::from_millis(50);
        }
        let stranger_pid = pid_file_holder(&pid_file)
            .and_then(|holder| holder.pid)
            .expect("the stranger must hold the pid file lock");

        // 1. Nothing of ours has been spawned, so the answering socket is not
        //    ours either. The wait must run out rather than report readiness.
        let error = handle
            .wait_until_listening()
            .await
            .expect_err("a stranger's socket must not count as our daemon listening");
        assert!(
            error.to_string().contains("did not accept a connection"),
            "the wait has to end in its own timeout, not somewhere else: {error}"
        );

        // 2. Same socket, same lock — but now the holder is the pid this handle
        //    calls its own. Readiness is about identity, not about refusing.
        handle.state.lock().await.pid = Some(stranger_pid);
        handle
            .wait_until_listening()
            .await
            .expect("our own daemon holding the lock and answering on the port is ready");

        let _ = stranger.kill();
        let _ = stranger.wait();
        fs::remove_dir_all(&base).ok();
    }

    /// A port nothing is using, for a test that must not meet a real daemon.
    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().expect("the bound address").port();
        drop(listener);
        port
    }

    // -----------------------------------------------------------------------
    // Run directory watchdog (ticket 0cedda6f)
    // -----------------------------------------------------------------------

    /// Settings whose run directory is `dir`, with the watchdog limits given.
    fn watch_settings(dir: &Path, log_limit: u64, run_dir_limit: u64) -> DaemonSettings {
        DaemonSettings::new(dir.join("rsyncd.conf"), dir)
            .without_stunnel_log()
            .with_log_warn_bytes(log_limit)
            .with_run_dir_warn_bytes(run_dir_limit)
    }

    fn fill(path: &Path, bytes: usize) {
        fs::write(path, vec![b'x'; bytes]).expect("fill");
    }

    #[test]
    fn an_oversized_audit_log_is_reported_and_is_not_touched() {
        let dir = scratch("0cedda6f-report");
        let settings = watch_settings(&dir, 1024, 0);
        let audit = settings.audit_file();
        fill(&audit, 4096);
        let before = fs::read(&audit).expect("audit log");

        let mut watch = RunDirWatch::new(&settings);
        let warnings = watch.check(std::time::Instant::now());

        assert_eq!(
            warnings.len(),
            1,
            "exactly the audit log is over the limit: {warnings:?}"
        );
        assert_eq!(warnings[0].kind, "audit log");
        assert_eq!(warnings[0].bytes, 4096);
        // The whole point of the ticket: it warns, it does not rotate.
        assert_eq!(
            fs::read(&audit).expect("audit log after the check"),
            before,
            "the watchdog must not shorten the audit log"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_log_under_its_limit_is_not_reported() {
        let dir = scratch("0cedda6f-quiet");
        let settings = watch_settings(&dir, 4096, 0);
        fill(&settings.audit_file(), 4096);

        let mut watch = RunDirWatch::new(&settings);
        assert!(
            watch.check(std::time::Instant::now()).is_empty(),
            "exactly at the limit is not over it"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_warning_repeats_on_growth_and_after_the_interval_but_not_every_check() {
        let dir = scratch("0cedda6f-repeat");
        let settings = watch_settings(&dir, 1024, 0);
        let audit = settings.audit_file();
        fill(&audit, 2048);

        let mut watch = RunDirWatch::new(&settings);
        let now = std::time::Instant::now();
        assert_eq!(watch.check(now).len(), 1, "the first crossing is reported");

        // A minute later, unchanged: still over the limit, and silent — a
        // warning every minute for the life of the container is noise.
        assert!(
            watch.check(now + RUN_DIR_CHECK_INTERVAL).is_empty(),
            "the same size must not be reported again immediately"
        );

        // Doubled: that is news even inside the quiet window.
        fill(&audit, 4096);
        assert_eq!(
            watch.check(now + RUN_DIR_CHECK_INTERVAL * 2).len(),
            1,
            "a file that doubled has to be reported again"
        );

        // And a condition that simply persists is repeated eventually, so it
        // reaches somebody who was not watching at the moment it started.
        assert!(
            watch
                .check(now + RUN_DIR_CHECK_INTERVAL * 2 + RUN_DIR_WARN_REPEAT)
                .len()
                == 1,
            "a persisting condition has to be repeated after the interval"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_directory_total_is_reported_even_when_no_single_file_is_over() {
        let dir = scratch("0cedda6f-total");
        let settings = watch_settings(&dir, 1024 * 1024, 3000);
        fill(&settings.audit_file(), 1024);
        fill(&settings.log_file(), 1024);
        fill(&dir.join("stunnel.log"), 1024);

        let mut watch = RunDirWatch::new(&settings);
        let warnings = watch.check(std::time::Instant::now());

        assert_eq!(warnings.len(), 1, "only the directory total: {warnings:?}");
        assert_eq!(warnings[0].kind, "run directory");
        assert_eq!(warnings[0].bytes, 3072);
        assert!(
            settings.audit_file().exists() && settings.log_file().exists(),
            "nothing in the run directory may be removed"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_limit_of_zero_switches_the_check_off() {
        let dir = scratch("0cedda6f-off");
        let settings = watch_settings(&dir, 0, 0);
        fill(&settings.audit_file(), 65536);

        let mut watch = RunDirWatch::new(&settings);
        assert!(
            watch.check(std::time::Instant::now()).is_empty(),
            "a limit of 0 means the file is not watched"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The warning really leaves the process, from the task that produces it.
    ///
    /// `#[ignore]`d because it installs a global `tracing` subscriber, which
    /// only one test per process may do. Run it on its own:
    ///
    /// ```text
    /// cargo test the_watchdog_task_really_prints_the_warning -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore]
    async fn the_watchdog_task_really_prints_the_warning() {
        let dir = scratch("0cedda6f-task");
        let settings = watch_settings(&dir, 1024, 0);
        let audit = settings.audit_file();
        fill(&audit, 8192);

        let captured = dir.join("application.log");
        let sink = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&sink)
                    .expect("the capture file")
            })
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one subscriber per process");

        let stopping = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(watch_run_dir(RunDirWatch::new(&settings), stopping));
        // The first measurement happens before the first sleep, so the warning
        // is out long before RUN_DIR_CHECK_INTERVAL.
        tokio::time::sleep(Duration::from_millis(250)).await;
        task.abort();

        let text = fs::read_to_string(&captured).expect("the captured application log");
        println!("{text}");
        assert!(
            text.contains("audit log"),
            "the warning names the file: {text}"
        );
        assert!(
            text.contains("NOT rotated by this process"),
            "the warning says who is responsible: {text}"
        );
        assert!(
            text.contains("nothing has been deleted"),
            "the warning says what it did not do: {text}"
        );
        assert_eq!(
            fs::metadata(&audit).expect("the audit log").len(),
            8192,
            "the task must not have shortened the audit log"
        );
        // And it did not write its own warning into the directory it warns about.
        assert!(
            !captured.starts_with(settings.run_dir.join("audit.log")),
            "the warning must not land in the audit log"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_run_directory_is_measured_as_empty_rather_than_failing() {
        let dir = scratch("0cedda6f-missing");
        let settings = watch_settings(&dir, 1024, 1);
        let _ = fs::remove_dir_all(&dir);

        let mut watch = RunDirWatch::new(&settings);
        assert!(
            watch.check(std::time::Instant::now()).is_empty(),
            "nothing there is nothing to report"
        );
    }
}

// ---------------------------------------------------------------------------
// Probe against a real rsync daemon
//
// The unit tests above check what the module writes. They cannot check whether
// rsync agrees, and a configuration that only looks right is worth nothing —
// `auth digest` was accepted by every parser and silently ignored by rsync
// 3.4.1. This writes a configuration to a directory of the caller's choosing so
// that a real daemon can be pointed at it.
//
// It is `#[ignore]`d because it needs a writable directory from outside and
// because the interesting part happens after it, in the shell:
//
//     D=<scratch>/rsyncd-db73d18e; mkdir -p $D/share $D/ro $D/etc
//     RSYNCD_PROBE_DIR=$D cargo test dump_for_real_rsync -- --ignored
//     # host (rsync 3.5.0), must log no warning:
//     rsync --daemon --no-detach --config=$D/etc/rsyncd.conf --port=8873 \
//           --dparam="pid file=$D/etc/p" --log-file=$D/etc/d.log
//     # image (alpine:3.22, rsync 3.4.3), needs root for chroot and uid/gid:
//     docker run --rm -v $D:/host:ro alpine:3.22 sh -c 'apk add rsync; ...'
// ---------------------------------------------------------------------------

#[cfg(test)]
mod real_rsync_probe {
    use super::*;

    #[test]
    #[ignore]
    fn dump_for_real_rsync() {
        let base = PathBuf::from(std::env::var("RSYNCD_PROBE_DIR").expect("RSYNCD_PROBE_DIR"));
        let mut cfg = DaemonConfig::new(base.join("etc").join("secrets"));
        // One module per scope, so the same daemon shows both branches.
        cfg.add_module(ModuleConfig::new(&base.join("share"), true, 1001, 1001, 4).unwrap());
        cfg.add_module(ModuleConfig::new(&base.join("ro"), false, 1001, 1001, 4).unwrap());
        cfg.write(&base.join("etc").join("rsyncd.conf")).unwrap();
    }

    // -----------------------------------------------------------------------
    // Runtime add/remove against a running daemon (ticket ae12dcd1)
    //
    // "rsync re-reads the configuration on every connection" is the assumption
    // the whole ticket rests on, so it is measured here rather than believed.
    // The probe drives a real daemon end to end: push, add a module while the
    // daemon runs, push into it, revoke a module, watch the next push fail, and
    // keep a slow transfer running across all of it.
    //
    // Two backends, because the host and the image differ:
    //
    //     # rsync 3.5.0 (host)
    //     RSYNCD_PROBE_DIR=<scratch>/rsyncd-ae12dcd1 \
    //       cargo test runtime_modules_on_the_host_rsync -- --ignored --nocapture
    //     # rsync 3.4.3 (alpine:3.22, what the image ships)
    //     RSYNCD_PROBE_DIR=<scratch>/rsyncd-ae12dcd1 \
    //       cargo test runtime_modules_in_the_container -- --ignored --nocapture
    //
    // Both are `#[ignore]`d: they need a scratch directory from outside, and the
    // container one needs docker and a network to install rsync.
    //
    // Two concessions of the harness, neither of them touching what is being
    // measured:
    //
    //   * The daemon has to run as root (chroot, and dropping to the module
    //     uid). On the host that is a user namespace — `unshare --map-root-user
    //     --map-users=auto --map-groups=auto`. Plain `unshare -r` is not enough:
    //     it maps a single uid and leaves `setgroups` denied, and rsync then
    //     rejects every connection with `@ERROR: setgroups failed`.
    //   * In the container the daemon really is root, but the bind-mounted
    //     configuration belongs to the host user, so `strict modes` would refuse
    //     the secrets file. The probe passes `--dparam=strict modes=no` for that
    //     reason alone; in production the daemon and the app run as the same
    //     user. The client runs as the host uid so its password file passes the
    //     same check.
    //
    // Also passed by hand: `--dparam=lock file=<scratch>/etc/lock`. `max
    // connections` needs a lock file and the built-in default is
    // `/var/run/rsyncd.lock`, which the probe cannot write. That is why
    // [`DaemonSettings`] passes one too.
    //
    // Nothing here is a fixed name. Port, container name and scratch
    // subdirectory are derived from the process id and a per-probe counter, so
    // two runs at the same time — two agents, or one `cargo test` running the
    // probes on parallel threads — do not fight over a port or delete each
    // other's directory. `RSYNCD_PROBE_PORT` overrides the base port for a run
    // that has to use a known one.
    // -----------------------------------------------------------------------

    use std::process::{Child, Command, Output, Stdio};
    use std::sync::atomic::AtomicU16;
    use std::time::Instant;

    /// Distinguishes probes inside one process; see [`Probe::new`].
    static PROBE_SEQ: AtomicU16 = AtomicU16::new(0);

    /// A port band of eight, unique per process, one port per probe in it.
    fn probe_port(seq: u16) -> u16 {
        let base: u16 = std::env::var("RSYNCD_PROBE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| 18000 + ((std::process::id() % 5000) as u16) * 8);
        base.wrapping_add(seq % 8)
    }

    /// A container name that no other run can be using.
    fn probe_container(seq: u16) -> String {
        format!("rsyncd-probe-{}-{seq}", std::process::id())
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Backend {
        /// The rsync on this machine, inside a user namespace.
        Host,
        /// The rsync on this machine, as the invoking user, with the
        /// configuration [`Hardening::Rootless`] generates: no chroot, no
        /// uid/gid, an unprivileged port. Ticket `50c8ec48`.
        ///
        /// No user namespace, and that is the point rather than a shortcut —
        /// this is the deployment a developer actually gets when they start the
        /// application as themselves, and the only way to measure what the
        /// module boundary is worth there.
        HostRootless,
        /// The rsync of the runtime image, inside a container.
        Docker,
    }

    impl Backend {
        /// The hardening the generated configuration is rendered for.
        fn hardening(self) -> Hardening {
            match self {
                Self::Host | Self::Docker => Hardening::Full,
                Self::HostRootless => Hardening::Rootless,
            }
        }
    }

    struct Probe {
        backend: Backend,
        base: PathBuf,
        /// Port and container name of this probe; never a fixed value.
        port: u16,
        container: String,
        /// uid/gid the modules drop to; also the owner of every probe file.
        uid: u32,
        gid: u32,
        daemon: Option<Child>,
    }

    impl Probe {
        fn new(backend: Backend) -> Self {
            let seq = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Own subdirectory per probe: `RSYNCD_PROBE_DIR` is wiped below, and
            // two probes sharing it would delete each other's daemon out from
            // under it.
            let base = PathBuf::from(
                std::env::var("RSYNCD_PROBE_DIR")
                    .expect("set RSYNCD_PROBE_DIR to a writable scratch directory"),
            )
            .join(format!("run-{}-{seq}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            for dir in ["etc", "src"] {
                fs::create_dir_all(base.join(dir)).expect("scratch dir");
            }
            let owner = fs::metadata(&base).expect("scratch dir");
            let (uid, gid) = (owner.uid(), owner.gid());
            let (uid, gid) = match backend {
                // Inside the user namespace the probe user *is* root, and only
                // root is mapped, so the module cannot drop to anything else.
                Backend::Host => (0, 0),
                // Rootless the daemon never drops anything, so these values do
                // not reach the generated configuration at all (see
                // `ModuleConfig::render`). They still have to be the real ones:
                // `ModuleConfig::new` stores them, and a module whose share it
                // could not stat would not be created.
                Backend::HostRootless => (uid, gid),
                // The daemon is really root here and drops to the owner of the
                // bind-mounted share directories.
                Backend::Docker => (uid, gid),
            };
            Self {
                backend,
                base,
                port: probe_port(seq),
                container: probe_container(seq),
                uid,
                gid,
                daemon: None,
            }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.base.join(rel)
        }

        fn share(&self, name: &str) -> PathBuf {
            let dir = self.path(name);
            fs::create_dir_all(&dir).expect("share dir");
            dir
        }

        /// A password file for `module`, 0600, owned by the client user.
        fn password_file(&self, module: &ModuleConfig) -> PathBuf {
            let path = self.path(&format!("etc/pw-{}", module.name()));
            write_private_file(&path, &format!("{}\n", module.secret())).expect("password file");
            path
        }

        fn start_daemon(&mut self) {
            let conf = self.path("etc/rsyncd.conf");
            let log = self.path("etc/daemon.log");
            let args = [
                "--daemon".to_string(),
                "--no-detach".to_string(),
                format!("--config={}", conf.display()),
                format!("--port={}", self.port),
                format!("--dparam=lock file={}", self.path("etc/lock").display()),
                format!("--log-file={}", log.display()),
            ];

            let mut command = match self.backend {
                Backend::Host => {
                    let mut c = Command::new("unshare");
                    c.args([
                        "--map-root-user",
                        "--map-users=auto",
                        "--map-groups=auto",
                        "rsync",
                    ]);
                    c
                }
                // Plain rsync, as the invoking user: no namespace, no
                // capabilities, nothing the rootless deployment does not have.
                Backend::HostRootless => Command::new("rsync"),
                Backend::Docker => {
                    self.start_container();
                    let mut c = Command::new("docker");
                    c.args(["exec", &self.container, "rsync", "--dparam=strict modes=no"]);
                    c
                }
            };
            let child = command
                .args(args)
                // `/dev/null`, not the test harness's stdin: `rsync --daemon`
                // inspects fd 0 and serves a single connection from it instead
                // of listening when it is a socket. See the note above
                // `DaemonSettings`. Inherited stdin made this harness fail as
                // `malformed address localhost` / `connect from UNKNOWN`
                // depending on how `cargo test` was invoked.
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("cannot start the rsync daemon");
            self.daemon = Some(child);
            self.wait_for_daemon(&log);
        }

        fn start_container(&self) {
            let image =
                std::env::var("RSYNCD_PROBE_IMAGE").unwrap_or_else(|_| "alpine:3.22".to_string());
            let install = std::env::var("RSYNCD_PROBE_INSTALL")
                .unwrap_or_else(|_| "apk add --no-cache rsync".to_string());
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.container])
                .output();
            // The configuration names host paths, so the scratch directory is
            // mounted at the very same path inside the container.
            let mount = format!("{}:{}", self.base.display(), self.base.display());
            run_ok(
                Command::new("docker").args([
                    "run",
                    "-d",
                    "--name",
                    &self.container,
                    "-v",
                    &mount,
                    &image,
                    "sleep",
                    "infinity",
                ]),
                "docker run",
            );
            run_ok(
                Command::new("docker").args(["exec", &self.container, "sh", "-c", &install]),
                "installing rsync in the container",
            );
        }

        /// Wait until the daemon logs that it is listening.
        ///
        /// On failure the daemon's own output is part of the panic — the usual
        /// cause is a leftover daemon of an earlier run still holding the port,
        /// and `Address already in use` says so immediately.
        fn wait_for_daemon(&mut self, log: &Path) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                if fs::read_to_string(log)
                    .map(|l| l.contains("listening on port"))
                    .unwrap_or(false)
                {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let mut output = String::new();
            if let Some(mut child) = self.daemon.take() {
                let _ = child.kill();
                if let Ok(out) = child.wait_with_output() {
                    output = format!(
                        "{}{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            }
            panic!(
                "daemon did not start.\nstderr: {output}\nlog: {:?}",
                fs::read_to_string(log)
            );
        }

        /// An rsync client pushing `source` into `module`, ready to run.
        ///
        /// The client always runs as the owner of the scratch directory: rsync
        /// refuses a password file that belongs to somebody else.
        fn client_command(&self, extra: &[&str], module: &ModuleConfig, source: &Path) -> Command {
            let password = self.password_file(module);
            let mut command = match self.backend {
                Backend::Host | Backend::HostRootless => Command::new("rsync"),
                Backend::Docker => {
                    let owner = fs::metadata(&self.base).expect("scratch dir");
                    let mut c = Command::new("docker");
                    c.args([
                        "exec",
                        "-u",
                        &format!("{}:{}", owner.uid(), owner.gid()),
                        &self.container,
                        "rsync",
                    ]);
                    c
                }
            };
            command
                .arg("-a")
                .arg(format!("--password-file={}", password.display()))
                .args(extra)
                .arg(source)
                .arg(format!(
                    "rsync://{name}@127.0.0.1:{port}/{name}/",
                    name = module.name(),
                    port = self.port
                ));
            command
        }

        /// Run a client and wait for it.
        fn client(&self, extra: &[&str], module: &ModuleConfig, source: &Path) -> Output {
            self.client_command(extra, module, source)
                .output()
                .expect("cannot run rsync")
        }

        /// Start a client without waiting for it.
        fn client_in_background(
            &self,
            extra: &[&str],
            module: &ModuleConfig,
            source: &Path,
        ) -> Child {
            self.client_command(extra, module, source)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("cannot run rsync")
        }

        fn daemon_log(&self) -> String {
            fs::read_to_string(self.path("etc/daemon.log")).unwrap_or_default()
        }

        fn stop(&mut self) {
            if let Some(mut child) = self.daemon.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            if self.backend == Backend::Docker {
                let _ = Command::new("docker")
                    .args(["rm", "-f", &self.container])
                    .output();
            }
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn run_ok(command: &mut Command, what: &str) -> Output {
        let out = command.output().unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(
            out.status.success(),
            "{what} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn stderr(out: &Output) -> String {
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    #[test]
    #[ignore]
    fn runtime_modules_on_the_host_rsync() {
        runtime_module_probe(Backend::Host);
    }

    #[test]
    #[ignore]
    fn runtime_modules_in_the_container() {
        runtime_module_probe(Backend::Docker);
    }

    /// The whole ticket, measured against a daemon that is never restarted.
    fn runtime_module_probe(backend: Backend) {
        let mut probe = Probe::new(backend);
        let (uid, gid) = (probe.uid, probe.gid);

        let small = probe.path("src/f.txt");
        fs::write(&small, "hello\n").unwrap();
        // Big enough that the transfer is still running while the
        // configuration is rewritten under it; `--bwlimit` does the rest.
        let big = probe.path("src/big.bin");
        fs::write(&big, vec![b'x'; 8 * 1024 * 1024]).unwrap();

        let mut reg = ModuleRegistry::new(probe.path("etc/rsyncd.conf"), probe.path("etc/secrets"));
        let a = reg
            .add_pairing(&probe.share("share-a"), true, uid, gid, 4)
            .unwrap();
        let b = reg
            .add_pairing(&probe.share("share-b"), true, uid, gid, 4)
            .unwrap();

        probe.start_daemon();

        // 1. The configuration the daemon started with works.
        let out = probe.client(&[], &a, &small);
        assert!(
            out.status.success(),
            "push to the first module: {}",
            stderr(&out)
        );
        assert!(probe.path("share-a/f.txt").exists());

        // 2. A module added while the daemon runs — no restart, no signal, and
        //    rsync has neither a reload command nor a SIGHUP handler.
        // Eight connections rather than four: this module later takes the
        // concurrent clients of step 4, and `max connections` is enforced
        // (`@ERROR: max connections (4) reached -- try again later`).
        let c = reg
            .add_pairing(&probe.share("share-c"), true, uid, gid, 8)
            .unwrap();
        let out = probe.client(&[], &c, &small);
        assert!(
            out.status.success(),
            "a module added at runtime must be reachable without a restart: {}",
            stderr(&out)
        );
        assert!(probe.path("share-c/f.txt").exists());

        // 3. A revoked module is gone with the next connection.
        assert!(reg.revoke(a.name()).unwrap());
        let out = probe.client(&[], &a, &small);
        assert!(
            !out.status.success(),
            "a revoked module must not accept a client"
        );
        assert!(
            stderr(&out).contains("Unknown module"),
            "expected \"Unknown module\", got: {}",
            stderr(&out)
        );
        // ... and its secret no longer authenticates anything.
        assert!(!fs::read_to_string(probe.path("etc/secrets"))
            .unwrap()
            .contains(a.secret()));

        // 4. A transfer that is already running survives every rewrite.
        let running = probe.client_in_background(&["--bwlimit=1M", "--partial"], &b, &big);
        std::thread::sleep(Duration::from_secs(2));
        let mut churn = Vec::new();
        for i in 0..4 {
            let dir = probe.share(&format!("churn-{i}"));
            // Connections that arrive *while* the files are being replaced
            // must not see a half-written configuration. They are started
            // first and the rewrite happens under them; because both files are
            // replaced with `rename`, each connection reads either the whole
            // old or the whole new file.
            let concurrent: Vec<Child> = (0..4)
                .map(|_| probe.client_in_background(&[], &c, &small))
                .collect();
            let module = reg.add_pairing(&dir, true, uid, gid, 4).unwrap();
            churn.push(module);
            for client in concurrent {
                let out = client.wait_with_output().expect("concurrent client");
                assert!(
                    out.status.success(),
                    "a connection during a configuration rewrite failed: {}",
                    stderr(&out)
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // Including a revoke of the module the transfer itself runs on.
        assert!(reg.revoke(b.name()).unwrap());
        for module in &churn {
            assert!(reg.revoke(module.name()).unwrap());
        }
        let out = running.wait_with_output().expect("background client");
        assert!(
            out.status.success(),
            "a running transfer must survive the configuration being rewritten: {}",
            stderr(&out)
        );
        assert_eq!(
            fs::metadata(probe.path("share-b/big.bin")).unwrap().len(),
            fs::metadata(&big).unwrap().len(),
            "the transfer that ran across the rewrites is incomplete"
        );

        // 5. The daemon logged the change, not a complaint about it.
        let log = probe.daemon_log();
        assert!(
            !log.to_lowercase().contains("unknown parameter"),
            "the generated configuration produced parser warnings:\n{log}"
        );
        assert!(log.contains(&format!("unknown module '{}'", a.name())));
        println!("--- daemon log ({backend:?}) ---\n{log}");

        probe.stop();
        let _ = fs::remove_dir_all(&probe.base);
    }

    // -----------------------------------------------------------------------
    // The process lifecycle against a real daemon (ticket 3ed12cdd)
    //
    // Everything the ticket asks to be proven, in one run and against a daemon
    // that is really started, really killed and really shut down:
    //
    //   1. it starts with the application and is usable
    //   2. `--delete` and every variant of it is refused, the share survives
    //   3. no zombies after a run of transfers
    //   4. a crash is survived: the supervisor brings it back
    //   5. orphaned partials are swept out of the module temp directory at
    //      the next start, and ordinary user files in the share root — including
    //      the ones that look exactly like rsync temp files — are untouched
    //   6. a revoke ends a transfer that is already running
    //   7. shutdown leaves no process behind and releases the pid file lock
    //   8. a second daemon on the same pid file is detected, not started
    //
    //     RSYNCD_PROBE_DIR=<scratch>/rsyncd-3ed12cdd \
    //       cargo test daemon_lifecycle_on_the_host_rsync -- --ignored --nocapture
    //
    // `#[ignore]`d for the same two reasons as the probes above: it needs a
    // scratch directory from outside and a daemon that can chroot.
    //
    // The daemon runs through a two-line wrapper script rather than as `rsync`
    // directly, because `use chroot = yes` and dropping to a module uid need
    // root and the probe has a user namespace instead. `unshare` execs rsync
    // in place, so the child the supervisor holds *is* the daemon: the pid it
    // signals and the pid in the log are the same one, which is the whole point
    // of the exercise.
    // -----------------------------------------------------------------------

    /// A scratch directory, a wrapper script and a registry.
    struct LifecycleProbe {
        base: PathBuf,
        port: u16,
        launcher: PathBuf,
    }

    impl LifecycleProbe {
        fn new() -> Self {
            let seq = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let base = PathBuf::from(
                std::env::var("RSYNCD_PROBE_DIR")
                    .expect("set RSYNCD_PROBE_DIR to a writable scratch directory"),
            )
            .join(format!("life-{}-{seq}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            for dir in ["etc", "run", "src"] {
                fs::create_dir_all(base.join(dir)).expect("scratch dir");
            }

            // `exec` so that the wrapper leaves no shell between the supervisor
            // and the daemon, and `unshare` without `--fork` so that rsync keeps
            // the pid the supervisor spawned.
            let launcher = base.join("rsyncd-as-root");
            fs::write(
                &launcher,
                "#!/bin/sh\nexec unshare --map-root-user --map-users=auto \
                 --map-groups=auto rsync \"$@\"\n",
            )
            .expect("launcher");
            fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).expect("launcher");

            Self {
                base,
                port: probe_port(seq),
                launcher,
            }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.base.join(rel)
        }

        fn share(&self, name: &str) -> PathBuf {
            let dir = self.path(name);
            fs::create_dir_all(&dir).expect("share dir");
            dir
        }

        /// Settings for a daemon started the way an unprivileged user gets it:
        /// plain `rsync`, no user namespace, the rootless port.
        ///
        /// Deliberately *not* a flag on [`LifecycleProbe::settings`] — the two
        /// differ in the launcher, in `strict modes` (nothing changes identity
        /// here, so the real check applies) and in the port, and a boolean
        /// parameter threading through three of those is how one of them ends
        /// up wrong.
        fn rootless_settings(&self) -> DaemonSettings {
            DaemonSettings::new(self.path("etc/rsyncd.conf"), self.path("run"))
                .with_port(self.port)
                .with_temp_file_min_age(Duration::ZERO)
                .without_stunnel_log()
                .without_audit_file()
        }

        fn settings(&self) -> DaemonSettings {
            DaemonSettings::new(self.path("etc/rsyncd.conf"), self.path("run"))
                .with_binary(&self.launcher)
                .with_port(self.port)
                // Everything the probe writes belongs to the invoking user, but
                // inside the namespace the daemon is root, so `strict modes`
                // would refuse the secrets file. Nothing to do with what is
                // being measured; in production both are the same user.
                .with_dparam("strict modes=no")
                .with_temp_file_min_age(Duration::ZERO)
        }

        fn password_file(&self, module: &ModuleConfig) -> PathBuf {
            let path = self.path(&format!("etc/pw-{}", module.name()));
            write_private_file(&path, &format!("{}\n", module.secret())).expect("password file");
            path
        }

        fn client(&self, extra: &[&str], module: &ModuleConfig, source: &Path) -> Output {
            self.client_command(extra, module, source)
                .output()
                .expect("cannot run rsync")
        }

        fn client_command(&self, extra: &[&str], module: &ModuleConfig, source: &Path) -> Command {
            let password = self.password_file(module);
            let mut command = Command::new("rsync");
            command
                .arg("-a")
                .arg(format!("--password-file={}", password.display()))
                .args(extra)
                .arg(source)
                .arg(format!(
                    "rsync://{name}@127.0.0.1:{port}/{name}/",
                    name = module.name(),
                    port = self.port
                ));
            command
        }

        fn client_in_background(
            &self,
            extra: &[&str],
            module: &ModuleConfig,
            source: &Path,
        ) -> Child {
            self.client_command(extra, module, source)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("cannot run rsync")
        }
    }

    /// Stop any daemon this probe started, even when the test panicked.
    ///
    /// `DaemonHandle` deliberately has no `Drop` that kills the daemon (see the
    /// note there), so a probe that fails an assertion would otherwise leave a
    /// daemon holding a port until somebody notices. The pid file is written by
    /// the daemon itself, so it is the one place that knows what to stop
    /// without an async context.
    impl Drop for LifecycleProbe {
        fn drop(&mut self) {
            let Ok(pid) = fs::read_to_string(self.path("run/rsyncd.pid")) else {
                return;
            };
            let Ok(pid) = pid.trim().parse::<u32>() else {
                return;
            };
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
    }

    /// Whether `pid` still exists at all.
    fn process_alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Wait until `f` holds, or panic with `what`.
    async fn until(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// The application's own start path, rootless (ticket `50c8ec48`).
    ///
    /// # What this measures that the boundary probe does not
    ///
    /// `module_boundaries_without_chroot_on_the_real_daemon` starts rsync by
    /// hand. This one goes through [`DaemonHandle::start`] — the code path a
    /// user gets when they run the application as themselves, which is where
    /// ticket `50c8ec48` began (`cannot create the daemon run directory
    /// /etc/rsyncd/run: Permission denied`). Nothing here is privileged: no
    /// `unshare`, no launcher script, no capability, and no `strict modes=no`
    /// concession, because rootless the daemon and the files really do belong
    /// to the same user.
    ///
    /// Readiness is not read off a log line. `start` returning `Ok` already
    /// means the port answered *and* the pid file lock is ours (see
    /// `wait_until_listening`), and on top of that a push and a pull-back run
    /// over the socket: the acceptance criterion is "a transfer works
    /// end-to-end", and only a byte that arrives proves that.
    ///
    /// `#[ignore]`d because it needs `RSYNCD_PROBE_DIR`, like every probe here.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn a_rootless_daemon_starts_and_transfers_on_the_host_rsync() {
        let probe = LifecycleProbe::new();
        // The real ids of the invoking user. They never reach the generated
        // configuration in this mode — that is asserted below — but a module
        // still records them.
        let owner = fs::metadata(&probe.base).expect("scratch dir");
        let (uid, gid) = (owner.uid(), owner.gid());

        let share = probe.share("share");
        fs::write(share.join("already-here.txt"), "server side\n").unwrap();
        let source = probe.path("src");
        fs::write(source.join("payload.txt"), "rootless payload\n").unwrap();

        let mut registry =
            ModuleRegistry::new(probe.path("etc/rsyncd.conf"), probe.path("etc/secrets"))
                .with_hardening(Hardening::Rootless);
        let module = registry
            .add_pairing(&share, true, uid, gid, 4)
            .expect("pairing");
        let registry = Arc::new(TokioMutex::new(registry));

        let handle = DaemonHandle::start(probe.rootless_settings(), Arc::clone(&registry))
            .await
            .expect("a rootless daemon has to come up");

        // 1. It holds the port. `start` proved it with a connect against the
        //    pid file lock; this is the same question asked from outside, so
        //    that the criterion does not rest on our own bookkeeping.
        assert!(
            TcpStream::connect(format!("{DAEMON_ADDRESS}:{}", probe.port))
                .await
                .is_ok(),
            "nothing answers on the rootless port"
        );
        let status = handle.status().await;
        assert!(status.running && status.pid.is_some(), "{status:?}");
        assert_eq!(status.port, probe.port);

        // 2. The configuration on disk is the rootless one — no chroot, no
        //    identity drop. Without this the transfer below could be passing
        //    because the daemon was hardened after all.
        let generated = fs::read_to_string(probe.path("etc/rsyncd.conf")).expect("rsyncd.conf");
        assert!(generated.contains("use chroot = no"), "{generated}");
        assert!(
            !generated.contains("    uid = ") && !generated.contains("    gid = "),
            "{generated}"
        );
        assert!(
            generated.contains("    munge symlinks = yes"),
            "{generated}"
        );

        // 3. End to end: a push in, and a pull back out.
        let out = probe.client(&[], &module, &source.join("payload.txt"));
        assert!(out.status.success(), "rootless push: {}", stderr(&out));
        assert_eq!(
            fs::read_to_string(share.join("payload.txt")).unwrap_or_default(),
            "rootless payload\n",
            "the pushed file did not arrive in the share"
        );

        let back = probe.path("back");
        fs::create_dir_all(&back).unwrap();
        let password = probe.password_file(&module);
        let out = Command::new("rsync")
            .arg("-a")
            .arg(format!("--password-file={}", password.display()))
            .arg(format!(
                "rsync://{name}@127.0.0.1:{port}/{name}/",
                name = module.name(),
                port = probe.port
            ))
            .arg(format!("{}/", back.display()))
            .output()
            .expect("cannot run rsync");
        assert!(out.status.success(), "rootless pull: {}", stderr(&out));
        assert_eq!(
            fs::read_to_string(back.join("already-here.txt")).unwrap_or_default(),
            "server side\n",
            "the pull delivered nothing, so the transfer is not proven"
        );

        // 4. And it goes away again, releasing the lock.
        let pid = status.pid.expect("a pid");
        handle.shutdown().await;
        until(
            "the rootless daemon to exit",
            Duration::from_secs(10),
            || !process_alive(pid),
        )
        .await;
        assert!(
            pid_file_holder(&probe.path("run/rsyncd.pid")).is_none(),
            "the pid file lock outlived the daemon"
        );
        let _ = fs::remove_dir_all(&probe.base);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn daemon_lifecycle_on_the_host_rsync() {
        let probe = LifecycleProbe::new();
        let uid = 0; // inside the user namespace the probe user is root
        let gid = 0;

        let small = probe.path("src/f.txt");
        fs::write(&small, "hello\n").unwrap();
        let big = probe.path("src/big.bin");
        fs::write(&big, vec![b'x'; 32 * 1024 * 1024]).unwrap();

        let mut registry =
            ModuleRegistry::new(probe.path("etc/rsyncd.conf"), probe.path("etc/secrets"));
        let share = probe.share("share");
        let victim = share.join("victim.txt");
        let victim_link = share.join("victim.link");
        fs::write(&victim, "do not delete me\n").unwrap();
        std::os::unix::fs::symlink("victim.txt", &victim_link).unwrap();

        // Six real user files whose names are shaped exactly like an rsync temp
        // file. The previous sweep deleted four of these out of a tester's
        // share; they are here so that a repeat of that is a failing test and
        // not a bug report.
        let bystanders: Vec<PathBuf> = [
            ".ssh.config",
            ".env.docker",
            ".bashrc.backup",
            ".htaccess.backup",
            ".gitlab.config",
            ".npmrc.backup",
        ]
        .iter()
        .map(|n| {
            let path = share.join(n);
            fs::write(&path, "mine\n").unwrap();
            path
        })
        .collect();

        let a = registry.add_pairing(&share, true, uid, gid, 8).unwrap();
        let b = registry
            .add_pairing(&probe.share("share-b"), true, uid, gid, 8)
            .unwrap();
        let registry = Arc::new(TokioMutex::new(registry));

        // --- 1. it starts with the application and is usable -----------------
        let daemon = DaemonHandle::start(probe.settings(), Arc::clone(&registry))
            .await
            .expect("the daemon must start");
        let status = daemon.status().await;
        assert!(status.running, "status must report a running daemon");
        let first_pid = status.pid.expect("a running daemon has a pid");
        assert!(process_alive(first_pid));
        assert_eq!(status.port, probe.port);
        assert_eq!(status.address, DAEMON_ADDRESS);
        assert_eq!(status.modules.len(), 2, "the status lists the modules");
        assert_eq!(status.restarts, 0);
        assert!(!status.already_running_elsewhere);

        let out = probe.client(&[], &a, &small);
        assert!(out.status.success(), "first push: {}", stderr(&out));
        assert!(probe.path("share/f.txt").exists());

        // --- 2. every measured way of destroying is refused, the share survives
        // `--force` is on the list although it is not a delete option: it lets
        // an incoming file take the place of a non-empty directory, which
        // removed a file in the share with exit 0 and empty stderr before
        // `force` went into [`REFUSED_OPTIONS`]. The three shapes of that attack
        // are exercised against a prepared directory in
        // `module_boundaries_on_the_real_daemon`; here it is only the refusal.
        // `--remove-sent-files` is the deprecated alias that the refusal for
        // `--remove-source-files` does not cover on a push.
        for option in [
            "--delete",
            "--delete-before",
            "--delete-during",
            "--delete-delay",
            "--delete-after",
            "--delete-excluded",
            "--delete-missing-args",
            "--remove-source-files",
            "--remove-sent-files",
            "--del",
            "--force",
        ] {
            let out = probe.client(&[option], &a, &small);
            assert!(
                !out.status.success(),
                "{option} was accepted; a peer with write access could destroy the share"
            );
            assert!(
                stderr(&out).contains("configured to refuse"),
                "{option} failed for the wrong reason: {}",
                stderr(&out)
            );
            assert!(
                victim.exists() && fs::symlink_metadata(&victim_link).is_ok(),
                "{option} destroyed content in the share"
            );
            assert!(
                small.exists(),
                "{option} destroyed content on the sender's side"
            );
        }

        // --- 3. a run of transfers leaves no zombies -------------------------
        for _ in 0..30 {
            let out = probe.client(&[], &a, &small);
            assert!(out.status.success(), "transfer: {}", stderr(&out));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let status = daemon.status().await;
        assert_eq!(
            status.zombie_children, 0,
            "the daemon left unreaped children behind after 30 transfers"
        );
        assert_eq!(status.connections, 0, "no connection should still be open");

        // --- 4. a crash is survived ------------------------------------------
        // SIGKILL is the simulated crash, not a shutdown: the supervisor has
        // not been told to stop, so it has to notice and bring the daemon back.
        assert!(send_signal(first_pid, "KILL").await);
        until(
            "the daemon to be restarted",
            Duration::from_secs(30),
            || !process_alive(first_pid),
        )
        .await;
        let mut restarted = None;
        for _ in 0..300 {
            let status = daemon.status().await;
            if status.running && status.pid != Some(first_pid) {
                restarted = status.pid;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let second_pid = restarted.expect("the supervisor must restart a crashed daemon");
        assert_ne!(second_pid, first_pid);
        let status = daemon.status().await;
        assert!(status.restarts >= 1, "the restart must be counted");
        let out = probe.client(&[], &a, &small);
        assert!(
            out.status.success(),
            "the restarted daemon must serve the same modules: {}",
            stderr(&out)
        );

        // --- 5. orphaned temp files are swept at the next start --------------
        // What a hard-killed daemon leaves behind: a partial in the module's
        // own temp directory, which is where `temp dir = /.rsync-tmp` puts it.
        // Verified below that the daemon really writes there.
        let temp_dir = share.join(MODULE_TEMP_DIR);
        assert!(
            temp_dir.is_dir(),
            "writing the configuration must create the module temp directory"
        );
        let orphan = temp_dir.join("big.bin.aB3xZ9");
        fs::write(&orphan, vec![b'x'; 4 * 1024 * 1024]).unwrap();
        let innocent = share.join("keep-me.txt");
        fs::write(&innocent, "keep\n").unwrap();
        assert!(send_signal(second_pid, "KILL").await);
        until(
            "the orphaned temp file to be swept",
            Duration::from_secs(30),
            || !orphan.exists(),
        )
        .await;
        assert!(innocent.exists(), "the sweep touched an ordinary file");
        assert!(victim.exists(), "the sweep touched an ordinary file");
        for path in &bystanders {
            assert!(
                path.exists(),
                "the sweep deleted the user file {}",
                path.display()
            );
        }
        let mut third_pid = None;
        for _ in 0..300 {
            let status = daemon.status().await;
            if status.running && status.pid != Some(second_pid) {
                third_pid = status.pid;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let third_pid = third_pid.expect("the daemon must come back a second time");

        // --- 6. a second daemon on the same pid file is detected ------------
        // rsync holds an exclusive flock on its pid file for its whole life, so
        // this is the daemon's own answer to "is one already running", not a
        // guess from a stale pid file.
        let error = match DaemonHandle::start(probe.settings(), Arc::clone(&registry)).await {
            Ok(_) => panic!("a second daemon on the same pid file must not start"),
            Err(e) => e.to_string(),
        };
        assert!(
            error.contains("pid file lock"),
            "expected the pid file lock to be the reason, got: {error}"
        );
        assert!(
            process_alive(third_pid),
            "the failed second start must not have disturbed the running daemon"
        );

        // --- 7. a revoke ends a transfer that is already running -------------
        // Without the kill this is the measured gap: the daemon forks a child
        // per connection, that child has already read its module, and the
        // transfer runs to exit 0 straight across the revoke.
        let mut running = probe.client_in_background(&["--bwlimit=512K", "--partial"], &b, &big);
        let module_b = b.name().to_string();
        let handle_for_wait = Arc::clone(&daemon);
        let mut seen = false;
        for _ in 0..300 {
            if handle_for_wait
                .status()
                .await
                .active_modules
                .contains(&module_b)
            {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            seen,
            "the connection table must show the transfer before it can be interrupted"
        );

        let outcome = daemon.revoke_now(&module_b).await.expect("revoke");
        assert!(outcome.module_removed, "the module must be gone");
        assert_eq!(
            outcome.connections_terminated, 1,
            "the transfer in flight must have been ended by the revoke"
        );

        let out = running.wait().expect("the interrupted client");
        assert!(
            !out.success(),
            "a transfer that was revoked must not report success (exit {out:?})"
        );
        assert!(
            fs::metadata(probe.path("share-b/big.bin"))
                .map(|m| m.len())
                .unwrap_or(0)
                < fs::metadata(&big).unwrap().len(),
            "the interrupted transfer still completed; the revoke did not take effect"
        );
        // And the next connection is refused outright, module gone.
        let out = probe.client(&[], &b, &small);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("Unknown module"), "{}", stderr(&out));

        // --- 8. shutdown leaves nothing behind -------------------------------
        daemon.shutdown().await;
        until("the daemon to be gone", Duration::from_secs(30), || {
            !process_alive(third_pid)
        })
        .await;
        let status = daemon.status().await;
        assert!(
            !status.running,
            "the status must report the daemon as stopped"
        );
        assert_eq!(status.pid, None);
        // No child of the daemon survived it either.
        assert_eq!(count_zombie_children(third_pid), 0);
        // The pid file lock is released: a fresh daemon can take it.
        let again = DaemonHandle::start(probe.settings(), Arc::clone(&registry))
            .await
            .expect("the pid file lock must be free after a clean shutdown");
        let last_pid = again.status().await.pid.expect("pid");
        again.shutdown().await;
        until(
            "the last daemon to be gone",
            Duration::from_secs(30),
            || !process_alive(last_pid),
        )
        .await;

        // Nothing was left behind by the SIGTERM shutdown itself. Two separate
        // claims, and the second one is the reason the temp directory exists:
        //
        //   a) the module temp directories are empty, and
        //   b) the share *root* never held a temp file to begin with. The
        //      bystanders are deliberately not filtered out here — they have
        //      rsync's shape, so if the daemon ever wrote a temp file into the
        //      share root again this check could not tell the difference, and
        //      the point is that it never has to.
        for dir in [
            share.join(MODULE_TEMP_DIR),
            probe.path("share-b").join(MODULE_TEMP_DIR),
        ] {
            let left: Vec<PathBuf> = fs::read_dir(&dir)
                .expect("the module temp directory must still exist")
                .flatten()
                .map(|e| e.path())
                .collect();
            assert!(
                left.is_empty(),
                "a clean shutdown left partial files in {}: {left:?}",
                dir.display()
            );
        }
        let in_share_root: Vec<PathBuf> = fs::read_dir(&share)
            .expect("share")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        let expected: HashSet<PathBuf> = bystanders
            .iter()
            .cloned()
            .chain([victim.clone(), victim_link.clone(), innocent.clone()])
            .chain([share.join("f.txt")])
            .collect();
        for path in &in_share_root {
            assert!(
                expected.contains(path),
                "the daemon left {} in the share root; temp files belong in {}",
                path.display(),
                MODULE_TEMP_DIR
            );
        }

        let _ = fs::remove_dir_all(&probe.base);
    }

    // -----------------------------------------------------------------------
    // Audit log against a real daemon (ticket 9f3d4888)
    //
    //     RSYNCD_PROBE_DIR=<dir> cargo test audit_log_on_the_real_daemon -- --ignored
    //
    // The unit tests above parse lines that were copied out of a real log. This
    // one produces them: it runs the shipped configuration against the rsync on
    // this machine, puts a stunnel-shaped forwarder in front of the daemon so
    // the merge of the two logs is exercised for real, and then asserts what
    // ends up in the audit log — including what stands in the client column.
    // -----------------------------------------------------------------------

    /// A stand-in for stunnel: forwards to the daemon and logs like stunnel does.
    ///
    /// It is not a TLS terminator and does not need to be. What is being tested
    /// is the join between two log files, and the only things that join depends
    /// on are the two log lines and the loopback port pair — which this
    /// reproduces exactly, down to the `LOG5[<id>]` thread id.
    async fn stunnel_shaped_forwarder(listen: tokio::net::TcpListener, backend: u16, log: PathBuf) {
        let mut id = 0u32;
        loop {
            let Ok((mut inbound, peer)) = listen.accept().await else {
                return;
            };
            let Ok(mut outbound) = tokio::net::TcpStream::connect(("127.0.0.1", backend)).await
            else {
                return;
            };
            let local = outbound.local_addr().expect("local address");
            let now = chrono::Local::now().format("%Y.%m.%d %H:%M:%S");
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .expect("stunnel log");
            writeln!(
                file,
                "{now} LOG5[{id}]: Service [rsyncd-tls] accepted connection from {}:{}",
                peer.ip(),
                peer.port()
            )
            .expect("stunnel log");
            writeln!(
                file,
                "{now} LOG5[{id}]: Service [rsyncd-tls] connected remote server from 127.0.0.1:{}",
                local.port()
            )
            .expect("stunnel log");
            drop(file);
            id += 1;
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn audit_log_on_the_real_daemon() {
        let probe = LifecycleProbe::new();
        let (uid, gid) = (0, 0); // inside the user namespace the probe user is root

        let source = probe.path("src");
        fs::write(source.join("bericht.txt"), "hallo\n").unwrap();
        fs::write(source.join("mit leer zeichen.txt"), "auch hallo\n").unwrap();

        let share = probe.share("share");
        let victim = share.join("victim.txt");
        fs::write(&victim, "do not delete me\n").unwrap();

        let mut registry =
            ModuleRegistry::new(probe.path("etc/rsyncd.conf"), probe.path("etc/secrets"));
        let module = registry.add_pairing(&share, true, uid, gid, 8).unwrap();
        let registry = Arc::new(TokioMutex::new(registry));

        let stunnel_log = probe.path("etc/stunnel.log");
        let settings = probe.settings().with_stunnel_log(&stunnel_log);
        let audit_file = settings.audit_file();
        let daemon = DaemonHandle::start(settings, Arc::clone(&registry))
            .await
            .expect("the daemon must start");

        // The generated configuration must carry the log file and the format;
        // without either the daemon writes nothing worth auditing.
        let conf = fs::read_to_string(probe.path("etc/rsyncd.conf")).unwrap();
        assert!(conf.contains("\nlog file = "), "conf:\n{conf}");
        assert!(
            conf.contains("    transfer logging = yes\n"),
            "conf:\n{conf}"
        );
        assert!(
            conf.contains(&format!("    log format = {MODULE_LOG_FORMAT}\n")),
            "conf:\n{conf}"
        );

        // The forwarder stands where stunnel stands: the client talks to it,
        // it talks to the daemon on loopback.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("forwarder port");
        let front_port = listener.local_addr().unwrap().port();
        let forwarder = tokio::spawn(stunnel_shaped_forwarder(
            listener,
            probe.port,
            stunnel_log.clone(),
        ));

        let password = probe.password_file(&module);
        let through_stunnel = |extra: Vec<&str>| {
            Command::new("rsync")
                .arg("-a")
                .arg(format!("--password-file={}", password.display()))
                .args(extra)
                .arg(format!("{}/", source.display()))
                .arg(format!(
                    "rsync://{name}@127.0.0.1:{front_port}/{name}/",
                    name = module.name()
                ))
                .output()
                .expect("cannot run rsync")
        };

        // --- 1. an ordinary access ------------------------------------------
        let out = through_stunnel(vec![]);
        assert!(out.status.success(), "push: {}", stderr(&out));

        // --- 2. an attempt to delete ----------------------------------------
        let out = through_stunnel(vec!["--delete"]);
        assert!(!out.status.success(), "--delete must be refused");
        assert!(victim.exists(), "the victim file was deleted");

        // The mirror polls; give it a moment to catch up with the daemon.
        until(
            "the audit log to be written",
            Duration::from_secs(30),
            || {
                fs::read_to_string(&audit_file)
                    .map(|log| log.contains("option_refused"))
                    .unwrap_or(false)
            },
        )
        .await;

        let events = daemon.audit_events(usize::MAX).await;
        assert!(!events.is_empty(), "the audit log must not be empty");

        // Who used which module, when, with what effect.
        let received: Vec<&AuditEvent> = events
            .iter()
            .filter(|e| e.action == AuditAction::FileReceived)
            .collect();
        assert!(
            received
                .iter()
                .any(|e| e.path.as_deref() == Some("bericht.txt")),
            "the transferred file is missing from the audit log: {events:#?}"
        );
        assert!(
            received
                .iter()
                .any(|e| e.path.as_deref() == Some("mit leer zeichen.txt")),
            "a file name with spaces was mangled: {events:#?}"
        );
        for event in &received {
            assert_eq!(event.module.as_deref(), Some(module.name()));
            assert_eq!(event.user.as_deref(), Some(module.name()));
            assert!(
                parse_rsync_time(&format!("{} x", event.at)).is_some(),
                "unparseable timestamp {:?}",
                event.at
            );
        }
        // The direction of the session is the one statement about the client's
        // options the daemon makes; `rsync to` is a client that writes.
        assert!(
            events.iter().any(|e| e.action == AuditAction::SessionWrite),
            "the session direction is missing: {events:#?}"
        );

        // The delete attempt, marked as such.
        let deletions = daemon.deletion_events(usize::MAX).await;
        assert!(
            deletions
                .iter()
                .any(|e| e.refused_option.as_deref() == Some("delete")),
            "the delete attempt is not marked in the audit log: {events:#?}"
        );

        // --- 3. the client column -------------------------------------------
        // The whole point of the exercise: the daemon says 127.0.0.1 for every
        // peer, and the audit log must not repeat that.
        let with_client: Vec<&AuditEvent> = events.iter().filter(|e| e.client.is_some()).collect();
        assert!(
            !with_client.is_empty(),
            "no event carries a client address, so the two logs were not joined: {events:#?}"
        );
        assert!(
            with_client
                .iter()
                .any(|e| e.client_source == ClientAddressSource::StunnelPort),
            "the port match never fired; only the weaker time match did: {with_client:#?}"
        );
        for event in &with_client {
            assert!(
                event.client_port.is_some(),
                "an address without the port it came from: {event:#?}"
            );
        }

        // And the audit file holds the same thing, one JSON object per line.
        let written = fs::read_to_string(&audit_file).expect("audit log");
        for line in written.lines() {
            let value: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("bad audit line {line:?}: {e}"));
            assert!(value["at"].is_string());
        }
        assert!(
            written.contains("\"refused_option\":\"delete\""),
            "the delete attempt is missing from the audit file"
        );
        // The secret must not leak into the audit log along the way.
        assert!(
            !written.contains(module.secret()),
            "the module secret reached the audit log"
        );

        // The probe exists to be read, not only to pass: print what was
        // actually recorded, so the evidence is in the test output rather than
        // in somebody's terminal history.
        println!("--- daemon log ---");
        println!(
            "{}",
            fs::read_to_string(probe.path("run/rsyncd.log")).unwrap_or_default()
        );
        println!("--- stunnel log ---");
        println!("{}", fs::read_to_string(&stunnel_log).unwrap_or_default());
        println!("--- audit log ---");
        println!("{written}");

        forwarder.abort();
        daemon.shutdown().await;
        let _ = fs::remove_dir_all(&probe.base);
    }

    // -----------------------------------------------------------------------
    // An orphaned daemon on the pid file (ticket f581f435)
    //
    // The state a hard kill of the application leaves behind: the daemon
    // outlives it and keeps the `flock` on the pid file, so every later start
    // fails with `failed to lock pid file: Resource temporarily unavailable`
    // and nothing says which process is in the way. Reproduced here with a
    // real rsync daemon that this process does not supervise — which is
    // exactly what an orphan is.
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore]
    async fn a_daemon_holding_the_pid_file_is_named_and_stops_blocking_once_it_is_gone() {
        let probe = LifecycleProbe::new();
        let run_dir = probe.path("run");
        fs::create_dir_all(&run_dir).expect("run dir");
        let pid_file = run_dir.join("rsyncd.pid");

        // The orphan: a daemon with no modules — it only has to hold the lock.
        let orphan_conf = probe.path("etc/orphan.conf");
        fs::write(
            &orphan_conf,
            format!(
                "pid file = {}\nlock file = {}\nlog file = {}\naddress = 127.0.0.1\n",
                pid_file.display(),
                run_dir.join("rsyncd.lock").display(),
                run_dir.join("orphan.log").display(),
            ),
        )
        .expect("orphan configuration");
        let orphan_port = probe.port + 4;
        let mut orphan = Command::new("rsync")
            .args([
                "--daemon".to_string(),
                "--no-detach".to_string(),
                format!("--config={}", orphan_conf.display()),
                format!("--port={orphan_port}"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the orphaned daemon");
        let orphan_pid = orphan.id();
        for _ in 0..100 {
            if fs::read_to_string(&pid_file)
                .map(|content| !content.trim().is_empty())
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // A start against the same run directory now has to refuse, at once,
        // and say who is holding it.
        let conf = probe.path("etc/rsyncd.conf");
        let registry = Arc::new(TokioMutex::new(ModuleRegistry::new(
            &conf,
            probe.path("etc/secrets"),
        )));
        let settings = DaemonSettings::new(&conf, &run_dir)
            .with_port(probe.port)
            .without_stunnel_log()
            .without_audit_file();
        let started = Instant::now();
        let error = match DaemonHandle::start(settings, Arc::clone(&registry)).await {
            Err(e) => e,
            Ok(_) => panic!("a second daemon on a locked pid file must not start"),
        };
        let blocked_after = started.elapsed();
        println!("blocked start took {blocked_after:?}: {error}");
        assert!(
            error.to_string().contains(&format!("pid {orphan_pid}")),
            "the message has to name the blocking process: {error}"
        );
        assert!(
            blocked_after < Duration::from_secs(2),
            "the refusal took {blocked_after:?}; it must not sit out the timeout"
        );

        // SIGTERM, not SIGKILL: the kernel drops the lock with the process
        // either way, but a hard kill is what leaves the partial files behind.
        assert!(
            send_signal(orphan_pid, "TERM").await,
            "SIGTERM to the orphan"
        );
        let _ = orphan.wait();

        // With the orphan gone the lock is gone with it, and the same settings
        // start normally — no leftover state to clean up by hand.
        let settings = DaemonSettings::new(&conf, &run_dir)
            .with_port(probe.port)
            .without_stunnel_log()
            .without_audit_file();
        let started = Instant::now();
        let daemon = DaemonHandle::start(settings, registry)
            .await
            .expect("the start has to succeed once the lock is gone");
        println!("start after the orphan took {:?}", started.elapsed());
        assert!(
            tokio::net::TcpStream::connect(format!("{DAEMON_ADDRESS}:{}", probe.port))
                .await
                .is_ok(),
            "the daemon reported ready, so the port has to answer"
        );
        daemon.shutdown().await;
        let _ = fs::remove_dir_all(&probe.base);
    }

    // -----------------------------------------------------------------------
    // Secrets and the connection limit against a real daemon (ticket 4292d027)
    //
    //     RSYNCD_PROBE_DIR=<scratch>/rsyncd-4292d027 \
    //       cargo test secrets_and_limits_on_the_real_daemon -- --ignored --nocapture
    //
    // Two claims that can only be checked while a daemon is actually running:
    //
    //   1. the module secret is in the 0600 secrets file and **nowhere else** —
    //      not in `/proc/<pid>/cmdline` of the daemon or of any connection
    //      child (world-readable for every user on the host), not in the daemon
    //      log, not in the configuration file
    //   2. `max connections` is enforced by the daemon, and it is enforced on
    //      *concurrency* — so a peer with many small transfers one after
    //      another cannot lock itself out with it
    //
    // Every "the secret is not in X" below is paired with something that *is*
    // in X, so that an empty file or an unreadable path cannot pass as a clean
    // result. That pairing is the whole reason this probe is longer than it
    // looks like it needs to be.
    // -----------------------------------------------------------------------

    /// Every live child of `pid`, from `/proc`.
    fn children_of(parent: u32) -> Vec<u32> {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| is_child_of(*pid, parent))
            .collect()
    }

    /// `/proc/<pid>/cmdline` as a readable string, or `None`.
    fn cmdline_of(pid: u32) -> Option<String> {
        let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        Some(
            raw.split(|byte| *byte == 0)
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<String>>()
                .join(" "),
        )
    }

    #[test]
    #[ignore]
    fn secrets_and_limits_on_the_real_daemon() {
        let mut probe = Probe::new(Backend::Host);
        let (uid, gid) = (probe.uid, probe.gid);

        let small = probe.path("src/f.txt");
        fs::write(&small, "hello\n").unwrap();
        // Big enough that three pushes overlap under `--bwlimit`, small enough
        // that the whole probe stays under half a minute: 3 MiB at 512 KiB/s is
        // about six seconds per transfer.
        let big = probe.path("src/big.bin");
        fs::write(&big, vec![b'x'; 3 * 1024 * 1024]).unwrap();

        let conf_path = probe.path("etc/rsyncd.conf");
        let secrets_path = probe.path("etc/secrets");
        let mut registry = ModuleRegistry::new(&conf_path, &secrets_path);
        // Two concurrent connections, so the limit can be reached with three
        // clients rather than with a crowd.
        let limit = 2u32;
        let module = registry
            .add_pairing(&probe.share("share"), true, uid, gid, limit)
            .expect("pairing");
        let secret = module.secret().to_string();
        probe.start_daemon();

        let daemon_pid = probe.daemon.as_ref().expect("the daemon is running").id();

        // --- 1. the secret is in one file and nowhere else -------------------
        // The control first: the file that is *supposed* to hold it does, with
        // mode 0600. Without this the four "not in X" checks below would also
        // pass if `generate_secret` had returned an empty string.
        let secrets = fs::read_to_string(&secrets_path).expect("the secrets file");
        assert!(
            secrets.contains(&secret),
            "the secrets file does not hold the secret, so nothing below means anything"
        );
        assert_eq!(
            fs::metadata(&secrets_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // The argument vector, of the daemon and of every child it forks. This
        // is the one that matters most: `/proc/<pid>/cmdline` is readable by
        // every user on the host, so a secret passed on the command line is
        // public for as long as the process lives.
        let mut checked = 0usize;
        let daemon_cmdline = cmdline_of(daemon_pid).expect("the daemon's own cmdline");
        assert!(
            daemon_cmdline.contains(&conf_path.display().to_string()),
            "this is not the daemon's command line, so reading it proves nothing: \
             {daemon_cmdline}"
        );
        assert!(
            !daemon_cmdline.contains(&secret),
            "the module secret is in the daemon's command line: {daemon_cmdline}"
        );
        checked += 1;

        // A connection child, caught while it is serving: it inherits the
        // daemon's argv, but a future change that hands a child anything of its
        // own would show up here.
        let running = probe.client_in_background(
            &["--bwlimit=512K", "--no-owner", "--no-group"],
            &module,
            &big,
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut seen_child = false;
        while Instant::now() < deadline {
            let children = children_of(daemon_pid);
            if !children.is_empty() {
                for child in children {
                    if let Some(cmdline) = cmdline_of(child) {
                        assert!(
                            !cmdline.contains(&secret),
                            "the module secret is in the command line of connection \
                             child {child}: {cmdline}"
                        );
                        checked += 1;
                        seen_child = true;
                    }
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            seen_child,
            "no connection child was ever observed, so its command line was not checked"
        );
        assert!(checked >= 2, "only {checked} command lines were examined");
        let out = running.wait_with_output().expect("background client");
        assert!(out.status.success(), "push: {}", stderr(&out));

        // The configuration file the daemon reads, and its own log.
        let conf = fs::read_to_string(&conf_path).expect("the configuration");
        assert!(
            conf.contains(module.name()),
            "the configuration does not name the module: {conf}"
        );
        assert!(
            !conf.contains(&secret),
            "the module secret is in rsyncd.conf, which is not the file with the \
             restricted mode: {conf}"
        );

        let log = probe.daemon_log();
        assert!(
            log.contains(module.name()),
            "the daemon log does not mention the module, so searching it for the \
             secret proves nothing:\n{log}"
        );
        assert!(
            !log.contains(&secret),
            "the module secret reached the daemon log:\n{log}"
        );

        // --- 2. the connection limit ----------------------------------------
        // `max connections` needs the lock file the daemon was started with;
        // without one rsync falls back to `/var/run/rsyncd.lock` and the limit
        // silently does nothing. That is why `DaemonSettings` passes one.
        let mut concurrent: Vec<Child> = (0..(limit + 1))
            .map(|_| {
                probe.client_in_background(
                    &["--bwlimit=512K", "--no-owner", "--no-group"],
                    &module,
                    &big,
                )
            })
            .collect();
        let mut refused = 0usize;
        let mut succeeded = 0usize;
        for client in concurrent.drain(..) {
            let out = client.wait_with_output().expect("concurrent client");
            if out.status.success() {
                succeeded += 1;
            } else if stderr(&out).contains(&format!("max connections ({limit}) reached")) {
                refused += 1;
            } else {
                panic!("a client failed for an unrelated reason: {}", stderr(&out));
            }
        }
        assert!(
            refused >= 1,
            "{} clients ran against a module with max connections = {limit} and none \
             was refused; the limit is not being enforced",
            limit + 1
        );
        assert!(
            succeeded >= 1,
            "the limit refused every client, which is a closed module and not a limit"
        );
        println!("max connections = {limit}: {succeeded} served, {refused} refused");

        // And the other half, which is what keeps the limit from being a foot
        // gun: it counts connections that are open at the same time, not
        // transfers over time. Ten small pushes in a row — the shape of a
        // legitimate peer syncing many small files — must all get through.
        for round in 0..10 {
            let out = probe.client(&["--no-owner", "--no-group"], &module, &small);
            assert!(
                out.status.success(),
                "sequential transfer {round} was refused, so a peer with many small \
                 transfers locks itself out: {}",
                stderr(&out)
            );
        }

        // --- 3. loopback only, according to the kernel ----------------------
        let addresses = listening_addresses(probe.port).expect("/proc/net/tcp is readable here");
        assert!(
            !addresses.is_empty(),
            "the daemon is serving clients, so it has to appear in /proc/net/tcp"
        );
        assert!(
            loopback_only_verdict(probe.port).is_ok(),
            "the shipped configuration produced a daemon that is reachable from \
             outside: {addresses:?}"
        );

        probe.stop();
        let _ = fs::remove_dir_all(&probe.base);
    }

    /// A daemon that would come up reachable from outside must not come up.
    ///
    ///     RSYNCD_PROBE_DIR=<dir> \
    ///       cargo test the_daemon_refuses_to_come_up_without_tls -- --ignored
    ///
    /// The unit tests cover the two halves of the check separately (the dparam
    /// guard, and the verdict against a real listening socket). This is the one
    /// that shows `DaemonHandle::start` actually asks: the same settings that
    /// start a daemon fine are given `--dparam=address=0.0.0.0`, and the start
    /// has to fail — with no daemon left behind, because a refusal that leaves
    /// the thing it refused running would be worse than no check.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn the_daemon_refuses_to_come_up_without_tls() {
        let probe = LifecycleProbe::new();
        let registry = Arc::new(TokioMutex::new(ModuleRegistry::new(
            probe.path("etc/rsyncd.conf"),
            probe.path("etc/secrets"),
        )));
        registry
            .lock()
            .await
            .add_pairing(&probe.share("share"), true, 0, 0, 4)
            .expect("pairing");

        // The control: these settings do start a daemon. Without it a refusal
        // below could just as well be a broken fixture.
        let daemon = DaemonHandle::start(probe.settings(), Arc::clone(&registry))
            .await
            .expect("the unmodified settings must start a daemon");
        let pid = daemon.status().await.pid.expect("pid");
        daemon.shutdown().await;
        until(
            "the control daemon to be gone",
            Duration::from_secs(30),
            || !process_alive(pid),
        )
        .await;

        // And the same settings with the listen address overridden do not.
        for param in ["address=0.0.0.0", "port=1", "address=::"] {
            let error = match DaemonHandle::start(
                probe.settings().with_dparam(param),
                Arc::clone(&registry),
            )
            .await
            {
                Ok(_) => panic!("a daemon with --dparam={param} must not start"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("TLS terminator"),
                "the refusal for {param} has to say why: {error}"
            );
            // Nothing was started, so nothing holds the pid file: the next
            // start has to be free to take it.
            assert!(
                !probe.path("run/rsyncd.pid").exists()
                    || fs::read_to_string(probe.path("run/rsyncd.pid"))
                        .map(|content| pid_file_blocker(Path::new(&content)).is_none())
                        .unwrap_or(true),
                "the refused start left a daemon holding the pid file"
            );
        }

        // The port is free again afterwards, which is the practical form of
        // "nothing was left behind".
        let daemon = DaemonHandle::start(probe.settings(), registry)
            .await
            .expect("a start after the refusals must work");
        let pid = daemon.status().await.pid.expect("pid");
        daemon.shutdown().await;
        until("the daemon to be gone", Duration::from_secs(30), || {
            !process_alive(pid)
        })
        .await;
        let _ = fs::remove_dir_all(&probe.base);
    }

    // -----------------------------------------------------------------------
    // Path and module boundaries against a real daemon (ticket 674170ac)
    //
    //     RSYNCD_PROBE_DIR=<scratch>/rsyncd-674170ac \
    //       cargo test module_boundaries_on_the_real_daemon -- --ignored --nocapture
    //
    // The unit tests above check what is written into `rsyncd.conf`. A line in
    // that file is not a boundary: `auth digest` was accepted by every parser
    // and ignored by rsync, and the spike read `/etc/passwd` out of a module
    // through a server-side symlink *while* `munge symlinks` was set. So every
    // boundary here is driven against a daemon that is really running, and the
    // verdict is always the same one: did the file that lives outside the
    // module arrive on the client side, yes or no.
    //
    // What is measured, and how each measurement is shown to be able to fail:
    //
    //   1. a pull of an in-module file (the control — it delivers content
    //      through the same code path every escape below uses, so a silently
    //      broken harness cannot pass as "nothing escaped")
    //   2. `..` and `../../etc/passwd` in the requested path
    //   3. an absolute path instead of a module name
    //   4. a **server-side** symlink out of the module, read with `-L`,
    //      `--copy-links`, `--copy-unsafe-links` and `--copy-dirlinks`
    //   5. the same symlinks on a plain pull: they come across as symlinks,
    //      never as the content behind them
    //   6. an unknown module name
    //   7. `list = no`: the module names are not enumerable
    //   8. an **uploaded** symlink is stored munged, so the daemon cannot
    //      follow it later
    //   9. `--delete` and `--remove-source-files`
    //
    // and then, on a second daemon, the counter-proof: the same attacks against
    // a module with `use chroot = no`, `munge symlinks = no`,
    // `insecure links = yes`, `list = yes` and no `refuse options` **succeed**,
    // `/etc/passwd` included. Without that half, "nothing leaked" would only
    // mean the harness never leaks anything.
    //
    // Two of the nine are honest exceptions and are marked as such below:
    // rsync refuses `..` and an absolute path itself, in **both**
    // configurations, so no configuration change can make those two
    // assertions fail. Their ability to fail rests on the control in 1.
    // -----------------------------------------------------------------------

    /// A file that lives outside the module and must never arrive.
    const OUTSIDE_SENTINEL: &str = "OUTSIDE-THE-MODULE-a7f3c1";
    /// A file inside the module, for the control transfer.
    const INSIDE_SENTINEL: &str = "INSIDE-THE-MODULE-b2c94e";

    /// Every regular file below `dir`, without ever following a symlink.
    ///
    /// Not following them is the whole point. The probe runs on the same host
    /// as the daemon, so a symlink that arrived as a symlink — `passwd.link ->
    /// /etc/passwd`, which is the correct and harmless outcome — would resolve
    /// locally and read exactly like a leak. A check that cannot tell those two
    /// apart would fail the hardened daemon and pass nothing.
    fn regular_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                out.extend(regular_files(&path));
            } else if meta.is_file() {
                out.push(path);
            }
        }
        out
    }

    /// Whether any regular file below `dir` holds `needle`.
    fn tree_holds(dir: &Path, needle: &str) -> bool {
        regular_files(dir).iter().any(|path| {
            fs::read(path)
                .map(|bytes| String::from_utf8_lossy(&bytes).contains(needle))
                .unwrap_or(false)
        })
    }

    /// The first line of `/etc/passwd`, when it is readable.
    ///
    /// The spike's escape ended in this file, so it is checked for by name as
    /// well as through our own sentinel. Optional on purpose: a host that does
    /// not have it must not turn the probe red, and the sentinel carries the
    /// measurement either way.
    fn passwd_marker() -> Option<String> {
        let content = fs::read_to_string("/etc/passwd").ok()?;
        let line = content.lines().next()?.trim().to_string();
        (line.len() > 8).then_some(line)
    }

    impl Probe {
        /// Run rsync with this module's password file and nothing else fixed.
        ///
        /// [`Probe::client`] hard-codes a push; the escapes below are pulls, and
        /// two of them do not name the module in the usual place at all.
        fn rsync(&self, module: &ModuleConfig, args: &[&str]) -> Output {
            let password = self.password_file(module);
            let mut command = match self.backend {
                Backend::Host | Backend::HostRootless => Command::new("rsync"),
                Backend::Docker => {
                    let owner = fs::metadata(&self.base).expect("scratch dir");
                    let mut c = Command::new("docker");
                    c.args([
                        "exec",
                        "-u",
                        &format!("{}:{}", owner.uid(), owner.gid()),
                        &self.container,
                        "rsync",
                    ]);
                    c
                }
            };
            command
                .arg("-a")
                // Never `-o`/`-g`: the daemon runs as root inside the user
                // namespace and would stamp the invoking user's numeric uid on
                // everything it receives, which lands outside the namespace as
                // a subuid the probe can no longer delete.
                .args(["--no-owner", "--no-group"])
                .arg(format!("--password-file={}", password.display()))
                .args(args)
                .output()
                .expect("cannot run rsync")
        }

        /// An empty destination directory. rsync creates only the last
        /// component itself, so a nested one has to exist beforehand.
        fn dst(&self, name: &str) -> PathBuf {
            let dir = self.base.join("dst").join(name);
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("destination dir");
            dir
        }

        /// `rsync://<module>@127.0.0.1:<port>/<path>`.
        fn url(&self, module: &ModuleConfig, path: &str) -> String {
            format!(
                "rsync://{name}@127.0.0.1:{port}/{path}",
                name = module.name(),
                port = self.port
            )
        }
    }

    #[test]
    #[ignore]
    fn module_boundaries_on_the_real_daemon() {
        module_boundary_probe(Backend::Host);
    }

    /// The same nine boundaries, against the configuration a rootless daemon
    /// gets (ticket `50c8ec48`).
    ///
    /// # Why this is the important half of that ticket
    ///
    /// Rootless there is no chroot, so the module root is no longer `/` for the
    /// serving process, and the second layer under `refuse options` is simply
    /// gone. What is left is rsync's own path handling plus `munge symlinks`
    /// plus the refusal list — and "left" is a claim, not a measurement, until
    /// the escapes are fired at it. So they are: the same function, the same
    /// assertions, the same [`WeakDaemon`] counter-proof, one value changed.
    ///
    /// The counter-proof is what makes it worth running. `WeakDaemon` also
    /// serves without a chroot; the difference between it and this daemon is
    /// `munge symlinks`, `refuse options` and the absence of `insecure links`.
    /// It leaks `/etc/passwd` (2597 bytes, measured) and this one must not, so a
    /// green run here says the remaining layers do the work — not that the
    /// harness transferred nothing.
    ///
    /// Host only, and on purpose: rsync 3.4.3 in the image refuses to follow a
    /// symlink out of a module whatever the configuration says (`Cross-device
    /// link`), so the counter-proof cannot be produced there. See the note on
    /// [`WeakDaemon`].
    #[test]
    #[ignore]
    fn module_boundaries_without_chroot_on_the_real_daemon() {
        module_boundary_probe(Backend::HostRootless);
    }

    /// The body of the two probes above. `backend` decides which hardening the
    /// configuration is generated for; everything measured is identical.
    fn module_boundary_probe(backend: Backend) {
        let mut probe = Probe::new(backend);
        let (uid, gid) = (probe.uid, probe.gid);

        // The file the escapes are after: one level above the share root.
        let outside = probe.path("outside.txt");
        fs::write(&outside, format!("{OUTSIDE_SENTINEL}\n")).unwrap();

        let share = probe.share("share");
        fs::write(share.join("inside.txt"), format!("{INSIDE_SENTINEL}\n")).unwrap();
        let victim = share.join("victim.txt");
        fs::write(&victim, "do not delete me\n").unwrap();
        // Three server-side symlinks — planted by somebody with access to the
        // share, not uploaded through rsync, which is the case `munge symlinks`
        // does *not* cover and the spike got burned by.
        std::os::unix::fs::symlink(&outside, share.join("escape.link")).unwrap();
        std::os::unix::fs::symlink("../outside.txt", share.join("relative.link")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", share.join("passwd.link")).unwrap();

        let mut registry =
            ModuleRegistry::new(probe.path("etc/rsyncd.conf"), probe.path("etc/secrets"))
                .with_hardening(backend.hardening());
        let module = registry
            .add_pairing(&share, true, uid, gid, 4)
            .expect("pairing");
        // The mode really did reach the file: an assertion here rather than a
        // trusted builder call, because a probe that silently measured the
        // hardened configuration twice would pass and prove nothing.
        let generated = fs::read_to_string(probe.path("etc/rsyncd.conf")).expect("rsyncd.conf");
        if backend.hardening().uses_chroot() {
            assert!(generated.contains("use chroot = yes"), "{generated}");
            assert!(generated.contains("    uid = "), "{generated}");
        } else {
            assert!(generated.contains("use chroot = no"), "{generated}");
            assert!(
                !generated.contains("    uid = ") && !generated.contains("    gid = "),
                "a rootless configuration must not ask for a uid/gid drop:\n{generated}"
            );
        }
        probe.start_daemon();

        let passwd = passwd_marker();
        // Asserts that nothing below `dir` holds anything from outside the
        // module. Used after every escape; `what` names the attempt.
        let clean = |dir: &Path, what: &str| {
            assert!(
                !tree_holds(dir, OUTSIDE_SENTINEL),
                "{what}: the file above the share root reached the client ({})",
                dir.display()
            );
            if let Some(marker) = &passwd {
                assert!(
                    !tree_holds(dir, marker),
                    "{what}: /etc/passwd reached the client ({})",
                    dir.display()
                );
            }
        };

        // --- 1. the control -------------------------------------------------
        // Everything below is "the outside file did not arrive". This is the
        // proof that a file *can* arrive this way, so that a broken harness
        // cannot pass all nine boundaries by transferring nothing at all.
        let control = probe.dst("control");
        let out = probe.rsync(
            &module,
            &[
                &probe.url(&module, &format!("{}/", module.name())),
                &format!("{}/", control.display()),
            ],
        );
        assert!(out.status.success(), "control pull: {}", stderr(&out));
        assert!(
            tree_holds(&control, INSIDE_SENTINEL),
            "the control pull delivered no content, so no later \"nothing \
             leaked\" assertion means anything: {}",
            stderr(&out)
        );

        // --- 5. the symlinks arrived as symlinks, not as their content ------
        // Same transfer as the control: a plain pull of the whole module.
        for name in ["escape.link", "relative.link", "passwd.link"] {
            let path = control.join(name);
            let meta = fs::symlink_metadata(&path)
                .unwrap_or_else(|e| panic!("{name} is missing from the control pull: {e}"));
            assert!(
                meta.file_type().is_symlink(),
                "{name} came across as a regular file, so the daemon followed it"
            );
        }
        clean(&control, "a plain pull of the module");

        // --- 2. `..` in the requested path ----------------------------------
        // rsync sanitises this itself, in every configuration: `link_stat
        // "/outside.txt" (in <module>) failed`. Kept because it is what the
        // ticket asks to be shown, and because a future rsync — or a `path`
        // with a `/./` split — could change it; but see the header, this one
        // cannot be made to fail by weakening the configuration.
        for (attempt, remote) in [
            ("..", format!("{}/../outside.txt", module.name())),
            ("../..", format!("{}/../../etc/passwd", module.name())),
        ] {
            let dst = probe.dst(&format!("dotdot-{}", attempt.len()));
            let out = probe.rsync(
                &module,
                &[&probe.url(&module, &remote), &format!("{}/", dst.display())],
            );
            assert!(
                !out.status.success(),
                "a request through {attempt} succeeded: {}",
                String::from_utf8_lossy(&out.stdout)
            );
            clean(&dst, &format!("a request through {attempt}"));
        }

        // --- 3. an absolute path instead of a module name -------------------
        let dst = probe.dst("absolute");
        let out = probe.rsync(
            &module,
            &[
                &probe.url(&module, "/etc/passwd"),
                &format!("{}/", dst.display()),
            ],
        );
        assert!(!out.status.success(), "an absolute remote path was served");
        assert!(
            stderr(&out).contains("must start with a module name"),
            "an absolute path failed for the wrong reason: {}",
            stderr(&out)
        );
        clean(&dst, "an absolute remote path");

        // --- 4. dereferencing a server-side symlink -------------------------
        // The spike's escape, exactly: the symlink is already in the share and
        // the client asks the daemon to follow it. This is what `refuse
        // options` is for — `munge symlinks` covers uploads, not what is
        // already lying there.
        for option in [
            "-L",
            "--copy-links",
            "--copy-unsafe-links",
            "--copy-dirlinks",
        ] {
            let dst = probe.dst(&format!("deref{}", option.replace('-', "")));
            let out = probe.rsync(
                &module,
                &[
                    option,
                    &probe.url(&module, &format!("{}/", module.name())),
                    &format!("{}/", dst.display()),
                ],
            );
            assert!(
                !out.status.success(),
                "{option} was accepted; a peer could read any file the daemon can"
            );
            assert!(
                stderr(&out).contains("configured to refuse"),
                "{option} failed for the wrong reason: {}",
                stderr(&out)
            );
            clean(&dst, option);
        }

        // --- 6. an unknown module name --------------------------------------
        let dst = probe.dst("unknown");
        let unknown = format!("{}-nope", module.name());
        let out = probe.rsync(
            &module,
            &[
                &probe.url(&module, &format!("{unknown}/")),
                &format!("{}/", dst.display()),
            ],
        );
        assert!(!out.status.success(), "an unknown module was served");
        assert!(
            stderr(&out).contains("Unknown module"),
            "an unknown module failed for the wrong reason: {}",
            stderr(&out)
        );

        // --- 7. the module names are not enumerable -------------------------
        // Without `list = no` this answers with every module name, anonymously
        // and before any authentication — which would make the unguessable
        // module name pointless, because nobody would have to guess it.
        let listing = Command::new("rsync")
            .arg(format!("rsync://127.0.0.1:{}/", probe.port))
            .output()
            .expect("cannot run rsync");
        let listed = String::from_utf8_lossy(&listing.stdout).into_owned();
        assert!(
            listed.trim().is_empty(),
            "the daemon enumerated its modules to an anonymous client: {listed:?}"
        );
        assert!(
            !listed.contains(module.name()),
            "the module name was handed out for free"
        );

        // --- 8. an uploaded symlink is stored munged ------------------------
        // The other direction of the symlink problem: a peer with write access
        // uploads `-> /etc/passwd` and reads it back through the same module.
        // `munge symlinks = yes` prefixes the stored value with
        // `/rsyncd-munged/`, a directory that does not exist, so the daemon
        // cannot follow it. Measured on the host: the value on disk is
        // `/rsyncd-munged//etc/passwd` and the client sees `/etc/passwd` again
        // on the way out.
        let upload = probe.path("upload");
        fs::create_dir_all(&upload).unwrap();
        fs::write(upload.join("plain.txt"), "harmless\n").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", upload.join("evil.link")).unwrap();
        std::os::unix::fs::symlink("../../../../etc/passwd", upload.join("evilrel.link")).unwrap();
        let out = probe.rsync(
            &module,
            &[
                &format!("{}/", upload.display()),
                &probe.url(&module, &format!("{}/up/", module.name())),
            ],
        );
        assert!(out.status.success(), "upload: {}", stderr(&out));
        for name in ["evil.link", "evilrel.link"] {
            let stored = fs::read_link(share.join("up").join(name))
                .unwrap_or_else(|e| panic!("{name} was not stored as a symlink: {e}"));
            let stored = stored.to_string_lossy().into_owned();
            assert!(
                stored.starts_with("/rsyncd-munged/"),
                "an uploaded symlink was stored unmunged as {stored:?}; the daemon \
                 can follow it and the peer can read whatever it points at"
            );
        }
        // And reading the module back does not deliver what they point at.
        let back = probe.dst("back");
        let out = probe.rsync(
            &module,
            &[
                &probe.url(&module, &format!("{}/up/", module.name())),
                &format!("{}/", back.display()),
            ],
        );
        assert!(out.status.success(), "pull back: {}", stderr(&out));
        clean(&back, "an uploaded symlink read back");

        // --- 9. deleting -----------------------------------------------------
        // The full matrix is in `daemon_lifecycle_on_the_host_rsync`; the ones
        // the ticket names are here so that this probe stands on its own.
        //
        // `--remove-sent-files` is the deprecated alias of
        // `--remove-source-files`, and refusal matches the spelling the client
        // sent: with only the modern name on the list a push carrying the alias
        // came back exit 0 on both 3.5.0 and 3.4.3.
        for option in ["--delete", "--remove-source-files", "--remove-sent-files"] {
            let out = probe.rsync(
                &module,
                &[
                    option,
                    &format!("{}/", upload.display()),
                    &probe.url(&module, &format!("{}/up/", module.name())),
                ],
            );
            assert!(!out.status.success(), "{option} was accepted");
            assert!(
                stderr(&out).contains("configured to refuse"),
                "{option} failed for the wrong reason: {}",
                stderr(&out)
            );
            assert!(victim.exists(), "{option} destroyed content in the share");
            assert!(
                upload.join("plain.txt").exists(),
                "{option} destroyed content on the sender's side"
            );
        }

        // --- 9b. destroying without any delete option ------------------------
        // `--force` is not a delete option and does not need to be one: it tells
        // rsync to make way for an incoming entry, and a non-empty directory
        // standing where a file is being written is what gets made way for. A
        // peer with nothing but write access wiped `keep/precious.txt` this way
        // — exit 0, empty stderr, no `--delete` anywhere — until `force` went on
        // the refusal list. The counter-proof for it is in
        // `WeakDaemon::assert_the_boundaries_can_be_broken`.
        //
        // Three shapes of the same attack, all measured to destroy on 3.5.0 and
        // 3.4.3 without the refusal: a file over a non-empty directory, a file
        // over a directory whose content sits one level deeper, and a symlink in
        // place of the file.
        let clobber = probe.path("clobber");
        for (label, deep, as_symlink) in [
            ("file over a non-empty directory", false, false),
            ("file over a directory with nested content", true, false),
            ("symlink over a non-empty directory", false, true),
        ] {
            let _ = fs::remove_dir_all(&clobber);
            fs::create_dir_all(&clobber).unwrap();
            let victim_dir = share.join("keep");
            // It may be a directory from the previous shape, or — if the
            // refusal ever regresses — the file or symlink that replaced it.
            let _ = fs::remove_file(&victim_dir);
            let _ = fs::remove_dir_all(&victim_dir);
            let nested = if deep {
                victim_dir.join("sub")
            } else {
                victim_dir.clone()
            };
            fs::create_dir_all(&nested).unwrap();
            let precious = nested.join("precious.txt");
            fs::write(&precious, "PRECIOUS\n").unwrap();
            if as_symlink {
                std::os::unix::fs::symlink("/etc/hostname", clobber.join("keep")).unwrap();
            } else {
                fs::write(clobber.join("keep"), "i am a file\n").unwrap();
            }

            let out = probe.rsync(
                &module,
                &[
                    "--force",
                    &format!("{}/", clobber.display()),
                    &probe.url(&module, &format!("{}/", module.name())),
                ],
            );
            assert!(
                !out.status.success(),
                "--force was accepted for a {label}: {}",
                stderr(&out)
            );
            assert!(
                stderr(&out).contains("configured to refuse"),
                "--force failed for the wrong reason on a {label}: {}",
                stderr(&out)
            );
            assert!(
                precious.exists(),
                "--force destroyed content in the share ({label}) with no delete \
                 option in sight"
            );
            let _ = fs::remove_file(&victim_dir);
            let _ = fs::remove_dir_all(&victim_dir);
        }
        let _ = fs::remove_dir_all(&clobber);

        // The generated configuration produced no parser complaint on the way.
        let log = probe.daemon_log();
        assert!(
            !log.to_lowercase().contains("unknown parameter"),
            "the generated configuration produced parser warnings:\n{log}"
        );
        println!("--- {backend:?} daemon log ---\n{log}");

        // -------------------------------------------------------------------
        // The counter-proof
        // -------------------------------------------------------------------
        let weak = WeakDaemon::start(&probe.base);
        weak.assert_the_boundaries_can_be_broken(passwd.as_deref());

        probe.stop();
        drop(weak);
        let _ = fs::remove_dir_all(&probe.base);
    }

    /// A daemon with every symlink and enumeration defence switched off.
    ///
    /// It exists so that "nothing escaped from the hardened daemon" is a
    /// statement about the hardening and not about the harness. Every check the
    /// probe above makes is aimed at this daemon as well, and has to come out
    /// the other way round.
    ///
    /// It needs no user namespace: `use chroot = no` and no `uid`/`gid`, so it
    /// runs as the invoking user — which is also why it can read `/etc/passwd`
    /// and hand it out.
    ///
    /// # Why there is no container variant of this probe
    ///
    /// Measured in `alpine:3.22` (rsync 3.4.3, what the image ships), with the
    /// share, the outside file and the destination all on one filesystem so
    /// that no mount boundary could be doing the work:
    ///
    /// | daemon | this configuration | with `insecure links = yes` |
    /// |---|---|---|
    /// | 3.5.0 (host) | no leak (`Too many levels of symbolic links`) | **`/etc/passwd` delivered** |
    /// | 3.4.3 (image) | no leak (`Cross-device link (18)`) | no leak, same message |
    ///
    /// So 3.4.3 refuses to follow a symlink out of a module *whatever* these
    /// parameters say — it neither warns about `insecure links` as an unknown
    /// parameter nor lets it re-open anything. The counter-proof can therefore
    /// only be produced on 3.5.0, and a `Backend::Docker` variant of this probe
    /// would fail its own counter-proof assertions for a reason that has
    /// nothing to do with the harness. That is good news about the image and a
    /// reason to leave the probe on the host, not a gap to be filled in.
    struct WeakDaemon {
        base: PathBuf,
        share: PathBuf,
        port: u16,
        password: PathBuf,
        pid_file: PathBuf,
        daemon: Option<Child>,
    }

    impl WeakDaemon {
        /// Secret and module name are fixed: nothing here is protecting
        /// anything, and a generated pair would only obscure the fixture.
        const MODULE: &'static str = "weak";
        const SECRET: &'static str = "weak-secret-not-protecting-anything";

        fn start(under: &Path) -> Self {
            let seq = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let base = under.join(format!("weak-{seq}"));
            let share = base.join("share");
            fs::create_dir_all(&share).expect("weak share");

            // The same content the hardened share has, so the two runs differ
            // in the configuration and in nothing else.
            let outside = base.join("outside.txt");
            fs::write(&outside, format!("{OUTSIDE_SENTINEL}\n")).unwrap();
            fs::write(share.join("inside.txt"), format!("{INSIDE_SENTINEL}\n")).unwrap();
            fs::write(share.join("victim.txt"), "do not delete me\n").unwrap();
            std::os::unix::fs::symlink(&outside, share.join("escape.link")).unwrap();
            std::os::unix::fs::symlink("../outside.txt", share.join("relative.link")).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", share.join("passwd.link")).unwrap();

            let secrets = base.join("weak.secrets");
            write_private_file(&secrets, &format!("{}:{}\n", Self::MODULE, Self::SECRET))
                .expect("weak secrets");
            let password = base.join("weak.pw");
            write_private_file(&password, &format!("{}\n", Self::SECRET)).expect("weak password");

            let log = base.join("weak.log");
            let pid_file = base.join("weak.pid");
            let conf = base.join("weak.conf");
            fs::write(
                &conf,
                format!(
                    "address = 127.0.0.1\n\
                     log file = {log}\n\
                     \n\
                     [{module}]\n\
                     \x20   path = {share}\n\
                     \x20   auth users = {module}\n\
                     \x20   secrets file = {secrets}\n\
                     \x20   list = yes\n\
                     \x20   read only = no\n\
                     \x20   use chroot = no\n\
                     \x20   munge symlinks = no\n\
                     \x20   insecure links = yes\n\
                     \x20   max connections = 4\n",
                    log = log.display(),
                    module = Self::MODULE,
                    share = share.display(),
                    secrets = secrets.display(),
                ),
            )
            .expect("weak configuration");

            let port = probe_port(seq);
            let child = Command::new("rsync")
                .args([
                    "--daemon".to_string(),
                    "--no-detach".to_string(),
                    format!("--config={}", conf.display()),
                    format!("--port={port}"),
                    format!("--dparam=pid file={}", pid_file.display()),
                    format!("--dparam=lock file={}", base.join("weak.lock").display()),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("cannot start the unhardened daemon");

            let mut weak = Self {
                base,
                share,
                port,
                password,
                pid_file,
                daemon: Some(child),
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                if fs::read_to_string(&log)
                    .map(|l| l.contains("listening on port"))
                    .unwrap_or(false)
                {
                    return weak;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            weak.stop();
            panic!(
                "the unhardened daemon did not start; log: {:?}",
                fs::read_to_string(&log)
            );
        }

        fn rsync(&self, args: &[&str]) -> Output {
            Command::new("rsync")
                .arg("-a")
                .args(["--no-owner", "--no-group"])
                .arg(format!("--password-file={}", self.password.display()))
                .args(args)
                .output()
                .expect("cannot run rsync")
        }

        fn url(&self, path: &str) -> String {
            format!(
                "rsync://{module}@127.0.0.1:{port}/{path}",
                module = Self::MODULE,
                port = self.port
            )
        }

        /// Every boundary the hardened daemon held, broken here.
        ///
        /// If any of these comes out "still safe", the matching assertion in
        /// [`module_boundaries_on_the_real_daemon`] proves nothing and has to
        /// be reworked or dropped — see the note in AGENTS.md about tests that
        /// cannot fail.
        fn assert_the_boundaries_can_be_broken(&self, passwd: Option<&str>) {
            // 4 + 5: dereferencing the server-side symlinks now delivers the
            // files behind them.
            let dst = self.base.join("dst-deref");
            fs::create_dir_all(&dst).expect("destination dir");
            let out = self.rsync(&[
                "-L",
                &self.url(&format!("{}/", Self::MODULE)),
                &format!("{}/", dst.display()),
            ]);
            assert!(
                tree_holds(&dst, OUTSIDE_SENTINEL),
                "the counter-proof did not leak the file above the share root, so \
                 the symlink assertions in the hardened run cannot fail and are \
                 worthless: {}",
                stderr(&out)
            );
            if let Some(marker) = passwd {
                assert!(
                    tree_holds(&dst, marker),
                    "the counter-proof did not leak /etc/passwd; the spike's own \
                     escape is therefore not being reproduced: {}",
                    stderr(&out)
                );
            }

            // 7: the module names are handed out anonymously.
            let listing = Command::new("rsync")
                .arg(format!("rsync://127.0.0.1:{}/", self.port))
                .output()
                .expect("cannot run rsync");
            let listed = String::from_utf8_lossy(&listing.stdout).into_owned();
            assert!(
                listed.contains(Self::MODULE),
                "the counter-proof did not enumerate its modules, so the \
                 `list = no` assertion cannot fail: {listed:?}"
            );

            // 8: an uploaded symlink is stored verbatim and can be followed.
            let upload = self.base.join("weak-upload");
            fs::create_dir_all(&upload).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", upload.join("evil.link")).unwrap();
            let out = self.rsync(&[
                &format!("{}/", upload.display()),
                &self.url(&format!("{}/up/", Self::MODULE)),
            ]);
            assert!(out.status.success(), "weak upload: {}", stderr(&out));
            let stored = fs::read_link(self.share.join("up").join("evil.link"))
                .expect("the uploaded symlink");
            let stored = stored.to_string_lossy().into_owned();
            assert!(
                !stored.starts_with("/rsyncd-munged/"),
                "the counter-proof munged the uploaded symlink anyway, so the \
                 munge assertion cannot fail: {stored:?}"
            );
            // Measured: `etc/passwd`, not `/etc/passwd`. With `munge symlinks`
            // off and the module served without a chroot, rsync still sanitises
            // a stored symlink value — it drops the leading slash and any
            // leading `..` — so the value cannot name a path above the module
            // even here. That is a *third* layer and it is worth knowing about,
            // but it is not the one under test: it constrains where an uploaded
            // symlink may point, while munging makes it unfollowable at all.
            println!("counter-proof: the uploaded symlink was stored as {stored:?}");

            // 9: deleting is accepted, and it deletes.
            let victim = self.share.join("victim.txt");
            assert!(victim.exists());
            let source = self.base.join("weak-source");
            fs::create_dir_all(&source).unwrap();
            fs::write(source.join("only.txt"), "the only file\n").unwrap();
            let out = self.rsync(&[
                "--delete",
                &format!("{}/", source.display()),
                &self.url(&format!("{}/", Self::MODULE)),
            ]);
            assert!(
                out.status.success() && !victim.exists(),
                "the counter-proof did not delete anything, so the `--delete` \
                 assertions cannot fail: {}",
                stderr(&out)
            );

            // 9b: `--force` destroys a non-empty directory here, with no
            // delete option involved. Without this half, the `--force`
            // assertions in the hardened run could be passing because the
            // attack does not work at all rather than because it is refused.
            let victim_dir = self.share.join("keep");
            let _ = fs::remove_dir_all(&victim_dir);
            fs::create_dir_all(&victim_dir).unwrap();
            let precious = victim_dir.join("precious.txt");
            fs::write(&precious, "PRECIOUS\n").unwrap();
            let clobber = self.base.join("weak-clobber");
            let _ = fs::remove_dir_all(&clobber);
            fs::create_dir_all(&clobber).unwrap();
            fs::write(clobber.join("keep"), "i am a file\n").unwrap();
            let out = self.rsync(&[
                "--force",
                &format!("{}/", clobber.display()),
                &self.url(&format!("{}/", Self::MODULE)),
            ]);
            assert!(
                out.status.success() && !precious.exists(),
                "the counter-proof did not destroy the non-empty directory, so \
                 the --force assertions cannot fail and prove nothing: {}",
                stderr(&out)
            );
            // And the same push without `--force` leaves it alone — which is
            // what makes the line above a statement about `--force` rather than
            // about pushing a file named `keep`. `keep` is a plain *file* now,
            // so it has to be unlinked before the directory can come back.
            let _ = fs::remove_file(&victim_dir);
            let _ = fs::remove_dir_all(&victim_dir);
            fs::create_dir_all(&victim_dir).unwrap();
            fs::write(&precious, "PRECIOUS\n").unwrap();
            let out = self.rsync(&[
                &format!("{}/", clobber.display()),
                &self.url(&format!("{}/", Self::MODULE)),
            ]);
            assert!(
                precious.exists(),
                "the same push without --force destroyed the directory as well, \
                 so --force is not what is being measured: {}",
                stderr(&out)
            );

            println!(
                "--- counter-proof: every boundary above was broken on the \
                 unhardened daemon (port {}) ---",
                self.port
            );
        }

        /// SIGTERM, never SIGKILL — a hard kill is what leaves partials behind.
        fn stop(&mut self) {
            if let Some(mut child) = self.daemon.take() {
                let _ = Command::new("kill")
                    .args(["-TERM", &child.id().to_string()])
                    .status();
                let _ = child.wait();
            }
            let _ = fs::remove_file(&self.pid_file);
        }
    }

    impl Drop for WeakDaemon {
        fn drop(&mut self) {
            self.stop();
        }
    }
}
