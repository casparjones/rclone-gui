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
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use tokio::io::{AsyncBufReadExt as _, BufReader};
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
//   * `delete remove-source-files` in the same list — a pairing carries write
//     access, and without this a peer that may write may also *destroy*: a push
//     with `--delete` removed every file in the share that the sender did not
//     have, exit 0, measured. `remove-source-files` is the same weapon pointed
//     the other way, it empties the *sender's* directory. Both are refused
//     unconditionally today; see [`REFUSED_OPTIONS`] for what has to happen
//     once the scope model knows `rsync:delete`, and for why the entry is the
//     bare word `delete` and emphatically not the wildcard `delete*`.
//
//   * `use chroot = yes` — usable since the base image moved to alpine:3.22
//     (ticket 3f276e8c); on musl 1.2.4 it broke every transfer with exit 23.
//     It is the second layer under `refuse options`.
//
//   * one module per pairing, writable by default — only push is supported,
//     there is no second read-only module for pull.
// ---------------------------------------------------------------------------

/// The daemon listens on loopback only; stunnel on 874 is the sole entry point.
pub const DAEMON_ADDRESS: &str = "127.0.0.1";
/// Local rsync daemon port behind the TLS terminator.
pub const DAEMON_PORT: u16 = 873;
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
/// whatever is pushed through it.
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
pub const REFUSED_OPTIONS: &str =
    "copy-links copy-dirlinks copy-unsafe-links delete remove-source-files";

/// Prefix of a generated module name. Carries no information about the share.
const MODULE_NAME_PREFIX: &str = "pair";
/// Random bytes behind the prefix, rendered as hex (16 characters, 64 bits).
const MODULE_NAME_RANDOM_BYTES: usize = 8;
/// Entropy of a module secret. The ticket requires at least 32 bytes.
const SECRET_BYTES: usize = 32;
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
#[derive(Debug, Clone)]
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
    fn render(&self, secrets_file: &str) -> Result<String> {
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
        Ok(format!(
            "[{name}]\n\
             \x20   path = {path}\n\
             \x20   auth users = {name}\n\
             \x20   secrets file = {secrets}\n\
             \x20   list = no\n\
             \x20   read only = {read_only}\n\
             \x20   use chroot = yes\n\
             \x20   munge symlinks = yes\n\
             \x20   uid = {uid}\n\
             \x20   gid = {gid}\n\
             \x20   max connections = {max_connections}\n\
             {temp_dir}\
             \x20   refuse options = {refused}\n",
            name = self.name,
            path = self.path,
            secrets = secrets_file,
            read_only = if self.read_only { "yes" } else { "no" },
            uid = self.uid,
            gid = self.gid,
            max_connections = self.max_connections,
            refused = REFUSED_OPTIONS,
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
            modules: Vec::new(),
        }
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
        out.push_str(&format!("port = {DAEMON_PORT}\n"));
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
            out.push_str(&module.render(secrets)?);
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

    /// The path of the generated `rsyncd.conf`.
    pub fn conf_path(&self) -> &Path {
        &self.conf_path
    }

    /// The configuration as it stands on disk.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
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
}

impl DaemonSettings {
    /// Settings for the configuration at `conf_path`, with the pid, lock and
    /// log files under `run_dir`.
    pub fn new(conf_path: impl Into<PathBuf>, run_dir: impl Into<PathBuf>) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_RSYNC_BINARY),
            conf_path: conf_path.into(),
            run_dir: run_dir.into(),
            port: DAEMON_PORT,
            extra_dparams: Vec::new(),
            temp_file_min_age: DEFAULT_TEMP_FILE_MIN_AGE,
            sweep_temp_files: true,
        }
    }

    /// Use a different rsync binary, e.g. one inside a container.
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Listen on a different port. Only the probes need this; in production the
    /// port is [`DAEMON_PORT`] behind the TLS terminator.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Pass an extra `--dparam=<key>=<value>` to the daemon.
    ///
    /// Meant for the probes (`strict modes=no` when the configuration is
    /// bind-mounted from another user). Production settings belong in the
    /// generated configuration, not here.
    pub fn with_dparam(mut self, param: impl Into<String>) -> Self {
        self.extra_dparams.push(param.into());
        self
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

    /// The port the daemon listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The full argument vector, in the order the daemon sees it.
    fn argv(&self) -> Vec<String> {
        let mut args = vec![
            "--daemon".to_string(),
            "--no-detach".to_string(),
            format!("--config={}", self.conf_path.display()),
            format!("--port={}", self.port),
            format!("--dparam=pid file={}", self.pid_file().display()),
            format!("--dparam=lock file={}", self.lock_file().display()),
            format!("--log-file={}", self.log_file().display()),
        ];
        for param in &self.extra_dparams {
            args.push(format!("--dparam={param}"));
        }
        args
    }
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
    last_error: Option<String>,
    /// Child pid of the daemon -> the module that connection is serving.
    connections: HashMap<u32, String>,
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
        fs::create_dir_all(&settings.run_dir).with_context(|| {
            format!(
                "cannot create the daemon run directory {}",
                settings.run_dir.display()
            )
        })?;
        registry
            .lock()
            .await
            .apply()
            .context("cannot publish the module configuration before starting the daemon")?;

        let handle = Arc::new(Self {
            settings,
            registry,
            state: Arc::new(TokioMutex::new(DaemonState::default())),
            stopping: Arc::new(AtomicBool::new(false)),
            supervisor: TokioMutex::new(None),
        });

        let task = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.supervise().await }
        });
        *handle.supervisor.lock().await = Some(task);

        handle.wait_until_listening().await?;
        Ok(handle)
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

    /// Block until the daemon reports that it is listening, or give up.
    async fn wait_until_listening(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while tokio::time::Instant::now() < deadline {
            {
                let state = self.state.lock().await;
                if state.already_running_elsewhere {
                    return Err(anyhow!(
                        "another rsync daemon already holds the pid file lock at {}; \
                         refusing to run a second one",
                        self.settings.pid_file().display()
                    ));
                }
                if state.pid.is_some()
                    && fs::read_to_string(self.settings.log_file())
                        .map(|log| log.contains("listening on port"))
                        .unwrap_or(false)
                {
                    return Ok(());
                }
            }
            tokio::time::sleep(LOG_POLL_INTERVAL).await;
        }
        let last = self.state.lock().await.last_error.clone();
        Err(anyhow!(
            "the rsync daemon did not start within 30 seconds{}",
            last.map(|e| format!(": {e}")).unwrap_or_default()
        ))
    }

    /// Start the daemon, wait for it, restart it, until told to stop.
    async fn supervise(self: Arc<Self>) {
        let mut consecutive_failures: u32 = 0;
        while !self.stopping.load(Ordering::SeqCst) {
            let started = tokio::time::Instant::now();
            match self.run_once().await {
                Ok(status) => {
                    if self.stopping.load(Ordering::SeqCst) {
                        tracing::info!(?status, "the rsync daemon exited during shutdown");
                        break;
                    }
                    tracing::warn!(?status, "the rsync daemon exited unexpectedly; restarting");
                    self.state.lock().await.restarts += 1;
                }
                Err(e) => {
                    tracing::error!(error = %e, "cannot start the rsync daemon");
                    self.state.lock().await.last_error = Some(e.to_string());
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
            tokio::time::sleep(backoff).await;
        }
        self.state.lock().await.pid = None;
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
            state.already_running_elsewhere = false;
        }
        tracing::info!(
            pid,
            port = self.settings.port,
            address = DAEMON_ADDRESS,
            conf = %self.settings.conf_path.display(),
            "rsync daemon started"
        );

        let finished = Arc::new(AtomicBool::new(false));
        let mirror = tokio::spawn(mirror_log_file(
            log_path,
            Arc::clone(&self.state),
            Arc::clone(&finished),
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
        let status = child.wait().await.context("cannot wait for the daemon")?;

        finished.store(true, Ordering::SeqCst);
        let _ = mirror.await;
        for task in [stdout, stderr].into_iter().flatten() {
            let _ = task.await;
        }

        {
            let mut state = self.state.lock().await;
            state.pid = None;
            state.connections.clear();
            if !status.success() {
                state.last_error = Some(format!("the rsync daemon exited with {status}"));
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
) {
    let mut offset: u64 = 0;
    let mut pending = String::new();
    let mut last_prune = tokio::time::Instant::now();
    loop {
        let done = finished.load(Ordering::SeqCst);
        match read_from(&path, offset).await {
            Ok((chunk, new_offset)) => {
                offset = new_offset;
                pending.push_str(&chunk);
                while let Some(index) = pending.find('\n') {
                    let line: String = pending.drain(..=index).collect();
                    handle_log_line(line.trim_end(), &state).await;
                }
            }
            Err(e) => {
                tracing::debug!(log = %path.display(), error = %e, "cannot read the daemon log");
            }
        }
        if done {
            if !pending.is_empty() {
                handle_log_line(pending.trim_end(), &state).await;
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

/// Mirror one log line and update the connection table from it.
async fn handle_log_line(line: &str, state: &Arc<TokioMutex<DaemonState>>) {
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
        return;
    };
    state.connections.retain(|pid, _| is_child_of(*pid, daemon));
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
             remove-source-files\n",
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
             remove-source-files\n"
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

    /// A write-only peer must not be able to destroy anything.
    ///
    /// The exact spelling matters and is measured, not assumed: see the note on
    /// [`REFUSED_OPTIONS`]. A wildcard `delete*` lets `--delete-missing-args`
    /// through on both rsync 3.4.3 and 3.5.0, so the constant must carry the
    /// bare word — and must keep carrying it after somebody decides the list
    /// looks repetitive.
    #[test]
    fn every_module_refuses_every_way_of_deleting() {
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
        assert!(
            refused.contains(&"remove-source-files"),
            "--remove-source-files empties the sender's directory and has no group"
        );
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
        // Without --log-file the daemon logs to syslog and there is nothing to
        // mirror; measured, stderr stays empty.
        assert!(argv
            .iter()
            .any(|a| a == "--log-file=/run/rsyncd/rsyncd.log"));
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

        let rendered = writable.render("/etc/rsyncd/secrets").unwrap();
        assert!(
            rendered.contains(&format!("temp dir = /{MODULE_TEMP_DIR}")),
            "a writable module must keep its temp files out of the share root: {rendered}"
        );
        // Measured on 3.4.3 and 3.5.0: the value is resolved against the module
        // root in both chroot modes, so it is a leading slash and no path.
        assert!(!rendered.contains(&format!("temp dir = {}", share.display())));
        assert!(
            !read_only
                .render("/etc/rsyncd/secrets")
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

    use std::os::unix::fs::MetadataExt as _;
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
        /// The rsync of the runtime image, inside a container.
        Docker,
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
                Backend::Docker => {
                    self.start_container();
                    let mut c = Command::new("docker");
                    c.args(["exec", &self.container, "rsync", "--dparam=strict modes=no"]);
                    c
                }
            };
            let child = command
                .args(args)
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
                Backend::Host => Command::new("rsync"),
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

        // --- 2. every way of deleting is refused, the share survives ---------
        for option in [
            "--delete",
            "--delete-before",
            "--delete-during",
            "--delete-delay",
            "--delete-after",
            "--delete-excluded",
            "--delete-missing-args",
            "--remove-source-files",
            "--del",
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
}
