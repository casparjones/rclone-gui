//! Die rsync-Engine: **Push** in ein Modul der Gegenseite über `rsync-ssl`.
//!
//! Alles Gemeinsame — Job-Anlage, Eigentümer, Statusverwaltung, Logdatei,
//! Prozessstart, Exit-Auswertung — bleibt im Elternmodul
//! [`crate::handlers::sync`]. Hier steht nur, was rsync von rclone
//! unterscheidet: der Aufruf, die Übergabe des Modul-Secrets und das Lesen des
//! Fortschritts aus `--info=progress2`.
//!
//! Der Aufruf ist nicht erfunden, sondern die im Spike (`docs/rsync-transport.md`)
//! gemessene Zeile:
//!
//! ```text
//! RSYNC_SSL_TYPE=openssl RSYNC_SSL_CA_CERT=<ca> \
//! rsync-ssl -a --partial --partial-dir=.rsync-partial --modify-window=-1 \
//!   --info=progress2 --stats --password-file=<0600-Datei> \
//!   <quelle>/ rsync://<modul>@<host>:874/<modul>/<zielpfad>
//! ```
//!
//! Drei Punkte daran sind **keine Kür**:
//!
//! * **`--modify-window=-1`.** Ohne den Parameter überspringt rsyncs
//!   Quick-Check eine Datei, die in *derselben Sekunde* geändert wurde wie der
//!   letzte Lauf: 74 B gesendet, der Zielinhalt bleibt falsch, und es gibt
//!   weder Fehler noch Warnung. Für ein Sync-Werkzeug ist das der schlimmste
//!   Fehlermodus, den es gibt. Gemessen im Spike, abgesichert durch
//!   [`tests::modify_window_is_never_missing`] und den Ende-zu-Ende-Nachweis im
//!   Ticketkommentar.
//! * **`--partial --partial-dir`.** Bei Wiederaufnahme nach einem Abbruch real
//!   33,8 % Ersparnis; ohne `--partial` gehen 100 % des Teiltransfers verloren.
//! * **`--password-file`.** Das Secret geht **niemals** über `argv` (systemweit
//!   über `/proc/<pid>/cmdline` lesbar) und auch nicht über `RSYNC_PASSWORD`
//!   (die Manpage empfiehlt ausdrücklich die Datei). Die Datei hat Modus 0600,
//!   liegt in einem 0700-Verzeichnis und wird vom gemeinsamen Runner nach dem
//!   Prozessende gelöscht ([`super::EngineCommand::temp_files`]).
//!
//! **Nur Push.** Entscheidung E3 im Spike: es gibt keinen Pull-Aufruf, damit
//! die Gegenseite kein zweites, lesbares Modul braucht.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use super::{
    classify_rsync_exit, is_dry_run, path_segments, EngineCommand, JobSpec, JobStatus,
    ProgressSnapshot, ProgressSource, SyncEngine, TransferMode,
};

/// Verzeichnis mit den Gegenstellen (eine `<name>.json` je Peer).
/// Über `RCLONE_GUI_PEERS_DIR` verlegbar, damit ein Test nicht im echten
/// `data/` arbeiten muss.
pub(crate) const PEERS_DIR_ENV: &str = "RCLONE_GUI_PEERS_DIR";
const DEFAULT_PEERS_DIR: &str = "data/peers";

/// Verzeichnis für die kurzlebigen Password-Dateien. Eigenes Verzeichnis mit
/// Modus 0700, damit die 0600-Datei nicht einmal aufgelistet werden kann.
const RUN_DIR_ENV: &str = "RCLONE_GUI_RSYNC_RUN_DIR";
const DEFAULT_RUN_DIR: &str = "data/rsync-run";

/// Der TLS-Port der Gegenstelle (stunnel vor dem lokalen `rsyncd:873`).
/// Der Klartextmodus auf 873 ist Entscheidung E2 — er ist **nicht** im Produkt.
const DEFAULT_TLS_PORT: u16 = 874;

/// Abbruch nach dieser Zeit ohne Datenverkehr. rsync kennt von Haus aus
/// **kein** Timeout; ohne diese Option bleibt ein hängender Transfer für immer
/// `Running`, und ein solcher Job ist auch nicht löschbar. 600 s sind
/// grosszügig — die Option zählt nur Leerlauf, nicht die Gesamtdauer.
const IO_TIMEOUT_SECS: u32 = 600;

/// Teiltransfers landen hier, nicht als `.name.XXXXXX` im Zielverzeichnis.
/// Die Serverseite hat dafür zusätzlich `temp dir` im Modul; der Client setzt
/// es trotzdem, weil er nicht wissen kann, ob die Gegenstelle so modern ist.
const PARTIAL_DIR: &str = ".rsync-partial";

/// Das Modul-Secret der Gegenstelle.
///
/// Eigener Typ mit **von Hand** geschriebenem [`fmt::Debug`], das den Wert
/// maskiert. Der Wächter `tests/no_debug_leaks.rs` kennt nur Feldnamen; er
/// hätte ein `derive(Debug)` über einem Feld `secret` gemeldet — die Lösung ist
/// nicht, den Namen zu vermeiden, sondern den Wert unerreichbar zu machen.
pub struct ModuleSecret(String);

impl ModuleSecret {
    /// Der Klartext. Bewusst so benannt, dass jede Fundstelle auffällt: es gibt
    /// genau eine, das Schreiben der Password-Datei.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ModuleSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redigiert, nicht entfernt: die Länge hilft beim Debuggen einer
        // fehlgeschlagenen Anmeldung, der Wert nicht.
        write!(f, "ModuleSecret(<redigiert, {} Zeichen>)", self.0.len())
    }
}

/// Eine gekoppelte Gegenstelle.
///
/// Entsteht **nur** aus [`lookup_peer`], also aus einer Datei, die dem Server
/// gehört und Modus 0600 hat. Kein Feld kommt aus dem Request.
pub struct PeerTarget {
    /// Der Name, unter dem die Gegenstelle im Request steht (`remote_name`).
    name: String,
    host: String,
    port: u16,
    module: String,
    secret: ModuleSecret,
    /// Die CA, gegen die `rsync-ssl` Kette **und** SAN-Hostnamen prüft.
    ca_cert: PathBuf,
}

impl fmt::Debug for PeerTarget {
    /// Von Hand, weil `secret` im Struct steht. Alles andere bleibt sichtbar —
    /// eine `Debug`-Ausgabe ohne Bezug wäre zum Debuggen wertlos.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerTarget")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("module", &self.module)
            .field("secret", &self.secret)
            .field("ca_cert", &self.ca_cert)
            .finish()
    }
}

/// Die Datei auf der Platte. Absichtlich **ohne** `Debug`.
#[derive(Deserialize)]
struct PeerFile {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    module: String,
    secret: String,
    /// Pfad zur CA. Relativ wird gegen das Peer-Verzeichnis aufgelöst.
    ca_cert: String,
}

/// Die Sperre um `RCLONE_GUI_PEERS_DIR`.
///
/// `std::env::set_var` wirkt **prozessweit**, und `cargo test` fährt alle Tests
/// in einem Prozess. Die Sperre steht deshalb hier und nicht im Testmodul: die
/// Tests der Verdrahtung in `sync.rs` (`select_engine`) verlegen dasselbe
/// Verzeichnis und müssen sich mit den Registry-Tests hier serialisieren. Zwei
/// getrennte Sperren wären keine.
#[cfg(test)]
pub(crate) fn peers_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let lock = LOCK.get_or_init(|| std::sync::Mutex::new(()));
    // Vergiftung wieder abräumen. Ein Test, der **während** er die Sperre hält
    // durchfällt, würde sonst jeden folgenden Test dieser Gruppe mit
    // `PoisonError` mitreissen — aus einem Fehlschlag würden fünf, und der
    // eigentliche Befund ginge in der Kaskade unter. Gemessen beim
    // Mutationsnachweis zu `ae3fdab2`.
    lock.clear_poison();
    lock
}

/// Das Peer-Verzeichnis dieser Instanz.
fn peers_dir() -> PathBuf {
    PathBuf::from(std::env::var(PEERS_DIR_ENV).unwrap_or_else(|_| DEFAULT_PEERS_DIR.to_string()))
}

/// Das Verzeichnis für Password-Dateien.
fn run_dir() -> PathBuf {
    PathBuf::from(std::env::var(RUN_DIR_ENV).unwrap_or_else(|_| DEFAULT_RUN_DIR.to_string()))
}

/// Ist `remote_name` eine gekoppelte Gegenstelle?
///
/// `Ok(None)` heisst „nein, das ist ein rclone-Remote" — der Aufrufer prüft es
/// dann wie bisher gegen die `rclone.conf`. `Err` heisst „es *ist* eine
/// Gegenstelle, aber ihre Hinterlegung ist unbrauchbar"; das wird abgelehnt,
/// **bevor** ein Job entsteht, und nicht stillschweigend zu rclone
/// umgeleitet — sonst liefe ein Push in ein gleichnamiges rclone-Remote.
pub async fn lookup_peer(remote_name: &str) -> Result<Option<PeerTarget>> {
    // Der Name kommt vom Client. Erst prüfen, dann in einen Pfad einsetzen.
    // `validate_remote_name` verbietet unter anderem `/`, `\`, `:` und
    // Steuerzeichen; ein Ausbruch aus dem Peer-Verzeichnis ist damit nicht
    // möglich. Ein *ungültiger* Name ist hier kein Fehler, sondern „kein
    // Peer": die Meldung dafür soll die bestehende aus der rclone-Prüfung
    // bleiben, wortgleich wie vorher.
    if crate::config_manager::validate_remote_name(remote_name).is_err() {
        return Ok(None);
    }

    let path = peers_dir().join(format!("{}.json", remote_name));
    let raw = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            // Der Pfad steht im Log, nicht in der Antwort: er verrät, welche
            // Gegenstellen es gibt.
            warn!("Gegenstelle {} nicht lesbar: {}", path.display(), e);
            bail!("Die Hinterlegung dieser Gegenstelle ist nicht lesbar");
        }
    };

    // Die Datei trägt das Modul-Secret. Ist sie für Gruppe oder Welt lesbar,
    // ist das Secret bereits verloren — dann wird nicht übertragen, sondern
    // abgelehnt. Genau dieselbe Prüfung macht rsync selbst mit der
    // Password-Datei, und aus demselben Grund.
    let mode = tokio::fs::metadata(&path)
        .await
        .with_context(|| "Modus der Peer-Datei nicht lesbar")?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        warn!(
            "Gegenstelle {} hat Modus {:o} — muss 0600 sein",
            path.display(),
            mode & 0o7777
        );
        bail!(
            "Die Hinterlegung dieser Gegenstelle ist für andere Konten lesbar (Modus muss 0600 \
             sein). Sie trägt das Modul-Secret; die Übertragung wird deshalb nicht gestartet."
        );
    }

    let file: PeerFile = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("Die Hinterlegung dieser Gegenstelle ist ungültig: {}", e))?;

    Ok(Some(PeerTarget::from_file(remote_name, file)?))
}

impl PeerTarget {
    fn from_file(name: &str, file: PeerFile) -> Result<Self> {
        let host = check_host(&file.host)?;
        let module = check_module(&file.module)?;
        let port = match file.port {
            Some(0) | None => DEFAULT_TLS_PORT,
            Some(port) => port,
        };
        if file.secret.trim().is_empty() {
            bail!("Die Gegenstelle hat kein Secret hinterlegt");
        }
        // Ein Secret mit Zeilenumbruch würde die Password-Datei zerreissen;
        // rsync liest nur die erste Zeile, der Rest wäre stiller Datenmüll.
        if file.secret.contains('\n') || file.secret.contains('\r') || file.secret.contains('\0') {
            bail!("Das Secret der Gegenstelle enthält ungültige Zeichen");
        }

        Ok(Self {
            name: name.to_string(),
            host,
            port,
            module,
            secret: ModuleSecret(file.secret),
            ca_cert: check_ca_cert(&file.ca_cert)?,
        })
    }

    /// `rsync://<modul>@<host>:<port>/<modul>/<pfad>`
    ///
    /// Der Modulname steht zweimal drin, und das ist kein Fehler: einmal als
    /// Benutzername für `auth users`, einmal als Modul. So macht es das
    /// Pairing, so steht es im Spike.
    fn url(&self, target_path: &str) -> String {
        let mut url = format!(
            "rsync://{}@{}:{}/{}",
            self.module, self.host, self.port, self.module
        );
        if !target_path.is_empty() {
            url.push('/');
            url.push_str(target_path);
        }
        // Abschliessender `/`: rsync legt den Zielordner dann als Ordner an,
        // statt eine gleichnamige Datei zu erzeugen.
        url.push('/');
        url
    }
}

/// Hostname der Gegenstelle.
///
/// Muss der Name sein, der im **SAN des Zertifikats** steht: gemessen im Spike
/// endet eine Verbindung über die IP statt über den SAN-Namen mit
/// `verify error:num=62:hostname mismatch` (exit 5). Erlaubt sind deshalb nur
/// die Zeichen, aus denen ein DNS-Name oder eine IPv4-Adresse besteht.
///
/// IPv6 ist damit **nicht** unterstützt — dafür bräuchte die URL Klammern und
/// das Zertifikat einen `IP:`-SAN. Vermerkt statt stillschweigend verstümmelt.
fn check_host(raw: &str) -> Result<String> {
    let host = raw.trim();
    if host.is_empty() {
        bail!("Die Gegenstelle hat keinen Hostnamen hinterlegt");
    }
    if host.len() > 253 {
        bail!("Der Hostname der Gegenstelle ist zu lang");
    }
    if host.starts_with('-') {
        // Landete sonst als **Option** in der Kommandozeile.
        bail!("Der Hostname der Gegenstelle darf nicht mit '-' beginnen");
    }
    if host.starts_with('.') || host.contains("..") {
        bail!("Der Hostname der Gegenstelle ist kein gültiger Name");
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        bail!(
            "Der Hostname der Gegenstelle darf nur Buchstaben, Ziffern, '.' und '-' enthalten \
             (IPv6-Adressen werden nicht unterstützt)"
        );
    }
    Ok(host.to_string())
}

/// Modulname der Gegenstelle. Das Pairing erzeugt `pair` + 16 Hex; geprüft
/// wird trotzdem, weil die Datei auch von Hand entstehen kann.
fn check_module(raw: &str) -> Result<String> {
    let module = raw.trim();
    if module.is_empty() {
        bail!("Die Gegenstelle hat keinen Modulnamen hinterlegt");
    }
    if module.len() > 64 {
        bail!("Der Modulname der Gegenstelle ist zu lang");
    }
    if module.starts_with('-') {
        bail!("Der Modulname der Gegenstelle darf nicht mit '-' beginnen");
    }
    if !module
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        bail!("Der Modulname der Gegenstelle enthält ungültige Zeichen");
    }
    Ok(module.to_string())
}

/// Pfad der CA-Datei.
///
/// Relative Angaben werden gegen das Peer-Verzeichnis aufgelöst, und der
/// kanonisierte Pfad muss **innerhalb** dieses Verzeichnisses liegen — auch
/// über aufgelöste Symlinks. Die CA gehört zur Kopplung und liegt bei ihr; ein
/// Peer-Eintrag ist damit keine Handhabe, den Server irgendeine Datei öffnen
/// zu lassen.
fn check_ca_cert(raw: &str) -> Result<PathBuf> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("Die Gegenstelle hat kein CA-Zertifikat hinterlegt");
    }

    let root = fs::canonicalize(peers_dir())
        .map_err(|e| anyhow::anyhow!("Das Verzeichnis der Gegenstellen ist nicht lesbar: {}", e))?;
    let candidate = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        root.join(value)
    };
    let resolved = fs::canonicalize(&candidate)
        .map_err(|_| anyhow::anyhow!("Das CA-Zertifikat der Gegenstelle ist nicht lesbar"))?;

    if !resolved.starts_with(&root) {
        warn!(
            "CA-Zertifikat {} liegt ausserhalb von {}",
            resolved.display(),
            root.display()
        );
        bail!("Das CA-Zertifikat der Gegenstelle muss neben ihrer Hinterlegung liegen");
    }
    if !resolved.is_file() {
        bail!("Das CA-Zertifikat der Gegenstelle ist keine Datei");
    }
    Ok(resolved)
}

/// Push über `rsync-ssl` in das Modul einer gekoppelten Gegenstelle.
#[derive(Debug)]
pub struct RsyncEngine {
    target: PeerTarget,
}

impl RsyncEngine {
    pub fn new(target: PeerTarget) -> Self {
        Self { target }
    }

    /// Der Zielpfad im Modul, in der Form, die in die URL geht.
    ///
    /// Geprüft wird mit demselben [`path_segments`] wie auf der rclone-Seite:
    /// leere Segmente und `.` fallen weg, `..` wird abgewiesen. Der Daemon
    /// hält einen Pfad-Ausbruch zwar auch selbst (`sanitize paths`, chroot,
    /// gemessen im Spike) — aber ein Aufruf, der ihn erst versucht, hat hier
    /// nichts zu suchen.
    fn target_path(remote_path: &str) -> Result<String> {
        if remote_path.contains('\0') || remote_path.contains('\n') || remote_path.contains('\r') {
            bail!("Der Zielpfad enthält ungültige Zeichen");
        }
        let segments = path_segments(remote_path);
        if segments.contains(&"..") {
            bail!("Der Zielpfad darf kein '..' enthalten");
        }
        Ok(segments.join("/"))
    }

    /// Die Quelle in der Form, die rsync braucht.
    ///
    /// Für ein Verzeichnis mit abschliessendem `/`: dann landet der **Inhalt**
    /// im Ziel, so wie `rclone copy` es tut. Ohne den Schrägstrich entstünde
    /// im Ziel eine zusätzliche Ebene — derselbe Aufruf mit einem anderen
    /// Ergebnis, und niemand würde es einer Fehlermeldung entnehmen können.
    fn source_argument(source_path: &str) -> Result<String> {
        if source_path.is_empty() {
            bail!("Kein Quellpfad angegeben");
        }
        if source_path.starts_with('-') {
            // Steht bereits kanonisiert und absolut da; die Prüfung ist der
            // Riegel für den Fall, dass jemand diesen Weg künftig anders
            // befüllt.
            bail!("Der Quellpfad darf nicht mit '-' beginnen");
        }
        if source_path.contains('\0') {
            bail!("Der Quellpfad enthält ungültige Zeichen");
        }
        if source_path.ends_with('/') {
            return Ok(source_path.to_string());
        }
        if Path::new(source_path).is_dir() {
            return Ok(format!("{}/", source_path));
        }
        Ok(source_path.to_string())
    }

    /// Schreibt das Secret in eine Datei mit Modus 0600 und gibt ihren Pfad
    /// zurück.
    ///
    /// Der Modus wird **beim Anlegen** gesetzt (`OpenOptions::mode`) und danach
    /// noch einmal nachgelesen: ein `chmod` nach dem Schreiben hätte ein
    /// Zeitfenster, in dem die Datei mit `umask`-Rechten auf der Platte liegt.
    /// rsync weist eine „other-accessible" Password-Datei ohnehin ab — die
    /// Prüfung hier ist die, die vor dem Prozessstart greift.
    fn write_password_file(&self, job_id: &str) -> Result<String> {
        let dir = run_dir();
        fs::create_dir_all(&dir)
            .with_context(|| format!("Verzeichnis {} anlegen", dir.display()))?;
        // Nicht nur beim Anlegen: das Verzeichnis kann aus einem früheren Lauf
        // stammen. 0700, damit die 0600-Datei nicht einmal auflistbar ist.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Modus von {} setzen", dir.display()))?;

        let path = dir.join(format!("{}.pw", job_id));
        // Ein Rest aus einem abgebrochenen Lauf würde sonst mit alten Rechten
        // weiterverwendet.
        let _ = fs::remove_file(&path);

        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("Password-Datei {} anlegen", path.display()))?;
        // rsync liest genau die erste Zeile.
        writeln!(file, "{}", self.target.secret.expose())
            .with_context(|| "Password-Datei schreiben")?;
        file.sync_all().ok();
        drop(file);

        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            let _ = fs::remove_file(&path);
            bail!(
                "Die Password-Datei hat Modus {:o} statt 0600 — die Übertragung wird nicht \
                 gestartet",
                mode
            );
        }

        Ok(path.to_string_lossy().into_owned())
    }
}

impl SyncEngine for RsyncEngine {
    fn name(&self) -> &'static str {
        "rsync"
    }

    /// Der Request, **bevor** ein Job entsteht.
    ///
    /// Alles, was ohne Seiteneffekt prüfbar ist, wird hier geprüft und nicht
    /// erst in `build_command`: ein abgelehnter Sync soll keinen Job, keine
    /// Logdatei und keine Password-Datei hinterlassen.
    fn validate_request(&self, request: &crate::models::SyncRequest) -> Result<()> {
        Self::target_path(&request.remote_path)?;
        Self::source_argument(&request.source_path)?;
        if !request
            .backup_dir
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            // `--backup-dir` gibt es bei rsync auch, aber die Prüfungen in
            // `backup_dir_target` sind auf rclones `remote:pfad`-Syntax
            // geschnitten. Ein halb geprüfter Sicherungsordner auf der
            // Gegenseite ist schlechter als keiner.
            bail!("Ein Sicherungsordner ist für diese Gegenstelle nicht unterstützt");
        }
        Ok(())
    }

    fn build_command(&self, spec: &JobSpec<'_>) -> Result<EngineCommand> {
        // Zweiter Riegel: `supports_mirror()` ist `false`, also darf hier kein
        // Löschlauf ankommen. Käme er doch an, wäre `--delete` die Folge —
        // deshalb bricht es hier ab, statt sich auf den Aufrufer zu verlassen.
        if spec.mode != TransferMode::Copy {
            bail!("„Im Ziel löschen\" ist für diese Gegenstelle nicht freigeschaltet");
        }

        let target_path = Self::target_path(&spec.request.remote_path)?;
        let source = Self::source_argument(&spec.request.source_path)?;
        let password_file = self.write_password_file(spec.job_id)?;

        let mut args: Vec<String> = vec![
            "-a".to_string(),
            "--partial".to_string(),
            format!("--partial-dir={}", PARTIAL_DIR),
            // Siehe Modulkopf: ohne diese Option bleibt eine in derselben
            // Sekunde geänderte Datei im Ziel falsch, ohne jede Meldung.
            "--modify-window=-1".to_string(),
            "--info=progress2".to_string(),
            "--stats".to_string(),
            format!("--timeout={}", IO_TIMEOUT_SECS),
            // Dateiliste und Fehler landen im Job-Log, das nur der Besitzer
            // des Jobs lesen darf. Der Fortschritt kommt getrennt davon aus
            // stdout (`--info=progress2`), das Log bleibt also lesbar.
            format!("--log-file={}", spec.log_file),
            format!("--password-file={}", password_file),
        ];

        if is_dry_run(spec.request) {
            args.push("--dry-run".to_string());
        }

        args.push(source);
        args.push(self.target.url(&target_path));

        let mut command = EngineCommand {
            program: "rsync-ssl".to_string(),
            args,
            env: vec![
                ("RSYNC_SSL_TYPE".to_string(), "openssl".to_string()),
                (
                    "RSYNC_SSL_CA_CERT".to_string(),
                    self.target.ca_cert.to_string_lossy().into_owned(),
                ),
                // **Nicht kosmetisch.** `--info=progress2` schreibt die
                // Bytezahl mit dem Tausendertrennzeichen der Locale: unter
                // `de_DE.UTF-8` „3.000.000", unter C „3,000,000" (beides
                // gemessen). Der Parser verträgt beides, aber ein Aufruf, der
                // je nach Umgebung anders aussieht, ist eine Fehlerquelle, die
                // niemand sucht.
                ("LC_ALL".to_string(), "C".to_string()),
            ],
            temp_files: vec![password_file],
        };
        // Die Reihenfolge ist stabil, damit ein Golden-Test sie festhalten
        // kann; `env` wird nur ergänzt, nie umsortiert.
        command.env.sort();

        info!(
            "🔐 rsync-Push an {} (Modul {}, Port {})",
            self.target.host, self.target.module, self.target.port
        );
        debug!("Gegenstelle: {:?}", self.target);
        Ok(command)
    }

    fn progress_source(&self) -> ProgressSource {
        ProgressSource::Stdout
    }

    /// **Nein.**
    ///
    /// Der Daemon der Gegenseite verweigert `--delete` serverseitig
    /// (`refuse options`, `rsyncd.rs`), und das ist kein Versehen: die Zeile
    /// war die Behebung eines Datenverlust-Fehlers. Ein Löschlauf über rsync
    /// braucht also **beides** — ein Recht, das die Gegenseite einräumt
    /// (Scope `rsync:delete`, im Modell noch nicht vorhanden), und eine
    /// Modulkonfiguration, die die Option nicht mehr verweigert.
    ///
    /// Solange es das nicht gibt, ist `false` die einzige richtige Antwort:
    /// `start_sync_for` lehnt einen Löschlauf damit ab, **bevor** ein Job
    /// entsteht, statt ihn zu starten und an `refuse options` scheitern zu
    /// lassen.
    fn supports_mirror(&self) -> bool {
        false
    }

    fn parse_progress(&self, chunk: &str) -> Option<ProgressSnapshot> {
        parse_progress2_line(chunk)
    }

    fn describe_exit(&self, code: Option<i32>) -> String {
        classify_rsync_exit(code).to_string()
    }

    /// rsync **hat** eine Exit-Code-Semantik, und 23/24 sind keine
    /// Fehlschläge, sondern Teilerfolge. Die Übersetzung steht in
    /// [`classify_rsync_exit`].
    fn classify_exit(&self, code: Option<i32>) -> JobStatus {
        classify_rsync_exit(code)
    }
}

/// Eine Fortschrittszeile von `--info=progress2`.
///
/// Gemessenes Format (rsync 3.5.0, Host, und 3.4.3 im Image):
///
/// ```text
///      3,000,000  20%    2.76GB/s    0:00:00 (xfr#1, to-chk=4/6)
/// ```
///
/// Zu beachten, alles gemessen:
///
/// * Die Sätze sind durch **`\r`** getrennt, nicht durch `\n` — nur der
///   letzte endet mit `\n`. Das Zerlegen macht deshalb
///   `super::pump_stdout_progress`, nicht `BufReader::lines()`.
/// * Das Tausendertrennzeichen hängt an der **Locale** (`.` unter de_DE,
///   `,` unter C). Der Aufruf setzt `LC_ALL=C`; der Parser verträgt trotzdem
///   beides, weil das Feld immer eine ganze Zahl ist und es dort kein
///   Dezimaltrennzeichen gibt.
/// * Die Gesamtgrösse steht **nicht** in der Zeile. Sie ergibt sich aus
///   Bytes und Prozent — mit `0 %` gibt es sie noch nicht, dann bleibt sie
///   `0`, genau wie bei einem rclone-Job vor der ersten Statistikzeile.
/// * `--stats` schreibt hinterher ebenfalls auf stdout („sent 15,001,234
///   bytes …", „total size is …"). Diese Zeilen dürfen den Fortschritt nicht
///   verstellen, deshalb wird das Prozentfeld **verlangt**.
pub fn parse_progress2_line(chunk: &str) -> Option<ProgressSnapshot> {
    let mut fields = chunk.split_whitespace();
    let bytes_field = fields.next()?;
    let percent_field = fields.next()?;

    let percent_digits = percent_field.strip_suffix('%')?;
    let percent: f64 = percent_digits.parse().ok()?;
    let transferred = parse_grouped_number(bytes_field)?;

    // Ausserhalb von 0..=100 ist es keine Fortschrittszeile.
    if !(0.0..=100.0).contains(&percent) {
        return None;
    }

    let total = if percent > 0.0 {
        // Aufrunden, damit `transferred` nie grösser als `total` wird: bei
        // 99 % wäre die abgerundete Gesamtgrösse kleiner als das bereits
        // Übertragene, und die Anzeige stünde über 100 %.
        (transferred as f64 * 100.0 / percent).ceil() as u64
    } else {
        0
    };

    Some(ProgressSnapshot {
        percent,
        transferred,
        total,
    })
}

/// Eine ganze Zahl mit Tausendertrennzeichen — `.` oder `,`, je nach Locale.
///
/// Verlangt mindestens eine Ziffer und lässt **nur** Ziffern und die beiden
/// Trennzeichen zu; „sent" oder „2.76GB/s" fallen damit durch.
fn parse_grouped_number(field: &str) -> Option<u64> {
    let mut digits = String::with_capacity(field.len());
    for c in field.chars() {
        match c {
            '0'..='9' => digits.push(c),
            '.' | ',' => {}
            _ => return None,
        }
    }
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SyncRequest;

    fn request(source: &str, remote: &str, path: &str) -> SyncRequest {
        SyncRequest {
            source_path: source.to_string(),
            remote_name: remote.to_string(),
            remote_path: path.to_string(),
            chunk_size: None,
            use_chunking: None,
            delete_target: None,
            delete_confirmed: None,
            dry_run: None,
            backup_dir: None,
        }
    }

    /// Ein Peer-Verzeichnis mit einer gültigen Hinterlegung. Der Name trägt
    /// die Ticket-ID, weil sich alle Agenten ein Scratchpad teilen.
    fn peer_target(module: &str) -> PeerTarget {
        PeerTarget {
            name: "peerb".to_string(),
            host: "peerb.example".to_string(),
            port: 874,
            module: module.to_string(),
            secret: ModuleSecret("s3cr3t-533ed42c".to_string()),
            ca_cert: PathBuf::from("/tmp/peer-ca-533ed42c.crt"),
        }
    }

    // -----------------------------------------------------------------------
    // Der Aufruf
    // -----------------------------------------------------------------------

    fn build(engine: &RsyncEngine, req: &SyncRequest, job: &str) -> EngineCommand {
        let spec = JobSpec {
            job_id: job,
            request: req,
            mode: TransferMode::Copy,
            log_file: "data/log/x.log",
        };
        engine.build_command(&spec).expect("Kommando")
    }

    fn with_run_dir<T>(name: &str, body: impl FnOnce() -> T) -> T {
        // `set_var` wirkt **prozessweit**, und `cargo test` läuft parallel:
        // ohne diese Sperre hat ein Test das Laufverzeichnis eines anderen
        // mitten im Schreiben weggeräumt (`os error 2`, so gemessen). Eigenes
        // Verzeichnis *und* Sperre — das eine macht die Namen eindeutig, das
        // andere die Umgebungsvariable.
        let _guard = env_lock().lock().expect("Sperre");
        let dir = std::env::temp_dir().join(format!("rsyncrun-533ed42c-{}", name));
        std::env::set_var(RUN_DIR_ENV, &dir);
        let out = body();
        let _ = fs::remove_dir_all(&dir);
        out
    }

    /// **Der Datenverfälschungs-Riegel.** Ohne `--modify-window=-1` bleibt
    /// eine in derselben Sekunde geänderte Datei im Ziel falsch — ohne Fehler,
    /// ohne Warnung. Der Test hält die Option in *jeder* Variante des Aufrufs
    /// fest, nicht nur in der Standardvariante.
    #[test]
    fn modify_window_is_never_missing() {
        with_run_dir("mw", || {
            let engine = RsyncEngine::new(peer_target("pairaaaa"));
            for req in [
                request("/src", "peerb", "ziel"),
                {
                    let mut r = request("/src", "peerb", "ziel");
                    r.dry_run = Some(true);
                    r
                },
                request("/src", "peerb", ""),
                request("/src/datei.bin", "peerb", "a/b/c"),
            ] {
                let args = build(&engine, &req, "job-mw").args;
                assert!(
                    args.iter().any(|a| a == "--modify-window=-1"),
                    "--modify-window=-1 fehlt in {:?}",
                    args
                );
                assert!(args.iter().any(|a| a == "--partial"), "{:?}", args);
                assert!(
                    args.iter().any(|a| a.starts_with("--partial-dir=")),
                    "{:?}",
                    args
                );
            }
        });
    }

    /// Das Secret steht **nicht** in `argv` — hier auf der Ebene, auf der die
    /// Engine es entscheidet. Der Nachweis am laufenden Prozess über
    /// `/proc/<pid>/cmdline` steht im Ticketkommentar.
    #[test]
    fn the_secret_never_reaches_argv() {
        with_run_dir("argv", || {
            let engine = RsyncEngine::new(peer_target("pairbbbb"));
            let req = request("/src", "peerb", "ziel");
            let command = build(&engine, &req, "job-argv");

            let line = command.args.join(" ");
            assert!(
                !line.contains("s3cr3t-533ed42c"),
                "Secret in argv: {}",
                line
            );
            for (key, value) in &command.env {
                assert!(
                    !value.contains("s3cr3t-533ed42c"),
                    "Secret in Umgebung {}={}",
                    key,
                    value
                );
            }
            // Gegenprobe: die Prüfung *kann* anschlagen. Ohne sie wäre ein
            // grüner Test nur ein Beweis, dass die Zeichenkette irgendwo
            // anders steht.
            let password_file = command
                .args
                .iter()
                .find_map(|a| a.strip_prefix("--password-file="))
                .expect("--password-file im Aufruf");
            let content = fs::read_to_string(password_file).expect("Password-Datei lesbar");
            assert!(
                content.contains("s3cr3t-533ed42c"),
                "Die Suche findet das Secret nicht einmal dort, wo es steht"
            );
            assert_eq!(
                fs::metadata(password_file)
                    .expect("Modus")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                command.temp_files,
                vec![password_file.to_string()],
                "Die Password-Datei muss aufgeräumt werden"
            );
        });
    }

    #[test]
    fn the_target_url_is_a_daemon_url_with_module_twice() {
        with_run_dir("url", || {
            let engine = RsyncEngine::new(peer_target("pair0123456789abcd"));
            let args = build(&engine, &request("/src", "peerb", "/a//b/./c/"), "job-url").args;
            assert_eq!(
                args.last().expect("Ziel"),
                "rsync://pair0123456789abcd@peerb.example:874/pair0123456789abcd/a/b/c/"
            );
        });
    }

    /// Ein Verzeichnis bekommt den abschliessenden `/` (Inhalt kopieren, wie
    /// `rclone copy`), eine Datei nicht.
    #[test]
    fn a_directory_source_gets_a_trailing_slash() {
        with_run_dir("src", || {
            let dir = std::env::temp_dir().join("rsyncsrc-533ed42c");
            fs::create_dir_all(&dir).expect("Quelle");
            let file = dir.join("datei.bin");
            fs::write(&file, b"x").expect("Datei");

            let engine = RsyncEngine::new(peer_target("paircccc"));
            let as_dir = build(
                &engine,
                &request(dir.to_str().expect("utf8"), "peerb", "ziel"),
                "job-dir",
            )
            .args;
            assert_eq!(
                as_dir[as_dir.len() - 2],
                format!("{}/", dir.to_str().expect("utf8"))
            );

            let as_file = build(
                &engine,
                &request(file.to_str().expect("utf8"), "peerb", "ziel"),
                "job-file",
            )
            .args;
            assert_eq!(as_file[as_file.len() - 2], file.to_str().expect("utf8"));
            let _ = fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn mirror_is_refused_by_the_engine_itself() {
        with_run_dir("mirror", || {
            let engine = RsyncEngine::new(peer_target("pairdddd"));
            assert!(!engine.supports_mirror());
            let req = request("/src", "peerb", "ziel");
            let spec = JobSpec {
                job_id: "job-mirror",
                request: &req,
                mode: TransferMode::Mirror,
                log_file: "data/log/x.log",
            };
            assert!(engine.build_command(&spec).is_err());
            // Kein `--delete` in irgendeiner Variante.
            let args = build(&engine, &req, "job-mirror2").args;
            assert!(!args.iter().any(|a| a.contains("delete")), "{:?}", args);
        });
    }

    #[test]
    fn dry_run_reaches_the_command_line() {
        with_run_dir("dry", || {
            let engine = RsyncEngine::new(peer_target("paireeee"));
            let mut req = request("/src", "peerb", "ziel");
            req.dry_run = Some(true);
            assert!(build(&engine, &req, "job-dry")
                .args
                .iter()
                .any(|a| a == "--dry-run"));
            let plain = build(&engine, &request("/src", "peerb", "ziel"), "job-wet").args;
            assert!(!plain.iter().any(|a| a == "--dry-run"));
        });
    }

    #[test]
    fn the_tls_environment_is_set() {
        with_run_dir("env", || {
            let engine = RsyncEngine::new(peer_target("pairffff"));
            let env = build(&engine, &request("/src", "peerb", "ziel"), "job-env").env;
            assert!(env.contains(&("RSYNC_SSL_TYPE".to_string(), "openssl".to_string())));
            assert!(env.contains(&(
                "RSYNC_SSL_CA_CERT".to_string(),
                "/tmp/peer-ca-533ed42c.crt".to_string()
            )));
            assert!(env.contains(&("LC_ALL".to_string(), "C".to_string())));
        });
    }

    // -----------------------------------------------------------------------
    // Eingaben, die nicht durchkommen dürfen
    // -----------------------------------------------------------------------

    #[test]
    fn a_target_path_cannot_escape_the_module() {
        let engine = RsyncEngine::new(peer_target("pairgggg"));
        for path in ["../geheim", "a/../../b", "..", "a/..", "a/\n/b", "a/\0/b"] {
            assert!(
                engine
                    .validate_request(&request("/src", "peerb", path))
                    .is_err(),
                "durchgekommen: {:?}",
                path
            );
        }
        // Gegenprobe: harmlose Pfade kommen durch.
        for path in ["", "/", "a", "a/b", "a/./b", "..punkte", "a..b"] {
            assert!(
                engine
                    .validate_request(&request("/src", "peerb", path))
                    .is_ok(),
                "abgewiesen: {:?}",
                path
            );
        }
    }

    #[test]
    fn a_source_that_looks_like_an_option_is_refused() {
        let engine = RsyncEngine::new(peer_target("pairhhhh"));
        assert!(engine
            .validate_request(&request("--delete", "peerb", "ziel"))
            .is_err());
        assert!(engine
            .validate_request(&request("", "peerb", "ziel"))
            .is_err());
    }

    #[test]
    fn a_backup_dir_is_refused_instead_of_half_checked() {
        let engine = RsyncEngine::new(peer_target("pairiiii"));
        let mut req = request("/src", "peerb", "ziel");
        req.backup_dir = Some("sicherung".to_string());
        assert!(engine.validate_request(&req).is_err());
        req.backup_dir = Some("   ".to_string());
        assert!(engine.validate_request(&req).is_ok());
    }

    #[test]
    fn hosts_and_modules_are_checked() {
        for host in ["-oProxy=x", "", "peer b", "a..b", ".peer", "1.2.3.4:874"] {
            assert!(check_host(host).is_err(), "durchgekommen: {:?}", host);
        }
        assert_eq!(
            check_host(" peerb.example ").expect("gültig"),
            "peerb.example"
        );
        assert_eq!(check_host("192.168.0.9").expect("gültig"), "192.168.0.9");

        for module in ["-x", "", "pair/../etc", "pair modul", "pair:x"] {
            assert!(check_module(module).is_err(), "durchgekommen: {:?}", module);
        }
        assert_eq!(check_module("pair_a-1").expect("gültig"), "pair_a-1");
    }

    /// Ein Secret mit Zeilenumbruch würde rsync eine andere Zeichenkette
    /// geben, als hinterlegt ist — und zwar lautlos, rsync liest nur die erste
    /// Zeile.
    #[test]
    fn a_secret_with_a_newline_is_refused() {
        let file = PeerFile {
            host: "peerb".to_string(),
            port: None,
            module: "pairjjjj".to_string(),
            secret: "erste\nzweite".to_string(),
            ca_cert: "ca.crt".to_string(),
        };
        assert!(PeerTarget::from_file("peerb", file).is_err());
    }

    // -----------------------------------------------------------------------
    // Die Peer-Datei
    // -----------------------------------------------------------------------

    /// Rahmen für die Registry-Tests: eigenes Peer-Verzeichnis, eigene CA.
    fn with_peers_dir<T>(name: &str, body: impl FnOnce(&Path) -> T) -> T {
        let dir = std::env::temp_dir().join(format!("peers-533ed42c-{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("Peer-Verzeichnis");
        fs::write(dir.join("ca.crt"), b"-----BEGIN CERTIFICATE-----\n").expect("CA");
        std::env::set_var(PEERS_DIR_ENV, &dir);
        let out = body(&dir);
        let _ = fs::remove_dir_all(&dir);
        out
    }

    fn write_peer(dir: &Path, name: &str, body: &str, mode: u32) {
        let path = dir.join(format!("{}.json", name));
        fs::write(&path, body).expect("Peer-Datei");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("Modus");
    }

    const GOOD_PEER: &str = r#"{
        "host": "peerb.example",
        "port": 874,
        "module": "pair0123456789abcd",
        "secret": "deadbeef",
        "ca_cert": "ca.crt"
    }"#;

    #[test]
    fn a_known_peer_is_found_and_an_unknown_name_is_not() {
        // Serialisiert über die Umgebungsvariable: `set_var` ist prozessweit.
        let _guard = env_lock().lock().expect("Sperre");
        with_peers_dir("found", |dir| {
            write_peer(dir, "peerb", GOOD_PEER, 0o600);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Runtime");
            rt.block_on(async {
                let found = lookup_peer("peerb").await.expect("lesbar").expect("Peer");
                assert_eq!(found.host, "peerb.example");
                assert_eq!(found.module, "pair0123456789abcd");
                assert_eq!(found.port, 874);
                assert!(lookup_peer("gibtsnicht")
                    .await
                    .expect("kein Fehler")
                    .is_none());
                // Ein Name, den `validate_remote_name` ablehnt, ist „kein
                // Peer" — die Meldung soll die bestehende aus der
                // rclone-Prüfung bleiben.
                assert!(lookup_peer("../peerb")
                    .await
                    .expect("kein Fehler")
                    .is_none());
            });
        });
    }

    /// Die Datei trägt das Modul-Secret. Ist sie für andere lesbar, wird
    /// **nicht** übertragen.
    #[test]
    fn a_world_readable_peer_file_is_refused() {
        let _guard = env_lock().lock().expect("Sperre");
        with_peers_dir("mode", |dir| {
            write_peer(dir, "peerb", GOOD_PEER, 0o644);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Runtime");
            rt.block_on(async {
                let err = lookup_peer("peerb")
                    .await
                    .expect_err("muss abgelehnt werden");
                assert!(err.to_string().contains("0600"), "{}", err);
                // Gegenprobe: mit 0600 geht dieselbe Datei durch.
                write_peer(dir, "peerb", GOOD_PEER, 0o600);
                assert!(lookup_peer("peerb").await.expect("lesbar").is_some());
            });
        });
    }

    /// Ein CA-Pfad, der aus dem Peer-Verzeichnis herausführt, wird abgewiesen —
    /// eine Hinterlegung ist keine Handhabe, den Server beliebige Dateien
    /// öffnen zu lassen.
    #[test]
    fn a_ca_outside_the_peers_dir_is_refused() {
        let _guard = env_lock().lock().expect("Sperre");
        with_peers_dir("ca", |dir| {
            write_peer(
                dir,
                "peerb",
                &GOOD_PEER.replace("\"ca.crt\"", "\"../../../etc/hostname\""),
                0o600,
            );
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Runtime");
            rt.block_on(async {
                assert!(lookup_peer("peerb").await.is_err());
            });
        });
    }

    #[test]
    fn a_broken_peer_file_is_an_error_not_a_fallback_to_rclone() {
        let _guard = env_lock().lock().expect("Sperre");
        with_peers_dir("broken", |dir| {
            write_peer(dir, "peerb", "{ kein json", 0o600);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Runtime");
            rt.block_on(async {
                // Nicht `Ok(None)`: sonst liefe der Push in ein gleichnamiges
                // rclone-Remote, also an ein anderes Ziel als gemeint.
                assert!(lookup_peer("peerb").await.is_err());
            });
        });
    }

    use super::peers_env_lock as env_lock;

    // -----------------------------------------------------------------------
    // Fortschritt
    // -----------------------------------------------------------------------

    /// Die gemessene Zeile, beide Locales.
    #[test]
    fn a_progress2_line_is_parsed_in_both_locales() {
        for line in [
            "      3,000,000  20%    2.76GB/s    0:00:00 (xfr#1, to-chk=4/6)",
            "      3.000.000  20%    2,76GB/s    0:00:00 (xfr#1, to-chk=4/6)",
        ] {
            let snapshot = parse_progress2_line(line).expect("Fortschritt");
            assert_eq!(snapshot.transferred, 3_000_000);
            assert_eq!(snapshot.percent, 20.0);
            assert_eq!(snapshot.total, 15_000_000);
        }
    }

    /// Die erste Zeile kommt mit `0 %` — dann ist die Gesamtgrösse noch
    /// unbekannt und bleibt `0`, wie bei rclone vor der ersten Statistikzeile.
    #[test]
    fn zero_percent_leaves_the_total_unknown() {
        let snapshot = parse_progress2_line("             32,768   0%    0.00kB/s    0:00:00")
            .expect("Fortschritt");
        assert_eq!(snapshot.transferred, 32_768);
        assert_eq!(snapshot.percent, 0.0);
        assert_eq!(snapshot.total, 0);
    }

    #[test]
    fn the_last_line_reaches_a_hundred_percent() {
        let snapshot =
            parse_progress2_line("     15,000,000 100%    2.32GB/s    0:00:00 (xfr#5, to-chk=0/6)")
                .expect("Fortschritt");
        assert_eq!(snapshot.percent, 100.0);
        assert_eq!(snapshot.transferred, 15_000_000);
        assert_eq!(snapshot.total, 15_000_000);
    }

    /// `--stats` schreibt auf **dieselbe** Leitung. Keine dieser Zeilen darf
    /// als Fortschritt gelten — sonst springt die Anzeige am Ende zurück.
    #[test]
    fn stats_and_noise_are_not_progress() {
        for line in [
            "",
            "   ",
            "Number of files: 6 (reg: 5, dir: 1)",
            "sent 15,001,234 bytes  received 130 bytes  30,002,728.00 bytes/sec",
            "total size is 15,000,000  speedup is 1.00",
            "rsync: [sender] change_dir \"/nix\" failed: No such file or directory (2)",
            "@ERROR: auth failed on module pairaaaa",
            "3,000,000 20",
            "3,000,000 abc%",
            "3,000,000 120%",
            "3,000,000 -5%",
            "2.76GB/s 20%",
        ] {
            assert!(
                parse_progress2_line(line).is_none(),
                "als Fortschritt gelesen: {:?}",
                line
            );
        }
    }

    /// Sehr viele kleine Dateien: `progress2` zählt kumulativ über alle
    /// Dateien, die Anzeige darf also nie zurückfallen.
    #[test]
    fn many_small_files_stay_monotonic() {
        let mut last = 0u64;
        let mut last_percent = 0.0f64;
        for (bytes, percent) in [
            (1u64, 1u32),
            (500, 25),
            (1_000, 50),
            (1_900, 95),
            (2_000, 100),
        ] {
            let line = format!(
                "        {}  {}%    1.00kB/s    0:00:01 (xfr#{}, to-chk={}/2000)",
                bytes,
                percent,
                percent * 20,
                2000 - percent * 20
            );
            let snapshot = parse_progress2_line(&line).expect("Fortschritt");
            assert!(snapshot.transferred >= last);
            assert!(snapshot.percent >= last_percent);
            assert!(
                snapshot.total >= snapshot.transferred,
                "total {} < transferred {}",
                snapshot.total,
                snapshot.transferred
            );
            last = snapshot.transferred;
            last_percent = snapshot.percent;
        }
    }

    /// Der Wächter `tests/no_debug_leaks.rs` kennt nur Feldnamen. Dass das
    /// `Debug` hier wirklich redigiert, prüft dieser Test — mit Gegenprobe,
    /// dass die Suche das Secret überhaupt finden könnte.
    #[test]
    fn debug_output_redacts_the_secret() {
        let target = peer_target("pairkkkk");
        let text = format!("{:?}", target);
        assert!(!text.contains("s3cr3t-533ed42c"), "{}", text);
        assert!(text.contains("redigiert"), "{}", text);
        assert!(text.contains("peerb.example"), "Bezug fehlt: {}", text);
        assert!(
            target.secret.expose().contains("s3cr3t-533ed42c"),
            "Die Gegenprobe greift nicht"
        );
    }

    /// Exit-Codes: 23/24 sind Teilerfolge, nicht Fehlschläge. Die Übersetzung
    /// gehört zu `classify_rsync_exit`; hier wird nur geprüft, dass die Engine
    /// sie **benutzt** — vorher war der Zweig von aussen unerreichbar.
    #[test]
    fn the_engine_uses_the_rsync_exit_codes() {
        let engine = RsyncEngine::new(peer_target("pairllll"));
        assert!(engine.classify_exit(Some(23)).is_partial());
        assert!(engine.classify_exit(Some(24)).is_partial());
        assert!(!engine.classify_exit(Some(23)).is_success());
        assert!(engine.classify_exit(Some(23)).is_terminal());
        assert!(!engine.classify_exit(Some(12)).is_partial());
        assert!(engine.describe_exit(Some(5)).contains("TLS"));
        assert_eq!(engine.progress_source(), ProgressSource::Stdout);
        assert_eq!(engine.name(), "rsync");
    }
}
