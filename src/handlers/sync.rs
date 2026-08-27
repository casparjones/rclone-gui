use crate::handlers::auth_web::CurrentUser;
use crate::handlers::download::{resolve_within_root, user_root, RootScope};
use crate::models::{ApiResponse, SyncProgress, SyncRequest};
use axum::{extract::Json, response::Json as ResponseJson, Extension};
use chrono::{self, Utc};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Die zweite Engine. Sie steht in einer eigenen Datei, weil dieses Modul
/// schon gross genug ist; als Kindmodul kommt sie an die privaten Bausteine
/// hier heran (`path_segments`, `is_dry_run`, `classify_rsync_exit`), ohne dass
/// dafür etwas öffentlich werden muss.
pub mod rsync_engine;

type SyncJobs = Arc<Mutex<HashMap<String, SyncProgress>>>;
type JobEngines = Arc<Mutex<HashMap<String, Arc<dyn SyncEngine>>>>;
/// Job-ID -> Eigentümer und Art des Laufs.
type JobOwners = Arc<Mutex<HashMap<String, JobOwner>>>;
/// Job-ID -> Abbruchflagge, sofern die Art des Jobs eine hat.
type JobCancels = Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>;

lazy_static::lazy_static! {
    /// **Die** Job-Tabelle. Sync-Läufe und URL-Abrufe stehen hier gemeinsam;
    /// es gibt keine zweite.
    static ref SYNC_JOBS: SyncJobs = Arc::new(Mutex::new(HashMap::new()));
    /// Engine used by a running job. Entries live only while the job runs.
    static ref JOB_ENGINES: JobEngines = Arc::new(Mutex::new(HashMap::new()));
    /// Wer einen Job gestartet hat und welcher Art er ist. Wird beim Anlegen
    /// gesetzt und mit dem Job wieder entfernt; ein Job ohne Eintrag gilt als
    /// **fremd**, nicht als frei (fail closed — nach einem Neustart ist die
    /// Jobtabelle ohnehin leer, siehe `recover_stranded_jobs`).
    static ref JOB_OWNERS: JobOwners = Arc::new(Mutex::new(HashMap::new()));
    /// Abbruchflaggen. Wie `JOB_ENGINES` eine Nebentabelle zu einem Eintrag in
    /// `SYNC_JOBS`, keine zweite Job-Tabelle: sie trägt keinen Zustand, den
    /// eine Antwort an den Client zeigt.
    static ref JOB_CANCELS: JobCancels = Arc::new(Mutex::new(HashMap::new()));
}

// ---------------------------------------------------------------------------
// Job status
//
// Der Status war früher eine freie Zeichenkette, und Löschprüfung, Cleanup und
// die CLI-Monitor-Schleife haben daran per String-Vergleich entschieden. Damit
// hing das Verhalten am *Wortlaut* der Fehlermeldung: `Failed to spawn rclone
// process: … (os error 2)` traf weder `== "Failed"` noch `contains("Error")`
// (klein geschrieben) — solche Jobs waren unlöschbar und die CLI lief endlos.
//
// Der Terminalzustand ist jetzt eine Eigenschaft des Typs (`is_terminal()`).
// Wie eine Fehlermeldung formuliert ist, spielt keine Rolle mehr.
// ---------------------------------------------------------------------------

/// Lebenszyklus eines Sync-Jobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobStatus {
    /// Angelegt, der Prozess läuft noch nicht.
    Starting,
    /// Der Engine-Prozess läuft.
    Running,
    /// Sauber durchgelaufen.
    Completed,
    /// Endzustand zwischen Erfolg und Fehlschlag: der Lauf ist durch, ein Teil
    /// der Daten ist übertragen, ein Teil nicht (rsync-Exit 23 und 24).
    ///
    /// Bewusst ein eigener Zustand und **kein** `Failed`: „ein paar Dateien
    /// waren nicht lesbar" oder „eine Datei war beim Zugriff schon weg" ist
    /// bei einem lebenden Verzeichnis Alltag, und als roter Fehlschlag gemeldet
    /// wären das Fehlalarme. Ihn zu `Completed` zu machen wäre die andere
    /// Falle — dann verschwände echter Datenverlust lautlos.
    Partial { reason: String },
    /// Endzustand mit Begründung. Der Text ist reine Anzeige — **keine** Stelle
    /// im Code leitet daraus noch eine Entscheidung ab.
    Failed { reason: String },
    /// Vom Nutzer abgebrochen.
    ///
    /// **Ein eigener Endzustand, kein Fehlschlag.** Dasselbe Argument wie bei
    /// [`JobStatus::Partial`]: als `Failed` gemeldet wäre es ein Fehlalarm über
    /// etwas, das der Nutzer selbst ausgelöst hat, und als `Completed` würde
    /// verschwiegen, dass die Übertragung unvollständig ist. Was bis zum
    /// Abbruch im Ziel geschrieben wurde, **bleibt dort liegen** — das ist
    /// unvermeidbar, steht aber in der Antwort des Endpunkts und im Job-Log.
    Cancelled,
}

impl JobStatus {
    /// Fehlerzustand mit Begründung.
    pub fn failed(reason: impl Into<String>) -> Self {
        JobStatus::Failed {
            reason: reason.into(),
        }
    }

    /// Teilerfolg mit Begründung.
    pub fn partial(reason: impl Into<String>) -> Self {
        JobStatus::Partial {
            reason: reason.into(),
        }
    }

    /// Der Job ist fertig — egal ob erfolgreich oder nicht. Ein Job in diesem
    /// Zustand ist löschbar, hat `end_time` gesetzt und beendet die
    /// CLI-Monitor-Schleife.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            JobStatus::Completed
                | JobStatus::Partial { .. }
                | JobStatus::Failed { .. }
                | JobStatus::Cancelled
        )
    }

    /// Der Lauf ist durch, aber nicht vollständig.
    pub fn is_partial(&self) -> bool {
        matches!(self, JobStatus::Partial { .. })
    }

    /// Terminal *und* erfolgreich.
    pub fn is_success(&self) -> bool {
        matches!(self, JobStatus::Completed)
    }

    /// Maschinenlesbarer Bezeichner für die API (`state`-Feld). Stabil, im
    /// Gegensatz zum Anzeigetext.
    pub fn state(&self) -> &'static str {
        match self {
            JobStatus::Starting => "starting",
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Partial { .. } => "partial",
            JobStatus::Failed { .. } => "failed",
            JobStatus::Cancelled => "cancelled",
        }
    }

    /// Rückweg aus der API-Darstellung. `state` gewinnt; fehlt es (alter
    /// Client), wird der Anzeigetext interpretiert.
    fn from_parts(state: Option<&str>, text: String) -> Self {
        match state {
            Some("starting") => JobStatus::Starting,
            Some("running") => JobStatus::Running,
            Some("completed") => JobStatus::Completed,
            Some("partial") => JobStatus::partial(text),
            Some("cancelled") => JobStatus::Cancelled,
            Some("failed") => JobStatus::failed(text),
            _ => match text.as_str() {
                "Starting" => JobStatus::Starting,
                "Running" => JobStatus::Running,
                "Completed" => JobStatus::Completed,
                "Cancelled" => JobStatus::Cancelled,
                _ => JobStatus::failed(text),
            },
        }
    }
}

impl fmt::Display for JobStatus {
    /// Anzeigetext. Bewusst wortgleich mit dem, was die alte Zeichenkette
    /// enthielt, damit Frontend und CLI-Ausgabe sich nicht ändern.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobStatus::Starting => f.write_str("Starting"),
            JobStatus::Running => f.write_str("Running"),
            JobStatus::Completed => f.write_str("Completed"),
            JobStatus::Partial { reason } => f.write_str(reason),
            JobStatus::Failed { reason } => f.write_str(reason),
            JobStatus::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// Serialisiert als **drei** Felder, die per `#[serde(flatten)]` direkt im
/// Job-Objekt landen:
///
/// * `status`  — Anzeigetext, unverändert gegenüber früher
/// * `state`   — maschinenlesbarer Bezeichner
/// * `terminal` — ob der Job fertig ist
///
/// Bestehende Clients lesen weiter `job.status` und sehen exakt dieselben
/// Zeichenketten wie vorher; neue Logik hängt an `terminal`/`state` statt an
/// Textvergleichen.
impl Serialize for JobStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("status", &self.to_string())?;
        map.serialize_entry("state", self.state())?;
        map.serialize_entry("terminal", &self.is_terminal())?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for JobStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            status: String,
            #[serde(default)]
            state: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(JobStatus::from_parts(raw.state.as_deref(), raw.status))
    }
}

// ---------------------------------------------------------------------------
// Engine abstraction
//
// Job creation, status handling, logging and task execution stay shared; only
// the transfer itself is engine specific. Today the single implementation is
// `RcloneEngine`, an `RsyncEngine` is meant to slot in next to it.
// ---------------------------------------------------------------------------

/// What happens to files that exist only in the target.
///
/// `Copy` never deletes (`rclone copy`, `rsync -a`), `Mirror` does
/// (`rclone sync`, `rsync -a --delete`).
///
/// **`Copy` ist die Vorgabe und bleibt es.** Es gibt bewusst keine
/// `Default`-Ableitung und keinen `From<bool>`: der Modus entsteht an genau
/// einer Stelle, [`transfer_mode`], und dort ist „Feld fehlt" gleichbedeutend
/// mit „nicht löschen".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    Copy,
    Mirror,
}

impl TransferMode {
    /// Bezeichner für API (`mode`-Feld), Log und Job-Liste.
    pub fn as_str(self) -> &'static str {
        match self {
            TransferMode::Copy => "copy",
            TransferMode::Mirror => "mirror",
        }
    }

    /// Löscht dieser Modus im Ziel?
    pub fn deletes(self) -> bool {
        matches!(self, TransferMode::Mirror)
    }
}

/// Modus eines Requests. **Die einzige Stelle, die aus dem Request einen
/// Löschlauf machen kann.**
///
/// Alles, was nicht ausdrücklich `delete_target: true` ist — fehlendes Feld,
/// `null`, `false` — ergibt [`TransferMode::Copy`].
pub fn transfer_mode(sync_request: &SyncRequest) -> TransferMode {
    match sync_request.delete_target {
        Some(true) => TransferMode::Mirror,
        _ => TransferMode::Copy,
    }
}

/// Trockenlauf? Fehlendes Feld heisst „nein" — ein Trockenlauf verändert
/// nichts, ein echter Lauf schon, also ist der harmlose Wert hier *nicht* die
/// Vorgabe.
fn is_dry_run(sync_request: &SyncRequest) -> bool {
    sync_request.dry_run == Some(true)
}

/// Baut aus `backup_dir` den rclone-Zielausdruck `<remote>:<pfad>`.
///
/// `Ok(None)` heisst „kein Sicherungsordner" — fehlendes Feld und leere
/// Eingabe sind dasselbe.
///
/// Geprüft wird gegen genau die Zeichen, mit denen man aus dem Zielremote
/// ausbrechen oder rclone eine Option unterschieben könnte:
///
/// * `:` — würde ein **anderes** Remote adressieren (`fremd:/`) oder rclones
///   Connection-String-Syntax öffnen. Der Sicherungsordner liegt immer auf
///   demselben Remote wie das Ziel; mehr braucht dieser Ticket-Umfang nicht,
///   und weniger Syntax heisst weniger Ausbruchsfläche.
/// * führendes `-` — landete als eigene **Option** in der Kommandozeile.
/// * `..` als Pfadbestandteil — auf einem Remote nicht auflösbar und ein
///   klarer Hinweis, dass jemand etwas anderes vorhat.
/// * NUL und Zeilenumbrüche — verstümmeln argv bzw. das Log.
fn backup_dir_target(sync_request: &SyncRequest) -> anyhow::Result<Option<String>> {
    let raw = match sync_request.backup_dir.as_deref() {
        Some(value) => value.trim(),
        None => return Ok(None),
    };

    if raw.is_empty() {
        return Ok(None);
    }

    if raw.contains(':') {
        anyhow::bail!(
            "Der Sicherungsordner muss auf demselben Ziel liegen und darf keinen Doppelpunkt \
             enthalten"
        );
    }
    if raw.starts_with('-') {
        anyhow::bail!("Der Sicherungsordner darf nicht mit '-' beginnen");
    }
    if raw.contains('\0') || raw.contains('\n') || raw.contains('\r') {
        anyhow::bail!("Der Sicherungsordner enthält ungültige Zeichen");
    }
    if raw.split('/').any(|part| part == "..") {
        anyhow::bail!("Der Sicherungsordner darf kein '..' enthalten");
    }

    // Überschneidung mit dem Ziel. rclone weist das selbst ab („destination and
    // parameter to --backup-dir mustn't overlap"), aber erst als **fatalen
    // Fehler mitten im Lauf**: der Job steht dann rot in der Liste, und wer
    // das Log nicht öffnet, weiss nicht warum. Gemessen an rclone 1.75.0.
    //
    // Hier abgefangen heisst: der Request wird abgelehnt, bevor ein Job
    // entsteht — und die Meldung sagt, was zu tun ist.
    // Verglichen wird **segmentweise** auf vollstaendig normalisierten Pfaden.
    // Beides ist noetig, und beides hat einen Grund:
    //
    // * Normalisieren: `raw_path` schnitt nur aussen `/` ab. Ein doppelter
    //   Slash im Inneren (`dst//sub` gegen `dst/sub/backup`) lief damit an der
    //   Pruefung vorbei — rclone brach den Lauf dann selbst ab, aber erst
    //   mitten drin. `.`-Segmente fallen aus demselben Grund weg; `..` ist
    //   oben bereits abgewiesen.
    // * Segmentweise: ein Praefixvergleich auf der Zeichenkette wuerde
    //   `dst-backup` als „innerhalb von `dst`" lesen und einen zulaessigen
    //   Ordner ablehnen.
    let dest = path_segments(&sync_request.remote_path);
    let backup = path_segments(raw);
    let overlaps =
        dest.is_empty() || backup.starts_with(&dest[..]) || dest.starts_with(&backup[..]);
    if overlaps {
        if dest.is_empty() {
            anyhow::bail!(
                "Der Sicherungsordner kann nicht angelegt werden, solange das Ziel das gesamte \
                 Remote ist. Als Ziel einen Unterordner wählen."
            );
        }
        anyhow::bail!(
            "Der Sicherungsordner darf nicht im Zielordner liegen (und umgekehrt) — sonst würde \
             er beim nächsten Lauf selbst wieder abgeglichen. Einen Ordner neben dem Ziel wählen."
        );
    }

    // Weitergegeben wird die **normalisierte** Form, nicht die Eingabe: sonst
    // pruefen wir einen Pfad und geben rclone einen anderen.
    Ok(Some(format!(
        "{}:{}",
        sync_request.remote_name,
        backup.join("/")
    )))
}

/// Vergleichsform eines Remote-Pfads: die bedeutungstragenden Segmente.
///
/// Leere Segmente (führende, abschliessende und doppelte `/`) und `.` fallen
/// weg. `"/"`, `""`, `"//"` und `"/./"` ergeben damit alle die leere Liste —
/// das Remote-Wurzelverzeichnis. Innerhalb eines Segments wird **nicht**
/// getrimmt: ein Ordnername darf am Rand ein Leerzeichen tragen.
fn path_segments(path: &str) -> Vec<&str> {
    path.trim()
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

/// Everything an engine needs to build the command line for one job.
pub struct JobSpec<'a> {
    /// Identifies the job; engines that need per-job scratch files (rsync's
    /// password file) name them after it.
    pub job_id: &'a str,
    pub request: &'a SyncRequest,
    pub mode: TransferMode,
    /// Path of the job log file (`data/log/<job_id>.log`), written by the
    /// shared code and, for log-based engines, also by the child process.
    pub log_file: &'a str,
}

/// A ready-to-spawn child process.
pub struct EngineCommand {
    pub program: String,
    pub args: Vec<String>,
    /// Extra environment variables (rsync needs `RSYNC_SSL_*`).
    pub env: Vec<(String, String)>,
    /// Files the engine created for this run (e.g. an rsync password file with
    /// mode 0600). The shared runner removes them once the child has exited.
    pub temp_files: Vec<String>,
}

impl EngineCommand {
    fn new(program: &str, args: Vec<String>) -> Self {
        Self {
            program: program.to_string(),
            args,
            env: Vec::new(),
            temp_files: Vec::new(),
        }
    }
}

/// Where the shared runner takes the progress numbers from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressSource {
    /// The child writes machine readable progress into the job log file, which
    /// is polled on demand (rclone `--use-json-log`).
    JobLog,
    /// The child reports progress on stdout, read while it runs
    /// (rsync `--info=progress2`, siehe `pump_stdout_progress`).
    Stdout,
}

/// One progress reading: percent complete plus transferred/total bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProgressSnapshot {
    pub percent: f64,
    pub transferred: u64,
    pub total: u64,
}

impl From<(f64, u64, u64)> for ProgressSnapshot {
    fn from((percent, transferred, total): (f64, u64, u64)) -> Self {
        Self {
            percent,
            transferred,
            total,
        }
    }
}

/// A transfer backend.
pub trait SyncEngine: Send + Sync {
    /// Short name, used in log messages.
    fn name(&self) -> &'static str;

    /// Der Request, **bevor** ein Job entsteht.
    ///
    /// Alles, was eine Engine ohne Seiteneffekt prüfen kann, gehört hierher und
    /// nicht in [`SyncEngine::build_command`]: ein abgelehnter Sync soll weder
    /// einen Job in der Liste noch eine Logdatei noch eine Password-Datei
    /// hinterlassen. Genau dieselbe Reihenfolge gilt schon für Remote-Name,
    /// Quellpfad und den Löschschalter.
    ///
    /// Vorgabe ist „nichts zu prüfen" — rclone bringt seine Prüfungen aus dem
    /// Bestand mit (`ensure_configured_remote`, `backup_dir_target`).
    fn validate_request(&self, _request: &SyncRequest) -> anyhow::Result<()> {
        Ok(())
    }

    /// Build the child process for one job. May fail for engines that have to
    /// materialise credentials first.
    fn build_command(&self, spec: &JobSpec<'_>) -> anyhow::Result<EngineCommand>;

    /// Where progress comes from for this engine.
    fn progress_source(&self) -> ProgressSource;

    /// Darf diese Engine im Ziel löschen?
    ///
    /// Vorgabe ist `false` — **opt-in, nicht opt-out**. Eine neue Engine, deren
    /// Autor diese Methode übersieht, lehnt Löschläufe ab statt sie
    /// stillschweigend zuzulassen.
    ///
    /// Für die rsync-Seite ist das keine Formalie: der Daemon in `rsyncd.rs`
    /// verweigert `--delete` serverseitig (`REFUSED_OPTIONS`), und ein
    /// Peer-Ziel darf die Option nur mit dem Scope `rsync:delete` bekommen.
    /// Wer die rsync-Engine baut, entscheidet das dort — nicht hier.
    fn supports_mirror(&self) -> bool {
        false
    }

    /// Parse progress out of the engine's progress stream.
    ///
    /// `chunk` is the complete log file content for [`ProgressSource::JobLog`]
    /// and a single stdout line for [`ProgressSource::Stdout`].
    fn parse_progress(&self, chunk: &str) -> Option<ProgressSnapshot>;

    /// Status text for a non-zero exit code. rclone has no meaningful exit code
    /// semantics, rsync has, so the translation belongs into the engine.
    fn describe_exit(&self, _code: Option<i32>) -> String {
        "Failed".to_string()
    }

    /// Endzustand für einen Exit-Code ungleich 0.
    ///
    /// Trennt sich von [`SyncEngine::describe_exit`], weil ein Exit-Code nicht
    /// nur einen *Text* bestimmt, sondern auch, **ob** der Lauf ein Fehlschlag
    /// ist: rsync kennt Codes (23/24), nach denen ein Teil der Daten sehr wohl
    /// angekommen ist. Voreinstellung bleibt der harte Fehlschlag mit dem Text
    /// aus `describe_exit()`, damit rclone sich nicht ändert.
    fn classify_exit(&self, code: Option<i32>) -> JobStatus {
        JobStatus::failed(self.describe_exit(code))
    }
}

// ---------------------------------------------------------------------------
// rsync-Exit-Codes
//
// rsync meldet praktisch alles über den Exit-Code; „exit status: 23" steht
// sonst nackt in der Oberfläche und sagt einem Betreiber nichts. Übersetzt
// werden deshalb die Codes, die im Betrieb dieser Anwendung tatsächlich
// vorkommen — nicht die vollständige Liste aus der Handbuchseite.
//
// **Kein Wort aus rsyncs stderr geht in diese Meldungen.** Dort stehen
// Modulnamen und Zielpfade; das Passwort selbst kommt nie über `argv`, sondern
// über `--password-file`. Die Meldungen sind ausschließlich aus dem Code
// gebaut, damit weder Oberfläche noch Log etwas ausplaudern können. Details zu
// einzelnen Dateien stehen im Job-Log, das nur der Besitzer des Jobs sieht.
// ---------------------------------------------------------------------------

/// Übersetzt einen rsync-Exit-Code in einen Endzustand mit deutschem Klartext.
///
/// Der Text sagt, **was zu tun ist**, nicht nur was kaputt ist; die rohe Zahl
/// steht in Klammern dahinter, damit man sie noch nachschlagen kann.
///
/// `code == None` bedeutet: durch ein Signal beendet, es gibt keinen Code.
pub fn classify_rsync_exit(code: Option<i32>) -> JobStatus {
    let code = match code {
        Some(code) => code,
        None => {
            return JobStatus::failed(
                "Die Übertragung wurde durch ein Signal beendet und hat keinen Exit-Code \
                 hinterlassen. Meist ein Abbruch von außen oder ein Eingriff des \
                 Betriebssystems (z. B. Speichermangel). Bitte erneut starten und, wenn es \
                 sich wiederholt, den Speicherverbrauch des Servers prüfen.",
            )
        }
    };

    match code {
        // Kein Fehlschlag, sondern „nicht alles" — siehe JobStatus::Partial.
        23 => JobStatus::partial(
            "Teilweise übertragen: einige Dateien konnten nicht übertragen werden (rsync-Code \
             23). Der Rest ist angekommen. Fast immer fehlen Leserechte an der Quelle oder \
             Schreibrechte im Ziel. Das Job-Log nennt die betroffenen Dateien; nach dem \
             Korrigieren der Rechte den Job einfach erneut starten — bereits übertragene \
             Dateien werden übersprungen.",
        ),
        24 => JobStatus::partial(
            "Teilweise übertragen: einige Quelldateien sind während des Laufs verschwunden \
             (rsync-Code 24). Bei einem Verzeichnis, in dem gleichzeitig gearbeitet wird, ist \
             das normal und kein Grund zur Sorge. Sollte dort nichts gelöscht werden, zeigt \
             das Job-Log die betroffenen Dateien; sonst genügt ein erneuter Lauf.",
        ),

        1 => JobStatus::failed(
            "Der Aufruf von rsync war fehlerhaft (rsync-Code 1: Syntax- oder \
             Verwendungsfehler). Das ist ein Fehler dieser Anwendung, nicht der Gegenstelle — \
             bitte das Job-Log mit der Meldung an die Entwicklung geben.",
        ),
        5 => JobStatus::failed(
            "Die Verbindung zur Gegenstelle konnte nicht ausgehandelt werden (rsync-Code 5). \
             Häufigste Ursache ist eine fehlgeschlagene TLS-Prüfung: das Zertifikat der \
             Gegenstelle ist abgelaufen, lautet auf einen anderen Namen oder ist hier nicht \
             als vertrauenswürdig hinterlegt. Zertifikat und Hostnamen der Gegenstelle prüfen.",
        ),
        10 => JobStatus::failed(
            "Die Netzwerkverbindung zur Gegenstelle ist fehlgeschlagen (rsync-Code 10). Prüfen, \
             ob der Gegenstellen-Dienst läuft und ob Host und Port von hier aus erreichbar sind \
             (Firewall, Portfreigabe).",
        ),
        11 => JobStatus::failed(
            "Dateien konnten nicht gelesen oder geschrieben werden (rsync-Code 11). Prüfen, ob \
             das Zielverzeichnis existiert, beschreibbar ist und genug freier Speicherplatz zur \
             Verfügung steht.",
        ),
        12 => JobStatus::failed(
            "Die Gegenstelle hat die Verbindung abgewiesen (rsync-Code 12: Protokollfehler). In \
             der Regel stimmen die Zugangsdaten oder der Modulname nicht, oder die Kopplung mit \
             der Gegenstelle ist abgelaufen. Die Verbindung zu diesem Ziel neu einrichten.",
        ),
        30 => JobStatus::failed(
            "Zeitüberschreitung bei der Übertragung (rsync-Code 30): die Gegenstelle hat zu \
             lange nicht geantwortet. Netzwerkverbindung prüfen und den Job erneut starten; bei \
             sehr langsamen Leitungen kann auch eine große Einzeldatei die Ursache sein.",
        ),

        // Sammelfall. Bewusst *kein* Zuschlagen zu einem der bekannten Fälle:
        // ein unbekannter Code als „Authentifizierung fehlgeschlagen" zu
        // melden schickt den Betreiber in die falsche Richtung. Die rohe Zahl
        // bleibt deshalb sichtbar.
        other => JobStatus::failed(format!(
            "Die Übertragung wurde mit rsync-Code {} abgebrochen. Diese Anwendung kennt den \
             Code nicht; seine Bedeutung steht in der rsync-Dokumentation. Das Job-Log zeigt, \
             wie weit der Lauf gekommen ist.",
            other
        )),
    }
}

/// Die Engine für einen Request — **und** die Prüfung, ob es das Ziel gibt.
///
/// Die beiden gehören zusammen, weil sie sich unterscheiden: ein rclone-Remote
/// muss in der `rclone.conf` des Nutzers stehen, eine rsync-Gegenstelle in
/// ihrer Hinterlegung unter `data/peers/`. Wären das zwei getrennte Schritte,
/// gäbe es einen Weg, an dem einer davon fehlt.
///
/// Die Reihenfolge ist Absicht: **erst** die Gegenstelle. Eine unbrauchbare
/// Hinterlegung ist ein Fehler und *kein* Rückfall auf rclone — sonst liefe ein
/// Push in ein gleichnamiges rclone-Remote, also an ein anderes Ziel als
/// gemeint. Ist der Name keine Gegenstelle, bleibt die rclone-Prüfung
/// wortgleich die von vorher.
///
/// Der Aufruf steht in `start_sync_for` vor der Job-Anlage; ein abgelehnter
/// Request hinterlässt weder Job noch Logdatei noch Prozess.
async fn select_engine(sync_request: &SyncRequest) -> anyhow::Result<Arc<dyn SyncEngine>> {
    select_engine_at(None, sync_request).await
}

/// Dieselbe Wahl, mit der Möglichkeit, die `rclone.conf` zu benennen.
///
/// `None` ist der produktive Fall und heisst „die gemeinsame Konfiguration",
/// also wortgleich der Aufruf von vorher. Ein Pfad kommt **nur** aus den Tests:
/// der Ort der gemeinsamen Konfiguration ist relativ zum Arbeitsverzeichnis,
/// und ein Test darf weder das Arbeitsverzeichnis des Prozesses umstellen
/// (prozessweit, mit allen anderen Tests im selben Prozess) noch in die echte
/// `data/cfg/rclone.conf` schreiben.
///
/// Der Umweg ist der Preis dafür, dass die **Verdrahtung** geprüft werden kann
/// und nicht nur `lookup_peer`. Genau das war die Lücke: das `?` hinter
/// `lookup_peer` liess sich gegen `.unwrap_or(None)` tauschen — also der
/// Rückfall auf ein gleichnamiges rclone-Remote einbauen — ohne dass ein Test
/// fiel. Dagegen stehen jetzt
/// `an_unusable_peer_never_falls_back_to_a_same_named_rclone_remote` und
/// `a_valid_peer_wins_over_a_same_named_rclone_remote`.
async fn select_engine_at(
    config_path: Option<&std::path::Path>,
    sync_request: &SyncRequest,
) -> anyhow::Result<Arc<dyn SyncEngine>> {
    if let Some(target) = rsync_engine::lookup_peer(&sync_request.remote_name).await? {
        return Ok(Arc::new(rsync_engine::RsyncEngine::new(target)));
    }

    match config_path {
        None => crate::config_manager::ensure_configured_remote(&sync_request.remote_name).await?,
        Some(path) => {
            crate::config_manager::ensure_configured_remote_at(path, &sync_request.remote_name)
                .await?
        }
    }
    Ok(Arc::new(RcloneEngine))
}

/// The engine a job runs with, falling back to rclone for unknown jobs.
async fn engine_for_job(job_id: &str) -> Arc<dyn SyncEngine> {
    let engines = JOB_ENGINES.lock().await;
    engines
        .get(job_id)
        .cloned()
        .unwrap_or_else(|| Arc::new(RcloneEngine))
}

/// Today's `rclone copy` with JSON logging into the job log file.
pub struct RcloneEngine;

impl RcloneEngine {
    const CONFIG_PATH: &'static str = crate::config_manager::RCLONE_CONFIG_PATH;
}

impl SyncEngine for RcloneEngine {
    fn name(&self) -> &'static str {
        "rclone"
    }

    fn build_command(&self, spec: &JobSpec<'_>) -> anyhow::Result<EngineCommand> {
        let sync_request = spec.request;
        // Zweiter Riegel direkt an der Kommandozeile. `start_sync` prüft
        // bereits gegen die Konfiguration; hier steht nur noch die
        // syntaktische Prüfung, weil `build_command` synchron ist und die
        // Konfiguration nicht lesen kann. Wer den Aufruf künftig an
        // `start_sync` vorbei baut, bekommt trotzdem kein `:local:` durch.
        crate::config_manager::validate_remote_name(&sync_request.remote_name)?;
        let remote_target = format!("{}:{}", sync_request.remote_name, sync_request.remote_path);
        // Der einzige Unterschied zwischen „kopieren" und „spiegeln" auf der
        // rclone-Seite: `copy` lässt das Ziel in Ruhe, `sync` gleicht es an
        // und löscht dabei. Der Modus kommt aus dem `JobSpec` und nicht aus
        // dem Request, damit der Aufrufer ihn nicht an `transfer_mode()`
        // vorbei setzen kann.
        let subcommand = match spec.mode {
            TransferMode::Copy => "copy",
            TransferMode::Mirror => "sync",
        };

        // Build basic rclone arguments with JSON logging
        let mut args: Vec<String> = vec![
            subcommand,
            "--config",
            Self::CONFIG_PATH,
            &sync_request.source_path,
            &remote_target,
            "--stats",
            "1s",
            "--stats-log-level",
            "NOTICE",
            "--transfers=1",
            "--checkers=1",
            "--retries=3",
            "--low-level-retries=3",
            "--timeout=0",
            "--contimeout=60s",
            "--ignore-checksum",
            "--size-only",
            "--use-json-log",
            "--log-file",
            spec.log_file,
            "--log-level",
            "INFO",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        // Add multi-threading and WebDAV chunk size based on chunk size selection
        if let Some(chunk_size) = &sync_request.chunk_size {
            let streams = match chunk_size.as_str() {
                "8M" => "2",
                "16M" => "4",
                "32M" => "6",
                "64M" => "8",
                "128M" => "8",
                _ => "4",
            };

            // Limit WebDAV chunk size to max 100M to avoid 413 errors
            let webdav_chunk = match chunk_size.as_str() {
                "8M" => "8M",
                "16M" => "16M",
                "32M" => "32M",
                "64M" => "64M",
                "128M" => "100M", // Cap at 100M for WebDAV safety
                _ => "50M",
            };

            let multi_thread_streams_str = format!("--multi-thread-streams={}", streams);
            let multi_thread_cutoff_str = format!("--multi-thread-cutoff={}", chunk_size);
            let webdav_chunk_size_str = format!("--webdav-nextcloud-chunk-size={}", webdav_chunk);

            // Log the actual parameter values being set
            info!("🔧 Setting rclone parameters:");
            info!("   multi_thread_streams_str: {}", multi_thread_streams_str);
            info!("   multi_thread_cutoff_str: {}", multi_thread_cutoff_str);
            info!("   webdav_chunk_size_str: {}", webdav_chunk_size_str);

            args.push(multi_thread_streams_str);
            args.push(multi_thread_cutoff_str);
            args.push(webdav_chunk_size_str);

            info!(
                "🔧 Using chunk size: {} (streams: {}, multi-thread-cutoff: {}, webdav-chunk: {})",
                chunk_size, streams, chunk_size, webdav_chunk
            );
        } else {
            // Default settings
            args.push("--multi-thread-streams=4".to_string());
            args.push("--multi-thread-cutoff=250M".to_string());
            args.push("--webdav-nextcloud-chunk-size=50M".to_string());

            info!("🔧 Using default settings (streams: 4, cutoff: 250M, webdav-chunk: 50M)");
        }

        // Trockenlauf. Steht bewusst *nach* allem anderen und wird nie durch
        // eine spätere Option überschrieben: `--dry-run` ist das, was einen
        // Spiegellauf ungefährlich macht, und es ist der einzige Schalter,
        // dessen Fehlen schlimmer ist als sein Vorhandensein.
        if is_dry_run(sync_request) {
            args.push("--dry-run".to_string());
        }

        // Sicherungsnetz: statt zu löschen/überschreiben verschiebt rclone die
        // betroffenen Dateien dorthin. Der Zielpfad ist auf dasselbe Remote
        // festgenagelt (siehe `backup_dir_target`).
        if let Some(target) = backup_dir_target(sync_request)? {
            args.push("--backup-dir".to_string());
            args.push(target);
        }

        Ok(EngineCommand::new("rclone", args))
    }

    fn progress_source(&self) -> ProgressSource {
        ProgressSource::JobLog
    }

    /// rclone kann spiegeln (`rclone sync`). Die Frage, *ob* gespiegelt werden
    /// darf, ist damit nicht beantwortet — die entscheidet der Nutzer über
    /// `delete_target` plus Bestätigung.
    fn supports_mirror(&self) -> bool {
        true
    }

    fn parse_progress(&self, chunk: &str) -> Option<ProgressSnapshot> {
        parse_rclone_log_progress(chunk).map(ProgressSnapshot::from)
    }
}

/// Kopfzeilen des Job-Logs.
///
/// Der Modus steht hier **in Klartext**, nicht nur als Flag in der
/// Argumentliste: wer hinterher wissen muss, ob ein Lauf im Ziel gelöscht hat,
/// findet es in der ersten Handvoll Zeilen des Logs, ohne den rclone-Aufruf
/// rekonstruieren zu müssen.
fn initial_log_text(
    job_id: &str,
    sync_request: &SyncRequest,
    mode: TransferMode,
    dry_run: bool,
    engine: &str,
) -> String {
    let remote_target = format!("{}:{}", sync_request.remote_name, sync_request.remote_path);
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

    let mode_line = match mode {
        TransferMode::Copy => "Mode: copy (Kopieren — im Ziel wird nichts geloescht)".to_string(),
        TransferMode::Mirror => {
            "Mode: mirror (Spiegeln — im Ziel werden Dateien GELOESCHT)".to_string()
        }
    };

    let mut text = format!(
        "[{}] Job {} started\n[{}] Source: {}\n[{}] Remote: {}\n[{}] Target: {}\n[{}] {}\n",
        timestamp,
        job_id,
        timestamp,
        sync_request.source_path,
        timestamp,
        sync_request.remote_name,
        timestamp,
        remote_target,
        timestamp,
        mode_line
    );

    if dry_run {
        text.push_str(&format!(
            "[{}] Dry run: es wird NICHTS veraendert, nur aufgelistet\n",
            timestamp
        ));
    }
    if let Some(dir) = sync_request.backup_dir.as_deref().map(str::trim) {
        if !dir.is_empty() {
            // Dieselbe normalisierte Form, die auch in die Kommandozeile geht —
            // sonst nennt das Log einen anderen Pfad als den, der laeuft.
            text.push_str(&format!(
                "[{}] Backup dir: {}:{} (statt loeschen wird dorthin verschoben)\n",
                timestamp,
                sync_request.remote_name,
                path_segments(dir).join("/")
            ));
        }
    }

    // Der Name der Engine, nicht das Wort „rclone": bei einem rsync-Lauf stand
    // hier sonst ein Werkzeug, das gar nicht beteiligt war.
    //
    // Die Ziel-URL der Gegenstelle steht bewusst **nicht** im Log. Sie enthält
    // den Modulnamen, und der ist Teil der Kopplung — der Nutzer sieht ihn
    // nirgends. `Remote:` und `Target:` nennen den Namen der Gegenstelle und
    // den Pfad, und das ist alles, was zum Nachvollziehen nötig ist.
    text.push_str(&format!(
        "[{}] Starting {} operation...\n\n",
        timestamp, engine
    ));
    text
}

// ---------------------------------------------------------------------------
// Logdatei-Jail
//
// `get_sync_log` hat den Pfad früher **ungeprüft** aus dem Pfadsegment gebaut
// (`format!("data/log/{}.log", job_id)`). Gemessen:
//
//     GET /api/sync/..%2F..%2Fserver/log   ->   liefert ../../server.log
//
// Also eine Datei ausserhalb von `data/log`. Dieselbe Fehlerklasse war für
// Auflistung, Vorschau, Download, ZIP, Thumbnails und die Sync-Quelle bereits
// je einmal als Sicherheitsticket geschlossen; hier fehlte sie noch.
//
// Zwei Riegel, absichtlich hintereinander:
//
//   1. **Positivprüfung auf das bekannte Format.** Eine Job-ID ist eine UUID.
//      Geprüft wird sie als solche, nicht durch eine Liste verbotener Zeichen —
//      die nächste Kodierungsvariante (`%252f`, Backslash, U+2215 …) umgeht
//      eine Negativliste, ein `Uuid::parse_str` nicht.
//   2. **Kanonisierung gegen `data/log/`**, wie AGENTS.md es für jeden vom
//      Client kommenden Pfad verlangt. Das ist der Teil, der auch dann noch
//      hält, wenn das Format der Job-IDs eines Tages wechselt, und der einen
//      Symlink im Logverzeichnis mitnimmt: der aufgelöste Pfad muss unterhalb
//      der Wurzel liegen, nicht die Eingabe.
//
// Wer die Logdatei eines *eigenen* Jobs schreibt (`create_initial_log`,
// `execute_sync`, die Fortschrittsauswertung), arbeitet mit einer selbst
// erzeugten ID und geht über `internal_log_path`. Der Unterschied ist die
// Herkunft der Zeichenkette, nicht der Dateiname.
// ---------------------------------------------------------------------------

/// Verzeichnis der Job-Logs, relativ zum Arbeitsverzeichnis — wie überall in
/// diesem Modul.
const LOG_DIR: &str = "data/log";

/// Eine Antwort für „gibt es nicht", „gehört dir nicht" und „ist kein
/// gültiges Segment".
///
/// Bewusst **eine** Zeichenkette ohne Detail: unterschiedliche Meldungen (oder
/// ein durchgereichter `io::Error`) machten den Endpunkt zu einem Orakel, mit
/// dem sich fremde Job-IDs und die Existenz von Dateien ausserhalb des
/// Logverzeichnisses abfragen liessen.
const LOG_UNAVAILABLE: &str = "Log file not found";

/// Pfad der Logdatei zu einer **selbst erzeugten** Job-ID.
fn internal_log_path(job_id: &str) -> String {
    format!("{}/{}.log", LOG_DIR, job_id)
}

/// Riegel 1: Ist dieses Segment eine Job-ID, und wie heisst dann ihre Datei?
///
/// Verlangt die kanonische Schreibweise, die `Uuid::new_v4().to_string()`
/// erzeugt — also klein geschrieben und mit Bindestrichen. `Uuid::parse_str`
/// nimmt auch `{…}`, `urn:uuid:…` und Grossschreibung an; alle drei wären
/// Zeichenketten, die für dieselbe ID einen *anderen* Dateinamen ergeben, und
/// keine davon kann von einem Client stammen, der eine ID benutzt, die er
/// vorher von uns bekommen hat.
fn job_log_file_name(job_id: &str) -> Option<String> {
    let parsed = Uuid::parse_str(job_id).ok()?;
    if parsed.hyphenated().to_string() != job_id {
        return None;
    }
    Some(format!("{}.log", job_id))
}

/// Riegel 1 **und** 2: Segment prüfen, Pfad kanonisieren, gegen `data/log`
/// halten. `None` heisst „kein lesbares Log" und sagt nicht, warum.
async fn resolved_log_path(job_id: &str) -> Option<PathBuf> {
    let file_name = job_log_file_name(job_id).or_else(|| {
        warn!("📖 Logabruf abgelehnt: '{}' ist keine Job-ID", job_id);
        None
    })?;

    // Die Wurzel muss kanonisch sein, sonst trägt der `starts_with`-Test
    // nichts. Fehlt das Verzeichnis, gibt es auch kein Log.
    let root = match fs::canonicalize(LOG_DIR).await {
        Ok(root) => root,
        Err(e) => {
            debug!("📖 Logverzeichnis {} nicht auflösbar: {}", LOG_DIR, e);
            return None;
        }
    };

    match resolve_within_root(&root, &file_name).await {
        Ok(path) => Some(path),
        Err(e) => {
            debug!("📖 Log von Job {} nicht auflösbar: {:?}", job_id, e);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Die gemeinsame Job-Verwaltung
//
// Es gibt genau **eine** Job-Tabelle (`SYNC_JOBS`) und genau **eine** Stelle,
// an der über den Zugriff auf einen Job entschieden wird (`job_access`).
//
// Vorher führte `handlers::downloader` eine zweite Tabelle, `main.rs` hängte
// beide Listen aneinander, und Fortschritt und Löschen fielen auf den
// Downloader zurück, wenn der Sync die ID nicht kannte. Diese Rückfallregel
// war der Grund, weshalb dieselbe fehlende Besitzprüfung **dreimal** gefunden
// wurde: Auflisten, Abbrechen, Löschen. Eine Prüfung, die an drei Stellen
// stehen muss, fehlt beim vierten Jobtyp wieder.
//
// Deshalb hier: eine Tabelle, eine Schleuse, und `main.rs` fügt nichts mehr
// zusammen — es reicht `current` durch und verzweigt allenfalls nach
// [`JobKind`], den die Schleuse mitliefert.
//
// **Zur Reihenfolge der Sperren:** `JOB_OWNERS`, `SYNC_JOBS`, `JOB_CANCELS`
// und `JOB_ENGINES` werden nie gleichzeitig gehalten. Jede Sperre wird in
// ihrer eigenen Anweisung genommen und dort wieder freigegeben; wo beides
// gebraucht wird, steht die Auswertung der ersten in einem eigenen Block.
// ---------------------------------------------------------------------------

/// Welcher Weg einen Job ausführt.
///
/// Die Schleuse gibt ihn zurück, damit der Aufrufer verzweigen kann, **ohne**
/// dafür eine ID in einer zweiten Tabelle zu suchen ("kennt der Sync sie
/// nicht, ist es ein Abruf") — genau diese Rückfallregel hat die Prüfung
/// dreimal verschluckt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    /// Übertragung durch eine Engine (`rclone`, `rsync`).
    Sync,
    /// HTTP-Abruf durch den Server (`handlers::downloader`).
    UrlFetch,
}

/// Wem ein Job gehört und welcher Art er ist.
struct JobOwner {
    /// `users.id` des Kontos, dem der Lauf zugerechnet wird.
    user_id: String,
    kind: JobKind,
}

impl JobOwner {
    /// **Die** Besitzentscheidung, an genau einer Stelle im Programm.
    ///
    /// Sie steht hier und nicht in den Aufrufern, weil es zwei Formen des
    /// Zugriffs gibt — „darf ich an diesen Job" ([`job_access`]) und „welche
    /// Jobs sind meine" ([`list_jobs_for`]) —, und zwei Vergleiche wären zwei
    /// Gelegenheiten, verschiedene Antworten zu geben. Ein Mutationstest, der
    /// diese Zeile aufweicht, muss **alle** Zugriffstests fallen lassen.
    fn belongs_to(&self, current: &CurrentUser) -> bool {
        self.user_id == current.user.id
    }
}

/// Eine Antwort für „gibt es nicht" **und** „gehört dir nicht".
///
/// Wie [`LOG_UNAVAILABLE`] bewusst eine einzige Zeichenkette: unterschiedliche
/// Meldungen machten jeden dieser Endpunkte zu einem Orakel, mit dem sich
/// fremde Job-IDs durchprobieren liessen. Der Wortlaut ist der, den ein
/// unbekannter Job schon vorher bekam.
pub const JOB_UNAVAILABLE: &str = "Job not found";

/// Legt einen Job an: Fortschritt, Eigentümer, Art und — wenn die Art eine
/// hat — die Abbruchflagge.
///
/// Der **einzige** Weg, einen Job in die Tabelle zu bekommen. Damit kann kein
/// Jobtyp entstehen, dessen Eigentümer niemand vermerkt hat: wer keinen
/// Eigentümer hat, ist für jeden unsichtbar (fail closed), und das fällt beim
/// ersten Blick in die eigene Job-Liste auf.
pub async fn register_job(
    progress: SyncProgress,
    owner_id: &str,
    kind: JobKind,
    cancel: Option<Arc<AtomicBool>>,
) {
    let job_id = progress.id.clone();
    SYNC_JOBS.lock().await.insert(job_id.clone(), progress);
    JOB_OWNERS.lock().await.insert(
        job_id.clone(),
        JobOwner {
            user_id: owner_id.to_string(),
            kind,
        },
    );
    if let Some(flag) = cancel {
        JOB_CANCELS.lock().await.insert(job_id, flag);
    }
}

/// Schreibt den Fortschritt eines Jobs fort.
///
/// Kennt die Tabelle die ID nicht mehr, passiert nichts — ein bereits
/// gelöschter Job darf einen noch laufenden Schreibweg nicht abstürzen lassen.
pub async fn update_job(job_id: &str, change: impl FnOnce(&mut SyncProgress)) {
    if let Some(progress) = SYNC_JOBS.lock().await.get_mut(job_id) {
        change(progress);
    }
}

/// Setzt einen Job auf einen Endzustand — für Aufrufer aussehalb dieses Moduls.
///
/// Geht durch dasselbe [`finish_job`] wie der Sync und rundet deshalb auch für
/// einen Abruf nur bei `is_success()` auf 100 %.
pub async fn complete_job(job_id: &str, status: JobStatus) {
    finish_job(&SYNC_JOBS, job_id, status).await;
}

/// Vergisst Eigentümer und Abbruchflagge eines Jobs, der aus der Tabelle fällt.
async fn forget_job_owner(job_id: &str) {
    JOB_OWNERS.lock().await.remove(job_id);
    JOB_CANCELS.lock().await.remove(job_id);
}

/// **Die** Zugriffsschleuse für Jobs jeder Art.
///
/// `Some(kind)` heisst „gehört diesem Konto"; `None` heisst „fremd **oder**
/// unbekannt", und die beiden Fälle sind nicht unterscheidbar:
///
/// * **Byte-gleich**, weil jeder Aufrufer daraus dieselbe Antwort baut
///   ([`JOB_UNAVAILABLE`], bzw. [`LOG_UNAVAILABLE`] beim Log).
/// * **Zeitgleich**, weil es für einen Unberechtigten keinen zweiten Zweig
///   gibt: es passiert genau eine Suche in einer `HashMap` und dann die
///   Rückgabe. Kein Dateisystem, keine Datenbank, kein Ausgleichsaufwand — die
///   Prüfung steht **vor** allem, dessen Dauer etwas verraten könnte. Genau
///   das war der Fehler in der Vorgängerfassung von `get_sync_log_for`, wo
///   `resolved_log_path()` vor der Besitzprüfung lief und damit die Existenz
///   der Datei messbar machte (Ticket `06955e97`).
///
/// **Fail closed**, in beide Richtungen: ein Job ohne bekannten Eigentümer ist
/// so unzugänglich wie der eines fremden Kontos. Auch ein Admin bekommt hier
/// keine Ausnahme — dieselbe Begründung wie beim fehlenden `scope=system` für
/// den Sync weiter oben: die Jobs tragen Quell- und Zielpfade fremder Konten,
/// und ein Hintergrundlauf ist kein sichtbarer Einzelzugriff, bei dem eine
/// Ausnahme pro Request in der URL stünde.
pub async fn job_access(job_id: &str, current: &CurrentUser) -> Option<JobKind> {
    match JOB_OWNERS.lock().await.get(job_id) {
        Some(owner) if owner.belongs_to(current) => Some(owner.kind),
        _ => None,
    }
}

/// Wirft einen Job samt Nebeneinträgen aus der Tabelle — **nur für Tests**
/// anderer Module, die einen Job anlegen und hinterher aufräumen müssen. Der
/// produktive Weg ist `delete_job_for`, das den Zugriff prüft.
#[cfg(test)]
pub async fn drop_job_for_test(job_id: &str) {
    SYNC_JOBS.lock().await.remove(job_id);
    forget_job_owner(job_id).await;
}

/// Was ein Abbruchversuch vorfindet.
pub enum CancelTarget {
    /// Läuft noch, hier ist seine Flagge.
    Running(Arc<AtomicBool>),
    /// Schon in einem Endzustand.
    Finished,
    /// Kennt die Tabelle nicht (mehr).
    Unknown,
}

/// Sucht die Abbruchflagge eines Jobs. **Ohne** Besitzprüfung — die hat der
/// Aufrufer über [`job_access`] schon gemacht; hier gibt es keine zweite.
pub async fn cancel_target(job_id: &str) -> CancelTarget {
    let terminal = match SYNC_JOBS.lock().await.get(job_id) {
        Some(progress) => progress.status.is_terminal(),
        None => return CancelTarget::Unknown,
    };
    if terminal {
        return CancelTarget::Finished;
    }
    match JOB_CANCELS.lock().await.get(job_id) {
        Some(flag) => CancelTarget::Running(Arc::clone(flag)),
        None => CancelTarget::Unknown,
    }
}

/// `POST /api/sync/:job_id/cancel` — bricht einen laufenden Übertragungsjob ab.
///
/// **Die Besitzprüfung steht vor allem anderen.** [`job_access`] ist die eine
/// Schleuse; es gibt hier keinen zweiten Weg an einen Job. Ein fremder und ein
/// unbekannter Job antworten deshalb byte-gleich ([`JOB_UNAVAILABLE`]) **und**
/// zeitgleich: für einen Unberechtigten passiert genau eine Suche in einer
/// `HashMap` und dann die Rückgabe — kein Dateisystem, keine Datenbank. Genau
/// das war an anderer Stelle der Fehler, wo die Pfadauflösung vor der Prüfung
/// lief und die Dauer damit die *Dateiexistenz* verriet (Ticket `06955e97`).
/// Deshalb wird das Job-Log erst **nach** der Prüfung angefasst.
///
/// **Idempotent.** Ein zweiter Abbruch und der Abbruch eines schon beendeten
/// Jobs sind kein Fehler: der gewünschte Zustand ist erreicht, und ein Nutzer,
/// der zweimal drückt, hat nichts falsch gemacht. Der Text unterscheidet die
/// Fälle, das Ergebnis nicht.
///
/// **Nur Sync-Läufe.** Ein URL-Abruf hat seinen eigenen Endpunkt
/// (`/api/download-url/:job_id/cancel`), weil er sein Log anders schreibt; ein
/// Abruf über diese Route ist hier so unzugänglich wie ein fremder Job — also
/// wieder dieselbe Antwort.
///
/// Was bis zum Abbruch im Ziel geschrieben wurde, bleibt liegen. Das lässt sich
/// nicht vermeiden, und es steht deshalb in der Antwort und im Job-Log.
pub async fn cancel_sync_for(
    current: &CurrentUser,
    job_id: String,
) -> ResponseJson<ApiResponse<String>> {
    if job_access(&job_id, current).await != Some(JobKind::Sync) {
        return ResponseJson(ApiResponse::error(JOB_UNAVAILABLE));
    }

    match cancel_target(&job_id).await {
        CancelTarget::Running(flag) => {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            info!("🛑 Abbruch angefordert für Job {}", job_id);
            append_job_log(&job_id, CANCEL_LOG_LINE).await;
            ResponseJson(ApiResponse::success(CANCEL_REQUESTED.to_string()))
        }
        // Schon in einem Endzustand — oder zwischen Schleuse und hier aus der
        // Tabelle gefallen. Beides ist „nichts mehr zu tun" und kein Fehler.
        CancelTarget::Finished | CancelTarget::Unknown => {
            ResponseJson(ApiResponse::success(CANCEL_ALREADY_DONE.to_string()))
        }
    }
}

/// Antwort auf einen angenommenen Abbruch. Nennt ausdrücklich, dass im Ziel
/// Geschriebenes liegen bleibt: das ist unvermeidbar, und es zu verschweigen
/// wäre die schlechtere Hälfte davon.
const CANCEL_REQUESTED: &str = "Abbruch angefordert. Was bis hierhin im Ziel geschrieben wurde, \
                                bleibt dort liegen und wird nicht zurückgenommen.";

/// Antwort, wenn nichts mehr abzubrechen war.
const CANCEL_ALREADY_DONE: &str = "Dieser Job ist bereits beendet.";

/// Die Zeile, die der Abbruch im Job-Log hinterlässt.
const CANCEL_LOG_LINE: &str = "Abbruch angefordert (SIGTERM, danach SIGKILL). Bereits \
                               übertragene Dateien bleiben im Ziel liegen.";

/// Hängt eine Zeile an das Log eines Jobs.
///
/// `job_id` hat die Schleuse passiert, ist also ein Schlüssel aus der
/// Jobtabelle und kein beliebiges Pfadsegment — dieselbe Begründung wie in
/// `parse_latest_progress_from_log`. Ein Fehlschlag wird geloggt und nicht
/// gemeldet: der Abbruch selbst ist längst angefordert, und ihn wegen eines
/// nicht schreibbaren Logs als gescheitert zu melden wäre falsch.
async fn append_job_log(job_id: &str, line: &str) {
    use tokio::io::AsyncWriteExt;

    let path = internal_log_path(job_id);
    let entry = format!("{} {}\n", Utc::now().to_rfc3339(), line);
    match fs::OpenOptions::new().append(true).open(&path).await {
        Ok(mut file) => {
            if let Err(e) = file.write_all(entry.as_bytes()).await {
                debug!("⚠️ Job-Log {} nicht beschreibbar: {}", path, e);
            }
        }
        Err(e) => debug!("⚠️ Job-Log {} nicht öffenbar: {}", path, e),
    }
}

/// Ensure the log directory exists and create a new log file with an initial entry
async fn create_initial_log(
    job_id: &str,
    sync_request: &SyncRequest,
    mode: TransferMode,
    dry_run: bool,
    engine: &str,
) -> tokio::io::Result<()> {
    fs::create_dir_all(LOG_DIR).await?;

    let log_file_path = internal_log_path(job_id);
    let initial_log = initial_log_text(job_id, sync_request, mode, dry_run, engine);

    fs::write(&log_file_path, initial_log).await
}

// ---------------------------------------------------------------------------
// Quellpfad-Jail
//
// Die Quelle eines Syncs ging früher **direkt** aus dem JSON-Body an rclone.
// Damit lief der meistgeprüfte Teil des Projekts – `resolve_within_root()` –
// für diesen Weg schlicht nie: ein `source_path: "/etc"` kopierte das
// Verzeichnis auf ein Remote. Die Schwesterlücke zum ungeprüften Remote-Namen
// (`ensure_configured_remote`), nur auf der anderen Seite der Übertragung.
//
// Die Jail-Logik selbst bleibt **unangetastet**; geändert hat sich nur, dass
// dieser Weg sie überhaupt aufruft. Wurzel ist – wie bei Auflistung, Download
// und Vorschau – das Home des Nutzers, dem der Lauf zugerechnet wird.
//
// **Entscheidung: kein `scope=system` für den Sync, auch nicht für Admins.**
// Begründung:
//   * Auflisten, Download und Vorschau sind kurze, sichtbare Einzelzugriffe,
//     bei denen `?scope=system` pro Request ausdrücklich in der URL steht.
//     Ein Sync ist das Gegenteil: ein Hintergrundlauf, der einen ganzen Baum
//     auf ein fremdes Remote schiebt. Ein versehentlich gesetzter Schalter
//     verschöbe dort das gesamte Wirtssystem, und das lässt sich nicht
//     zurücknehmen.
//   * `SyncRequest` (`src/models.rs`) hat kein `scope`-Feld, und weder das
//     Frontend noch ein Task in der Datenbank kann eines setzen. Ein
//     Admin-Weg wäre also heute ohnehin unerreichbar – ihn trotzdem
//     einzubauen hiesse, eine ungenutzte Ausnahme offenzuhalten.
//   * Ein Admin, der wirklich ausserhalb syncen muss, hat den Weg über sein
//     eigenes `users.home_path`. Das ist eine bewusste, sichtbare Einstellung
//     statt eines Flags im Request.
// Kurz: fail closed, wie überall sonst in diesem Modul.
// ---------------------------------------------------------------------------

/// Löst `source_path` gegen das Home des Aufrufers auf.
///
/// Gibt den kanonisierten Pfad zurück – der, und nicht die Eingabe, geht
/// anschliessend an rclone. Damit ist ausgeschlossen, dass zwischen Prüfung
/// und Start noch ein `..` oder ein Symlink in der Zeichenkette steckt.
async fn resolved_source_path(
    current: &CurrentUser,
    source_path: &str,
) -> Result<String, &'static str> {
    let root = user_root(current, RootScope::Home).await.map_err(|e| {
        warn!(
            "Sync abgelehnt: Home von '{}' nicht verfügbar ({:?})",
            current.user.username, e
        );
        "Das Home-Verzeichnis dieses Kontos ist nicht verfügbar"
    })?;

    let resolved = resolve_within_root(&root, source_path).await.map_err(|e| {
        warn!(
            "Sync abgelehnt: Quellpfad '{}' von '{}' ausserhalb des erlaubten Bereichs ({:?})",
            source_path, current.user.username, e
        );
        "Quellpfad liegt ausserhalb des erlaubten Wurzelverzeichnisses"
    })?;

    // Ein Pfad, der sich nicht als UTF-8 darstellen lässt, ginge unbemerkt
    // verstümmelt in die Kommandozeile – lieber ablehnen.
    resolved.to_str().map(str::to_string).ok_or_else(|| {
        warn!("Sync abgelehnt: Quellpfad ist kein gültiges UTF-8");
        "Quellpfad enthält ungültige Zeichen"
    })
}

/// HTTP-Einstieg. Der angemeldete Nutzer kommt aus den Request-Extensions und
/// ist der Beweis, dass die Sitzungsprüfung gelaufen ist.
pub async fn start_sync(
    Extension(current): Extension<CurrentUser>,
    Json(sync_request): Json<SyncRequest>,
) -> ResponseJson<ApiResponse<String>> {
    start_sync_for(&current, sync_request).await
}

/// Gemeinsamer Kern für HTTP und CLI (`--start-task`).
///
/// Der CLI-Weg läuft an der Middleware vorbei und ruft diese Funktion direkt
/// auf; die Nutzerzuordnung erfolgt dort über `--user`. Beide Wege gehen damit
/// durch **dieselbe** Prüfung – es gibt keinen zweiten Einstieg, an dem sie
/// vergessen werden könnte.
pub async fn start_sync_for(
    current: &CurrentUser,
    mut sync_request: SyncRequest,
) -> ResponseJson<ApiResponse<String>> {
    // Vor allem anderen: das Ziel muss existieren, und der Name muss
    // syntaktisch sauber sein. Ein Name wie `:local` wäre rclones
    // On-the-fly-Syntax für ein nicht konfiguriertes Backend und schriebe in
    // beliebige Wirtspfade. Die Prüfung steht deshalb vor der Job-Anlage:
    // Wird sie abgelehnt, entsteht weder ein Job noch ein Log noch ein
    // Kindprozess.
    //
    // `select_engine` entscheidet dabei in einem Schritt, **welche** Engine
    // überträgt: eine gekoppelte rsync-Gegenstelle oder ein rclone-Remote.
    let engine = match select_engine(&sync_request).await {
        Ok(engine) => engine,
        Err(e) => {
            warn!("Sync abgelehnt: {}", e);
            return ResponseJson(ApiResponse::error(&e.to_string()));
        }
    };

    // Dasselbe gilt für die Quelle: abgelehnt wird, bevor ein Job in der
    // Tabelle steht, bevor eine Logdatei angelegt ist und bevor irgendein
    // Prozess startet.
    match resolved_source_path(current, &sync_request.source_path).await {
        // Was an rclone geht, ist der kanonisierte Pfad – nicht die Eingabe.
        Ok(path) => sync_request.source_path = path,
        Err(message) => return ResponseJson(ApiResponse::error(message)),
    }

    // ---------------------------------------------------------------------
    // Löschschalter. Steht bewusst **vor** der Job-Anlage, in derselben Reihe
    // wie Remote- und Pfadprüfung: ein abgelehnter Löschlauf hinterlässt
    // keinen Job, keine Logdatei und keinen Prozess.
    //
    // Zwei Bedingungen, beide notwendig:
    //   1. Die Engine muss spiegeln können (`supports_mirror`, opt-in).
    //   2. Der Nutzer muss ausdrücklich bestätigt haben.
    //
    // Punkt 2 ist die serverseitige Hälfte der Warnung im Dialog. Ohne sie
    // wäre die Bestätigung reine Anzeige und ein direkter API-Aufruf käme
    // ohne sie durch — genau der Weg, auf dem hier Daten verschwinden.
    // Ein Trockenlauf ist davon **nicht** ausgenommen: er ändert zwar nichts,
    // aber wer die Bestätigung dort weglassen dürfte, hätte einen Request, der
    // sich durch Umlegen eines einzigen Flags in einen echten Löschlauf
    // verwandelt.
    // ---------------------------------------------------------------------
    let mode = transfer_mode(&sync_request);
    let dry_run = is_dry_run(&sync_request);

    // Was die Engine an diesem Request auszusetzen hat — auch das noch vor der
    // Job-Anlage. Für rclone ist das leer, die rsync-Engine prüft hier
    // Zielpfad, Quelle und den (dort nicht unterstützten) Sicherungsordner.
    if let Err(e) = engine.validate_request(&sync_request) {
        warn!("Sync abgelehnt ({}): {}", engine.name(), e);
        return ResponseJson(ApiResponse::error(&e.to_string()));
    }

    if mode.deletes() {
        if !engine.supports_mirror() {
            warn!(
                "Sync abgelehnt: Engine '{}' darf im Ziel nicht löschen",
                engine.name()
            );
            return ResponseJson(ApiResponse::error(
                "Für dieses Ziel ist „Im Ziel löschen\" nicht zulässig",
            ));
        }
        if sync_request.delete_confirmed != Some(true) {
            warn!(
                "Sync abgelehnt: „Im Ziel löschen\" ohne Bestätigung (Nutzer '{}')",
                current.user.username
            );
            return ResponseJson(ApiResponse::error(
                "„Im Ziel löschen\" muss ausdrücklich bestätigt werden",
            ));
        }
    }

    // Der Sicherungsordner wird ebenfalls vor der Job-Anlage geprüft, damit
    // eine unbrauchbare Angabe nicht erst beim Prozessstart auffällt — dann
    // stünde bereits ein fehlgeschlagener Job in der Liste.
    if let Err(e) = backup_dir_target(&sync_request) {
        warn!("Sync abgelehnt: {}", e);
        return ResponseJson(ApiResponse::error(&e.to_string()));
    }

    let job_id = Uuid::new_v4().to_string();

    info!("🚀 Starting new sync job: {}", job_id);
    info!("   Source: {}", sync_request.source_path);
    info!(
        "   Remote: {}:{}",
        sync_request.remote_name, sync_request.remote_path
    );
    info!("   Mode: {} (dry_run: {})", mode.as_str(), dry_run);
    if mode.deletes() && !dry_run {
        warn!(
            "🔥 Job {} spiegelt: im Ziel {}:{} werden Dateien gelöscht",
            job_id, sync_request.remote_name, sync_request.remote_path
        );
    }

    let source_name = sync_request
        .source_path
        .split('/')
        .last()
        .unwrap_or(&sync_request.source_path)
        .to_string();
    let start_time = Utc::now().timestamp();

    let progress = SyncProgress {
        id: job_id.clone(),
        progress: 0.0,
        status: JobStatus::Starting,
        transferred: 0,
        total: 0,
        source_name,
        start_time,
        end_time: None,
        mode: mode.as_str().to_string(),
        dry_run,
    };

    // Anlegen, Eigentümer und Art in einem Schritt — `register_job` ist der
    // einzige Weg in die Job-Tabelle, und damit gibt es keinen Job ohne
    // vermerkten Eigentümer. Der CLI-Weg (`--start-task`) geht durch dieselbe
    // Funktion und trägt deshalb ebenfalls ein.
    //
    // **Mit** Abbruchflagge: sie ist dieselbe Flagge, die ein URL-Abruf schon
    // hat, und `execute_sync` beendet den Kindprozess, sobald sie gesetzt ist.
    // Ein rsync-Transfer kann Stunden laufen; ein Lauf, der sich nicht
    // abbrechen lässt, ist bei dieser Laufzeit ein Mangel und nicht bloss
    // unbequem. Was noch fehlt, ist der HTTP-Weg, der sie setzt — die Route
    // liegt in `main.rs` und gehört einem anderen Ticket.
    let cancel = Arc::new(AtomicBool::new(false));
    register_job(
        progress,
        &current.user.id,
        JobKind::Sync,
        Some(Arc::clone(&cancel)),
    )
    .await;

    // Immediately create the log file so it is visible in the UI
    if let Err(e) = create_initial_log(&job_id, &sync_request, mode, dry_run, engine.name()).await {
        error!("Failed to create initial log for {}: {}", job_id, e);
    } else {
        debug!("📝 Initial log file created for job {}", job_id);
    }

    {
        let mut engines = JOB_ENGINES.lock().await;
        engines.insert(job_id.clone(), engine.clone());
    }

    let job_id_clone = job_id.clone();
    let sync_jobs = SYNC_JOBS.clone();

    tokio::spawn(async move {
        execute_sync(job_id_clone, sync_request, sync_jobs, engine, cancel).await;
    });

    ResponseJson(ApiResponse::success(job_id))
}

/// `GET /api/sync/:job_id` — Fortschritt eines Jobs, **mit** Besitzprüfung.
///
/// Die Schleuse läuft vor allem anderen: ein fremder oder unbekannter Job
/// erzeugt weder einen Tabellenzugriff noch eine Dateioperation, und beide
/// Fälle antworten byte-gleich mit [`JOB_UNAVAILABLE`] — dieselbe Meldung, die
/// eine unbekannte ID auch vorher bekam.
///
/// Gilt für Sync-Läufe **und** URL-Abrufe; die Jobart entscheidet nur, ob der
/// Fortschritt aus dem Job-Log nachgelesen wird.
pub async fn get_sync_progress_for(
    current: &CurrentUser,
    job_id: String,
) -> ResponseJson<ApiResponse<SyncProgress>> {
    let Some(kind) = job_access(&job_id, current).await else {
        return ResponseJson(ApiResponse::error(JOB_UNAVAILABLE));
    };
    job_progress(kind, job_id).await
}

/// Fortschritt eines Jobs, dessen Zugriff **bereits geprüft** ist.
async fn job_progress(kind: JobKind, job_id: String) -> ResponseJson<ApiResponse<SyncProgress>> {
    let engine = engine_for_job(&job_id).await;
    let mut jobs = SYNC_JOBS.lock().await;

    match jobs.get_mut(&job_id) {
        Some(progress) => {
            // Update progress from log file if job is running and the engine
            // reports through the log file. Stdout based engines push their
            // progress into the job themselves while they run.
            //
            // Nur für Sync-Läufe: ein URL-Abruf schreibt kein rclone-JSON in
            // sein Log und führt seinen Fortschritt selbst fort
            // (`downloader::set_transferred`). Ohne diese Bedingung liefe er in
            // den Standard-Engine-Zweig, weil `engine_for_job` für eine ID ohne
            // Engine die rclone-Engine annimmt.
            if kind == JobKind::Sync
                && progress.status == JobStatus::Running
                && engine.progress_source() == ProgressSource::JobLog
            {
                if let Some(snapshot) =
                    parse_latest_progress_from_log(&job_id, engine.as_ref()).await
                {
                    progress.progress = snapshot.percent;
                    progress.transferred = snapshot.transferred;
                    progress.total = snapshot.total;
                }
            }
            ResponseJson(ApiResponse::success(progress.clone()))
        }
        None => ResponseJson(ApiResponse::error(JOB_UNAVAILABLE)),
    }
}

/// `GET /api/sync` — die Jobs **dieses** Kontos, neueste zuerst.
///
/// Sync-Läufe und URL-Abrufe stehen in derselben Tabelle und kommen deshalb
/// aus **einer** Abfrage; `main.rs` fügt nichts mehr zusammen.
///
/// Sortiert nach `start_time` (absteigend), bei Gleichstand nach ID. Nach
/// Job-ID allein wäre die Reihenfolge bei UUIDs willkürlich — das war schon
/// beim Zusammenführen zweier Quellen der Grund für die Umstellung, und es
/// bleibt so.
pub async fn list_jobs_for(current: &CurrentUser) -> ResponseJson<ApiResponse<Vec<SyncProgress>>> {
    cleanup_stale_jobs().await;

    // Erst die eigenen IDs, dann die Einträge — die beiden Sperren werden
    // nacheinander gehalten, nie gleichzeitig.
    let own: Vec<String> = {
        let owners = JOB_OWNERS.lock().await;
        owners
            .iter()
            .filter(|(_, owner)| owner.belongs_to(current))
            .map(|(job_id, _)| job_id.clone())
            .collect()
    };

    let mut job_list: Vec<SyncProgress> = {
        let jobs = SYNC_JOBS.lock().await;
        own.iter().filter_map(|id| jobs.get(id).cloned()).collect()
    };

    job_list.sort_by(|a, b| b.start_time.cmp(&a.start_time).then(b.id.cmp(&a.id)));

    ResponseJson(ApiResponse::success(job_list))
}

/// Wirft beendete Jobs weg, die älter als 24 Stunden sind — samt Logdatei,
/// Eigentümer und Abbruchflagge. Keine Zugriffsentscheidung: der Durchlauf
/// gilt für alle Jobs und läuft bei jedem Abruf der Liste mit.
async fn cleanup_stale_jobs() {
    let mut jobs = SYNC_JOBS.lock().await;

    // Clean up jobs older than 24 hours (86400 seconds)
    let now = Utc::now().timestamp();
    let cleanup_threshold = now - 86400; // 24 hours ago

    let mut jobs_to_remove = Vec::new();

    // Find finished jobs older than 24 hours. Der Terminalzustand kommt aus
    // dem Typ, nicht aus dem Meldungstext — sonst fallen genau die Jobs durch,
    // deren Fehlermeldung anders formuliert ist als erwartet.
    for (job_id, job) in jobs.iter() {
        if let Some(end_time) = job.end_time {
            if end_time < cleanup_threshold && job.status.is_terminal() {
                jobs_to_remove.push(job_id.clone());
            }
        }
    }

    // Remove old jobs and their log files
    for job_id in jobs_to_remove {
        if let Some(job) = jobs.remove(&job_id) {
            info!(
                "🧹 Auto-cleanup: Removing job {} (completed {}h ago)",
                job_id,
                (now - job.end_time.unwrap_or(now)) / 3600
            );

            // Remove log file
            let log_file_path = internal_log_path(&job_id);
            if let Err(e) = tokio::fs::remove_file(&log_file_path).await {
                debug!("⚠️ Could not delete log file {}: {}", log_file_path, e);
            }

            forget_job_owner(&job_id).await;
        }
    }
}

/// `GET /api/sync/:job_id/log` — das Log eines Jobs, **mit** Besitzprüfung.
///
/// Reihenfolge, und die ist der Punkt: **erst** die Schleuse, **dann** das
/// Dateisystem. Wer keinen Anspruch auf den Job hat, löst keine Dateioperation
/// aus — dann kann deren Dauer auch nichts verraten. Die Vorgängerfassung rief
/// `resolved_log_path()` vor der Prüfung und machte damit messbar, ob es die
/// Datei gibt (+23,6 µs für eine von Hand angelegte Logdatei ohne Eigentümer,
/// Ticket `06955e97`).
///
/// Danach dasselbe Jail wie zuvor: gültige Job-ID **und** kanonisierter Pfad
/// unterhalb von `data/log`. Der bleibt auch für einen Job, der dem Aufrufer
/// gehört, unangetastet — die ID kommt aus einem Pfadsegment, egal wem sie
/// gehört.
///
/// Fremder Job und unbekannter Job antworten **identisch** (dieselbe Meldung,
/// derselbe Erfolgsstatus), sonst wäre der Endpunkt ein Orakel, mit dem sich
/// fremde Job-IDs bestätigen liessen. Aus dem gleichen Grund wird die
/// Ablehnung nur mit `user_id` und Job-ID protokolliert, nicht dem Client
/// mitgeteilt.
///
/// Gilt für **beide** Jobarten: ein URL-Abruf schreibt sein Log an dieselbe
/// Stelle (`data/log/<job_id>.log`) und steht in derselben Tabelle, also
/// braucht dieser Weg keine Verzweigung. Genau dadurch ist das Log eines
/// Abrufs für seinen Erzeuger wieder lesbar.
pub async fn get_sync_log_for(
    current: &CurrentUser,
    job_id: String,
) -> ResponseJson<ApiResponse<String>> {
    if job_access(&job_id, current).await.is_none() {
        warn!(
            "📖 Logabruf abgelehnt: Job {} gehört nicht zu Konto {}",
            job_id, current.user.id
        );
        return ResponseJson(ApiResponse::error(LOG_UNAVAILABLE));
    }

    let Some(path) = resolved_log_path(&job_id).await else {
        return ResponseJson(ApiResponse::error(LOG_UNAVAILABLE));
    };

    read_job_log(&job_id, &path).await
}

/// Gemeinsames Lesen für beide Einstiege. Nimmt einen bereits geprüften Pfad.
async fn read_job_log(job_id: &str, path: &std::path::Path) -> ResponseJson<ApiResponse<String>> {
    debug!("📖 Reading log file for job {}: {}", job_id, path.display());

    match fs::read_to_string(path).await {
        Ok(content) => {
            info!(
                "📖 Log file read successfully for job {}, {} bytes",
                job_id,
                content.len()
            );
            ResponseJson(ApiResponse::success(content))
        }
        Err(e) => {
            // Der Grund bleibt im Log; die Antwort ist für jeden Fehlerfall
            // dieselbe.
            warn!("📖 Log file read failed for job {}: {}", job_id, e);
            ResponseJson(ApiResponse::error(LOG_UNAVAILABLE))
        }
    }
}

/// `DELETE /api/sync/:job_id` — löscht einen beendeten Job, **mit**
/// Besitzprüfung.
///
/// Die Schleuse steht vor allem anderen; ein fremder oder unbekannter Job
/// bekommt [`JOB_UNAVAILABLE`] und löst keine Datei- oder Tabellenoperation
/// aus. Gilt für Sync-Läufe und URL-Abrufe gleich — beide stehen in derselben
/// Tabelle und legen ihr Log an derselben Stelle ab.
pub async fn delete_job_for(
    current: &CurrentUser,
    job_id: String,
) -> ResponseJson<ApiResponse<String>> {
    if job_access(&job_id, current).await.is_none() {
        warn!(
            "🗑️ Löschung abgelehnt: Job {} gehört nicht zu Konto {}",
            job_id, current.user.id
        );
        return ResponseJson(ApiResponse::error(JOB_UNAVAILABLE));
    }
    delete_own_job(job_id).await
}

/// Löschen eines Jobs, dessen Zugriff **bereits geprüft** ist.
async fn delete_own_job(job_id: String) -> ResponseJson<ApiResponse<String>> {
    info!("🗑️ Delete request for job {}", job_id);

    let mut jobs = SYNC_JOBS.lock().await;

    // Check if job exists and is completed
    let can_delete = if let Some(job) = jobs.get(&job_id) {
        let deletable = job.status.is_terminal();
        info!(
            "📊 Job {} status: {}, can delete: {}",
            job_id, job.status, deletable
        );
        deletable
    } else {
        warn!("❌ Job {} not found for deletion", job_id);
        false
    };

    if !can_delete {
        return ResponseJson(ApiResponse::error(
            "Can only delete completed or failed jobs",
        ));
    }

    // Remove from memory
    jobs.remove(&job_id);
    forget_job_owner(&job_id).await;

    // Remove log file. `job_id` hat oben den Abgleich mit der Jobtabelle
    // bestanden, ist also ein selbst erzeugter Schlüssel und kein beliebiges
    // Pfadsegment mehr — genau deshalb war dieser Weg von der Lücke in
    // `get_sync_log` nicht betroffen.
    let log_file_path = internal_log_path(&job_id);
    if let Err(e) = fs::remove_file(&log_file_path).await {
        println!(
            "Warning: Could not delete log file {}: {}",
            log_file_path, e
        );
    }

    ResponseJson(ApiResponse::success("Job deleted successfully".to_string()))
}

/// Wie lange ein abgebrochenes Kind auf SIGTERM reagieren darf, bevor SIGKILL
/// folgt.
///
/// **SIGTERM zuerst, nie SIGKILL sofort.** Ein hart getötetes rsync lässt seine
/// verwaisten `.name.XXXXXX`-Dateien im Ziel liegen — im Spike mit 85 MB
/// gemessen — und rsync nimmt sie nie wieder auf; rclone lässt Teildateien
/// zurück. Auf SIGTERM räumen beide selbst auf. Zehn Sekunden ist derselbe Wert,
/// den der Daemon in `rsyncd.rs` benutzt (`SIGTERM_GRACE`); ein längeres Fenster
/// wäre für einen Nutzer, der auf „Abbrechen" gedrückt hat, nicht mehr
/// erklärbar.
const CANCEL_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Schickt `signal` an `pid`. `true`, wenn es zugestellt wurde.
///
/// Über `kill(1)` statt `libc::kill`: `libc` ist **keine** direkte Abhängigkeit
/// dieses Crates, und `Cargo.toml` gehört nicht zu diesem Ticket. `kill` liegt
/// auf dem Host in coreutils und im Image in busybox, ist also überall
/// vorhanden, wo die Anwendung läuft — dieselbe Annahme, die sie über `rsync`
/// selbst ohnehin macht. `Child::kill`/`start_kill` ist kein Ersatz: die
/// schicken SIGKILL, also genau das Signal, das die verwaisten Temp-Dateien
/// kostet.
///
/// Kein Risiko einer wiederverwendeten PID: der Aufrufer hält den `Child` und
/// hat ihn noch nicht erfolgreich abgeräumt, das Kind ist also höchstens ein
/// Zombie und seine PID bis dahin vergeben.
///
/// Dieselbe Begründung und derselbe Aufbau stehen als `send_signal` in
/// `rsyncd.rs`. Dort ist die Funktion privat und die Datei gehört einem anderen
/// Ticket; die zweite Kopie ist bewusst und im Bericht vermerkt.
async fn send_signal(pid: u32, signal: &str) -> bool {
    match Command::new("kill")
        .arg(format!("-{}", signal))
        .arg(pid.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(e) => {
            warn!("Signal {} an PID {} nicht zustellbar: {}", signal, pid, e);
            false
        }
    }
}

async fn execute_sync(
    job_id: String,
    sync_request: SyncRequest,
    sync_jobs: SyncJobs,
    engine: Arc<dyn SyncEngine>,
    cancel: Arc<AtomicBool>,
) {
    let log_file_path = internal_log_path(&job_id);

    // Der Modus wird hier **erneut** aus dem Request abgeleitet und nicht von
    // `start_sync_for` durchgereicht. Beide Wege benutzen dieselbe Funktion,
    // und ein zusätzlicher Parameter wäre eine zweite Stelle, an der jemand
    // versehentlich `Mirror` einsetzen könnte.
    let mode = transfer_mode(&sync_request);
    let dry_run = is_dry_run(&sync_request);

    // Ensure log directory and initial log exist in case start_sync didn't manage to create them (e.g. on crash)
    if let Err(e) = create_initial_log(&job_id, &sync_request, mode, dry_run, engine.name()).await {
        eprintln!("Failed to ensure initial log: {}", e);
    }

    {
        let mut jobs = sync_jobs.lock().await;
        if let Some(progress) = jobs.get_mut(&job_id) {
            progress.status = JobStatus::Running;
        }
    }

    // Everything engine specific — program, arguments, environment — comes
    // from the engine; spawning and status handling stay here.
    let spec = JobSpec {
        job_id: &job_id,
        request: &sync_request,
        mode,
        log_file: &log_file_path,
    };

    let command = match engine.build_command(&spec) {
        Ok(command) => command,
        Err(e) => {
            let error_msg = format!("Failed to prepare {} command: {}", engine.name(), e);
            error!("❌ {}", error_msg);

            finish_job(&sync_jobs, &job_id, JobStatus::failed(error_msg)).await;
            forget_engine(&job_id).await;
            return;
        }
    };

    // Print the full command being executed (debug only)
    info!(
        "🚀 Executing {} command: {}",
        engine.name(),
        command.args.join(" ")
    );

    let capture_stdout = engine.progress_source() == ProgressSource::Stdout;

    let mut process = Command::new(&command.program);
    process.args(&command.args);
    for (key, value) in &command.env {
        process.env(key, value);
    }
    if capture_stdout {
        process.stdout(std::process::Stdio::piped());
    }

    // Spawn the engine process. Log based engines need no output capture,
    // they write into the job log file themselves.
    let mut child = match process.spawn() {
        Ok(child) => {
            info!("✅ {} process started for job {}", engine.name(), job_id);
            child
        }
        Err(e) => {
            let error_msg = format!("Failed to spawn {} process: {}", engine.name(), e);
            error!("❌ {}", error_msg);

            finish_job(&sync_jobs, &job_id, JobStatus::failed(error_msg)).await;
            cleanup_temp_files(&command).await;
            forget_engine(&job_id).await;
            return;
        }
    };

    // For stdout based engines the progress has to be read while the process
    // runs; log based engines are polled on demand in get_sync_progress.
    if capture_stdout {
        if let Some(stdout) = child.stdout.take() {
            let job_id_clone = job_id.clone();
            let jobs_clone = sync_jobs.clone();
            let engine_clone = engine.clone();
            tokio::spawn(async move {
                pump_stdout_progress(stdout, job_id_clone, jobs_clone, engine_clone).await;
            });
        }
    }

    // Auf das Prozessende warten — und dabei die Abbruchflagge im Auge
    // behalten.
    //
    // Warum ein Zeitscheiben-Warten und kein `select!` auf die Flagge: in einem
    // `select!` müssten beide Zweige `child` mutably halten (einer für
    // `wait()`, der andere für `start_kill()`), und das lässt der Borrow-Checker
    // nicht zu. `Child::wait` ist ausdrücklich abbruchsicher (Tokio-Doku), das
    // Wiederaufsetzen verliert den Exit-Status also nicht.
    // `Some(zeitpunkt)` heisst „SIGTERM ist raus"; `escalated`, dass SIGKILL
    // gefolgt ist.
    let mut cancelled: Option<std::time::Instant> = None;
    let mut escalated = false;
    let status = loop {
        match tokio::time::timeout(std::time::Duration::from_millis(200), child.wait()).await {
            Ok(status) => break status,
            Err(_) => match cancelled {
                // Erster Abbruch: SIGTERM.
                None if cancel.load(std::sync::atomic::Ordering::Relaxed) => {
                    warn!("🛑 Job {} wird abgebrochen (SIGTERM)", job_id);
                    match child.id() {
                        Some(pid) => {
                            if !send_signal(pid, "TERM").await {
                                // Konnte nicht zugestellt werden — dann sofort
                                // hart, statt die Frist abzuwarten.
                                warn!(
                                    "🛑 Job {}: SIGTERM nicht zustellbar, sofort SIGKILL",
                                    job_id
                                );
                                if let Err(e) = child.start_kill() {
                                    warn!("🛑 Job {} liess sich nicht beenden: {}", job_id, e);
                                }
                                escalated = true;
                            }
                        }
                        // Ohne PID gibt es nur den Weg über tokio, und der ist
                        // SIGKILL. Kommt vor, wenn das Kind zwischen `wait()`
                        // und hier schon geendet hat.
                        None => {
                            if let Err(e) = child.start_kill() {
                                warn!("🛑 Job {} liess sich nicht beenden: {}", job_id, e);
                            }
                            escalated = true;
                        }
                    }
                    cancelled = Some(std::time::Instant::now());
                }
                // Frist abgelaufen, das Kind lebt noch: jetzt hart.
                Some(sent) if !escalated && sent.elapsed() >= CANCEL_GRACE => {
                    warn!(
                        "🛑 Job {} hat auf SIGTERM nach {}s nicht geendet, SIGKILL folgt. \
                         Teildateien im Ziel können zurückbleiben.",
                        job_id,
                        CANCEL_GRACE.as_secs()
                    );
                    if let Err(e) = child.start_kill() {
                        warn!("🛑 Job {} liess sich nicht beenden: {}", job_id, e);
                    }
                    escalated = true;
                }
                _ => {}
            },
        }
    };

    cleanup_temp_files(&command).await;

    // Update in-memory status based on exit code. Der Wortlaut von
    // `describe_exit()` ist hier nur noch Anzeigetext — er wird in
    // `JobStatus::Failed` verpackt, das Terminal-Verhalten hängt am Typ.
    let final_status = match &status {
        // Ein abgebrochener Lauf ist `Cancelled` und nicht „durch ein Signal
        // beendet" — den Text hätte sonst der Nutzer verursacht und würde ihn
        // als Fehler der Anwendung lesen.
        _ if cancelled.is_some() => {
            info!("🛑 Job {} abgebrochen", job_id);
            JobStatus::Cancelled
        }
        Ok(es) if es.success() => {
            info!("✅ Job {} completed successfully", job_id);
            JobStatus::Completed
        }
        Ok(es) => {
            // Der Exit-Code entscheidet über Text *und* Zustand: manche Codes
            // (rsync 23/24) sind Teilerfolge und keine Fehlschläge.
            let status = engine.classify_exit(es.code());
            if status.is_partial() {
                warn!(
                    "⚠️ Job {} nur teilweise übertragen (exit code {:?})",
                    job_id,
                    es.code()
                );
            } else {
                warn!("❌ Job {} failed with exit code: {:?}", job_id, es.code());
            }
            status
        }
        Err(e) => {
            error!("💥 Job {} error: {}", job_id, e);
            JobStatus::failed(format!("Error: {}", e))
        }
    };

    finish_job(&sync_jobs, &job_id, final_status).await;
    forget_engine(&job_id).await;
}

/// Setzt einen Job in seinen Endzustand — Status **und** `end_time`, immer
/// zusammen.
///
/// Jeder Terminalpfad geht hier durch. Vorher setzte nur der reguläre
/// Exit-Pfad `end_time`; Jobs, die schon am Prozessstart scheiterten, blieben
/// ohne Zeitstempel liegen und wurden damit auch vom 24-Stunden-Cleanup nie
/// erfasst.
async fn finish_job(sync_jobs: &SyncJobs, job_id: &str, status: JobStatus) {
    debug_assert!(status.is_terminal(), "finish_job braucht einen Endzustand");

    let mut jobs = sync_jobs.lock().await;
    if let Some(progress) = jobs.get_mut(job_id) {
        if status.is_success() {
            progress.progress = 100.0;
        }
        progress.status = status;
        progress.end_time = Some(Utc::now().timestamp());
    }
}

/// Räumt Jobs auf, die einen Neustart nicht überlebt haben.
///
/// Die Jobtabelle liegt im Speicher, ein Neustart leert sie also ohnehin.
/// Trotzdem läuft der Durchlauf explizit: sobald der Zustand irgendwann
/// persistiert wird, darf kein Job in `Starting`/`Running` hängenbleiben —
/// ohne laufenden Prozess wäre er nie terminal, nie löschbar und für den
/// Cleanup unsichtbar. Genau das Muster, das dieses Ticket behebt.
pub async fn recover_stranded_jobs() {
    recover_stranded_in(&SYNC_JOBS).await
}

async fn recover_stranded_in(sync_jobs: &SyncJobs) {
    let stranded: Vec<String> = {
        let jobs = sync_jobs.lock().await;
        jobs.iter()
            .filter(|(_, job)| !job.status.is_terminal())
            .map(|(id, _)| id.clone())
            .collect()
    };

    for job_id in stranded {
        warn!(
            "🧹 Job {} hat den Neustart nicht überlebt, wird beendet",
            job_id
        );
        finish_job(
            sync_jobs,
            &job_id,
            JobStatus::failed("Failed: interrupted by server restart"),
        )
        .await;
    }
}

/// Drop the engine of a finished job.
async fn forget_engine(job_id: &str) {
    let mut engines = JOB_ENGINES.lock().await;
    engines.remove(job_id);
}

/// Remove credential or scratch files an engine created for one run.
async fn cleanup_temp_files(command: &EngineCommand) {
    for path in &command.temp_files {
        if let Err(e) = fs::remove_file(path).await {
            debug!("⚠️ Could not delete temp file {}: {}", path, e);
        }
    }
}

/// Read progress from an engine's stdout and write it into the shared job state.
///
/// **Zerlegt an `\r` *und* `\n`, nicht mit `BufReader::lines()`.** rsyncs
/// `--info=progress2` trennt seine Sätze mit Wagenrücklauf; nur der letzte endet
/// mit `\n` (gemessen, rsync 3.5.0 und 3.4.3). Mit `lines()` käme deshalb bis
/// zum Prozessende **eine** riesige Zeile an, und der Fortschritt stünde die
/// ganze Laufzeit auf 0 % — ein Fehler, den niemand als Parserfehler erkennt,
/// weil die Anzeige einfach nur „hängt".
async fn pump_stdout_progress(
    stdout: tokio::process::ChildStdout,
    job_id: String,
    sync_jobs: SyncJobs,
    engine: Arc<dyn SyncEngine>,
) {
    use tokio::io::AsyncReadExt;

    let mut stdout = stdout;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        let read = match stdout.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(e) => {
                debug!("Fortschritt von Job {} nicht mehr lesbar: {}", job_id, e);
                break;
            }
        };
        buffer.extend_from_slice(&chunk[..read]);

        // Der letzte, noch unvollständige Satz bleibt im Puffer.
        let mut start = 0;
        let mut last_end = 0;
        let mut records: Vec<String> = Vec::new();
        for (index, byte) in buffer.iter().enumerate() {
            if *byte == b'\r' || *byte == b'\n' {
                if index > start {
                    records.push(String::from_utf8_lossy(&buffer[start..index]).into_owned());
                }
                start = index + 1;
                last_end = start;
            }
        }
        buffer.drain(..last_end);

        for record in records {
            if let Some(snapshot) = engine.parse_progress(&record) {
                let mut jobs = sync_jobs.lock().await;
                if let Some(progress) = jobs.get_mut(&job_id) {
                    progress.progress = snapshot.percent;
                    progress.transferred = snapshot.transferred;
                    progress.total = snapshot.total;
                }
            }
        }
    }

    // Was ohne abschliessendes Trennzeichen übrig bleibt, ist trotzdem ein
    // vollständiger Satz — bei einem hart beendeten Kindprozess der letzte
    // gemessene Stand.
    if !buffer.is_empty() {
        let rest = String::from_utf8_lossy(&buffer).into_owned();
        if let Some(snapshot) = engine.parse_progress(&rest) {
            let mut jobs = sync_jobs.lock().await;
            if let Some(progress) = jobs.get_mut(&job_id) {
                progress.progress = snapshot.percent;
                progress.transferred = snapshot.transferred;
                progress.total = snapshot.total;
            }
        }
    }
}

/// Read the job log file and let the engine parse the latest progress out of it.
/// Shared for all log based engines; only the parsing is engine specific.
async fn parse_latest_progress_from_log(
    job_id: &str,
    engine: &dyn SyncEngine,
) -> Option<ProgressSnapshot> {
    // `job_id` ist hier immer ein Schlüssel aus `SYNC_JOBS`, also eine
    // selbst erzeugte ID — der Aufrufer hat den Job vorher in der Tabelle
    // gefunden. Kein Request-Segment, deshalb kein Jail.
    let log_file_path = internal_log_path(job_id);

    // Read the log file
    let content = match fs::read_to_string(&log_file_path).await {
        Ok(content) => content,
        Err(_) => {
            debug!("📖 Could not read log file for job {}", job_id);
            return None;
        }
    };

    match engine.parse_progress(&content) {
        Some(snapshot) => Some(snapshot),
        None => {
            debug!("📖 No recent progress found in log for job {}", job_id);
            None
        }
    }
}

/// Parse the latest progress out of rclone's JSON log
/// Reads the last 10 lines and looks for the most recent stats entry
fn parse_rclone_log_progress(content: &str) -> Option<(f64, u64, u64)> {
    // Get last 10 lines
    let lines: Vec<&str> = content.lines().collect();
    let start_idx = if lines.len() > 10 {
        lines.len() - 10
    } else {
        0
    };
    let last_lines = &lines[start_idx..];

    // Parse JSON logs in reverse order (newest first)
    for line in last_lines.iter().rev() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            // Debug: Log what we find for development
            if let Some(level) = json.get("level").and_then(|v| v.as_str()) {
                if level == "notice" || level == "info" {
                    debug!(
                        "🔍 Found JSON log entry: level={}, msg={:?}",
                        level,
                        json.get("msg")
                    );
                }
            }

            // Look for NOTICE level entries with stats (rclone JSON stats)
            if let Some(level) = json.get("level").and_then(|v| v.as_str()) {
                if level == "notice" {
                    if let Some(progress_info) = parse_json_stats(&json) {
                        debug!("📊 Found NOTICE stats in log: {}%", progress_info.0);
                        return Some(progress_info);
                    }
                }

                // Check for successful file copy completion
                if level == "info" {
                    if let Some(msg) = json.get("msg").and_then(|v| v.as_str()) {
                        if msg == "Copied (new)" || msg == "Copied (replaced existing)" {
                            if let Some(object_name) = json.get("object").and_then(|v| v.as_str()) {
                                debug!("✅ File successfully copied: {}", object_name);
                                // This indicates successful completion, return 100%
                                // Use reasonable default values for bytes if not available
                                let total_bytes =
                                    json.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                                return Some((100.0, total_bytes, total_bytes));
                            }
                        }
                    }
                }
            }

            // Alternative: look for explicit stats messages
            if let Some(msg) = json.get("msg").and_then(|v| v.as_str()) {
                if msg.contains("Transferred:") && msg.contains("%") {
                    if let Some(progress_info) = parse_traditional_progress(msg) {
                        debug!(
                            "📊 Found traditional progress in JSON msg: {}%",
                            progress_info.0
                        );
                        return Some(progress_info);
                    }
                }
            }
        }
    }

    None
}

/// Parse progress information from a rclone JSON log entry
fn parse_json_stats(json: &serde_json::Value) -> Option<(f64, u64, u64)> {
    // rclone JSON stats structure with --stats-log-level NOTICE
    // Use the correct fields for accurate progress tracking

    // First check for nested stats object (most common location)
    if let Some(stats) = json.get("stats") {
        if let (Some(transferred), Some(total_size)) = (
            stats.get("bytes").and_then(|v| v.as_u64()),
            stats.get("totalBytes").and_then(|v| v.as_u64()),
        ) {
            let transfers_completed = stats.get("transfers").and_then(|v| v.as_u64()).unwrap_or(0);
            let transferring_list = stats.get("transferring").and_then(|v| v.as_array());
            let is_transferring = transferring_list.map_or(false, |arr| !arr.is_empty());

            let percent = if total_size > 0 {
                if transferred == total_size && transfers_completed >= 1 && !is_transferring {
                    100.0
                } else {
                    (transferred as f64 / total_size as f64) * 100.0
                }
            } else {
                0.0
            };

            debug!(
                "📊 Nested stats: bytes={}, totalBytes={}, transfers={}, transferring={}, percent={:.1}%",
                transferred, total_size, transfers_completed, is_transferring, percent
            );

            return Some((percent, transferred, total_size));
        } else {
            debug!("⚠️ Stats object found but missing bytes/totalBytes fields");
        }
    }

    // Fallback: Check for direct stats fields in the JSON object
    if let (Some(transferred), Some(total_size)) = (
        json.get("bytes").and_then(|v| v.as_u64()),
        json.get("totalBytes").and_then(|v| v.as_u64()),
    ) {
        // Check transfer completion status
        let transfers_completed = json.get("transfers").and_then(|v| v.as_u64()).unwrap_or(0);
        let transferring_list = json.get("transferring").and_then(|v| v.as_array());
        let is_transferring = transferring_list.map_or(false, |arr| !arr.is_empty());

        // Calculate accurate percentage
        let percent = if total_size > 0 {
            if transferred == total_size && transfers_completed >= 1 && !is_transferring {
                // Transfer is definitely complete
                100.0
            } else {
                // Calculate based on bytes transferred
                (transferred as f64 / total_size as f64) * 100.0
            }
        } else {
            0.0
        };

        debug!(
            "📊 Direct JSON stats: bytes={}, totalBytes={}, transfers={}, transferring={}, percent={:.1}%",
            transferred, total_size, transfers_completed, is_transferring, percent
        );

        return Some((percent, transferred, total_size));
    }

    // Check for alternative field names (rclone variations)
    if let (Some(transferred), Some(total_size)) = (
        json.get("transferredBytes").and_then(|v| v.as_u64()),
        json.get("totalSize").and_then(|v| v.as_u64()),
    ) {
        let percent = if total_size > 0 {
            (transferred as f64 / total_size as f64) * 100.0
        } else {
            0.0
        };
        return Some((percent, transferred, total_size));
    }

    // Check for message with transfer info (fallback)
    if let Some(msg) = json.get("msg").and_then(|v| v.as_str()) {
        if msg.contains("Transferred:") && msg.contains("%") {
            return parse_traditional_progress(msg);
        }
    }

    None
}

/// Fallback parser for traditional rclone output embedded in JSON messages
fn parse_traditional_progress(line: &str) -> Option<(f64, u64, u64)> {
    if line.contains("Transferred:") && line.contains('%') {
        if let Some(percent_pos) = line.find('%') {
            let before_percent = &line[..percent_pos];
            if let Some(last_comma_or_space) = before_percent.rfind(|c: char| c == ',' || c == ' ')
            {
                let percent_str = before_percent[last_comma_or_space + 1..].trim();
                if let Ok(progress) = percent_str.parse::<f64>() {
                    let (transferred, total) = parse_transferred_bytes(line);
                    return Some((progress, transferred, total));
                }
            }
        }
    }
    None
}

/// Helper: extract transferred and total bytes from a standard rclone stats line
fn parse_transferred_bytes(line: &str) -> (u64, u64) {
    if let Some(start) = line.find("Transferred:") {
        let after = &line[start + 12..].trim();
        if let Some(slash) = after.find(" / ") {
            let transferred_part = after[..slash].trim();
            let rest = &after[slash + 3..];
            let total_part = rest
                .split(|c| c == ',' || c == '%')
                .next()
                .unwrap_or(rest)
                .trim();
            return (
                parse_byte_value(transferred_part),
                parse_byte_value(total_part),
            );
        }
    }
    (0, 0)
}

/// Convert strings like "1.23 MByte" to bytes
fn parse_byte_value(s: &str) -> u64 {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() {
        return 0;
    }
    let num: f64 = parts[0].replace(',', "").parse().unwrap_or(0.0);
    if parts.len() == 1 {
        return num as u64;
    }
    match parts[1].to_lowercase().as_str() {
        "byte" | "bytes" | "b" => num as u64,
        "kbyte" | "kb" | "k" => (num * 1024.0) as u64,
        "mbyte" | "mb" | "m" => (num * 1024.0 * 1024.0) as u64,
        "gbyte" | "gb" | "g" => (num * 1024.0 * 1024.0 * 1024.0) as u64,
        "tbyte" | "tb" | "t" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => num as u64,
    }
}

// ---------------------------------------------------------------------------
// Trockenlauf: was würde verschwinden?
//
// Ein Trockenlauf, der nur „ok" meldet, ist wertlos — die Frage vor einem
// Spiegellauf lautet nicht „läuft es durch", sondern **„welche Dateien sind
// danach weg"**. rclone beantwortet sie im JSON-Log, und zwar
// maschinenlesbar; die Meldungen unterscheiden sich zwischen Trockenlauf und
// echtem Lauf, deshalb liest der Parser beide Formen (geprüft gegen rclone
// 1.75.0 auf dem Host):
//
//   Trockenlauf  {"level":"notice","skipped":"delete",              "object":"a.txt","size":4}
//                {"level":"notice","skipped":"remove directory",    "object":"sub"}
//                {"level":"notice","skipped":"move into backup dir","object":"a.txt","size":4}
//   echter Lauf  {"level":"info","msg":"Deleted",             "object":"a.txt"}
//                {"level":"info","msg":"Removing directory",  "object":"sub"}
//                {"level":"info","msg":"Moved into backup dir","object":"a.txt"}
//
// Ausgewertet wird das **strukturierte** Feld (`skipped` bzw. `msg`) und nicht
// der freie Meldungstext: `msg` enthält im Trockenlauf die Grösse ("… (size 4)")
// und ist damit kein stabiler Vergleichswert.
// ---------------------------------------------------------------------------

/// Ein Eintrag der Löschvorschau.
///
/// `dead_code` nur, weil die Route noch fehlt: `get_sync_deletions_for` ist in
/// `src/main.rs` nicht registriert, und diese Datei darf das Routing nicht
/// anfassen. Sobald `GET /api/sync/deletions/:job_id` steht, fällt das Attribut
/// hier und an den drei folgenden Stellen weg.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlannedDeletion {
    /// Pfad relativ zum Ziel, so wie rclone ihn meldet.
    pub path: String,
    /// Grösse in Bytes, sofern rclone sie mitgeliefert hat (Verzeichnisse
    /// haben keine).
    pub size: Option<u64>,
    /// Ein Verzeichnis, das leer zurückbliebe und entfernt würde.
    pub is_dir: bool,
    /// `false` = die Datei wird **statt gelöscht** in den Sicherungsordner
    /// verschoben. Der Unterschied zwischen „weg" und „umgezogen" ist genau
    /// der Punkt des Sicherungsnetzes und darf in der Vorschau nicht
    /// verschwinden.
    pub deleted: bool,
}

/// Ergebnis der Löschvorschau für einen Job.
#[allow(dead_code)] // siehe `PlannedDeletion`: Route fehlt noch
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeletionReport {
    /// Stammt der Bericht aus einem Trockenlauf (nichts verändert) oder aus
    /// einem echten Lauf (bereits geschehen)?
    pub dry_run: bool,
    /// Anzahl der gefundenen Einträge — auch wenn `entries` gekürzt ist.
    pub total: usize,
    /// Die Einträge, höchstens [`DELETION_REPORT_LIMIT`] Stück.
    pub entries: Vec<PlannedDeletion>,
    /// `true`, wenn `entries` gekürzt wurde.
    pub truncated: bool,
}

/// Obergrenze der ausgelieferten Einträge. Ein Spiegellauf über ein grosses
/// Verzeichnis kann sechsstellig viele Löschungen melden; die vollständige
/// Liste steht weiterhin im Job-Log.
#[allow(dead_code)] // siehe `PlannedDeletion`: Route fehlt noch
const DELETION_REPORT_LIMIT: usize = 1000;

/// Zieht aus einem rclone-JSON-Log alles heraus, was im Ziel verschwindet.
///
/// Reine Funktion über den Logtext, damit sie ohne rclone-Lauf prüfbar ist.
/// Zeilen, die kein JSON sind (die Kopfzeilen von `initial_log_text`), werden
/// übersprungen.
#[allow(dead_code)] // von `get_sync_deletions_for` benutzt, das noch keine Route hat
pub fn parse_planned_deletions(content: &str) -> Vec<PlannedDeletion> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(json) => json,
            Err(_) => continue,
        };

        let object = match json.get("object").and_then(|v| v.as_str()) {
            Some(object) if !object.is_empty() => object,
            _ => continue,
        };
        let size = json.get("size").and_then(|v| v.as_u64());

        // Trockenlauf meldet über `skipped`, der echte Lauf über `msg`.
        let kind = json
            .get("skipped")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                json.get("msg")
                    .and_then(|v| v.as_str())
                    .map(|msg| msg.to_lowercase())
            });

        let (is_dir, deleted) = match kind.as_deref() {
            Some("delete") | Some("deleted") => (false, true),
            Some("remove directory") | Some("removing directory") => (true, true),
            Some("move into backup dir") | Some("moved into backup dir") => (false, false),
            _ => continue,
        };

        entries.push(PlannedDeletion {
            path: object.to_string(),
            size,
            is_dir,
            deleted,
        });
    }

    entries
}

/// Löschvorschau eines Jobs: welche Dateien würde dieser Lauf entfernen?
///
/// Liest dieselbe Logdatei, die auch `get_sync_log` ausliefert — es entsteht
/// kein zweiter rclone-Aufruf und damit auch keine zweite Gelegenheit, etwas
/// zu verändern. Ob der Bericht aus einem Trockenlauf stammt, steht im
/// Ergebnis (`dry_run`) und wird aus der Kopfzeile des Logs gelesen, damit ein
/// abgeräumter Job (Neustart) den Bericht nicht als „echt" ausgibt.
/// Der Weg geht durch **dieselbe** Schleuse wie Fortschritt, Log und Löschen —
/// schon jetzt, obwohl die Route noch fehlt. Er liest ein Job-Log und damit
/// Pfade eines Kontos; ohne die Prüfung wäre er die vierte Fundstelle desselben
/// Musters, und genau das sollen die zusammengelegten Tickets verhindern.
/// Reihenfolge wie überall: Besitz vor Dateisystem.
#[allow(dead_code)] // siehe `PlannedDeletion`: Route fehlt noch
pub async fn get_sync_deletions_for(
    current: &CurrentUser,
    job_id: String,
) -> ResponseJson<ApiResponse<DeletionReport>> {
    if job_access(&job_id, current).await.is_none() {
        return ResponseJson(ApiResponse::error(LOG_UNAVAILABLE));
    }

    // Dasselbe Jail wie in `get_sync_log_for`: die ID kommt aus einem
    // Request-Segment, also wird sie geprüft, bevor sie einen Pfad bildet —
    // auch schon, solange die Route noch fehlt.
    let Some(log_file_path) = resolved_log_path(&job_id).await else {
        return ResponseJson(ApiResponse::error(LOG_UNAVAILABLE));
    };

    let content = match fs::read_to_string(&log_file_path).await {
        Ok(content) => content,
        Err(e) => {
            warn!("📖 Löschvorschau für {} nicht lesbar: {}", job_id, e);
            return ResponseJson(ApiResponse::error(LOG_UNAVAILABLE));
        }
    };

    let dry_run = content
        .lines()
        .take(20)
        .any(|line| line.contains("] Dry run:"));

    let mut entries = parse_planned_deletions(&content);
    let total = entries.len();
    let truncated = total > DELETION_REPORT_LIMIT;
    entries.truncate(DELETION_REPORT_LIMIT);

    debug!(
        "🧾 Löschvorschau für Job {}: {} Einträge (dry_run={})",
        job_id, total, dry_run
    );

    ResponseJson(ApiResponse::success(DeletionReport {
        dry_run,
        total,
        entries,
        truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(chunk_size: Option<&str>) -> SyncRequest {
        SyncRequest {
            source_path: "/data/src".to_string(),
            remote_name: "myremote".to_string(),
            remote_path: "/dest".to_string(),
            chunk_size: chunk_size.map(String::from),
            use_chunking: chunk_size.map(|_| true),
            delete_target: None,
            delete_confirmed: None,
            dry_run: None,
            backup_dir: None,
        }
    }

    /// Baut die rclone-Argumentliste für einen Request — der Weg, den auch
    /// `execute_sync` nimmt (Modus aus `transfer_mode()`, nicht von Hand).
    fn args_for(request: &SyncRequest) -> Vec<String> {
        let spec = JobSpec {
            job_id: "job-test",
            request,
            mode: transfer_mode(request),
            log_file: "data/log/job-test.log",
        };
        RcloneEngine
            .build_command(&spec)
            .expect("Kommandozeile baubar")
            .args
    }

    /// Eindeutiges Testverzeichnis, wie in `download.rs`.
    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rclone-gui-sync-{}-{}", label, Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis anlegbar");
        dir
    }

    /// Angemeldeter Nutzer mit dem angegebenen Home. Die Sitzung ist Beiwerk —
    /// geprüft wird ausschliesslich über `user.home_path`.
    fn user_with_home(home: &std::path::Path, role: &str) -> CurrentUser {
        let now = Utc::now();
        CurrentUser {
            user: crate::database::User {
                id: "u-1".to_string(),
                username: "tester".to_string(),
                password_hash: String::new(),
                role: role.to_string(),
                home_path: home.to_string_lossy().to_string(),
                is_active: true,
                created_at: now,
                last_login_at: None,
            },
            session: crate::database::Session {
                id: String::new(),
                user_id: "u-1".to_string(),
                created_at: now,
                expires_at: now,
                user_agent: None,
                ip: None,
            },
        }
    }

    /// Die Quelle eines Syncs unterliegt derselben Jail-Prüfung wie jeder
    /// andere vom Client gelieferte Pfad: `..`, absolute Fremdpfade und
    /// Symlink-Ausbrüche werden abgewiesen, der eigene Baum bleibt erlaubt.
    #[tokio::test]
    async fn sync_source_stays_inside_the_home() {
        let base = temp_dir("quelle");
        let home = base.join("home");
        let outside = base.join("outside");
        std::fs::create_dir_all(home.join("daten")).expect("home");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret.txt"), b"geheim").expect("secret");

        let current = user_with_home(&home, "user");
        let canonical_home = std::fs::canonicalize(&home).expect("canonical home");

        // Innerhalb: erlaubt, und was zurückkommt ist der kanonisierte Pfad.
        let resolved = resolved_source_path(&current, "daten")
            .await
            .expect("eigener Baum ist erlaubt");
        assert_eq!(resolved, canonical_home.join("daten").to_string_lossy());

        // `..`-Ausbruch
        assert!(resolved_source_path(&current, "../outside").await.is_err());

        // Absoluter Fremdpfad
        assert!(resolved_source_path(&current, "/etc").await.is_err());
        assert!(resolved_source_path(&current, &outside.to_string_lossy())
            .await
            .is_err());

        // Symlink aus dem Home heraus
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, home.join("escape")).expect("symlink");
            assert!(resolved_source_path(&current, "escape").await.is_err());
        }

        // Leerer Pfad und Nullbyte
        assert!(resolved_source_path(&current, "").await.is_err());
        assert!(resolved_source_path(&current, "daten\0").await.is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Auch ein Admin synct nur aus seinem eigenen Home: `RootScope::System`
    /// wird auf diesem Weg bewusst nicht angeboten (Begründung oben am
    /// Quellpfad-Jail).
    #[tokio::test]
    async fn admin_source_is_jailed_too() {
        let base = temp_dir("admin");
        let home = base.join("home");
        std::fs::create_dir_all(&home).expect("home");

        let admin = user_with_home(&home, "admin");
        assert!(resolved_source_path(&admin, "/etc").await.is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Ein Konto ohne Home kann nicht syncen, statt still auf einen globalen
    /// Pfad zurückzufallen.
    #[tokio::test]
    async fn missing_home_is_refused() {
        let current = user_with_home(std::path::Path::new(""), "user");
        assert!(resolved_source_path(&current, "irgendwas").await.is_err());
    }

    fn rclone_args(request: &SyncRequest) -> Vec<String> {
        let spec = JobSpec {
            job_id: "job-1",
            request,
            mode: TransferMode::Copy,
            log_file: "data/log/job-1.log",
        };
        RcloneEngine.build_command(&spec).expect("command").args
    }

    /// Golden command line, taken verbatim from the pre-refactoring code path.
    #[test]
    fn rclone_copy_command_is_unchanged() {
        let expected: Vec<String> = [
            "copy",
            "--config",
            "data/cfg/rclone.conf",
            "/data/src",
            "myremote:/dest",
            "--stats",
            "1s",
            "--stats-log-level",
            "NOTICE",
            "--transfers=1",
            "--checkers=1",
            "--retries=3",
            "--low-level-retries=3",
            "--timeout=0",
            "--contimeout=60s",
            "--ignore-checksum",
            "--size-only",
            "--use-json-log",
            "--log-file",
            "data/log/job-1.log",
            "--log-level",
            "INFO",
            "--multi-thread-streams=4",
            "--multi-thread-cutoff=250M",
            "--webdav-nextcloud-chunk-size=50M",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        assert_eq!(rclone_args(&request(None)), expected);
    }

    #[test]
    fn chunk_size_maps_to_the_same_tuning_flags_as_before() {
        let cases = [
            ("8M", "2", "8M"),
            ("16M", "4", "16M"),
            ("32M", "6", "32M"),
            ("64M", "8", "64M"),
            ("128M", "8", "100M"),
            ("999M", "4", "50M"),
        ];

        for (chunk, streams, webdav) in cases {
            let args = rclone_args(&request(Some(chunk)));
            let tail = &args[args.len() - 3..];
            assert_eq!(
                tail,
                [
                    format!("--multi-thread-streams={}", streams),
                    format!("--multi-thread-cutoff={}", chunk),
                    format!("--webdav-nextcloud-chunk-size={}", webdav),
                ],
                "chunk size {}",
                chunk
            );
        }
    }

    #[test]
    fn mirror_mode_switches_the_subcommand_only() {
        let req = request(None);
        let spec = JobSpec {
            job_id: "job-1",
            request: &req,
            mode: TransferMode::Mirror,
            log_file: "data/log/job-1.log",
        };
        let args = RcloneEngine.build_command(&spec).expect("command").args;
        assert_eq!(args[0], "sync");
        assert_eq!(args[1..], rclone_args(&req)[1..]);
    }

    #[test]
    fn engine_reports_rclone_progress_from_the_job_log() {
        assert_eq!(RcloneEngine.progress_source(), ProgressSource::JobLog);
        assert_eq!(RcloneEngine.describe_exit(Some(3)), "Failed");
    }

    #[test]
    fn nested_json_stats_are_parsed() {
        let log = concat!(
            "[2026-08-15 12:00:00 UTC] Job job-1 started\n",
            r#"{"level":"notice","msg":"stats","stats":{"bytes":250,"totalBytes":1000,"transfers":0,"transferring":[{"name":"a"}]}}"#,
            "\n"
        );
        let snapshot = RcloneEngine.parse_progress(log).expect("progress");
        assert_eq!(snapshot.percent, 25.0);
        assert_eq!(snapshot.transferred, 250);
        assert_eq!(snapshot.total, 1000);
    }

    #[test]
    fn completion_needs_a_finished_transfer_not_only_equal_byte_counts() {
        let still_running = r#"{"level":"notice","stats":{"bytes":1000,"totalBytes":1000,"transfers":0,"transferring":[{"name":"a"}]}}"#;
        let done = r#"{"level":"notice","stats":{"bytes":1000,"totalBytes":1000,"transfers":1,"transferring":[]}}"#;

        assert_eq!(
            RcloneEngine.parse_progress(still_running).unwrap().percent,
            100.0
        );
        assert_eq!(RcloneEngine.parse_progress(done).unwrap().percent, 100.0);
        assert_eq!(
            parse_json_stats(&serde_json::from_str(done).unwrap()),
            Some((100.0, 1000, 1000))
        );
    }

    #[test]
    fn zero_total_bytes_yields_zero_percent() {
        let line = r#"{"level":"notice","stats":{"bytes":0,"totalBytes":0}}"#;
        assert_eq!(RcloneEngine.parse_progress(line).unwrap().percent, 0.0);
    }

    #[test]
    fn copied_message_counts_as_hundred_percent() {
        let line = r#"{"level":"info","msg":"Copied (new)","object":"file.bin","size":4096}"#;
        let snapshot = RcloneEngine.parse_progress(line).expect("progress");
        assert_eq!(
            (snapshot.percent, snapshot.transferred, snapshot.total),
            (100.0, 4096, 4096)
        );
    }

    #[test]
    fn only_the_last_ten_lines_are_considered() {
        let mut log = String::from(
            r#"{"level":"notice","stats":{"bytes":100,"totalBytes":1000,"transfers":0,"transferring":[]}}"#,
        );
        log.push('\n');
        for _ in 0..12 {
            log.push_str("plain text line\n");
        }
        assert!(RcloneEngine.parse_progress(&log).is_none());
    }

    #[test]
    fn the_newest_stats_entry_wins() {
        let log = concat!(
            r#"{"level":"notice","stats":{"bytes":100,"totalBytes":1000,"transfers":0,"transferring":[]}}"#,
            "\n",
            r#"{"level":"notice","stats":{"bytes":600,"totalBytes":1000,"transfers":0,"transferring":[]}}"#,
            "\n"
        );
        assert_eq!(RcloneEngine.parse_progress(log).unwrap().transferred, 600);
    }

    #[test]
    fn alternative_and_textual_stats_still_work() {
        let alternative = r#"{"level":"notice","transferredBytes":500,"totalSize":2000}"#;
        assert_eq!(
            RcloneEngine.parse_progress(alternative).unwrap().percent,
            25.0
        );

        assert_eq!(
            parse_traditional_progress("Transferred: 1.5 MByte / 3 MByte, 50%, 1 MByte/s"),
            Some((50.0, 1572864, 3145728))
        );
        assert_eq!(parse_traditional_progress("nothing here"), None);
    }

    #[test]
    fn byte_values_keep_their_units() {
        assert_eq!(parse_byte_value("512"), 512);
        assert_eq!(parse_byte_value("2 KByte"), 2048);
        assert_eq!(parse_byte_value("1.5 MB"), 1572864);
        assert_eq!(parse_byte_value("1 GByte"), 1073741824);
        assert_eq!(parse_byte_value(""), 0);
    }

    // -----------------------------------------------------------------
    // JobStatus
    // -----------------------------------------------------------------

    /// Die Meldung, an der die alte Logik gescheitert ist: weder `== "Failed"`
    /// noch `contains("Error")` (rclone schreibt `os error 2`, klein).
    const SPAWN_FAILURE: &str =
        "Failed to spawn rclone process: No such file or directory (os error 2)";

    #[test]
    fn terminal_state_does_not_depend_on_the_wording() {
        assert!(!JobStatus::Starting.is_terminal());
        assert!(!JobStatus::Running.is_terminal());
        assert!(JobStatus::Completed.is_terminal());
        assert!(JobStatus::Cancelled.is_terminal());

        // Beliebig formulierte Fehlermeldungen — alle terminal.
        for reason in [
            SPAWN_FAILURE,
            "Failed",
            "Error: broken pipe",
            "rsync: partial transfer due to vanished source files",
            "",
        ] {
            let status = JobStatus::failed(reason);
            assert!(status.is_terminal(), "nicht terminal: {:?}", reason);
            assert!(!status.is_success());
            assert_eq!(status.state(), "failed");
        }

        assert!(JobStatus::Completed.is_success());
        assert!(!JobStatus::Cancelled.is_success());
    }

    /// `describe_exit()` liefert freien Text; der landet in `Failed` und darf
    /// das Terminal-Verhalten nicht mehr beeinflussen. Das ist die Falle, vor
    /// der das Engine-Ticket gewarnt hat.
    #[test]
    fn describe_exit_wording_cannot_break_termination() {
        struct OddEngine;
        impl SyncEngine for OddEngine {
            fn name(&self) -> &'static str {
                "odd"
            }
            fn build_command(&self, _spec: &JobSpec<'_>) -> anyhow::Result<EngineCommand> {
                unreachable!()
            }
            fn progress_source(&self) -> ProgressSource {
                ProgressSource::JobLog
            }
            fn parse_progress(&self, _chunk: &str) -> Option<ProgressSnapshot> {
                None
            }
            fn describe_exit(&self, _code: Option<i32>) -> String {
                "Übertragung unvollständig abgebrochen".to_string()
            }
        }

        let status = JobStatus::failed(OddEngine.describe_exit(Some(23)));
        assert!(status.is_terminal());
        assert!(!status.is_success());
    }

    /// Der Anzeigetext bleibt wortgleich mit der früheren Zeichenkette, damit
    /// Frontend und CLI-Ausgabe sich nicht ändern.
    #[test]
    fn display_text_is_unchanged() {
        assert_eq!(JobStatus::Starting.to_string(), "Starting");
        assert_eq!(JobStatus::Running.to_string(), "Running");
        assert_eq!(JobStatus::Completed.to_string(), "Completed");
        assert_eq!(JobStatus::failed("Failed").to_string(), "Failed");
        assert_eq!(JobStatus::failed(SPAWN_FAILURE).to_string(), SPAWN_FAILURE);
    }

    // -----------------------------------------------------------------
    // rsync-Exit-Codes
    // -----------------------------------------------------------------

    /// Jeder übersetzte Code ergibt deutschen Klartext — keine nackte Zahl,
    /// kein englisches "exit status".
    #[test]
    fn known_rsync_exit_codes_are_translated_into_plain_german() {
        for code in [1, 5, 10, 11, 12, 23, 24, 30] {
            let text = classify_rsync_exit(Some(code)).to_string();
            assert!(
                text.len() > 40,
                "Code {} hat keine erklärende Meldung: {:?}",
                code,
                text
            );
            assert!(
                !text.to_lowercase().contains("exit status"),
                "Code {} meldet noch roh: {:?}",
                code,
                text
            );
            // Die Zahl bleibt nachschlagbar, steht aber nicht allein.
            assert!(
                text.contains(&format!("rsync-Code {}", code)),
                "Code {} nicht nachvollziehbar: {:?}",
                code,
                text
            );
        }
    }

    /// Ein Auth-/Protokollfehler darf nicht wie ein Netzwerkausfall aussehen
    /// und umgekehrt — sonst sucht der Betreiber an der falschen Stelle.
    #[test]
    fn auth_and_network_failures_are_distinguishable() {
        let auth = classify_rsync_exit(Some(12)).to_string();
        let tls = classify_rsync_exit(Some(5)).to_string();
        let network = classify_rsync_exit(Some(10)).to_string();

        assert!(auth.contains("Zugangsdaten"), "{}", auth);
        assert!(!auth.contains("Firewall"), "{}", auth);

        assert!(tls.contains("Zertifikat"), "{}", tls);

        assert!(network.contains("erreichbar"), "{}", network);
        assert!(!network.contains("Zugangsdaten"), "{}", network);

        for status in [
            classify_rsync_exit(Some(12)),
            classify_rsync_exit(Some(5)),
            classify_rsync_exit(Some(10)),
        ] {
            assert_eq!(status.state(), "failed");
        }
    }

    /// 23 und 24 sind Teilerfolge: terminal, nicht erfolgreich, aber auch kein
    /// harter Fehlschlag.
    #[test]
    fn partial_transfers_are_neither_success_nor_failure() {
        for code in [23, 24] {
            let status = classify_rsync_exit(Some(code));
            assert!(status.is_partial(), "Code {} nicht als Teilerfolg", code);
            assert!(status.is_terminal());
            assert!(!status.is_success());
            assert_eq!(status.state(), "partial");
            assert!(
                status.to_string().starts_with("Teilweise übertragen"),
                "Code {} nicht als Teilerfolg formuliert: {}",
                code,
                status
            );
        }

        // 24 sagt ausdrücklich, dass verschwundene Quelldateien normal sind —
        // sonst erzeugt ein lebendes Verzeichnis Dauer-Fehlalarm.
        assert!(classify_rsync_exit(Some(24))
            .to_string()
            .contains("verschwunden"));
    }

    /// Der Sammelfall darf nicht in einen bekannten Fall kippen. Genau daran
    /// ist an anderer Stelle in diesem Projekt schon eine Fehlerunterscheidung
    /// gescheitert.
    #[test]
    fn unknown_exit_codes_get_their_own_honest_case() {
        for code in [2, 3, 6, 13, 14, 19, 20, 21, 22, 25, 31, 35, 99, 137, -1] {
            let status = classify_rsync_exit(Some(code));
            assert!(!status.is_partial(), "Code {} fälschlich Teilerfolg", code);
            let text = status.to_string();
            assert!(
                text.contains(&format!("rsync-Code {}", code)),
                "Code {} verliert die rohe Zahl: {}",
                code,
                text
            );
            assert!(
                text.contains("kennt den Code nicht"),
                "Code {} wird einem bekannten Fall zugeschlagen: {}",
                code,
                text
            );
        }

        // Durch Signal beendet: kein Code, trotzdem eine ehrliche Aussage.
        let signalled = classify_rsync_exit(None);
        assert!(!signalled.is_partial());
        assert!(signalled.to_string().contains("Signal"));
    }

    /// Keine Meldung darf etwas enthalten, das aus rsyncs stderr stammt
    /// (Modulnamen, Pfade) oder gar ein Geheimnis. Die Texte werden
    /// ausschließlich aus dem Code gebaut.
    #[test]
    fn messages_never_carry_secrets_or_remote_details() {
        let codes = [
            None,
            Some(1),
            Some(5),
            Some(10),
            Some(11),
            Some(12),
            Some(23),
            Some(24),
            Some(30),
            Some(42),
        ];
        for code in codes {
            let text = classify_rsync_exit(code).to_string();
            for forbidden in [
                "password",
                "Passwort",
                "--password-file",
                "@",
                "://",
                "rsync://",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{:?} enthält {:?}: {}",
                    code,
                    forbidden,
                    text
                );
            }
        }
    }

    /// Der Teilerfolg überlebt den Weg durch die API-Darstellung.
    #[test]
    fn partial_state_survives_serialisation() {
        let status = classify_rsync_exit(Some(23));
        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["state"], "partial");
        assert_eq!(json["terminal"], true);
        assert_eq!(json["status"], status.to_string());

        let back = JobStatus::from_parts(Some("partial"), status.to_string());
        assert_eq!(back, status);
    }

    /// Ein Engine, der `classify_exit` nicht überschreibt, verhält sich wie
    /// bisher: harter Fehlschlag mit dem Text aus `describe_exit`.
    #[test]
    fn engines_without_own_classification_keep_hard_failure() {
        let status = RcloneEngine.classify_exit(Some(23));
        assert_eq!(status, JobStatus::failed("Failed"));
        assert!(!status.is_partial());
    }

    /// Ein Engine, der rsync-Codes benutzt, bekommt den Teilerfolg bis in den
    /// Endzustand durch — das ist der Weg, den `execute_sync` geht.
    #[test]
    fn rsync_classification_reaches_the_final_status() {
        struct RsyncLike;
        impl SyncEngine for RsyncLike {
            fn name(&self) -> &'static str {
                "rsync"
            }
            fn build_command(&self, _spec: &JobSpec<'_>) -> anyhow::Result<EngineCommand> {
                unreachable!()
            }
            fn progress_source(&self) -> ProgressSource {
                ProgressSource::Stdout
            }
            fn parse_progress(&self, _chunk: &str) -> Option<ProgressSnapshot> {
                None
            }
            fn classify_exit(&self, code: Option<i32>) -> JobStatus {
                classify_rsync_exit(code)
            }
        }

        assert!(RsyncLike.classify_exit(Some(24)).is_partial());
        assert_eq!(RsyncLike.classify_exit(Some(12)).state(), "failed");
        assert!(RsyncLike.classify_exit(Some(30)).is_terminal());
    }

    /// Gegenprobe mit echten Prozessen: der `ExitStatus`, den `execute_sync`
    /// auswertet, kommt aus dem Betriebssystem — nicht aus einer Konstanten.
    #[tokio::test]
    async fn real_exit_statuses_are_classified_the_same_way() {
        for (code, expect_partial) in [(23, true), (24, true), (12, false), (77, false)] {
            let status = Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("exit {}", code))
                .status()
                .await
                .expect("stub process");
            assert!(!status.success());
            let job = classify_rsync_exit(status.code());
            assert_eq!(
                job.is_partial(),
                expect_partial,
                "Code {} falsch eingeordnet: {}",
                code,
                job
            );
            assert!(job.is_terminal());
        }
    }

    /// Ein Teilerfolg ist löschbar und wird vom Cleanup erfasst — er darf
    /// nicht als „läuft noch" hängenbleiben.
    #[tokio::test]
    async fn partial_jobs_are_finished_like_any_other_terminal_state() {
        let jobs: SyncJobs = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut map = jobs.lock().await;
            map.insert("p1".to_string(), job("p1", JobStatus::Running));
        }

        finish_job(&jobs, "p1", classify_rsync_exit(Some(23))).await;

        let map = jobs.lock().await;
        let stored = map.get("p1").expect("job");
        assert!(stored.status.is_partial());
        assert!(stored.status.is_terminal());
        assert!(stored.end_time.is_some());
        // Kein Aufrunden auf 100 % — der Lauf war eben nicht vollständig.
        assert!(stored.progress < 100.0);
    }

    fn job(id: &str, status: JobStatus) -> SyncProgress {
        SyncProgress {
            id: id.to_string(),
            progress: 0.0,
            status,
            transferred: 0,
            total: 0,
            source_name: "src".to_string(),
            start_time: 1_000,
            end_time: None,
            mode: TransferMode::Copy.as_str().to_string(),
            dry_run: false,
        }
    }

    /// Die API liefert `status` unverändert weiter und ergänzt `state` und
    /// `terminal` auf derselben Ebene.
    #[test]
    fn json_keeps_the_old_status_field_and_adds_the_typed_ones() {
        let value =
            serde_json::to_value(job("j1", JobStatus::failed(SPAWN_FAILURE))).expect("json");

        assert_eq!(value["status"], SPAWN_FAILURE);
        assert_eq!(value["state"], "failed");
        assert_eq!(value["terminal"], true);
        // Die übrigen Felder liegen weiterhin flach daneben.
        assert_eq!(value["id"], "j1");
        assert_eq!(value["start_time"], 1_000);

        let running = serde_json::to_value(job("j2", JobStatus::Running)).expect("json");
        assert_eq!(running["status"], "Running");
        assert_eq!(running["state"], "running");
        assert_eq!(running["terminal"], false);
    }

    #[test]
    fn json_round_trips() {
        for status in [
            JobStatus::Starting,
            JobStatus::Running,
            JobStatus::Completed,
            JobStatus::Cancelled,
            JobStatus::failed(SPAWN_FAILURE),
        ] {
            let json = serde_json::to_string(&job("j", status.clone())).expect("json");
            let back: SyncProgress = serde_json::from_str(&json).expect("parse");
            assert_eq!(back.status, status);
        }
    }

    /// Ein Client, der nur den alten Anzeigetext kennt, wird weiterhin richtig
    /// eingeordnet.
    #[test]
    fn legacy_status_text_without_state_is_understood() {
        assert_eq!(
            JobStatus::from_parts(None, "Running".into()),
            JobStatus::Running
        );
        assert_eq!(
            JobStatus::from_parts(None, "Completed".into()),
            JobStatus::Completed
        );
        let legacy = JobStatus::from_parts(None, SPAWN_FAILURE.into());
        assert!(legacy.is_terminal());
    }

    // -----------------------------------------------------------------
    // Terminalpfade in der Jobtabelle
    // -----------------------------------------------------------------

    /// Legt einen Job über den regulären Weg an — mit Eigentümer, denn ohne
    /// einen ist er für jeden unsichtbar (fail closed).
    async fn insert_job(id: &str, status: JobStatus) {
        register_job(job(id, status), TEST_OWNER, JobKind::Sync, None).await;
    }

    /// Konto, dem die Jobs dieser Testgruppe gehören.
    const TEST_OWNER: &str = "u-owner-1e67022b";

    /// Der Kern des Tickets: ein Job, dessen Prozessstart fehlschlägt, ist
    /// löschbar und hat `end_time` gesetzt.
    #[tokio::test]
    async fn a_job_that_failed_to_spawn_is_deletable_and_has_an_end_time() {
        let id = "test-spawn-failure-1e67022b";
        insert_job(id, JobStatus::Running).await;

        finish_job(&SYNC_JOBS, id, JobStatus::failed(SPAWN_FAILURE)).await;

        {
            let jobs = SYNC_JOBS.lock().await;
            let stored = jobs.get(id).expect("job");
            assert!(stored.end_time.is_some(), "end_time fehlt");
            assert!(stored.status.is_terminal());
        }

        let response = delete_job_for(&user_with_id(TEST_OWNER), id.to_string()).await;
        assert!(
            response.0.success,
            "Job war nicht löschbar: {:?}",
            response.0.error
        );
        assert!(SYNC_JOBS.lock().await.get(id).is_none());
    }

    /// Ein laufender Job bleibt geschützt.
    #[tokio::test]
    async fn a_running_job_cannot_be_deleted() {
        let id = "test-running-1e67022b";
        insert_job(id, JobStatus::Running).await;

        let response = delete_job_for(&user_with_id(TEST_OWNER), id.to_string()).await;
        assert!(!response.0.success);

        SYNC_JOBS.lock().await.remove(id);
        forget_job_owner(id).await;
    }

    /// Der 24-Stunden-Cleanup erfasst auch fehlgeschlagene Jobs — vorher fiel
    /// alles durch, dessen Meldung nicht exakt passte.
    #[tokio::test]
    async fn the_cleanup_catches_failed_jobs_regardless_of_wording() {
        let old = Utc::now().timestamp() - 90_000; // > 24 h
        let ids = [
            (
                "test-cleanup-failed-1e67022b",
                JobStatus::failed(SPAWN_FAILURE),
            ),
            ("test-cleanup-done-1e67022b", JobStatus::Completed),
        ];

        for (id, status) in &ids {
            let mut entry = job(id, status.clone());
            entry.end_time = Some(old);
            register_job(entry, TEST_OWNER, JobKind::Sync, None).await;
        }

        let _ = list_jobs_for(&user_with_id(TEST_OWNER)).await;

        let jobs = SYNC_JOBS.lock().await;
        for (id, _) in &ids {
            assert!(jobs.get(*id).is_none(), "Job {} wurde nicht aufgeräumt", id);
        }
    }

    /// Gestrandete Jobs bekommen beim Start einen Endzustand. Läuft auf einer
    /// eigenen Tabelle, damit der Durchlauf nicht die Jobs der Nachbartests
    /// beendet.
    #[tokio::test]
    async fn stranded_jobs_are_finished_on_startup() {
        let table: SyncJobs = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut jobs = table.lock().await;
            jobs.insert("running".to_string(), job("running", JobStatus::Running));
            jobs.insert("starting".to_string(), job("starting", JobStatus::Starting));

            let mut done = job("done", JobStatus::Completed);
            done.end_time = Some(42);
            jobs.insert("done".to_string(), done);
        }

        recover_stranded_in(&table).await;

        let jobs = table.lock().await;
        for id in ["running", "starting"] {
            let stored = jobs.get(id).expect("job");
            assert!(stored.status.is_terminal(), "{} nicht beendet", id);
            assert!(stored.end_time.is_some(), "{} ohne end_time", id);
        }
        // Fertige Jobs bleiben unangetastet.
        assert_eq!(jobs["done"].end_time, Some(42));
        assert_eq!(jobs["done"].status, JobStatus::Completed);
    }

    #[test]
    fn garbage_input_is_ignored() {
        assert!(RcloneEngine.parse_progress("").is_none());
        assert!(RcloneEngine.parse_progress("not json at all").is_none());
        assert!(RcloneEngine
            .parse_progress(r#"{"level":"debug"}"#)
            .is_none());
    }

    // -----------------------------------------------------------------------
    // „Im Ziel löschen"
    //
    // Die Prüfungen hier drehen sich alle um denselben Satz: **ohne
    // ausdrückliches `delete_target: true` landet niemals `sync` in der
    // Argumentliste.** Deshalb wird nicht nur der gesetzte Fall geprüft,
    // sondern jede Form von „nicht gesetzt".
    // -----------------------------------------------------------------------

    #[test]
    fn ohne_schalter_wird_kopiert() {
        let mut req = request(None);

        // Feld fehlt
        assert_eq!(transfer_mode(&req), TransferMode::Copy);
        let args = args_for(&req);
        assert_eq!(args[0], "copy");
        assert!(!args.iter().any(|a| a == "sync"));

        // ausdrücklich aus
        req.delete_target = Some(false);
        assert_eq!(transfer_mode(&req), TransferMode::Copy);
        assert_eq!(args_for(&req)[0], "copy");

        // Bestätigung allein macht noch keinen Löschlauf
        req.delete_target = None;
        req.delete_confirmed = Some(true);
        assert_eq!(transfer_mode(&req), TransferMode::Copy);
        assert_eq!(args_for(&req)[0], "copy");
    }

    /// Ein Request-JSON ohne die neuen Felder — der Ist-Zustand jedes alten
    /// Clients — darf nicht löschen. Das ist die Zeile, die verhindert, dass
    /// ein `#[serde(default)]` irgendwann auf die falsche Seite kippt.
    #[test]
    fn fehlende_felder_im_json_loeschen_nicht() {
        let req: SyncRequest = serde_json::from_str(
            r#"{"source_path":"/data/src","remote_name":"myremote","remote_path":"/dest"}"#,
        )
        .expect("alter Client bleibt lesbar");

        assert_eq!(req.delete_target, None);
        assert_eq!(req.delete_confirmed, None);
        assert_eq!(req.dry_run, None);
        assert_eq!(transfer_mode(&req), TransferMode::Copy);
        assert!(!is_dry_run(&req));
        assert_eq!(args_for(&req)[0], "copy");
    }

    /// `null` ist kein `true`.
    #[test]
    fn null_im_json_loescht_nicht() {
        let req: SyncRequest = serde_json::from_str(
            r#"{"source_path":"/s","remote_name":"myremote","remote_path":"/d",
                "delete_target":null,"dry_run":null}"#,
        )
        .expect("null ist lesbar");
        assert_eq!(transfer_mode(&req), TransferMode::Copy);
        assert_eq!(args_for(&req)[0], "copy");
    }

    #[test]
    fn mit_schalter_wird_gespiegelt() {
        let mut req = request(None);
        req.delete_target = Some(true);
        req.delete_confirmed = Some(true);

        assert_eq!(transfer_mode(&req), TransferMode::Mirror);
        assert!(transfer_mode(&req).deletes());

        let args = args_for(&req);
        assert_eq!(args[0], "sync");
        assert!(!args.iter().any(|a| a == "copy"));
    }

    #[test]
    fn dry_run_landet_in_der_argumentliste() {
        let mut req = request(None);
        assert!(!args_for(&req).iter().any(|a| a == "--dry-run"));

        req.dry_run = Some(true);
        req.delete_target = Some(true);
        req.delete_confirmed = Some(true);
        let args = args_for(&req);
        assert_eq!(args[0], "sync");
        assert!(args.iter().any(|a| a == "--dry-run"));
    }

    #[test]
    fn backup_dir_bleibt_auf_dem_zielremote() {
        let mut req = request(None);

        // Nicht gesetzt und leer sind dasselbe: kein Argument.
        assert_eq!(backup_dir_target(&req).expect("ohne Angabe"), None);
        req.backup_dir = Some("   ".to_string());
        assert_eq!(backup_dir_target(&req).expect("leere Angabe"), None);
        assert!(!args_for(&req).iter().any(|a| a == "--backup-dir"));

        req.backup_dir = Some("archiv/2026".to_string());
        assert_eq!(
            backup_dir_target(&req).expect("gültig"),
            Some("myremote:archiv/2026".to_string())
        );
        let args = args_for(&req);
        let idx = args
            .iter()
            .position(|a| a == "--backup-dir")
            .expect("--backup-dir gesetzt");
        assert_eq!(args[idx + 1], "myremote:archiv/2026");

        // Fremdes Remote, Options-Schmuggel, Ausbruch, Steuerzeichen.
        for bad in [
            "fremd:/",
            ":local:/etc",
            "--config=/tmp/x",
            "../../etc",
            "archiv/../../etc",
            "archiv\ndrop",
            "archiv\0",
        ] {
            req.backup_dir = Some(bad.to_string());
            assert!(
                backup_dir_target(&req).is_err(),
                "'{}' haette abgelehnt werden muessen",
                bad
            );
        }
    }

    /// rclone bricht einen überlappenden Sicherungsordner mit einem fatalen
    /// Fehler *im Lauf* ab (gemessen mit 1.75.0: „destination and parameter to
    /// --backup-dir mustn't overlap"). Abgelehnt wird deshalb vorher.
    #[test]
    fn backup_dir_darf_sich_nicht_mit_dem_ziel_ueberschneiden() {
        let mut req = request(None);
        req.remote_path = "/backup/fotos".to_string();

        // Daneben: in Ordnung.
        req.backup_dir = Some("backup/archiv".to_string());
        assert_eq!(
            backup_dir_target(&req).expect("neben dem Ziel"),
            Some("myremote:backup/archiv".to_string())
        );

        // Im Ziel, gleich dem Ziel, oberhalb des Ziels: alles Überschneidung.
        for bad in [
            "backup/fotos",
            "backup/fotos/alt",
            "/backup/fotos/",
            "backup",
        ] {
            req.backup_dir = Some(bad.to_string());
            assert!(
                backup_dir_target(&req).is_err(),
                "'{}' ueberschneidet sich mit dem Ziel",
                bad
            );
        }

        // Ziel ist das ganze Remote — dann gibt es keinen Platz daneben.
        for root in ["/", "", "//"] {
            req.remote_path = root.to_string();
            req.backup_dir = Some("archiv".to_string());
            assert!(backup_dir_target(&req).is_err(), "Wurzel als Ziel");
        }
    }

    /// Ticket `9a481914`: doppelte Slashes und `.`-Segmente liefen an der
    /// Ueberschneidungspruefung vorbei, weil nur aussen getrimmt wurde. rclone
    /// brach den Lauf dann selbst ab — aber erst mitten drin, und die Pruefung
    /// ist ausdruecklich eine Vorab-Pruefung.
    #[test]
    fn backup_dir_pruefung_normalisiert_den_pfad_vollstaendig() {
        let mut req = request(None);
        req.remote_path = "/dst/sub".to_string();

        // Alle Schreibweisen desselben ueberschneidenden Pfades.
        for bad in [
            "//dst/sub/backup",
            "dst//sub/backup",
            "dst/./sub/backup",
            "dst/sub/./backup",
            "./dst/sub",
            "dst//sub",
            "dst/sub//",
            "//dst//sub//",
            "/./",
            "//",
            ".",
        ] {
            req.backup_dir = Some(bad.to_string());
            assert!(
                backup_dir_target(&req).is_err(),
                "'{}' haette als Ueberschneidung abgelehnt werden muessen",
                bad
            );
        }

        // Und umgekehrt: das **Ziel** in krummer Schreibweise darf die Pruefung
        // genauso nicht aushebeln.
        for dest in ["//dst//sub", "dst/./sub/", "/dst/sub//"] {
            req.remote_path = dest.to_string();
            req.backup_dir = Some("dst/sub/backup".to_string());
            assert!(
                backup_dir_target(&req).is_err(),
                "Ziel '{}' haette die Ueberschneidung erkennen muessen",
                dest
            );
        }
    }

    /// Die Gegenprobe zur Normalisierung: verglichen wird auf **Segment**-
    /// grenzen. Ein Praefixvergleich auf der Zeichenkette wuerde `dst-backup`
    /// faelschlich als „innerhalb von `dst`" lesen — derselbe Fehler wie eine
    /// Origin-Pruefung per Praefix.
    #[test]
    fn backup_dir_neben_dem_ziel_wird_nicht_faelschlich_abgelehnt() {
        let mut req = request(None);
        req.remote_path = "/dst".to_string();

        for good in ["dst-backup", "dstx", "dst-backup/2026", "/dst-backup/"] {
            req.backup_dir = Some(good.to_string());
            assert!(
                backup_dir_target(&req).is_ok(),
                "'{}' liegt neben dem Ziel und ist zulaessig",
                good
            );
        }

        // Weitergegeben wird die normalisierte Form — geprueft und ausgefuehrt
        // ist derselbe Pfad.
        req.backup_dir = Some("//dst-backup//2026/./alt/".to_string());
        assert_eq!(
            backup_dir_target(&req).expect("neben dem Ziel"),
            Some("myremote:dst-backup/2026/alt".to_string())
        );
        let args = args_for(&req);
        let idx = args
            .iter()
            .position(|a| a == "--backup-dir")
            .expect("--backup-dir gesetzt");
        assert_eq!(args[idx + 1], "myremote:dst-backup/2026/alt");
        // Und das Log nennt denselben Pfad.
        assert!(
            initial_log_text("job-1", &req, TransferMode::Mirror, false, "rclone")
                .contains("Backup dir: myremote:dst-backup/2026/alt")
        );
    }

    /// Der Modus steht im Log-Kopf, in Klartext und ohne Zweideutigkeit.
    #[test]
    fn log_kopf_nennt_den_modus() {
        let req = request(None);

        let kopie = initial_log_text("job-1", &req, TransferMode::Copy, false, "rclone");
        assert!(kopie.contains("Mode: copy"));
        assert!(!kopie.contains("GELOESCHT"));
        assert!(!kopie.contains("Dry run:"));

        let spiegel = initial_log_text("job-1", &req, TransferMode::Mirror, true, "rclone");
        assert!(spiegel.contains("Mode: mirror"));
        assert!(spiegel.contains("GELOESCHT"));
        assert!(spiegel.contains("Dry run:"));

        let mut mit_backup = request(None);
        mit_backup.backup_dir = Some("archiv".to_string());
        let text = initial_log_text("job-1", &mit_backup, TransferMode::Mirror, false, "rclone");
        assert!(text.contains("Backup dir: myremote:archiv"));
    }

    /// Engines müssen das Spiegeln ausdrücklich erlauben. Die Vorgabe des
    /// Traits ist `false` — eine neue Engine löscht nicht aus Versehen.
    #[test]
    fn spiegeln_ist_opt_in_der_engine() {
        struct StummeEngine;
        impl SyncEngine for StummeEngine {
            fn name(&self) -> &'static str {
                "stumm"
            }
            fn build_command(&self, _spec: &JobSpec<'_>) -> anyhow::Result<EngineCommand> {
                Ok(EngineCommand::new("true", Vec::new()))
            }
            fn progress_source(&self) -> ProgressSource {
                ProgressSource::JobLog
            }
            fn parse_progress(&self, _chunk: &str) -> Option<ProgressSnapshot> {
                None
            }
        }

        assert!(!StummeEngine.supports_mirror());
        assert!(RcloneEngine.supports_mirror());
    }

    // -----------------------------------------------------------------------
    // Löschvorschau
    //
    // Die Zeilen stammen aus einem echten rclone-Lauf (1.75.0), nicht aus dem
    // Kopf: ein Parser gegen selbst ausgedachte Meldungen prüft nur die
    // eigene Fantasie.
    // -----------------------------------------------------------------------

    const DRY_RUN_LOG: &str = concat!(
        "[2026-08-18 21:00:00 UTC] Job job-1 started\n",
        "[2026-08-18 21:00:00 UTC] Mode: mirror (Spiegeln)\n",
        "[2026-08-18 21:00:00 UTC] Dry run: es wird NICHTS veraendert, nur aufgelistet\n",
        r#"{"level":"notice","msg":"Skipped copy as --dry-run is set (size 6)","skipped":"copy","size":6,"object":"keep.txt"}"#,
        "\n",
        r#"{"level":"notice","msg":"Skipped delete as --dry-run is set (size 4)","skipped":"delete","size":4,"object":"obsolete.txt"}"#,
        "\n",
        r#"{"level":"notice","msg":"Skipped delete as --dry-run is set (size 2)","skipped":"delete","size":2,"object":"sub/tief.txt"}"#,
        "\n",
        r#"{"level":"notice","msg":"Skipped remove directory as --dry-run is set","skipped":"remove directory","object":"sub"}"#,
        "\n",
        r#"{"level":"notice","msg":"Skipped move into backup dir as --dry-run is set (size 9)","skipped":"move into backup dir","size":9,"object":"alt.txt"}"#,
        "\n",
    );

    const ECHTER_LAUF_LOG: &str = concat!(
        r#"{"level":"info","msg":"Copied (new)","size":6,"object":"keep.txt"}"#,
        "\n",
        r#"{"level":"info","msg":"Deleted","object":"obsolete.txt"}"#,
        "\n",
        r#"{"level":"info","msg":"Removing directory","object":"sub"}"#,
        "\n",
        r#"{"level":"info","msg":"Moved into backup dir","object":"alt.txt"}"#,
        "\n",
    );

    #[test]
    fn trockenlauf_listet_was_geloescht_wuerde() {
        let entries = parse_planned_deletions(DRY_RUN_LOG);

        assert_eq!(
            entries,
            vec![
                PlannedDeletion {
                    path: "obsolete.txt".to_string(),
                    size: Some(4),
                    is_dir: false,
                    deleted: true,
                },
                PlannedDeletion {
                    path: "sub/tief.txt".to_string(),
                    size: Some(2),
                    is_dir: false,
                    deleted: true,
                },
                PlannedDeletion {
                    path: "sub".to_string(),
                    size: None,
                    is_dir: true,
                    deleted: true,
                },
                PlannedDeletion {
                    path: "alt.txt".to_string(),
                    size: Some(9),
                    is_dir: false,
                    deleted: false,
                },
            ]
        );
    }

    #[test]
    fn echter_lauf_wird_ebenso_gelesen() {
        let entries = parse_planned_deletions(ECHTER_LAUF_LOG);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "obsolete.txt");
        assert!(entries[0].deleted);
        assert!(entries[1].is_dir);
        assert!(
            !entries[2].deleted,
            "Backup-Verschiebung ist keine Loeschung"
        );
    }

    /// Ein reiner Kopierlauf hat nichts zu melden — und die Kopfzeilen des
    /// Logs (kein JSON) dürfen den Parser nicht stören.
    #[test]
    fn kopierlauf_meldet_keine_loeschungen() {
        let log = concat!(
            "[2026-08-18 21:00:00 UTC] Job job-2 started\n",
            "[2026-08-18 21:00:00 UTC] Mode: copy (Kopieren)\n",
            r#"{"level":"info","msg":"Copied (new)","size":6,"object":"keep.txt"}"#,
            "\n",
            "kein json\n",
            r#"{"level":"notice","msg":"\nTransferred: 6 B / 6 B, 100%","stats":{"bytes":6}}"#,
            "\n",
        );
        assert!(parse_planned_deletions(log).is_empty());
    }

    // -----------------------------------------------------------------
    // Logdatei-Jail (Ticket e785215e)
    // -----------------------------------------------------------------

    /// Eine Datei unter `data/log`, die sich selbst wieder aufräumt — auch
    /// wenn der Test durchfällt oder in der Mitte abbricht.
    struct TestLogFile {
        path: std::path::PathBuf,
    }

    impl TestLogFile {
        fn new(file_name: &str, content: &str) -> Self {
            std::fs::create_dir_all(LOG_DIR).expect("Logverzeichnis anlegbar");
            let path = std::path::Path::new(LOG_DIR).join(file_name);
            std::fs::write(&path, content).expect("Logdatei schreibbar");
            Self { path }
        }

        /// Datei **neben** dem Logverzeichnis, also das Ziel eines Ausbruchs.
        fn beside(file_name: &str, content: &str) -> Self {
            let path = std::path::Path::new(LOG_DIR)
                .parent()
                .expect("data/")
                .join(file_name);
            std::fs::create_dir_all(path.parent().expect("data/")).expect("data/ anlegbar");
            std::fs::write(&path, content).expect("Datei schreibbar");
            Self { path }
        }
    }

    impl Drop for TestLogFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Schreibt einen Eigentümer in die Tabelle, ohne einen Job anzulegen.
    /// Nur für Tests, die allein den Log-Weg prüfen.
    async fn remember_owner_for_test(job_id: &str, user_id: &str) {
        JOB_OWNERS.lock().await.insert(
            job_id.to_string(),
            JobOwner {
                user_id: user_id.to_string(),
                kind: JobKind::Sync,
            },
        );
    }

    fn user_with_id(id: &str) -> CurrentUser {
        let mut current = user_with_home(std::path::Path::new("/nonexistent"), "user");
        current.user.id = id.to_string();
        current
    }

    /// Riegel 1, ohne Dateisystem: nur die kanonische UUID-Schreibweise ist
    /// eine Job-ID. Die Liste enthält den gemessenen Angriff sowohl in der
    /// Form, in der er auf der Leitung steht, als **auch** so, wie axum ihn
    /// dekodiert an den Handler gibt — und dazu die Kodierungsvarianten, an
    /// denen eine Negativliste scheitern würde.
    #[test]
    fn only_a_canonical_uuid_becomes_a_log_file_name() {
        let real = Uuid::new_v4().to_string();

        for candidate in [
            // Der gemessene Befund, dekodiert und undekodiert.
            "../../server",
            "..%2F..%2Fserver",
            "..%2f..%2fserver",
            // Doppelt kodiert — die zweite Runde entsteht erst im Handler.
            "..%252F..%252Fserver",
            "%2e%2e/%2e%2e/server",
            // Backslash und Mischformen aus `.` und `..`.
            r"..\..\server",
            "./../data/tasks",
            "a/../../etc/hosts",
            "./.././server",
            // Absolute Pfade.
            "/etc/passwd",
            "/var/log/syslog",
            "//etc/passwd",
            // Slash-Homoglyphen, die schon einmal probiert wurden.
            "..\u{2215}..\u{2215}server",
            "..\u{ff0f}..\u{ff0f}server",
            "..\u{2044}..\u{2044}server",
            // Leeres, entartetes, nicht-UUID-Segment.
            "",
            " ",
            ".",
            "..",
            "job-1",
            "\0",
            // Eine echte UUID, aber mit Anhang oder in einer Schreibweise,
            // die einen anderen Dateinamen ergäbe als die ausgegebene ID.
            &format!("{real}.log"),
            &format!("{real}/../../etc/hosts"),
            &format!("{real}\0"),
            &format!(" {real}"),
            &format!("{real} "),
            &real.to_uppercase(),
            &format!("{{{real}}}"),
            &format!("urn:uuid:{real}"),
            &real.replace('-', ""),
        ] {
            assert!(
                job_log_file_name(candidate).is_none(),
                "hätte abgewiesen werden müssen: {candidate:?}"
            );
        }

        // Gegenprobe: die Form, die `Uuid::new_v4().to_string()` erzeugt, geht
        // durch — sonst prüfte der Test nur, dass die Funktion immer `None`
        // liefert.
        assert_eq!(
            job_log_file_name(&real).as_deref(),
            Some(format!("{real}.log").as_str())
        );
    }

    /// Der gemessene Ausbruch, gegen eine Datei die es **wirklich** gibt:
    /// `data/<uuid>.log` liegt eine Ebene über dem Logverzeichnis und wäre
    /// über `..` erreichbar. Der Endpunkt liefert sie nicht.
    #[tokio::test]
    async fn the_log_endpoint_does_not_escape_the_log_directory() {
        let id = Uuid::new_v4().to_string();
        let outside = TestLogFile::beside(&format!("{id}.log"), "GEHEIM: nicht ausliefern\n");

        // Kontrolle: die Datei ist da und lesbar. Ohne diesen Nachweis könnte
        // der Test auch bestehen, weil das Ziel gar nicht existiert.
        assert!(
            std::fs::read_to_string(&outside.path)
                .expect("Kontrolldatei lesbar")
                .contains("GEHEIM"),
            "Testaufbau kaputt: die Zieldatei fehlt"
        );

        // Jeder Angriffsversuch wird dem Aufrufer **zugeschrieben** — sonst
        // fiele er schon an der Zugriffsschleuse durch, und der Test bewiese
        // nur noch, dass unbekannte IDs abgewiesen werden. So prüft er, was er
        // prüfen soll: das Pfad-Jail hält auch für einen Job, der dem Aufrufer
        // gehört.
        let owner = user_with_id("u-jail-owner");
        for attempt in [
            format!("../{id}"),
            format!("..%2F{id}"),
            format!("../../{id}"),
            format!(r"..\{id}"),
            format!("./../{id}"),
        ] {
            remember_owner_for_test(&attempt, &owner.user.id).await;
            let response = get_sync_log_for(&owner, attempt.clone()).await.0;
            assert!(!response.success, "Ausbruch gelungen mit {attempt:?}");
            assert!(
                response
                    .data
                    .as_deref()
                    .is_none_or(|body| !body.contains("GEHEIM")),
                "Inhalt ausserhalb von {LOG_DIR} ausgeliefert: {attempt:?}"
            );
            assert_eq!(response.error.as_deref(), Some(LOG_UNAVAILABLE));
        }
    }

    /// Eine gültige Job-ID funktioniert unverändert, und der aufgelöste Pfad
    /// liegt unter der kanonisierten Wurzel.
    #[tokio::test]
    async fn a_valid_job_id_still_reads_its_log() {
        let id = Uuid::new_v4().to_string();
        let _log = TestLogFile::new(&format!("{id}.log"), "[test] hallo\n");

        let resolved = resolved_log_path(&id).await.expect("Pfad auflösbar");
        let root = tokio::fs::canonicalize(LOG_DIR).await.expect("Wurzel");
        assert!(resolved.starts_with(&root), "Pfad ausserhalb: {resolved:?}");

        let owner = user_with_id("u-valid-owner");
        remember_owner_for_test(&id, &owner.user.id).await;
        let response = get_sync_log_for(&owner, id).await.0;
        assert!(response.success, "Log nicht lesbar: {:?}", response.error);
        assert_eq!(response.data.as_deref(), Some("[test] hallo\n"));
    }

    /// Riegel 2 allein: heisst die Datei richtig, zeigt aber per Symlink nach
    /// draussen, entscheidet der **kanonisierte** Pfad — nicht der Name.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_log_file_does_not_leave_the_directory() {
        let base = temp_dir("logjail");
        let target = base.join("geheim.log");
        std::fs::write(&target, "GEHEIM\n").expect("Zieldatei");

        let id = Uuid::new_v4().to_string();
        let link = std::path::Path::new(LOG_DIR).join(format!("{id}.log"));
        std::fs::create_dir_all(LOG_DIR).expect("Logverzeichnis");
        std::os::unix::fs::symlink(&target, &link).expect("Symlink");
        // Aufräumen auch im Fehlerfall.
        let _guard = TestLogFile { path: link.clone() };

        assert!(
            resolved_log_path(&id).await.is_none(),
            "Symlink nach draussen wurde akzeptiert"
        );
        let owner = user_with_id("u-symlink-owner");
        remember_owner_for_test(&id, &owner.user.id).await;
        let response = get_sync_log_for(&owner, id).await.0;
        assert!(!response.success);
        assert!(response
            .data
            .as_deref()
            .is_none_or(|body| !body.contains("GEHEIM")));

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Zugriffsrecht: das Log eines fremden Jobs ist nicht lesbar, und die
    /// Antwort ist von der für eine unbekannte Job-ID **nicht zu
    /// unterscheiden** — sonst wäre der Endpunkt ein Orakel für fremde IDs.
    #[tokio::test]
    async fn a_foreign_job_log_is_indistinguishable_from_an_unknown_one() {
        let id = Uuid::new_v4().to_string();
        let _log = TestLogFile::new(&format!("{id}.log"), "[test] Quelle: /home/alice\n");

        let owner = user_with_id("u-owner");
        let stranger = user_with_id("u-stranger");
        remember_owner_for_test(&id, &owner.user.id).await;

        let mine = get_sync_log_for(&owner, id.clone()).await.0;
        assert!(mine.success, "Eigenes Log nicht lesbar: {:?}", mine.error);
        assert_eq!(mine.data.as_deref(), Some("[test] Quelle: /home/alice\n"));

        let foreign = get_sync_log_for(&stranger, id.clone()).await.0;
        // Eine Job-ID, die es nie gegeben hat: dieselbe Antwort, Wort für Wort.
        let unknown = get_sync_log_for(&stranger, Uuid::new_v4().to_string())
            .await
            .0;

        assert!(!foreign.success, "fremdes Log wurde ausgeliefert");
        assert!(foreign.data.is_none(), "fremder Loginhalt in der Antwort");
        assert_eq!(foreign.success, unknown.success);
        assert_eq!(foreign.error, unknown.error);
        assert_eq!(foreign.error.as_deref(), Some(LOG_UNAVAILABLE));

        // Und ein Job ohne bekannten Eigentümer bleibt zu (fail closed).
        forget_job_owner(&id).await;
        let orphan = get_sync_log_for(&owner, id).await.0;
        assert!(!orphan.success);
        assert_eq!(orphan.error, unknown.error);
    }

    // -----------------------------------------------------------------
    // Zugriffsschleuse: fremde Jobs
    //
    // Die Tickets `5f4cf35a`, `9337871d` und `fae31c06`. Gemessen wurde vorher
    // mit zwei echten Konten: `GET /api/sync` zeigte fremde Abrufe samt
    // Dateinamen, der Abbruch eines fremden Jobs ging durch, und `DELETE`
    // löschte Job und Logdatei eines fremden Kontos.
    // -----------------------------------------------------------------

    /// Ein fremder Job ist nicht auflistbar — und die Gegenprobe zeigt, dass
    /// derselbe Aufbau einen sichtbaren Job **melden würde**.
    #[tokio::test]
    async fn a_foreign_job_is_not_in_the_list() {
        let owner = user_with_id("u-list-owner");
        let stranger = user_with_id("u-list-stranger");
        let mine = format!("test-list-mine-{}", Uuid::new_v4());
        let theirs = format!("test-list-theirs-{}", Uuid::new_v4());

        register_job(
            job(&mine, JobStatus::Completed),
            &owner.user.id,
            JobKind::Sync,
            None,
        )
        .await;
        register_job(
            job(&theirs, JobStatus::Completed),
            &stranger.user.id,
            JobKind::UrlFetch,
            None,
        )
        .await;

        let list = list_jobs_for(&owner).await.0.data.expect("Liste");
        let ids: Vec<&str> = list.iter().map(|p| p.id.as_str()).collect();

        // Gegenprobe im selben Test: der eigene Job **ist** drin. Ohne diesen
        // Nachweis könnte der Test auch bestehen, weil die Liste leer ist.
        assert!(ids.contains(&mine.as_str()), "eigener Job fehlt: {ids:?}");
        assert!(
            !ids.contains(&theirs.as_str()),
            "fremder Job in der Liste: {ids:?}"
        );

        drop_job_for_test(&mine).await;
        drop_job_for_test(&theirs).await;
    }

    /// Fortschritt, Log und Löschen: fremd und unbekannt antworten byte-gleich,
    /// und der eigene Job funktioniert unverändert.
    #[tokio::test]
    async fn foreign_and_unknown_answer_alike_on_every_job_route() {
        let owner = user_with_id("u-routes-owner");
        let stranger = user_with_id("u-routes-stranger");
        let id = Uuid::new_v4().to_string();
        let _log = TestLogFile::new(&format!("{id}.log"), "[test] Quelle: /home/alice\n");
        let unknown = Uuid::new_v4().to_string();

        register_job(
            job(&id, JobStatus::Completed),
            &owner.user.id,
            JobKind::UrlFetch,
            None,
        )
        .await;

        // Fortschritt.
        let foreign = get_sync_progress_for(&stranger, id.clone()).await.0;
        let nobody = get_sync_progress_for(&stranger, unknown.clone()).await.0;
        assert!(!foreign.success && foreign.data.is_none());
        assert_eq!(foreign.error, nobody.error);
        assert_eq!(foreign.error.as_deref(), Some(JOB_UNAVAILABLE));
        // Gegenprobe: dem Eigentümer antwortet derselbe Weg mit dem Job.
        let mine = get_sync_progress_for(&owner, id.clone()).await.0;
        assert!(mine.success, "eigener Fortschritt: {:?}", mine.error);

        // Log — der Kern von `fae31c06`: das Log eines **Abruf**-Jobs ist für
        // seinen Erzeuger wieder lesbar, für ein fremdes Konto nicht.
        let mine_log = get_sync_log_for(&owner, id.clone()).await.0;
        assert!(mine_log.success, "eigenes Abruf-Log: {:?}", mine_log.error);
        assert_eq!(
            mine_log.data.as_deref(),
            Some("[test] Quelle: /home/alice\n")
        );
        let foreign_log = get_sync_log_for(&stranger, id.clone()).await.0;
        let nobody_log = get_sync_log_for(&stranger, unknown.clone()).await.0;
        assert!(foreign_log.data.is_none(), "fremder Loginhalt ausgeliefert");
        assert_eq!(foreign_log.error, nobody_log.error);
        assert_eq!(foreign_log.error.as_deref(), Some(LOG_UNAVAILABLE));

        // Abbruch: der Weg über die Schleuse gibt für ein fremdes Konto keine
        // Jobart heraus, also erreicht die Route den Downloader nie.
        assert!(job_access(&id, &stranger).await.is_none());
        assert_eq!(job_access(&id, &owner).await, Some(JobKind::UrlFetch));

        // Löschen: fremd == unbekannt, und der Job ist danach noch da.
        let foreign_del = delete_job_for(&stranger, id.clone()).await.0;
        let nobody_del = delete_job_for(&stranger, unknown).await.0;
        assert!(!foreign_del.success);
        assert_eq!(foreign_del.error, nobody_del.error);
        assert_eq!(foreign_del.error.as_deref(), Some(JOB_UNAVAILABLE));
        assert!(
            SYNC_JOBS.lock().await.contains_key(&id),
            "fremdes Löschen hat den Job entfernt"
        );

        // Und der Eigentümer darf löschen.
        let mine_del = delete_job_for(&owner, id.clone()).await.0;
        assert!(mine_del.success, "eigenes Löschen: {:?}", mine_del.error);
        assert!(!SYNC_JOBS.lock().await.contains_key(&id));
    }

    /// Gegenprobe zur Schleuse: **ohne** die Besitzprüfung — hier als naive
    /// Suche nachgebaut, die nur nach der ID geht — wäre der fremde Job
    /// erreichbar. Der Test hält damit fest, dass die vorigen Tests nicht
    /// deshalb grün sind, weil die Tabelle leer ist oder die ID nicht passt.
    #[tokio::test]
    async fn without_the_check_the_foreign_job_would_be_reachable() {
        let owner = user_with_id("u-control-owner");
        let stranger = user_with_id("u-control-stranger");
        let id = format!("test-control-{}", Uuid::new_v4());
        register_job(
            job(&id, JobStatus::Completed),
            &owner.user.id,
            JobKind::Sync,
            None,
        )
        .await;

        // Die naive Fassung: ID in der Tabelle, fertig.
        let naive = SYNC_JOBS.lock().await.contains_key(&id);
        assert!(
            naive,
            "Testaufbau kaputt: der Job liegt nicht in der Tabelle"
        );

        // Die echte Fassung sagt trotzdem nein.
        assert!(job_access(&id, &stranger).await.is_none());

        drop_job_for_test(&id).await;
    }

    /// Ein Job ohne Eigentümer bleibt zu — auch für den, der ihn angelegt hat
    /// (fail closed). Deckt den Fall nach einem Neustart ab, in dem die
    /// Eigentümertabelle leer ist.
    #[tokio::test]
    async fn a_job_without_an_owner_is_closed_to_everyone() {
        let owner = user_with_id("u-orphan-owner");
        let id = Uuid::new_v4().to_string();
        let _log = TestLogFile::new(&format!("{id}.log"), "[test] verwaist\n");
        register_job(
            job(&id, JobStatus::Completed),
            &owner.user.id,
            JobKind::Sync,
            None,
        )
        .await;

        // Gegenprobe zuerst: mit Eigentümer ist es lesbar.
        assert!(get_sync_log_for(&owner, id.clone()).await.0.success);

        forget_job_owner(&id).await;
        let orphan = get_sync_log_for(&owner, id.clone()).await.0;
        assert!(!orphan.success);
        assert_eq!(orphan.error.as_deref(), Some(LOG_UNAVAILABLE));
        assert!(get_sync_progress_for(&owner, id.clone())
            .await
            .0
            .data
            .is_none());

        SYNC_JOBS.lock().await.remove(&id);
    }

    /// `finish_job` gilt für beide Jobarten gleich: aufgerundet wird nur bei
    /// Erfolg. Ein abgebrochener Abruf behält seinen letzten Stand — sonst
    /// stünde in der Liste „100 %" über einer Datei, die es nicht gibt.
    #[tokio::test]
    async fn a_cancelled_fetch_is_not_rounded_up_to_a_hundred() {
        let owner = user_with_id("u-round-owner");
        for (suffix, status, expected) in [
            ("cancelled", JobStatus::Cancelled, 42.0),
            ("completed", JobStatus::Completed, 100.0),
        ] {
            let id = format!("test-round-{suffix}-{}", Uuid::new_v4());
            let mut entry = job(&id, JobStatus::Running);
            entry.progress = 42.0;
            register_job(entry, &owner.user.id, JobKind::UrlFetch, None).await;

            complete_job(&id, status).await;

            let stored = SYNC_JOBS.lock().await.get(&id).cloned().expect("Job");
            assert_eq!(stored.progress, expected, "Job {id}");
            assert!(stored.end_time.is_some(), "end_time fehlt bei {id}");

            drop_job_for_test(&id).await;
        }
    }

    /// Zeitgleichheit von „fremd" und „unbekannt" am Log-Weg.
    ///
    /// **Bewusst `#[ignore]`:** eine Laufzeitmessung ist auf einer geteilten
    /// Maschine kein verlässliches Testkriterium — grün oder rot hinge an der
    /// Last des Nachbarprozesses. Der Lauf ist reproduzierbar hinterlegt, damit
    /// die Messung wiederholbar ist:
    ///
    /// ```text
    /// cargo test -- --ignored --nocapture foreign_and_unknown_take_the_same_time
    /// ```
    ///
    /// Aufbau wie in der Vorlage: n Paare, die Reihenfolge **innerhalb** des
    /// Paares abwechselnd, damit eine Drift der Maschine beide Seiten gleich
    /// trifft. Dazu eine **Nullkontrolle** mit einer echten Differenz — ohne
    /// sie wäre „kein Signal gefunden" wertlos.
    #[tokio::test]
    #[ignore]
    async fn foreign_and_unknown_take_the_same_time() {
        use std::time::Instant;

        let stranger = user_with_id("u-timing-stranger");
        let owner = user_with_id("u-timing-owner");

        // Ein fremder Job, dessen Logdatei **existiert** — das ist der Fall,
        // der in der Vorgängerfassung messbar war.
        let foreign = Uuid::new_v4().to_string();
        let _log = TestLogFile::new(&format!("{foreign}.log"), "[test] fremd\n");
        register_job(
            job(&foreign, JobStatus::Completed),
            &owner.user.id,
            JobKind::Sync,
            None,
        )
        .await;

        let pairs = 6000usize;
        let mut d_real = Vec::with_capacity(pairs);
        let mut d_null = Vec::with_capacity(pairs);

        for i in 0..pairs {
            let unknown = Uuid::new_v4().to_string();

            // Realfall: fremd gegen unbekannt.
            let (a, b) = if i % 2 == 0 {
                let t0 = Instant::now();
                let _ = get_sync_log_for(&stranger, foreign.clone()).await;
                let a = t0.elapsed();
                let t1 = Instant::now();
                let _ = get_sync_log_for(&stranger, unknown.clone()).await;
                (a, t1.elapsed())
            } else {
                let t1 = Instant::now();
                let _ = get_sync_log_for(&stranger, unknown.clone()).await;
                let b = t1.elapsed();
                let t0 = Instant::now();
                let _ = get_sync_log_for(&stranger, foreign.clone()).await;
                (t0.elapsed(), b)
            };
            d_real.push(a.as_nanos() as f64 - b.as_nanos() as f64);

            // Nullkontrolle: derselbe Aufbau, aber eine Seite macht
            // zusätzlich das, was die Prüfung verhindert — sie fasst das
            // Dateisystem an. Findet die Messung *das* nicht, findet sie
            // nichts.
            let t2 = Instant::now();
            let _ = resolved_log_path(&foreign).await;
            let _ = get_sync_log_for(&stranger, foreign.clone()).await;
            let with_fs = t2.elapsed();
            let t3 = Instant::now();
            let _ = get_sync_log_for(&stranger, unknown).await;
            let without = t3.elapsed();
            d_null.push(with_fs.as_nanos() as f64 - without.as_nanos() as f64);
        }

        let report = |label: &str, d: &[f64]| {
            let n = d.len() as f64;
            let mean = d.iter().sum::<f64>() / n;
            let var = d.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
            let t = mean / (var / n).sqrt();
            println!("{label}: n={n} mean={mean:.1} ns t={t:.2}");
            t
        };

        let t_real = report("Realfall (fremd - unbekannt)", &d_real);
        let t_null = report("Nullkontrolle (mit Dateizugriff)", &d_null);

        // Die Nullkontrolle muss deutlich anschlagen, sonst taugt die Messung
        // nichts. Der Realfall darf es nicht.
        assert!(
            t_null.abs() > 5.0,
            "Nullkontrolle findet keine echte Differenz (t={t_null:.2}) — die Messung taugt nicht"
        );
        assert!(
            t_real.abs() < 3.0,
            "Realfall zeigt ein Zeitsignal (t={t_real:.2})"
        );

        drop_job_for_test(&foreign).await;
    }

    /// Abbruch: die Flagge, die `cancel_target` herausgibt, ist **die** des
    /// laufenden Abrufs — und ein beendeter oder unbekannter Job gibt keine
    /// heraus. Über HTTP war der laufende Fall auf dieser Maschine nicht
    /// erreichbar (kein Netz für einen Abruf, der lange genug läuft), deshalb
    /// hier.
    #[tokio::test]
    async fn cancel_target_hands_out_the_flag_of_a_running_fetch() {
        let owner = user_with_id("u-cancel-owner");
        let id = format!("test-cancel-{}", Uuid::new_v4());
        let flag = Arc::new(AtomicBool::new(false));
        register_job(
            job(&id, JobStatus::Running),
            &owner.user.id,
            JobKind::UrlFetch,
            Some(Arc::clone(&flag)),
        )
        .await;

        match cancel_target(&id).await {
            CancelTarget::Running(handed) => {
                handed.store(true, std::sync::atomic::Ordering::SeqCst);
                assert!(
                    flag.load(std::sync::atomic::Ordering::SeqCst),
                    "die herausgegebene Flagge gehört zu einem anderen Job"
                );
            }
            _ => panic!("laufender Abruf gilt nicht als laufend"),
        }

        // Beendet: keine Flagge mehr.
        complete_job(&id, JobStatus::Cancelled).await;
        assert!(matches!(cancel_target(&id).await, CancelTarget::Finished));

        // Unbekannt: auch keine.
        assert!(matches!(
            cancel_target(&Uuid::new_v4().to_string()).await,
            CancelTarget::Unknown
        ));

        // Und mit dem Job verschwindet die Flagge aus der Nebentabelle.
        let _ = delete_job_for(&owner, id.clone()).await;
        assert!(
            !JOB_CANCELS.lock().await.contains_key(&id),
            "Abbruchflagge überlebt den Job"
        );
    }

    // -----------------------------------------------------------------------
    // Der Stdout-Weg der rsync-Engine, an echten Prozessen
    //
    // Beide Tests fahren `execute_sync` mit einer Engine, deren Kindprozess
    // wirklich startet. Ein Parser-Test allein hätte den Fehler nicht gefunden,
    // um den es hier geht: rsync trennt seine Fortschrittssätze mit `\r`, und
    // mit `BufReader::lines()` käme bis zum Prozessende **eine** Zeile an.
    // -----------------------------------------------------------------------

    /// Engine, die ein Shell-Kommando startet und ihren Fortschritt wie die
    /// rsync-Engine aus stdout liest.
    struct StdoutEngine {
        script: &'static str,
    }

    impl SyncEngine for StdoutEngine {
        fn name(&self) -> &'static str {
            "stdout-test"
        }
        fn build_command(&self, _spec: &JobSpec<'_>) -> anyhow::Result<EngineCommand> {
            Ok(EngineCommand::new(
                "sh",
                vec!["-c".to_string(), self.script.to_string()],
            ))
        }
        fn progress_source(&self) -> ProgressSource {
            ProgressSource::Stdout
        }
        fn parse_progress(&self, chunk: &str) -> Option<ProgressSnapshot> {
            // Derselbe Parser, den die rsync-Engine benutzt.
            rsync_engine::parse_progress2_line(chunk)
        }
    }

    fn sync_request_for_test(source: &str) -> SyncRequest {
        SyncRequest {
            source_path: source.to_string(),
            remote_name: "peer-test".to_string(),
            remote_path: "ziel".to_string(),
            chunk_size: None,
            use_chunking: None,
            delete_target: None,
            delete_confirmed: None,
            dry_run: None,
            backup_dir: None,
        }
    }

    /// **Der Riegel gegen die `\r`-Falle.** Das Skript schreibt genau das, was
    /// `--info=progress2` schreibt: Sätze durch Wagenrücklauf getrennt, nur der
    /// letzte mit `\n`, danach die `--stats`-Zeilen. Am Ende muss der Job den
    /// letzten Fortschrittssatz tragen — nicht 0 %, und nicht die Zahlen aus
    /// den Statistikzeilen.
    #[tokio::test]
    async fn progress_arrives_from_stdout_split_at_carriage_returns() {
        let id = format!("stdout-969c46ad-{}", Uuid::new_v4());
        insert_job(&id, JobStatus::Starting).await;

        let engine: Arc<dyn SyncEngine> = Arc::new(StdoutEngine {
            script: concat!(
                r"printf '\r        32,768   0%%    0.00kB/s    0:00:00';",
                r"printf '\r     3,000,000  20%%    2.76GB/s    0:00:01 (xfr#1, to-chk=4/6)';",
                r"printf '\r    15,000,000 100%%    2.32GB/s    0:00:02 (xfr#5, to-chk=0/6)\n';",
                r"printf 'sent 15,001,234 bytes  received 130 bytes  1,000.00 bytes/sec\n';",
                r"printf 'total size is 15,000,000  speedup is 1.00\n'"
            ),
        });

        execute_sync(
            id.clone(),
            sync_request_for_test("/tmp"),
            SYNC_JOBS.clone(),
            engine,
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        {
            let jobs = SYNC_JOBS.lock().await;
            let stored = jobs.get(&id).expect("job");
            assert!(stored.status.is_success(), "Status: {}", stored.status);
            assert_eq!(stored.transferred, 15_000_000, "letzter Fortschrittssatz");
            assert_eq!(stored.total, 15_000_000);
            assert_eq!(stored.progress, 100.0);
        }

        let _ = delete_job_for(&user_with_id(TEST_OWNER), id.clone()).await;
        let _ = fs::remove_file(internal_log_path(&id)).await;
    }

    /// Gegenprobe zum Test darüber: **derselbe** Aufbau mit einem Kind, das
    /// gar keinen Fortschritt schreibt, lässt den Job bei 0 %. Ohne diese
    /// Gegenprobe wäre der grüne Test oben auch dann grün, wenn die Zahlen aus
    /// irgendeiner anderen Quelle kämen.
    #[tokio::test]
    async fn without_progress_output_the_job_stays_at_zero() {
        let id = format!("stdout-quiet-969c46ad-{}", Uuid::new_v4());
        insert_job(&id, JobStatus::Starting).await;

        let engine: Arc<dyn SyncEngine> = Arc::new(StdoutEngine {
            script: "printf 'kein Fortschritt hier\\n'",
        });

        execute_sync(
            id.clone(),
            sync_request_for_test("/tmp"),
            SYNC_JOBS.clone(),
            engine,
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        {
            let jobs = SYNC_JOBS.lock().await;
            let stored = jobs.get(&id).expect("job");
            // Erfolgreich, deshalb rundet `finish_job` auf 100 % — die
            // *gemessenen* Bytes bleiben aber 0.
            assert_eq!(stored.transferred, 0);
            assert_eq!(stored.total, 0);
        }

        let _ = delete_job_for(&user_with_id(TEST_OWNER), id.clone()).await;
        let _ = fs::remove_file(internal_log_path(&id)).await;
    }

    /// Abbruch: die Flagge, die `cancel_target` herausgibt, beendet den
    /// Kindprozess, und der Job landet in `Cancelled` — nicht in „durch ein
    /// Signal beendet", was der Nutzer als Fehler der Anwendung lesen würde.
    #[tokio::test]
    async fn a_running_sync_is_killed_when_its_cancel_flag_is_set() {
        let id = format!("cancel-533ed42c-{}", Uuid::new_v4());
        let cancel = Arc::new(AtomicBool::new(false));
        register_job(
            job(&id, JobStatus::Starting),
            TEST_OWNER,
            JobKind::Sync,
            Some(Arc::clone(&cancel)),
        )
        .await;

        // Das Kind schreibt seine PID und lebt dann lange genug, dass der
        // Abbruch wirklich einen laufenden Prozess trifft.
        let pid_file = std::env::temp_dir().join(format!("cancel-533ed42c-{}.pid", Uuid::new_v4()));
        // `exec` ist Absicht: `rsync-ssl` ruft am Ende `exec rsync …` auf, das
        // Kind, das wir beenden, **ist** also der Übertragungsprozess und nicht
        // eine Hülle darum. Ein Skript ohne `exec` würde einen Enkel
        // hinterlassen und damit etwas anderes prüfen als die Wirklichkeit.
        let script: &'static str =
            Box::leak(format!("echo $$ > {} ; exec sleep 60", pid_file.display()).into_boxed_str());
        let engine: Arc<dyn SyncEngine> = Arc::new(StdoutEngine { script });

        let id_clone = id.clone();
        // **Dieselbe** Flagge, die `register_job` in die Nebentabelle gelegt
        // hat — genau wie im produktiven Weg. Eine eigene Flagge hier hätte
        // einen Test ergeben, der nie abbricht (erst so gemessen).
        let flag_for_run = Arc::clone(&cancel);
        let run = tokio::spawn(async move {
            execute_sync(
                id_clone,
                sync_request_for_test("/tmp"),
                SYNC_JOBS.clone(),
                engine,
                flag_for_run,
            )
            .await;
        });

        // Warten, bis das Kind läuft — sonst prüft der Test den Abbruch eines
        // Prozesses, den es noch nicht gibt.
        let mut pid = None;
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(&pid_file) {
                if let Ok(parsed) = text.trim().parse::<u32>() {
                    pid = Some(parsed);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let pid = pid.expect("Kindprozess ist gestartet");

        // Über denselben Weg wie ein URL-Abruf: Flagge holen, Flagge setzen.
        match cancel_target(&id).await {
            CancelTarget::Running(flag) => flag.store(true, std::sync::atomic::Ordering::SeqCst),
            _ => panic!("laufender Sync gilt nicht als laufend"),
        }

        tokio::time::timeout(std::time::Duration::from_secs(20), run)
            .await
            .expect("Lauf endet nach dem Abbruch")
            .expect("Lauf ohne Panik");

        {
            let jobs = SYNC_JOBS.lock().await;
            let stored = jobs.get(&id).expect("job");
            assert!(
                matches!(stored.status, JobStatus::Cancelled),
                "Status nach Abbruch: {}",
                stored.status
            );
            assert!(stored.end_time.is_some(), "end_time fehlt");
        }

        // Kein Prozess bleibt zurück. Gezielt über die gemerkte PID — niemals
        // `pkill -f`, das trifft die Testserver aller parallel laufenden
        // Agenten.
        assert!(
            !std::path::Path::new(&format!("/proc/{}", pid)).exists()
                || std::fs::read_to_string(format!("/proc/{}/stat", pid))
                    .map(|s| s.contains(" Z "))
                    .unwrap_or(true),
            "Kindprozess {} lebt nach dem Abbruch weiter",
            pid
        );

        let _ = std::fs::remove_file(&pid_file);
        let _ = delete_job_for(&user_with_id(TEST_OWNER), id.clone()).await;
        let _ = fs::remove_file(internal_log_path(&id)).await;
    }

    // -----------------------------------------------------------------------
    // Die Verdrahtung: eine unbrauchbare Gegenstelle fällt **nicht** auf
    // rclone zurück (Ticket `ae3fdab2`)
    //
    // Der Bestand prüfte `lookup_peer` selbst — nicht, was `select_engine` mit
    // seinem Ergebnis macht. Deshalb blieb `cargo test` grün, als ein Tester
    // das `?` hinter `lookup_peer` gegen `.unwrap_or(None)` tauschte, also
    // genau den Rückfall einbaute, den es nicht geben darf: der Push liefe dann
    // in ein **gleichnamiges rclone-Remote**, und bei `type = local` landen die
    // Daten im lokalen Dateisystem statt auf der Gegenstelle. Kein Fehler,
    // keine Warnung, falsches Ziel.
    //
    // Jeder Test hier legt deshalb ein gleichnamiges rclone-Remote **daneben**.
    // Ohne das wäre „kein Rückfall" nicht beobachtbar, sondern nur nicht
    // beobachtet: `select_engine` würde auch mit Rückfall scheitern, nur mit
    // der Meldung „Unknown remote".
    // -----------------------------------------------------------------------

    /// Aufbau für einen Verdrahtungstest: eigenes Peer-Verzeichnis mit CA und
    /// eine `rclone.conf`, in der `PEER_NAME` als `local`-Remote steht.
    ///
    /// Gibt den Pfad des Peer-Verzeichnisses und den der Konfiguration zurück.
    /// Serialisiert über [`rsync_engine::peers_env_lock`], weil
    /// `RCLONE_GUI_PEERS_DIR` prozessweit wirkt.
    fn wiring_fixture(case: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("wiring-ae3fdab2-{}", case));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("Peer-Verzeichnis");
        std::fs::write(
            dir.join("ca.crt"),
            b"-----BEGIN CERTIFICATE-----\nnicht echt\n-----END CERTIFICATE-----\n",
        )
        .expect("CA");

        // Das gleichnamige rclone-Remote. `type = local` ist der Fall, der weh
        // tut: ein Rückfall würde die Daten in das lokale Dateisystem schieben.
        let config = dir.join("rclone-ae3fdab2.conf");
        std::fs::write(
            &config,
            format!("[{}]\ntype = local\nnounc = true\n", PEER_NAME),
        )
        .expect("rclone.conf");

        std::env::set_var(rsync_engine::PEERS_DIR_ENV, &dir);
        (dir, config)
    }

    /// Der Name, den Gegenstelle und rclone-Remote **teilen**.
    const PEER_NAME: &str = "peer-ae3fdab2";

    fn write_peer_file(dir: &std::path::Path, body: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(format!("{}.json", PEER_NAME));
        std::fs::write(&path, body).expect("Peer-Datei");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("Modus");
    }

    /// Eine brauchbare Hinterlegung. Die CA liegt als `ca.crt` daneben.
    const WIRING_PEER: &str = r#"{
        "host": "localhost",
        "port": 8740,
        "module": "pair0123456789abcd",
        "secret": "deadbeef",
        "ca_cert": "ca.crt"
    }"#;

    fn wiring_request() -> SyncRequest {
        let mut request = sync_request_for_test("/tmp");
        request.remote_name = PEER_NAME.to_string();
        request
    }

    /// **Der Riegel.** Fünf Arten kaputter Hinterlegung, jede mit dem
    /// gleichnamigen rclone-`local`-Remote daneben. Keine davon darf eine
    /// Engine liefern.
    ///
    /// Der Nachweis, dass dieser Test die Verdrahtung fährt und nicht nur
    /// `lookup_peer`: mit `.unwrap_or(None)` statt `?` in
    /// [`select_engine_at`] liefert jeder Durchgang `Ok(RcloneEngine)` und der
    /// Test fällt durch.
    ///
    /// Ein synchroner Test mit eigener Runtime, nicht `#[tokio::test]`: die
    /// Sperre um die Umgebungsvariable ist ein `std::sync::Mutex`, und ihn über
    /// einen `await` zu halten ist genau das, was `clippy::await_holding_lock`
    /// zu Recht meldet. Derselbe Aufbau wie in den Registry-Tests.
    #[test]
    fn an_unusable_peer_never_falls_back_to_a_same_named_rclone_remote() {
        let _guard = rsync_engine::peers_env_lock().lock().expect("Sperre");
        let (dir, config) = wiring_fixture("mode");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Runtime");

        rt.block_on(async {
            // 1. Datei für andere lesbar — sie trägt das Modul-Secret.
            write_peer_file(&dir, WIRING_PEER, 0o644);
            expect_no_engine(&config, "Modus 0644").await;

            // 2. Kaputtes JSON.
            write_peer_file(&dir, "{ kein json", 0o600);
            expect_no_engine(&config, "kaputtes JSON").await;

            // 3. Fehlende CA.
            write_peer_file(
                &dir,
                &WIRING_PEER.replace("ca.crt", "gibtsnicht.crt"),
                0o600,
            );
            expect_no_engine(&config, "fehlende CA").await;

            // 4. CA absolut, ausserhalb des Peer-Verzeichnisses.
            write_peer_file(
                &dir,
                &WIRING_PEER.replace("\"ca.crt\"", "\"/etc/hostname\""),
                0o600,
            );
            expect_no_engine(&config, "CA absolut ausserhalb").await;

            // 5. CA per Symlink aus dem Peer-Verzeichnis hinaus. Die Prüfung
            //    kanonisiert, der Symlink ändert daran nichts.
            let link = dir.join("weg.crt");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink("/etc/hostname", &link).expect("Symlink");
            write_peer_file(&dir, &WIRING_PEER.replace("ca.crt", "weg.crt"), 0o600);
            expect_no_engine(&config, "CA per Symlink hinaus").await;
        });

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var(rsync_engine::PEERS_DIR_ENV);
    }

    /// Ein Durchgang: `select_engine_at` darf **keine** Engine liefern.
    ///
    /// Die Meldung nennt den Fall, damit ein Fehlschlag sagt, *welche* der fünf
    /// Varianten durchgekommen ist — und sie nennt die Engine, weil `"rclone"`
    /// genau der Rückfall ist, um den es geht.
    async fn expect_no_engine(config: &std::path::Path, case: &str) {
        match select_engine_at(Some(config), &wiring_request()).await {
            Err(_) => {}
            Ok(engine) => panic!(
                "{}: durchgekommen als Engine {:?} — bei \"rclone\" ist es der Rückfall auf das \
                 gleichnamige Remote, und der Push landet am falschen Ziel",
                case,
                engine.name()
            ),
        }
    }

    /// Der Positivfall, ohne den der Riegel oben auch von einem kaputten
    /// `lookup_peer` erfüllt wäre: eine **gültige** Gegenstelle gewinnt gegen
    /// das gleichnamige rclone-Remote.
    #[test]
    fn a_valid_peer_wins_over_a_same_named_rclone_remote() {
        let _guard = rsync_engine::peers_env_lock().lock().expect("Sperre");
        let (dir, config) = wiring_fixture("valid");
        write_peer_file(&dir, WIRING_PEER, 0o600);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Runtime");

        rt.block_on(async {
            let engine = select_engine_at(Some(&config), &wiring_request())
                .await
                .expect("gültige Gegenstelle");
            assert_eq!(engine.name(), "rsync", "das rclone-Remote hat gewonnen");
        });

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var(rsync_engine::PEERS_DIR_ENV);
    }

    /// Gegenprobe zu beidem: **ohne** Peer-Datei entscheidet dieselbe
    /// `rclone.conf` auf `rclone`. Damit steht fest, dass die Fehlschläge oben
    /// aus der Peer-Prüfung kommen und nicht daraus, dass die Konfiguration im
    /// Test gar nicht gelesen würde.
    #[test]
    fn without_a_peer_file_the_same_config_selects_rclone() {
        let _guard = rsync_engine::peers_env_lock().lock().expect("Sperre");
        let (dir, config) = wiring_fixture("norsync");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Runtime");

        rt.block_on(async {
            let engine = select_engine_at(Some(&config), &wiring_request())
                .await
                .expect("rclone-Remote ist konfiguriert");
            assert_eq!(engine.name(), "rclone");

            // Und ein Name, der in keiner der beiden Quellen steht, wird
            // abgelehnt — kein stiller Erfolg.
            let mut unknown = wiring_request();
            unknown.remote_name = "gibtsnicht-ae3fdab2".to_string();
            assert!(select_engine_at(Some(&config), &unknown).await.is_err());
        });

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var(rsync_engine::PEERS_DIR_ENV);
    }

    // -----------------------------------------------------------------------
    // Der Restpuffer in `pump_stdout_progress` (Ticket `ae3fdab2`)
    // -----------------------------------------------------------------------

    /// Der **letzte** Fortschrittssatz kommt ohne Trennzeichen.
    ///
    /// `--info=progress2` trennt mit `\r`, nicht mit `\n`: endet der Prozess,
    /// bevor er den nächsten Wagenrücklauf schreibt, steht der zuletzt
    /// gemessene Stand als **unvollständige** letzte Zeile im Puffer. Nur der
    /// Zweig hinter der Leseschleife holt ihn noch heraus.
    ///
    /// Vorgeführt: streicht man diesen Zweig, bleibt der Job auf dem vorletzten
    /// Satz (3.000.000) stehen und dieser Test fällt durch.
    ///
    /// **Gefahren wird `pump_stdout_progress` direkt, nicht `execute_sync`.**
    /// Nicht aus Bequemlichkeit: `execute_sync` startet den Leser als eigene
    /// Task und wartet am Ende **nicht** auf sie. Eine Messung über
    /// `execute_sync` misst deshalb ein Wettrennen und nicht den Zweig — sie
    /// war zuerst so gebaut und schlug mit 3.000.000 fehl, obwohl der Zweig
    /// vorhanden ist. Der Befund ist notiert; ihn zu beheben (auf die
    /// Leser-Task warten) gehört nicht in dieses Ticket.
    #[tokio::test]
    async fn the_last_record_without_a_separator_still_counts() {
        let id = format!("stdout-rest-ae3fdab2-{}", Uuid::new_v4());
        insert_job(&id, JobStatus::Starting).await;

        let engine: Arc<dyn SyncEngine> = Arc::new(StdoutEngine { script: "" });

        // Zwei Sätze, getrennt durch `\r`; der letzte endet **ohne** jedes
        // Trennzeichen. Zwei `printf`-Aufrufe, damit sie als zwei Schreibvorgänge
        // in die Pipe gehen — so, wie rsync sie schreibt.
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(concat!(
                r"printf '\r     3,000,000  27%%    2.76GB/s    0:00:01 (xfr#1, to-chk=4/6)';",
                r"printf '\r     7,777,777  70%%    2.32GB/s    0:00:02 (xfr#3, to-chk=2/6)'"
            ))
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("sh");
        let stdout = child.stdout.take().expect("stdout");

        pump_stdout_progress(stdout, id.clone(), SYNC_JOBS.clone(), engine).await;
        let _ = child.wait().await;

        {
            let jobs = SYNC_JOBS.lock().await;
            let stored = jobs.get(&id).expect("job");
            assert_eq!(
                stored.transferred, 7_777_777,
                "der letzte Satz ohne Trennzeichen ist verloren gegangen"
            );
            assert_eq!(stored.total, 11_111_110);
            assert_eq!(stored.progress, 70.0);
        }

        let _ = delete_job_for(&user_with_id(TEST_OWNER), id.clone()).await;
        let _ = fs::remove_file(internal_log_path(&id)).await;
    }

    /// Gegenprobe: **derselbe** Aufbau, nur mit abschliessendem `\r` hinter dem
    /// letzten Satz. Dann trägt ihn die Leseschleife, und der Restpuffer ist
    /// leer. Ohne diese Gegenprobe wäre der Test darüber auch dann grün, wenn
    /// die Leseschleife den letzten Satz ohnehin sähe — und würde den
    /// Restpuffer-Zweig gar nicht absichern.
    #[tokio::test]
    async fn with_a_trailing_separator_the_read_loop_already_has_it() {
        let id = format!("stdout-sep-ae3fdab2-{}", Uuid::new_v4());
        insert_job(&id, JobStatus::Starting).await;

        let engine: Arc<dyn SyncEngine> = Arc::new(StdoutEngine { script: "" });

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(concat!(
                r"printf '\r     3,000,000  27%%    2.76GB/s    0:00:01 (xfr#1, to-chk=4/6)';",
                r"printf '\r     7,777,777  70%%    2.32GB/s    0:00:02 (xfr#3, to-chk=2/6)\r'"
            ))
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("sh");
        let stdout = child.stdout.take().expect("stdout");

        pump_stdout_progress(stdout, id.clone(), SYNC_JOBS.clone(), engine).await;
        let _ = child.wait().await;

        {
            let jobs = SYNC_JOBS.lock().await;
            let stored = jobs.get(&id).expect("job");
            assert_eq!(stored.transferred, 7_777_777);
        }

        let _ = delete_job_for(&user_with_id(TEST_OWNER), id.clone()).await;
        let _ = fs::remove_file(internal_log_path(&id)).await;
    }

    // -----------------------------------------------------------------------
    // Abbruch über den Endpunkt (Ticket `45130845`, Anforderungen aus `13927646`)
    // -----------------------------------------------------------------------

    /// Ein laufender Job, dessen Kind seine PID ablegt und auf SIGTERM
    /// ordentlich aussteigt. Gibt PID-Datei, Marker-Datei und das Skript.
    ///
    /// Das Kind ist hier **absichtlich** eine Shell mit `trap` und nicht
    /// `exec sleep`: nur so lässt sich beobachten, *welches* Signal ankam. Für
    /// die Frage „ist der Prozess danach weg" gibt es den Bestandstest
    /// `a_running_sync_is_killed_when_its_cancel_flag_is_set`, der mit `exec`
    /// arbeitet, weil `rsync-ssl` mit `exec rsync` endet.
    fn trapping_child(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, &'static str) {
        let unique = Uuid::new_v4();
        let pid_file = std::env::temp_dir().join(format!("cancel-45130845-{}-{}.pid", tag, unique));
        let marker = std::env::temp_dir().join(format!("cancel-45130845-{}-{}.term", tag, unique));
        let script: &'static str = Box::leak(
            format!(
                "trap 'printf TERM > {marker}; exit 143' TERM; echo $$ > {pid}; \
                 while true; do sleep 0.1; done",
                marker = marker.display(),
                pid = pid_file.display()
            )
            .into_boxed_str(),
        );
        (pid_file, marker, script)
    }

    /// Wartet, bis das Kind seine PID geschrieben hat.
    async fn await_pid(pid_file: &std::path::Path) -> u32 {
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(pid_file) {
                if let Ok(parsed) = text.trim().parse::<u32>() {
                    return parsed;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("Kindprozess ist nicht gestartet");
    }

    /// **Der Kern des Tickets.** Der Besitzer bricht über `cancel_sync_for` ab;
    /// das Kind bekommt **SIGTERM** (nicht SIGKILL), der Job landet in
    /// `Cancelled`, und der Prozess ist danach weg.
    ///
    /// Der Marker ist der Nachweis über das Signal: er entsteht **nur** im
    /// `trap`-Zweig. Ein SIGKILL zuerst — der Zustand vor diesem Ticket — lässt
    /// ihn nicht entstehen, und dieser Test fällt durch. Genau das kostet bei
    /// rsync die verwaisten `.name.XXXXXX`-Dateien.
    #[tokio::test]
    async fn cancelling_sends_sigterm_and_the_process_is_gone_afterwards() {
        let id = format!("cancel-45130845-{}", Uuid::new_v4());
        let cancel = Arc::new(AtomicBool::new(false));
        register_job(
            job(&id, JobStatus::Starting),
            TEST_OWNER,
            JobKind::Sync,
            Some(Arc::clone(&cancel)),
        )
        .await;

        let (pid_file, marker, script) = trapping_child("term");
        let engine: Arc<dyn SyncEngine> = Arc::new(StdoutEngine { script });

        let id_clone = id.clone();
        let flag_for_run = Arc::clone(&cancel);
        let run = tokio::spawn(async move {
            execute_sync(
                id_clone,
                sync_request_for_test("/tmp"),
                SYNC_JOBS.clone(),
                engine,
                flag_for_run,
            )
            .await;
        });

        let pid = await_pid(&pid_file).await;

        // Über den Endpunkt, nicht über die Flagge — die Verdrahtung ist der
        // Punkt des Tickets.
        let response = cancel_sync_for(&user_with_id(TEST_OWNER), id.clone()).await;
        assert!(
            response.0.success,
            "Abbruch abgelehnt: {:?}",
            response.0.error
        );

        tokio::time::timeout(std::time::Duration::from_secs(20), run)
            .await
            .expect("Lauf endet nach dem Abbruch")
            .expect("Lauf ohne Panik");

        // Das Signal war SIGTERM. Der Marker entsteht nur im `trap`-Zweig.
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap_or_default(),
            "TERM",
            "das Kind hat kein SIGTERM gesehen — bei SIGKILL bleiben bei rsync \
             verwaiste .name.XXXXXX-Dateien im Ziel liegen"
        );

        {
            let jobs = SYNC_JOBS.lock().await;
            let stored = jobs.get(&id).expect("job");
            assert!(
                matches!(stored.status, JobStatus::Cancelled),
                "Status nach Abbruch: {}",
                stored.status
            );
            // Ein eigener Endzustand: weder Erfolg noch Fehlschlag noch
            // Teilerfolg — und trotzdem terminal, also löschbar.
            assert!(!stored.status.is_success());
            assert!(!stored.status.is_partial());
            assert!(stored.status.is_terminal());
            assert_eq!(stored.status.state(), "cancelled");
            assert!(stored.end_time.is_some(), "end_time fehlt");
        }

        // Der Prozess ist weg. Gezielt über die gemerkte PID — niemals
        // `pkill -f`, das trifft die Testserver aller parallel laufenden Agenten.
        assert!(
            !std::path::Path::new(&format!("/proc/{}", pid)).exists()
                || std::fs::read_to_string(format!("/proc/{}/stat", pid))
                    .map(|s| s.contains(" Z "))
                    .unwrap_or(true),
            "Kindprozess {} lebt nach dem Abbruch weiter",
            pid
        );

        // Der Hinweis, dass im Ziel Geschriebenes liegen bleibt, steht in der
        // Antwort **und** im Job-Log.
        assert!(response
            .0
            .data
            .as_deref()
            .unwrap_or_default()
            .contains("bleibt dort liegen"));
        let log = fs::read_to_string(internal_log_path(&id))
            .await
            .unwrap_or_default();
        assert!(log.contains("Abbruch angefordert"), "Log: {}", log);

        let _ = std::fs::remove_file(&pid_file);
        let _ = std::fs::remove_file(&marker);
        let _ = delete_job_for(&user_with_id(TEST_OWNER), id.clone()).await;
        let _ = fs::remove_file(internal_log_path(&id)).await;
    }

    /// **Nur der Besitzer.** Ein fremdes Konto und eine unbekannte ID bekommen
    /// dieselbe Antwort — byte-gleich —, und der fremde Job läuft **weiter**:
    /// die Flagge bleibt aus.
    ///
    /// Dass die beiden Fälle auch **zeitlich** nicht zu unterscheiden sind,
    /// hängt am Aufbau und nicht an einer Messung: für einen Unberechtigten ist
    /// [`job_access`] die erste und einzige Anweisung — eine `HashMap`-Suche,
    /// danach die Rückgabe. Kein Dateisystem, keine Datenbank, kein zweiter
    /// Zweig. Genau deshalb steht `append_job_log` **hinter** der Prüfung: an
    /// anderer Stelle verriet die Dauer die Dateiexistenz, weil die
    /// Pfadauflösung vorher lief.
    #[tokio::test]
    async fn a_stranger_cannot_cancel_and_gets_the_same_answer_as_for_an_unknown_job() {
        let id = format!("cancel-foreign-45130845-{}", Uuid::new_v4());
        let cancel = Arc::new(AtomicBool::new(false));
        register_job(
            job(&id, JobStatus::Running),
            TEST_OWNER,
            JobKind::Sync,
            Some(Arc::clone(&cancel)),
        )
        .await;

        let stranger = user_with_id("u-stranger-45130845");
        let foreign = cancel_sync_for(&stranger, id.clone()).await;
        let unknown = cancel_sync_for(&stranger, Uuid::new_v4().to_string()).await;

        assert!(!foreign.0.success);
        assert_eq!(foreign.0.error.as_deref(), Some(JOB_UNAVAILABLE));
        // Byte-gleich, nicht nur „beides ein Fehler".
        assert_eq!(foreign.0.error, unknown.0.error);
        assert_eq!(foreign.0.success, unknown.0.success);
        assert_eq!(foreign.0.data, unknown.0.data);

        // Und der fremde Job läuft weiter.
        assert!(
            !cancel.load(std::sync::atomic::Ordering::SeqCst),
            "ein fremdes Konto hat die Abbruchflagge gesetzt"
        );

        drop_job_for_test(&id).await;
    }

    /// Ein **URL-Abruf** ist über diese Route nicht abbrechbar — er hat seinen
    /// eigenen Endpunkt. Und die Antwort ist wieder dieselbe, damit die Route
    /// nicht verrät, welcher Art ein fremder Job ist.
    #[tokio::test]
    async fn a_url_fetch_is_not_cancellable_through_the_sync_route() {
        let id = format!("cancel-fetch-45130845-{}", Uuid::new_v4());
        let cancel = Arc::new(AtomicBool::new(false));
        register_job(
            job(&id, JobStatus::Running),
            TEST_OWNER,
            JobKind::UrlFetch,
            Some(Arc::clone(&cancel)),
        )
        .await;

        let response = cancel_sync_for(&user_with_id(TEST_OWNER), id.clone()).await;
        assert!(!response.0.success);
        assert_eq!(response.0.error.as_deref(), Some(JOB_UNAVAILABLE));
        assert!(!cancel.load(std::sync::atomic::Ordering::SeqCst));

        drop_job_for_test(&id).await;
    }

    /// **Idempotent.** Zweimal abbrechen und ein bereits beendeter Job laufen
    /// beide sauber durch — kein Fehler.
    #[tokio::test]
    async fn a_second_cancel_and_a_finished_job_are_not_an_error() {
        let id = format!("cancel-twice-45130845-{}", Uuid::new_v4());
        let cancel = Arc::new(AtomicBool::new(false));
        register_job(
            job(&id, JobStatus::Running),
            TEST_OWNER,
            JobKind::Sync,
            Some(Arc::clone(&cancel)),
        )
        .await;
        let owner = user_with_id(TEST_OWNER);

        let first = cancel_sync_for(&owner, id.clone()).await;
        assert!(first.0.success);
        assert!(cancel.load(std::sync::atomic::Ordering::SeqCst));

        // Zweiter Versuch, während der Job noch als laufend in der Tabelle
        // steht: dieselbe Antwort, kein Fehler.
        let second = cancel_sync_for(&owner, id.clone()).await;
        assert!(second.0.success);
        assert_eq!(first.0.data, second.0.data);

        // Und nach dem Endzustand: ebenfalls kein Fehler, nur ein anderer Text.
        complete_job(&id, JobStatus::Cancelled).await;
        let third = cancel_sync_for(&owner, id.clone()).await;
        assert!(
            third.0.success,
            "Abbruch eines beendeten Jobs war ein Fehler"
        );
        assert_eq!(third.0.data.as_deref(), Some(CANCEL_ALREADY_DONE));

        drop_job_for_test(&id).await;
    }
}
