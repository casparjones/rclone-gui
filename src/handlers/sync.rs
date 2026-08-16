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
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

type SyncJobs = Arc<Mutex<HashMap<String, SyncProgress>>>;
type JobEngines = Arc<Mutex<HashMap<String, Arc<dyn SyncEngine>>>>;

lazy_static::lazy_static! {
    static ref SYNC_JOBS: SyncJobs = Arc::new(Mutex::new(HashMap::new()));
    /// Engine used by a running job. Entries live only while the job runs.
    static ref JOB_ENGINES: JobEngines = Arc::new(Mutex::new(HashMap::new()));
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
    /// Endzustand mit Begründung. Der Text ist reine Anzeige — **keine** Stelle
    /// im Code leitet daraus noch eine Entscheidung ab.
    Failed { reason: String },
    /// Vom Nutzer abgebrochen. Noch nicht erzeugt; der Abbruch-Knopf ist ein
    /// eigenes Ticket. Der Zustand steht hier, damit Terminal-Logik und
    /// Serialisierung ihn von Anfang an mit abdecken.
    #[allow(dead_code)]
    Cancelled,
}

impl JobStatus {
    /// Fehlerzustand mit Begründung.
    pub fn failed(reason: impl Into<String>) -> Self {
        JobStatus::Failed {
            reason: reason.into(),
        }
    }

    /// Der Job ist fertig — egal ob erfolgreich oder nicht. Ein Job in diesem
    /// Zustand ist löschbar, hat `end_time` gesetzt und beendet die
    /// CLI-Monitor-Schleife.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            JobStatus::Completed | JobStatus::Failed { .. } | JobStatus::Cancelled
        )
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
/// (`rclone sync`, `rsync -a --delete`). Only `Copy` is used today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    Copy,
    #[allow(dead_code)] // wired up by the "Im Ziel löschen" ticket
    Mirror,
}

/// Everything an engine needs to build the command line for one job.
pub struct JobSpec<'a> {
    /// Identifies the job; engines that need per-job scratch files (rsync's
    /// password file) name them after it.
    #[allow(dead_code)]
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
    /// The child reports progress on stdout, read line by line while it runs
    /// (rsync `--info=progress2`).
    #[allow(dead_code)] // used by the rsync engine
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

    /// Build the child process for one job. May fail for engines that have to
    /// materialise credentials first.
    fn build_command(&self, spec: &JobSpec<'_>) -> anyhow::Result<EngineCommand>;

    /// Where progress comes from for this engine.
    fn progress_source(&self) -> ProgressSource;

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
}

/// Engine for a request. Only rclone exists today; the mode switch that picks
/// a different engine is a separate ticket.
fn select_engine(_sync_request: &SyncRequest) -> Arc<dyn SyncEngine> {
    Arc::new(RcloneEngine)
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

        Ok(EngineCommand::new("rclone", args))
    }

    fn progress_source(&self) -> ProgressSource {
        ProgressSource::JobLog
    }

    fn parse_progress(&self, chunk: &str) -> Option<ProgressSnapshot> {
        parse_rclone_log_progress(chunk).map(ProgressSnapshot::from)
    }
}

/// Ensure the log directory exists and create a new log file with an initial entry
async fn create_initial_log(job_id: &str, sync_request: &SyncRequest) -> tokio::io::Result<()> {
    fs::create_dir_all("data/log").await?;

    let remote_target = format!("{}:{}", sync_request.remote_name, sync_request.remote_path);
    let log_file_path = format!("data/log/{}.log", job_id);
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

    let initial_log = format!(
        "[{}] Job {} started\n[{}] Source: {}\n[{}] Remote: {}\n[{}] Target: {}\n[{}] Starting rclone operation...\n\n",
        timestamp,
        job_id,
        timestamp,
        sync_request.source_path,
        timestamp,
        sync_request.remote_name,
        timestamp,
        remote_target,
        timestamp
    );

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
    // Vor allem anderen: der Remote-Name muss syntaktisch sauber und
    // konfiguriert sein. Ein Name wie `:local` wäre rclones
    // On-the-fly-Syntax für ein nicht konfiguriertes Backend und schriebe in
    // beliebige Wirtspfade. Die Prüfung steht deshalb vor der Job-Anlage:
    // Wird sie abgelehnt, entsteht weder ein Job noch ein Log noch ein
    // rclone-Prozess.
    if let Err(e) = crate::config_manager::ensure_configured_remote(&sync_request.remote_name).await
    {
        warn!("Sync abgelehnt: {}", e);
        return ResponseJson(ApiResponse::error(&e.to_string()));
    }

    // Dasselbe gilt für die Quelle: abgelehnt wird, bevor ein Job in der
    // Tabelle steht, bevor eine Logdatei angelegt ist und bevor irgendein
    // Prozess startet.
    match resolved_source_path(current, &sync_request.source_path).await {
        // Was an rclone geht, ist der kanonisierte Pfad – nicht die Eingabe.
        Ok(path) => sync_request.source_path = path,
        Err(message) => return ResponseJson(ApiResponse::error(message)),
    }

    let job_id = Uuid::new_v4().to_string();

    info!("🚀 Starting new sync job: {}", job_id);
    info!("   Source: {}", sync_request.source_path);
    info!(
        "   Remote: {}:{}",
        sync_request.remote_name, sync_request.remote_path
    );

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
    };

    {
        let mut jobs = SYNC_JOBS.lock().await;
        jobs.insert(job_id.clone(), progress);
    }

    // Immediately create the log file so it is visible in the UI
    if let Err(e) = create_initial_log(&job_id, &sync_request).await {
        error!("Failed to create initial log for {}: {}", job_id, e);
    } else {
        debug!("📝 Initial log file created for job {}", job_id);
    }

    let engine = select_engine(&sync_request);
    {
        let mut engines = JOB_ENGINES.lock().await;
        engines.insert(job_id.clone(), engine.clone());
    }

    let job_id_clone = job_id.clone();
    let sync_jobs = SYNC_JOBS.clone();

    tokio::spawn(async move {
        execute_sync(job_id_clone, sync_request, sync_jobs, engine).await;
    });

    ResponseJson(ApiResponse::success(job_id))
}

pub async fn get_sync_progress(job_id: String) -> ResponseJson<ApiResponse<SyncProgress>> {
    let engine = engine_for_job(&job_id).await;
    let mut jobs = SYNC_JOBS.lock().await;

    match jobs.get_mut(&job_id) {
        Some(progress) => {
            // Update progress from log file if job is running and the engine
            // reports through the log file. Stdout based engines push their
            // progress into the job themselves while they run.
            if progress.status == JobStatus::Running
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
        None => ResponseJson(ApiResponse::error("Job not found")),
    }
}

pub async fn list_sync_jobs() -> ResponseJson<ApiResponse<Vec<SyncProgress>>> {
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
            let log_file_path = format!("data/log/{}.log", job_id);
            if let Err(e) = tokio::fs::remove_file(&log_file_path).await {
                debug!("⚠️ Could not delete log file {}: {}", log_file_path, e);
            }
        }
    }

    let mut job_list: Vec<SyncProgress> = jobs.values().cloned().collect();

    // Sort by creation time (newest first) - using job_id as timestamp proxy
    job_list.sort_by(|a, b| b.id.cmp(&a.id));

    ResponseJson(ApiResponse::success(job_list))
}

pub async fn get_sync_log(job_id: String) -> ResponseJson<ApiResponse<String>> {
    let log_file_path = format!("data/log/{}.log", job_id);
    debug!("📖 Reading log file for job {}: {}", job_id, log_file_path);

    match fs::read_to_string(&log_file_path).await {
        Ok(content) => {
            info!(
                "📖 Log file read successfully for job {}, {} bytes",
                job_id,
                content.len()
            );
            ResponseJson(ApiResponse::success(content))
        }
        Err(e) => {
            warn!("📖 Log file read failed for job {}: {}", job_id, e);
            ResponseJson(ApiResponse::error(&format!("Log file not found: {}", e)))
        }
    }
}

pub async fn delete_sync_job(job_id: String) -> ResponseJson<ApiResponse<String>> {
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

    // Remove log file
    let log_file_path = format!("data/log/{}.log", job_id);
    if let Err(e) = fs::remove_file(&log_file_path).await {
        println!(
            "Warning: Could not delete log file {}: {}",
            log_file_path, e
        );
    }

    ResponseJson(ApiResponse::success("Job deleted successfully".to_string()))
}

async fn execute_sync(
    job_id: String,
    sync_request: SyncRequest,
    sync_jobs: SyncJobs,
    engine: Arc<dyn SyncEngine>,
) {
    let log_file_path = format!("data/log/{}.log", job_id);

    // Ensure log directory and initial log exist in case start_sync didn't manage to create them (e.g. on crash)
    if let Err(e) = create_initial_log(&job_id, &sync_request).await {
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
        mode: TransferMode::Copy,
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

    // Wait for the engine process to exit
    let status = child.wait().await;

    cleanup_temp_files(&command).await;

    // Update in-memory status based on exit code. Der Wortlaut von
    // `describe_exit()` ist hier nur noch Anzeigetext — er wird in
    // `JobStatus::Failed` verpackt, das Terminal-Verhalten hängt am Typ.
    let final_status = match &status {
        Ok(es) if es.success() => {
            info!("✅ Job {} completed successfully", job_id);
            JobStatus::Completed
        }
        Ok(es) => {
            warn!("❌ Job {} failed with exit code: {:?}", job_id, es.code());
            JobStatus::failed(engine.describe_exit(es.code()))
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
async fn pump_stdout_progress(
    stdout: tokio::process::ChildStdout,
    job_id: String,
    sync_jobs: SyncJobs,
    engine: Arc<dyn SyncEngine>,
) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(snapshot) = engine.parse_progress(&line) {
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
    let log_file_path = format!("data/log/{}.log", job_id);

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
        }
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

    async fn insert_job(id: &str, status: JobStatus) {
        SYNC_JOBS
            .lock()
            .await
            .insert(id.to_string(), job(id, status));
    }

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

        let response = delete_sync_job(id.to_string()).await;
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

        let response = delete_sync_job(id.to_string()).await;
        assert!(!response.0.success);

        SYNC_JOBS.lock().await.remove(id);
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
            SYNC_JOBS.lock().await.insert(id.to_string(), entry);
        }

        let _ = list_sync_jobs().await;

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
}
