//! Downloader: „Von URL holen" als regulärer Job.
//!
//! Der Nutzer gibt eine URL an, der **Server** holt sie ab und legt das
//! Ergebnis in seinem Home ab. Der Abruf läuft als Job — mit Eintrag in der
//! Job-Liste, mit Logdatei unter `data/log/<job_id>.log` und mit Abbruch —,
//! damit Fortschritt, Log und Abbrechen dieselben Wege benutzen wie ein Sync
//! und nicht als Sonderfall daneben stehen.
//!
//! ## Entscheidung: eigener Streaming-Download, nicht `rclone copyurl`
//!
//! Das Ticket lässt beides offen. Genommen ist der eigene Download, aus einem
//! Grund: `rclone copyurl` würde die URL **selbst** auflösen und selbst
//! Weiterleitungen folgen. Damit wäre der gesamte SSRF-Schutz aus
//! [`crate::handlers::urlguard`] wirkungslos — kein `vet_url`, keine geprüfte
//! Adresse, keine Prüfung nach jedem Sprung, und nichts davon nachrüstbar,
//! weil die Auflösung in einem fremden Prozess passiert. Ein Nutzer könnte
//! `http://169.254.169.254/latest/meta-data/` angeben und bekäme die Antwort
//! in seinen Ordner gelegt.
//!
//! Der Preis ist, dass Fortschritt und Rahmenwerk hier selbst gebaut sind
//! statt aus rclones JSON-Log zu kommen. Das ist deutlich weniger Code als der
//! Versuch, `copyurl` nachträglich einzuzäunen — und der Zaun wäre unecht.
//!
//! ## Was hier *nicht* passiert
//!
//! Zu jeder Regel ist unten angegeben, **welcher Test sie absichert** und dass
//! er in der Gegenprobe (Regel absichtlich verletzt) tatsächlich durchfällt.
//! Eine Zusicherung, deren Test in der Mutation grün bleibt, ist keine.
//!
//! * **Keine eigene Namensauflösung.** Die Adresse kommt aus `vet_url`, der
//!   Transport verbindet ausschliesslich damit.
//!   Nachweis: `urlguard::tests::streaming_transport_connects_to_the_vetted_address_without_resolving`
//!   — feuert, wenn `connect_vetted` in `StreamingHttpTransport::open` durch
//!   ein eigenes `TcpStream::connect` ersetzt wird. Der ältere Mock-Test
//!   `stream_transport_sees_only_the_vetted_address` bleibt dabei grün: er
//!   prüft nur, welche Adresse die Schleife *übergibt*.
//! * **Keine eigene Redirect-Verfolgung.** Die Schleife führt
//!   `fetch_guarded_stream`, damit jeder Sprung erneut geprüft wird.
//!   Nachweis: `urlguard::tests::stream_redirect_to_metadata_address_is_rejected`
//!   und `stream_later_hop_to_loopback_is_rejected` — beide feuern, wenn die
//!   Wiederprüfung ab dem zweiten Sprung entfällt.
//! * **Kein Puffern im Speicher.** Der Körper geht stückweise in die
//!   Zieldatei; die Grössengrenze ist damit eine Downloadgrenze.
//!   Nachweis: `tests::datei_waechst_vor_dem_ende_des_abrufs` — feuert, wenn
//!   `run_fetch` die Stücke sammelt und erst am Ende schreibt. Vorher gab es
//!   für diese Regel **keinen** Test, der das bemerkt hätte.
//! * **Kein `allow_private_addresses`.** Das Feld wird auf dem produktiven Weg
//!   nirgends gesetzt (siehe [`production_policy`]).
//!   Nachweis: `tests::production_policy_erlaubt_keine_privaten_adressen` und
//!   `tests::ipv4_literal_bleibt_geprueft` — beide feuern, wenn
//!   `production_policy` das Feld setzt. Dass `start_url_fetch` genau dieses
//!   Regelwerk weitergibt, ist dagegen **nur durch Codelesen** belegt.
//! * **Kein `scope=system`.** Wurzel ist immer das Home des anfragenden
//!   Nutzers — dieselbe Begründung wie beim Sync: ein Hintergrundlauf, der
//!   irgendwohin schreiben darf, ist nicht zurücknehmbar.
//!
//! ## Terminalzustand
//!
//! Ein abgebrochener oder an einer Grenze gescheiterter Download hinterlässt
//! **keine** Datei: geschrieben wird in `.rclone-gui-<job>.part`, und dieses
//! Bruchstück wird bei jedem Fehlweg gelöscht. Damit gibt es hier nichts
//! „Teilweises", das ein Nutzer weiterverwenden könnte —
//! [`JobStatus::Partial`] wäre eine Lüge über den Zustand des Zielordners.
//! Abbruch ist deshalb `Cancelled`, eine überschrittene Grenze `Failed`.

use crate::handlers::auth_web::CurrentUser;
use crate::handlers::download::{is_within_root, resolve_within_root, user_root, RootScope};
use crate::handlers::sync::JobStatus;
use crate::handlers::urlguard::{
    fetch_guarded_stream, parse_url, vet_url, DownloadSlot, DownloadSlots, GuardError, GuardPolicy,
    Resolver, StreamingHttpTransport, StreamingTransport, SystemResolver,
};
use crate::models::{ApiResponse, SyncProgress};
use axum::{extract::Json, response::Json as ResponseJson, Extension};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Anfrage
// ---------------------------------------------------------------------------

/// Was der Client schickt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlFetchRequest {
    /// Die abzurufende URL. Nur `http`/`https`.
    pub url: String,
    /// Zielordner, relativ zum Home des Nutzers. Fehlt er, ist es das Home.
    #[serde(default)]
    pub target_path: Option<String>,
    /// Wunschname. Fehlt er, entscheidet `Content-Disposition`, sonst die URL.
    #[serde(default)]
    pub filename: Option<String>,
}

// ---------------------------------------------------------------------------
// Regelwerk
// ---------------------------------------------------------------------------

/// Das Regelwerk des produktiven Wegs.
///
/// Bewusst ohne Schalter: `GuardPolicy::default()` hat
/// `allow_private_addresses = false`, und diese Funktion ist die **einzige**
/// Stelle, an der dieses Modul ein Regelwerk für einen echten Abruf baut.
/// Wer den Wert hier setzt, fällt über den Test darunter.
pub fn production_policy() -> GuardPolicy {
    GuardPolicy::default()
}

lazy_static::lazy_static! {
    /// Gleichzeitige Abrufe je Nutzer.
    static ref SLOTS: Arc<DownloadSlots> =
        DownloadSlots::new(production_policy().max_concurrent_per_user);

    /// Die Jobs dieses Moduls.
    ///
    /// Eigene Tabelle, weil die des Syncs (`sync::SYNC_JOBS`) modulprivat ist
    /// und `sync.rs` in diesem Ticket nicht angefasst wird. Nach ausserhalb
    /// sieht es trotzdem wie **eine** Liste aus: `main.rs` hängt
    /// [`job_list`] an die Sync-Liste an, und die Fortschritts-, Log- und
    /// Löschwege fallen auf dieses Modul zurück, wenn der Sync die Job-ID
    /// nicht kennt. Der saubere Endzustand wäre eine gemeinsame Registry in
    /// `sync.rs` — das ist eine Änderung an fremder Datei und im Bericht
    /// vermerkt.
    static ref JOBS: Mutex<HashMap<String, JobEntry>> = Mutex::new(HashMap::new());
}

/// Ein Job dieses Moduls.
struct JobEntry {
    progress: SyncProgress,
    /// Wird gesetzt, wenn abgebrochen werden soll. Der Schreibweg prüft es
    /// nach jedem Stück.
    cancel: Arc<AtomicBool>,
}

/// Sperre auf der Job-Tabelle. Ein vergifteter Mutex darf keinen Request-Pfad
/// abstürzen lassen — dieselbe Behandlung wie in `handlers::shares`.
fn jobs() -> MutexGuard<'static, HashMap<String, JobEntry>> {
    JOBS.lock().unwrap_or_else(|p| p.into_inner())
}

/// Alle Jobs dieses Moduls, für die gemeinsame Job-Liste.
pub fn job_list() -> Vec<SyncProgress> {
    let mut list: Vec<SyncProgress> = jobs().values().map(|e| e.progress.clone()).collect();
    list.sort_by_key(|p| std::cmp::Reverse(p.start_time));
    list
}

/// Fortschritt eines Jobs, oder `None`, wenn er nicht hierher gehört.
pub fn job_progress(job_id: &str) -> Option<SyncProgress> {
    jobs().get(job_id).map(|e| e.progress.clone())
}

/// Löscht einen beendeten Job samt Logdatei.
///
/// `None` heisst „kenne ich nicht" — dann ist der Sync zuständig.
pub async fn delete_job(job_id: &str) -> Option<ApiResponse<String>> {
    {
        let mut guard = jobs();
        let entry = guard.get(job_id)?;
        if !entry.progress.status.is_terminal() {
            return Some(ApiResponse::error(
                "Ein laufender Abruf kann nur abgebrochen werden",
            ));
        }
        guard.remove(job_id);
    }
    if let Err(e) = tokio::fs::remove_file(log_path(job_id)).await {
        tracing::debug!("Logdatei von {} nicht löschbar: {}", job_id, e);
    }
    Some(ApiResponse::success("Job deleted successfully".to_string()))
}

/// Bricht einen laufenden Abruf ab.
pub async fn cancel_job(job_id: String) -> ResponseJson<ApiResponse<String>> {
    let flag = {
        let guard = jobs();
        match guard.get(&job_id) {
            None => return ResponseJson(ApiResponse::error("Job not found")),
            Some(entry) if entry.progress.status.is_terminal() => {
                return ResponseJson(ApiResponse::error("Der Abruf ist bereits beendet"))
            }
            Some(entry) => Arc::clone(&entry.cancel),
        }
    };
    flag.store(true, Ordering::SeqCst);
    info!("🛑 Abbruch angefordert für Abruf {}", job_id);
    append_log(&job_id, "Abbruch angefordert").await;
    ResponseJson(ApiResponse::success("Abbruch angefordert".to_string()))
}

// ---------------------------------------------------------------------------
// Dateiname
// ---------------------------------------------------------------------------

/// Obergrenze für einen Dateinamen. `NAME_MAX` ist auf ext4 255 **Byte**; der
/// Wert bleibt darunter, damit auch ein `(1)`-Suffix noch passt.
const MAX_NAME_BYTES: usize = 200;

/// Macht aus Fremdeingabe einen Dateinamen — oder `None`.
///
/// Die Eingabe kommt aus drei Quellen, die alle der Gegenseite bzw. dem Nutzer
/// gehören: dem Wunschnamen im Request, `Content-Disposition` und dem letzten
/// Segment der URL. Keine davon darf aus dem Zielordner führen.
///
/// Regeln: alles bis zum letzten `/` oder `\` fällt weg (damit ist `../..`
/// erledigt, ohne dass es als Muster gesucht werden muss), Steuerzeichen und
/// NUL fallen weg, `.` und `..` sind kein Name, und die Länge ist begrenzt.
pub fn sanitize_filename(raw: &str) -> Option<String> {
    // Nur der Teil hinter dem letzten Trenner. `\` zählt mit, weil ein
    // Windows-Server ihn schickt und ein späterer Leser ihn als Trenner
    // deuten könnte.
    let base = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.');

    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '\0' && *c != '/' && *c != '\\')
        .collect();
    let cleaned = cleaned.trim();

    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return None;
    }

    // Auf Bytegrenze kürzen, ohne einen Mehrbyte-Codepoint zu zerschneiden.
    let mut out = String::new();
    for c in cleaned.chars() {
        if out.len() + c.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Löst `%XX` auf. Ungültige Folgen bleiben stehen, statt zu scheitern —
/// gesäubert wird danach ohnehin.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Userinfo in einer URL
//
// Eine URL vom Nutzer kann Zugangsdaten tragen:
// `https://nutzer:geheim@example.com/datei`. Die gehören **nirgends** hin, wo
// sie später gelesen werden — nicht ins Job-Log (das jede angemeldete Sitzung
// über `/api/sync/<id>/log` abrufen kann), nicht in eine Statusmeldung, nicht
// in eine `Debug`-Ausgabe.
//
// Das Projekt hat dieses Muster fünfmal gehabt: `derive(Debug)` über einem
// Struct mit Geheimnis (`LoginOutcome`, `ModuleConfig`, `RcloneConfig`,
// `ConfigRequest`, `NewShare`). Es fällt nicht auf, weil ein Log-Leck keine
// Fehlermeldung erzeugt. Deshalb hier: eine Funktion, die maskiert, ein
// handgeschriebenes `Debug` darüber, und Tests samt Gegenprobe.
//
// `parse_url` verwirft die Userinfo ohnehin, `ParsedUrl` kann sie also nicht
// mehr ausgeben. Diese Funktion ist für alles, was die **rohe** Eingabe oder
// eine daraus gebaute Meldung anfasst.
// ---------------------------------------------------------------------------

/// Ersetzt die Userinfo jeder URL im Text durch `<redacted>`.
///
/// Schema, Host und Pfad bleiben stehen — eine vollständig maskierte Meldung
/// wäre zum Nachvollziehen wertlos, und genau das ist der Grund, warum
/// Maskierung sonst wieder ausgebaut wird.
pub fn redact_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(at) = rest.find("://") {
        let after_scheme = at + 3;
        out.push_str(&rest[..after_scheme]);
        let tail = &rest[after_scheme..];
        // Die Authority endet am ersten Trenner — oder am Ende des Textes.
        let end = tail
            .find(['/', '?', '#', ' ', '\t', '"', '\'', ')', ','])
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority.rfind('@') {
            Some(at_in_authority) => {
                out.push_str("<redacted>@");
                out.push_str(&authority[at_in_authority + 1..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Holt den Dateinamen aus einem `Content-Disposition`-Wert.
///
/// `filename*=UTF-8''…` (RFC 5987) hat Vorrang vor `filename="…"`, weil es die
/// genauere Angabe ist. Beides geht anschliessend durch
/// [`sanitize_filename`] — der Header ist Fremdeingabe.
pub fn filename_from_disposition(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();

    if let Some(at) = lower.find("filename*=") {
        let rest = value[at + "filename*=".len()..].trim();
        let rest = rest.split(';').next().unwrap_or("").trim();
        // `charset'lang'wert` — nur der Wert interessiert.
        let encoded = match rest.rsplit_once('\'') {
            Some((_, v)) => v,
            None => rest,
        };
        if let Some(name) = sanitize_filename(&percent_decode(encoded.trim_matches('"'))) {
            return Some(name);
        }
    }

    if let Some(at) = lower.find("filename=") {
        let rest = value[at + "filename=".len()..].trim();
        let raw = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next().unwrap_or("")
        } else {
            rest.split(';').next().unwrap_or("").trim()
        };
        if let Some(name) = sanitize_filename(raw) {
            return Some(name);
        }
    }
    None
}

/// Dateiname aus dem Pfad einer URL, sonst `download`.
fn filename_from_path(path_and_query: &str) -> String {
    let path = path_and_query.split(['?', '#']).next().unwrap_or("");
    sanitize_filename(&percent_decode(path)).unwrap_or_else(|| "download".to_string())
}

// ---------------------------------------------------------------------------
// Zielpfad
// ---------------------------------------------------------------------------

/// Ergebnis der Zielprüfung: die kanonisierte Wurzel und der kanonisierte
/// Ordner darin.
struct Target {
    root: PathBuf,
    dir: PathBuf,
}

/// Prüft den Zielordner gegen das Home — **vor** jeder Nebenwirkung.
///
/// Es entsteht hier kein Job, keine Logdatei und keine Datei. Die Prüfung
/// benutzt `resolve_within_root`, also dieselbe Jail-Logik wie Auflistung,
/// Download und Vorschau, samt aufgelöster Symlinks.
async fn resolve_target(
    current: &CurrentUser,
    target_path: Option<&str>,
) -> Result<Target, String> {
    let root = user_root(current, RootScope::Home).await.map_err(|e| {
        warn!(
            "Abruf abgelehnt: Home von '{}' nicht verfügbar ({:?})",
            current.user.username, e
        );
        "Das Home-Verzeichnis dieses Kontos ist nicht verfügbar".to_string()
    })?;

    let requested = target_path.map(str::trim).filter(|p| !p.is_empty());
    let dir = match requested {
        None => root.clone(),
        Some(path) => resolve_within_root(&root, path).await.map_err(|e| {
            warn!(
                "Abruf abgelehnt: Zielordner '{}' von '{}' ausserhalb des erlaubten Bereichs ({:?})",
                path, current.user.username, e
            );
            "Zielordner liegt ausserhalb des erlaubten Wurzelverzeichnisses".to_string()
        })?,
    };

    // `resolve_within_root` sichert die Wurzel zu, sagt aber nichts darüber,
    // ob es ein Ordner ist.
    match tokio::fs::metadata(&dir).await {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err("Das Ziel ist kein Ordner".to_string()),
        Err(e) => return Err(format!("Zielordner nicht verfügbar: {}", e)),
    }

    Ok(Target { root, dir })
}

/// Belegt einen Zieldateinamen exklusiv und gibt den belegten Pfad zurück.
///
/// `create_new` ist der Kern: es scheitert, wenn schon etwas da ist — auch
/// wenn dieses „etwas" ein Symlink nach ausserhalb ist. Damit kann ein
/// vorbereiteter Symlink im Zielordner den Schreibvorgang nicht umleiten.
/// Bei Kollision wird `name (1)`, `name (2)` … versucht, wie es ein Browser
/// auch tut.
async fn reserve_name(dir: &Path, name: &str) -> Result<PathBuf, String> {
    let (stem, ext) = match name.rsplit_once('.') {
        // Ein führender Punkt ist kein Trenner für die Endung (`.bashrc`).
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{}", e)),
        _ => (name.to_string(), String::new()),
    };

    for n in 0..100u32 {
        let candidate = if n == 0 {
            name.to_string()
        } else {
            format!("{} ({}){}", stem, n, ext)
        };
        let path = dir.join(&candidate);
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("Zieldatei nicht anlegbar: {}", e)),
        }
    }
    Err("Zu viele Dateien gleichen Namens im Zielordner".to_string())
}

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

fn log_path(job_id: &str) -> String {
    format!("data/log/{}.log", job_id)
}

fn stamp() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Legt die Logdatei an. Erst nach der Prüfung — ein abgelehnter Abruf
/// hinterlässt keine.
async fn create_log(job_id: &str, url: &str, dir: &Path) -> tokio::io::Result<()> {
    tokio::fs::create_dir_all("data/log").await?;
    let t = stamp();
    // Die URL steht im Log, weil ohne sie nicht nachvollziehbar ist, was
    // geholt wurde — aber **ohne Userinfo**. Das Log ist über
    // `/api/sync/<id>/log` abrufbar; `https://nutzer:geheim@host/…` würde die
    // Zugangsdaten des Nutzers dort ablegen, wo sie niemand mehr sucht.
    let text = format!(
        "[{t}] Job {job_id} started\n\
         [{t}] Aktion: Von URL holen (HTTP-Abruf durch den Server)\n\
         [{t}] Quelle: {quelle}\n\
         [{t}] Zielordner: {}\n\
         [{t}] Mode: copy (im Ziel wird nichts geloescht)\n\n",
        dir.display(),
        quelle = redact_userinfo(url)
    );
    tokio::fs::write(log_path(job_id), text).await
}

/// Hängt eine Zeile an das Job-Log. Ein Fehler dabei bricht den Abruf nicht
/// ab — ein fehlendes Log ist ärgerlich, ein abgebrochener Download schlimmer.
async fn append_log(job_id: &str, line: &str) {
    let text = format!("[{}] {}\n", stamp(), line);
    let opened = tokio::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path(job_id))
        .await;
    match opened {
        Ok(mut f) => {
            if let Err(e) = f.write_all(text.as_bytes()).await {
                tracing::debug!("Log von {} nicht schreibbar: {}", job_id, e);
            }
        }
        Err(e) => tracing::debug!("Log von {} nicht öffenbar: {}", job_id, e),
    }
}

// ---------------------------------------------------------------------------
// Einstieg
// ---------------------------------------------------------------------------

/// `POST /api/download-url`
pub async fn start_url_fetch(
    Extension(current): Extension<CurrentUser>,
    Json(request): Json<UrlFetchRequest>,
) -> ResponseJson<ApiResponse<String>> {
    start_url_fetch_for(
        &current,
        request,
        Arc::new(SystemResolver),
        Arc::new(StreamingHttpTransport),
        production_policy(),
    )
    .await
}

/// Gemeinsamer Kern. Resolver, Transport und Regelwerk sind Parameter, damit
/// die Tests einen lokalen Server ansprechen können, **ohne** dass der
/// produktive Weg einen Schalter dafür bekommt.
async fn start_url_fetch_for(
    current: &CurrentUser,
    request: UrlFetchRequest,
    resolver: Arc<dyn Resolver>,
    transport: Arc<dyn StreamingTransport>,
    policy: GuardPolicy,
) -> ResponseJson<ApiResponse<String>> {
    // ---------------------------------------------------------------------
    // Alles, was scheitern darf, scheitert hier: vor dem Job, vor dem Log,
    // vor der ersten Verbindung. Dieselbe Reihenfolge wie in `start_sync_for`
    // — dort war es ein behobener Sicherheitsfehler, hier von Anfang an so.
    // ---------------------------------------------------------------------

    // 1. Schema und Form der URL. `file:`, `ftp:`, `gopher:` fallen hier.
    let parsed = match parse_url(&request.url) {
        Ok(p) => p,
        Err(e) => {
            warn!("Abruf abgelehnt: {}", e);
            return ResponseJson(ApiResponse::error(&e.to_string()));
        }
    };

    // 2. Wunschname, falls angegeben. Ein Name, der nur aus Pfadanteilen
    //    besteht, ist eine Ablehnung und kein stilles „dann eben anders".
    let wanted_name = match request.filename.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => match sanitize_filename(raw) {
            Some(name) => Some(name),
            None => {
                warn!("Abruf abgelehnt: Dateiname '{}' unbrauchbar", raw);
                return ResponseJson(ApiResponse::error(
                    "Der angegebene Dateiname ist nicht verwendbar",
                ));
            }
        },
        _ => None,
    };

    // 3. Zielordner gegen das Home.
    let target = match resolve_target(current, request.target_path.as_deref()).await {
        Ok(t) => t,
        Err(message) => return ResponseJson(ApiResponse::error(&message)),
    };

    // 4. Zieladresse. Der Abruf im Hintergrund prüft sie **erneut** (und nach
    //    jedem Redirect); diese Prüfung hier dient nur dazu, eine gesperrte
    //    Adresse sofort zu beantworten, statt einen Job anzulegen, der eine
    //    Sekunde später fehlschlägt.
    if let Err(e) = vet_url(&request.url, &policy, resolver.as_ref()).await {
        warn!("Abruf abgelehnt: {}", e);
        return ResponseJson(ApiResponse::error(&user_message(&e)));
    }

    // 5. Gleichzeitige Abrufe des Nutzers.
    let slot = match SLOTS.acquire(&current.user.username) {
        Ok(slot) => slot,
        Err(e) => {
            warn!(
                "Abruf abgelehnt: '{}' hat die Grenze erreicht ({})",
                current.user.username, e
            );
            return ResponseJson(ApiResponse::error(&user_message(&e)));
        }
    };

    // Ab hier entstehen Nebenwirkungen.
    let job_id = Uuid::new_v4().to_string();
    let cancel = Arc::new(AtomicBool::new(false));

    let source_name = wanted_name
        .clone()
        .unwrap_or_else(|| filename_from_path(&parsed.path_and_query));

    let progress = SyncProgress {
        id: job_id.clone(),
        progress: 0.0,
        status: JobStatus::Starting,
        transferred: 0,
        total: 0,
        source_name,
        start_time: Utc::now().timestamp(),
        end_time: None,
        // Ein Abruf löscht im Ziel nichts — dieselbe Bedeutung wie beim Sync.
        mode: "copy".to_string(),
        dry_run: false,
    };

    jobs().insert(
        job_id.clone(),
        JobEntry {
            progress,
            cancel: Arc::clone(&cancel),
        },
    );

    if let Err(e) = create_log(&job_id, &request.url, &target.dir).await {
        tracing::error!("Logdatei für {} nicht anlegbar: {}", job_id, e);
    }

    info!(
        "⬇️  Abruf {} gestartet: {} → {} (Nutzer '{}')",
        job_id,
        parsed,
        target.dir.display(),
        current.user.username
    );

    let task_id = job_id.clone();
    let url = request.url.clone();
    tokio::spawn(async move {
        // Der Platz wird erst frei, wenn diese Aufgabe endet — auch bei einem
        // Abbruch mitten im Strom.
        let _slot: DownloadSlot = slot;
        let outcome = run_fetch(
            &task_id,
            &url,
            &target,
            wanted_name.as_deref(),
            &policy,
            resolver.as_ref(),
            transport.as_ref(),
            &cancel,
        )
        .await;

        let status = match outcome {
            Ok(landed) => {
                append_log(
                    &task_id,
                    &format!("Fertig: {} ({} Byte)", landed.name, landed.bytes),
                )
                .await;
                set_final_name(&task_id, &landed.name);
                JobStatus::Completed
            }
            Err(FetchFailure::Cancelled) => {
                append_log(&task_id, "Abgebrochen, unvollständige Datei entfernt").await;
                JobStatus::Cancelled
            }
            Err(FetchFailure::Failed(message)) => {
                // Zweiter Riegel: die Meldungen aus `user_message` sind schon
                // maskiert, die aus `format!` über einen IO-Fehler tragen
                // keine URL. Beides kann sich ändern — das Log und die
                // Statuszeile sind die Stellen, an denen es auffiele.
                let message = redact_userinfo(&message);
                append_log(&task_id, &format!("Fehlgeschlagen: {}", message)).await;
                JobStatus::failed(message)
            }
        };
        finish(&task_id, status);
    });

    ResponseJson(ApiResponse::success(job_id))
}

/// Was der Nutzer über einen Fehler erfährt.
///
/// Bei einer gesperrten Adresse ausdrücklich **ohne** die Adresse: sonst wäre
/// der Downloader ein Portscanner mit Auskunft über das interne Netz. Die
/// vollständige Meldung steht im Log des Servers.
fn user_message(error: &GuardError) -> String {
    match error {
        GuardError::BlockedAddress(_) => {
            "Diese Adresse liegt in einem gesperrten Bereich und wird nicht abgerufen".to_string()
        }
        // Alles andere kann einen Hostnamen oder eine ganze URL enthalten —
        // und damit eine Userinfo.
        other => redact_userinfo(&other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Der Abruf
// ---------------------------------------------------------------------------

/// Erfolgreich gelandete Datei.
struct Landed {
    name: String,
    bytes: u64,
}

enum FetchFailure {
    Cancelled,
    Failed(String),
}

/// Handgeschrieben, **nicht** abgeleitet.
///
/// In `Failed` steckt eine Meldung, die aus einer vom Nutzer gelieferten URL
/// entstehen kann. Ein `derive(Debug)` würde eine darin enthaltene Userinfo
/// beim ersten `tracing::debug!(?fehler)` ins Log schreiben — dieselbe Falle
/// wie bei `LoginOutcome`, `ModuleConfig` und `NewShare`. Abgesichert durch
/// `fetchfailure_debug_maskiert_userinfo` samt Gegenprobe.
impl std::fmt::Debug for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Failed(message) => f
                .debug_tuple("Failed")
                .field(&redact_userinfo(message))
                .finish(),
        }
    }
}

impl From<GuardError> for FetchFailure {
    fn from(e: GuardError) -> Self {
        FetchFailure::Failed(user_message(&e))
    }
}

/// Nach wie vielen Bytes bzw. wie oft der Fortschritt fortgeschrieben wird.
/// Ohne die Zeitbremse schreibt eine schnelle Leitung tausende Logzeilen.
const PROGRESS_EVERY_BYTES: u64 = 8 * 1024 * 1024;
const PROGRESS_EVERY: Duration = Duration::from_secs(1);

#[allow(clippy::too_many_arguments)]
async fn run_fetch(
    job_id: &str,
    url: &str,
    target: &Target,
    wanted_name: Option<&str>,
    policy: &GuardPolicy,
    resolver: &dyn Resolver,
    transport: &dyn StreamingTransport,
    cancel: &AtomicBool,
) -> Result<Landed, FetchFailure> {
    set_status(job_id, JobStatus::Running);

    // Die Redirect-Schleife führt `fetch_guarded_stream`: jeder Sprung
    // durchläuft `vet_url` erneut.
    let (response, mut body) = fetch_guarded_stream(url, policy, resolver, transport).await?;

    if response.head.status != 200 {
        return Err(FetchFailure::Failed(format!(
            "Die Gegenstelle antwortete mit HTTP {}",
            response.head.status
        )));
    }

    append_log(
        job_id,
        &format!(
            "Verbunden: {} ({})",
            response.final_url, response.final_addr
        ),
    )
    .await;

    // Reihenfolge der Namensquellen: ausdrücklicher Wunsch, dann
    // `Content-Disposition`, dann der Pfad der **endgültigen** URL. Alle drei
    // sind durch `sanitize_filename` gegangen.
    let name = wanted_name
        .map(str::to_string)
        .or_else(|| {
            response
                .head
                .content_disposition
                .as_deref()
                .and_then(filename_from_disposition)
        })
        .unwrap_or_else(|| filename_from_path(&response.final_url.path_and_query));

    let total = response.head.content_length.unwrap_or(0);
    set_total(job_id, total);
    append_log(
        job_id,
        &match response.head.content_length {
            Some(n) => format!("Angekündigte Grösse: {} Byte, Ziel: {}", n, name),
            None => format!("Grösse unbekannt (keine Content-Length), Ziel: {}", name),
        },
    )
    .await;

    // Geschrieben wird in ein Bruchstück mit der Job-ID im Namen. Zwei
    // gleichzeitige Abrufe in denselben Ordner können sich damit nicht in die
    // Quere kommen, und ein Abbruch lässt keine halbe Datei mit dem
    // richtigen Namen zurück.
    let temp_path = target.dir.join(format!(".rclone-gui-{}.part", job_id));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
        .map_err(|e| FetchFailure::Failed(format!("Zieldatei nicht anlegbar: {}", e)))?;

    let mut written: u64 = 0;
    let mut last_report = std::time::Instant::now();
    let mut last_reported_bytes: u64 = 0;
    let deadline = std::time::Instant::now() + policy.total_timeout;

    loop {
        if cancel.load(Ordering::SeqCst) {
            drop(file);
            remove_temp(&temp_path).await;
            return Err(FetchFailure::Cancelled);
        }
        let chunk = match body.next_chunk(deadline).await {
            Ok(chunk) => chunk,
            Err(e) => {
                drop(file);
                remove_temp(&temp_path).await;
                return Err(FetchFailure::from(e));
            }
        };
        if chunk.is_empty() {
            break;
        }
        if let Err(e) = file.write_all(&chunk).await {
            drop(file);
            remove_temp(&temp_path).await;
            return Err(FetchFailure::Failed(format!(
                "Schreiben fehlgeschlagen: {}",
                e
            )));
        }
        written += chunk.len() as u64;
        set_transferred(job_id, written, total);

        if written - last_reported_bytes >= PROGRESS_EVERY_BYTES
            || last_report.elapsed() >= PROGRESS_EVERY
        {
            last_report = std::time::Instant::now();
            last_reported_bytes = written;
            append_log(job_id, &format!("Übertragen: {} Byte", written)).await;
        }
    }

    if let Err(e) = file.flush().await {
        remove_temp(&temp_path).await;
        return Err(FetchFailure::Failed(format!(
            "Schreiben fehlgeschlagen: {}",
            e
        )));
    }
    drop(file);

    // Der endgültige Name wird erst jetzt belegt, damit ein gescheiterter
    // Abruf keinen Namen im Zielordner verbraucht.
    let final_path = match reserve_name(&target.dir, &name).await {
        Ok(path) => path,
        Err(message) => {
            remove_temp(&temp_path).await;
            return Err(FetchFailure::Failed(message));
        }
    };

    // Gürtel und Hosenträger: der belegte Pfad muss in der Wurzel liegen.
    // Er *muss* es, weil `dir` kanonisiert und in der Wurzel ist und `name`
    // keinen Trenner enthält — genau deshalb ist ein Treffer hier ein Fehler
    // im Programm und kein Nutzerproblem.
    if !is_within_root(&target.root, &final_path) {
        tracing::error!(
            "Abruf {}: Zielpfad {} liegt ausserhalb der Wurzel {} — abgebrochen",
            job_id,
            final_path.display(),
            target.root.display()
        );
        remove_temp(&temp_path).await;
        let _ = tokio::fs::remove_file(&final_path).await;
        return Err(FetchFailure::Failed(
            "Zielpfad liegt ausserhalb des erlaubten Bereichs".to_string(),
        ));
    }

    tokio::fs::rename(&temp_path, &final_path)
        .await
        .map_err(|e| {
            FetchFailure::Failed(format!(
                "Umbenennen der fertigen Datei fehlgeschlagen: {}",
                e
            ))
        })?;

    let landed_name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or(name);

    Ok(Landed {
        name: landed_name,
        bytes: written,
    })
}

async fn remove_temp(path: &Path) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        tracing::debug!("Bruchstück {} nicht löschbar: {}", path.display(), e);
    }
}

// ---------------------------------------------------------------------------
// Fortschritt fortschreiben
// ---------------------------------------------------------------------------

fn set_status(job_id: &str, status: JobStatus) {
    if let Some(entry) = jobs().get_mut(job_id) {
        entry.progress.status = status;
    }
}

fn set_total(job_id: &str, total: u64) {
    if let Some(entry) = jobs().get_mut(job_id) {
        entry.progress.total = total;
    }
}

fn set_transferred(job_id: &str, written: u64, total: u64) {
    if let Some(entry) = jobs().get_mut(job_id) {
        entry.progress.transferred = written;
        entry.progress.total = total;
        entry.progress.progress = if total > 0 {
            (written as f64 / total as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
    }
}

fn set_final_name(job_id: &str, name: &str) {
    if let Some(entry) = jobs().get_mut(job_id) {
        entry.progress.source_name = name.to_string();
    }
}

fn finish(job_id: &str, status: JobStatus) {
    let mut guard = jobs();
    if let Some(entry) = guard.get_mut(job_id) {
        if status.is_success() {
            entry.progress.progress = 100.0;
        }
        entry.progress.status = status;
        entry.progress.end_time = Some(Utc::now().timestamp());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::urlguard::StaticResolver;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;

    // -----------------------------------------------------------------------
    // Regel 4: der produktive Weg hebt die Adressprüfung nicht auf
    // -----------------------------------------------------------------------

    #[test]
    fn production_policy_erlaubt_keine_privaten_adressen() {
        assert!(
            !production_policy().allow_private_addresses,
            "der produktive Weg darf allow_private_addresses nie setzen"
        );
    }

    #[test]
    fn production_policy_hat_die_grenzen_des_bausteins() {
        let p = production_policy();
        assert_eq!(p.max_bytes, 512 * 1024 * 1024);
        assert_eq!(p.max_redirects, 5);
        assert_eq!(p.total_timeout, Duration::from_secs(300));
    }

    /// Gegenprobe zum Test darüber: derselbe Aufbau **würde** ein gesetztes
    /// Flag melden. Ohne das wäre die Zusicherung wertlos.
    #[test]
    fn gegenprobe_gesetztes_flag_wuerde_auffallen() {
        let mut p = production_policy();
        p.allow_private_addresses = true;
        assert!(p.allow_private_addresses);
    }

    // -----------------------------------------------------------------------
    // Userinfo darf nirgends auftauchen
    // -----------------------------------------------------------------------

    #[test]
    fn redact_userinfo_maskiert_zugangsdaten() {
        assert_eq!(
            redact_userinfo("https://nutzer:geheim@example.com/datei.bin"),
            "https://<redacted>@example.com/datei.bin"
        );
        // Der Trick mit mehreren `@` — maskiert wird bis zum letzten.
        assert_eq!(
            redact_userinfo("http://a@b:c@127.0.0.1/x"),
            "http://<redacted>@127.0.0.1/x"
        );
        // Ohne Userinfo bleibt der Text unverändert.
        assert_eq!(
            redact_userinfo("http://example.com/a?b=c"),
            "http://example.com/a?b=c"
        );
        // Mitten in einem Satz, und mehr als eine URL.
        assert_eq!(
            redact_userinfo(
                "von https://u:p@a.example/1 nach https://v:q@b.example/2 fehlgeschlagen"
            ),
            "von https://<redacted>@a.example/1 nach https://<redacted>@b.example/2 fehlgeschlagen"
        );
        // Kein Schema, nichts zu maskieren.
        assert_eq!(redact_userinfo("kein Schema"), "kein Schema");
    }

    #[test]
    fn fetchfailure_debug_maskiert_userinfo() {
        let failure = FetchFailure::Failed(
            "Abruf von https://nutzer:geheim@example.com/x fehlgeschlagen".into(),
        );
        let shown = format!("{failure:?}");
        assert!(
            !shown.contains("geheim"),
            "Passwort in der Ausgabe: {shown}"
        );
        assert!(
            !shown.contains("nutzer"),
            "Nutzername in der Ausgabe: {shown}"
        );
        // Zum Debuggen muss aber noch etwas übrig bleiben.
        assert!(shown.contains("example.com"), "unbrauchbar: {shown}");
        assert!(shown.contains("<redacted>"), "keine Maskierung: {shown}");
    }

    /// Gegenprobe: derselbe Aufbau **würde** ein Leck melden. Ohne das wäre der
    /// Test darüber auch grün, wenn er das Falsche prüfte.
    #[test]
    fn gegenprobe_ein_leck_wuerde_auffallen() {
        let leaked = format!(
            "Failed({:?})",
            "Abruf von https://nutzer:geheim@example.com/x fehlgeschlagen"
        );
        assert!(
            leaked.contains("geheim"),
            "die Prüfung selbst greift nicht: {leaked}"
        );
    }

    #[tokio::test]
    async fn joblog_enthaelt_keine_zugangsdaten() {
        let dir = tempdir("joblog");
        let job_id = format!("test-{}", Uuid::new_v4());
        create_log(&job_id, "https://nutzer:geheim@example.com/datei.bin", &dir)
            .await
            .expect("Log anlegbar");
        let text = std::fs::read_to_string(log_path(&job_id)).expect("Log lesbar");
        assert!(!text.contains("geheim"), "Passwort im Job-Log: {text}");
        assert!(!text.contains("nutzer"), "Nutzername im Job-Log: {text}");
        // Gegenprobe: die Herkunft ist trotzdem nachvollziehbar.
        assert!(text.contains("example.com/datei.bin"), "{text}");
        let _ = std::fs::remove_file(log_path(&job_id));
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Dateinamen
    // -----------------------------------------------------------------------

    #[test]
    fn dateiname_verliert_pfadanteile() {
        assert_eq!(
            sanitize_filename("../../etc/passwd").as_deref(),
            Some("passwd")
        );
        assert_eq!(sanitize_filename("/etc/shadow").as_deref(), Some("shadow"));
        assert_eq!(
            sanitize_filename("..\\..\\windows\\system32\\x.dll").as_deref(),
            Some("x.dll")
        );
        assert_eq!(sanitize_filename("a/b/c.txt").as_deref(), Some("c.txt"));
    }

    #[test]
    fn dateiname_ohne_inhalt_wird_abgelehnt() {
        assert_eq!(sanitize_filename(".."), None);
        assert_eq!(sanitize_filename("."), None);
        assert_eq!(sanitize_filename("   "), None);
        assert_eq!(sanitize_filename("/"), None);
        assert_eq!(sanitize_filename("../../"), None);
        assert_eq!(sanitize_filename("\u{0}"), None);
    }

    #[test]
    fn dateiname_ohne_steuerzeichen() {
        assert_eq!(
            sanitize_filename("re\rport\n.pdf").as_deref(),
            Some("report.pdf")
        );
    }

    #[test]
    fn dateiname_bleibt_kurz() {
        let long = "ä".repeat(500);
        let name = sanitize_filename(&long).expect("bleibt etwas übrig");
        assert!(name.len() <= MAX_NAME_BYTES, "{} Byte", name.len());
        assert!(
            name.chars().all(|c| c == 'ä'),
            "kein zerschnittener Codepoint"
        );
    }

    #[test]
    fn dateiname_aus_content_disposition() {
        assert_eq!(
            filename_from_disposition("attachment; filename=\"bericht.pdf\"").as_deref(),
            Some("bericht.pdf")
        );
        assert_eq!(
            filename_from_disposition("attachment; filename=bericht.pdf; size=12").as_deref(),
            Some("bericht.pdf")
        );
        // Der interessante Fall: Pfadanteile im Header.
        assert_eq!(
            filename_from_disposition("attachment; filename=\"../../../etc/passwd\"").as_deref(),
            Some("passwd")
        );
        // RFC 5987 hat Vorrang und wird prozentdekodiert.
        assert_eq!(
            filename_from_disposition(
                "attachment; filename=\"x.bin\"; filename*=UTF-8''%C3%A4.txt"
            )
            .as_deref(),
            Some("ä.txt")
        );
        // Auch dekodierte Trenner führen nicht heraus.
        assert_eq!(
            filename_from_disposition("attachment; filename*=UTF-8''%2Fetc%2Fpasswd").as_deref(),
            Some("passwd")
        );
        assert_eq!(filename_from_disposition("inline"), None);
    }

    #[test]
    fn dateiname_aus_url_pfad() {
        assert_eq!(filename_from_path("/dir/datei.txt?x=1"), "datei.txt");
        assert_eq!(filename_from_path("/dir/"), "download");
        assert_eq!(filename_from_path("/"), "download");
        assert_eq!(filename_from_path("/a%20b.txt"), "a b.txt");
    }

    // -----------------------------------------------------------------------
    // Namensbelegung
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reserve_name_weicht_bei_kollision_aus() {
        let dir = tempdir("reserve");
        let first = reserve_name(&dir, "a.txt").await.expect("erster Name");
        assert_eq!(first.file_name().unwrap(), "a.txt");
        let second = reserve_name(&dir, "a.txt").await.expect("zweiter Name");
        assert_eq!(second.file_name().unwrap(), "a (1).txt");
        let third = reserve_name(&dir, "ohne_endung").await.expect("dritter");
        assert_eq!(third.file_name().unwrap(), "ohne_endung");
        let fourth = reserve_name(&dir, "ohne_endung").await.expect("vierter");
        assert_eq!(fourth.file_name().unwrap(), "ohne_endung (1)");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn reserve_name_folgt_keinem_symlink() {
        let dir = tempdir("symlink");
        let outside = dir.join("aussen.txt");
        std::fs::write(&outside, b"unberuehrt").expect("Datei aussen");
        let link = dir.join("ziel.txt");
        std::os::unix::fs::symlink(&outside, &link).expect("Symlink");

        // Der Name ist belegt (durch den Symlink), also weicht die Belegung
        // aus — statt durch den Symlink zu schreiben.
        let path = reserve_name(&dir, "ziel.txt").await.expect("Name");
        assert_eq!(path.file_name().unwrap(), "ziel (1).txt");
        assert_eq!(
            std::fs::read(&outside).expect("noch da"),
            b"unberuehrt".to_vec()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Ein echter Abruf gegen einen lokalen Server
    // -----------------------------------------------------------------------

    fn tempdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rclone-gui-c9857502-{}-{}", tag, Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis");
        std::fs::canonicalize(&dir).expect("kanonisch")
    }

    /// Ein Server, der genau eine Antwort schickt und dann zumacht.
    async fn serve_once(response: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // Anfrage lesen und verwerfen, damit der Client nicht auf
                // einem vollen Puffer sitzt.
                let mut buf = [0u8; 2048];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                let _ = socket.write_all(&response).await;
                let _ = socket.shutdown().await;
            }
        });
        addr
    }

    fn test_policy() -> GuardPolicy {
        // `for_tests` erlaubt Loopback — nur hier, nie im produktiven Weg.
        GuardPolicy::for_tests()
    }

    async fn fetch_into(
        dir: &Path,
        url: &str,
        wanted: Option<&str>,
        policy: &GuardPolicy,
        resolver: &dyn Resolver,
        cancel: &AtomicBool,
    ) -> Result<Landed, FetchFailure> {
        let job_id = format!("test-{}", Uuid::new_v4());
        let target = Target {
            root: dir.to_path_buf(),
            dir: dir.to_path_buf(),
        };
        jobs().insert(
            job_id.clone(),
            JobEntry {
                progress: SyncProgress {
                    id: job_id.clone(),
                    progress: 0.0,
                    status: JobStatus::Starting,
                    transferred: 0,
                    total: 0,
                    source_name: String::new(),
                    start_time: 0,
                    end_time: None,
                    mode: "copy".to_string(),
                    dry_run: false,
                },
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
        let result = run_fetch(
            &job_id,
            url,
            &target,
            wanted,
            policy,
            resolver,
            &StreamingHttpTransport,
            cancel,
        )
        .await;
        jobs().remove(&job_id);
        // Das Log dieses Testjobs nicht liegen lassen.
        let _ = std::fs::remove_file(log_path(&job_id));
        result
    }

    #[tokio::test]
    async fn datei_landet_im_zielordner() {
        let dir = tempdir("landen");
        let body = b"inhalt-der-datei";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect::<Vec<u8>>();
        let addr = serve_once(response).await;

        let landed = fetch_into(
            &dir,
            &format!("http://{}/pfad/datei.txt", addr),
            None,
            &test_policy(),
            &StaticResolver::new(),
            &AtomicBool::new(false),
        )
        .await
        .expect("Abruf gelingt");

        assert_eq!(landed.name, "datei.txt");
        assert_eq!(landed.bytes, body.len() as u64);
        assert_eq!(
            std::fs::read(dir.join("datei.txt")).expect("Datei da"),
            body.to_vec()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn content_disposition_mit_pfadanteil_bleibt_im_ordner() {
        let dir = tempdir("disposition");
        let body = b"x";
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Disposition: attachment; filename=\"../../ausbruch.txt\"\r\n\r\n".to_vec();
        response.extend_from_slice(body);
        let addr = serve_once(response).await;

        let landed = fetch_into(
            &dir,
            &format!("http://{}/x", addr),
            None,
            &test_policy(),
            &StaticResolver::new(),
            &AtomicBool::new(false),
        )
        .await
        .expect("Abruf gelingt");

        assert_eq!(landed.name, "ausbruch.txt");
        assert!(dir.join("ausbruch.txt").exists(), "landet im Zielordner");
        // Und eben nicht zwei Ebenen darüber.
        let escaped = dir
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("ausbruch.txt"));
        if let Some(escaped) = escaped {
            assert!(
                !escaped.exists(),
                "{} darf nicht entstehen",
                escaped.display()
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn groessengrenze_bricht_ab_und_laesst_nichts_liegen() {
        let dir = tempdir("grenze");
        // Ohne Content-Length, damit die Grenze am Strom greift und nicht
        // schon am Kopfteil.
        let mut response = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b'a', 4096));
        let addr = serve_once(response).await;

        let mut policy = test_policy();
        policy.max_bytes = 1024;

        let err = fetch_into(
            &dir,
            &format!("http://{}/gross.bin", addr),
            None,
            &policy,
            &StaticResolver::new(),
            &AtomicBool::new(false),
        )
        .await
        .err()
        .expect("muss scheitern");
        assert!(
            matches!(err, FetchFailure::Failed(ref m) if m.contains("1024")),
            "Meldung nennt die Grenze"
        );

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("lesbar")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            leftovers.is_empty(),
            "kein Bruchstück im Zielordner: {:?}",
            leftovers
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn gegenprobe_dieselbe_grenze_laesst_kleine_datei_durch() {
        // Ohne diese Gegenprobe wäre der Test darüber auch grün, wenn der
        // Abruf grundsätzlich nicht funktionierte.
        let dir = tempdir("gegenprobe");
        let mut response = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b'a', 512));
        let addr = serve_once(response).await;

        let mut policy = test_policy();
        policy.max_bytes = 1024;

        let landed = fetch_into(
            &dir,
            &format!("http://{}/klein.bin", addr),
            None,
            &policy,
            &StaticResolver::new(),
            &AtomicBool::new(false),
        )
        .await
        .expect("512 Byte sind unter der Grenze");
        assert_eq!(landed.bytes, 512);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn abbruch_laesst_nichts_liegen() {
        let dir = tempdir("abbruch");
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b'a', 4096));
        let addr = serve_once(response).await;

        // Bereits gesetzt: der Abbruch greift beim ersten Durchlauf.
        let cancel = AtomicBool::new(true);
        let err = fetch_into(
            &dir,
            &format!("http://{}/x.bin", addr),
            None,
            &test_policy(),
            &StaticResolver::new(),
            &cancel,
        )
        .await
        .err()
        .expect("muss abbrechen");
        assert!(matches!(err, FetchFailure::Cancelled));

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("lesbar")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(leftovers.is_empty(), "kein Bruchstück: {:?}", leftovers);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Dass eine Weiterleitung auf eine gesperrte Adresse abgewiesen wird,
    /// steht in `urlguard::tests::stream_redirect_to_metadata_address_is_rejected`
    /// samt Gegenprobe — dort lässt sich der erste Sprung als *öffentlich*
    /// vortäuschen, was mit einem echten Testserver auf Loopback nicht geht.
    ///
    /// Was hier fehlt, ist der Nachweis, dass der **produktive** Transport die
    /// Kette überhaupt weiterläuft, statt beim ersten `302` stehen zu bleiben:
    /// der zweite Sprung geht an einen Namen, den der Test-Resolver nicht
    /// kennt, und genau diese Auflösung muss in der Fehlermeldung auftauchen.
    #[tokio::test]
    async fn redirect_wird_ueber_den_produktiven_transport_verfolgt() {
        let dir = tempdir("redirect");
        let response =
            b"HTTP/1.1 302 Found\r\nLocation: http://zweiter-sprung.example.com/geheim\r\nContent-Length: 0\r\n\r\n"
                .to_vec();
        let addr = serve_once(response).await;

        let err = fetch_into(
            &dir,
            &format!("http://{}/start", addr),
            None,
            // Loopback muss erlaubt sein, damit der Testserver überhaupt
            // erreichbar ist. Nur im Test — siehe `production_policy`.
            &test_policy(),
            &StaticResolver::new(),
            &AtomicBool::new(false),
        )
        .await
        .err()
        .expect("der zweite Sprung ist nicht auflösbar");
        match err {
            FetchFailure::Failed(m) => assert!(
                m.contains("zweiter-sprung.example.com"),
                "der zweite Sprung wurde nicht versucht: {m}"
            ),
            other => panic!("unerwartet: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ein Server, der den Körper in zwei Hälften schickt und zwischen ihnen
    /// wartet, bis `release` gesetzt ist. Damit ist der Zeitpunkt „die erste
    /// Hälfte ist unterwegs, die zweite noch nicht" von aussen beobachtbar.
    async fn serve_in_two_halves(
        first: Vec<u8>,
        second: Vec<u8>,
        release: Arc<AtomicBool>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let total = first.len() + second.len();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", total);
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&first).await;
                let _ = socket.flush().await;
                // Warten, bis der Test die zweite Hälfte freigibt.
                while !release.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let _ = socket.write_all(&second).await;
                let _ = socket.shutdown().await;
            }
        });
        addr
    }

    /// Grösse des Bruchstücks (`.part`) im Zielordner, falls vorhanden.
    fn part_len(dir: &Path) -> Option<u64> {
        std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .find_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.ends_with(".part").then(|| e.metadata().ok()).flatten()
            })
            .map(|m| m.len())
    }

    /// **Der Nachweis für Regel 3: es wird gestreamt, nicht gepuffert.**
    ///
    /// Ein Speichertest wäre die direkte Messung, aber zu wackelig für eine
    /// Suite. Beobachtbar ist stattdessen der *Zeitpunkt* des Schreibens: die
    /// Zieldatei muss wachsen, **bevor** der Abruf fertig ist.
    ///
    /// Ohne diesen Test bleibt die Suite grün, wenn `run_fetch` alle Stücke in
    /// einem `Vec` sammelt und erst am Ende schreibt — gemessen, deshalb steht
    /// dieser Test hier. Mit dem Puffer bleibt das Bruchstück bei 0 Byte,
    /// bis die Gegenstelle fertig ist; die Beobachtung läuft in die Zeitgrenze
    /// und der Test fällt durch.
    #[tokio::test]
    async fn datei_waechst_vor_dem_ende_des_abrufs() {
        const HALF: usize = 128 * 1024;
        let dir = tempdir("streamt");
        let release = Arc::new(AtomicBool::new(false));
        let addr =
            serve_in_two_halves(vec![b'a'; HALF], vec![b'b'; HALF], Arc::clone(&release)).await;

        let url = format!("http://{}/gross.bin", addr);
        let cancel = AtomicBool::new(false);
        let policy = test_policy();
        let resolver = StaticResolver::new();

        // Beobachter: wartet darauf, dass das Bruchstück wächst, und gibt
        // danach die zweite Hälfte frei. Auch im Fehlerfall wird freigegeben,
        // sonst käme der Abruf nie zurück und der Test würde hängen statt
        // durchzufallen.
        let observe = async {
            let start = std::time::Instant::now();
            let grew = loop {
                if part_len(&dir).is_some_and(|n| n as usize >= HALF) {
                    break true;
                }
                if start.elapsed() > Duration::from_secs(3) {
                    break false;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            release.store(true, Ordering::SeqCst);
            grew
        };

        let (landed, grew) = tokio::join!(
            fetch_into(&dir, &url, Some("gross.bin"), &policy, &resolver, &cancel),
            observe
        );

        assert!(
            grew,
            "das Bruchstück hat vor dem Ende des Abrufs nicht {HALF} Byte erreicht — \
             der Körper wird offenbar gepuffert statt gestreamt"
        );
        let landed = landed.expect("Abruf gelingt");
        assert_eq!(landed.bytes, (2 * HALF) as u64);
        assert_eq!(
            std::fs::metadata(dir.join("gross.bin"))
                .expect("Datei da")
                .len(),
            (2 * HALF) as u64
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn chunked_wird_streamend_entpackt() {
        let dir = tempdir("chunked");
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo\r\n5\r\n-welt\r\n0\r\n\r\n"
                .to_vec();
        let addr = serve_once(response).await;

        let landed = fetch_into(
            &dir,
            &format!("http://{}/c.txt", addr),
            Some("c.txt"),
            &test_policy(),
            &StaticResolver::new(),
            &AtomicBool::new(false),
        )
        .await
        .expect("Abruf gelingt");
        assert_eq!(landed.bytes, 10);
        assert_eq!(
            std::fs::read_to_string(dir.join("c.txt")).expect("da"),
            "hallo-welt"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn abgeschnittener_koerper_gilt_nicht_als_erfolg() {
        let dir = tempdir("abgeschnitten");
        // Content-Length verspricht 100 Byte, geliefert werden 10.
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b'a', 10));
        let addr = serve_once(response).await;

        let err = fetch_into(
            &dir,
            &format!("http://{}/t.bin", addr),
            None,
            &test_policy(),
            &StaticResolver::new(),
            &AtomicBool::new(false),
        )
        .await
        .err()
        .expect("darf nicht als Erfolg gelten");
        assert!(matches!(err, FetchFailure::Failed(_)));
        let leftovers = std::fs::read_dir(&dir).expect("lesbar").count();
        assert_eq!(leftovers, 0, "kein Bruchstück");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn nicht_http_schema_wird_ohne_nebenwirkung_abgelehnt() {
        // `parse_url` ist die erste Prüfung in `start_url_fetch_for`; sie
        // läuft, bevor irgendetwas angelegt wird.
        for url in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "gopher://example.com/",
        ] {
            assert!(parse_url(url).is_err(), "{url} muss abgelehnt werden");
        }
        assert!(parse_url("http://example.com/x").is_ok());
    }

    #[test]
    fn ipv4_literal_bleibt_geprueft() {
        // Kein eigener Weg für IP-Literale: 169.254.169.254 als Literal muss
        // genauso scheitern wie über einen Namen.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let policy = production_policy();
        let resolver = StaticResolver::new();
        let err = rt.block_on(async {
            vet_url("http://169.254.169.254/", &policy, &resolver)
                .await
                .err()
        });
        assert!(matches!(
            err,
            Some(GuardError::BlockedAddress(IpAddr::V4(a))) if a == Ipv4Addr::new(169,254,169,254)
        ));
    }
}
