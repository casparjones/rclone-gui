//! Download-Endpunkte: Einzeldatei als Stream, Ordner/Mehrfachauswahl als
//! streamend erzeugtes ZIP.
//!
//! Beide Wege puffern die Nutzdaten weder im RAM noch auf der Platte. Die
//! Einzeldatei wird über einen `ReaderStream` direkt auf den Response-Body
//! geschoben. Das ZIP läuft über einen `tokio::io::duplex`-Kanal: ein
//! Blocking-Task schreibt das Archiv Eintrag für Eintrag in die eine Hälfte,
//! der Response-Body liest aus der anderen. Ist der Puffer voll, blockiert der
//! Schreiber, bis der Client weitergelesen hat. Der Speicherverbrauch bleibt
//! damit unabhängig von der Grösse des Ordners konstant (`DUPLEX_BUFFER`).
//!
//! Für das Archiv wird das `zip`-Crate mit `ZipWriter::new_stream` verwendet.
//! Es schreibt ohne `Seek` nach vorne durch (Data Descriptor hinter den Daten)
//! und schaltet ZIP64 nur ein, wenn es gebraucht wird. Die zunächst geprüfte
//! Alternative `async_zip` wurde aus Reifegründen nicht genommen; die früher
//! hier notierte Begründung („schreibt ZIP64-Platzhalter `0xFFFFFFFF` in den
//! lokalen Header, `unzip` lehnt das ab") trägt nicht: dieselben Platzhalter
//! schreibt auch `zip` bei Einträgen über 4 GB, und Info-ZIP `unzip`
//! akzeptiert solche Archive anstandslos.

use axum::{
    body::Body,
    extract::Query,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json as ResponseJson, Response},
};
use std::collections::HashSet;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use tokio_util::io::{ReaderStream, SyncIoBridge};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime as ZipDateTime, ZipWriter};

use crate::models::ApiResponse;

/// Puffer zwischen ZIP-Schreiber und Response-Body. Begrenzt den Speicher, den
/// ein laufender ZIP-Download belegt.
const DUPLEX_BUFFER: usize = 64 * 1024;

/// Lesepuffer beim Kopieren einer Datei in das Archiv bzw. auf den Body.
const COPY_BUFFER: usize = 64 * 1024;

/// Ab dieser Grösse braucht ein Eintrag zwingend ZIP64-Felder.
const ZIP64_THRESHOLD: u64 = u32::MAX as u64;

/// Fehler, die vor dem Beginn des Streams auftreten können. Sobald der Body
/// läuft, lässt sich der Status nicht mehr ändern – ab da wird nur noch geloggt.
#[derive(Debug)]
pub struct DownloadError {
    status: StatusCode,
    message: String,
}

impl DownloadError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for DownloadError {
    fn into_response(self) -> Response {
        tracing::warn!("Download abgelehnt ({}): {}", self.status, self.message);
        (
            self.status,
            ResponseJson(ApiResponse::<String>::error(&self.message)),
        )
            .into_response()
    }
}

/// Erlaubter Wurzelpfad für alle Downloads.
fn configured_root() -> String {
    std::env::var("RCLONE_GUI_DEFAULT_PATH").unwrap_or_else(|_| "/mnt/home".to_string())
}

/// Kanonisiert den Wurzelpfad. Existiert er nicht, ist kein Download möglich.
pub(crate) async fn download_root() -> Result<PathBuf, DownloadError> {
    let root = configured_root();
    tokio::fs::canonicalize(&root).await.map_err(|e| {
        DownloadError::internal(format!(
            "Wurzelverzeichnis '{}' nicht verfügbar: {}",
            root, e
        ))
    })
}

/// Löst `.` und `..` rein lexikalisch auf, ohne das Dateisystem zu befragen.
///
/// `..` hebt genau ein vorangehendes normales Segment auf. Läuft es über eine
/// absolute Wurzel hinaus, wird es verworfen (`/..` bleibt `/`); bei einem
/// relativen Pfad bleibt es als führendes `..` stehen, damit ein solcher Pfad
/// den `starts_with`-Test gegen die absolute Wurzel niemals besteht.
/// Mehrfache Trenner und `.`-Segmente entfernt `Path::components` bereits.
///
/// Das ist **keine** Sicherheitsprüfung – Symlinks sieht diese Funktion nicht.
/// Sie dient allein dazu, einen Ausbruchsversuch von einem schlicht nicht
/// existierenden Pfad zu unterscheiden.
fn lexically_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let pops_segment =
                    matches!(out.components().next_back(), Some(Component::Normal(_)));
                if pops_segment {
                    out.pop();
                } else if !out.has_root() {
                    // Relativer Pfad: führendes `..` bleibt erhalten.
                    out.push(Component::ParentDir.as_os_str());
                }
                // Absolute Wurzel: `..` verpufft, wie im Dateisystem auch.
            }
            Component::Normal(part) => out.push(part),
        }
    }

    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// Löst einen vom Client gelieferten Pfad auf und stellt sicher, dass er
/// – inklusive aufgelöster Symlinks – unterhalb von `root` liegt.
///
/// Relative Pfade werden gegen `root` aufgelöst, absolute Pfade unverändert
/// übernommen und anschliessend geprüft. `..` verschwindet durch die
/// Kanonisierung, ein Ausbruch fällt beim `starts_with`-Test auf.
///
/// Massgeblich für die Zugriffsentscheidung bleibt ausschliesslich der
/// kanonisierte Pfad – nur er hat Symlinks aufgelöst. Scheitert die
/// Kanonisierung (der Pfad existiert nicht), entscheidet zusätzlich die
/// lexikalische Normalisierung über den *Statuscode*: zeigt der Pfad schon rein
/// syntaktisch aus der Wurzel heraus, ist das ein Ausbruchsversuch (403);
/// bleibt er innerhalb, existiert er schlicht nicht (404).
pub(crate) async fn resolve_within_root(
    root: &Path,
    candidate: &str,
) -> Result<PathBuf, DownloadError> {
    if candidate.trim().is_empty() {
        return Err(DownloadError::bad_request("Pfad darf nicht leer sein"));
    }
    if candidate.contains('\0') {
        return Err(DownloadError::bad_request("Pfad enthält ungültige Zeichen"));
    }

    let raw = PathBuf::from(candidate);
    let joined = if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    };

    let outside =
        DownloadError::forbidden("Pfad liegt ausserhalb des erlaubten Wurzelverzeichnisses");

    let resolved = match tokio::fs::canonicalize(&joined).await {
        Ok(resolved) => resolved,
        Err(_) => {
            if !lexically_normalize(&joined).starts_with(root) {
                return Err(outside);
            }
            return Err(DownloadError::not_found(format!(
                "Pfad nicht gefunden: {}",
                candidate
            )));
        }
    };

    if !resolved.starts_with(root) {
        return Err(outside);
    }

    Ok(resolved)
}

/// Jail-Prüfung für bereits kanonisierte Pfade.
pub(crate) fn is_within_root(root: &Path, path: &Path) -> bool {
    path.starts_with(root)
}

/// Letztes Pfadsegment als Dateiname, mit Fallback für Sonderfälle wie `/`.
fn base_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "download".to_string())
}

/// Entfernt Zeichen, die einen Header-Wert zerstören oder als Pfadtrenner
/// missbraucht werden könnten.
fn sanitize_download_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\' && *c != '"')
        .collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() {
        "download".to_string()
    } else {
        cleaned
    }
}

/// Prozentkodierung nach RFC 5987 für den `filename*`-Parameter.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

/// Baut einen `Content-Disposition`-Header, der auch mit Umlauten und
/// Sonderzeichen funktioniert: ASCII-Fallback plus RFC-5987-Variante.
fn content_disposition(name: &str) -> Result<HeaderValue, DownloadError> {
    let name = sanitize_download_name(name);
    let ascii_fallback: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let value = format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        ascii_fallback,
        percent_encode(&name)
    );
    HeaderValue::from_str(&value)
        .map_err(|_| DownloadError::internal("Dateiname nicht als Header darstellbar"))
}

// ---------------------------------------------------------------------------
// Einzeldatei
// ---------------------------------------------------------------------------

/// `GET /api/download/file?path=<pfad>`
///
/// Streamt genau eine Datei. `Content-Length` wird gesetzt, der Body wird
/// chunkweise aus der Datei gelesen – auch mehrere GB belegen keinen
/// zusätzlichen Speicher.
pub async fn download_file(
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Response, DownloadError> {
    let path_param = params
        .iter()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| DownloadError::bad_request("Query-Parameter 'path' fehlt"))?;

    let root = download_root().await?;
    let path = resolve_within_root(&root, &path_param).await?;

    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| DownloadError::not_found(format!("Datei nicht lesbar: {}", e)))?;

    if !metadata.is_file() {
        return Err(DownloadError::bad_request(
            "Pfad ist keine Datei – für Ordner /api/download/zip verwenden",
        ));
    }

    let file = tokio::fs::File::open(&path).await.map_err(|e| {
        DownloadError::internal(format!("Datei konnte nicht geöffnet werden: {}", e))
    })?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(metadata.len()));
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(&base_name(&path))?,
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("none"));

    tracing::info!(
        "Datei-Download gestartet: {} ({} Bytes)",
        path.display(),
        metadata.len()
    );

    let body = Body::from_stream(ReaderStream::with_capacity(file, COPY_BUFFER));
    Ok((headers, body).into_response())
}

// ---------------------------------------------------------------------------
// ZIP (Ordner und Mehrfachauswahl)
// ---------------------------------------------------------------------------

/// `GET /api/download/zip?path=<a>&path=<b>&name=<archivname>`
///
/// Erzeugt aus einer beliebigen Mischung von Dateien und Ordnern ein ZIP.
/// Das Archiv wird während des Sendens erzeugt; es existiert zu keinem Zeitpunkt
/// vollständig im Speicher oder auf der Platte, daher auch kein `Content-Length`.
pub async fn download_zip(
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Response, DownloadError> {
    let requested: Vec<String> = params
        .iter()
        .filter(|(k, _)| k == "path" || k == "paths")
        .map(|(_, v)| v.clone())
        .collect();

    if requested.is_empty() {
        return Err(DownloadError::bad_request(
            "Mindestens ein Query-Parameter 'path' wird benötigt",
        ));
    }

    let root = download_root().await?;

    let mut selections = Vec::with_capacity(requested.len());
    for candidate in &requested {
        selections.push(resolve_within_root(&root, candidate).await?);
    }

    // Archivname: expliziter Wunsch, sonst der Name der einzigen Auswahl,
    // sonst ein generischer Name.
    let archive_name = params
        .iter()
        .find(|(k, _)| k == "name")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| {
            if selections.len() == 1 {
                base_name(&selections[0])
            } else {
                "download".to_string()
            }
        });
    let archive_name = sanitize_download_name(&archive_name);
    let archive_name = if archive_name.to_lowercase().ends_with(".zip") {
        archive_name
    } else {
        format!("{}.zip", archive_name)
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(&archive_name)?,
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    tracing::info!(
        "ZIP-Download gestartet: {} ({} Einträge ausgewählt)",
        archive_name,
        selections.len()
    );

    let (writer, reader) = tokio::io::duplex(DUPLEX_BUFFER);
    // Die Brücke muss im async-Kontext gebaut werden, benutzt wird sie im
    // Blocking-Task.
    let bridge = SyncIoBridge::new(writer);
    let root_for_task = root.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = write_zip(bridge, &root_for_task, &selections) {
            // Der Header ist längst raus – mehr als loggen und den Stream
            // abbrechen ist an dieser Stelle nicht möglich.
            tracing::error!("ZIP-Erzeugung abgebrochen: {}", e);
        }
    });

    let body = Body::from_stream(ReaderStream::with_capacity(reader, DUPLEX_BUFFER));
    Ok((headers, body).into_response())
}

/// Schreibt das komplette Archiv in `writer`. Blockierend, läuft deshalb im
/// Blocking-Pool; der Rückstau über den Duplex-Puffer regelt das Tempo.
fn write_zip<W: Write>(writer: W, root: &Path, selections: &[PathBuf]) -> anyhow::Result<()> {
    let mut zip = ZipWriter::new_stream(writer).set_auto_large_file();
    let mut used_names: HashSet<String> = HashSet::new();

    for selection in selections {
        // Die Auswahl ist bereits kanonisiert, also kein Symlink mehr.
        let metadata = match std::fs::symlink_metadata(selection) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Auswahl übersprungen ({}): {}", selection.display(), e);
                continue;
            }
        };

        let entry_name = unique_name(&mut used_names, &base_name(selection));

        if metadata.is_dir() {
            add_directory(&mut zip, root, selection, &entry_name)?;
        } else if metadata.is_file() {
            add_file(&mut zip, selection, &entry_name)?;
        } else {
            tracing::warn!(
                "Auswahl ist weder Datei noch Ordner, übersprungen: {}",
                selection.display()
            );
        }
    }

    let mut inner = zip.finish()?;
    inner.flush()?;
    Ok(())
}

/// Läuft einen Ordner iterativ ab (kein Rekursions-Stack, keine Sammelliste über
/// den gesamten Baum) und schreibt jeden Eintrag direkt ins Archiv.
fn add_directory<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    root: &Path,
    dir: &Path,
    prefix: &str,
) -> anyhow::Result<()> {
    let mut stack: Vec<(PathBuf, String)> = vec![(dir.to_path_buf(), prefix.to_string())];

    while let Some((current, current_prefix)) = stack.pop() {
        let read_dir = match std::fs::read_dir(&current) {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!(
                    "Ordner nicht lesbar, übersprungen ({}): {}",
                    current.display(),
                    e
                );
                continue;
            }
        };

        let mut is_empty = true;

        for entry in read_dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!(
                        "Verzeichniseintrag nicht lesbar ({}): {}",
                        current.display(),
                        e
                    );
                    continue;
                }
            };

            let child_path = entry.path();
            let child_name = entry.file_name().to_string_lossy().to_string();
            let child_zip_name = format!("{}/{}", current_prefix, child_name);

            let link_metadata = match std::fs::symlink_metadata(&child_path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Eintrag übersprungen ({}): {}", child_path.display(), e);
                    continue;
                }
            };

            if link_metadata.file_type().is_symlink() {
                // Symlinks werden aufgelöst und erneut gegen das Jail geprüft.
                // Verzeichnis-Symlinks werden grundsätzlich nicht verfolgt,
                // sonst wären Zyklen möglich.
                let resolved = match std::fs::canonicalize(&child_path) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("Symlink nicht auflösbar ({}): {}", child_path.display(), e);
                        continue;
                    }
                };
                if !is_within_root(root, &resolved) {
                    tracing::warn!(
                        "Symlink zeigt aus dem Wurzelverzeichnis heraus, übersprungen: {}",
                        child_path.display()
                    );
                    continue;
                }
                match std::fs::metadata(&resolved) {
                    Ok(m) if m.is_file() => {
                        is_empty = false;
                        add_file(zip, &resolved, &child_zip_name)?;
                    }
                    Ok(_) => {
                        tracing::warn!(
                            "Verzeichnis-Symlink nicht verfolgt: {}",
                            child_path.display()
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Symlink-Ziel nicht lesbar ({}): {}",
                            child_path.display(),
                            e
                        );
                    }
                }
                continue;
            }

            if link_metadata.is_dir() {
                is_empty = false;
                stack.push((child_path, child_zip_name));
            } else if link_metadata.is_file() {
                is_empty = false;
                add_file(zip, &child_path, &child_zip_name)?;
            } else {
                tracing::warn!("Spezialdatei übersprungen: {}", child_path.display());
            }
        }

        if is_empty {
            // Leere Ordner bekommen einen eigenen Eintrag, damit die Struktur
            // im Archiv erhalten bleibt.
            let modified = std::fs::metadata(&current).and_then(|m| m.modified()).ok();
            add_empty_directory(zip, &current_prefix, modified)?;
        }
    }

    Ok(())
}

/// Schreibt den Eintrag für einen leeren Ordner.
///
/// Bewusst **nicht** über `ZipWriter::add_directory`: im Stream-Modus setzt das
/// `zip`-Crate für jeden Eintrag das General-Purpose-Bit 3 („Data Descriptor
/// folgt"), schliesst den Verzeichniseintrag danach aber nicht ab – der
/// Descriptor fehlt, und der nächste lokale Header beginnt direkt hinter dem
/// Namen. Info-ZIP `unzip -t` rechnet daraus zu Recht eine Überlappung aus und
/// weist das gesamte Archiv mit „overlapped components" zurück.
///
/// Ein regulär gestarteter Eintrag mit `/` am Ende und ohne Nutzdaten wird
/// dagegen sauber abgeschlossen: Der Descriptor (CRC 0, Grösse 0) wird
/// geschrieben, das Archiv ist spec-konform. Verzeichnis bleibt der Eintrag
/// über den Namen – daran erkennen ihn `unzip`, `bsdtar`, `7z` und das
/// `zip`-Crate gleichermassen.
fn add_empty_directory<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    prefix: &str,
    modified: Option<std::time::SystemTime>,
) -> anyhow::Result<()> {
    let name = format!("{}/", zip_entry_name(prefix));
    zip.start_file(
        name,
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .last_modified_time(zip_date_time(modified)),
    )?;
    Ok(())
}

/// Rechnet die mtime einer Datei in die MS-DOS-Zeit des ZIP-Eintrags um.
///
/// ZIP speichert die Änderungszeit als MS-DOS-Paar: 2-Sekunden-Auflösung,
/// Jahre nur von 1980 bis 2107, und zwar als **lokale** Zeit ohne Zonenangabe.
/// Deshalb wird hier bewusst über `chrono::Local` gerechnet – ein Auspacken auf
/// demselben Rechner liefert damit wieder denselben Zeitpunkt.
///
/// Werte ausserhalb des darstellbaren Bereichs werden **geklemmt**, nicht als
/// Fehler behandelt: eine Datei von 1970 oder mit kaputter mtime darf einen
/// laufenden Download nicht abbrechen. Fehlt die mtime ganz (Dateisystem ohne
/// Unterstützung), bleibt es bei der ZIP-Epoche.
fn zip_date_time(modified: Option<std::time::SystemTime>) -> ZipDateTime {
    use chrono::{Datelike, Local, Timelike};

    /// Grösster in MS-DOS-Zeit darstellbarer Zeitpunkt (Sekunden gerade).
    fn max_date_time() -> ZipDateTime {
        ZipDateTime::from_date_and_time(2107, 12, 31, 23, 59, 58).unwrap_or_default()
    }

    let Some(modified) = modified else {
        return ZipDateTime::default();
    };

    let local: chrono::DateTime<Local> = modified.into();
    let year = local.year();
    if year < 1980 {
        // `DateTime::default()` ist exakt 1980-01-01 00:00:00, die Untergrenze.
        return ZipDateTime::default();
    }
    if year > 2107 {
        return max_date_time();
    }

    ZipDateTime::from_date_and_time(
        year as u16,
        local.month() as u8,
        local.day() as u8,
        local.hour() as u8,
        local.minute() as u8,
        // Schaltsekunden meldet chrono als 60; das Format kennt sie nicht.
        local.second().min(58) as u8,
    )
    .unwrap_or_default()
}

/// Kopiert eine Datei chunkweise in einen Archiv-Eintrag.
///
/// Namen werden vom `zip`-Crate als UTF-8 geschrieben; sobald sie nicht rein
/// ASCII sind, setzt es zusätzlich das General-Purpose-Flag Bit 11 (0x800).
fn add_file<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    path: &Path,
    entry_name: &str,
) -> anyhow::Result<()> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("Datei übersprungen ({}): {}", path.display(), e);
            return Ok(());
        }
    };

    // Grösse und mtime stammen aus demselben Handle: sie beschreiben damit
    // sicher die Datei, die gleich gelesen wird.
    let metadata = file.metadata().ok();
    let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
    let modified = metadata.as_ref().and_then(|m| m.modified().ok());
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(size >= ZIP64_THRESHOLD)
        .last_modified_time(zip_date_time(modified));

    zip.start_file(zip_entry_name(entry_name), options)?;

    let mut buffer = vec![0u8; COPY_BUFFER];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                // Der Eintrag wird trotzdem sauber abgeschlossen, sonst wäre
                // das gesamte Archiv defekt.
                tracing::warn!("Lesefehler in {}: {}", path.display(), e);
                break;
            }
        };
        zip.write_all(&buffer[..read])?;
    }

    Ok(())
}

/// Normalisiert einen Eintragsnamen für das Archiv: keine absoluten Pfade,
/// keine `..`-Segmente, immer `/` als Trenner.
fn zip_entry_name(name: &str) -> String {
    let normalized: Vec<String> = Path::new(name)
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    if normalized.is_empty() {
        "unnamed".to_string()
    } else {
        normalized.join("/")
    }
}

/// Verhindert doppelte Wurzeleinträge, wenn zwei Auswahlen denselben Basisnamen
/// haben (z.B. `/a/docs` und `/b/docs`).
fn unique_name(used: &mut HashSet<String>, name: &str) -> String {
    let base = zip_entry_name(name);
    if used.insert(base.clone()) {
        return base;
    }

    let (stem, extension) = match base.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), format!(".{}", ext)),
        _ => (base.clone(), String::new()),
    };

    let mut counter = 2;
    loop {
        let candidate = format!("{} ({}){}", stem, counter, extension);
        if used.insert(candidate.clone()) {
            return candidate;
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    /// Legt ein eindeutiges Testverzeichnis unterhalb von `std::env::temp_dir()` an.
    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rclone-gui-{}-{}", label, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis anlegen");
        dir
    }

    /// Liest das General-Purpose-Bit-Feld aus dem lokalen Dateikopf des
    /// Eintrags mit dem angegebenen Namen direkt aus den Archiv-Bytes.
    fn local_header_flags(archive: &[u8], entry_name: &str) -> Option<u16> {
        let wanted = entry_name.as_bytes();
        let mut offset = 0usize;
        while let Some(found) = archive[offset..]
            .windows(4)
            .position(|w| w == b"PK\x03\x04")
            .map(|p| offset + p)
        {
            if found + 30 > archive.len() {
                return None;
            }
            let flags = u16::from_le_bytes([archive[found + 6], archive[found + 7]]);
            let name_len = u16::from_le_bytes([archive[found + 26], archive[found + 27]]) as usize;
            let name_start = found + 30;
            if archive.get(name_start..name_start + name_len) == Some(wanted) {
                return Some(flags);
            }
            offset = found + 4;
        }
        None
    }

    /// Sucht den lokalen Dateikopf eines Eintrags und liefert
    /// `(flags, offset_hinter_dem_namen)`.
    fn local_header_of(archive: &[u8], entry_name: &str) -> Option<(u16, usize)> {
        let wanted = entry_name.as_bytes();
        let mut offset = 0usize;
        while let Some(found) = archive[offset..]
            .windows(4)
            .position(|w| w == b"PK\x03\x04")
            .map(|p| offset + p)
        {
            if found + 30 > archive.len() {
                return None;
            }
            let flags = u16::from_le_bytes([archive[found + 6], archive[found + 7]]);
            let name_len = u16::from_le_bytes([archive[found + 26], archive[found + 27]]) as usize;
            let extra_len = u16::from_le_bytes([archive[found + 28], archive[found + 29]]) as usize;
            let name_start = found + 30;
            if archive.get(name_start..name_start + name_len) == Some(wanted) {
                return Some((flags, name_start + name_len + extra_len));
            }
            offset = found + 4;
        }
        None
    }

    /// Regressionstest zum Fehlschlag „overlapped components / possible zip
    /// bomb" bei Archiven mit leeren Ordnern.
    ///
    /// Der frühere Weg über `ZipWriter::add_directory` setzte im Stream-Modus
    /// General-Purpose-Bit 3 („Data Descriptor folgt"), schrieb aber keinen
    /// Descriptor – hinter dem Namen begann sofort der nächste lokale Header.
    /// Info-ZIP `unzip -t` wies das gesamte Archiv daraufhin zurück
    /// (Exit-Code 12).
    ///
    /// Geprüft wird deshalb am Byte-Bild, dass der Verzeichniseintrag
    /// spec-konform ist: entweder ohne Bit 3, oder mit einem vollständigen
    /// Data Descriptor (`PK\x07\x08`, CRC und Grössen null, weil der Eintrag
    /// keine Nutzdaten hat) direkt hinter dem Eintrag.
    #[test]
    fn empty_directory_entry_is_spec_conform() {
        let base = temp_dir("leerer-ordner");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let tree = root.join("Ordner");
        std::fs::create_dir_all(tree.join("leer")).expect("leer");
        std::fs::write(tree.join("datei.txt"), b"inhalt").expect("datei");

        let mut archive = Vec::new();
        write_zip(&mut archive, &root, std::slice::from_ref(&tree)).expect("zip ok");

        let (flags, after_name) =
            local_header_of(&archive, "Ordner/leer/").expect("lokaler Header des leeren Ordners");

        if flags & 0x8 != 0 {
            // Bit 3 gesetzt: dann muss der Descriptor auch wirklich dastehen.
            let descriptor = archive
                .get(after_name..after_name + 16)
                .expect("Bytes hinter dem Verzeichniseintrag");
            assert_eq!(
                &descriptor[..4],
                b"PK\x07\x08",
                "Bit 3 gesetzt, aber kein Data Descriptor hinter dem Eintrag: {:02x?}",
                descriptor
            );
            assert_eq!(
                &descriptor[4..16],
                &[0u8; 12],
                "Verzeichniseintrag darf keine Nutzdaten melden: {:02x?}",
                descriptor
            );
        } else {
            // Ohne Bit 3 folgt unmittelbar der nächste Header bzw. die
            // Central Directory – beides ist gültig.
            let next = archive
                .get(after_name..after_name + 4)
                .expect("Bytes hinter dem Verzeichniseintrag");
            assert!(
                next == b"PK\x03\x04" || next == b"PK\x01\x02",
                "unerwartete Bytes hinter dem Verzeichniseintrag: {:02x?}",
                next
            );
        }

        // Gegenprobe mit einem echten Leser: der Eintrag ist vorhanden, wird
        // als Ordner erkannt und hat keine Nutzdaten.
        let mut zip = zip::ZipArchive::new(Cursor::new(archive)).expect("gültiges ZIP");
        let entry = zip.by_name("Ordner/leer/").expect("Eintrag leerer Ordner");
        assert!(entry.is_dir(), "Eintrag muss als Ordner gelten");
        assert_eq!(entry.size(), 0);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Setzt die mtime einer Datei bzw. eines Ordners auf einen bekannten
    /// Zeitpunkt. `File::set_modified` funktioniert auch für Verzeichnisse.
    fn set_mtime(path: &Path, when: std::time::SystemTime) {
        let file = std::fs::File::options()
            .read(true)
            .open(path)
            .expect("Handle für mtime");
        file.set_modified(when).expect("mtime setzen");
    }

    /// Baut einen `SystemTime`-Wert aus lokaler Zivilzeit.
    fn local_time(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> std::time::SystemTime {
        use chrono::TimeZone;
        chrono::Local
            .with_ymd_and_hms(year, month, day, hour, min, sec)
            .single()
            .expect("eindeutige lokale Zeit")
            .into()
    }

    /// Die mtime der Quelldatei landet im ZIP-Eintrag – vorher trugen alle
    /// Einträge die ZIP-Epoche 1980-01-01.
    #[test]
    fn zip_entries_keep_source_mtime() {
        let base = temp_dir("mtime");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let tree = root.join("Ordner");
        std::fs::create_dir_all(tree.join("leer")).expect("leer");
        std::fs::write(tree.join("datei.txt"), b"inhalt").expect("datei");

        // Ungerade Sekunde, damit die 2-Sekunden-Rasterung sichtbar wird.
        set_mtime(&tree.join("datei.txt"), local_time(2021, 6, 15, 12, 34, 57));
        set_mtime(&tree.join("leer"), local_time(2019, 3, 4, 5, 6, 7));

        let mut archive = Vec::new();
        write_zip(&mut archive, &root, std::slice::from_ref(&tree)).expect("zip ok");

        let mut zip = zip::ZipArchive::new(Cursor::new(archive)).expect("gültiges ZIP");

        let file_time = zip
            .by_name("Ordner/datei.txt")
            .expect("Datei-Eintrag")
            .last_modified()
            .expect("Zeitstempel");
        assert_eq!(
            (
                file_time.year(),
                file_time.month(),
                file_time.day(),
                file_time.hour(),
                file_time.minute()
            ),
            (2021, 6, 15, 12, 34)
        );
        // 2-Sekunden-Raster: 57 wird auf 56 abgerundet.
        assert!(
            file_time.second() == 56 || file_time.second() == 58,
            "unerwartete Sekunde: {}",
            file_time.second()
        );

        let dir_time = zip
            .by_name("Ordner/leer/")
            .expect("Ordner-Eintrag")
            .last_modified()
            .expect("Zeitstempel");
        assert_eq!(
            (
                dir_time.year(),
                dir_time.month(),
                dir_time.day(),
                dir_time.hour()
            ),
            (2019, 3, 4, 5)
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Randfälle der MS-DOS-Zeit: alles ausserhalb von [1980, 2107] wird
    /// geklemmt, nicht als Fehler behandelt.
    #[test]
    fn out_of_range_mtimes_are_clamped() {
        let epoch = zip_date_time(Some(std::time::UNIX_EPOCH));
        assert_eq!((epoch.year(), epoch.month(), epoch.day()), (1980, 1, 1));

        let far_past = zip_date_time(Some(
            std::time::UNIX_EPOCH - std::time::Duration::from_secs(100 * 365 * 86_400),
        ));
        assert_eq!((far_past.year(), far_past.month()), (1980, 1));

        let far_future = zip_date_time(Some(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(9_000_000_000),
        ));
        assert_eq!((far_future.year(), far_future.month()), (2107, 12));
        assert!(far_future.is_valid());

        // Ohne mtime bleibt es bei der Epoche.
        let none = zip_date_time(None);
        assert_eq!((none.year(), none.month(), none.day()), (1980, 1, 1));
    }

    /// Eine Datei von 1970 darf den Download nicht scheitern lassen: der
    /// Eintrag wird geschrieben, das Archiv bleibt lesbar.
    #[test]
    fn pre_1980_file_does_not_break_the_download() {
        let base = temp_dir("alt");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let tree = root.join("Ordner");
        std::fs::create_dir_all(&tree).expect("ordner");
        std::fs::write(tree.join("alt.txt"), b"alt").expect("datei");
        set_mtime(&tree.join("alt.txt"), std::time::UNIX_EPOCH);

        let mut archive = Vec::new();
        write_zip(&mut archive, &root, std::slice::from_ref(&tree)).expect("zip trotz alter mtime");

        let mut zip = zip::ZipArchive::new(Cursor::new(archive)).expect("gültiges ZIP");
        let mut entry = zip.by_name("Ordner/alt.txt").expect("Eintrag");
        assert_eq!(entry.last_modified().expect("Zeitstempel").year(), 1980);
        let mut content = Vec::new();
        entry.read_to_end(&mut content).expect("lesbar");
        assert_eq!(content, b"alt");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn zip_entry_name_strips_traversal() {
        assert_eq!(zip_entry_name("../../etc/passwd"), "etc/passwd");
        assert_eq!(zip_entry_name("/absolute/pfad"), "absolute/pfad");
        assert_eq!(zip_entry_name("normal.txt"), "normal.txt");
        assert_eq!(zip_entry_name(".."), "unnamed");
    }

    #[test]
    fn unique_name_deduplicates() {
        let mut used = HashSet::new();
        assert_eq!(unique_name(&mut used, "docs"), "docs");
        assert_eq!(unique_name(&mut used, "docs"), "docs (2)");
        assert_eq!(unique_name(&mut used, "a.txt"), "a.txt");
        assert_eq!(unique_name(&mut used, "a.txt"), "a (2).txt");
    }

    #[test]
    fn content_disposition_encodes_umlauts() {
        let value = content_disposition("Übung & Größe.txt").expect("Header baubar");
        let value = value.to_str().expect("ASCII");
        assert!(value.contains("filename*=UTF-8''"));
        assert!(
            value.contains("%C3%9C"),
            "Umlaut muss prozentkodiert sein: {}",
            value
        );
        assert!(value.is_ascii());
    }

    #[test]
    fn sanitize_removes_separators_and_controls() {
        assert_eq!(sanitize_download_name("a/b\\c\"d"), "abcd");
        assert_eq!(sanitize_download_name("bad\r\nname"), "badname");
        assert_eq!(sanitize_download_name("   "), "download");
    }

    #[tokio::test]
    async fn path_jail_rejects_traversal_and_symlink_escape() {
        let base = temp_dir("jail");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret.txt"), b"geheim").expect("secret");
        std::fs::write(root.join("ok.txt"), b"ok").expect("ok");

        let canonical_root = std::fs::canonicalize(&root).expect("canonical root");

        // Innerhalb: erlaubt
        assert!(resolve_within_root(&canonical_root, "ok.txt").await.is_ok());

        // `..`-Ausbruch: abgewiesen
        let err = resolve_within_root(&canonical_root, "../outside/secret.txt")
            .await
            .expect_err("muss fehlschlagen");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        // Absoluter Pfad ausserhalb: abgewiesen
        let outside_file = outside.join("secret.txt").to_string_lossy().to_string();
        let err = resolve_within_root(&canonical_root, &outside_file)
            .await
            .expect_err("muss fehlschlagen");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        // Symlink aus dem Jail heraus: abgewiesen
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("escape")).expect("symlink");
            let err = resolve_within_root(&canonical_root, "escape/secret.txt")
                .await
                .expect_err("muss fehlschlagen");
            assert_eq!(err.status, StatusCode::FORBIDDEN);
        }

        // Leerer Pfad: abgewiesen
        assert_eq!(
            resolve_within_root(&canonical_root, "")
                .await
                .expect_err("leer")
                .status,
            StatusCode::BAD_REQUEST
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lexical_normalization_resolves_without_filesystem() {
        // `.`, doppelte Trenner und `..` werden aufgelöst.
        assert_eq!(
            lexically_normalize(Path::new("/a/b/./c//d/../e")),
            PathBuf::from("/a/b/c/e")
        );
        // `..` über die absolute Wurzel hinaus verpufft, statt zu unterlaufen.
        assert_eq!(
            lexically_normalize(Path::new("/a/../../../etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        assert_eq!(lexically_normalize(Path::new("/..")), PathBuf::from("/"));
        // Relativ: führendes `..` bleibt stehen, damit der Pfad den
        // starts_with-Test gegen eine absolute Wurzel nie besteht.
        assert_eq!(
            lexically_normalize(Path::new("../x")),
            PathBuf::from("../x")
        );
        assert_eq!(lexically_normalize(Path::new("./")), PathBuf::from("."));
    }

    /// Statuscode-Matrix für alle bisher von Testern gemeldeten
    /// Ausbruchsvarianten. Ein Ausbruch ist 403, ein nicht existierender Pfad
    /// **innerhalb** der Wurzel bleibt 404.
    #[tokio::test]
    async fn path_jail_status_codes_per_attack_variant() {
        let base = temp_dir("jail-status");
        let root = base.join("root");
        // Geschwister mit gemeinsamem Präfix – darf nicht als „innerhalb" gelten.
        let sibling = base.join("rootevil");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&sibling).expect("sibling");
        std::fs::create_dir_all(outside.join("dir")).expect("outside");
        std::fs::write(outside.join("secret.txt"), b"geheim").expect("secret");
        std::fs::write(sibling.join("evil.txt"), b"evil").expect("evil");
        std::fs::write(root.join("ok.txt"), b"ok").expect("ok");
        std::fs::create_dir_all(root.join("sub")).expect("sub");

        let canonical_root = std::fs::canonicalize(&root).expect("canonical root");

        let status_of = |candidate: String| {
            let root = canonical_root.clone();
            async move {
                resolve_within_root(&root, &candidate)
                    .await
                    .err()
                    .map(|e| e.status)
            }
        };

        // --- erlaubt ---------------------------------------------------
        assert!(status_of("ok.txt".into()).await.is_none());
        assert!(status_of("./sub/../ok.txt".into()).await.is_none());
        assert!(status_of("sub".into()).await.is_none());

        // --- 404: existiert nicht, liegt aber innerhalb der Wurzel ------
        assert_eq!(
            status_of("gibtesnicht.txt".into()).await,
            Some(StatusCode::NOT_FOUND)
        );
        assert_eq!(
            status_of("sub/tiefer/gibtesnicht.txt".into()).await,
            Some(StatusCode::NOT_FOUND)
        );
        // Doppelt kodiert: der Server dekodiert genau einmal, übrig bleibt ein
        // literaler Dateiname ohne Trenner – also ein nicht existierender Pfad
        // innerhalb der Wurzel, kein Ausbruch.
        assert_eq!(
            status_of("%2e%2e%2fetc%2fpasswd".into()).await,
            Some(StatusCode::NOT_FOUND)
        );

        // --- 403: Ausbruch, Ziel existiert nicht (der gemeldete Fehler) --
        assert_eq!(
            status_of("../../etc/passwd".into()).await,
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            status_of("../../../../../../gibtesnicht".into()).await,
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            status_of("sub/../../outside/gibtesnicht".into()).await,
            Some(StatusCode::FORBIDDEN)
        );

        // --- 403: Ausbruch, Ziel existiert -----------------------------
        assert_eq!(
            status_of("../outside/secret.txt".into()).await,
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            status_of("/etc/passwd".into()).await,
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            status_of(outside.join("secret.txt").to_string_lossy().to_string()).await,
            Some(StatusCode::FORBIDDEN)
        );
        // Geschwister-Präfix: `…/rootevil` darf nicht als `…/root` durchgehen.
        assert_eq!(
            status_of("../rootevil/evil.txt".into()).await,
            Some(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            status_of(sibling.join("evil.txt").to_string_lossy().to_string()).await,
            Some(StatusCode::FORBIDDEN)
        );

        // --- 400: strukturell ungültig ---------------------------------
        assert_eq!(status_of("".into()).await, Some(StatusCode::BAD_REQUEST));
        assert_eq!(status_of("   ".into()).await, Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            status_of("ok.txt\0.png".into()).await,
            Some(StatusCode::BAD_REQUEST)
        );

        // --- Symlinks: lexikalisch unauffällig, trotzdem 403 -----------
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("datei-link"))
                .expect("datei-symlink");
            std::os::unix::fs::symlink(&outside, root.join("ordner-link")).expect("ordner-symlink");
            // Symlink auf ein Ziel, das es nicht gibt.
            std::os::unix::fs::symlink(outside.join("weg.txt"), root.join("toter-link"))
                .expect("toter-symlink");

            assert_eq!(
                status_of("datei-link".into()).await,
                Some(StatusCode::FORBIDDEN)
            );
            assert_eq!(
                status_of("ordner-link/secret.txt".into()).await,
                Some(StatusCode::FORBIDDEN)
            );
            assert_eq!(
                status_of("ordner-link/dir".into()).await,
                Some(StatusCode::FORBIDDEN)
            );
            // Der lexikalische Weg würde `ordner-link/..` als Wurzel ansehen;
            // massgeblich ist die Kanonisierung, und die landet ausserhalb.
            assert_eq!(
                status_of("ordner-link/../outside/secret.txt".into()).await,
                Some(StatusCode::FORBIDDEN)
            );
            // Toter Symlink: kanonisieren scheitert, lexikalisch innerhalb.
            assert_eq!(
                status_of("toter-link".into()).await,
                Some(StatusCode::NOT_FOUND)
            );
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn zip_preserves_structure_and_utf8_names() {
        let base = temp_dir("zip");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let tree = root.join("Ordner");
        std::fs::create_dir_all(tree.join("unter")).expect("unter");
        std::fs::create_dir_all(tree.join("leer")).expect("leer");
        std::fs::write(tree.join("Grüße & Umlaute.txt"), b"hallo").expect("datei");
        std::fs::write(tree.join("unter").join("tief.bin"), vec![7u8; 10_000]).expect("tief");
        std::fs::write(root.join("einzeln.txt"), b"solo").expect("einzeln");

        let mut archive = Vec::new();
        write_zip(
            &mut archive,
            &root,
            &[tree.clone(), root.join("einzeln.txt")],
        )
        .expect("zip ok");

        // Nicht-ASCII-Name muss das UTF-8-Flag (Bit 11) im lokalen Header tragen.
        let flags = local_header_flags(&archive, "Ordner/Grüße & Umlaute.txt")
            .expect("lokaler Header des Umlaut-Eintrags");
        assert_eq!(flags & 0x800, 0x800, "UTF-8-Flag fehlt: {:#x}", flags);

        let mut zip = zip::ZipArchive::new(Cursor::new(archive)).expect("gültiges ZIP");
        let names: Vec<String> = zip.file_names().map(|n| n.to_string()).collect();

        assert!(
            names.contains(&"Ordner/Grüße & Umlaute.txt".to_string()),
            "Namen: {:?}",
            names
        );
        assert!(
            names.contains(&"Ordner/unter/tief.bin".to_string()),
            "Namen: {:?}",
            names
        );
        assert!(
            names.contains(&"Ordner/leer/".to_string()),
            "Namen: {:?}",
            names
        );
        assert!(
            names.contains(&"einzeln.txt".to_string()),
            "Namen: {:?}",
            names
        );

        // Inhalt einer Datei gegenprüfen.
        let mut entry = zip.by_name("Ordner/unter/tief.bin").expect("tief.bin");
        let mut content = Vec::new();
        entry.read_to_end(&mut content).expect("inhalt");
        assert_eq!(content.len(), 10_000);
        assert!(content.iter().all(|b| *b == 7));

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Belegt, dass das Archiv wirklich streamt: der Duplex-Puffer ist klein,
    /// die Quelldaten sind ein Vielfaches davon. Die ersten Bytes müssen beim
    /// Leser ankommen, während der Schreiber noch läuft – bei einem gepufferten
    /// oder auf Platte vorproduzierten Archiv wäre das nicht der Fall.
    #[tokio::test]
    async fn zip_streams_without_full_buffering() {
        let base = temp_dir("stream");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let dir = root.join("gross");
        std::fs::create_dir_all(&dir).expect("dir");
        for i in 0..8u64 {
            // Schlecht komprimierbare Daten, damit Deflate nichts wegkürzt.
            let data: Vec<u8> = (0..512u64 * 1024)
                .map(|b| ((b * 31 + i * 7) % 251) as u8)
                .collect();
            std::fs::write(dir.join(format!("teil{}.bin", i)), data).expect("teil");
        }

        let (writer, mut reader) = tokio::io::duplex(16 * 1024);
        let bridge = SyncIoBridge::new(writer);
        let root_for_task = root.clone();
        let selections = vec![dir.clone()];
        let task =
            tokio::task::spawn_blocking(move || write_zip(bridge, &root_for_task, &selections));

        let mut head = vec![0u8; 4096];
        reader.read_exact(&mut head).await.expect("kopf lesen");
        assert!(
            !task.is_finished(),
            "Bei echtem Streaming ist der Schreiber hier noch nicht fertig"
        );
        assert_eq!(&head[..4], b"PK\x03\x04");

        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.expect("rest lesen");
        task.await.expect("task").expect("zip ok");

        let mut archive = head;
        archive.extend_from_slice(&rest);
        let zip = zip::ZipArchive::new(Cursor::new(archive)).expect("gültiges ZIP");
        assert_eq!(zip.len(), 8);

        let _ = std::fs::remove_dir_all(&base);
    }
}
