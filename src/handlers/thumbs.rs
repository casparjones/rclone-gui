//! Thumbnail-Endpunkt für die Preview-Ansicht des File-Browsers.
//!
//! `GET /api/thumb?path=…` liefert ein verkleinertes Vorschaubild (maximale
//! Kantenlänge [`MAX_EDGE`]) für Bilddateien unterhalb des erlaubten
//! Wurzelverzeichnisses. Alles andere wird abgelehnt – das Frontend zeigt dann
//! sein Typ-Icon.
//!
//! Grundsätze:
//!
//! * **Jail.** Der Pfad kommt vom Client und wird über `resolve_within_root`
//!   aus `download.rs` kanonisiert und geprüft – inklusive aufgelöster
//!   Symlinks. Es gibt hier bewusst keine eigene Pfadlogik.
//! * **Dekompressionsbomben.** Vor dem Dekodieren begrenzen wir die Dateigrösse
//!   ([`MAX_SOURCE_BYTES`]), die Bilddimensionen und den Speicher, den der
//!   Decoder allozieren darf ([`MAX_DECODE_ALLOC`]). Ein 8 KB grosses PNG mit
//!   64000×64000 Pixeln fällt damit vor der ersten Allokation durch.
//! * **Gegendruck.** Ein Ordner mit tausend Bildern erzeugt tausend Anfragen.
//!   Ein Semaphor begrenzt die gleichzeitig laufenden Dekodierungen, damit der
//!   Speicherverbrauch unabhängig von der Ordnergrösse bleibt.
//! * **Cache.** Fertige Thumbnails landen in einem Cache-Verzeichnis, das
//!   **ausserhalb** des browsebaren Wurzelverzeichnisses liegen muss – sonst
//!   tauchten sie in der Ordneranzeige auf und wären selbst wieder Quelle.
//!   Der Cache ist nach Anzahl und Bytes begrenzt und wird nach LRU verdrängt;
//!   siehe [`cleanup_cache`].
//!
//! Kein `unwrap()`/`expect()` im Request-Pfad.

use axum::{
    body::Body,
    extract::Query,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use image::{ImageFormat, ImageReader, Limits};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;

use crate::handlers::download::{
    download_root, is_within_root, resolve_within_root, DownloadError,
};

/// Maximale Kantenlänge des erzeugten Thumbnails. Das Seitenverhältnis bleibt
/// erhalten, das Bild wird nie hochskaliert.
const MAX_EDGE: u32 = 256;

/// Grösste Quelldatei, die überhaupt dekodiert wird.
///
/// 128 MB. Der frühere Wert von 32 MB war real zu knapp: ein 36-MB-TIFF fiel
/// auf das Typ-Icon zurück, moderne Kameras liefern deutlich grössere RAW- und
/// TIFF-Dateien. Das Limit ist **keine** Abwehr von Dekompressionsbomben – die
/// hängt an [`MAX_SOURCE_EDGE`] und [`MAX_DECODE_ALLOC`], die beide unverändert
/// bleiben und schon am Header greifen. Hier begrenzt der Wert nur den
/// kurzzeitigen Lesepuffer: mit [`MAX_CONCURRENT_DECODES`] parallelen
/// Dekodierungen ist der Worst Case an Quell-Bytes im Speicher beschränkt.
const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;

/// Obergrenze für die Bildkanten der Quelle. Alles darüber gilt als Angriff
/// oder als für eine Vorschau untauglich.
const MAX_SOURCE_EDGE: u32 = 16_384;

/// Speicher, den der Decoder für ein einzelnes Bild belegen darf.
const MAX_DECODE_ALLOC: u64 = 128 * 1024 * 1024;

/// Gleichzeitig laufende Dekodierungen. Mehr Anfragen warten, statt parallel
/// Speicher zu belegen.
const MAX_CONCURRENT_DECODES: usize = 4;

/// JPEG-Qualität für Thumbnails ohne Alphakanal.
const JPEG_QUALITY: u8 = 80;

/// Dateiendungen, für die überhaupt ein Thumbnail versucht wird. Passt zu den
/// aktivierten Features des `image`-Crates.
const SUPPORTED_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "ico",
];

/// Höchstzahl der Thumbnails im Cache. Ein Testlauf über einen einzigen Ordner
/// hinterliess 2121 Einträge – ohne Grenze läuft die Platte voll. 5000 deckt
/// mehrere grosse Ordner ab und bleibt beim Aufräumen (ein `read_dir` plus ein
/// kleiner Read je Eintrag) im Millisekundenbereich.
const MAX_CACHE_ENTRIES: usize = 5_000;

/// Harte Obergrenze in Bytes, unabhängig von der Anzahl. Ein Thumbnail mit
/// 256 px Kantenlänge liegt als JPEG typisch bei 10–30 KB, als PNG mit Alpha im
/// Extremfall bei rund 250 KB. 256 MB decken den PNG-Worst-Case für die volle
/// Eintragszahl ab und begrenzen den Platzbedarf trotzdem verlässlich.
const MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;

/// Abstand der periodischen Aufräumläufe – deutlich enger als das
/// 24-Stunden-Cleanup der Sync-Jobs, weil hier Plattenplatz wächst, nicht nur
/// eine HashMap.
const CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

/// So viele geschriebene Einträge stossen zusätzlich einen Lauf an. Damit ist
/// die Überschreitung des Limits zwischen zwei Zeitläufen nach oben begrenzt:
/// höchstens dieser Wert an Einträgen über [`MAX_CACHE_ENTRIES`].
const CLEANUP_AFTER_WRITES: usize = 256;

/// Ab diesem Alter gilt eine liegengebliebene `.tmp`-Datei als Leiche eines
/// abgebrochenen Schreibvorgangs.
const STALE_TEMP_AGE: Duration = Duration::from_secs(3600);

/// Endung der Beidatei, die zu jedem Thumbnail den Quellpfad festhält. Ohne sie
/// liesse sich aus dem gehashten Schlüssel nicht ermitteln, ob die Quelle noch
/// existiert.
const SIDECAR_EXTENSION: &str = "src";

fn decode_semaphore() -> &'static Semaphore {
    static SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();
    SEMAPHORE.get_or_init(|| Semaphore::new(MAX_CONCURRENT_DECODES))
}

/// Kodierung des Thumbnails. PNG nur dort, wo Transparenz erhalten bleiben
/// muss – sonst ist JPEG deutlich kleiner.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ThumbFormat {
    Jpeg,
    Png,
}

impl ThumbFormat {
    fn extension(self) -> &'static str {
        match self {
            ThumbFormat::Jpeg => "jpg",
            ThumbFormat::Png => "png",
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            ThumbFormat::Jpeg => "image/jpeg",
            ThumbFormat::Png => "image/png",
        }
    }
}

/// Ein fertiges Thumbnail samt Kodierung.
struct Thumbnail {
    bytes: Vec<u8>,
    format: ThumbFormat,
}

/// `GET /api/thumb?path=…`
pub async fn get_thumbnail(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, DownloadError> {
    let requested = params
        .get("path")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| DownloadError::bad_request("Pfad fehlt"))?;

    let root = download_root().await?;
    let source = resolve_within_root(&root, requested).await?;

    let metadata = tokio::fs::metadata(&source)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;
    if !metadata.is_file() {
        return Err(DownloadError::bad_request("Kein Bild"));
    }
    if metadata.len() == 0 {
        return Err(DownloadError::bad_request("Datei ist leer"));
    }
    if !source_size_is_acceptable(metadata.len()) {
        return Err(DownloadError::bad_request(
            "Datei ist zu gross für eine Vorschau",
        ));
    }
    if extension_of(&source)
        .filter(|ext| SUPPORTED_EXTENSIONS.contains(&ext.as_str()))
        .is_none()
    {
        return Err(DownloadError::bad_request("Kein unterstütztes Bildformat"));
    }

    // Der Cache-Schlüssel bindet Pfad, Grösse und Änderungszeit ein: eine
    // ersetzte Datei bekommt automatisch einen neuen Eintrag.
    let key = cache_key(&source, metadata.len(), modified_seconds(&metadata));
    let etag = format!("\"{}\"", key);

    if header_matches(&headers, &etag) {
        return not_modified(&etag);
    }

    let cache_dir = thumb_cache_dir(&root).await?;
    ensure_cache_janitor(&cache_dir);

    if let Some(hit) = read_from_cache(&cache_dir, &key).await {
        return respond(hit, &etag);
    }

    let thumb = render_thumbnail(source.clone()).await?;
    write_to_cache(&cache_dir, &key, &thumb, &source).await;
    respond(thumb, &etag)
}

/// Passt die Quelldatei durch das Grössenlimit? Eigene Funktion, damit die
/// Grenze testbar ist, ohne den ganzen Request-Pfad aufzubauen.
fn source_size_is_acceptable(len: u64) -> bool {
    len <= MAX_SOURCE_BYTES
}

/// Kleinschreibung der Dateiendung, ohne Punkt.
fn extension_of(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

/// Änderungszeit als Unix-Sekunden. Nicht ermittelbar heisst 0 – dann ist der
/// Cache-Schlüssel nur über Pfad und Grösse bestimmt.
fn modified_seconds(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 128-Bit-FNV-1a über Pfad, Grösse und Mtime, als Hex.
///
/// Bewusst selbst gerechnet statt über `DefaultHasher`: dessen Ergebnis ist
/// zwischen Rust-Versionen nicht stabil, der Cache würde bei jedem
/// Toolchain-Wechsel komplett verwaisen.
fn cache_key(path: &Path, size: u64, modified: u64) -> String {
    let mut material = path.to_string_lossy().into_owned().into_bytes();
    material.extend_from_slice(&size.to_le_bytes());
    material.extend_from_slice(&modified.to_le_bytes());

    format!(
        "{:016x}{:016x}",
        fnv1a64(&material, 0xcbf2_9ce4_8422_2325),
        fnv1a64(&material, 0x9dc5_bb17_1b9d_2a11)
    )
}

fn fnv1a64(bytes: &[u8], offset_basis: u64) -> u64 {
    let mut hash = offset_basis;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Konfiguriertes Cache-Verzeichnis. Standard ist `data/cache/thumbs`, also
/// neben der Datenbank und ausserhalb dessen, was der Browser anzeigt.
fn configured_cache_dir() -> PathBuf {
    std::env::var("RCLONE_GUI_THUMB_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/cache/thumbs"))
}

/// Legt das Cache-Verzeichnis an und stellt sicher, dass es **nicht** innerhalb
/// des browsebaren Wurzelverzeichnisses liegt.
async fn thumb_cache_dir(root: &Path) -> Result<PathBuf, DownloadError> {
    let dir = configured_cache_dir();

    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        DownloadError::internal(format!(
            "Thumbnail-Cache '{}' nicht anlegbar: {}",
            dir.display(),
            e
        ))
    })?;

    let canonical = tokio::fs::canonicalize(&dir).await.map_err(|e| {
        DownloadError::internal(format!(
            "Thumbnail-Cache '{}' nicht auflösbar: {}",
            dir.display(),
            e
        ))
    })?;

    if is_within_root(root, &canonical) {
        return Err(DownloadError::internal(
            "Thumbnail-Cache liegt im browsebaren Verzeichnis – RCLONE_GUI_THUMB_CACHE anpassen",
        ));
    }

    Ok(canonical)
}

/// Sucht beide möglichen Kodierungen zum Schlüssel. Ein defekter oder fehlender
/// Eintrag ist kein Fehler, sondern nur ein Cache-Miss.
async fn read_from_cache(cache_dir: &Path, key: &str) -> Option<Thumbnail> {
    for format in [ThumbFormat::Jpeg, ThumbFormat::Png] {
        let path = cache_dir.join(format!("{}.{}", key, format.extension()));
        if let Ok(bytes) = tokio::fs::read(&path).await {
            if !bytes.is_empty() {
                touch(path);
                return Some(Thumbnail { bytes, format });
            }
        }
    }
    None
}

/// Setzt die Änderungszeit eines Eintrags auf jetzt. Die Verdrängung sortiert
/// danach – ohne diesen Schritt wäre sie „ältester Schreibvorgang" statt LRU.
/// Best effort: schlägt es fehl, altert der Eintrag eben schneller.
fn touch(path: PathBuf) {
    tokio::task::spawn_blocking(move || {
        let Ok(file) = std::fs::File::options().write(true).open(&path) else {
            return;
        };
        let now = SystemTime::now();
        let times = std::fs::FileTimes::new()
            .set_accessed(now)
            .set_modified(now);
        let _ = file.set_times(times);
    });
}

/// Schreibt erst in eine temporäre Datei und benennt dann um, damit parallele
/// Leser nie einen halb geschriebenen Eintrag sehen. Fehler werden geloggt,
/// aber nicht an den Client durchgereicht – das Bild steht ja bereits.
async fn write_to_cache(cache_dir: &Path, key: &str, thumb: &Thumbnail, source: &Path) {
    let final_path = cache_dir.join(format!("{}.{}", key, thumb.format.extension()));
    let temp_path = cache_dir.join(format!("{}.{}.tmp", key, std::process::id()));

    if let Err(e) = tokio::fs::write(&temp_path, &thumb.bytes).await {
        tracing::warn!("Thumbnail-Cache nicht schreibbar: {}", e);
        return;
    }
    if let Err(e) = tokio::fs::rename(&temp_path, &final_path).await {
        tracing::warn!("Thumbnail-Cache nicht umbenennbar: {}", e);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return;
    }

    write_sidecar(cache_dir, key, source).await;
    note_cache_write(cache_dir);
}

/// Hält den Quellpfad neben dem Thumbnail fest, damit das Aufräumen verwaiste
/// Einträge erkennt. Nur für Pfade, die sich als UTF-8 darstellen lassen – ein
/// Eintrag ohne Beidatei wird beim Aufräumen nie als verwaist gewertet, sondern
/// altert regulär über die Verdrängung heraus.
async fn write_sidecar(cache_dir: &Path, key: &str, source: &Path) {
    let Some(text) = source.to_str() else {
        return;
    };

    let final_path = cache_dir.join(format!("{}.{}", key, SIDECAR_EXTENSION));
    let temp_path = cache_dir.join(format!(
        "{}.{}.{}.tmp",
        key,
        SIDECAR_EXTENSION,
        std::process::id()
    ));

    if tokio::fs::write(&temp_path, text.as_bytes()).await.is_err() {
        return;
    }
    if tokio::fs::rename(&temp_path, &final_path).await.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }
}

// ---------------------------------------------------------------------------
// Aufräumen des Cache-Verzeichnisses
// ---------------------------------------------------------------------------

/// Zählt geschriebene Einträge seit dem letzten Aufräumen.
static WRITES_SINCE_CLEANUP: AtomicUsize = AtomicUsize::new(0);

/// Verhindert, dass zwei Aufräumläufe gleichzeitig dieselben Dateien löschen.
static CLEANUP_RUNNING: AtomicBool = AtomicBool::new(false);

/// Startet den Aufräumdienst beim ersten Zugriff: ein Lauf sofort, danach alle
/// [`CACHE_CLEANUP_INTERVAL`]. Bewusst hier und nicht in `main.rs` – der
/// Endpunkt ist die einzige Stelle, die das Cache-Verzeichnis kennt und prüft.
fn ensure_cache_janitor(cache_dir: &Path) {
    static JANITOR: OnceLock<()> = OnceLock::new();

    let dir = cache_dir.to_path_buf();
    JANITOR.get_or_init(move || {
        tokio::spawn(async move {
            loop {
                run_cleanup(&dir).await;
                tokio::time::sleep(CACHE_CLEANUP_INTERVAL).await;
            }
        });
    });
}

/// Zusätzlicher Auslöser über die Schreibrate, damit ein Ordner mit
/// zehntausend Bildern das Limit nicht bis zum nächsten Zeitlauf überrennt.
fn note_cache_write(cache_dir: &Path) {
    if WRITES_SINCE_CLEANUP.fetch_add(1, Ordering::Relaxed) + 1 < CLEANUP_AFTER_WRITES {
        return;
    }
    let dir = cache_dir.to_path_buf();
    tokio::spawn(async move { run_cleanup(&dir).await });
}

/// Ein Lauf, gegen Parallelität abgesichert und mit Log-Zeile.
async fn run_cleanup(cache_dir: &Path) {
    if CLEANUP_RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    WRITES_SINCE_CLEANUP.store(0, Ordering::Relaxed);

    match cleanup_cache(cache_dir, MAX_CACHE_ENTRIES, MAX_CACHE_BYTES).await {
        Ok(report) if report.removed() > 0 => tracing::info!(
            "🧹 Thumbnail-Cache: {} verwaist, {} verdrängt, {} Reste – {} Einträge / {} Bytes bleiben",
            report.orphans,
            report.evicted,
            report.leftovers,
            report.remaining_entries,
            report.remaining_bytes
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!("Thumbnail-Cache nicht aufräumbar: {}", e),
    }

    CLEANUP_RUNNING.store(false, Ordering::Release);
}

/// Ergebnis eines Aufräumlaufs. Existiert für die Log-Zeile und die Tests.
#[derive(Debug, Default, PartialEq, Eq)]
struct CleanupReport {
    /// Einträge, deren Quelldatei es nicht mehr gibt.
    orphans: usize,
    /// Einträge, die wegen der Limits verdrängt wurden (LRU).
    evicted: usize,
    /// Liegengebliebene `.tmp`-Dateien und Beidateien ohne Thumbnail.
    leftovers: usize,
    remaining_entries: usize,
    remaining_bytes: u64,
}

impl CleanupReport {
    fn removed(&self) -> usize {
        self.orphans + self.evicted + self.leftovers
    }
}

/// Ein Thumbnail im Cache, so wie das Aufräumen es sieht.
struct CacheEntry {
    thumb: PathBuf,
    sidecar: Option<PathBuf>,
    /// Thumbnail plus Beidatei – beide zählen auf das Byte-Limit.
    bytes: u64,
    /// Letzter Zugriff (Thumbnails werden beim Treffer angefasst).
    modified: SystemTime,
    /// Quellpfad laut Beidatei; `None` heisst „nicht überprüfbar".
    source: Option<PathBuf>,
}

/// Räumt das Cache-Verzeichnis auf:
///
/// 1. abgebrochene `.tmp`-Dateien und Beidateien ohne Thumbnail entfernen,
/// 2. Einträge entfernen, deren Quelldatei nicht mehr existiert,
/// 3. den Rest nach LRU verdrängen, bis Anzahl **und** Bytes unter den Limits
///    liegen.
///
/// Limits als Parameter, damit die Tests sie ohne 5000 Dateien prüfen können.
async fn cleanup_cache(
    cache_dir: &Path,
    max_entries: usize,
    max_bytes: u64,
) -> std::io::Result<CleanupReport> {
    let now = SystemTime::now();
    let mut report = CleanupReport::default();

    let mut thumbs: HashMap<String, (PathBuf, u64, SystemTime)> = HashMap::new();
    let mut sidecars: HashMap<String, (PathBuf, u64)> = HashMap::new();

    let mut dir = tokio::fs::read_dir(cache_dir).await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        let Ok(metadata) = entry.metadata().await else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if name.ends_with(".tmp") {
            let stale = metadata
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .map(|age| age >= STALE_TEMP_AGE)
                .unwrap_or(false);
            if stale && tokio::fs::remove_file(&path).await.is_ok() {
                report.leftovers += 1;
            }
            continue;
        }

        let Some((key, ext)) = name.rsplit_once('.') else {
            continue;
        };
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        if ext == SIDECAR_EXTENSION {
            sidecars.insert(key.to_string(), (path, metadata.len()));
        } else if ext == ThumbFormat::Jpeg.extension() || ext == ThumbFormat::Png.extension() {
            thumbs.insert(key.to_string(), (path, metadata.len(), modified));
        }
    }

    // Beidateien ohne Thumbnail sind wertlos.
    for (key, (path, _)) in sidecars.iter() {
        if !thumbs.contains_key(key) && tokio::fs::remove_file(path).await.is_ok() {
            report.leftovers += 1;
        }
    }

    let mut entries = Vec::with_capacity(thumbs.len());
    for (key, (thumb, len, modified)) in thumbs {
        let sidecar = sidecars.get(&key).map(|(path, _)| path.clone());
        let sidecar_len = sidecars.get(&key).map(|(_, len)| *len).unwrap_or(0);
        let source = match &sidecar {
            Some(path) => tokio::fs::read(path)
                .await
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(PathBuf::from),
            None => None,
        };

        entries.push(CacheEntry {
            thumb,
            sidecar,
            bytes: len + sidecar_len,
            modified,
            source,
        });
    }

    // Verwaiste Einträge: Quelle bekannt, aber nicht mehr vorhanden.
    let mut survivors = Vec::with_capacity(entries.len());
    for entry in entries {
        let orphaned = match &entry.source {
            Some(source) => tokio::fs::symlink_metadata(source).await.is_err(),
            None => false,
        };
        if orphaned {
            remove_entry(&entry).await;
            report.orphans += 1;
        } else {
            survivors.push(entry);
        }
    }

    // Verdrängung nach LRU: älteste Zugriffe zuerst.
    survivors.sort_by_key(|entry| entry.modified);

    let mut total_bytes: u64 = survivors.iter().map(|entry| entry.bytes).sum();
    let mut index = 0;
    while (survivors.len() - index > max_entries || total_bytes > max_bytes)
        && index < survivors.len()
    {
        let entry = &survivors[index];
        remove_entry(entry).await;
        total_bytes = total_bytes.saturating_sub(entry.bytes);
        report.evicted += 1;
        index += 1;
    }

    report.remaining_entries = survivors.len() - index;
    report.remaining_bytes = total_bytes;
    Ok(report)
}

/// Entfernt Thumbnail und Beidatei. Fehler sind belanglos – der nächste Lauf
/// versucht es erneut.
async fn remove_entry(entry: &CacheEntry) {
    let _ = tokio::fs::remove_file(&entry.thumb).await;
    if let Some(sidecar) = &entry.sidecar {
        let _ = tokio::fs::remove_file(sidecar).await;
    }
}

/// Liest die Quelldatei und erzeugt das Thumbnail in einem Blocking-Task.
/// Das Semaphor begrenzt, wie viele davon gleichzeitig laufen.
async fn render_thumbnail(source: PathBuf) -> Result<Thumbnail, DownloadError> {
    let permit = decode_semaphore()
        .acquire()
        .await
        .map_err(|_| DownloadError::internal("Thumbnail-Dienst steht nicht zur Verfügung"))?;

    let bytes = tokio::fs::read(&source)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;

    let result = tokio::task::spawn_blocking(move || decode_and_resize(&bytes)).await;

    drop(permit);

    match result {
        Ok(inner) => inner,
        Err(e) => {
            tracing::warn!("Thumbnail-Task abgebrochen: {}", e);
            Err(DownloadError::internal(
                "Thumbnail konnte nicht erzeugt werden",
            ))
        }
    }
}

/// Reine CPU-Arbeit: dekodieren (mit Limits), verkleinern, kodieren.
fn decode_and_resize(bytes: &[u8]) -> Result<Thumbnail, DownloadError> {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_EDGE);
    limits.max_image_height = Some(MAX_SOURCE_EDGE);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);

    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| DownloadError::bad_request(format!("Format nicht erkannt: {}", e)))?;
    reader.limits(limits);

    let image = reader
        .decode()
        .map_err(|e| DownloadError::bad_request(format!("Bild nicht dekodierbar: {}", e)))?;

    // `thumbnail` behält das Seitenverhältnis, würde ein kleines Bild aber auf
    // die Zielgrösse aufblasen. Wer ohnehin unter der Grenze liegt, bleibt wie
    // er ist – das spart Bytes und verhindert unscharfe Vorschauen.
    let resized = if image.width() > MAX_EDGE || image.height() > MAX_EDGE {
        image.thumbnail(MAX_EDGE, MAX_EDGE)
    } else {
        image
    };

    let format = if resized.color().has_alpha() {
        ThumbFormat::Png
    } else {
        ThumbFormat::Jpeg
    };

    let mut out = Cursor::new(Vec::new());
    match format {
        ThumbFormat::Png => resized
            .write_to(&mut out, ImageFormat::Png)
            .map_err(|e| DownloadError::internal(format!("PNG nicht kodierbar: {}", e)))?,
        ThumbFormat::Jpeg => {
            let encoder =
                image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY);
            resized
                .to_rgb8()
                .write_with_encoder(encoder)
                .map_err(|e| DownloadError::internal(format!("JPEG nicht kodierbar: {}", e)))?;
        }
    }

    Ok(Thumbnail {
        bytes: out.into_inner(),
        format,
    })
}

/// Prüft `If-None-Match` gegen das aktuelle ETag.
fn header_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').any(|candidate| candidate.trim() == etag))
        .unwrap_or(false)
}

fn not_modified(etag: &str) -> Result<Response, DownloadError> {
    let mut response = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .body(Body::empty())
        .map_err(|e| DownloadError::internal(format!("Antwort nicht baubar: {}", e)))?;
    apply_cache_headers(response.headers_mut(), etag);
    Ok(response)
}

fn respond(thumb: Thumbnail, etag: &str) -> Result<Response, DownloadError> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, thumb.format.content_type())
        .body(Body::from(thumb.bytes))
        .map_err(|e| DownloadError::internal(format!("Antwort nicht baubar: {}", e)))?;
    apply_cache_headers(response.headers_mut(), etag);
    Ok(response)
}

/// Thumbnails sind an Pfad und Mtime gebunden, dürfen also lange im
/// Browser-Cache bleiben. `private`, weil die Inhalte nutzerbezogen sind.
fn apply_cache_headers(headers: &mut HeaderMap, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=86400"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_stable_and_sensitive() {
        let path = Path::new("/mnt/home/bild.jpg");
        let base = cache_key(path, 1024, 42);

        assert_eq!(
            base,
            cache_key(path, 1024, 42),
            "gleiche Eingabe, gleicher Schlüssel"
        );
        assert_eq!(base.len(), 32, "128 Bit als Hex");
        assert_ne!(base, cache_key(path, 1025, 42), "Grösse fliesst ein");
        assert_ne!(base, cache_key(path, 1024, 43), "Mtime fliesst ein");
        assert_ne!(
            base,
            cache_key(Path::new("/mnt/home/andere.jpg"), 1024, 42),
            "Pfad fliesst ein"
        );
    }

    #[test]
    fn only_known_image_extensions_are_accepted() {
        for good in ["a.JPG", "a.jpeg", "a.png", "a.WebP", "a.tiff"] {
            let ext = extension_of(Path::new(good)).unwrap_or_default();
            assert!(SUPPORTED_EXTENSIONS.contains(&ext.as_str()), "{}", good);
        }
        for bad in ["a.svg", "a.pdf", "a.exe", "a.mp4", "noextension"] {
            let ext = extension_of(Path::new(bad)).unwrap_or_default();
            assert!(!SUPPORTED_EXTENSIONS.contains(&ext.as_str()), "{}", bad);
        }
    }

    #[tokio::test]
    async fn cache_dir_inside_browsable_root_is_rejected() {
        let root = std::env::temp_dir().join(format!("rclone-thumb-root-{}", std::process::id()));
        let inside = root.join("cache");
        let _ = tokio::fs::create_dir_all(&inside).await;

        let canonical_root = match tokio::fs::canonicalize(&root).await {
            Ok(p) => p,
            Err(_) => return,
        };

        std::env::set_var("RCLONE_GUI_THUMB_CACHE", &inside);
        let result = thumb_cache_dir(&canonical_root).await;
        std::env::remove_var("RCLONE_GUI_THUMB_CACHE");

        assert!(
            result.is_err(),
            "Cache im Wurzelverzeichnis muss abgelehnt werden"
        );
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[test]
    fn resize_keeps_aspect_ratio_and_caps_the_long_edge() {
        let source = image::DynamicImage::new_rgb8(1000, 500);
        let mut encoded = Cursor::new(Vec::new());
        source
            .write_to(&mut encoded, ImageFormat::Png)
            .expect("Testbild kodierbar");

        let thumb = decode_and_resize(encoded.get_ref()).expect("Thumbnail erzeugbar");
        let decoded = image::load_from_memory(&thumb.bytes).expect("Thumbnail lesbar");

        assert_eq!(decoded.width(), MAX_EDGE);
        assert_eq!(decoded.height(), MAX_EDGE / 2);
    }

    #[test]
    fn small_images_are_never_upscaled() {
        let source = image::DynamicImage::new_rgb8(40, 20);
        let mut encoded = Cursor::new(Vec::new());
        source
            .write_to(&mut encoded, ImageFormat::Png)
            .expect("Testbild kodierbar");

        let thumb = decode_and_resize(encoded.get_ref()).expect("Thumbnail erzeugbar");
        let decoded = image::load_from_memory(&thumb.bytes).expect("Thumbnail lesbar");

        assert_eq!((decoded.width(), decoded.height()), (40, 20));
    }

    #[test]
    fn oversized_images_are_rejected_before_decoding() {
        // 20000×20000 als IHDR: der Header allein reicht, um über
        // `max_image_width`/`max_image_height` abgewiesen zu werden.
        let source = image::DynamicImage::new_luma8(1, 1);
        let mut encoded = Cursor::new(Vec::new());
        source
            .write_to(&mut encoded, ImageFormat::Png)
            .expect("Testbild kodierbar");
        let mut bytes = encoded.into_inner();
        // Breite und Höhe im IHDR (Offset 16..24) auf 20000 hochschreiben.
        bytes[16..20].copy_from_slice(&20_000u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&20_000u32.to_be_bytes());

        assert!(
            decode_and_resize(&bytes).is_err(),
            "Bild über {} Pixel Kantenlänge muss abgelehnt werden",
            MAX_SOURCE_EDGE
        );
    }

    #[test]
    fn images_with_alpha_stay_png() {
        let source = image::DynamicImage::new_rgba8(64, 64);
        let mut encoded = Cursor::new(Vec::new());
        source
            .write_to(&mut encoded, ImageFormat::Png)
            .expect("Testbild kodierbar");

        let thumb = decode_and_resize(encoded.get_ref()).expect("Thumbnail erzeugbar");
        assert!(thumb.format == ThumbFormat::Png);
    }

    #[test]
    fn garbage_input_is_a_client_error_not_a_panic() {
        let result = decode_and_resize(b"definitely not an image");
        assert!(result.is_err());
    }

    #[test]
    fn source_limit_covers_current_camera_files() {
        // Befund des Testers: ein 36-MB-TIFF fiel auf das Typ-Icon zurück.
        assert!(
            source_size_is_acceptable(36 * 1024 * 1024),
            "36-MB-Quellen müssen durchgehen"
        );
        assert!(
            source_size_is_acceptable(128 * 1024 * 1024),
            "genau am Limit ist noch erlaubt"
        );
        assert!(
            !source_size_is_acceptable(128 * 1024 * 1024 + 1),
            "darüber wird abgelehnt"
        );
    }

    #[test]
    fn a_tiff_beyond_the_old_limit_still_yields_a_thumbnail() {
        // 3600×3600 RGB unkomprimiert ≈ 37 MB – genau der Fall, der unter dem
        // alten 32-MB-Limit auf das Typ-Icon zurückfiel.
        let source = image::DynamicImage::new_rgb8(3600, 3600);
        let mut encoded = Cursor::new(Vec::new());
        source
            .write_to(&mut encoded, ImageFormat::Tiff)
            .expect("Testbild kodierbar");
        let bytes = encoded.into_inner();

        assert!(
            bytes.len() as u64 > 36 * 1024 * 1024,
            "Testdatei muss über 36 MB liegen, ist {}",
            bytes.len()
        );
        assert!(source_size_is_acceptable(bytes.len() as u64));

        let thumb = decode_and_resize(&bytes).expect("Thumbnail erzeugbar");
        let decoded = image::load_from_memory(&thumb.bytes).expect("Thumbnail lesbar");
        assert_eq!((decoded.width(), decoded.height()), (MAX_EDGE, MAX_EDGE));
    }

    #[test]
    fn decompression_bomb_is_rejected_before_allocation() {
        // Der vom Tester geprüfte Fall: 30000×30000 in einer winzigen Datei.
        // Die Pixelgrenzen greifen am Header, unabhängig von MAX_SOURCE_BYTES.
        let source = image::DynamicImage::new_luma8(1, 1);
        let mut encoded = Cursor::new(Vec::new());
        source
            .write_to(&mut encoded, ImageFormat::Png)
            .expect("Testbild kodierbar");
        let mut bytes = encoded.into_inner();
        bytes[16..20].copy_from_slice(&30_000u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&30_000u32.to_be_bytes());

        assert!(
            decode_and_resize(&bytes).is_err(),
            "30000×30000 muss vor der Allokation scheitern"
        );
    }

    // -- Cache-Aufräumen ----------------------------------------------------

    /// Eigenes Verzeichnis je Test, damit die Läufe sich nicht stören.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rclone-thumb-{}-{}-{}",
            name,
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("Testverzeichnis anlegbar");
        dir
    }

    /// Quelldateien liegen in einem Unterverzeichnis, damit sie beim Scannen
    /// des Cache-Verzeichnisses nicht selbst als Einträge gezählt werden.
    fn source_file(cache_dir: &Path, name: &str) -> PathBuf {
        let dir = cache_dir.join("quellen");
        std::fs::create_dir_all(&dir).expect("Quellverzeichnis anlegbar");
        let path = dir.join(name);
        std::fs::write(&path, b"x").expect("Quelle schreibbar");
        path
    }

    /// Legt Thumbnail und Beidatei an und setzt die Änderungszeit, damit die
    /// Reihenfolge der Verdrängung deterministisch prüfbar ist.
    fn seed_entry(cache_dir: &Path, key: &str, bytes: usize, age: Duration, source: Option<&Path>) {
        let thumb = cache_dir.join(format!("{}.jpg", key));
        std::fs::write(&thumb, vec![0u8; bytes]).expect("Eintrag schreibbar");

        if let Some(source) = source {
            let sidecar = cache_dir.join(format!("{}.{}", key, SIDECAR_EXTENSION));
            std::fs::write(&sidecar, source.to_string_lossy().as_bytes())
                .expect("Beidatei schreibbar");
        }

        let when = SystemTime::now() - age;
        let file = std::fs::File::options()
            .write(true)
            .open(&thumb)
            .expect("Eintrag öffenbar");
        file.set_times(
            std::fs::FileTimes::new()
                .set_accessed(when)
                .set_modified(when),
        )
        .expect("Zeitstempel setzbar");
    }

    fn entry_exists(cache_dir: &Path, key: &str) -> bool {
        cache_dir.join(format!("{}.jpg", key)).exists()
    }

    #[tokio::test]
    async fn eviction_hits_the_oldest_entries_first() {
        let dir = scratch("lru");
        let source = source_file(&dir, "quelle.jpg");

        // key0 ist am ältesten, key9 am jüngsten.
        for i in 0..10u64 {
            seed_entry(
                &dir,
                &format!("key{}", i),
                100,
                Duration::from_secs(1000 - i * 10),
                Some(&source),
            );
        }

        let report = cleanup_cache(&dir, 4, u64::MAX).await.expect("Lauf geht");

        assert_eq!(report.evicted, 6);
        assert_eq!(report.remaining_entries, 4);
        for i in 0..6u64 {
            assert!(
                !entry_exists(&dir, &format!("key{}", i)),
                "key{} war alt und muss weg sein",
                i
            );
        }
        for i in 6..10u64 {
            assert!(
                entry_exists(&dir, &format!("key{}", i)),
                "key{} war jung und muss bleiben",
                i
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn byte_limit_is_enforced() {
        let dir = scratch("bytes");
        let source = source_file(&dir, "quelle.jpg");

        // 8 Einträge à 1000 Byte Thumbnail plus Beidatei.
        for i in 0..8u64 {
            seed_entry(
                &dir,
                &format!("key{}", i),
                1000,
                Duration::from_secs(800 - i * 10),
                Some(&source),
            );
        }

        let report = cleanup_cache(&dir, usize::MAX, 3_000).await.expect("Lauf");

        assert!(
            report.remaining_bytes <= 3_000,
            "Byte-Limit überschritten: {}",
            report.remaining_bytes
        );

        // Gegenprobe am Dateisystem, nicht nur am Bericht.
        let mut on_disk = 0u64;
        for entry in std::fs::read_dir(&dir).expect("lesbar").flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".jpg") && name.starts_with("key") {
                on_disk += entry.metadata().map(|m| m.len()).unwrap_or(0);
            } else if name.ends_with(SIDECAR_EXTENSION) {
                on_disk += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
        assert!(on_disk <= 3_000, "auf der Platte liegen {} Bytes", on_disk);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn entries_without_source_file_are_removed() {
        let dir = scratch("orphan");
        let alive = source_file(&dir, "da.jpg");
        let gone = dir.join("quellen").join("weg.jpg");

        seed_entry(&dir, "lebt", 10, Duration::from_secs(10), Some(&alive));
        seed_entry(&dir, "tot", 10, Duration::from_secs(10), Some(&gone));
        // Ohne Beidatei ist der Zustand unbekannt – der Eintrag bleibt.
        seed_entry(&dir, "unbekannt", 10, Duration::from_secs(10), None);

        let report = cleanup_cache(&dir, usize::MAX, u64::MAX)
            .await
            .expect("Lauf");

        assert_eq!(report.orphans, 1);
        assert!(entry_exists(&dir, "lebt"));
        assert!(!entry_exists(&dir, "tot"));
        assert!(
            !dir.join(format!("tot.{}", SIDECAR_EXTENSION)).exists(),
            "Beidatei des verwaisten Eintrags muss mit weg"
        );
        assert!(entry_exists(&dir, "unbekannt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn leftovers_are_swept() {
        let dir = scratch("leftovers");

        // Beidatei ohne Thumbnail.
        std::fs::write(
            dir.join(format!("waise.{}", SIDECAR_EXTENSION)),
            b"/nirgends",
        )
        .expect("schreibbar");

        // Liegengebliebene Temp-Datei, älter als STALE_TEMP_AGE.
        let stale = dir.join("abcdef.4711.tmp");
        std::fs::write(&stale, b"halb").expect("schreibbar");
        let old = SystemTime::now() - STALE_TEMP_AGE - Duration::from_secs(60);
        let file = std::fs::File::options()
            .write(true)
            .open(&stale)
            .expect("öffenbar");
        file.set_times(
            std::fs::FileTimes::new()
                .set_accessed(old)
                .set_modified(old),
        )
        .expect("Zeitstempel setzbar");

        // Frische Temp-Datei eines laufenden Schreibvorgangs bleibt.
        let fresh = dir.join("beefbeef.4711.tmp");
        std::fs::write(&fresh, b"laeuft").expect("schreibbar");

        let report = cleanup_cache(&dir, usize::MAX, u64::MAX)
            .await
            .expect("Lauf");

        assert_eq!(report.leftovers, 2);
        assert!(!stale.exists());
        assert!(
            fresh.exists(),
            "laufender Schreibvorgang darf nicht sterben"
        );
        assert!(!dir.join(format!("waise.{}", SIDECAR_EXTENSION)).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn repeated_writes_never_exceed_the_limit() {
        let dir = scratch("stress");
        let source = source_file(&dir, "quelle.jpg");

        let thumb = Thumbnail {
            bytes: vec![7u8; 512],
            format: ThumbFormat::Jpeg,
        };

        // 200 Schreibvorgänge, zwischendurch aufgeräumt: der Cache bleibt unter
        // dem Limit, statt wie bisher unbegrenzt zu wachsen.
        for i in 0..200u32 {
            write_to_cache(&dir, &format!("{:032x}", i), &thumb, &source).await;
            if i % 25 == 0 {
                let report = cleanup_cache(&dir, 20, u64::MAX).await.expect("Lauf");
                assert!(report.remaining_entries <= 20);
            }
        }

        let report = cleanup_cache(&dir, 20, u64::MAX).await.expect("Lauf");
        assert_eq!(report.remaining_entries, 20);

        let thumbs = std::fs::read_dir(&dir)
            .expect("lesbar")
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jpg"))
            .count();
        assert_eq!(thumbs, 20, "genau 20 Cache-Einträge");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
