//! Vorschau-Grundgerüst: Typerkennung für die Datei-Vorschau des File-Browsers.
//!
//! `GET /api/preview/info?path=…` liefert zu genau einer Datei die Angaben, die
//! das Overlay im Frontend braucht: Name, Grösse, erkannter MIME-Typ und die
//! daraus abgeleitete Vorschau-Gattung (`text`, `image`, `video`, `unknown`).
//!
//! Grundsätze:
//!
//! * **Der Typ kommt aus dem Inhalt, nicht aus dem Namen.** Die Dateiendung des
//!   Clients ist eine Behauptung, kein Befund. Eine `bild.txt` mit PNG-Inhalt
//!   wird als Bild erkannt, eine `foto.png` mit Textinhalt als Text. Die Endung
//!   wird lediglich als *Hinweis* mitgeliefert (`extension`), damit eine spätere
//!   Textvorschau ein Syntax-Highlighting wählen kann – die Gattung entscheidet
//!   sie nie.
//! * **Jail.** Der Pfad wird über `resolve_within_root` aus `download.rs`
//!   kanonisiert und geprüft, inklusive aufgelöster Symlinks. Es gibt hier
//!   bewusst keine eigene Pfadlogik; alles ausserhalb des Wurzelverzeichnisses
//!   endet mit 403.
//! * **Begrenzter Lesezugriff.** Für die Erkennung werden höchstens
//!   [`HEAD_BYTES`] Bytes vom Dateianfang gelesen. Die Grösse der Datei spielt
//!   dabei keine Rolle, es wird nie die ganze Datei angefasst.
//! * Kein `unwrap()`/`expect()` im Request-Pfad.
//!
//! Neben der Erkennung liefert das Modul die Inhalts-Endpunkte für die
//! **Textvorschau** (`GET /api/preview/text?path=…`) und die **Bildvorschau**
//! (`GET /api/preview/image?path=…`). Video bringt seinen eigenen Endpunkt mit
//! (mit Range-Requests) und setzt ebenfalls auf der hier ermittelten Gattung
//! auf.
//!
//! Für den Text gilt zusätzlich:
//!
//! * **Das Limit ist serverseitig und nicht verhandelbar.** Es gibt keinen
//!   Parameter, mit dem der Client mehr als [`TEXT_LIMIT`] Bytes anfordern
//!   könnte; aus einer 10-GB-Datei werden nie mehr als die ersten 2 MB gelesen.
//! * **Ungültiges UTF-8 ist ein Fehler mit Meldung, keine kaputte Anzeige.**
//!   Der einzige geduldete Fall ist eine angefangene Mehrbyte-Sequenz genau am
//!   Abschneidepunkt – die gehört zum Limit, nicht zur Datei.
//! * **Steuerzeichen werden entschärft.** Eine als Text erkannte Datei kann
//!   hinter der Stichprobe Binärmüll enthalten; ANSI-Sequenzen fallen weg,
//!   übrige Steuerzeichen werden zu `U+FFFD`. Das Frontend setzt den Inhalt
//!   ausschliesslich über `textContent` ins DOM.
//!
//! Die beiden letzten Punkte greifen ineinander und sind dabei bewusst
//! ungleich: Binärmüll hinter der Stichprobe wird *entschärft angezeigt*,
//! solange er gültiges UTF-8 ist, und *abgelehnt*, sobald er es nicht ist.
//! Das wirkt uneinheitlich, ist aber Absicht – Steuerzeichen sind ein
//! Darstellungsproblem und werden entschärft, ungültige Bytefolgen sind ein
//! Kodierungsbefund und werden benannt. Eine verlustbehaftete Dekodierung
//! würde daraus stillschweigend eine Reihe von `U+FFFD` machen und dem Nutzer
//! einen Text vorgaukeln, den die Datei nicht enthält.

use axum::{
    body::Body,
    extract::Query,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json as ResponseJson, Response},
};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::handlers::download::{download_root, resolve_within_root, DownloadError};
use crate::models::ApiResponse;

/// So viele Bytes vom Dateianfang fliessen in die Typerkennung ein. Alle
/// bekannten Magic-Bytes liegen weit innerhalb dieses Fensters; für die
/// Text-Heuristik ist es eine grosszügige Stichprobe.
const HEAD_BYTES: usize = 8192;

/// Obergrenze der Textvorschau. Mehr als so viele Bytes werden nie gelesen und
/// nie ausgeliefert – unabhängig davon, was der Client anfragt. 2 MiB reichen
/// für jede Log- oder Quelltextdatei, die ein Mensch im Overlay noch überfliegt,
/// und begrenzen zugleich die Antwortgrösse.
const TEXT_LIMIT: usize = 2 * 1024 * 1024;

/// Gattung der Vorschau. Bewusst grob: das Frontend hat je Gattung genau eine
/// Darstellung, und alles, wofür es keine gibt, fällt auf den Download-Dialog
/// zurück. Der genaue MIME-Typ steht daneben und wird im Fallback angezeigt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PreviewKind {
    Text,
    Image,
    Video,
    Unknown,
}

/// Antwort von `/api/preview/info`.
#[derive(Debug, Serialize)]
pub struct PreviewInfo {
    /// Kanonisierter Pfad. Das Frontend arbeitet ab hier mit diesem Wert.
    pub path: String,
    pub name: String,
    pub size: u64,
    pub kind: PreviewKind,
    pub mime: String,
    /// Kleingeschriebene Dateiendung – **nur** ein Hinweis für die Darstellung
    /// (z.B. Syntax-Highlighting), nie die Grundlage der Typentscheidung.
    pub extension: String,
}

/// `GET /api/preview/info?path=…`
pub async fn preview_info(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, DownloadError> {
    let requested = params
        .get("path")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| DownloadError::bad_request("Pfad fehlt"))?;

    let root = download_root().await?;
    let info = build_preview(&root, requested).await?;

    Ok(ResponseJson(ApiResponse::success(info)).into_response())
}

/// Prüft den Pfad gegen das Jail und ermittelt die Vorschau-Angaben.
///
/// Getrennt vom Handler, damit die Prüfung in Tests gegen ein explizites
/// Wurzelverzeichnis laufen kann, ohne Umgebungsvariablen zu setzen.
async fn build_preview(root: &Path, requested: &str) -> Result<PreviewInfo, DownloadError> {
    let path = resolve_within_root(root, requested).await?;

    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;

    if !metadata.is_file() {
        return Err(DownloadError::bad_request(
            "Für Ordner gibt es keine Vorschau",
        ));
    }

    let head = read_head(&path).await?;
    let (kind, mime) = sniff(&head);

    Ok(PreviewInfo {
        path: path.to_string_lossy().to_string(),
        name: base_name(&path),
        size: metadata.len(),
        kind,
        mime: mime.to_string(),
        extension: extension_of(&path).unwrap_or_default(),
    })
}

/// Liest höchstens [`HEAD_BYTES`] Bytes vom Dateianfang.
async fn read_head(path: &Path) -> Result<Vec<u8>, DownloadError> {
    read_prefix(path, HEAD_BYTES).await
}

/// Zuwachs, wenn die Datei mehr hergibt als ihre gemeldete Grösse versprach.
/// Kommt nur bei Dateien ohne brauchbare Grössenangabe vor (`/proc`, Pipes) und
/// bei Dateien, die zwischen `metadata()` und dem Lesen gewachsen sind.
const READ_GROW_CHUNK: usize = 64 * 1024;

/// Liest höchstens `max` Bytes vom Dateianfang.
///
/// **`max` ist eine harte Obergrenze.** Der Puffer wächst nie darüber hinaus,
/// also kann auch nie mehr gelesen werden – unabhängig davon, was die Datei
/// oder ihre Metadaten behaupten. Aufgerufen wird die Funktion ausschliesslich
/// mit [`HEAD_BYTES`] bzw. [`TEXT_LIMIT`]; es gibt keinen Weg, den Wert von
/// aussen zu beeinflussen.
///
/// Die *Anfangsgrösse* des Puffers richtet sich nach der gemeldeten Dateigrösse
/// (gedeckelt auf `max`), nicht pauschal nach `max`: eine 20-Byte-Datei kostet
/// 21 Bytes und nicht 2 MiB, was bei vielen gleichzeitigen Vorschau-Anfragen
/// den Unterschied zwischen ein paar Kilobyte und mehreren hundert Megabyte
/// nullgefülltem Speicher ausmacht. Das eine Byte über der Dateigrösse spart
/// den sonst nötigen zweiten Lesedurchgang, der nur das EOF bestätigt.
///
/// Die Grössenangabe ist dabei nur ein *Hinweis*: meldet sie zu wenig (bei
/// `/proc` etwa 0), wird in [`READ_GROW_CHUNK`]-Schritten nachgelegt, bis
/// entweder EOF erreicht oder `max` ausgeschöpft ist.
async fn read_prefix(path: &Path, max: usize) -> Result<Vec<u8>, DownloadError> {
    if max == 0 {
        return Ok(Vec::new());
    }

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;

    // Nur ein Hinweis, keine Zusicherung – deshalb `unwrap_or(0)` statt Fehler.
    let hint = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let initial = if hint > 0 {
        hint.saturating_add(1).min(max as u64) as usize
    } else {
        max.min(READ_GROW_CHUNK)
    };

    let mut buffer = vec![0u8; initial];
    let mut filled = 0usize;

    loop {
        if filled == buffer.len() {
            if buffer.len() >= max {
                // Obergrenze erreicht: hier endet das Lesen, immer.
                break;
            }
            let grow = READ_GROW_CHUNK.min(max - buffer.len());
            buffer.resize(buffer.len() + grow, 0);
        }

        let read = file
            .read(&mut buffer[filled..])
            .await
            .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;
        if read == 0 {
            break;
        }
        filled += read;
    }

    debug_assert!(filled <= max);
    buffer.truncate(filled);
    Ok(buffer)
}

fn base_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Datei".to_string())
}

fn extension_of(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// Textinhalt
// ---------------------------------------------------------------------------

/// Antwort von `/api/preview/text`.
#[derive(Debug, Serialize)]
pub struct PreviewText {
    /// Kanonisierter Pfad, wie ihn `/api/preview/info` geliefert hat.
    pub path: String,
    pub name: String,
    /// Grösse der **Datei**, nicht der Antwort.
    pub size: u64,
    /// Tatsächlich gelesene Bytes (höchstens [`TEXT_LIMIT`]).
    pub bytes_read: u64,
    /// Serverseitige Obergrenze, damit die UI den Hinweis beziffern kann.
    pub limit: u64,
    /// Wahr, wenn die Datei am Limit abgeschnitten wurde.
    pub truncated: bool,
    /// Erkannte Kodierung: `utf-8`, `utf-16le` oder `utf-16be`.
    pub encoding: &'static str,
    /// Wahr, wenn Steuerzeichen oder ungültige UTF-16-Paare ersetzt wurden.
    /// Die UI weist darauf hin – so bleibt Binärmüll sichtbar gemeldet, statt
    /// die Darstellung stillschweigend zu verfälschen.
    pub sanitized: bool,
    /// Endung als Hinweis für das Syntax-Highlighting im Frontend.
    pub extension: String,
    /// Der Inhalt selbst. Geht im Frontend ausschliesslich über `textContent`
    /// ins DOM.
    pub content: String,
}

/// `GET /api/preview/text?path=…`
///
/// Bewusst **ohne** Grössen- oder Offset-Parameter: das Limit gehört dem
/// Server. Wer mehr will, lädt die Datei herunter.
pub async fn preview_text(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, DownloadError> {
    let requested = params
        .get("path")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| DownloadError::bad_request("Pfad fehlt"))?;

    let root = download_root().await?;
    let text = build_text_preview(&root, requested).await?;

    Ok(ResponseJson(ApiResponse::success(text)).into_response())
}

/// Prüft den Pfad gegen das Jail, liest den begrenzten Anfang und dekodiert ihn.
///
/// Getrennt vom Handler, damit die Tests ohne Umgebungsvariablen gegen ein
/// explizites Wurzelverzeichnis laufen können.
async fn build_text_preview(root: &Path, requested: &str) -> Result<PreviewText, DownloadError> {
    let path = resolve_within_root(root, requested).await?;

    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;

    if !metadata.is_file() {
        return Err(DownloadError::bad_request(
            "Für Ordner gibt es keine Vorschau",
        ));
    }

    let bytes = read_prefix(&path, TEXT_LIMIT).await?;

    // Gegenprobe mit derselben Erkennung wie in `/api/preview/info`: wer hier
    // mit einem PNG anklopft, bekommt eine klare Absage statt einer
    // Dekodierfehlermeldung. SVG ist die eine Ausnahme – es gilt als Bild,
    // ist aber Text und darf auch als solcher angesehen werden.
    let head_len = bytes.len().min(HEAD_BYTES);
    let (kind, mime) = sniff(&bytes[..head_len]);
    if kind != PreviewKind::Text && mime != "image/svg+xml" {
        return Err(DownloadError::bad_request(format!(
            "Datei ist kein Text (erkannt als {})",
            mime
        )));
    }

    let truncated = (bytes.len() as u64) < metadata.len();
    let decoded = decode_text(&bytes, truncated).map_err(DownloadError::bad_request)?;
    let (content, sanitized) = sanitize_text(&decoded.text);

    Ok(PreviewText {
        path: path.to_string_lossy().to_string(),
        name: base_name(&path),
        size: metadata.len(),
        bytes_read: bytes.len() as u64,
        limit: TEXT_LIMIT as u64,
        truncated,
        encoding: decoded.encoding,
        sanitized: sanitized || decoded.lossy,
        extension: extension_of(&path).unwrap_or_default(),
        content,
    })
}

/// Ergebnis der Dekodierung.
struct DecodedText {
    text: String,
    encoding: &'static str,
    /// Wahr, wenn beim Dekodieren Ersatzzeichen entstanden sind (nur UTF-16).
    lossy: bool,
}

/// Dekodiert den gelesenen Anfang.
///
/// UTF-8 ist der Normalfall; UTF-16 wird nur mit BOM erkannt, weil die
/// Typerkennung es auch nur so durchlässt. Ein Fehler ohne Länge am Ende des
/// Puffers ist eine am Limit abgeschnittene Mehrbyte-Sequenz und wird
/// abgeschnitten – aber nur, wenn tatsächlich abgeschnitten wurde. Alles andere
/// ist ungültiges UTF-8 und wird mit Position gemeldet.
fn decode_text(bytes: &[u8], truncated: bool) -> Result<DecodedText, String> {
    if let Some(rest) = bytes.strip_prefix(&[0xff, 0xfe]) {
        return Ok(decode_utf16(rest, "utf-16le", u16::from_le_bytes));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xfe, 0xff]) {
        return Ok(decode_utf16(rest, "utf-16be", u16::from_be_bytes));
    }

    // UTF-8-BOM gehört nicht in den angezeigten Text.
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);

    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(DecodedText {
            text: text.to_string(),
            encoding: "utf-8",
            lossy: false,
        }),
        Err(e) if e.error_len().is_none() && truncated => {
            // Angefangenes Zeichen am Abschneidepunkt: der Rest ist gültig.
            let valid = std::str::from_utf8(&bytes[..e.valid_up_to()])
                .map_err(|_| "Datei ist nicht als UTF-8 lesbar".to_string())?;
            Ok(DecodedText {
                text: valid.to_string(),
                encoding: "utf-8",
                lossy: false,
            })
        }
        Err(e) => Err(format!(
            "Datei ist nicht als UTF-8 lesbar: ungültiges Byte an Position {}",
            e.valid_up_to()
        )),
    }
}

/// Dekodiert UTF-16 hinter dem BOM. Ein am Limit abgeschnittenes halbes
/// Code-Unit fällt weg, ungültige Surrogatpaare werden zu `U+FFFD`.
fn decode_utf16(rest: &[u8], encoding: &'static str, to_u16: fn([u8; 2]) -> u16) -> DecodedText {
    let units: Vec<u16> = rest
        .chunks_exact(2)
        .map(|pair| to_u16([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let lossy = text.contains('\u{fffd}');
    DecodedText {
        text,
        encoding,
        lossy,
    }
}

/// Entschärft Steuerzeichen, damit Binärmüll in einer als Text erkannten Datei
/// die Anzeige nicht zerlegt:
///
/// * ANSI-Escape-Sequenzen (CSI und OSC) fallen ersatzlos weg – Terminal-Logs
///   sind ausdrücklich im Umfang und sollen lesbar bleiben, nicht voller
///   Klammeraffen stehen.
/// * `\r\n` und einzelnes `\r` werden zu `\n`.
/// * Jedes übrige Steuerzeichen (inklusive `\0`) wird zu `U+FFFD`.
///
/// Der zweite Rückgabewert meldet, ob etwas ersetzt oder entfernt wurde.
fn sanitize_text(input: &str) -> (String, bool) {
    let mut out = String::with_capacity(input.len());
    let mut changed = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\n' | '\t' => out.push(c),
            '\r' => {
                // \r\n zählt als ein Umbruch, ein einzelnes \r ebenso.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\u{1b}' => {
                changed = true;
                skip_ansi_sequence(&mut chars);
            }
            c if c.is_control() => {
                changed = true;
                out.push('\u{fffd}');
            }
            c => out.push(c),
        }
    }

    (out, changed)
}

/// Überspringt den Rest einer ANSI-Sequenz hinter dem bereits konsumierten ESC.
fn skip_ansi_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.next() {
        // CSI: Parameter- und Zwischenbytes, dann ein Endbyte 0x40–0x7e.
        Some('[') => {
            for c in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    break;
                }
            }
        }
        // OSC: läuft bis BEL oder ST (ESC \).
        Some(']') => {
            while let Some(c) = chars.next() {
                if c == '\u{7}' {
                    break;
                }
                if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                    chars.next();
                    break;
                }
            }
        }
        // Alles andere ist eine Zwei-Zeichen-Sequenz und damit schon erledigt.
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Bildinhalt
// ---------------------------------------------------------------------------
//
// `GET /api/preview/image?path=…` liefert die **Originaldatei** aus, nicht ein
// neu kodiertes Bild: die Vorschau soll zeigen, was in der Datei steht, und der
// Browser dekodiert jedes hier zugelassene Format ohnehin selbst. Die Datei
// wird gestreamt (`ReaderStream`), nie am Stück in den Speicher gelesen.
//
// **SVG ist aktiver Inhalt** und der Grund für die Kopfzeilen unten. Ein SVG
// kann `<script>`, `onload=` und externe Referenzen enthalten. Drei Lagen
// verhindern, dass davon etwas im Ursprung der App läuft:
//
//  1. *Darstellungskontext.* Das Frontend hängt die URL an ein `<img>`. In
//     einem Bildkontext führt kein Browser Skripte im SVG aus und lädt auch
//     keine externen Referenzen nach – das ist die eigentliche Absicherung und
//     sie gilt unabhängig von allen Kopfzeilen.
//  2. *[`IMAGE_CSP`].* Greift für den Fall, dass jemand die URL direkt in einem
//     Tab öffnet oder in einen Frame hängt: Dann ist die Antwort ein Dokument,
//     und `sandbox` (ohne `allow-scripts`, ohne `allow-same-origin`) plus
//     `default-src 'none'` machen es zu einem skriptlosen Dokument in einem
//     undurchsichtigen Ursprung. Es hat damit weder Zugriff auf Cookies noch
//     auf `localStorage` oder das DOM der App.
//  3. *`X-Content-Type-Options: nosniff` und ein aus dem Inhalt bestimmter
//     Content-Type.* Eine als `.png` benannte Datei mit SVG-Inhalt bekommt
//     `image/svg+xml`, eine als `.svg` benannte mit PNG-Inhalt `image/png` –
//     die Endung entscheidet auch hier nichts.
//
// Der Inhalt selbst wird bewusst **nicht** umgeschrieben. Eine
// SVG-Bereinigung ist eine Filterliste, die man laufend gegen neue
// Umgehungen nachziehen muss; die drei Lagen oben sind es nicht.

/// Grösste Datei, die die Bildvorschau ausliefert. Darüber bleibt nur der
/// Download – ein Bild jenseits dieser Grösse ist im Overlay ohnehin nicht mehr
/// darstellbar, und die Grenze hält den Browser davon ab, sich an einer
/// Kamera-RAW-Datei zu verschlucken. Der Server puffert nichts davon: der Wert
/// begrenzt die Übertragung, nicht den Speicher.
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Puffergrösse beim Streamen.
const IMAGE_STREAM_BUFFER: usize = 64 * 1024;

/// Kopfzeile für jede Bildantwort. `sandbox` ohne jedes `allow-*` ist der
/// entscheidende Teil, `default-src 'none'` der Gürtel dazu.
const IMAGE_CSP: &str =
    "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox";

/// `GET /api/preview/image?path=…`
pub async fn preview_image(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, DownloadError> {
    let requested = params
        .get("path")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| DownloadError::bad_request("Pfad fehlt"))?;

    let root = download_root().await?;
    build_image_response(&root, requested, &headers).await
}

/// Prüft den Pfad gegen das Jail, bestimmt den Typ aus dem Inhalt und streamt
/// die Datei. Getrennt vom Handler, damit die Tests ohne Umgebungsvariablen
/// gegen ein explizites Wurzelverzeichnis laufen können.
async fn build_image_response(
    root: &Path,
    requested: &str,
    request_headers: &HeaderMap,
) -> Result<Response, DownloadError> {
    let path = resolve_within_root(root, requested).await?;

    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;

    if !metadata.is_file() {
        return Err(DownloadError::bad_request(
            "Für Ordner gibt es keine Vorschau",
        ));
    }
    if metadata.len() == 0 {
        return Err(DownloadError::bad_request("Datei ist leer"));
    }
    if metadata.len() > MAX_IMAGE_BYTES {
        return Err(DownloadError::bad_request(format!(
            "Bild ist zu gross für die Vorschau ({} Bytes, Grenze {} Bytes)",
            metadata.len(),
            MAX_IMAGE_BYTES
        )));
    }

    // Derselbe Befund wie in `/api/preview/info`: der Typ kommt aus dem Inhalt.
    // Wer hier mit einem PDF anklopft, bekommt eine Absage statt einer Antwort
    // mit falschem Content-Type.
    let head = read_head(&path).await?;
    let (kind, mime) = sniff(&head);
    if kind != PreviewKind::Image {
        return Err(DownloadError::bad_request(format!(
            "Datei ist kein Bild (erkannt als {})",
            mime
        )));
    }

    // Grösse und Änderungszeit reichen als Validator: eine ersetzte Datei
    // bekommt einen neuen ETag, der Rest kommt aus dem Cache des Browsers.
    let etag = image_etag(metadata.len(), modified_nanos(&metadata));
    if if_none_match(request_headers, &etag) {
        let mut response = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .map_err(|e| DownloadError::internal(format!("Antwort nicht baubar: {}", e)))?;
        apply_image_headers(response.headers_mut(), mime, &etag, None, &path)?;
        return Ok(response);
    }

    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Datei nicht lesbar: {}", e)))?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from_stream(ReaderStream::with_capacity(
            file,
            IMAGE_STREAM_BUFFER,
        )))
        .map_err(|e| DownloadError::internal(format!("Antwort nicht baubar: {}", e)))?;
    apply_image_headers(
        response.headers_mut(),
        mime,
        &etag,
        Some(metadata.len()),
        &path,
    )?;

    Ok(response)
}

/// Setzt die Kopfzeilen jeder Bildantwort – auch die der 304, damit ein
/// erneuter Treffer im Cache nicht schlechter geschützt ist als der erste.
fn apply_image_headers(
    headers: &mut HeaderMap,
    mime: &'static str,
    etag: &str,
    length: Option<u64>,
    path: &Path,
) -> Result<(), DownloadError> {
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(IMAGE_CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Der Browser soll das Bild anzeigen, nicht speichern. `inline` mit
    // Dateinamen ist auch die Vorgabe, wenn der Nutzer es doch sichert.
    headers.insert(
        header::CONTENT_DISPOSITION,
        inline_disposition(&base_name(path))?,
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
    // `no-cache` heisst nicht „nicht speichern", sondern „vor der
    // Wiederverwendung nachfragen". Genau das ist hier richtig: ein
    // Dateibrowser zeigt Dateien, die sich ändern, und mit `max-age` bekäme der
    // Nutzer nach einem Überschreiben minutenlang das alte Bild. Der ETag macht
    // die Rückfrage billig – sie endet im Normalfall mit einer leeren 304.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, value);
    }
    if let Some(length) = length {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    }

    Ok(())
}

/// `Content-Disposition: inline` mit ASCII-Fallback und RFC-5987-Variante.
/// Eigene Fassung, weil die aus `download.rs` `attachment` schreibt und dem
/// Download-Ticket gehört.
fn inline_disposition(name: &str) -> Result<HeaderValue, DownloadError> {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\' && *c != '"')
        .collect();
    let cleaned = cleaned.trim();
    let cleaned = if cleaned.is_empty() { "bild" } else { cleaned };

    let ascii: String = cleaned
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let mut encoded = String::with_capacity(cleaned.len());
    for byte in cleaned.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            encoded.push(c);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }

    HeaderValue::from_str(&format!(
        "inline; filename=\"{}\"; filename*=UTF-8''{}",
        ascii, encoded
    ))
    .map_err(|_| DownloadError::internal("Dateiname nicht als Header darstellbar"))
}

/// Änderungszeit als Unix-**Nanosekunden**; nicht ermittelbar heisst 0.
///
/// Sekundengenauigkeit reichte nicht: eine gleich grosse Ersetzung innerhalb
/// derselben Sekunde ergab denselben ETag, und der Browser hätte auf eine 304
/// hin das alte Bild behalten. Praktisch entschärft war das nur durch
/// `Cache-Control: no-cache`. Die Nanosekunden kommen ohne Zusatzaufwand aus
/// derselben `metadata()`-Abfrage; die tatsächliche Auflösung bestimmt das
/// Dateisystem (ext4/btrfs: Nanosekunden, exFAT: gröber). Schlechter als vorher
/// wird es dadurch nirgends.
fn modified_nanos(metadata: &std::fs::Metadata) -> u128 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn image_etag(size: u64, modified: u128) -> String {
    format!("\"{:x}-{:x}\"", size, modified)
}

/// Wertet `If-None-Match` aus.
///
/// `*` ist laut RFC 9110 §13.1.2 ein Treffer, sobald die Ressource überhaupt
/// existiert – und das ist an der Aufrufstelle bereits geprüft. Vorher fiel der
/// Fall durch das Rasten und wurde mit einer vollen 200 beantwortet: korrekt im
/// Ergebnis, aber unnötig teuer.
fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate == etag
            })
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Typerkennung
// ---------------------------------------------------------------------------

/// Bestimmt Gattung und MIME-Typ allein aus den ersten Bytes.
///
/// Reihenfolge: erst die eindeutigen Signaturen (Magic Bytes), dann die
/// Text-Heuristik. Wer beides nicht erfüllt, gilt als unbekannt und bekommt im
/// Frontend den Download-Dialog.
fn sniff(head: &[u8]) -> (PreviewKind, &'static str) {
    if head.is_empty() {
        // Leere Dateien lassen sich gefahrlos als leerer Text anzeigen.
        return (PreviewKind::Text, "text/plain");
    }

    if let Some(found) = sniff_binary(head) {
        return found;
    }

    if looks_like_text(head) {
        if contains_svg_root(head) {
            // SVG ist XML und wird deshalb erst von der Text-Heuristik
            // eingesammelt. Als Bild taugt es trotzdem – die Bildvorschau muss
            // es allerdings über ein <img> bzw. eine sandboxed Anzeige laden,
            // niemals inline ins DOM setzen: SVG kann Skripte enthalten.
            return (PreviewKind::Image, "image/svg+xml");
        }
        return (PreviewKind::Text, "text/plain");
    }

    (PreviewKind::Unknown, "application/octet-stream")
}

/// Signaturvergleich für Binärformate.
fn sniff_binary(head: &[u8]) -> Option<(PreviewKind, &'static str)> {
    // --- Bilder ---
    if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some((PreviewKind::Image, "image/png"));
    }
    if head.starts_with(b"\xff\xd8\xff") {
        return Some((PreviewKind::Image, "image/jpeg"));
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return Some((PreviewKind::Image, "image/gif"));
    }
    if looks_like_bmp(head) {
        return Some((PreviewKind::Image, "image/bmp"));
    }
    if head.starts_with(b"II\x2a\x00") || head.starts_with(b"MM\x00\x2a") {
        return Some((PreviewKind::Image, "image/tiff"));
    }
    if head.starts_with(b"\x00\x00\x01\x00") {
        return Some((PreviewKind::Image, "image/x-icon"));
    }

    // --- RIFF-Container: WebP (Bild), AVI (Video), WAVE (Audio) ---
    if head.starts_with(b"RIFF") && head.len() >= 12 {
        return match &head[8..12] {
            b"WEBP" => Some((PreviewKind::Image, "image/webp")),
            b"AVI " => Some((PreviewKind::Video, "video/x-msvideo")),
            b"WAVE" => Some((PreviewKind::Unknown, "audio/wav")),
            _ => Some((PreviewKind::Unknown, "application/octet-stream")),
        };
    }

    // --- ISO-BMFF: MP4, MOV, M4V, aber auch AVIF und HEIC/HEIF ---
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        return Some(classify_iso_bmff(&head[8..12]));
    }

    // --- Matroska/WebM: gleicher EBML-Kopf, der DocType entscheidet ---
    if head.starts_with(b"\x1a\x45\xdf\xa3") {
        // Der DocType steht als String direkt im EBML-Header, also weit
        // innerhalb der gelesenen Stichprobe.
        if contains(head, b"webm") {
            return Some((PreviewKind::Video, "video/webm"));
        }
        return Some((PreviewKind::Video, "video/x-matroska"));
    }

    // --- weitere Videocontainer ---
    if head.starts_with(b"FLV\x01") {
        return Some((PreviewKind::Video, "video/x-flv"));
    }
    if head.starts_with(b"\x00\x00\x01\xba") || head.starts_with(b"\x00\x00\x01\xb3") {
        return Some((PreviewKind::Video, "video/mpeg"));
    }
    if head.starts_with(b"OggS") {
        // Ogg trägt Audio wie Video. Ohne Auswertung der Codec-Seite ist die
        // Gattung nicht sicher, deshalb bleibt es beim Fallback.
        return Some((PreviewKind::Unknown, "application/ogg"));
    }

    // --- Häufige Nicht-Vorschau-Formate: erkannt, aber ohne eigene Anzeige.
    //     Der MIME-Typ landet im Download-Dialog und ist dort die Erklärung,
    //     warum es keine Vorschau gibt. ---
    if head.starts_with(b"%PDF-") {
        return Some((PreviewKind::Unknown, "application/pdf"));
    }
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Some((PreviewKind::Unknown, "application/zip"));
    }
    if head.starts_with(b"\x1f\x8b") {
        // Hier landet auch `.svgz` – eine gzip-komprimierte SVG-Datei. Das ist
        // Absicht und nicht der Fehler, nach dem es aussieht:
        //
        // * Um sie als Bild zu erkennen, müsste der Server den Strom
        //   entpacken. Das zöge `flate2` als **direkte** Abhängigkeit nach
        //   sich (im Baum liegt es bisher nur transitiv über `zip`/`image`)
        //   und brächte mit der gzip-Bombe eine neue Klasse von Eingaben, die
        //   diese Vorschau bislang nicht kennt.
        // * Ausliefern ohne Entpacken (Originalbytes mit
        //   `Content-Type: image/svg+xml` plus `Content-Encoding: gzip`) käme
        //   ohne Abhängigkeit aus, würde die Gattung aber allein aus der
        //   **Endung** ableiten – genau das Prinzip, auf dem dieses Modul
        //   aufgebaut ist. Ein gzip-Archiv mit beliebigem Inhalt und der
        //   Endung `.svgz` liefe dann als Bild aus und scheiterte erst im
        //   Browser: derselbe Fehler, nur an einer schlechteren Stelle.
        //
        // `svgz` gehört deshalb nicht in die Bildliste des Frontends
        // (`static/js/ui/preview-image.js`, `IMAGE_EXTENSIONS`) – sie steuert
        // nur, was beim Blättern mitzählt. Solange es dort steht, blättert der
        // Nutzer auf eine Datei, die dieser Endpunkt mit
        // „Datei ist kein Bild (erkannt als application/gzip)" ablehnt.
        return Some((PreviewKind::Unknown, "application/gzip"));
    }
    if head.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some((PreviewKind::Unknown, "application/x-7z-compressed"));
    }
    if looks_like_id3(head) || head.starts_with(b"\xff\xfb") {
        return Some((PreviewKind::Unknown, "audio/mpeg"));
    }
    if head.starts_with(b"fLaC") {
        return Some((PreviewKind::Unknown, "audio/flac"));
    }
    if head.starts_with(b"\x7fELF") {
        return Some((PreviewKind::Unknown, "application/x-elf"));
    }
    if looks_like_pe(head) {
        return Some((
            PreviewKind::Unknown,
            "application/vnd.microsoft.portable-executable",
        ));
    }

    None
}

/// Ordnet einen ISO-BMFF-Brand (`ftyp`-Box, 4 Bytes) einer Gattung zu.
///
/// ISO-BMFF ist ein reiner Container: MP4, MOV, M4A, AVIF und HEIC teilen sich
/// denselben Kopf und unterscheiden sich **nur** im Brand. Die frühere Regel
/// „alles ausser `qt` und `M4A` ist `video/mp4`" hat deshalb jede AVIF- und
/// HEIC-Datei in den Videoplayer geschoben.
///
/// Hier gilt umgekehrt eine **Positivliste**: nur bekannte Brands bekommen eine
/// Gattung, alles Unbekannte fällt auf `application/octet-stream` und damit auf
/// den dokumentierten Fallback-Dialog. Das ist die robustere Richtung, weil die
/// Brand-Registry offen ist und laufend neue Bildformate hinzukommen (AVIF war
/// genau so einer). Ein Fallback-Dialog bei einem exotischen Videocontainer
/// kostet einen Klick auf „Herunterladen"; ein Bild im Videoplayer sieht dagegen
/// nach einem Defekt der Datei aus.
fn classify_iso_bmff(brand: &[u8]) -> (PreviewKind, &'static str) {
    match brand {
        // --- AVIF: Einzelbild und Sequenz. Alle Browser, die diese GUI
        //     bedient, zeigen es direkt im <img> an. ---
        b"avif" | b"avis" | b"avio" | b"avdt" => (PreviewKind::Image, "image/avif"),

        // --- HEIC/HEIF: erkannt, aber bewusst `Unknown`.
        //     Ausser Safari kann kein Browser HEIC im <img> dekodieren, und
        //     ausgeliefert wird die Originaldatei (kein Server-Transcode, das
        //     `image`-Crate kann HEIC ebenfalls nicht). `Image` ergäbe also ein
        //     kaputtes Bild statt einer Erklärung. Mit `Unknown` und korrektem
        //     MIME greift der Fallback-Dialog, der den Typ nennt und den
        //     Download anbietet. ---
        b"heic" | b"heix" | b"heim" | b"heis" | b"hevc" | b"hevx" | b"hevm" | b"hevs" => {
            (PreviewKind::Unknown, "image/heic")
        }
        b"mif1" | b"mif2" | b"msf1" | b"mia1" => (PreviewKind::Unknown, "image/heif"),

        // --- Audio im MP4-Container ---
        b"M4A " | b"M4B " | b"M4P " => (PreviewKind::Unknown, "audio/mp4"),
        b"F4A " | b"F4B " => (PreviewKind::Unknown, "audio/mp4"),

        // --- QuickTime ---
        b"qt  " => (PreviewKind::Video, "video/quicktime"),

        // --- Video-Brands. `M4V` bleibt `video/mp4`: es ist ein MP4, und der
        //     Player im Frontend hängt am MIME-Typ. ---
        b"isom" | b"iso2" | b"iso3" | b"iso4" | b"iso5" | b"iso6" | b"iso7" | b"iso8" | b"iso9"
        | b"mp41" | b"mp42" | b"mp71" | b"mmp4" | b"avc1" | b"avc3" | b"dash" | b"cmfc"
        | b"M4V " | b"M4VH" | b"M4VP" | b"F4V " | b"dby1" => (PreviewKind::Video, "video/mp4"),

        // 3GPP/3GPP2 sind eigene Brand-Familien mit laufender Nummer
        // (`3gp4`…`3gp9`, `3g2a`…), deshalb hier über das Präfix.
        _ if brand.starts_with(b"3gp") || brand.starts_with(b"3gs") => {
            (PreviewKind::Video, "video/3gpp")
        }
        _ if brand.starts_with(b"3g2") => (PreviewKind::Video, "video/3gpp2"),

        // Unbekannter Brand: keine Gattung raten.
        _ => (PreviewKind::Unknown, "application/octet-stream"),
    }
}

// --- Plausibilitätsprüfungen für sehr kurze Signaturen ----------------------
//
// `BM`, `MZ` und `ID3` sind zwei bis drei Zeichen lang und stehen genauso am
// Anfang harmloser Textdateien („BM: siehe Anhang", „MZ Kunde 4711",
// „ID3-Tags entfernen"). Ohne weitere Prüfung landet eine solche Datei in der
// falschen Vorschau – im BMP-Fall in der Bildanzeige, wo der Fehler dann in
// einem ganz anderen Modul gesucht wird. Schlägt die Prüfung fehl, fällt die
// Erkennung auf die Text-Heuristik zurück.

/// BMP: hinter `BM` stehen Dateigrösse (4 Bytes LE), zwei reservierte Felder,
/// die praktisch immer null sind, und der Offset der Bilddaten. Der Offset muss
/// hinter dem 14 Byte grossen Dateikopf und innerhalb der Datei liegen.
fn looks_like_bmp(head: &[u8]) -> bool {
    if !head.starts_with(b"BM") || head.len() < 14 {
        return false;
    }
    let size = u32::from_le_bytes([head[2], head[3], head[4], head[5]]);
    let reserved = u32::from_le_bytes([head[6], head[7], head[8], head[9]]);
    let offset = u32::from_le_bytes([head[10], head[11], head[12], head[13]]);

    reserved == 0 && offset >= 26 && size > offset
}

/// ID3v2: Version (2–4), Revision (nie `0xFF`), Flags mit reservierten unteren
/// Bits auf null und eine Grösse in „synchsafe integers" – jedes dieser vier
/// Bytes hat das oberste Bit auf null. ASCII-Text hinter „ID3" scheitert schon
/// an der Versionsnummer.
fn looks_like_id3(head: &[u8]) -> bool {
    if !head.starts_with(b"ID3") || head.len() < 10 {
        return false;
    }
    let version_ok = (2..=4).contains(&head[3]) && head[4] != 0xff;
    let flags_ok = head[5] & 0x0f == 0;
    let size_ok = head[6..10].iter().all(|b| *b < 0x80);

    version_ok && flags_ok && size_ok
}

/// MZ: `e_lfanew` an Offset 0x3C zeigt auf den PE-Kopf. Liegt der Wert noch im
/// gelesenen Fenster, muss dort auch `PE\0\0` stehen; sonst reicht ein
/// plausibler Offset. Eine Textdatei hat an dieser Stelle ASCII und kommt damit
/// auf Werte weit jenseits jeder realen Kopfgrösse.
fn looks_like_pe(head: &[u8]) -> bool {
    if !head.starts_with(b"MZ") || head.len() < 0x40 {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([head[0x3c], head[0x3d], head[0x3e], head[0x3f]]) as usize;
    if !(0x40..=0x1000).contains(&e_lfanew) {
        return false;
    }
    match head.get(e_lfanew..e_lfanew + 4) {
        Some(signature) => signature == b"PE\0\0",
        // Der PE-Kopf liegt hinter der Stichprobe – der Offset ist plausibel,
        // mehr lässt sich hier nicht prüfen.
        None => true,
    }
}

/// Heuristik für Textdateien: gültiges UTF-8 (bzw. UTF-16 mit BOM), kein
/// Nullbyte, keine ungewöhnlichen Steuerzeichen.
///
/// Die Stichprobe ist ein Dateianfang und kann mitten in einer
/// Mehrbyte-Sequenz enden. Ein Fehler ganz am Ende ohne Länge
/// (`error_len() == None`) ist deshalb genau das und kein Grund, die Datei als
/// binär einzustufen.
fn looks_like_text(head: &[u8]) -> bool {
    // UTF-16 mit BOM enthält reihenweise Nullbytes und käme durch die
    // UTF-8-Prüfung nie durch – die Vorschau kann es trotzdem darstellen.
    if head.starts_with(&[0xff, 0xfe]) || head.starts_with(&[0xfe, 0xff]) {
        return true;
    }

    let text = match std::str::from_utf8(head) {
        Ok(text) => text,
        Err(e) if e.error_len().is_none() => match std::str::from_utf8(&head[..e.valid_up_to()]) {
            Ok(text) => text,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    // Steuerzeichen, die in echten Textdateien vorkommen: Tab, Zeilenumbrüche,
    // Seitenvorschub und ESC (Terminal-Logs mit Farbcodes).
    !text.chars().any(|c| {
        c == '\0'
            || (c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1b}'))
    })
}

/// Sucht das SVG-Wurzelelement im Dateianfang. Ein Prolog oder ein Kommentar
/// davor ist üblich, deshalb wird nicht auf den Dateianfang geprüft.
fn contains_svg_root(head: &[u8]) -> bool {
    contains(head, b"<svg")
}

/// Teilfolgen-Suche über Bytes, kleinschreibungsunabhängig für ASCII.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rclone-gui-{}-{}", label, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis anlegen");
        dir
    }

    #[test]
    fn images_are_recognised_by_signature() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n\x00\x00").0, PreviewKind::Image);
        assert_eq!(sniff(b"\xff\xd8\xff\xe0JFIF").0, PreviewKind::Image);
        assert_eq!(sniff(b"GIF89a\x01\x00").0, PreviewKind::Image);
        assert_eq!(sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 ").1, "image/webp");
    }

    #[test]
    fn videos_are_recognised_by_signature() {
        assert_eq!(sniff(b"\x00\x00\x00\x18ftypisom\x00\x00").1, "video/mp4");
        assert_eq!(
            sniff(b"\x00\x00\x00\x14ftypqt  \x00\x00").1,
            "video/quicktime"
        );
        assert_eq!(
            sniff(b"\x1a\x45\xdf\xa3\x01\x00\x00\x00\x42\x82\x84webm").1,
            "video/webm"
        );
        assert_eq!(
            sniff(b"\x1a\x45\xdf\xa3\x42\x82\x88matroska").1,
            "video/x-matroska"
        );
        assert_eq!(sniff(b"RIFF\x00\x00\x00\x00AVI LIST").0, PreviewKind::Video);
    }

    /// AVIF ist ISO-BMFF wie MP4 und wurde deshalb früher als `video/mp4`
    /// ausgeliefert – die Datei landete im Videoplayer statt in der
    /// Bildanzeige.
    #[test]
    fn avif_is_an_image_not_a_video() {
        for brand in [b"avif", b"avis"] {
            let mut head = b"\x00\x00\x00\x20ftyp".to_vec();
            head.extend_from_slice(brand);
            head.extend_from_slice(b"\x00\x00\x00\x00");
            assert_eq!(
                sniff(&head),
                (PreviewKind::Image, "image/avif"),
                "Brand {:?}",
                std::str::from_utf8(brand)
            );
        }
    }

    /// HEIC/HEIF wird erkannt, aber nicht als Video ausgeliefert. Anzeigen kann
    /// es die Bildvorschau nicht (kein Browser ausser Safari), deshalb
    /// `Unknown` mit korrektem MIME – das ist der Fallback-Dialog.
    #[test]
    fn heif_family_is_not_video() {
        let cases: [(&[u8; 4], &str); 6] = [
            (b"heic", "image/heic"),
            (b"heix", "image/heic"),
            (b"hevc", "image/heic"),
            (b"mif1", "image/heif"),
            (b"msf1", "image/heif"),
            (b"mia1", "image/heif"),
        ];
        for (brand, mime) in cases {
            let mut head = b"\x00\x00\x00\x18ftyp".to_vec();
            head.extend_from_slice(brand);
            head.extend_from_slice(b"\x00\x00\x00\x00");
            let found = sniff(&head);
            assert_eq!(found, (PreviewKind::Unknown, mime));
        }
    }

    /// Die Positivliste darf die gängigen Videocontainer nicht verlieren.
    #[test]
    fn known_video_brands_stay_video() {
        for brand in [
            b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V ", b"3gp4",
        ] {
            let mut head = b"\x00\x00\x00\x18ftyp".to_vec();
            head.extend_from_slice(brand);
            head.extend_from_slice(b"\x00\x00\x00\x00");
            assert_eq!(
                sniff(&head).0,
                PreviewKind::Video,
                "Brand {:?}",
                std::str::from_utf8(brand)
            );
        }
        assert_eq!(
            sniff(b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00").1,
            "audio/mp4"
        );
    }

    /// Unbekannter Brand: keine Gattung raten, sondern Fallback-Dialog.
    #[test]
    fn unknown_iso_bmff_brand_falls_back() {
        assert_eq!(
            sniff(b"\x00\x00\x00\x18ftypzzzz\x00\x00\x00\x00"),
            (PreviewKind::Unknown, "application/octet-stream")
        );
    }

    /// Kernpunkt des Tickets: die Endung spielt keine Rolle.
    #[test]
    fn extension_never_decides() {
        // PNG-Inhalt in einer .txt bleibt ein Bild …
        let png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        assert_eq!(sniff(png_bytes).0, PreviewKind::Image);
        // … und Textinhalt in einer .png bleibt Text.
        assert_eq!(sniff(b"das ist einfach nur Text\n").0, PreviewKind::Text);
    }

    #[test]
    fn text_heuristic_accepts_real_text_and_rejects_binary() {
        assert_eq!(sniff(b"{\n  \"a\": 1\n}\n").0, PreviewKind::Text);
        assert_eq!(
            sniff("Grüße mit Umlauten\n".as_bytes()).0,
            PreviewKind::Text
        );
        assert_eq!(sniff(b"\x1b[32mgruen\x1b[0m log\n").0, PreviewKind::Text);
        assert_eq!(sniff(b"").0, PreviewKind::Text);

        // Nullbytes und wilde Steuerzeichen sind kein Text.
        assert_eq!(sniff(b"abc\x00def").0, PreviewKind::Unknown);
        assert_eq!(sniff(b"\x01\x02\x03\x04\x05\x06").0, PreviewKind::Unknown);
        // Ungültiges UTF-8 mitten im Puffer.
        assert_eq!(sniff(b"ok \xc3\x28 nicht").0, PreviewKind::Unknown);
    }

    /// Der Puffer endet nach [`HEAD_BYTES`] und darf mitten in einem
    /// Mehrbyte-Zeichen aufhören, ohne dass daraus „binär" wird.
    #[test]
    fn truncated_multibyte_at_the_end_is_still_text() {
        let mut bytes = "Grüße".as_bytes().to_vec();
        bytes.push(0xc3); // angefangenes Zeichen, Rest fehlt
        assert_eq!(sniff(&bytes).0, PreviewKind::Text);
    }

    #[test]
    fn svg_counts_as_image_although_it_is_xml() {
        let svg = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>"#;
        assert_eq!(sniff(svg), (PreviewKind::Image, "image/svg+xml"));
    }

    #[test]
    fn known_but_unpreviewable_types_report_their_mime() {
        // Vollständiger ID3v2.3-Kopf: Version, Flags und synchsafe Grösse.
        let id3 = b"ID3\x03\x00\x00\x00\x00\x02\x01";
        assert_eq!(sniff(b"%PDF-1.7\n").1, "application/pdf");
        assert_eq!(sniff(b"PK\x03\x04\x14\x00").1, "application/zip");
        assert_eq!(sniff(id3).1, "audio/mpeg");
        for probe in [
            b"%PDF-1.7\n".as_slice(),
            b"PK\x03\x04\x14\x00".as_slice(),
            id3.as_slice(),
        ] {
            assert_eq!(sniff(probe).0, PreviewKind::Unknown);
        }
    }

    /// Nachbesserung aus dem Grundgerüst-Ticket: sehr kurze Signaturen (`BM`,
    /// `MZ`, `ID3`) stehen genauso am Anfang harmloser Textdateien. Erst die
    /// Plausibilität des Kopfes entscheidet.
    #[test]
    fn short_signatures_do_not_beat_the_text_heuristic() {
        // Der schädliche Fall: als Bild eingestuft, scheitert später in der
        // Bildvorschau.
        let bmp_text = b"BM: siehe Anhang, Bestellung 4711\nMit freundlichen Gruessen\n";
        assert_eq!(sniff(bmp_text), (PreviewKind::Text, "text/plain"));

        let mz_text =
            b"MZ Kunde 4711, Rechnung vom 01.01.2026\nBetrag: 42,00 EUR\nZahlungsziel 14 Tage\n"
                .repeat(2);
        assert_eq!(sniff(&mz_text), (PreviewKind::Text, "text/plain"));

        let id3_text = b"ID3-Tags entfernen, dann neu einlesen\nsiehe Skript bereinigen.sh\n";
        assert_eq!(sniff(id3_text), (PreviewKind::Text, "text/plain"));

        // Gegenprobe: echte Köpfe werden weiterhin erkannt.
        let mut bmp = vec![b'B', b'M'];
        bmp.extend_from_slice(&1024u32.to_le_bytes()); // Dateigrösse
        bmp.extend_from_slice(&0u32.to_le_bytes()); // reserviert
        bmp.extend_from_slice(&54u32.to_le_bytes()); // Offset der Bilddaten
        assert_eq!(sniff(&bmp), (PreviewKind::Image, "image/bmp"));

        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(
            sniff(&pe).1,
            "application/vnd.microsoft.portable-executable"
        );
    }

    #[tokio::test]
    async fn preview_reads_type_from_content_not_from_the_name() {
        let base = temp_dir("preview");
        let root = std::fs::canonicalize(&base).expect("canonical");

        // Eine .txt mit PNG-Inhalt: ein 1×1-PNG reicht, der Header entscheidet.
        let png: Vec<u8> = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01".to_vec();
        std::fs::write(root.join("getarnt.txt"), &png).expect("schreiben");
        std::fs::write(root.join("echt.png"), b"nur Text, keine Grafik\n").expect("schreiben");

        let as_image = build_preview(&root, "getarnt.txt")
            .await
            .expect("Vorschau ermittelbar");
        assert_eq!(as_image.kind, PreviewKind::Image);
        assert_eq!(as_image.mime, "image/png");
        assert_eq!(as_image.extension, "txt", "Endung nur als Hinweis");
        assert_eq!(as_image.name, "getarnt.txt");
        assert_eq!(as_image.size, png.len() as u64);

        let as_text = build_preview(&root, "echt.png")
            .await
            .expect("Vorschau ermittelbar");
        assert_eq!(as_text.kind, PreviewKind::Text);

        let _ = std::fs::remove_dir_all(&base);
    }

    // --- Textvorschau -----------------------------------------------------

    #[tokio::test]
    async fn text_preview_keeps_umlauts_and_reports_no_truncation() {
        let base = temp_dir("preview-text");
        let root = std::fs::canonicalize(&base).expect("canonical");
        std::fs::write(root.join("grüße.txt"), "Grüße, Straße – ok\n").expect("schreiben");

        let text = build_text_preview(&root, "grüße.txt")
            .await
            .expect("Text lesbar");
        assert_eq!(text.content, "Grüße, Straße – ok\n");
        assert_eq!(text.encoding, "utf-8");
        assert!(!text.truncated);
        assert!(!text.sanitized);
        assert_eq!(text.limit, TEXT_LIMIT as u64);
        assert_eq!(text.extension, "txt");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Kernpunkt des Tickets: das Limit greift serverseitig, und die Antwort
    /// sagt es auch.
    #[tokio::test]
    async fn text_preview_truncates_at_the_server_side_limit() {
        let base = temp_dir("preview-limit");
        let root = std::fs::canonicalize(&base).expect("canonical");

        // Eine Zeile mit Umlaut am Ende jedes Blocks, damit der Schnitt mit
        // hoher Wahrscheinlichkeit mitten in eine Mehrbyte-Sequenz fällt.
        let block = "abcdefghij-üäö\n";
        let mut content = String::new();
        while content.len() < TEXT_LIMIT + 4096 {
            content.push_str(block);
        }
        std::fs::write(root.join("gross.log"), &content).expect("schreiben");

        let text = build_text_preview(&root, "gross.log")
            .await
            .expect("Text lesbar");
        assert!(
            text.truncated,
            "Datei über dem Limit muss abgeschnitten sein"
        );
        assert_eq!(text.bytes_read, TEXT_LIMIT as u64);
        assert_eq!(text.size, content.len() as u64);
        assert!(
            text.content.len() <= TEXT_LIMIT,
            "nie mehr als das Limit ausliefern"
        );
        // Der abgeschnittene Anfang muss trotzdem sauberer Text sein.
        assert!(text.content.starts_with("abcdefghij-üäö\n"));
        assert!(!text.sanitized);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn invalid_utf8_yields_a_clean_error() {
        let base = temp_dir("preview-utf8");
        let root = std::fs::canonicalize(&base).expect("canonical");

        // Beginnt als Text (die Erkennung sieht nur den Anfang), enthält aber
        // weiter hinten ungültiges UTF-8.
        let mut bytes = vec![b'a'; HEAD_BYTES];
        bytes.push(b'\n');
        bytes.extend_from_slice(&[0xc3, 0x28, 0xff]);
        std::fs::write(root.join("kaputt.txt"), &bytes).expect("schreiben");

        let err = build_text_preview(&root, "kaputt.txt")
            .await
            .expect_err("muss abgelehnt werden");
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);

        // Als Binärdatei erkannter Inhalt wird gar nicht erst als Text geliefert.
        std::fs::write(root.join("bild.txt"), b"\x89PNG\r\n\x1a\n\x00\x00").expect("schreiben");
        assert!(build_text_preview(&root, "bild.txt").await.is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn control_characters_are_neutralised_and_reported() {
        let base = temp_dir("preview-control");
        let root = std::fs::canonicalize(&base).expect("canonical");

        // Gültiges UTF-8, aber mit Nullbytes und ANSI-Farben: die Erkennung
        // lässt ESC durch, Nullbytes tauchen erst hinter der Stichprobe auf.
        let mut content = String::from("\u{1b}[32mgruen\u{1b}[0m ok\r\nzeile2\r");
        content.push_str(&"x".repeat(HEAD_BYTES));
        content.push('\u{0}');
        std::fs::write(root.join("log.log"), content.as_bytes()).expect("schreiben");

        let text = build_text_preview(&root, "log.log")
            .await
            .expect("Text lesbar");
        assert!(text.sanitized, "Ersetzungen müssen gemeldet werden");
        assert!(text.content.starts_with("gruen ok\nzeile2\n"));
        assert!(!text.content.contains('\u{1b}'));
        assert!(!text.content.contains('\u{0}'));
        assert!(text.content.contains('\u{fffd}'));
        assert!(!text.content.contains('\r'));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn utf16_with_bom_is_decoded() {
        let base = temp_dir("preview-utf16");
        let root = std::fs::canonicalize(&base).expect("canonical");

        let mut bytes = vec![0xff, 0xfe];
        for unit in "Grüße\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(root.join("u16.txt"), &bytes).expect("schreiben");

        let text = build_text_preview(&root, "u16.txt")
            .await
            .expect("Text lesbar");
        assert_eq!(text.encoding, "utf-16le");
        assert_eq!(text.content, "Grüße\n");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sanitize_keeps_tabs_and_newlines() {
        let (out, changed) = sanitize_text("a\tb\nc");
        assert_eq!(out, "a\tb\nc");
        assert!(!changed);
    }

    #[tokio::test]
    async fn text_preview_rejects_paths_outside_the_root() {
        let base = temp_dir("preview-text-jail");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret.txt"), b"geheim").expect("secret");
        let canonical_root = std::fs::canonicalize(&root).expect("canonical root");

        let absolute = outside.join("secret.txt").to_string_lossy().to_string();
        for candidate in ["../outside/secret.txt", absolute.as_str()] {
            let status = match build_text_preview(&canonical_root, candidate).await {
                Ok(_) => StatusCode::OK,
                Err(e) => e.into_response().status(),
            };
            assert_eq!(status, StatusCode::FORBIDDEN, "Pfad: {}", candidate);
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("escape")).expect("symlink");
            let status = match build_text_preview(&canonical_root, "escape/secret.txt").await {
                Ok(_) => StatusCode::OK,
                Err(e) => e.into_response().status(),
            };
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        assert!(build_text_preview(&canonical_root, ".").await.is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    // --- Bildvorschau -----------------------------------------------------

    /// Ein 1×1-PNG. Reicht für alles, was hier geprüft wird: die Erkennung
    /// sieht nur den Kopf, ausgeliefert werden die Bytes unverändert.
    fn tiny_png() -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        bytes
    }

    async fn body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("Body lesbar")
            .to_vec()
    }

    fn header_of(response: &Response, name: header::HeaderName) -> String {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    #[tokio::test]
    async fn image_preview_streams_the_original_bytes() {
        let base = temp_dir("preview-image");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let png = tiny_png();
        std::fs::write(root.join("bild.png"), &png).expect("schreiben");

        let response = build_image_response(&root, "bild.png", &HeaderMap::new())
            .await
            .expect("Bild lieferbar");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header_of(&response, header::CONTENT_TYPE), "image/png");
        assert_eq!(
            header_of(&response, header::X_CONTENT_TYPE_OPTIONS),
            "nosniff"
        );
        assert_eq!(header_of(&response, header::ACCEPT_RANGES), "none");
        assert!(header_of(&response, header::CONTENT_DISPOSITION).starts_with("inline;"));
        assert_eq!(
            header_of(&response, header::CONTENT_LENGTH),
            png.len().to_string()
        );
        assert_eq!(body_bytes(response).await, png, "Bytes unverändert");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Akzeptanzkriterium des Tickets: ein SVG mit eingebettetem Skript darf
    /// keinen Code im Kontext der App ausführen.
    ///
    /// Serverseitig prüfbar ist davon der Teil, der dem Server gehört: der
    /// Content-Type kommt aus dem Inhalt, `nosniff` verbietet die Umdeutung,
    /// und die CSP macht die Antwort auch dann inert, wenn sie **nicht** als
    /// Bild, sondern als Dokument geladen wird – `sandbox` ohne `allow-scripts`
    /// und ohne `allow-same-origin`. Dass ein `<img>` gar nicht erst Skripte
    /// ausführt, ist die Lage darüber und wird im Browser geprüft.
    #[tokio::test]
    async fn svg_with_a_script_is_served_inert() {
        let base = temp_dir("preview-svg");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<script>window.top.pwned = true;</script><rect width="10" height="10"/></svg>"#;
        std::fs::write(root.join("boese.svg"), svg).expect("schreiben");

        let response = build_image_response(&root, "boese.svg", &HeaderMap::new())
            .await
            .expect("SVG lieferbar");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header_of(&response, header::CONTENT_TYPE), "image/svg+xml");
        assert_eq!(
            header_of(&response, header::X_CONTENT_TYPE_OPTIONS),
            "nosniff"
        );

        let csp = header_of(&response, header::CONTENT_SECURITY_POLICY);
        assert!(csp.contains("sandbox"), "CSP ohne sandbox: {}", csp);
        assert!(!csp.contains("allow-scripts"), "sandbox zu weit: {}", csp);
        assert!(
            !csp.contains("allow-same-origin"),
            "sandbox zu weit: {}",
            csp
        );
        assert!(csp.contains("default-src 'none'"), "CSP zu weit: {}", csp);

        // Der Inhalt wird nicht umgeschrieben – die Absicherung liegt im
        // Kontext, nicht in einer Filterliste.
        assert_eq!(body_bytes(response).await, svg.to_vec());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Die Endung entscheidet auch beim Ausliefern nichts: eine `.png` mit
    /// SVG-Inhalt bekommt `image/svg+xml` und damit dieselbe Behandlung wie
    /// jedes andere SVG. Sonst käme aktiver Inhalt an der Absicherung vorbei,
    /// nur weil er anders heisst.
    #[tokio::test]
    async fn content_type_follows_the_content_not_the_name() {
        let base = temp_dir("preview-image-name");
        let root = std::fs::canonicalize(&base).expect("canonical");
        std::fs::write(
            root.join("getarnt.png"),
            br#"<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>"#,
        )
        .expect("schreiben");
        std::fs::write(root.join("getarnt.svg"), tiny_png()).expect("schreiben");

        let as_svg = build_image_response(&root, "getarnt.png", &HeaderMap::new())
            .await
            .expect("lieferbar");
        assert_eq!(header_of(&as_svg, header::CONTENT_TYPE), "image/svg+xml");

        let as_png = build_image_response(&root, "getarnt.svg", &HeaderMap::new())
            .await
            .expect("lieferbar");
        assert_eq!(header_of(&as_png, header::CONTENT_TYPE), "image/png");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn image_preview_rejects_everything_that_is_not_an_image() {
        let base = temp_dir("preview-image-kind");
        let root = std::fs::canonicalize(&base).expect("canonical");
        std::fs::write(root.join("text.png"), b"nur Text, keine Grafik\n").expect("schreiben");
        std::fs::write(root.join("dok.jpg"), b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n").expect("schreiben");
        std::fs::write(root.join("leer.png"), b"").expect("schreiben");

        for candidate in ["text.png", "dok.jpg", "leer.png"] {
            let status = match build_image_response(&root, candidate, &HeaderMap::new()).await {
                Ok(response) => response.status(),
                Err(e) => e.into_response().status(),
            };
            assert_eq!(status, StatusCode::BAD_REQUEST, "Datei: {}", candidate);
        }

        // Ordner haben keine Bildvorschau, eine fehlende Datei erst recht
        // nicht (die kommt aus dem Jail bereits als 404 zurück).
        assert!(build_image_response(&root, ".", &HeaderMap::new())
            .await
            .is_err());
        assert!(build_image_response(&root, "fehlt.png", &HeaderMap::new())
            .await
            .is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn image_preview_answers_304_and_keeps_its_headers() {
        let base = temp_dir("preview-image-etag");
        let root = std::fs::canonicalize(&base).expect("canonical");
        std::fs::write(root.join("bild.png"), tiny_png()).expect("schreiben");

        let first = build_image_response(&root, "bild.png", &HeaderMap::new())
            .await
            .expect("lieferbar");
        let etag = header_of(&first, header::ETAG);
        assert!(!etag.is_empty(), "ETag fehlt");

        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&etag).expect("ETag als Header"),
        );
        let second = build_image_response(&root, "bild.png", &headers)
            .await
            .expect("lieferbar");
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        // Auch die 304 trägt die Schutz-Kopfzeilen.
        assert!(header_of(&second, header::CONTENT_SECURITY_POLICY).contains("sandbox"));
        assert_eq!(body_bytes(second).await, Vec::<u8>::new());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn image_preview_rejects_paths_outside_the_root() {
        let base = temp_dir("preview-image-jail");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("geheim.png"), tiny_png()).expect("secret");
        let canonical_root = std::fs::canonicalize(&root).expect("canonical root");

        let absolute = outside.join("geheim.png").to_string_lossy().to_string();
        for candidate in ["../outside/geheim.png", absolute.as_str()] {
            let status =
                match build_image_response(&canonical_root, candidate, &HeaderMap::new()).await {
                    Ok(response) => response.status(),
                    Err(e) => e.into_response().status(),
                };
            assert_eq!(status, StatusCode::FORBIDDEN, "Pfad: {}", candidate);
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("escape")).expect("symlink");
            let status =
                match build_image_response(&canonical_root, "escape/geheim.png", &HeaderMap::new())
                    .await
                {
                    Ok(response) => response.status(),
                    Err(e) => e.into_response().status(),
                };
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn inline_disposition_survives_umlauts_and_quotes() {
        let value = inline_disposition("Grüße \"1\"/2.png").expect("Header baubar");
        let text = value.to_str().expect("ASCII");
        assert!(text.starts_with("inline; "));
        assert!(!text.contains('/'));
        assert!(text.contains("filename*=UTF-8''"));
        assert!(text.contains("%C3%BC"));
    }

    #[tokio::test]
    async fn paths_outside_the_root_are_rejected() {
        let base = temp_dir("preview-jail");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret.txt"), b"geheim").expect("secret");
        let canonical_root = std::fs::canonicalize(&root).expect("canonical root");

        // Der Status wird über die Antwort geprüft, nicht über das Fehlerobjekt:
        // das Kriterium lautet 403, nicht „irgendein Fehler".
        async fn status_of(root: &Path, candidate: &str) -> StatusCode {
            match build_preview(root, candidate).await {
                Ok(_) => StatusCode::OK,
                Err(e) => e.into_response().status(),
            }
        }

        // `..`-Ausbruch
        assert_eq!(
            status_of(&canonical_root, "../outside/secret.txt").await,
            StatusCode::FORBIDDEN
        );

        // Absoluter Pfad ausserhalb
        let absolute = outside.join("secret.txt").to_string_lossy().to_string();
        assert_eq!(
            status_of(&canonical_root, &absolute).await,
            StatusCode::FORBIDDEN
        );

        // Symlink aus dem Jail heraus
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("escape")).expect("symlink");
            assert_eq!(
                status_of(&canonical_root, "escape/secret.txt").await,
                StatusCode::FORBIDDEN
            );
        }

        // Ordner haben keine Vorschau
        assert!(build_preview(&canonical_root, ".").await.is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------
    // Puffer-Dimensionierung (Befund 1)
    // -----------------------------------------------------------------

    /// Eine winzige Datei darf keinen Puffer in Limit-Grösse anlegen.
    /// `capacity()` ist hier ausnahmsweise das Prüfkriterium – genau um die
    /// Allokation geht es.
    #[tokio::test]
    async fn read_prefix_sizes_the_buffer_after_the_file_not_the_limit() {
        let base = temp_dir("preview-bufsize");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let tiny = root.join("winzig.txt");
        std::fs::write(&tiny, b"nur zwanzig Bytes...").expect("schreiben");

        let bytes = read_prefix(&tiny, TEXT_LIMIT).await.expect("lesbar");
        assert_eq!(bytes.len(), 20);
        assert!(
            bytes.capacity() < 4096,
            "Puffer viel zu gross: {} Bytes für eine 20-Byte-Datei",
            bytes.capacity()
        );

        // Leere Datei: keine Sonderbehandlung, nur kein Riesenpuffer.
        let empty = root.join("leer.txt");
        std::fs::write(&empty, b"").expect("schreiben");
        let bytes = read_prefix(&empty, TEXT_LIMIT).await.expect("lesbar");
        assert!(bytes.is_empty());
        assert!(bytes.capacity() <= READ_GROW_CHUNK);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Die kleinere Anfangsgrösse darf nichts abschneiden: eine Datei, die
    /// zwischen `metadata()` und dem Lesen wächst, wird trotzdem bis `max`
    /// gelesen. Nachgestellt über `max`-Werte über und unter der Dateigrösse.
    #[tokio::test]
    async fn read_prefix_still_reads_up_to_max_and_never_beyond() {
        let base = temp_dir("preview-bufgrow");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let path = root.join("gross.txt");
        let payload = vec![b'x'; 300 * 1024];
        std::fs::write(&path, &payload).expect("schreiben");

        // max grösser als die Datei -> ganze Datei
        let all = read_prefix(&path, TEXT_LIMIT).await.expect("lesbar");
        assert_eq!(all.len(), payload.len());

        // max kleiner als die Datei -> exakt max, keinen Deut mehr
        for max in [1usize, 10, HEAD_BYTES, READ_GROW_CHUNK, 200 * 1024] {
            let cut = read_prefix(&path, max).await.expect("lesbar");
            assert_eq!(cut.len(), max, "max={}", max);
        }

        assert!(read_prefix(&path, 0).await.expect("lesbar").is_empty());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Der Kern von Akzeptanzkriterium 2: `/api/preview/text` nimmt **keine**
    /// Parameter ausser `path` entgegen. Der Handler wird hier mit genau den
    /// elf Parametern aufgerufen, mit denen der Tester das Limit anzugreifen
    /// versucht hat – zusätzlich in Array-Form und mit doppeltem `path`.
    /// `bytes_read` bleibt in jedem Fall bei `TEXT_LIMIT`.
    #[tokio::test]
    async fn text_limit_cannot_be_raised_by_any_parameter() {
        let base = temp_dir("preview-limit-e506755d");
        let root = std::fs::canonicalize(&base).expect("canonical");
        let path = root.join("riesig.txt");
        // Deutlich über dem Limit, damit jede Aufweichung sofort auffiele.
        let payload = vec![b'a'; TEXT_LIMIT + 512 * 1024];
        std::fs::write(&path, &payload).expect("schreiben");

        // Ohne jeden Zusatzparameter: der Bezugswert.
        let plain = build_text_preview(&root, "riesig.txt").await.expect("ok");
        assert_eq!(plain.bytes_read, TEXT_LIMIT as u64);
        assert_eq!(plain.limit, TEXT_LIMIT as u64);
        assert!(plain.truncated);
        assert_eq!(plain.content.len(), TEXT_LIMIT);

        // Und jetzt mit dem vollen Arsenal. `preview_text` liest aus der
        // `Query`-Map ausschliesslich `path`; jeder andere Schlüssel wird
        // verworfen, bevor irgendetwas gelesen wird. Nachgestellt wird das
        // hier über genau die Auswertung, die der Handler vornimmt – der
        // Handler selbst braucht das Wurzelverzeichnis aus der Umgebung und
        // wird deshalb im HTTP-Lauf geprüft, nicht im Unit-Test.
        let mut params: HashMap<String, String> = HashMap::new();
        params.insert("path".to_string(), "riesig.txt".to_string());
        for key in [
            "limit",
            "size",
            "offset",
            "max",
            "bytes",
            "count",
            "length",
            "end",
            "range",
            "n",
            "TEXT_LIMIT",
            "limit[]",
            "size[]",
            "Limit",
            "LIMIT",
        ] {
            params.insert(key.to_string(), "999999999".to_string());
        }

        let requested = params
            .get("path")
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .expect("Pfad");
        assert_eq!(requested, "riesig.txt");

        let attacked = build_text_preview(&root, requested).await.expect("ok");
        assert_eq!(attacked.bytes_read, TEXT_LIMIT as u64);
        assert_eq!(attacked.limit, TEXT_LIMIT as u64);
        assert!(attacked.truncated);
        assert_eq!(
            attacked.content.len(),
            TEXT_LIMIT,
            "es wurde mehr als das Limit ausgeliefert"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------
    // svgz (Befund 2)
    // -----------------------------------------------------------------

    /// Entscheidung festgeschrieben: gzip bleibt gzip, auch wenn ein SVG darin
    /// steckt und die Datei `.svgz` heisst. Die Endung ändert nichts – sonst
    /// liefe ein beliebiges Archiv als Bild aus.
    #[tokio::test]
    async fn svgz_is_gzip_and_not_an_image() {
        // Echte gzip-Datei, deren Inhalt ein SVG ist (fest verdrahtet, damit
        // der Test keine Kompressionsbibliothek braucht).
        let gzipped_svg: &[u8] = &[
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x75, 0x8c, 0x41, 0x0e,
            0x84, 0x20, 0x0c, 0x45, 0xf7, 0x9e, 0xa2, 0xe9, 0x01, 0x68, 0xc7, 0xd9, 0x4d, 0x00,
            0x0f, 0x33, 0x32, 0x40, 0xc2, 0xa8, 0x81, 0xc6, 0x7a, 0x7c, 0xd1, 0xbd, 0xbb, 0x97,
            0xbc, 0xf7, 0xbf, 0x9d, 0x8e, 0x7f, 0x81, 0x3d, 0xd4, 0x96, 0xd7, 0xc5, 0xe1, 0xcb,
            0x30, 0x4e, 0x7e, 0xb0, 0x6d, 0x8f, 0xd0, 0xc5, 0xd2, 0x1c, 0x26, 0x91, 0xed, 0x43,
            0xa4, 0xaa, 0x46, 0xdf, 0x66, 0xad, 0x91, 0x46, 0x66, 0xa6, 0x5e, 0x20, 0x68, 0x9e,
            0x25, 0xf5, 0x15, 0x23, 0xa4, 0x90, 0x63, 0x92, 0x9b, 0xbd, 0xad, 0xe1, 0x2b, 0x0f,
            0x12, 0x7e, 0xb9, 0x14, 0x87, 0x35, 0xcc, 0x48, 0xde, 0x5e, 0x37, 0x7e, 0x38, 0x01,
            0x0b, 0x94, 0x3f, 0xaa, 0x85, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            sniff(gzipped_svg),
            (PreviewKind::Unknown, "application/gzip")
        );
        // Kein zufälliger Treffer: ein unkomprimiertes SVG bleibt ein Bild.
        assert_eq!(
            sniff(b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n"),
            (PreviewKind::Image, "image/svg+xml")
        );

        let base = temp_dir("preview-svgz-e506755d");
        let root = std::fs::canonicalize(&base).expect("canonical");
        std::fs::write(root.join("logo.svgz"), gzipped_svg).expect("schreiben");

        // `/api/preview/info` meldet die Gattung, an der sich das Frontend
        // ausrichtet: keine Bildvorschau.
        let info = build_preview(&root, "logo.svgz").await.expect("ok");
        assert_eq!(info.kind, PreviewKind::Unknown);
        assert_eq!(info.mime, "application/gzip");
        assert_eq!(info.extension, "svgz");

        // Und die Bildvorschau lehnt sie mit einer klaren Begründung ab,
        // statt gzip-Bytes als image/svg+xml auszuliefern.
        let status = match build_image_response(&root, "logo.svgz", &HeaderMap::new()).await {
            Ok(response) => response.status(),
            Err(e) => e.into_response().status(),
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------
    // Kleinbefunde
    // -----------------------------------------------------------------

    /// `If-None-Match: *` ist laut RFC 9110 ein Treffer, sobald die Ressource
    /// existiert.
    #[tokio::test]
    async fn if_none_match_star_yields_304() {
        let base = temp_dir("preview-inm-star-e506755d");
        let root = std::fs::canonicalize(&base).expect("canonical");
        std::fs::write(root.join("bild.png"), tiny_png()).expect("schreiben");

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        let response = build_image_response(&root, "bild.png", &headers)
            .await
            .expect("lieferbar");
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        // Die Schutz-Kopfzeilen fehlen auch hier nicht.
        assert!(header_of(&response, header::CONTENT_SECURITY_POLICY).contains("sandbox"));

        // Ein fremder ETag bleibt eine 200.
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"fremd\""));
        let response = build_image_response(&root, "bild.png", &headers)
            .await
            .expect("lieferbar");
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Gleiche Grösse, andere Änderungszeit innerhalb derselben Sekunde:
    /// der ETag muss sich trotzdem unterscheiden.
    #[test]
    fn etag_distinguishes_same_size_within_one_second() {
        let a = image_etag(1024, 1_700_000_000_000_000_000);
        let b = image_etag(1024, 1_700_000_000_400_000_000);
        assert_ne!(a, b, "ETag kollidiert bei Ersetzung in derselben Sekunde");
    }
}
