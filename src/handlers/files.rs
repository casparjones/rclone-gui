//! Verzeichnis-Auflistung für den lokalen Browser und für rclone-Remotes.
//!
//! Der lokale Teil liefert nicht nur die Einträge, sondern gleich alles, was die
//! Navigation im Frontend braucht: den kanonisierten Pfad, den Elternordner und
//! die Breadcrumb-Segmente. Damit muss der Client keine Pfade selbst
//! zusammensetzen – er schickt nur zurück, was der Server ihm gegeben hat.
//!
//! Jeder vom Client kommende Pfad wird über `resolve_within_root` aus
//! `download.rs` kanonisiert und gegen den konfigurierten Wurzelpfad geprüft.
//! `..`, absolute Fremdpfade und Symlinks, die aus dem Wurzelverzeichnis
//! herausführen, werden abgewiesen bzw. beim Auflisten übersprungen.

use axum::{extract::Query, http::StatusCode, response::Json as ResponseJson, Extension, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

use crate::config_manager::{ensure_configured_remote, RCLONE_CONFIG_PATH};
use crate::handlers::auth_web::CurrentUser;
use crate::handlers::download::{
    is_within_root, resolve_within_root, scope_from_map, user_root, DownloadError,
};
use crate::models::{ApiResponse, FileEntry};

/// Ein Segment der Breadcrumb-Leiste. `path` ist bereits kanonisiert und kann
/// unverändert wieder an den Server geschickt werden.
#[derive(Debug, Serialize)]
pub struct PathSegment {
    pub name: String,
    pub path: String,
}

/// Antwort von `GET /api/files/local`.
#[derive(Debug, Serialize)]
pub struct LocalListing {
    /// Kanonisierter Wurzelpfad – oberhalb davon gibt es keine Navigation.
    /// Das ist das Home des angemeldeten Nutzers, ausser ein Admin hat
    /// ausdrücklich `scope=system` angefordert.
    pub root: String,
    /// `home` oder `system`. Das Frontend kennzeichnet damit sichtbar, dass
    /// gerade ausserhalb des eigenen Bereichs navigiert wird.
    pub scope: String,
    /// Kanonisierter Pfad des angezeigten Ordners.
    pub path: String,
    /// Elternordner, solange der aktuelle Ordner nicht die Wurzel ist.
    pub parent: Option<String>,
    /// Breadcrumb von der Wurzel bis zum aktuellen Ordner.
    pub segments: Vec<PathSegment>,
    /// Inhalt des Ordners, Ordner zuerst, dann alphabetisch.
    pub entries: Vec<FileEntry>,
}

pub async fn list_local_files(
    Extension(current): Extension<CurrentUser>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<ResponseJson<ApiResponse<LocalListing>>, DownloadError> {
    let scope = scope_from_map(&params)?;
    let root = user_root(&current, scope).await?;

    // Kein oder ein leerer Pfad bedeutet: Wurzelverzeichnis. Ein einzelner
    // Schrägstrich wird bewusst ebenfalls auf die Wurzel abgebildet – der
    // Browser soll nie auf das Dateisystem-Root zeigen.
    let requested = params.get("path").map(|p| p.trim()).unwrap_or("");
    let dir = if requested.is_empty() || requested == "/" {
        root.clone()
    } else {
        resolve_within_root(&root, requested).await?
    };

    let metadata = tokio::fs::metadata(&dir)
        .await
        .map_err(|e| DownloadError::bad_request(format!("Pfad nicht lesbar: {}", e)))?;
    if !metadata.is_dir() {
        return Err(DownloadError::bad_request("Pfad ist kein Ordner"));
    }

    let entries = read_directory(&root, &dir).await?;

    Ok(ResponseJson(ApiResponse::success(LocalListing {
        root: path_to_string(&root),
        scope: scope.as_str().to_string(),
        path: path_to_string(&dir),
        parent: parent_within_root(&root, &dir).map(|p| path_to_string(&p)),
        segments: breadcrumb_segments(&root, &dir),
        entries,
    })))
}

pub async fn list_remote_files(
    Query(params): Query<HashMap<String, String>>,
) -> ResponseJson<ApiResponse<Vec<FileEntry>>> {
    let remote_name = match params.get("remote") {
        Some(name) => name,
        None => return ResponseJson(ApiResponse::error("Remote name is required")),
    };

    let default_remote_path = "/".to_string();
    let remote_path = params
        .get("path")
        .unwrap_or(&default_remote_path)
        .to_string();

    match list_remote_directory(remote_name, &remote_path).await {
        Ok(files) => ResponseJson(ApiResponse::success(files)),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

/// Liest einen Ordner und liefert die Einträge sortiert zurück: Ordner zuerst,
/// darin alphabetisch ohne Rücksicht auf Groß-/Kleinschreibung.
///
/// Einträge, die nicht gelesen werden können, werden übersprungen statt die
/// gesamte Auflistung scheitern zu lassen. Symlinks werden aufgelöst und erneut
/// gegen das Wurzelverzeichnis geprüft; wer hinausführt, taucht nicht auf.
async fn read_directory(root: &Path, dir: &Path) -> Result<Vec<FileEntry>, DownloadError> {
    let mut read_dir = tokio::fs::read_dir(dir).await.map_err(|e| {
        DownloadError::internal(format!("Ordner konnte nicht gelesen werden: {}", e))
    })?;

    let mut files = Vec::new();

    loop {
        let entry = match read_dir.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("Verzeichniseintrag nicht lesbar ({}): {}", dir.display(), e);
                break;
            }
        };

        let name = entry.file_name().to_string_lossy().to_string();
        let child = entry.path();

        let link_metadata = match tokio::fs::symlink_metadata(&child).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Eintrag übersprungen ({}): {}", child.display(), e);
                continue;
            }
        };

        // Nur Symlinks müssen erneut geprüft werden: `dir` ist kanonisiert, ein
        // echter Kindeintrag kann das Jail deshalb nicht verlassen.
        let target = if link_metadata.file_type().is_symlink() {
            match tokio::fs::canonicalize(&child).await {
                Ok(resolved) if is_within_root(root, &resolved) => resolved,
                Ok(resolved) => {
                    tracing::warn!(
                        "Symlink zeigt aus dem Wurzelverzeichnis heraus, übersprungen: {} -> {}",
                        child.display(),
                        resolved.display()
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!("Symlink nicht auflösbar ({}): {}", child.display(), e);
                    continue;
                }
            }
        } else {
            child
        };

        let metadata = match tokio::fs::metadata(&target).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Eintrag übersprungen ({}): {}", target.display(), e);
                continue;
            }
        };

        // Geräte, Sockets und FIFOs gehören nicht in einen Dateibrowser.
        if !metadata.is_dir() && !metadata.is_file() {
            continue;
        }

        let size = if metadata.is_file() {
            Some(metadata.len())
        } else {
            None
        };

        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs().to_string());

        files.push(FileEntry {
            name,
            path: path_to_string(&target),
            is_dir: metadata.is_dir(),
            size,
            modified,
        });
    }

    files.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(files)
}

/// Elternordner, solange er noch innerhalb des Wurzelverzeichnisses liegt.
fn parent_within_root(root: &Path, dir: &Path) -> Option<PathBuf> {
    if dir == root {
        return None;
    }
    dir.parent()
        .filter(|parent| is_within_root(root, parent))
        .map(|parent| parent.to_path_buf())
}

/// Breadcrumb von der Wurzel bis zum aktuellen Ordner. Das erste Segment ist
/// immer die Wurzel; darüber hinaus gibt es keine Navigation.
fn breadcrumb_segments(root: &Path, dir: &Path) -> Vec<PathSegment> {
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "/".to_string());

    let mut segments = vec![PathSegment {
        name: root_name,
        path: path_to_string(root),
    }];

    let relative = match dir.strip_prefix(root) {
        Ok(rest) => rest,
        Err(_) => return segments,
    };

    let mut current = root.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(part) = component {
            current.push(part);
            segments.push(PathSegment {
                name: part.to_string_lossy().to_string(),
                path: path_to_string(&current),
            });
        }
    }

    segments
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

async fn list_remote_directory(
    remote_name: &str,
    remote_path: &str,
) -> anyhow::Result<Vec<FileEntry>> {
    // Zuerst der Name, dann erst der Prozess: `:local:` wäre rclones
    // On-the-fly-Syntax für ein nicht konfiguriertes Backend und führte am
    // gesamten Pfad-Jail vorbei. Wird hier abgelehnt, startet kein rclone.
    ensure_configured_remote(remote_name).await?;

    let remote_full_path = format!("{}:{}", remote_name, remote_path);

    let output = Command::new("rclone")
        .args(["lsjson", "--config", RCLONE_CONFIG_PATH, &remote_full_path])
        .output()
        .await?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("rclone error: {}", error));
    }

    let json_output = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<serde_json::Value> = serde_json::from_str(&json_output)?;

    let mut files = Vec::new();

    for entry in entries {
        let name = entry["Name"].as_str().unwrap_or("").to_string();
        let path = format!("{}/{}", remote_path.trim_end_matches('/'), name);
        let is_dir = entry["IsDir"].as_bool().unwrap_or(false);
        let size = entry["Size"].as_u64();
        let modified = entry["ModTime"].as_str().map(|s| s.to_string());

        files.push(FileEntry {
            name,
            path,
            is_dir,
            size,
            modified,
        });
    }

    Ok(files)
}

// ---------------------------------------------------------------------------
// Ordner auf einem rclone-Remote anlegen
// ---------------------------------------------------------------------------

/// Frist für den `rclone mkdir`-Prozess.
///
/// Der Client bricht nach 20 s selbst ab (`createRemoteFolder` in
/// `static/js/api.js`). Der Server muss **vorher** aufgeben, sonst kommt die
/// Antwort `504` nie an und der Nutzer sieht nur den Abbruch des Browsers, dem
/// keine Fehlerart zu entnehmen ist.
const REMOTE_MKDIR_TIMEOUT: Duration = Duration::from_secs(15);

/// Obergrenze für einen Ordnernamen. Kein Backend erlaubt mehr, und ein
/// längerer Name gehört ohnehin nicht in eine Kommandozeile.
const MAX_REMOTE_DIR_NAME_LEN: usize = 255;

/// Wie viel rclone-stderr in die Antwort darf. Der Wortlaut hilft beim
/// Nachvollziehen, aber er geht an den Client – also gekappt und einzeilig.
const MAX_REMOTE_ERROR_LEN: usize = 400;

#[derive(Debug, Deserialize)]
pub struct RemoteMkdirRequest {
    /// Name aus `/api/configs`. Wird gegen `rclone.conf` geprüft, bevor
    /// irgendein Prozess startet.
    pub remote: String,
    /// Ordner, in dem angelegt wird. Fehlt er, ist es die Wurzel des Remotes.
    pub path: Option<String>,
    /// Ein einzelnes Pfadsegment – kein Pfad.
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct RemoteMkdirResult {
    /// Der angelegte Pfad, so wie der Client ihn zum Navigieren wieder
    /// einsetzen kann.
    pub path: String,
}

type MkdirResponse = (StatusCode, ResponseJson<ApiResponse<RemoteMkdirResult>>);

fn mkdir_error(status: StatusCode, message: &str) -> MkdirResponse {
    (status, ResponseJson(ApiResponse::error(message)))
}

/// `POST /api/files/remote/mkdir` – legt **einen** Ordner auf einem
/// konfigurierten Remote an.
///
/// Anders als `/api/files/remote`, das jeden Fehlschlag als HTTP 200 mit
/// `{success:false, error:"rclone error: …"}` ausliefert, setzt dieser
/// Endpunkt den Statuscode: `403` fehlende Schreibrechte, `404` Elternpfad
/// weg, `401` Zugangsdaten des Remotes abgelehnt, `504` keine Antwort in der
/// Frist. Nur was sich nicht zuordnen lässt, bleibt bei 200 mit
/// `success:false` – das ist der dokumentierte Sammelfall des Kontrakts, nicht
/// ein vergessener Statuscode.
pub async fn create_remote_directory(Json(request): Json<RemoteMkdirRequest>) -> MkdirResponse {
    // Zuerst der Name, dann erst der Prozess: `:local:` wäre rclones
    // On-the-fly-Syntax für ein nicht konfiguriertes Backend und führte am
    // gesamten Pfad-Jail vorbei (siehe `5d31b2f7`). Wird hier abgelehnt,
    // startet kein rclone.
    if let Err(e) = ensure_configured_remote(&request.remote).await {
        return mkdir_error(StatusCode::BAD_REQUEST, &e.to_string());
    }

    let name = match validate_remote_dir_name(&request.name) {
        Ok(name) => name,
        Err(e) => return mkdir_error(StatusCode::BAD_REQUEST, &e),
    };

    let parent = match normalize_remote_path(request.path.as_deref().unwrap_or("/")) {
        Ok(path) => path,
        Err(e) => return mkdir_error(StatusCode::BAD_REQUEST, &e),
    };

    let created = join_remote_path(&parent, &name);
    let target = format!("{}:{}", request.remote, created);

    match run_rclone_mkdir(&target).await {
        Ok(()) => (
            StatusCode::OK,
            ResponseJson(ApiResponse::success(RemoteMkdirResult { path: created })),
        ),
        Err(MkdirFailure::Timeout) => mkdir_error(
            StatusCode::GATEWAY_TIMEOUT,
            "The remote did not answer within 15 seconds",
        ),
        Err(MkdirFailure::Spawn(message)) => {
            mkdir_error(StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
        Err(MkdirFailure::Rclone(stderr)) => {
            let (status, reason) = classify_rclone_failure(&stderr);
            mkdir_error(status, &format!("{}: {}", reason, excerpt(&stderr)))
        }
    }
}

/// Warum `rclone mkdir` nicht durchkam. Getrennt von der Zuordnung zu einem
/// Statuscode, damit die Zuordnung für sich testbar bleibt.
enum MkdirFailure {
    /// Der Prozess lief in die Frist.
    Timeout,
    /// Der Prozess liess sich nicht starten oder nicht einsammeln.
    Spawn(String),
    /// rclone lief und sagte nein. Trägt stderr.
    Rclone(String),
}

async fn run_rclone_mkdir(target: &str) -> Result<(), MkdirFailure> {
    // `--retries`/`--low-level-retries`: ohne sie wiederholt rclone einen
    // abgelehnten Aufruf so lange, dass die Frist zuschlägt, bevor der
    // eigentliche Grund im stderr steht – aus einem sauberen `403` würde ein
    // nichtssagendes `504`.
    let child = Command::new("rclone")
        .args([
            "mkdir",
            "--config",
            RCLONE_CONFIG_PATH,
            "--retries",
            "1",
            "--low-level-retries",
            "1",
            target,
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let child = match child {
        Ok(child) => child,
        Err(e) => return Err(MkdirFailure::Spawn(format!("rclone did not start: {}", e))),
    };

    // `kill_on_drop` oben ist der eigentliche Aufräummechanismus: läuft die
    // Frist ab, wird das Future fallengelassen und der Prozess mit ihm – sonst
    // bliebe bei jedem hängenden Remote ein rclone stehen.
    match tokio::time::timeout(REMOTE_MKDIR_TIMEOUT, child.wait_with_output()).await {
        Err(_) => Err(MkdirFailure::Timeout),
        Ok(Err(e)) => Err(MkdirFailure::Spawn(format!(
            "rclone could not be collected: {}",
            e
        ))),
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => Err(MkdirFailure::Rclone(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )),
    }
}

/// Ordnet rclones stderr einer Fehlerart zu.
///
/// rclone hat keinen brauchbaren Exit-Code für die Unterscheidung – jeder
/// Fehlschlag ist `1`. Der Wortlaut ist deshalb die einzige Quelle. Die
/// Reihenfolge ist bedeutsam: „access denied" taucht in Authentifizierungs-
/// **und** Rechtefehlern auf, die Anmeldung wird zuerst geprüft.
fn classify_rclone_failure(stderr: &str) -> (StatusCode, &'static str) {
    let text = stderr.to_lowercase();

    let has = |needles: &[&str]| needles.iter().any(|n| text.contains(n));

    if has(&[
        "401",
        "unauthorized",
        "authentication failed",
        "authenticationfailed",
        "invalid credentials",
        "bad credentials",
        "signaturedoesnotmatch",
        "invalidaccesskeyid",
        "didn't match",
        "auth error",
        "token expired",
        "invalid_grant",
    ]) {
        return (
            StatusCode::UNAUTHORIZED,
            "The remote rejected the credentials",
        );
    }

    if has(&[
        "403",
        "permission denied",
        "access denied",
        "accessdenied",
        "forbidden",
        "read-only",
        "read only",
        "not writable",
        "quota",
    ]) {
        return (StatusCode::FORBIDDEN, "No write permission on the remote");
    }

    if has(&[
        "404",
        "directory not found",
        "no such file or directory",
        "not found",
        "nosuchbucket",
        "nosuchkey",
        "doesn't exist",
        "does not exist",
    ]) {
        return (StatusCode::NOT_FOUND, "The parent path does not exist");
    }

    if has(&[
        "deadline exceeded",
        "timed out",
        "i/o timeout",
        "timeout",
        "connection refused",
        "no such host",
        "network is unreachable",
    ]) {
        return (StatusCode::GATEWAY_TIMEOUT, "The remote did not answer");
    }

    // Der dokumentierte Sammelfall: 200 mit `success:false`. Der Client zeigt
    // den Grund an, ordnet ihn aber keiner der vier Arten zu – das ist besser,
    // als eine Art zu raten.
    (StatusCode::OK, "The folder could not be created")
}

/// Prüft einen Ordnernamen. Ein Name ist **ein** Segment, kein Pfad.
///
/// Abgewiesen werden `/` und `\` (Pfadtrenner in rclone-Zielen), `.` und `..`
/// (Navigation statt Name), Steuerzeichen und ein führendes `-`, das rclone als
/// Option läse. Nicht abgewiesen wird `:` – der Remote-Name steht vor dem
/// ersten Doppelpunkt, alles danach ist für rclone Pfad.
fn validate_remote_dir_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err("The folder name must not be empty".to_string());
    }
    if trimmed.chars().count() > MAX_REMOTE_DIR_NAME_LEN {
        return Err(format!(
            "The folder name must not be longer than {} characters",
            MAX_REMOTE_DIR_NAME_LEN
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("The folder name must not contain control characters".to_string());
    }
    if let Some(c) = trimmed.chars().find(|c| matches!(c, '/' | '\\')) {
        return Err(format!("The folder name must not contain '{}'", c));
    }
    if trimmed == "." || trimmed == ".." {
        return Err("'.' and '..' are not folder names".to_string());
    }
    if trimmed.starts_with('-') {
        // Sonst liest rclone den Namen als Option.
        return Err("The folder name must not start with '-'".to_string());
    }

    Ok(trimmed.to_string())
}

/// Bringt einen vom Client kommenden Remote-Pfad auf die Form
/// `/a/b` (Wurzel: `/`).
///
/// Was für lokale Pfade `resolve_within_root` leistet, ist auf einem Remote
/// nicht möglich – es gibt kein Dateisystem zum Kanonisieren. Also wird
/// syntaktisch abgewiesen statt aufgelöst: `..` kommt nicht durch, und nichts
/// Ungeprüftes gerät in die rclone-Argumentliste.
fn normalize_remote_path(path: &str) -> Result<String, String> {
    if path.chars().any(|c| c.is_control()) {
        return Err("The path must not contain control characters".to_string());
    }

    let mut segments = Vec::new();
    for segment in path.split(['/', '\\']) {
        match segment.trim() {
            "" | "." => continue,
            ".." => return Err("The path must not contain '..'".to_string()),
            other => segments.push(other.to_string()),
        }
    }

    if segments.is_empty() {
        return Ok("/".to_string());
    }

    Ok(format!("/{}", segments.join("/")))
}

fn join_remote_path(parent: &str, name: &str) -> String {
    format!("{}/{}", parent.trim_end_matches('/'), name)
}

/// Einzeiliger, gekappter Auszug aus rclones stderr für die Antwort.
fn excerpt(stderr: &str) -> String {
    let single_line = stderr
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");

    if single_line.chars().count() > MAX_REMOTE_ERROR_LEN {
        let cut: String = single_line.chars().take(MAX_REMOTE_ERROR_LEN).collect();
        format!("{}…", cut)
    } else {
        single_line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Legt ein eindeutiges Testverzeichnis unterhalb von `std::env::temp_dir()` an.
    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rclone-gui-files-{}-{}",
            label,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis anlegen");
        dir
    }

    #[test]
    fn breadcrumb_starts_at_root_and_follows_the_path() {
        let root = Path::new("/mnt/home");
        let segments = breadcrumb_segments(root, Path::new("/mnt/home/a/b"));

        let names: Vec<&str> = segments.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["home", "a", "b"]);

        let paths: Vec<&str> = segments.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, vec!["/mnt/home", "/mnt/home/a", "/mnt/home/a/b"]);
    }

    #[test]
    fn breadcrumb_of_root_has_a_single_segment() {
        let root = Path::new("/mnt/home");
        let segments = breadcrumb_segments(root, root);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].path, "/mnt/home");
    }

    #[test]
    fn parent_stops_at_the_root() {
        let root = Path::new("/mnt/home");
        assert_eq!(parent_within_root(root, root), None);
        assert_eq!(
            parent_within_root(root, Path::new("/mnt/home/a/b")),
            Some(PathBuf::from("/mnt/home/a"))
        );
        // Der Elternordner der Wurzel liegt ausserhalb und wird nicht geliefert.
        assert_eq!(parent_within_root(root, Path::new("/mnt")), None);
    }

    #[tokio::test]
    async fn listing_sorts_directories_first_and_skips_escaping_symlinks() {
        let base = temp_dir("listing");
        let root = std::fs::canonicalize(&base).expect("kanonische Wurzel");
        let outside = root
            .join("..")
            .join(format!("rclone-gui-files-outside-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("secret.txt"), b"geheim").expect("secret");

        std::fs::create_dir_all(root.join("zeta")).expect("zeta");
        std::fs::create_dir_all(root.join("alpha")).expect("alpha");
        std::fs::write(root.join("b.txt"), b"bb").expect("b.txt");
        std::fs::write(root.join("A.txt"), b"a").expect("A.txt");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("escape")).expect("symlink");
            std::os::unix::fs::symlink(root.join("b.txt"), root.join("inside-link"))
                .expect("symlink");
        }

        let entries = read_directory(&root, &root).await.expect("Auflistung");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

        // Ordner zuerst, danach Dateien, jeweils alphabetisch.
        assert_eq!(&names[..2], &["alpha", "zeta"], "Namen: {:?}", names);
        assert!(names.contains(&"A.txt"), "Namen: {:?}", names);
        assert!(names.contains(&"b.txt"), "Namen: {:?}", names);

        // Symlink innerhalb der Wurzel bleibt sichtbar …
        #[cfg(unix)]
        {
            assert!(names.contains(&"inside-link"), "Namen: {:?}", names);
            // … der Ausbruch nicht.
            assert!(!names.contains(&"escape"), "Namen: {:?}", names);
        }

        // Grösse nur bei Dateien, Ordner ohne.
        let alpha = entries.iter().find(|e| e.name == "alpha").expect("alpha");
        assert!(alpha.is_dir);
        assert_eq!(alpha.size, None);
        let b = entries.iter().find(|e| e.name == "b.txt").expect("b.txt");
        assert!(!b.is_dir);
        assert_eq!(b.size, Some(2));
        assert!(b.modified.is_some());

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[tokio::test]
    async fn traversal_out_of_the_root_is_rejected() {
        let base = temp_dir("traversal");
        let root = std::fs::canonicalize(&base).expect("kanonische Wurzel");
        std::fs::create_dir_all(root.join("sub")).expect("sub");

        // Innerhalb: erlaubt.
        assert!(resolve_within_root(&root, "sub").await.is_ok());

        // `..`-Ausbruch und absoluter Fremdpfad: abgewiesen.
        assert!(resolve_within_root(&root, "../..").await.is_err());
        assert!(resolve_within_root(&root, "/etc").await.is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn folder_names_that_are_paths_or_navigation_are_rejected() {
        assert_eq!(
            validate_remote_dir_name("Urlaub 2026").unwrap(),
            "Urlaub 2026"
        );
        // Umgebende Leerzeichen sind ein Tippfehler, kein Name.
        assert_eq!(validate_remote_dir_name("  neu  ").unwrap(), "neu");

        for bad in ["", "   ", "a/b", "a\\b", ".", "..", "-x", "a\u{0}b", "a\nb"] {
            assert!(
                validate_remote_dir_name(bad).is_err(),
                "wurde nicht abgewiesen: {:?}",
                bad
            );
        }

        let too_long = "x".repeat(MAX_REMOTE_DIR_NAME_LEN + 1);
        assert!(validate_remote_dir_name(&too_long).is_err());
    }

    #[test]
    fn remote_paths_are_normalised_and_traversal_is_rejected() {
        assert_eq!(normalize_remote_path("").unwrap(), "/");
        assert_eq!(normalize_remote_path("/").unwrap(), "/");
        assert_eq!(normalize_remote_path("///").unwrap(), "/");
        assert_eq!(normalize_remote_path("a/b").unwrap(), "/a/b");
        assert_eq!(normalize_remote_path("/a//b/").unwrap(), "/a/b");
        assert_eq!(normalize_remote_path("/a/./b").unwrap(), "/a/b");

        assert!(normalize_remote_path("/a/../b").is_err());
        assert!(normalize_remote_path("..").is_err());
        // Der Backslash trennt hier ebenfalls, sonst wäre `..\..` ein Name.
        assert!(normalize_remote_path("a\\..\\b").is_err());
        assert!(normalize_remote_path("/a\u{0}b").is_err());
    }

    #[test]
    fn the_created_path_is_the_one_the_client_gets_back() {
        assert_eq!(join_remote_path("/", "neu"), "/neu");
        assert_eq!(
            join_remote_path("/parent", "neuer ordner"),
            "/parent/neuer ordner"
        );
    }

    #[test]
    fn rclone_stderr_is_mapped_to_the_four_error_kinds() {
        let kind = |stderr: &str| classify_rclone_failure(stderr).0;

        assert_eq!(
            kind("Failed to mkdir: 401 Unauthorized"),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            kind("SignatureDoesNotMatch: the request signature we calculated"),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            kind("Failed to mkdir: permission denied"),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            kind("Failed to mkdir: 403 Forbidden"),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            kind("Failed to mkdir: directory not found"),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            kind("Post \"https://example\": net/http: request canceled (Client.Timeout exceeded)"),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            kind("dial tcp: connection refused"),
            StatusCode::GATEWAY_TIMEOUT
        );

        // Nicht zuordenbar: der dokumentierte Sammelfall, kein geratener Code.
        assert_eq!(kind("something went sideways"), StatusCode::OK);

        // Anmeldung schlägt Rechte, wo beides im Wortlaut steht.
        assert_eq!(
            kind("access denied: authentication failed"),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn the_error_excerpt_is_one_line_and_bounded() {
        assert_eq!(excerpt("  eins  \n\n zwei \n"), "eins | zwei");

        let long = "y".repeat(MAX_REMOTE_ERROR_LEN + 50);
        let cut = excerpt(&long);
        assert_eq!(cut.chars().count(), MAX_REMOTE_ERROR_LEN + 1);
        assert!(cut.ends_with('…'));
    }
}
