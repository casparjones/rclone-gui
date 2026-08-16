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

use axum::{extract::Query, response::Json as ResponseJson};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use tokio::process::Command;

use crate::config_manager::{ensure_configured_remote, RCLONE_CONFIG_PATH};
use crate::handlers::download::{
    download_root, is_within_root, resolve_within_root, DownloadError,
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
    pub root: String,
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
    Query(params): Query<HashMap<String, String>>,
) -> Result<ResponseJson<ApiResponse<LocalListing>>, DownloadError> {
    let root = download_root().await?;

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
}
