use crate::database;
use crate::handlers::sync;
use crate::models::{ApiResponse, StartTaskRequest, SyncRequest, Task, TaskRequest};
use axum::{extract::Json, extract::Path, response::Json as ResponseJson, Extension};
use chrono::Utc;
use sqlx::{Pool, Sqlite};
use tracing::{error, info, warn};
use uuid::Uuid;

fn validate_task_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Task name cannot be empty".to_string());
    }

    if name.len() > 50 {
        return Err("Task name cannot be longer than 50 characters".to_string());
    }

    // Check if name is alphanumeric (plus underscore and hyphen)
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Task name can only contain alphanumeric characters, underscores, and hyphens"
                .to_string(),
        );
    }

    Ok(())
}

/// Grundprüfung für die Pfadfelder eines Tasks.
///
/// Escaping gehört an die Ausgabe, nicht an den Eingang: die Anzeige schreibt
/// diese Werte per `textContent` ins DOM, damit sind `< > " ' &` und Backtick
/// harmlos — und in Ordnernamen wie `Rock & Roll` oder `Mom's Photos` völlig
/// üblich. Abgelehnt wird deshalb nur noch, was tatsächlich schadet:
/// Steuerzeichen inklusive NUL und Zeilenumbrüchen (die Konfigurationsdateien
/// und Logzeilen zerlegen), Überlänge und leer.
fn validate_task_path_field(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} cannot be empty", label));
    }

    if value.len() > 4096 {
        return Err(format!("{} cannot be longer than 4096 characters", label));
    }

    // `is_control()` deckt NUL, `\n` und `\r` mit ab.
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        warn!(
            "Rejected task field '{}': control character U+{:04X}",
            label, c as u32
        );
        return Err(format!(
            "{} cannot contain control characters or line breaks",
            label
        ));
    }

    Ok(())
}

fn validate_task_request(task_request: &TaskRequest) -> Result<(), String> {
    validate_task_name(&task_request.name)?;
    validate_task_path_field("Source path", &task_request.source_path)?;
    validate_task_path_field("Remote path", &task_request.remote_path)?;

    // Der Remote-Name ist kein Pfadfeld: er landet später als `<name>:` in
    // einer rclone-Kommandozeile. Deshalb dieselbe zentrale Prüfung wie überall
    // sonst (`config_manager::validate_remote_name`) statt der laxen
    // Pfadprüfung. Ob das Remote tatsächlich konfiguriert ist, prüft
    // `start_sync` beim Starten – ein Task darf auch angelegt werden, bevor das
    // Remote existiert.
    crate::config_manager::validate_remote_name(&task_request.remote_name)
        .map_err(|e| e.to_string())?;

    if let Some(chunk_size) = &task_request.chunk_size {
        validate_task_path_field("Chunk size", chunk_size)?;
    }

    Ok(())
}

pub async fn create_task(
    Extension(pool): Extension<Pool<Sqlite>>,
    Json(task_request): Json<TaskRequest>,
) -> ResponseJson<ApiResponse<String>> {
    info!("🎯 Creating new task: {}", task_request.name);

    // Validate task name and the path fields
    if let Err(e) = validate_task_request(&task_request) {
        warn!("Rejected task '{}': {}", task_request.name, e);
        return ResponseJson(ApiResponse::error(&e));
    }

    // Check if task name already exists
    match database::task_name_exists(&pool, &task_request.name).await {
        Ok(exists) if exists => {
            return ResponseJson(ApiResponse::error("Task name already exists"));
        }
        Err(e) => {
            error!("Failed to check task name existence: {}", e);
            return ResponseJson(ApiResponse::error("Database error"));
        }
        _ => {}
    }

    let task = Task {
        id: Uuid::new_v4().to_string(),
        name: task_request.name.clone(),
        source_path: task_request.source_path,
        remote_name: task_request.remote_name,
        remote_path: task_request.remote_path,
        chunk_size: task_request.chunk_size,
        use_chunking: task_request.use_chunking.unwrap_or(false),
        created_at: Utc::now(),
    };

    match database::create_task(&pool, &task).await {
        Ok(_) => {
            info!(
                "✅ Task '{}' created successfully with ID: {}",
                task.name, task.id
            );
            ResponseJson(ApiResponse::success(task.id))
        }
        Err(e) => {
            error!("Failed to create task '{}': {}", task.name, e);
            ResponseJson(ApiResponse::error("Failed to create task"))
        }
    }
}

pub async fn get_tasks(
    Extension(pool): Extension<Pool<Sqlite>>,
) -> ResponseJson<ApiResponse<Vec<Task>>> {
    match database::get_all_tasks(&pool).await {
        Ok(tasks) => {
            info!("📋 Retrieved {} tasks", tasks.len());
            ResponseJson(ApiResponse::success(tasks))
        }
        Err(e) => {
            error!("Failed to retrieve tasks: {}", e);
            ResponseJson(ApiResponse::error("Failed to retrieve tasks"))
        }
    }
}

pub async fn delete_task(
    Extension(pool): Extension<Pool<Sqlite>>,
    Path(task_id): Path<String>,
) -> ResponseJson<ApiResponse<String>> {
    info!("🗑️ Deleting task: {}", task_id);

    match database::delete_task(&pool, &task_id).await {
        Ok(deleted) if deleted => {
            info!("✅ Task {} deleted successfully", task_id);
            ResponseJson(ApiResponse::success(
                "Task deleted successfully".to_string(),
            ))
        }
        Ok(_) => {
            warn!("Task {} not found for deletion", task_id);
            ResponseJson(ApiResponse::error("Task not found"))
        }
        Err(e) => {
            error!("Failed to delete task {}: {}", task_id, e);
            ResponseJson(ApiResponse::error("Failed to delete task"))
        }
    }
}

pub async fn start_task(
    Extension(pool): Extension<Pool<Sqlite>>,
    Json(start_request): Json<StartTaskRequest>,
) -> ResponseJson<ApiResponse<String>> {
    info!("🚀 Starting task: {}", start_request.task_name);

    // Get task from database
    let task = match database::get_task_by_name(&pool, &start_request.task_name).await {
        Ok(Some(task)) => task,
        Ok(None) => {
            warn!("Task '{}' not found", start_request.task_name);
            return ResponseJson(ApiResponse::error("Task not found"));
        }
        Err(e) => {
            error!(
                "Failed to retrieve task '{}': {}",
                start_request.task_name, e
            );
            return ResponseJson(ApiResponse::error("Failed to retrieve task"));
        }
    };

    // Convert task to sync request
    let sync_request = SyncRequest {
        source_path: task.source_path,
        remote_name: task.remote_name,
        remote_path: task.remote_path,
        chunk_size: task.chunk_size,
        use_chunking: Some(task.use_chunking),
    };

    // Start the sync job using existing sync handler
    info!("🔄 Converting task '{}' to sync job", task.name);
    sync::start_sync(Json(sync_request)).await
}
#[cfg(test)]
mod tests {
    use super::*;

    fn request(source: &str, remote_name: &str, remote_path: &str) -> TaskRequest {
        TaskRequest {
            name: "backup1".to_string(),
            source_path: source.to_string(),
            remote_name: remote_name.to_string(),
            remote_path: remote_path.to_string(),
            chunk_size: None,
            use_chunking: None,
        }
    }

    #[test]
    fn accepts_a_plain_task() {
        assert!(validate_task_request(&request("/data/photos", "gdrive", "/backup")).is_ok());
    }

    // Legale Ordnernamen mit Sonderzeichen. Die waren zwischenzeitlich
    // abgelehnt; Escaping passiert an der Ausgabe, nicht hier.
    #[test]
    fn accepts_ampersands_and_quotes_in_paths() {
        assert!(validate_task_request(&request("/music/Rock & Roll", "gdrive", "/backup")).is_ok());
        assert!(
            validate_task_request(&request("/photos/Mom's Photos", "gdrive", "/backup")).is_ok()
        );
        assert!(
            validate_task_request(&request("/music/Best of 80's & 90's", "gdrive", "/backup"))
                .is_ok()
        );
        assert!(validate_task_request(&request(
            "/pics/Bilder \"Urlaub 2024\"",
            "gdrive",
            "/backup"
        ))
        .is_ok());
        assert!(validate_task_request(&request("/data/<a>`x`", "gdrive", "/backup")).is_ok());
    }

    // Markup wird in den *Pfadfeldern* angenommen — die Anzeige schreibt per
    // `textContent`, dort liegt der Schutz. Der Wert kommt unverändert wieder
    // heraus. Der Remote-Name ist ausgenommen: er geht in eine
    // rclone-Kommandozeile und wird streng geprüft (siehe Test darunter).
    #[test]
    fn accepts_markup_in_every_path_field() {
        let payload = "<img src=x onerror=window.__XSS__=1>";
        assert!(validate_task_request(&request(payload, "gdrive", "/backup")).is_ok());
        assert!(validate_task_request(&request("/data", "gdrive", payload)).is_ok());
    }

    /// Der Remote-Name eines Tasks wird gegen dieselbe zentrale Regel geprüft
    /// wie überall sonst — sonst wandert `:local` über den Umweg eines
    /// gespeicherten Tasks in den rclone-Aufruf.
    #[test]
    fn rejects_dangerous_remote_names() {
        for bad in [
            "<img src=x onerror=window.__XSS__=1>",
            ":local",
            "gdrive:",
            "a/b",
            "a\\b",
            "[evil]",
            "a=b",
            "gdrive\n[evil]",
            "",
        ] {
            assert!(
                validate_task_request(&request("/data", bad, "/backup")).is_err(),
                "Remote-Name {:?} haette abgelehnt werden muessen",
                bad
            );
        }

        for good in ["gdrive", "my-remote_1", "web.dav", "nextcloud@home"] {
            assert!(
                validate_task_request(&request("/data", good, "/backup")).is_ok(),
                "Remote-Name {:?} haette angenommen werden muessen",
                good
            );
        }
    }

    #[test]
    fn rejects_control_characters_and_line_breaks() {
        assert!(validate_task_request(&request("/data\nrm -rf", "gdrive", "/backup")).is_err());
        assert!(validate_task_request(&request("/data\rx", "gdrive", "/backup")).is_err());
        assert!(validate_task_request(&request("/data\u{0}", "gdrive", "/backup")).is_err());
        assert!(validate_task_request(&request("/data", "gdrive\n[evil]", "/backup")).is_err());
        assert!(validate_task_request(&request("/data", "gdrive", "/b\u{7}ackup")).is_err());
    }

    #[test]
    fn rejects_overlong_path_fields() {
        let long = "a".repeat(4097);
        assert!(validate_task_request(&request(&long, "gdrive", "/backup")).is_err());
    }

    #[test]
    fn rejects_empty_path_fields() {
        assert!(validate_task_request(&request("", "gdrive", "/backup")).is_err());
        assert!(validate_task_request(&request("/data", "", "/backup")).is_err());
        assert!(validate_task_request(&request("/data", "gdrive", "")).is_err());
    }

    #[test]
    fn rejects_chunk_size_with_control_characters() {
        let mut req = request("/data", "gdrive", "/backup");
        req.chunk_size = Some("64M\n".to_string());
        assert!(validate_task_request(&req).is_err());

        req.chunk_size = Some("64M".to_string());
        assert!(validate_task_request(&req).is_ok());
    }

    #[test]
    fn still_rejects_a_bad_task_name() {
        let mut req = request("/data", "gdrive", "/backup");
        req.name = "<img src=x>".to_string();
        assert!(validate_task_request(&req).is_err());
    }
}
