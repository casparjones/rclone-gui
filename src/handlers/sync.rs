use axum::{extract::Json, response::Json as ResponseJson};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::process::Command;
use uuid::Uuid;
use crate::models::{ApiResponse, SyncRequest, SyncProgress};

type SyncJobs = Arc<Mutex<HashMap<String, SyncProgress>>>;

lazy_static::lazy_static! {
    static ref SYNC_JOBS: SyncJobs = Arc::new(Mutex::new(HashMap::new()));
}

pub async fn start_sync(Json(sync_request): Json<SyncRequest>) -> ResponseJson<ApiResponse<String>> {
    let job_id = Uuid::new_v4().to_string();
    
    let progress = SyncProgress {
        id: job_id.clone(),
        progress: 0.0,
        status: "Starting".to_string(),
        transferred: 0,
        total: 0,
    };
    
    {
        let mut jobs = SYNC_JOBS.lock().await;
        jobs.insert(job_id.clone(), progress);
    }

    let job_id_clone = job_id.clone();
    let sync_jobs = SYNC_JOBS.clone();
    
    tokio::spawn(async move {
        execute_sync(job_id_clone, sync_request, sync_jobs).await;
    });

    ResponseJson(ApiResponse::success(job_id))
}

pub async fn get_sync_progress(job_id: String) -> ResponseJson<ApiResponse<SyncProgress>> {
    let jobs = SYNC_JOBS.lock().await;
    
    match jobs.get(&job_id) {
        Some(progress) => ResponseJson(ApiResponse::success(progress.clone())),
        None => ResponseJson(ApiResponse::error("Job not found")),
    }
}

pub async fn list_sync_jobs() -> ResponseJson<ApiResponse<Vec<SyncProgress>>> {
    let jobs = SYNC_JOBS.lock().await;
    let job_list: Vec<SyncProgress> = jobs.values().cloned().collect();
    ResponseJson(ApiResponse::success(job_list))
}

async fn execute_sync(job_id: String, sync_request: SyncRequest, sync_jobs: SyncJobs) {
    let remote_target = format!("{}:{}", sync_request.remote_name, sync_request.remote_path);
    let config_path = "data/cfg/rclone.conf";
    
    {
        let mut jobs = sync_jobs.lock().await;
        if let Some(progress) = jobs.get_mut(&job_id) {
            progress.status = "Running".to_string();
        }
    }

    // Build basic rclone arguments with only valid flags
    let mut args = vec![
        "copy",
        "--config", config_path,
        &sync_request.source_path,
        &remote_target,
        "--progress",
        "--stats=1s",
        "--transfers=1",              // Eine Datei gleichzeitig
        "--checkers=1",               // Ein Checker gleichzeitig
        "--retries=3",                // 3 Wiederholungsversuche
        "--low-level-retries=3",      // Low-level Wiederholungen
        "--timeout=0",                // Kein Timeout
        "--contimeout=60s",           // 60s Verbindungs-Timeout
        "--ignore-checksum",          // Checksum-Probleme ignorieren
        "--size-only",                // Nur Größe vergleichen
    ];

    // Add multi-threading based on chunk size selection
    let multi_thread_str;
    if let Some(chunk_size) = &sync_request.chunk_size {
        // Use chunk size to determine multi-threading level
        let streams = match chunk_size.as_str() {
            "8M" => "2",   // Kleinere Chunks = weniger Streams
            "16M" => "4",  // Mittlere Chunks = mittlere Streams
            "32M" => "6",  // Größere Chunks = mehr Streams
            "64M" => "8",  // Sehr große Chunks = viele Streams
            "128M" => "8", // Maximum Streams
            _ => "4",      // Default
        };
        multi_thread_str = format!("--multi-thread-streams={}", streams);
        args.push(&multi_thread_str);
    } else {
        // Default multi-threading
        args.push("--multi-thread-streams=4");
    }

    let mut child = match Command::new("rclone")
        .args(&args)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let mut jobs = sync_jobs.lock().await;
            if let Some(progress) = jobs.get_mut(&job_id) {
                progress.status = format!("Error: {}", e);
            }
            return;
        }
    };

    let status = child.wait().await;
    
    {
        let mut jobs = sync_jobs.lock().await;
        if let Some(progress) = jobs.get_mut(&job_id) {
            match status {
                Ok(exit_status) if exit_status.success() => {
                    progress.status = "Completed".to_string();
                    progress.progress = 100.0;
                }
                Ok(_) => {
                    progress.status = "Failed".to_string();
                }
                Err(e) => {
                    progress.status = format!("Error: {}", e);
                }
            }
        }
    }
}