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

    // Build basic rclone arguments
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
        "--multi-thread-streams=4",   // Multi-threading für große Dateien
        "--webdav-chunk-size=8M",     // WebDAV Chunk-Größe
        "--s3-chunk-size=8M",         // S3 Chunk-Größe
        "--s3-upload-part-size=8M",   // S3 Upload Part-Größe
    ];

    // Add chunking parameters if specified
    let chunk_size_str;
    let s3_chunk_str;
    if let Some(chunk_size) = &sync_request.chunk_size {
        chunk_size_str = format!("--webdav-chunk-size={}", chunk_size);
        s3_chunk_str = format!("--s3-chunk-size={}", chunk_size);
        args.push(&chunk_size_str);
        args.push(&s3_chunk_str);
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