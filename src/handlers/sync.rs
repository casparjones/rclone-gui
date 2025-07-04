use axum::{extract::Json, response::Json as ResponseJson};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::process::Command;
use tokio::fs;
use uuid::Uuid;
use chrono::{self, Utc};
use tracing::{info, warn, error, debug};
use serde_json;
use crate::models::{ApiResponse, SyncRequest, SyncProgress};

type SyncJobs = Arc<Mutex<HashMap<String, SyncProgress>>>;

lazy_static::lazy_static! {
    static ref SYNC_JOBS: SyncJobs = Arc::new(Mutex::new(HashMap::new()));
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

pub async fn start_sync(Json(sync_request): Json<SyncRequest>) -> ResponseJson<ApiResponse<String>> {
    let job_id = Uuid::new_v4().to_string();

    info!("🚀 Starting new sync job: {}", job_id);
    info!("   Source: {}", sync_request.source_path);
    info!("   Remote: {}:{}", sync_request.remote_name, sync_request.remote_path);

    let source_name = sync_request.source_path.split('/').last().unwrap_or(&sync_request.source_path).to_string();
    let start_time = Utc::now().timestamp();
    
    let progress = SyncProgress {
        id: job_id.clone(),
        progress: 0.0,
        status: "Starting".to_string(),
        transferred: 0,
        total: 0,
        source_name,
        start_time,
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

    let job_id_clone = job_id.clone();
    let sync_jobs = SYNC_JOBS.clone();

    tokio::spawn(async move {
        execute_sync(job_id_clone, sync_request, sync_jobs).await;
    });

    ResponseJson(ApiResponse::success(job_id))
}

pub async fn get_sync_progress(job_id: String) -> ResponseJson<ApiResponse<SyncProgress>> {
    let mut jobs = SYNC_JOBS.lock().await;

    match jobs.get_mut(&job_id) {
        Some(progress) => {
            // Update progress from log file if job is running
            if progress.status == "Running" {
                if let Some((percent, transferred, total)) = parse_latest_progress_from_log(&job_id).await {
                    progress.progress = percent;
                    progress.transferred = transferred;
                    progress.total = total;
                }
            }
            ResponseJson(ApiResponse::success(progress.clone()))
        },
        None => ResponseJson(ApiResponse::error("Job not found")),
    }
}

pub async fn list_sync_jobs() -> ResponseJson<ApiResponse<Vec<SyncProgress>>> {
    let jobs = SYNC_JOBS.lock().await;
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
            info!("📖 Log file read successfully for job {}, {} bytes", job_id, content.len());
            ResponseJson(ApiResponse::success(content))
        },
        Err(e) => {
            warn!("📖 Log file read failed for job {}: {}", job_id, e);
            ResponseJson(ApiResponse::error(&format!("Log file not found: {}", e)))
        },
    }
}

pub async fn delete_sync_job(job_id: String) -> ResponseJson<ApiResponse<String>> {
    info!("🗑️ Delete request for job {}", job_id);

    let mut jobs = SYNC_JOBS.lock().await;

    // Check if job exists and is completed
    let can_delete = if let Some(job) = jobs.get(&job_id) {
        let deletable = job.status == "Completed" || job.status == "Failed" || job.status.contains("Error");
        info!("📊 Job {} status: {}, can delete: {}", job_id, job.status, deletable);
        deletable
    } else {
        warn!("❌ Job {} not found for deletion", job_id);
        false
    };

    if !can_delete {
        return ResponseJson(ApiResponse::error("Can only delete completed or failed jobs"));
    }

    // Remove from memory
    jobs.remove(&job_id);

    // Remove log file
    let log_file_path = format!("data/log/{}.log", job_id);
    if let Err(e) = fs::remove_file(&log_file_path).await {
        println!("Warning: Could not delete log file {}: {}", log_file_path, e);
    }

    ResponseJson(ApiResponse::success("Job deleted successfully".to_string()))
}

async fn execute_sync(job_id: String, sync_request: SyncRequest, sync_jobs: SyncJobs) {
    let remote_target = format!("{}:{}", sync_request.remote_name, sync_request.remote_path);
    let config_path = "data/cfg/rclone.conf";
    let log_file_path = format!("data/log/{}.log", job_id);

    // Ensure log directory and initial log exist in case start_sync didn't manage to create them (e.g. on crash)
    if let Err(e) = create_initial_log(&job_id, &sync_request).await {
        eprintln!("Failed to ensure initial log: {}", e);
    }

    {
        let mut jobs = sync_jobs.lock().await;
        if let Some(progress) = jobs.get_mut(&job_id) {
            progress.status = "Running".to_string();
        }
    }

    // Build basic rclone arguments with JSON logging
    let mut args = vec![
        "copy",
        "--config", config_path,
        &sync_request.source_path,
        &remote_target,
        "--stats", "1s",
        "--stats-log-level", "NOTICE",
        "--transfers=1",
        "--checkers=1", 
        "--retries=3",
        "--low-level-retries=3",
        "--timeout=0",
        "--contimeout=60s",
        "--ignore-checksum",
        "--size-only",
        "--use-json-log",
        "--log-file", &log_file_path,
        "--log-level", "INFO",
    ];

    // Add multi-threading and WebDAV chunk size based on chunk size selection
    let multi_thread_streams_str;
    let multi_thread_cutoff_str;
    let webdav_chunk_size_str;
    
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
            "128M" => "100M",  // Cap at 100M for WebDAV safety
            _ => "50M",
        };
        
        multi_thread_streams_str = format!("--multi-thread-streams={}", streams);
        multi_thread_cutoff_str = format!("--multi-thread-cutoff={}", chunk_size);
        webdav_chunk_size_str = format!("--webdav-nextcloud-chunk-size={}", webdav_chunk);
        
        // Log the actual parameter values being set
        info!("🔧 Setting rclone parameters:");
        info!("   multi_thread_streams_str: {}", multi_thread_streams_str);
        info!("   multi_thread_cutoff_str: {}", multi_thread_cutoff_str);
        info!("   webdav_chunk_size_str: {}", webdav_chunk_size_str);
        
        args.push(&multi_thread_streams_str);
        args.push(&multi_thread_cutoff_str);
        args.push(&webdav_chunk_size_str);
        
        info!("🔧 Using chunk size: {} (streams: {}, multi-thread-cutoff: {}, webdav-chunk: {})", 
            chunk_size, streams, chunk_size, webdav_chunk);
    } else {
        // Default settings
        args.push("--multi-thread-streams=4");
        args.push("--multi-thread-cutoff=250M");
        args.push("--webdav-nextcloud-chunk-size=50M");
        
        info!("🔧 Using default settings (streams: 4, cutoff: 250M, webdav-chunk: 50M)");
    }

    // Print the full rclone command being executed (debug only)
    info!("🚀 Executing rclone command: {}", args.join(" "));
    
    // Spawn rclone - no need to capture output since it writes to log file
    let mut child = match Command::new("rclone")
        .args(&args)
        .spawn()
    {
        Ok(child) => {
            info!("✅ Rclone process started for job {}", job_id);
            child
        },
        Err(e) => {
            let error_msg = format!("Failed to spawn rclone process: {}", e);
            error!("❌ {}", error_msg);
            
            let mut jobs = sync_jobs.lock().await;
            if let Some(progress) = jobs.get_mut(&job_id) {
                progress.status = error_msg;
            }
            return;
        }
    };

    // Wait for rclone to exit - no output processing needed as rclone writes to log file
    let status = child.wait().await;

    // Update in-memory status based on exit code
    let mut jobs = sync_jobs.lock().await;
    if let Some(progress) = jobs.get_mut(&job_id) {
        match &status {
            Ok(es) if es.success() => {
                progress.status = "Completed".to_string();
                progress.progress = 100.0;
                info!("✅ Job {} completed successfully", job_id);
            }
            Ok(es) => {
                progress.status = "Failed".to_string();
                warn!("❌ Job {} failed with exit code: {:?}", job_id, es.code());
            }
            Err(e) => {
                progress.status = format!("Error: {}", e);
                error!("💥 Job {} error: {}", job_id, e);
            }
        }
    }
}

/// Parse the latest progress from the rclone JSON log file
/// Reads the last 10 lines and looks for the most recent stats entry
async fn parse_latest_progress_from_log(job_id: &str) -> Option<(f64, u64, u64)> {
    let log_file_path = format!("data/log/{}.log", job_id);
    
    // Read the log file
    let content = match fs::read_to_string(&log_file_path).await {
        Ok(content) => content,
        Err(_) => {
            debug!("📖 Could not read log file for job {}", job_id);
            return None;
        }
    };
    
    // Get last 10 lines
    let lines: Vec<&str> = content.lines().collect();
    let start_idx = if lines.len() > 10 { lines.len() - 10 } else { 0 };
    let last_lines = &lines[start_idx..];
    
    // Parse JSON logs in reverse order (newest first)
    for line in last_lines.iter().rev() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            // Debug: Log what we find for development
            if let Some(level) = json.get("level").and_then(|v| v.as_str()) {
                if level == "notice" || level == "info" {
                    debug!("🔍 Found JSON log entry for {}: level={}, msg={:?}", 
                        job_id, level, json.get("msg"));
                }
            }
            
            // Look for NOTICE level entries with stats (rclone JSON stats)
            if let Some(level) = json.get("level").and_then(|v| v.as_str()) {
                if level == "notice" {
                    if let Some(progress_info) = parse_json_stats(&json) {
                        debug!("📊 Found NOTICE stats in log for job {}: {}%", job_id, progress_info.0);
                        return Some(progress_info);
                    }
                }
                
                // Check for successful file copy completion
                if level == "info" {
                    if let Some(msg) = json.get("msg").and_then(|v| v.as_str()) {
                        if msg == "Copied (new)" || msg == "Copied (replaced existing)" {
                            if let Some(object_name) = json.get("object").and_then(|v| v.as_str()) {
                                debug!("✅ File successfully copied for job {}: {}", job_id, object_name);
                                // This indicates successful completion, return 100%
                                // Use reasonable default values for bytes if not available
                                let total_bytes = json.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
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
                        debug!("📊 Found traditional progress in JSON msg for job {}: {}%", job_id, progress_info.0);
                        return Some(progress_info);
                    }
                }
            }
        }
    }
    
    debug!("📖 No recent progress found in log for job {}", job_id);
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
            stats.get("totalBytes").and_then(|v| v.as_u64())
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
        json.get("totalBytes").and_then(|v| v.as_u64())
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
        json.get("totalSize").and_then(|v| v.as_u64())
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
            if let Some(last_comma_or_space) = before_percent.rfind(|c: char| c == ',' || c == ' ') {
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
            let total_part = rest.split(|c| c == ',' || c == '%').next().unwrap_or(rest).trim();
            return (parse_byte_value(transferred_part), parse_byte_value(total_part));
        }
    }
    (0, 0)
}

/// Convert strings like "1.23 MByte" to bytes
fn parse_byte_value(s: &str) -> u64 {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() { return 0; }
    let num: f64 = parts[0].replace(',', "").parse().unwrap_or(0.0);
    if parts.len() == 1 { return num as u64; }
    match parts[1].to_lowercase().as_str() {
        "byte" | "bytes" | "b" => num as u64,
        "kbyte" | "kb" | "k" => (num * 1024.0) as u64,
        "mbyte" | "mb" | "m" => (num * 1024.0 * 1024.0) as u64,
        "gbyte" | "gb" | "g" => (num * 1024.0 * 1024.0 * 1024.0) as u64,
        "tbyte" | "tb" | "t" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => num as u64,
    }
}
