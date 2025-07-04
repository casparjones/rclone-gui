use axum::{extract::Json, response::Json as ResponseJson};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::process::Command;
use std::process::Stdio;
use tokio::io::{BufReader, AsyncBufReadExt};
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
        "-P",
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
    let multi_thread_streams_str;
    let multi_thread_cutoff_str;
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
        multi_thread_streams_str = format!("--multi-thread-streams={}", streams);
        multi_thread_cutoff_str = format!("--multi-thread-cutoff={}", chunk_size);
        args.push(&multi_thread_streams_str);
        args.push(&multi_thread_cutoff_str);
    } else {
        // Default multi-threading - only enable for files larger than 250MB
        args.push("--multi-thread-streams=4");
        args.push("--multi-thread-cutoff=250M");
    }

    // Debug: Print the full rclone command being executed
    println!("DEBUG: Executing rclone command:");
    println!("DEBUG: rclone {}", args.join(" "));
    
    // TEST MODE: Uncomment the next 4 lines to test progress parsing with fake output
    // let mut child = match Command::new("bash")
    //     .args(&["-c", "echo 'Transferred: 1.234 MByte / 5.678 MByte, 21%, 345.67 kByte/s, ETA 12s'; sleep 2; echo 'Transferred: 3.456 MByte / 5.678 MByte, 60%, 500 kByte/s, ETA 4s'; sleep 2; echo 'Transferred: 5.678 MByte / 5.678 MByte, 100%, 600 kByte/s, ETA 0s'"])
    
    let mut child = match Command::new("rclone")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            println!("DEBUG: rclone process started successfully");
            child
        },
        Err(e) => {
            let error_msg = format!("Failed to spawn rclone process: {}", e);
            println!("ERROR: {}", error_msg);
            let mut jobs = sync_jobs.lock().await;
            if let Some(progress) = jobs.get_mut(&job_id) {
                progress.status = error_msg;
            }
            return;
        }
    };

    // Capture stderr for progress information (rclone outputs progress to stderr)
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            println!("ERROR: Could not capture stderr from rclone process");
            let mut jobs = sync_jobs.lock().await;
            if let Some(progress) = jobs.get_mut(&job_id) {
                progress.status = "Error: Could not capture rclone output".to_string();
            }
            return;
        }
    };
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    // Spawn a task to read rclone output and update progress
    let job_id_for_output = job_id.clone();
    let sync_jobs_for_output = sync_jobs.clone();
    let output_task = tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            // Print every line from rclone for debugging
            println!("🔧 RCLONE RAW OUTPUT: {}", line);
            
            // Try to parse progress and show detailed parsing info
            if let Some(progress_info) = parse_rclone_progress(&line) {
                println!("✅ PARSED SUCCESSFULLY:");
                println!("   📊 Progress: {}%", progress_info.0);
                println!("   📤 Transferred: {} bytes ({:.2} MB)", 
                    progress_info.1, 
                    progress_info.1 as f64 / 1024.0 / 1024.0);
                println!("   📁 Total Size: {} bytes ({:.2} MB)", 
                    progress_info.2, 
                    progress_info.2 as f64 / 1024.0 / 1024.0);
                println!("   🎯 Completion: {:.1}%", 
                    if progress_info.2 > 0 { 
                        (progress_info.1 as f64 / progress_info.2 as f64) * 100.0 
                    } else { 
                        0.0 
                    });
                println!(""); // Empty line for readability
                
                let mut jobs = sync_jobs_for_output.lock().await;
                if let Some(progress) = jobs.get_mut(&job_id_for_output) {
                    progress.progress = progress_info.0;
                    progress.transferred = progress_info.1;
                    progress.total = progress_info.2;
                    progress.status = "Running".to_string();
                    println!("🔄 UPDATED JOB STATUS: {}% - {} bytes transferred", 
                        progress.progress, progress.transferred);
                }
            } else {
                // Show when parsing fails
                if line.contains("Transferred") || line.contains("%") || line.contains("ETA") {
                    println!("❌ PARSING FAILED for line containing progress indicators:");
                    println!("   Line: '{}'", line);
                    println!("   Contains 'Transferred': {}", line.contains("Transferred"));
                    println!("   Contains '%': {}", line.contains("%"));
                    println!("   Contains 'ETA': {}", line.contains("ETA"));
                    println!("");
                }
            }
        }
        println!("🏁 RCLONE OUTPUT STREAM ENDED");
    });

    let status = child.wait().await;
    output_task.abort(); // Stop reading output when process ends
    
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

/// Parse rclone progress output to extract progress percentage, transferred bytes, and total bytes
/// Returns: (progress_percent, transferred_bytes, total_bytes)
fn parse_rclone_progress(line: &str) -> Option<(f64, u64, u64)> {
    // rclone progress output examples:
    // "Transferred:      1.234 MByte / 5.678 MByte, 21%, 345.67 kByte/s, ETA 12s"
    // "Transferred:        123 / 456, 27%"
    // " * file.txt: 100% /1.23MB, 456kB/s, 2s"
    
    // Check for standard "Transferred:" lines
    if line.contains("Transferred:") && line.contains("%") {
        // Try to extract percentage
        if let Some(percent_pos) = line.find("%") {
            // Look backwards from % to find the number
            let before_percent = &line[..percent_pos];
            if let Some(last_comma_or_space) = before_percent.rfind(|c: char| c == ',' || c == ' ') {
                let percent_str = before_percent[last_comma_or_space + 1..].trim();
                if let Ok(progress) = percent_str.parse::<f64>() {
                    // Try to extract transferred and total bytes
                    let (transferred, total) = parse_transferred_bytes(line);
                    return Some((progress, transferred, total));
                }
            }
        }
    }
    
    // Check for individual file progress lines like " * file.txt: 100% /1.23MB, 456kB/s, 2s"
    if line.contains(": ") && line.contains("% /") {
        if let Some(percent_start) = line.find(": ") {
            let after_colon = &line[percent_start + 2..];
            if let Some(percent_end) = after_colon.find("% /") {
                let percent_str = after_colon[..percent_end].trim();
                if let Ok(progress) = percent_str.parse::<f64>() {
                    // Extract file size from after "% /"
                    let after_percent = &after_colon[percent_end + 3..];
                    if let Some(comma_pos) = after_percent.find(',') {
                        let size_str = after_percent[..comma_pos].trim();
                        let total_bytes = parse_byte_value(size_str);
                        let transferred_bytes = ((progress / 100.0) * total_bytes as f64) as u64;
                        return Some((progress, transferred_bytes, total_bytes));
                    }
                }
            }
        }
    }
    
    None
}

/// Parse transferred bytes from rclone output
/// Returns: (transferred_bytes, total_bytes)
fn parse_transferred_bytes(line: &str) -> (u64, u64) {
    println!("🔍 PARSING BYTES from line: '{}'", line);
    
    // Look for pattern like "1.234 MByte / 5.678 MByte" or "123 / 456"
    if let Some(transferred_start) = line.find("Transferred:") {
        let after_transferred = &line[transferred_start + 12..].trim();
        println!("   After 'Transferred:': '{}'", after_transferred);
        
        // Look for the pattern "number unit / number unit" or "number / number"
        if let Some(slash_pos) = after_transferred.find(" / ") {
            let transferred_part = after_transferred[..slash_pos].trim();
            let remaining = &after_transferred[slash_pos + 3..];
            
            println!("   Found slash at position: {}", slash_pos);
            println!("   Transferred part: '{}'", transferred_part);
            println!("   Remaining part: '{}'", remaining);
            
            // Find where the total part ends (before comma or percentage)
            let total_part = if let Some(comma_pos) = remaining.find(',') {
                println!("   Found comma at position: {}", comma_pos);
                remaining[..comma_pos].trim()
            } else if let Some(percent_pos) = remaining.find('%') {
                println!("   Found % at position: {}", percent_pos);
                // Find the last space before %
                if let Some(space_pos) = remaining[..percent_pos].rfind(' ') {
                    remaining[..space_pos].trim()
                } else {
                    remaining.trim()
                }
            } else {
                println!("   No comma or % found, using whole remaining");
                remaining.trim()
            };
            
            println!("   Final total part: '{}'", total_part);
            
            let transferred = parse_byte_value(transferred_part);
            let total = parse_byte_value(total_part);
            
            println!("   Parsed transferred: {} bytes", transferred);
            println!("   Parsed total: {} bytes", total);
            
            return (transferred, total);
        }
    }
    (0, 0)
}

/// Parse a byte value like "1.234 MByte" or "123" to bytes
fn parse_byte_value(value_str: &str) -> u64 {
    println!("     🔢 Parsing byte value: '{}'", value_str);
    
    let parts: Vec<&str> = value_str.split_whitespace().collect();
    if parts.is_empty() {
        println!("     ❌ No parts found");
        return 0;
    }
    
    println!("     Parts: {:?}", parts);
    
    let number_str = parts[0];
    let number = if let Ok(n) = number_str.parse::<f64>() {
        println!("     ✅ Parsed number: {}", n);
        n
    } else {
        println!("     ❌ Could not parse number: '{}'", number_str);
        return 0;
    };
    
    if parts.len() == 1 {
        // Just a number, assume bytes
        println!("     📝 No unit, assuming bytes: {}", number as u64);
        return number as u64;
    }
    
    let unit = parts[1].to_lowercase();
    println!("     📏 Unit (lowercase): '{}'", unit);
    
    let multiplier = match unit.as_str() {
        "byte" | "bytes" | "b" => 1u64,
        "kbyte" | "kb" | "k" => 1024u64,
        "mbyte" | "mb" | "m" => 1024u64 * 1024u64,
        "gbyte" | "gb" | "g" => 1024u64 * 1024u64 * 1024u64,
        "tbyte" | "tb" | "t" => 1024u64 * 1024u64 * 1024u64 * 1024u64,
        _ => {
            println!("     ⚠️  Unknown unit '{}', using multiplier 1", unit);
            1u64
        },
    };
    
    let result = (number * multiplier as f64) as u64;
    println!("     ✅ Final result: {} bytes (number: {} × multiplier: {})", result, number, multiplier);
    
    result
}