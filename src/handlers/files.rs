use axum::{extract::Query, response::Json as ResponseJson};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::process::Command;
use crate::models::{ApiResponse, FileEntry};

pub async fn list_local_files(
    Query(params): Query<HashMap<String, String>>,
) -> ResponseJson<ApiResponse<Vec<FileEntry>>> {
    let default_path = std::env::var("RCLONE_GUI_DEFAULT_PATH").unwrap_or_else(|_| "/mnt/home".to_string());
    let path = params.get("path").unwrap_or(&default_path).clone();
    
    match list_directory(&path).await {
        Ok(files) => ResponseJson(ApiResponse::success(files)),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

pub async fn list_remote_files(
    Query(params): Query<HashMap<String, String>>,
) -> ResponseJson<ApiResponse<Vec<FileEntry>>> {
    let remote_name = match params.get("remote") {
        Some(name) => name,
        None => return ResponseJson(ApiResponse::error("Remote name is required")),
    };
    
    let remote_path = params.get("path").unwrap_or(&"/".to_string()).clone();
    
    match list_remote_directory(remote_name, &remote_path).await {
        Ok(files) => ResponseJson(ApiResponse::success(files)),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

async fn list_directory(path: &str) -> anyhow::Result<Vec<FileEntry>> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(anyhow::anyhow!("Directory does not exist"));
    }

    let mut files = Vec::new();
    
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let file_name = entry.file_name().to_string_lossy().to_string();
        let file_path = entry.path().to_string_lossy().to_string();
        
        let size = if metadata.is_file() {
            Some(metadata.len())
        } else {
            None
        };

        let modified = metadata.modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs().to_string());

        files.push(FileEntry {
            name: file_name,
            path: file_path,
            is_dir: metadata.is_dir(),
            size,
            modified,
        });
    }

    files.sort_by(|a, b| {
        if a.is_dir && !b.is_dir {
            std::cmp::Ordering::Less
        } else if !a.is_dir && b.is_dir {
            std::cmp::Ordering::Greater
        } else {
            a.name.cmp(&b.name)
        }
    });

    Ok(files)
}

async fn list_remote_directory(remote_name: &str, remote_path: &str) -> anyhow::Result<Vec<FileEntry>> {
    let remote_full_path = format!("{}:{}", remote_name, remote_path);
    let config_path = "data/cfg/rclone.conf";
    
    let output = Command::new("rclone")
        .args(&["lsjson", "--config", config_path, &remote_full_path])
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