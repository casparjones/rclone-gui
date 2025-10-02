use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcloneConfig {
    pub name: String,
    pub config_type: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub additional_fields: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    pub source_path: String,
    pub remote_name: String,
    pub remote_path: String,
    pub chunk_size: Option<String>,  // z.B. "8M", "16M", "32M"
    pub use_chunking: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {
    pub id: String,
    pub progress: f64,
    pub status: String,
    pub transferred: u64,
    pub total: u64,
    pub source_name: String,
    pub start_time: i64,
    pub end_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigRequest {
    pub name: String,
    pub config_type: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub additional_fields: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub source_path: String,
    pub remote_name: String,
    pub remote_path: String,
    pub chunk_size: Option<String>,
    pub use_chunking: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskRequest {
    pub name: String,
    pub source_path: String,
    pub remote_name: String,
    pub remote_path: String,
    pub chunk_size: Option<String>,
    pub use_chunking: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartTaskRequest {
    pub task_name: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }
    }
}