use axum::{extract::Json, response::Json as ResponseJson, Extension, extract::Path};
use sqlx::{Pool, Sqlite};
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn, error};
use crate::models::{ApiResponse, Task, TaskRequest, StartTaskRequest, SyncRequest};
use crate::database;
use crate::handlers::sync;

fn validate_task_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Task name cannot be empty".to_string());
    }
    
    if name.len() > 50 {
        return Err("Task name cannot be longer than 50 characters".to_string());
    }
    
    // Check if name is alphanumeric (plus underscore and hyphen)
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err("Task name can only contain alphanumeric characters, underscores, and hyphens".to_string());
    }
    
    Ok(())
}

pub async fn create_task(
    Extension(pool): Extension<Pool<Sqlite>>,
    Json(task_request): Json<TaskRequest>,
) -> ResponseJson<ApiResponse<String>> {
    info!("🎯 Creating new task: {}", task_request.name);
    
    // Validate task name
    if let Err(e) = validate_task_name(&task_request.name) {
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
            info!("✅ Task '{}' created successfully with ID: {}", task.name, task.id);
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
            ResponseJson(ApiResponse::success("Task deleted successfully".to_string()))
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
            error!("Failed to retrieve task '{}': {}", start_request.task_name, e);
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