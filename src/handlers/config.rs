use axum::{extract::Json, response::Json as ResponseJson, Extension};
use std::sync::Arc;
use crate::models::{ApiResponse, ConfigRequest, RcloneConfig};
use crate::config_manager::ConfigManager;

pub async fn get_configs(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
) -> ResponseJson<ApiResponse<Vec<RcloneConfig>>> {
    match config_manager.load_configs().await {
        Ok(configs) => ResponseJson(ApiResponse::success(configs)),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

pub async fn save_config(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
    Json(config_request): Json<ConfigRequest>,
) -> ResponseJson<ApiResponse<String>> {
    match config_manager.save_config(&config_request).await {
        Ok(_) => ResponseJson(ApiResponse::success("Configuration saved successfully".to_string())),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

pub async fn delete_config(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
    name: String,
) -> ResponseJson<ApiResponse<String>> {
    match config_manager.delete_config(&name).await {
        Ok(_) => ResponseJson(ApiResponse::success("Configuration deleted successfully".to_string())),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

pub async fn persist_configs(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
) -> ResponseJson<ApiResponse<String>> {
    match config_manager.persist_to_file().await {
        Ok(_) => ResponseJson(ApiResponse::success("Configurations persisted to file successfully".to_string())),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

pub async fn get_config_for_edit(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
    name: String,
) -> ResponseJson<ApiResponse<RcloneConfig>> {
    match config_manager.load_configs().await {
        Ok(configs) => {
            if let Some(mut config) = configs.into_iter().find(|c| c.name == name) {
                // Try to reveal password for editing
                if let Some(ref obscured_password) = config.password {
                    if !obscured_password.is_empty() {
                        match config_manager.reveal_password(obscured_password).await {
                            Ok(revealed) => config.password = Some(revealed),
                            Err(_) => {
                                // If revelation fails, keep the obscured password
                                // This might happen if password was stored in plain text
                            }
                        }
                    }
                }
                ResponseJson(ApiResponse::success(config))
            } else {
                ResponseJson(ApiResponse::error("Configuration not found"))
            }
        }
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

