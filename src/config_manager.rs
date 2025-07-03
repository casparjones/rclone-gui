use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::models::{RcloneConfig, ConfigRequest};
use std::path::Path;
use configparser::ini::Ini;
use tokio::process::Command;

pub struct ConfigManager {
    memory_configs: Arc<RwLock<HashMap<String, RcloneConfig>>>,
    use_memory_only: bool,
}

impl ConfigManager {
    pub fn new(use_memory_only: bool) -> Self {
        Self {
            memory_configs: Arc::new(RwLock::new(HashMap::new())),
            use_memory_only,
        }
    }

    pub async fn load_configs(&self) -> anyhow::Result<Vec<RcloneConfig>> {
        if self.use_memory_only {
            let configs = self.memory_configs.read().await;
            Ok(configs.values().cloned().collect())
        } else {
            self.load_from_file().await
        }
    }

    pub async fn save_config(&self, config_request: &ConfigRequest) -> anyhow::Result<()> {
        // Obscure password if provided
        let obscured_password = if let Some(password) = &config_request.password {
            if !password.is_empty() {
                Some(self.obscure_password(password).await?)
            } else {
                None
            }
        } else {
            None
        };

        let config = RcloneConfig {
            name: config_request.name.clone(),
            config_type: config_request.config_type.clone(),
            url: config_request.url.clone(),
            username: config_request.username.clone(),
            password: obscured_password.clone(),
            additional_fields: config_request.additional_fields.clone().unwrap_or_default(),
        };

        if self.use_memory_only {
            let mut configs = self.memory_configs.write().await;
            configs.insert(config.name.clone(), config);
            Ok(())
        } else {
            // Create a modified request with obscured password for file saving
            let mut modified_request = config_request.clone();
            modified_request.password = obscured_password;
            self.save_to_file(&modified_request).await
        }
    }

    pub async fn delete_config(&self, name: &str) -> anyhow::Result<()> {
        if self.use_memory_only {
            let mut configs = self.memory_configs.write().await;
            configs.remove(name);
            Ok(())
        } else {
            self.delete_from_file(name).await
        }
    }

    pub async fn persist_to_file(&self) -> anyhow::Result<()> {
        if !self.use_memory_only {
            return Ok(());
        }

        let configs = self.memory_configs.read().await;
        let config_path = "data/cfg/rclone.conf";
        
        // Ensure directory exists
        if let Some(parent) = Path::new(config_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let mut conf = Ini::new();

        for (_, config) in configs.iter() {
            conf.set(&config.name, "type", Some(config.config_type.clone()));

            if let Some(url) = &config.url {
                conf.set(&config.name, "url", Some(url.clone()));
            }

            if let Some(username) = &config.username {
                conf.set(&config.name, "user", Some(username.clone()));
            }

            if let Some(password) = &config.password {
                if !password.is_empty() {
                    // Note: Passwords in memory configs should already be obscured
                    // when they were saved initially
                    conf.set(&config.name, "pass", Some(password.clone()));
                }
            }

            for (key, value) in &config.additional_fields {
                conf.set(&config.name, key, Some(value.clone()));
            }
        }

        conf.write(config_path).map_err(|e| anyhow::anyhow!("Failed to write config: {}", e))?;
        Ok(())
    }

    pub async fn load_from_file_to_memory(&self) -> anyhow::Result<()> {
        let configs = self.load_from_file().await?;
        let mut memory_configs = self.memory_configs.write().await;
        
        for config in configs {
            memory_configs.insert(config.name.clone(), config);
        }
        
        Ok(())
    }

    async fn load_from_file(&self) -> anyhow::Result<Vec<RcloneConfig>> {
        let config_path = "data/cfg/rclone.conf";
        
        if !Path::new(config_path).exists() {
            return Ok(Vec::new());
        }

        let mut conf = Ini::new();
        conf.load(config_path).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
        let mut configs = Vec::new();

        for section_name in conf.sections() {
                let mut config = RcloneConfig {
                    name: section_name.to_string(),
                    config_type: conf.get(&section_name, "type").unwrap_or("".to_string()),
                    url: conf.get(&section_name, "url"),
                    username: conf.get(&section_name, "user"),
                    password: conf.get(&section_name, "pass"),
                    additional_fields: HashMap::new(),
                };

                // Note: Passwords are loaded as-is from the config file
                // New passwords will be automatically obscured when saved

                if let Some(section_map) = conf.get_map_ref().get(&section_name) {
                    for (key, value) in section_map.iter() {
                        if !matches!(key.as_str(), "type" | "url" | "user" | "pass") {
                            if let Some(value) = value {
                                config.additional_fields.insert(key.to_string(), value.to_string());
                            }
                        }
                    }
                }

                configs.push(config);
        }

        Ok(configs)
    }

    async fn save_to_file(&self, config_request: &ConfigRequest) -> anyhow::Result<()> {
        let config_path = "data/cfg/rclone.conf";
        
        // Ensure directory exists
        if let Some(parent) = Path::new(config_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let mut conf = Ini::new();
        
        if Path::new(config_path).exists() {
            conf.load(config_path).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
        }

        conf.set(&config_request.name, "type", Some(config_request.config_type.clone()));

        if let Some(url) = &config_request.url {
            conf.set(&config_request.name, "url", Some(url.clone()));
        }

        if let Some(username) = &config_request.username {
            conf.set(&config_request.name, "user", Some(username.clone()));
        }

        if let Some(password) = &config_request.password {
            if !password.is_empty() {
                // Password should already be obscured when passed to this method
                conf.set(&config_request.name, "pass", Some(password.clone()));
            }
        }

        if let Some(additional_fields) = &config_request.additional_fields {
            for (key, value) in additional_fields {
                conf.set(&config_request.name, key, Some(value.clone()));
            }
        }

        conf.write(config_path).map_err(|e| anyhow::anyhow!("Failed to write config: {}", e))?;
        Ok(())
    }

    async fn delete_from_file(&self, name: &str) -> anyhow::Result<()> {
        let config_path = "data/cfg/rclone.conf";
        
        if !Path::new(config_path).exists() {
            return Ok(());
        }

        let mut conf = Ini::new();
        conf.load(config_path).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
        conf.remove_section(name);
        conf.write(config_path).map_err(|e| anyhow::anyhow!("Failed to write config: {}", e))?;
        Ok(())
    }

    /// Obscure password using rclone obscure command
    async fn obscure_password(&self, password: &str) -> anyhow::Result<String> {
        let output = Command::new("rclone")
            .args(&["obscure", password])
            .output()
            .await?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to obscure password: {}", error));
        }

        let obscured = String::from_utf8_lossy(&output.stdout);
        Ok(obscured.trim().to_string())
    }

    /// Reveal password using rclone reveal command (for display purposes)
    pub async fn reveal_password(&self, obscured_password: &str) -> anyhow::Result<String> {
        let output = Command::new("rclone")
            .args(&["reveal", obscured_password])
            .output()
            .await?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to reveal password: {}", error));
        }

        let revealed = String::from_utf8_lossy(&output.stdout);
        Ok(revealed.trim().to_string())
    }

}