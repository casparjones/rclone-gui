use crate::models::{ConfigRequest, RcloneConfig};
use configparser::ini::Ini;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::RwLock;

/// Die rclone-Konfiguration, die jedem rclone-Aufruf per `--config` mitgegeben
/// wird. Alles, was gegen "ist dieses Remote konfiguriert?" geprüft wird, muss
/// gegen genau diese Datei geprüft werden – sonst prüft man etwas anderes, als
/// rclone später liest.
pub const RCLONE_CONFIG_PATH: &str = "data/cfg/rclone.conf";

/// Längenobergrenze für einen Remote-Namen. rclone selbst kennt keine, aber ein
/// Name dieser Grösse ist bereits jenseits jeder legitimen Verwendung.
const MAX_REMOTE_NAME_LEN: usize = 64;

/// Syntaktische Prüfung eines Remote-Namens – die **einzige** Stelle im Code,
/// an der entschieden wird, wie ein Remote-Name aussehen darf.
///
/// Sie gilt an beiden Enden: beim **Anlegen** (`POST /api/configs`, damit kein
/// Name als Abschnitts-Kopfzeile in `rclone.conf` injiziert werden kann) und
/// beim **Benutzen** (damit kein Name in eine rclone-Kommandozeile gerät).
/// Zum Benutzen kommt `ensure_configured_remote` hinzu, das zusätzlich
/// verlangt, dass der Name tatsächlich konfiguriert ist.
///
/// Verboten sind insbesondere:
/// * `:` – `:local:` ist rclones On-the-fly-Syntax für ein *nicht*
///   konfiguriertes Backend und führt am gesamten Pfad-Jail vorbei
/// * `/` und `\` – trennen in rclone-Zielen Remote von Pfad
/// * `[`, `]`, `=` und Steuerzeichen – erzeugen in `rclone.conf` zusätzliche
///   Abschnitte und Schlüssel
///
/// Umgesetzt ist das als Positivliste (rclones eigener Zeichenvorrat für
/// Remote-Namen), weil eine Negativliste erfahrungsgemäss immer ein Zeichen
/// vergisst.
pub fn validate_remote_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("Remote name must not be empty");
    }

    if name.chars().count() > MAX_REMOTE_NAME_LEN {
        anyhow::bail!(
            "Remote name must not be longer than {} characters",
            MAX_REMOTE_NAME_LEN
        );
    }

    // Eigene Meldungen für die Zeichen, die tatsächlich gefährlich sind – die
    // generische Meldung der Positivliste würde nicht erklären, warum.
    if let Some(c) = name.chars().find(|c| c.is_control()) {
        anyhow::bail!(
            "Remote name must not contain control characters (U+{:04X})",
            c as u32
        );
    }
    if let Some(c) = name.chars().find(|c| matches!(c, ':' | '/' | '\\')) {
        anyhow::bail!("Remote name must not contain '{}'", c);
    }
    if let Some(c) = name.chars().find(|c| matches!(c, '[' | ']' | '=')) {
        anyhow::bail!("Remote name must not contain '{}'", c);
    }

    if let Some(c) = name.chars().find(|c| !is_allowed_remote_name_char(*c)) {
        anyhow::bail!("Remote name must not contain '{}'", c);
    }

    if name.starts_with(' ') || name.ends_with(' ') {
        anyhow::bail!("Remote name must not start or end with a space");
    }
    if name.starts_with('-') {
        // Sonst liest rclone den Namen als Option.
        anyhow::bail!("Remote name must not start with '-'");
    }

    Ok(())
}

fn is_allowed_remote_name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '@' | ' ')
}

/// Prüfung vor **jeder** Verwendung eines Remote-Namens: syntaktisch sauber
/// *und* in `rclone.conf` vorhanden.
///
/// Wird sie abgelehnt, darf kein rclone-Prozess starten – die Aufrufer rufen
/// sie deshalb vor dem Bau der Kommandozeile auf, nicht danach.
///
/// TODO(Ticket `65fe551e` – eigene rclone-Remotes pro Nutzer): sobald Remotes
/// einem Nutzer gehören, muss hier gegen die Remotes **des angemeldeten
/// Nutzers** geprüft werden, nicht gegen alle konfigurierten. Bis dahin ist die
/// Prüfung bewusst global.
pub async fn ensure_configured_remote(name: &str) -> anyhow::Result<()> {
    validate_remote_name(name)?;

    let contents = tokio::fs::read_to_string(RCLONE_CONFIG_PATH)
        .await
        .map_err(|e| anyhow::anyhow!("rclone configuration is not readable: {}", e))?;

    if configured_remote_names(&contents)
        .iter()
        .any(|configured| configured.eq_ignore_ascii_case(name))
    {
        Ok(())
    } else {
        // Der Name wird bewusst nicht wiederholt: er kommt vom Client.
        Err(anyhow::anyhow!("Unknown remote"))
    }
}

/// Abschnitts-Kopfzeilen aus dem Inhalt einer `rclone.conf`.
///
/// Bewusst ein eigener, minimaler Parser statt `Ini`: `Ini` normalisiert die
/// Gross-/Kleinschreibung, hier wird der Name aber so gebraucht, wie er in der
/// Datei steht.
fn configured_remote_names(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|line| line.trim())
        .filter_map(|line| line.strip_prefix('['))
        .filter_map(|line| line.strip_suffix(']'))
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

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
        // Der Name wird zur Abschnitts-Kopfzeile in `rclone.conf`. Ohne diese
        // Prüfung hängt ein Name mit `[`, `]`, `=` oder Zeilenumbruch beliebige
        // weitere Abschnitte und Schlüssel an die Konfiguration an – und würde
        // eine spätere Prüfung "ist dieses Remote konfiguriert?" anschliessend
        // sogar bestehen. Deshalb steht sie vor allem anderen, insbesondere vor
        // dem `rclone obscure`-Aufruf.
        validate_remote_name(&config_request.name)?;

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

    /// Löschen prüft den Namen bewusst **nicht**: eine `rclone.conf`, in die vor
    /// dieser Prüfung ein bösartiger Abschnitt geraten ist, muss über die
    /// Oberfläche wieder aufräumbar bleiben. Gelöscht wird nur, kein Prozess
    /// gestartet und nichts in die Kommandozeile übernommen.
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
        let config_path = RCLONE_CONFIG_PATH;

        // Ensure directory exists
        if let Some(parent) = Path::new(config_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conf = Ini::new();

        for (_, config) in configs.iter() {
            // Handle WebDAV subtypes and set appropriate type and vendor
            let (actual_type, vendor) = match config.config_type.as_str() {
                "webdav-nextcloud" => ("webdav", Some("nextcloud")),
                "webdav-owncloud" => ("webdav", Some("owncloud")),
                "webdav-sharepoint" => ("webdav", Some("sharepoint")),
                "webdav-fastmail" => ("webdav", Some("fastmail")),
                "webdav-other" => ("webdav", Some("other")),
                _ => (config.config_type.as_str(), None),
            };

            conf.set(&config.name, "type", Some(actual_type.to_string()));

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

            // Set vendor for WebDAV configurations
            if let Some(vendor_value) = vendor {
                conf.set(&config.name, "vendor", Some(vendor_value.to_string()));
            }

            for (key, value) in &config.additional_fields {
                conf.set(&config.name, key, Some(value.clone()));
            }
        }

        conf.write(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to write config: {}", e))?;
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
        let config_path = RCLONE_CONFIG_PATH;

        if !Path::new(config_path).exists() {
            return Ok(Vec::new());
        }

        let mut conf = Ini::new();
        conf.load(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
        let mut configs = Vec::new();

        for section_name in conf.sections() {
            let rclone_type = conf.get(&section_name, "type").unwrap_or("".to_string());
            let vendor = conf.get(&section_name, "vendor");

            let mut config = RcloneConfig {
                name: section_name.to_string(),
                config_type: Self::get_ui_config_type(&rclone_type, vendor.as_deref()),
                url: conf.get(&section_name, "url"),
                username: conf.get(&section_name, "user"),
                password: conf.get(&section_name, "pass"),
                additional_fields: HashMap::new(),
            };

            // Note: Passwords are loaded as-is from the config file
            // New passwords will be automatically obscured when saved

            if let Some(section_map) = conf.get_map_ref().get(&section_name) {
                for (key, value) in section_map.iter() {
                    if !matches!(key.as_str(), "type" | "url" | "user" | "pass" | "vendor") {
                        if let Some(value) = value {
                            config
                                .additional_fields
                                .insert(key.to_string(), value.to_string());
                        }
                    }
                }
            }

            configs.push(config);
        }

        Ok(configs)
    }

    /// Helper function to map rclone type and vendor back to UI subtype
    fn get_ui_config_type(rclone_type: &str, vendor: Option<&str>) -> String {
        match (rclone_type, vendor) {
            ("webdav", Some("nextcloud")) => "webdav-nextcloud".to_string(),
            ("webdav", Some("owncloud")) => "webdav-owncloud".to_string(),
            ("webdav", Some("sharepoint")) => "webdav-sharepoint".to_string(),
            ("webdav", Some("fastmail")) => "webdav-fastmail".to_string(),
            ("webdav", Some("other")) => "webdav-other".to_string(),
            ("webdav", _) => "webdav-other".to_string(), // fallback for webdav without vendor
            (other_type, _) => other_type.to_string(),
        }
    }

    async fn save_to_file(&self, config_request: &ConfigRequest) -> anyhow::Result<()> {
        let config_path = RCLONE_CONFIG_PATH;

        // Ensure directory exists
        if let Some(parent) = Path::new(config_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conf = Ini::new();

        if Path::new(config_path).exists() {
            conf.load(config_path)
                .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
        }

        // Handle WebDAV subtypes and set appropriate type and vendor
        let (actual_type, vendor) = match config_request.config_type.as_str() {
            "webdav-nextcloud" => ("webdav", Some("nextcloud")),
            "webdav-owncloud" => ("webdav", Some("owncloud")),
            "webdav-sharepoint" => ("webdav", Some("sharepoint")),
            "webdav-fastmail" => ("webdav", Some("fastmail")),
            "webdav-other" => ("webdav", Some("other")),
            _ => (config_request.config_type.as_str(), None),
        };

        conf.set(&config_request.name, "type", Some(actual_type.to_string()));

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

        // Set vendor for WebDAV configurations
        if let Some(vendor_value) = vendor {
            conf.set(
                &config_request.name,
                "vendor",
                Some(vendor_value.to_string()),
            );
        }

        if let Some(additional_fields) = &config_request.additional_fields {
            for (key, value) in additional_fields {
                conf.set(&config_request.name, key, Some(value.clone()));
            }
        }

        conf.write(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to write config: {}", e))?;
        Ok(())
    }

    async fn delete_from_file(&self, name: &str) -> anyhow::Result<()> {
        let config_path = RCLONE_CONFIG_PATH;

        if !Path::new(config_path).exists() {
            return Ok(());
        }

        let mut conf = Ini::new();
        conf.load(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
        conf.remove_section(name);
        conf.write(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to write config: {}", e))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_remote_names() {
        for name in [
            "gdrive",
            "my-remote_1",
            "web.dav",
            "nextcloud@home",
            "Backup 2024",
            "remote+1",
        ] {
            assert!(
                validate_remote_name(name).is_ok(),
                "{:?} haette angenommen werden muessen",
                name
            );
        }
    }

    /// `:local:` ist rclones On-the-fly-Syntax fuer ein nicht konfiguriertes
    /// Backend — der eigentliche Ausbruch aus dem Pfad-Jail.
    #[test]
    fn rejects_on_the_fly_backend_syntax() {
        assert!(validate_remote_name(":local").is_err());
        assert!(validate_remote_name(":local:").is_err());
        assert!(validate_remote_name("gdrive:").is_err());
        assert!(validate_remote_name(":http,url='http://x':").is_err());
    }

    /// Diese Zeichen erzeugen in `rclone.conf` zusaetzliche Abschnitte und
    /// Schluessel, wenn der Name als Kopfzeile geschrieben wird.
    #[test]
    fn rejects_config_file_injection() {
        assert!(validate_remote_name("[evil]").is_err());
        assert!(validate_remote_name("a]b").is_err());
        assert!(validate_remote_name("a=b").is_err());
        assert!(validate_remote_name("ok\n[evil]\ntype = local").is_err());
        assert!(validate_remote_name("ok\rx").is_err());
        assert!(validate_remote_name("ok\u{0}").is_err());
        assert!(validate_remote_name("<img src=x onerror=window.__XSS__=1>").is_err());
    }

    #[test]
    fn rejects_path_separators_and_edge_cases() {
        assert!(validate_remote_name("a/b").is_err());
        assert!(validate_remote_name("a\\b").is_err());
        assert!(validate_remote_name("").is_err());
        assert!(validate_remote_name(" lead").is_err());
        assert!(validate_remote_name("trail ").is_err());
        assert!(validate_remote_name("--flag").is_err());
        assert!(validate_remote_name(&"a".repeat(MAX_REMOTE_NAME_LEN + 1)).is_err());
        assert!(validate_remote_name(&"a".repeat(MAX_REMOTE_NAME_LEN)).is_ok());
    }

    #[test]
    fn section_headers_are_read_verbatim() {
        let conf = "\
# Kommentar
[gdrive]
type = drive

[MyBox]
type = webdav
url = https://example.org/[nicht]
";
        assert_eq!(configured_remote_names(conf), vec!["gdrive", "MyBox"]);
    }

    #[tokio::test]
    async fn unconfigured_names_are_rejected_before_anything_else() {
        // Ohne lesbare Konfiguration gibt es kein bekanntes Remote — und ein
        // syntaktisch verbotener Name scheitert schon vorher.
        assert!(ensure_configured_remote(":local").await.is_err());
        assert!(ensure_configured_remote("[evil]").await.is_err());
    }
}
