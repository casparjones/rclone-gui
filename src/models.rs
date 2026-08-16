use crate::handlers::sync::JobStatus;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;

/// Eine Remote-Verbindung, so wie sie in `rclone.conf` steht.
///
/// `password` trägt den von `rclone obscure` verschleierten Wert – und der ist
/// genauso geheim wie das Klartextpasswort, weil `reveal` daraus wieder Klartext
/// macht (siehe `config_manager::reveal_password`). Deshalb:
///
/// - **kein abgeleitetes `Debug`.** Ein `tracing::debug!(?config)` beim Suchen
///   eines ganz anderen Fehlers hätte das Passwort ins Log geschrieben. Dasselbe
///   Muster hat hier bereits `LoginOutcome` (`auth.rs`) und `ModuleConfig`
///   (`rsyncd.rs`) getroffen.
/// - **kein Serialisieren des Passworts.** Das Struct ist der Antworttyp von
///   `GET /api/configs` und `GET /api/configs/:name/edit`; ohne
///   `skip_serializing` genügt ein neuer Handler, der es zurückgibt, um es
///   wieder in die Oberfläche zu tragen. Gelesen wird es weiterhin nur
///   serverseitig aus dem Feld.
///
/// `additional_fields` enthält alles, was `rclone.conf` sonst noch im Abschnitt
/// führt – bei S3 zum Beispiel `secret_access_key`. Die **Werte** sind damit
/// ebenfalls potenzielle Geheimnisse und erscheinen im `Debug` nicht.
#[derive(Clone, Serialize, Deserialize)]
pub struct RcloneConfig {
    pub name: String,
    pub config_type: String,
    pub url: Option<String>,
    pub username: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    /// Ebenfalls nicht in der Antwort: bei S3 steht hier `secret_access_key`,
    /// bei anderen Backends ein Token. Die Oberfläche wertet die Zusatzfelder
    /// nirgends aus – sie brauchte Name, Typ, URL und Benutzer. Wer sie einmal
    /// anzeigen will, holt sich die unbedenklichen Schlüssel gezielt, statt den
    /// ganzen Abschnitt der `rclone.conf` in den Browser zu schicken.
    #[serde(skip_serializing)]
    pub additional_fields: HashMap<String, String>,
}

impl std::fmt::Debug for RcloneConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RcloneConfig")
            .field("name", &self.name)
            .field("config_type", &self.config_type)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "additional_fields",
                &RedactedFields(&self.additional_fields),
            )
            .finish()
    }
}

/// Zeigt die Schlüssel der Zusatzfelder, aber keinen einzigen Wert.
///
/// Welche Schlüssel gesetzt sind, ist beim Debuggen die eigentliche Information;
/// die Werte sind der Teil, der ein Token sein kann.
struct RedactedFields<'a>(&'a HashMap<String, String>);

impl std::fmt::Debug for RedactedFields<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|key| (key, "<redacted>")))
            .finish()
    }
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
    pub chunk_size: Option<String>, // z.B. "8M", "16M", "32M"
    pub use_chunking: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {
    pub id: String,
    pub progress: f64,
    /// Serialisiert flach als `status` (Anzeigetext), `state` und `terminal` —
    /// siehe `handlers::sync::JobStatus`.
    #[serde(flatten)]
    pub status: JobStatus,
    pub transferred: u64,
    pub total: u64,
    pub source_name: String,
    pub start_time: i64,
    pub end_time: Option<i64>,
}

/// Was der Client beim Anlegen oder Bearbeiten einer Verbindung schickt.
///
/// `password` ist hier **Klartext** – der Wert, den der Nutzer gerade eingegeben
/// hat. Ein abgeleitetes `Debug` würde ihn in dem Moment ins Log schreiben, in
/// dem jemand die Anfrage beim Debuggen ausgibt; deshalb steht es von Hand da.
/// Zur Bedeutung von „Feld fehlt" gegenüber „leerer String" siehe
/// `handlers::config::save_config`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ConfigRequest {
    pub name: String,
    pub config_type: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub additional_fields: Option<HashMap<String, String>>,
}

impl std::fmt::Debug for ConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigRequest")
            .field("name", &self.name)
            .field("config_type", &self.config_type)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "additional_fields",
                &self.additional_fields.as_ref().map(RedactedFields),
            )
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-p4ssw0rd";

    fn sample_config() -> RcloneConfig {
        let mut additional_fields = HashMap::new();
        additional_fields.insert("secret_access_key".to_string(), SECRET.to_string());

        RcloneConfig {
            name: "box".to_string(),
            config_type: "webdav-nextcloud".to_string(),
            url: Some("https://example.org/dav".to_string()),
            username: Some("alice".to_string()),
            password: Some(SECRET.to_string()),
            additional_fields,
        }
    }

    fn sample_request() -> ConfigRequest {
        let mut additional_fields = HashMap::new();
        additional_fields.insert("secret_access_key".to_string(), SECRET.to_string());

        ConfigRequest {
            name: "box".to_string(),
            config_type: "webdav-nextcloud".to_string(),
            url: Some("https://example.org/dav".to_string()),
            username: Some("alice".to_string()),
            password: Some(SECRET.to_string()),
            additional_fields: Some(additional_fields),
        }
    }

    /// Der Kern des Tickets: `{:?}` darf das Passwort nicht zeigen – weder das
    /// verschleierte noch das eingegebene.
    #[test]
    fn debug_hides_the_password() {
        let rendered = format!("{:?}", sample_config());
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Was beim Debuggen tatsächlich hilft, bleibt sichtbar.
        assert!(rendered.contains("box"), "{rendered}");

        let rendered = format!("{:?}", sample_request());
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// Zusatzfelder tragen bei manchen Backends den eigentlichen Schlüssel
    /// (`secret_access_key` bei S3). Die Namen bleiben, die Werte gehen nicht raus.
    #[test]
    fn debug_hides_additional_field_values() {
        let rendered = format!("{:?}", sample_config());
        assert!(rendered.contains("secret_access_key"), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");

        let rendered = format!("{:?}", sample_request());
        assert!(rendered.contains("secret_access_key"), "{rendered}");
        assert!(!rendered.contains(SECRET), "{rendered}");
    }

    /// Ein `Debug` schützt nur, wenn es auch dann greift, wenn das Struct in
    /// etwas anderem steckt – der übliche Weg, auf dem so ein Wert doch ins Log
    /// gerät, ist ein `tracing::debug!(?response)`.
    #[test]
    fn nested_debug_stays_redacted() {
        let rendered = format!("{:?}", ApiResponse::success(sample_config()));
        assert!(!rendered.contains(SECRET), "{rendered}");

        let rendered = format!("{:?}", vec![sample_config()]);
        assert!(!rendered.contains(SECRET), "{rendered}");

        let rendered = format!("{:?}", Some(sample_request()));
        assert!(!rendered.contains(SECRET), "{rendered}");
    }

    /// `RcloneConfig` ist der Antworttyp zweier Endpunkte. Das Passwort ist vom
    /// Serialisieren ausgenommen, damit es auch ein künftiger Handler nicht
    /// versehentlich ausliefert.
    #[test]
    fn serialised_config_carries_no_password() {
        let json = serde_json::to_string(&sample_config()).expect("serialise");
        assert!(!json.contains(SECRET), "{json}");
        assert!(!json.contains("\"password\""), "{json}");
        // Zusatzfelder tragen bei S3 den Schlüssel selbst — auch sie gehen nicht raus.
        assert!(!json.contains("secret_access_key"), "{json}");
        // Was die Oberfläche braucht, bleibt.
        assert!(json.contains("\"username\":\"alice\""), "{json}");
        assert!(json.contains("\"name\":\"box\""), "{json}");
    }

    /// Gelesen wird das Feld weiterhin – nur eben nur serverseitig.
    #[test]
    fn password_still_deserialises() {
        let config: RcloneConfig = serde_json::from_str(
            r#"{"name":"box","config_type":"webdav","url":null,"username":null,
                "password":"obscured","additional_fields":{}}"#,
        )
        .expect("deserialise");
        assert_eq!(config.password.as_deref(), Some("obscured"));
    }
}
