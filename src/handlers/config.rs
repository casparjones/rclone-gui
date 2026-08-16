use crate::config_manager::ConfigManager;
use crate::models::{ApiResponse, ConfigRequest, RcloneConfig};
use axum::{extract::Json, response::Json as ResponseJson, Extension};
use std::sync::Arc;

/// Nimmt einer Verbindung das Passwort ab, bevor sie das Haus verlässt.
///
/// In `rclone.conf` steht der von `rclone obscure` verschleierte Wert, und der
/// ist kein Schutz: `reveal` macht daraus wieder Klartext, ohne Schlüssel und
/// ohne Rückfrage (siehe `config_manager::reveal_password`). Ausgeliefert wäre
/// er damit dasselbe Leck wie das Klartextpasswort – er stünde im DOM, in der
/// Netzwerkantwort, im Cache und in jedem Mitschnitt.
///
/// `RcloneConfig` überspringt das Feld inzwischen schon beim Serialisieren
/// (`models.rs`). Diese Funktion räumt es zusätzlich aus der Struktur, damit die
/// Absicht am Endpunkt selbst sichtbar ist und nicht von einem Attribut in einer
/// anderen Datei abhängt.
fn without_password(mut config: RcloneConfig) -> RcloneConfig {
    config.password = None;
    config
}

pub async fn get_configs(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
) -> ResponseJson<ApiResponse<Vec<RcloneConfig>>> {
    match config_manager.load_configs().await {
        Ok(configs) => ResponseJson(ApiResponse::success(
            configs.into_iter().map(without_password).collect(),
        )),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

/// Was der Client zum Passwort einer bestehenden Verbindung sagt.
///
/// Die Unterscheidung ist der Grund, warum das Feld `Option<String>` bleibt und
/// nicht auf einen leeren String normalisiert wird:
///
/// | JSON                | Bedeutung                                  |
/// |---------------------|--------------------------------------------|
/// | Feld fehlt / `null` | unverändert lassen                         |
/// | `""`                | gespeichertes Passwort **entfernen**       |
/// | sonst               | neu setzen                                 |
///
/// Ohne die mittlere Zeile wäre eine Verbindung ohne Passwort nach dem ersten
/// gesetzten Passwort nicht mehr herstellbar – „leer gelassen" hiesse immer
/// „behalten", und es gäbe keinen Weg zurück.
enum PasswordIntent {
    Keep,
    Remove,
    Set(String),
}

impl PasswordIntent {
    fn from_request(password: Option<String>) -> Self {
        match password {
            None => Self::Keep,
            Some(password) if password.is_empty() => Self::Remove,
            Some(password) => Self::Set(password),
        }
    }
}

/// Das gespeicherte Passwort als Klartext, oder `None`, wenn keins da ist.
///
/// `ConfigManager::save_config` verschleiert, was es bekommt. Ein bereits
/// verschleierter Wert dürfte also nicht einfach durchgereicht werden – er käme
/// doppelt verschleiert in der Datei an und die Verbindung wäre kaputt. Deshalb
/// wird für „unverändert lassen" der gespeicherte Wert einmal aufgelöst und als
/// Klartext übergeben; das Ergebnis in der Datei ist dasselbe Passwort.
///
/// Schlägt das Auflösen fehl, stand in der `rclone.conf` kein von rclone
/// verschleierter Wert, sondern Klartext (von Hand geschrieben). Dann ist der
/// gespeicherte Wert selbst schon der Klartext und wird so übernommen – beim
/// Speichern wird er dann verschleiert, was die Datei sogar verbessert.
async fn stored_password_as_plaintext(
    config_manager: &ConfigManager,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let stored = config_manager
        .load_configs()
        .await?
        .into_iter()
        .find(|config| config.name == name)
        .and_then(|config| config.password)
        .filter(|password| !password.is_empty());

    let Some(stored) = stored else {
        return Ok(None);
    };

    match config_manager.reveal_password(&stored).await {
        Ok(revealed) => Ok(Some(revealed)),
        Err(_) => Ok(Some(stored)),
    }
}

/// Legt eine Verbindung an oder überschreibt sie.
///
/// Zum Passwort siehe `PasswordIntent`.
pub async fn save_config(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
    Json(mut config_request): Json<ConfigRequest>,
) -> ResponseJson<ApiResponse<String>> {
    let intent = PasswordIntent::from_request(config_request.password.take());

    let result = match intent {
        PasswordIntent::Set(password) => {
            config_request.password = Some(password);
            config_manager.save_config(&config_request).await
        }
        PasswordIntent::Keep => {
            match stored_password_as_plaintext(&config_manager, &config_request.name).await {
                Ok(password) => {
                    config_request.password = password;
                    config_manager.save_config(&config_request).await
                }
                Err(e) => Err(e),
            }
        }
        PasswordIntent::Remove => remove_password_and_save(&config_manager, config_request).await,
    };

    match result {
        Ok(_) => ResponseJson(ApiResponse::success(
            "Configuration saved successfully".to_string(),
        )),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

/// Speichert die Verbindung **ohne** Passwort.
///
/// Das kostet einen Umweg: `ConfigManager::save_config` schreibt nur die
/// Schlüssel, die es bekommt, in den bestehenden Abschnitt – ein `pass`, das
/// schon in `rclone.conf` steht, überlebt ein leeres Feld also unbeschadet. Um
/// es wirklich loszuwerden, wird der Abschnitt gelöscht und aus der Anfrage neu
/// geschrieben.
///
/// Damit dabei nichts verloren geht, werden die Zusatzfelder des gespeicherten
/// Abschnitts übernommen, sofern die Anfrage keine eigenen mitbringt – `type`,
/// `url`, `user` und `vendor` stehen ohnehin in der Anfrage.
///
/// Bringt die Verbindung gar kein Passwort mit (oder gibt es sie noch nicht),
/// bleibt es beim gewöhnlichen Speichern: der löschende Weg wird nur gegangen,
/// wenn es etwas zu löschen gibt.
async fn remove_password_and_save(
    config_manager: &ConfigManager,
    mut config_request: ConfigRequest,
) -> anyhow::Result<()> {
    config_request.password = None;

    let stored = config_manager
        .load_configs()
        .await?
        .into_iter()
        .find(|config| config.name == config_request.name);

    let has_password = stored
        .as_ref()
        .and_then(|config| config.password.as_deref())
        .is_some_and(|password| !password.is_empty());

    if !has_password {
        return config_manager.save_config(&config_request).await;
    }

    if config_request.additional_fields.is_none() {
        if let Some(stored) = stored {
            if !stored.additional_fields.is_empty() {
                config_request.additional_fields = Some(stored.additional_fields);
            }
        }
    }

    config_manager.delete_config(&config_request.name).await?;
    config_manager.save_config(&config_request).await
}

pub async fn delete_config(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
    name: String,
) -> ResponseJson<ApiResponse<String>> {
    match config_manager.delete_config(&name).await {
        Ok(_) => ResponseJson(ApiResponse::success(
            "Configuration deleted successfully".to_string(),
        )),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

pub async fn persist_configs(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
) -> ResponseJson<ApiResponse<String>> {
    match config_manager.persist_to_file().await {
        Ok(_) => ResponseJson(ApiResponse::success(
            "Configurations persisted to file successfully".to_string(),
        )),
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

/// Die Werte für das Bearbeiten-Formular – **ohne** Passwort.
///
/// Früher stand hier ein `reveal_password`-Aufruf: das Formular sollte das
/// gespeicherte Passwort anzeigen. Das trug es in die Oberfläche und damit in
/// jeden Mitschnitt. Das Formular kommt ohne aus – es lässt das Feld leer und
/// schickt beim Speichern nur dann eines mit, wenn der Nutzer etwas eingegeben
/// hat (siehe `PasswordIntent`).
pub async fn get_config_for_edit(
    Extension(config_manager): Extension<Arc<ConfigManager>>,
    name: String,
) -> ResponseJson<ApiResponse<RcloneConfig>> {
    match config_manager.load_configs().await {
        Ok(configs) => match configs.into_iter().find(|c| c.name == name) {
            Some(config) => ResponseJson(ApiResponse::success(without_password(config))),
            None => ResponseJson(ApiResponse::error("Configuration not found")),
        },
        Err(e) => ResponseJson(ApiResponse::error(&e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET: &str = "geheim-123";

    /// Speichern verschleiert über `rclone obscure`, das ist ein Kindprozess.
    /// Auf einem Rechner ohne rclone (laut AGENTS.md der Normalfall ausserhalb
    /// des Containers) hat der Test nichts zu prüfen und sagt das.
    fn rclone_missing() -> bool {
        let missing = std::process::Command::new("rclone")
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err();

        if missing {
            eprintln!("übersprungen: kein rclone-Binary im PATH");
        }

        missing
    }

    /// Speicherbetrieb, damit kein Test die echte `data/cfg/rclone.conf` anfasst.
    fn manager() -> Arc<ConfigManager> {
        Arc::new(ConfigManager::new(true))
    }

    fn request(name: &str, password: Option<&str>) -> ConfigRequest {
        ConfigRequest {
            name: name.to_string(),
            config_type: "webdav-nextcloud".to_string(),
            url: Some("https://example.org/dav".to_string()),
            username: Some("alice".to_string()),
            password: password.map(str::to_string),
            additional_fields: None,
        }
    }

    async fn stored(config_manager: &ConfigManager, name: &str) -> Option<String> {
        config_manager
            .load_configs()
            .await
            .expect("load")
            .into_iter()
            .find(|config| config.name == name)
            .and_then(|config| config.password)
    }

    fn body_of<T: serde::Serialize>(response: &ResponseJson<ApiResponse<T>>) -> String {
        serde_json::to_string(&response.0).expect("serialise")
    }

    /// Akzeptanzkriterium: der rohe Antwortkörper trägt kein Passwort – weder
    /// das eingegebene noch den verschleierten Wert aus der Datei.
    #[tokio::test]
    async fn edit_response_carries_no_password() {
        if rclone_missing() {
            return;
        }

        let config_manager = manager();
        let _ = save_config(
            Extension(config_manager.clone()),
            Json(request("box", Some(SECRET))),
        )
        .await;

        let obscured = stored(&config_manager, "box").await.expect("gespeichert");
        let body =
            body_of(&get_config_for_edit(Extension(config_manager), "box".to_string()).await);

        assert!(!body.contains(SECRET), "{body}");
        assert!(!body.contains(&obscured), "{body}");
        assert!(!body.contains("password"), "{body}");
        // Alles andere wird zum Vorbefüllen des Formulars gebraucht.
        assert!(body.contains("alice"), "{body}");
    }

    /// Dasselbe für die Liste: sie füllt `state.configs` im Frontend und landet
    /// damit genauso im DOM.
    #[tokio::test]
    async fn list_response_carries_no_password() {
        if rclone_missing() {
            return;
        }

        let config_manager = manager();
        let _ = save_config(
            Extension(config_manager.clone()),
            Json(request("box", Some(SECRET))),
        )
        .await;

        let obscured = stored(&config_manager, "box").await.expect("gespeichert");
        let body = body_of(&get_configs(Extension(config_manager)).await);

        assert!(!body.contains(SECRET), "{body}");
        assert!(!body.contains(&obscured), "{body}");
    }

    /// Bearbeiten ohne Eingabe lässt das gespeicherte Passwort in Ruhe. Der Wert
    /// in der Datei darf sich ändern (neue Verschleierung, neuer IV) – das
    /// Passwort dahinter nicht.
    #[tokio::test]
    async fn saving_without_password_keeps_the_stored_one() {
        if rclone_missing() {
            return;
        }

        let config_manager = manager();
        let _ = save_config(
            Extension(config_manager.clone()),
            Json(request("box", Some(SECRET))),
        )
        .await;

        let response = save_config(
            Extension(config_manager.clone()),
            Json(request("box", None)),
        )
        .await;
        assert!(response.0.success, "{:?}", response.0.error);

        let obscured = stored(&config_manager, "box").await.expect("noch da");
        assert_eq!(
            config_manager
                .reveal_password(&obscured)
                .await
                .expect("reveal"),
            SECRET
        );
    }

    /// Und mit Eingabe wird es neu gesetzt.
    #[tokio::test]
    async fn saving_with_password_replaces_it() {
        if rclone_missing() {
            return;
        }

        let config_manager = manager();
        let _ = save_config(
            Extension(config_manager.clone()),
            Json(request("box", Some(SECRET))),
        )
        .await;
        let _ = save_config(
            Extension(config_manager.clone()),
            Json(request("box", Some("ein-anderes"))),
        )
        .await;

        let obscured = stored(&config_manager, "box").await.expect("gespeichert");
        assert_eq!(
            config_manager
                .reveal_password(&obscured)
                .await
                .expect("reveal"),
            "ein-anderes"
        );
    }

    /// Der Weg zurück: ein leeres Feld ist „behalten", ein ausdrücklich leerer
    /// String ist „entfernen". Ohne diesen Unterschied liesse sich eine
    /// Verbindung nie wieder ohne Passwort speichern.
    #[tokio::test]
    async fn empty_string_removes_the_password() {
        if rclone_missing() {
            return;
        }

        let config_manager = manager();
        let mut with_fields = request("box", Some(SECRET));
        let mut fields = HashMap::new();
        fields.insert("bearer_token_command".to_string(), "true".to_string());
        with_fields.additional_fields = Some(fields);

        let _ = save_config(Extension(config_manager.clone()), Json(with_fields)).await;

        let response = save_config(
            Extension(config_manager.clone()),
            Json(request("box", Some(""))),
        )
        .await;
        assert!(response.0.success, "{:?}", response.0.error);

        assert_eq!(stored(&config_manager, "box").await, None);

        // Die Verbindung selbst überlebt das Entfernen vollständig.
        let config = config_manager
            .load_configs()
            .await
            .expect("load")
            .into_iter()
            .find(|config| config.name == "box")
            .expect("Verbindung noch da");
        assert_eq!(config.username.as_deref(), Some("alice"));
        assert_eq!(
            config.additional_fields.get("bearer_token_command"),
            Some(&"true".to_string())
        );
    }

    /// Eine neue Verbindung ohne Passwort ist der häufigste Fall des Formulars
    /// und darf nicht am Löschweg hängenbleiben.
    #[tokio::test]
    async fn creating_without_password_works() {
        let config_manager = manager();

        for password in [None, Some("")] {
            let response = save_config(
                Extension(config_manager.clone()),
                Json(request("local-box", password)),
            )
            .await;
            assert!(response.0.success, "{:?}", response.0.error);
            assert_eq!(stored(&config_manager, "local-box").await, None);
        }
    }
}
