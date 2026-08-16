use crate::models::{ConfigRequest, RcloneConfig};
use configparser::ini::Ini;
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
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

    /// Entfernt das gespeicherte Passwort eines Remotes.
    ///
    /// Der Weg über `save_config` gibt es nicht her: dort bedeutet „kein
    /// Passwort" *unverändert lassen*, nicht *löschen*. Wer ein Passwort
    /// loswerden wollte, musste deshalb den ganzen Abschnitt löschen und ohne
    /// `pass` neu schreiben — und zwischen beiden Schritten lag ein Fenster, in
    /// dem ein IO-Fehler nicht das Passwort, sondern die **ganze Verbindung**
    /// verlor.
    ///
    /// `allow(dead_code)`: der Aufrufer ist `remove_password_and_save` in
    /// `src/handlers/config.rs`. Dessen Umstellung ist ein eigener Eingriff und
    /// gehört nicht zu diesem Ticket — bis dahin ruft nur der Test hier auf.
    #[allow(dead_code)]
    pub async fn clear_password(&self, name: &str) -> anyhow::Result<()> {
        if self.use_memory_only {
            let mut configs = self.memory_configs.write().await;
            if let Some(config) = configs.get_mut(name) {
                config.password = None;
            }
            return Ok(());
        }

        self.remove_key(name, "pass").await
    }

    /// Entfernt **einen** Schlüssel aus **einem** Abschnitt der `rclone.conf`.
    ///
    /// Bewusst zeilenweise auf dem Dateitext statt über `Ini`: `Ini` schreibt
    /// die Datei komplett neu und verliert dabei Kommentare, Reihenfolge und
    /// Schreibweise. Hier bleibt jede nicht betroffene Zeile byte-genau stehen,
    /// auch in anderen Abschnitten.
    ///
    /// Abschnitts- und Schlüsselname werden ohne Beachtung der
    /// Gross-/Kleinschreibung verglichen — genauso, wie `ensure_configured_remote`
    /// einen Remote-Namen wiedererkennt und wie rclone die Datei liest.
    ///
    /// Geschrieben wird über [`write_config_atomically`]: entweder steht die
    /// vollständige neue Fassung auf Platte oder unverändert die alte. Einen
    /// Zwischenzustand gibt es nicht.
    pub async fn remove_key(&self, section: &str, key: &str) -> anyhow::Result<()> {
        let config_path = Path::new(RCLONE_CONFIG_PATH);

        if !config_path.exists() {
            return Ok(());
        }

        let contents = tokio::fs::read_to_string(config_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read config: {}", e))?;

        let Some(updated) = remove_key_from_contents(&contents, section, key) else {
            // Der Schlüssel war nicht da. Dann wird auch nichts geschrieben —
            // ein Schreibvorgang ohne Änderung ist nur ein weiteres Risiko.
            return Ok(());
        };

        write_config_atomically(config_path, &updated)
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

    /// Verschleiert ein Passwort mit `rclone obscure`.
    ///
    /// Das Passwort geht über **stdin** an den Kindprozess, nicht über `argv`:
    /// `/proc/<pid>/cmdline` ist unter Linux für jeden lokalen Nutzer lesbar, ein
    /// `ps auxww` zum richtigen Zeitpunkt genügt. `rclone obscure -` liest die
    /// erste Zeile von stdin als Passwort (dokumentiert in `rclone obscure --help`).
    async fn obscure_password(&self, password: &str) -> anyhow::Result<String> {
        // rclone liest genau die erste Zeile. Ein Passwort mit Zeilenumbruch würde
        // also still abgeschnitten und der Nutzer könnte sich anschliessend nicht
        // mehr anmelden – deshalb wird es abgelehnt statt verstümmelt.
        if password.contains('\n') || password.contains('\r') {
            return Err(anyhow::anyhow!(
                "Password must not contain line breaks: rclone reads only the first line"
            ));
        }

        let mut child = Command::new("rclone")
            .args(["obscure", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(map_rclone_spawn_error)?;

        // stdin wird vollständig geschrieben und **geschlossen**, bevor auf die
        // Ausgabe gewartet wird. Sonst wartet rclone auf das Zeilenende und wir
        // auf rclone.
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("Failed to open stdin of rclone obscure"))?;
            stdin.write_all(password.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.shutdown().await?;
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            // stderr wird bewusst nicht durchgereicht: es kann den fehlgeschlagenen
            // Aufruf zitieren und damit das Geheimnis enthalten.
            return Err(anyhow::anyhow!(
                "Failed to obscure password: rclone obscure exited with {}",
                output.status
            ));
        }

        let obscured = String::from_utf8_lossy(&output.stdout);
        Ok(obscured.trim().to_string())
    }

    /// Macht ein von rclone verschleiertes Passwort wieder lesbar (für das
    /// Bearbeiten-Formular).
    ///
    /// Anders als `obscure` kennt `rclone reveal` **keinen** stdin-Weg – der Wert
    /// ist dort ein Positionsargument (`rclone reveal password`, geprüft gegen
    /// rclone v1.75.0 und v1.70.1: `reveal -` behandelt den Bindestrich als den
    /// zu entschlüsselnden Wert). Der verschleierte Wert ist aber genauso geheim
    /// wie das Klartextpasswort, denn `reveal` macht daraus wieder Klartext.
    /// Deshalb wird hier kein Prozess mehr gestartet, sondern das Verfahren direkt
    /// umgesetzt: rclones „obscure" ist AES-256-CTR mit einem **fest im
    /// rclone-Quelltext stehenden** Schlüssel und base64url ohne Padding
    /// (`fs/config/obscure/obscure.go`). Es ist ausdrücklich kein Schutz gegen
    /// einen Angreifer, sondern nur gegen „Eyedropping"; das Nachbilden gibt also
    /// nichts preis, was rclone nicht selbst preisgibt.
    pub async fn reveal_password(&self, obscured_password: &str) -> anyhow::Result<String> {
        let ciphertext = base64url_decode(obscured_password.trim())
            .ok_or_else(|| anyhow::anyhow!("base64 decode failed - is the password obscured?"))?;

        if ciphertext.len() < AES_BLOCK_SIZE {
            return Err(anyhow::anyhow!(
                "input too short - is the password obscured?"
            ));
        }

        let (iv, data) = ciphertext.split_at(AES_BLOCK_SIZE);
        let mut plaintext = data.to_vec();
        aes256_ctr_xor(&RCLONE_OBSCURE_KEY, iv, &mut plaintext);

        String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("revealed password is not valid UTF-8"))
    }
}

/// Entfernt alle Zeilen `key = ...` innerhalb des Abschnitts `[section]`.
///
/// `None`, wenn nichts zu tun war — der Aufrufer schreibt dann gar nicht erst.
/// Alles ausserhalb des Abschnitts bleibt unangetastet, einschliesslich
/// Kommentaren, Leerzeilen und der Reihenfolge der Schlüssel.
fn remove_key_from_contents(contents: &str, section: &str, key: &str) -> Option<String> {
    let mut out = String::with_capacity(contents.len());
    let mut in_section = false;
    let mut removed = false;

    for line in contents.split_inclusive('\n') {
        let trimmed = line.trim();

        if let Some(header) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            in_section = header.trim().eq_ignore_ascii_case(section);
            out.push_str(line);
            continue;
        }

        // Nur echte Zuweisungen betrachten. Ein Kommentar `# pass = ...` sieht
        // zwar so aus, ist aber keiner und bleibt stehen.
        if in_section && !trimmed.starts_with('#') && !trimmed.starts_with(';') {
            if let Some((name, _)) = trimmed.split_once('=') {
                if name.trim().eq_ignore_ascii_case(key) {
                    removed = true;
                    continue;
                }
            }
        }

        out.push_str(line);
    }

    removed.then_some(out)
}

/// Schreibt die Konfiguration so, dass sie **nie halb** auf Platte liegt.
///
/// Der Ablauf ist der übliche: in eine Nebendatei im **selben Verzeichnis**
/// schreiben, `fsync`, dann `rename`. Nur innerhalb eines Dateisystems ist
/// `rename` atomar — eine Nebendatei in `/tmp` wäre ein Kopieren über eine
/// Dateisystemgrenze und damit genau der Zwischenzustand, den das hier
/// verhindern soll. Jeder Fehler vor dem `rename` lässt die alte Datei
/// vollständig zurück; die Nebendatei wird dann wieder entfernt.
///
/// **Rechte:** `rclone.conf` enthält Zugangsdaten. Eine frisch angelegte Datei
/// bekäme die Rechte aus der umask (typisch 0644, also weltlesbar), deshalb
/// wird sie mit 0600 angelegt und anschliessend auf den Modus der Zieldatei
/// gesetzt. Existiert noch keine Zieldatei, bleibt es bei 0600.
fn write_config_atomically(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // Der Name enthält PID und Zeitstempel, damit zwei gleichzeitige Schreiber
    // nicht dieselbe Nebendatei benutzen. Der Punkt am Anfang hält sie aus der
    // Anzeige heraus, falls doch einmal eine liegen bleibt.
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "rclone.conf".to_string());
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        file_name,
        std::process::id(),
        stamp
    ));

    let mode = existing_file_mode(path);

    let write_result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temp_path)?;
        file.write_all(contents.as_bytes())?;
        file.flush()?;

        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }

        // Erst die Daten auf Platte, dann umbenennen. Ohne `sync_all` könnte
        // ein Absturz nach dem `rename` eine sichtbare, aber leere Datei
        // hinterlassen.
        file.sync_all()?;
        drop(file);

        std::fs::rename(&temp_path, path)
    })();

    if let Err(e) = write_result {
        // Nach einem Fehlschlag darf keine Nebendatei zurückbleiben. Schlägt
        // auch das Aufräumen fehl, zählt trotzdem der ursprüngliche Fehler.
        let _ = std::fs::remove_file(&temp_path);
        return Err(anyhow::anyhow!("Failed to write config: {}", e));
    }

    Ok(())
}

/// Der Rechte-Modus einer bestehenden Datei, sofern lesbar. `None` bedeutet
/// „keine Vorlage" — der Aufrufer bleibt dann bei 0600, dem engeren Wert.
fn existing_file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|meta| meta.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Ein fehlender `rclone`-Aufruf endete bisher in `No such file or directory
/// (os error 2)` – das nennt weder das Programm noch den Zusammenhang, und der
/// Fehler landet unverändert in der Oberfläche.
fn map_rclone_spawn_error(err: std::io::Error) -> anyhow::Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!(
            "rclone binary not found in PATH. rclone ships inside the container image; \
             run the application via `docker compose up` or install rclone on this host."
        )
    } else {
        anyhow::anyhow!("Failed to start rclone: {}", err)
    }
}

/// Blockgrösse von AES in Bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Der Schlüssel, mit dem rclone Passwörter in der `rclone.conf` verschleiert.
/// Er steht unverändert in rclones Quelltext (`fs/config/obscure/obscure.go`)
/// und ist damit öffentlich – siehe die Erläuterung an `reveal_password`.
const RCLONE_OBSCURE_KEY: [u8; 32] = [
    0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
    0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb, 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38,
];

/// base64url ohne Padding, wie Gos `base64.RawURLEncoding`. Angehängtes `=`
/// wird toleriert, alles andere abgelehnt (`None`).
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;

        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }

    // Übrige Bits müssen Null sein, sonst war die Eingabe keine gültige Kodierung.
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }

    Some(out)
}

/// AES-CTR ist eine Stromchiffre: Ver- und Entschlüsseln sind dieselbe
/// XOR-Operation. `iv` ist der Startzähler und wird – wie in Gos
/// `cipher.NewCTR` – als 128-Bit-Zahl big-endian hochgezählt.
fn aes256_ctr_xor(key: &[u8; 32], iv: &[u8], data: &mut [u8]) {
    let round_keys = aes256_expand_key(key);
    let mut counter = [0u8; AES_BLOCK_SIZE];
    counter.copy_from_slice(&iv[..AES_BLOCK_SIZE]);

    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        let keystream = aes256_encrypt_block(&round_keys, &counter);
        for (byte, key_byte) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= key_byte;
        }
        for position in (0..AES_BLOCK_SIZE).rev() {
            counter[position] = counter[position].wrapping_add(1);
            if counter[position] != 0 {
                break;
            }
        }
    }
}

/// AES-S-Box (FIPS-197, Figure 7).
#[rustfmt::skip]
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Schlüsselexpansion für AES-256: 15 Rundenschlüssel zu je 16 Bytes.
fn aes256_expand_key(key: &[u8; 32]) -> [[u8; AES_BLOCK_SIZE]; 15] {
    let mut words = [[0u8; 4]; 60];
    for (index, word) in words.iter_mut().take(8).enumerate() {
        word.copy_from_slice(&key[index * 4..index * 4 + 4]);
    }

    let mut rcon: u8 = 1;
    for index in 8..60 {
        let mut temp = words[index - 1];
        if index % 8 == 0 {
            temp = [
                AES_SBOX[temp[1] as usize] ^ rcon,
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
                AES_SBOX[temp[0] as usize],
            ];
            rcon = xtime(rcon);
        } else if index % 8 == 4 {
            temp = [
                AES_SBOX[temp[0] as usize],
                AES_SBOX[temp[1] as usize],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
            ];
        }
        for byte in 0..4 {
            words[index][byte] = words[index - 8][byte] ^ temp[byte];
        }
    }

    let mut round_keys = [[0u8; AES_BLOCK_SIZE]; 15];
    for (round, round_key) in round_keys.iter_mut().enumerate() {
        for word in 0..4 {
            round_key[word * 4..word * 4 + 4].copy_from_slice(&words[round * 4 + word]);
        }
    }
    round_keys
}

/// Verdopplung im GF(2^8) des AES.
fn xtime(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 != 0 { 0x1b } else { 0x00 }
}

/// Ein AES-256-Block, verschlüsselt. Mehr braucht CTR nicht – der Klartext wird
/// nur mit dem Ergebnis verXORt.
fn aes256_encrypt_block(
    round_keys: &[[u8; AES_BLOCK_SIZE]; 15],
    block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let mut state = *block;
    for (index, byte) in state.iter_mut().enumerate() {
        *byte ^= round_keys[0][index];
    }

    for (round, round_key) in round_keys.iter().enumerate().skip(1) {
        for byte in state.iter_mut() {
            *byte = AES_SBOX[*byte as usize];
        }

        // ShiftRows: der Zustand liegt spaltenweise, Zeile r wird um r rotiert.
        let previous = state;
        for column in 0..4 {
            for row in 0..4 {
                state[column * 4 + row] = previous[((column + row) % 4) * 4 + row];
            }
        }

        // MixColumns entfällt in der letzten Runde.
        if round != 14 {
            for column in 0..4 {
                let c = &mut state[column * 4..column * 4 + 4];
                let sum = c[0] ^ c[1] ^ c[2] ^ c[3];
                let first = c[0];
                c[0] ^= sum ^ xtime(c[0] ^ c[1]);
                c[1] ^= sum ^ xtime(c[1] ^ c[2]);
                c[2] ^= sum ^ xtime(c[2] ^ c[3]);
                c[3] ^= sum ^ xtime(c[3] ^ first);
            }
        }

        for (index, byte) in state.iter_mut().enumerate() {
            *byte ^= round_key[index];
        }
    }

    state
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

    /// FIPS-197, Anhang C.3 (AES-256). Bricht der Blockchiffre etwas weg, fällt
    /// es hier auf und nicht erst an einem unlesbaren Passwort.
    #[test]
    fn aes256_matches_fips197_vector() {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let round_keys = aes256_expand_key(&key);
        assert_eq!(aes256_encrypt_block(&round_keys, &block), expected);
    }

    #[test]
    fn base64url_decode_rejects_garbage() {
        assert_eq!(base64url_decode("AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(base64url_decode("-_"), None); // Restbits != 0
        assert_eq!(base64url_decode("AA+A"), None); // '+' gehört zu base64 std
        assert_eq!(base64url_decode("A A"), None);
    }

    /// Die Werte stammen aus `rclone obscure` (Image `rclone/rclone:1.70.1`,
    /// dieselbe Version wie im Dockerfile). Sie prüfen, dass `reveal_password`
    /// ohne rclone-Prozess genau das liefert, was `rclone reveal` liefern würde.
    #[tokio::test]
    async fn reveal_matches_rclone_obscure_output() {
        let manager = ConfigManager::new(true);
        let vectors = [
            ("qGHjt3AYErSFYeUMErKAmcrgNNWknuvtRA", "geheim123"),
            (
                "jZN1iNeFsoDHBfwwbZrgO9IDiVmJoWMSJz64LRTNorUyu7lGQg",
                "ümläut-päss wörd!",
            ),
            ("Ses2qTSf-G82GZKMOiMAqw8", "x"),
            (
                "6fKHEUoh0S2T8igyGygzHB9Co1i2PamKNhdcchAUuF4KBqO_8rCK3gwe_3xSp6pMx7iK7B4Ct2jaDSbxKZ_XrpyG5t4q7YKet1fL1QBqhtkHFOA",
                "a-very-long-password-that-spans-more-than-two-aes-blocks-1234567890",
            ),
        ];

        for (obscured, plain) in vectors {
            assert_eq!(
                manager.reveal_password(obscured).await.unwrap(),
                plain,
                "reveal({obscured}) falsch"
            );
        }
    }

    /// Ein eigenes Testverzeichnis je Testfall — die Tests laufen parallel und
    /// dürfen sich nicht dieselbe Datei teilen.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // Über `RCLONE_GUI_TEST_SCRATCH_DIR` lässt sich das Basisverzeichnis
        // umhängen — damit läuft derselbe Test auf einem winzigen Dateisystem
        // und erzwingt einen echten ENOSPC (siehe
        // `large_write_is_all_or_nothing`).
        let base = std::env::var_os("RCLONE_GUI_TEST_SCRATCH_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!(
            "rclone-gui-c9a674ee-{}-{}-{}",
            tag,
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&dir).expect("Testverzeichnis anlegbar");
        dir
    }

    const SAMPLE_CONF: &str = "\
# Von Hand kommentiert
[gdrive]
type = drive
provider = Google
pass = OBSCURED_A

[MyBox]
type = webdav
url = https://example.org/dav
user = frank
pass = OBSCURED_B
region = eu-central
# pass = alter Wert, nur Kommentar
";

    #[test]
    fn remove_key_touches_only_the_named_section() {
        let out = remove_key_from_contents(SAMPLE_CONF, "MyBox", "pass").unwrap();

        // Der Zielschlüssel ist weg …
        assert!(!out.contains("pass = OBSCURED_B"));
        // … alles andere des Abschnitts steht unverändert, auch Unbekanntes.
        assert!(out.contains("region = eu-central"));
        assert!(out.contains("user = frank"));
        assert!(out.contains("url = https://example.org/dav"));
        assert!(out.contains("[MyBox]"));
        // … und der fremde Abschnitt bleibt komplett.
        assert!(out.contains("pass = OBSCURED_A"));
        assert!(out.contains("provider = Google"));
        assert!(out.contains("# Von Hand kommentiert"));
        // Ein Kommentar, der nur wie eine Zuweisung aussieht, ist keine.
        assert!(out.contains("# pass = alter Wert"));
    }

    #[test]
    fn remove_key_is_case_insensitive_and_reports_no_op() {
        assert!(remove_key_from_contents(SAMPLE_CONF, "mybox", "PASS").is_some());
        // Nichts zu entfernen -> kein Schreibvorgang.
        assert!(remove_key_from_contents(SAMPLE_CONF, "MyBox", "token").is_none());
        assert!(remove_key_from_contents(SAMPLE_CONF, "unbekannt", "pass").is_none());
    }

    #[test]
    fn atomic_write_keeps_the_permissions_of_the_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("perm");
        let path = dir.join("rclone.conf");
        std::fs::write(&path, SAMPLE_CONF).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let updated = remove_key_from_contents(SAMPLE_CONF, "MyBox", "pass").unwrap();
        write_config_atomically(&path, &updated).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "Rechte der Zieldatei müssen erhalten bleiben");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), updated);
        // Keine Nebendatei übrig.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Der Kern des Tickets: geht das Schreiben schief, liegt die **alte**
    /// Konfiguration vollständig da — nicht die halbe neue. Erzwungen über ein
    /// Elternverzeichnis, das keines ist: das Anlegen der Nebendatei scheitert
    /// dann mit ENOTDIR, und zwar für jeden Nutzer, auch für root.
    #[test]
    fn a_failed_write_leaves_the_old_configuration_complete() {
        let dir = scratch_dir("fail");
        let blocker = dir.join("cfg");
        std::fs::write(&blocker, "keine Datei, sondern ein Verzeichnis-Platzhalter").unwrap();
        let path = blocker.join("rclone.conf");

        let err = write_config_atomically(&path, "neu").unwrap_err();
        assert!(err.to_string().contains("Failed to write config"));

        // Der „Verzeichnis"-Pfad ist unangetastet, und es liegt keine
        // Nebendatei irgendwo herum.
        assert_eq!(
            std::fs::read_to_string(&blocker).unwrap(),
            "keine Datei, sondern ein Verzeichnis-Platzhalter"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Zweiter Weg zum selben Nachweis, diesmal mit einer echten Zieldatei:
    /// ein nicht beschreibbares Verzeichnis. Als root greift das nicht — dann
    /// wird der Testteil übersprungen statt falsch bestanden.
    #[test]
    fn a_failed_write_keeps_the_existing_file_byte_for_byte() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("readonly");
        let path = dir.join("rclone.conf");
        std::fs::write(&path, SAMPLE_CONF).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        // Probe: darf hier überhaupt niemand mehr schreiben?
        let probe = dir.join(".probe");
        let writable = std::fs::File::create(&probe).is_ok();
        std::fs::remove_file(&probe).ok();

        if !writable {
            let err = write_config_atomically(&path, "halbe neue Fassung").unwrap_err();
            assert!(err.to_string().contains("Failed to write config"));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), SAMPLE_CONF);
        }

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Derselbe Nachweis mit einem Fehler **mitten im Schreiben** statt beim
    /// Anlegen: eine Fassung, die nicht mehr auf das Dateisystem passt.
    ///
    /// Auf einem normalen `/tmp` geht das durch — dann prüft der Test den
    /// Erfolgsfall. Interessant wird er auf einem winzigen Dateisystem:
    ///
    /// ```text
    /// unshare -Urm --propagation private sh -c '
    ///   mkdir -p /tmp/tiny && mount -t tmpfs -o size=64k tmpfs /tmp/tiny
    ///   RCLONE_GUI_TEST_SCRATCH_DIR=/tmp/tiny cargo test config_manager'
    /// ```
    ///
    /// Dort scheitert `write_all` mit ENOSPC, und genau dann muss die alte
    /// Datei vollständig dastehen und die Nebendatei verschwunden sein.
    #[test]
    fn large_write_is_all_or_nothing() {
        let dir = scratch_dir("enospc");
        let path = dir.join("rclone.conf");
        std::fs::write(&path, SAMPLE_CONF).unwrap();

        let big = "x".repeat(256 * 1024);
        match write_config_atomically(&path, &big) {
            Ok(()) => assert_eq!(std::fs::read_to_string(&path).unwrap(), big),
            Err(_) => {
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    SAMPLE_CONF,
                    "die alte Konfiguration muss vollständig zurückbleiben"
                );
            }
        }
        // In beiden Fällen: keine Nebendatei übrig.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn clear_password_in_memory_mode_drops_only_the_password() {
        let manager = ConfigManager::new(true);
        let request = ConfigRequest {
            name: "membox".to_string(),
            config_type: "webdav-nextcloud".to_string(),
            url: Some("https://example.org/dav".to_string()),
            username: Some("frank".to_string()),
            password: None,
            additional_fields: Some(HashMap::from([(
                "region".to_string(),
                "eu-central".to_string(),
            )])),
        };
        manager.save_config(&request).await.unwrap();

        manager.clear_password("membox").await.unwrap();

        let configs = manager.load_configs().await.unwrap();
        let stored = configs.iter().find(|c| c.name == "membox").unwrap();
        assert!(stored.password.is_none());
        assert_eq!(stored.username.as_deref(), Some("frank"));
        assert_eq!(
            stored.additional_fields.get("region").map(String::as_str),
            Some("eu-central")
        );
    }

    #[tokio::test]
    async fn reveal_rejects_values_that_are_not_obscured() {
        let manager = ConfigManager::new(true);
        // Klartext aus einer von Hand geschriebenen rclone.conf: zu kurz bzw.
        // keine gültige Kodierung — es darf nichts Zufälliges herauskommen.
        assert!(manager.reveal_password("plaintext!").await.is_err());
        assert!(manager.reveal_password("AAAA").await.is_err());
    }
}
