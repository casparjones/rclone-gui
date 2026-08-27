use crate::models::{ConfigRequest, RcloneConfig};
use configparser::ini::Ini;
use std::collections::HashMap;
use std::path::{Component, Path};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::RwLock;

/// Die **gemeinsame** rclone-Konfiguration, die heute jedem rclone-Aufruf per
/// `--config` mitgegeben wird. Alles, was gegen "ist dieses Remote
/// konfiguriert?" geprüft wird, muss gegen genau die Datei geprüft werden, die
/// rclone anschliessend liest – sonst prüft man etwas anderes.
///
/// Der Wert ist die **Zeichenkettenform** von [`shared_config_path`]; er bleibt
/// als `const` erhalten, weil er an mehreren Stellen direkt als
/// `--config`-Argument in eine rclone-Kommandozeile geht. Dass beide Formen
/// nicht auseinanderlaufen, sichert `shared_path_matches_the_constant` ab.
///
/// Sobald Remotes einem Nutzer gehören, ist nicht mehr diese Datei der
/// Bezugspunkt, sondern [`config_path_for`]. Siehe die Erläuterung dort.
pub const RCLONE_CONFIG_PATH: &str = "data/cfg/rclone.conf";

/// Verzeichnis aller rclone-Konfigurationen, relativ zum Arbeitsverzeichnis des
/// Prozesses – wie alles unter `data/`.
const CONFIG_DIR: &str = "data/cfg";

/// Unterverzeichnis, unter dem je Nutzer ein eigenes Verzeichnis liegt.
const USER_CONFIG_SUBDIR: &str = "users";

/// Dateiname der Konfiguration, in jedem Geltungsbereich derselbe.
const CONFIG_FILE_NAME: &str = "rclone.conf";

/// Rechte des Verzeichnisses einer Nutzer-Konfiguration. Es enthält
/// Zugangsdaten und listet ausserdem auf, welche Nutzer es überhaupt gibt.
const USER_CONFIG_DIR_MODE: u32 = 0o700;

/// Rechte einer frisch angelegten Konfigurationsdatei. Denselben Wert benutzt
/// [`write_config_atomically`] für seine Nebendatei.
const CONFIG_FILE_MODE: u32 = 0o600;

/// Der gemeinsame, nicht nutzergebundene Konfigurationspfad.
///
/// Das ist die Datei, die es heute gibt und in der die bestehenden Remotes
/// stehen. Sie wird durch die Umstellung auf nutzereigene Konfigurationen
/// **nicht** angetastet: nichts verschiebt, kopiert oder löscht sie hier. Ob
/// und wie ihr Inhalt einem Nutzer zugeschlagen wird, entscheidet das Ticket
/// `771319ce` (Migration/Admin-Remotes) – bis dahin bleibt sie unverändert
/// lesbar.
pub fn shared_config_path() -> std::path::PathBuf {
    Path::new(CONFIG_DIR).join(CONFIG_FILE_NAME)
}

// Die Bausteine der nutzergebundenen Auflösung. Sie sind hier vollständig
// umgesetzt und geprüft, aber noch von keinem Aufrufer benutzt: die Umstellung
// der Aufrufer liegt in `src/handlers/{files,sync,config}.rs`, `src/main.rs`
// (CLI `--start-task`) und `src/database.rs` (Anlegen/Löschen eines Nutzers) —
// Dateien, die dieses Ticket nicht besitzt. Deshalb `allow(dead_code)`: das
// Attribut markiert die Lücke, statt sie zu verstecken, und fällt beim Einbau
// (Ticket `ce385143` bzw. `0541474c`) wieder weg.
/// **Die** Stelle, an der aus einem Nutzer ein Konfigurationspfad wird –
/// das Gegenstück zu `user_root()` für den Dateibaum.
///
/// Kein Aufrufer setzt den Pfad selbst zusammen. Sonst entstehen zwei
/// Wahrheiten: eine, gegen die geprüft wird („ist dieses Remote
/// konfiguriert?"), und eine, die rclone per `--config` tatsächlich liest. Genau
/// diese Lücke war `5d31b2f7`, nur an einer anderen Stelle.
///
/// **Die Nutzerkennung wird zu einem Verzeichnisnamen.** Sie kommt heute aus
/// `uuid::Uuid::new_v4()` und ist damit unbedenklich – aber sie kommt über die
/// Datenbank, und eine von Hand bearbeitete `users`-Tabelle ist ein Pfad, den
/// niemand prüft. Ein Wert wie `../../..` oder `/etc` würde die Konfiguration
/// samt Zugangsdaten aus `data/` heraustragen. Deshalb wird die Kennung hier als
/// **ein** Pfadsegment validiert, statt sie zu vertrauen; `..`, `/`, `\`, `.`
/// und alles ausserhalb von `[A-Za-z0-9-]` sind abgelehnt. Das ist eine
/// Positivliste aus demselben Grund wie bei den Remote-Namen.
#[allow(dead_code)]
pub fn config_path_for(user_id: &str) -> anyhow::Result<std::path::PathBuf> {
    config_path_in(Path::new(CONFIG_DIR), user_id)
}

/// Legt das Konfigurationsverzeichnis eines Nutzers an und darin eine leere
/// `rclone.conf`. Gibt den Pfad der Datei zurück.
///
/// Gehört an das **Anlegen** eines Nutzers. Ohne die leere Datei liefe jede
/// Prüfung „ist dieses Remote konfiguriert?" gegen eine nicht lesbare Datei –
/// technisch dasselbe Ergebnis (abgelehnt), aber mit einer Fehlermeldung über
/// eine fehlende Datei statt über ein unbekanntes Remote.
///
/// Idempotent: ein zweiter Aufruf ändert nichts. Insbesondere werden die Rechte
/// einer **bestehenden** Datei nicht überschrieben – wer bewusst `0640` gesetzt
/// hat, behält es, genau wie bei [`write_config_atomically`].
#[allow(dead_code)]
pub fn ensure_user_config(user_id: &str) -> anyhow::Result<std::path::PathBuf> {
    ensure_user_config_in(Path::new(CONFIG_DIR), user_id)
}

/// Entfernt die Konfiguration eines Nutzers samt Verzeichnis.
///
/// Gehört an das **Löschen** eines Nutzers: bleibt die Datei liegen, erbt der
/// nächste Nutzer mit derselben Kennung fremde Remotes samt Zugangsdaten. Dass
/// eine UUID sich nicht wiederholt, ist dafür kein Verlass – eine
/// wiederhergestellte Datenbank genügt.
///
/// Ein nicht vorhandenes Verzeichnis ist kein Fehler.
#[allow(dead_code)]
pub fn remove_user_config(user_id: &str) -> anyhow::Result<()> {
    remove_user_config_in(Path::new(CONFIG_DIR), user_id)
}

// ---------------------------------------------------------------------------
// Derselbe Kern, aber mit ausdrücklichem Wurzelverzeichnis.
//
// `CONFIG_DIR` ist **relativ** zum Arbeitsverzeichnis des Prozesses. Ein Test,
// der die Dateiwirkung prüfen will, müsste also `chdir` aufrufen — das ist
// prozessweit und bricht die parallel laufenden Tests. Deshalb dieselbe
// Auslagerung, die es hier für `delete_section_atomically` und
// `render_configs_ini` schon gibt: der Kern nimmt die Wurzel als Argument, die
// öffentliche Fassung setzt `CONFIG_DIR` ein.
// ---------------------------------------------------------------------------

fn config_path_in(base: &Path, user_id: &str) -> anyhow::Result<std::path::PathBuf> {
    Ok(user_config_dir_in(base, user_id)?.join(CONFIG_FILE_NAME))
}

fn user_config_dir_in(base: &Path, user_id: &str) -> anyhow::Result<std::path::PathBuf> {
    validate_user_id(user_id)?;
    Ok(base.join(USER_CONFIG_SUBDIR).join(user_id))
}

fn ensure_user_config_in(base: &Path, user_id: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = user_config_dir_in(base, user_id)?;

    // `DirBuilder` mit `mode` setzt die Rechte **beim Anlegen**, nicht danach –
    // es gibt also kein Fenster, in dem das Verzeichnis weltlesbar ist. Auf ein
    // bereits bestehendes Verzeichnis wirkt der Modus nicht, das ist gewollt.
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(USER_CONFIG_DIR_MODE);
    }
    builder
        .create(&dir)
        .map_err(|e| anyhow::anyhow!("Failed to create config directory: {}", e))?;

    let path = dir.join(CONFIG_FILE_NAME);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(CONFIG_FILE_MODE);
    }
    match options.open(&path) {
        Ok(_) => Ok(path),
        // Schon da – dann ist nichts zu tun, insbesondere werden die Rechte
        // einer bestehenden Datei nicht angetastet.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(path),
        Err(e) => Err(anyhow::anyhow!("Failed to create config: {}", e)),
    }
}

fn remove_user_config_in(base: &Path, user_id: &str) -> anyhow::Result<()> {
    let dir = user_config_dir_in(base, user_id)?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Failed to remove config: {}", e)),
    }
}

/// Obergrenze für eine Nutzerkennung als Verzeichnisname. Eine UUID hat 36
/// Zeichen; alles jenseits dieser Grösse ist keine Kennung mehr.
const MAX_USER_ID_LEN: usize = 64;

/// Eine Nutzerkennung, die als **ein** Pfadsegment taugt. Siehe die Begründung
/// an [`config_path_for`].
fn validate_user_id(user_id: &str) -> anyhow::Result<()> {
    if user_id.is_empty() {
        anyhow::bail!("User id must not be empty");
    }
    if user_id.len() > MAX_USER_ID_LEN {
        anyhow::bail!(
            "User id must not be longer than {} characters",
            MAX_USER_ID_LEN
        );
    }
    if !user_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        // Die Kennung wird bewusst nicht wiederholt: sie kann alles enthalten.
        anyhow::bail!("User id is not usable as a directory name");
    }
    Ok(())
}

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
/// Diese Fassung prüft gegen die **gemeinsame** Konfiguration. Sie ist ein
/// Aufruf von [`ensure_configured_remote_at`] mit [`shared_config_path`] – es
/// gibt nur **eine** Umsetzung der Prüfung, damit die nutzergebundene und die
/// gemeinsame Variante nicht auseinanderlaufen können.
///
/// TODO(Ticket `ce385143` – Remote-Isolation): die Aufrufer in
/// `src/handlers/files.rs`, `src/handlers/sync.rs` und `src/handlers/config.rs`
/// haben den angemeldeten Nutzer bereits zur Hand bzw. können ihn sich aus den
/// Request-Extensions geben lassen. Sie rufen dann
/// `ensure_configured_remote_at(&config_path_for(&user.id)?, name)` und geben
/// **denselben** Pfad als `--config` an rclone weiter. Solange das nicht
/// geschehen ist, ist die Prüfung bewusst global.
///
pub async fn ensure_configured_remote(name: &str) -> anyhow::Result<()> {
    ensure_configured_remote_at(&shared_config_path(), name).await
}

/// Dieselbe Prüfung gegen eine **benannte** Konfiguration.
///
/// Der Pfad kommt aus [`config_path_for`] und ist genau der, der anschliessend
/// als `--config` an rclone geht. Wer hier gegen eine andere Datei prüft als
/// rclone später liest, prüft nichts: das war `5d31b2f7`.
///
/// Ein Remote, das nur in der Konfiguration eines **anderen** Nutzers steht, ist
/// damit „unknown" – ununterscheidbar von einem frei erfundenen Namen. Das ist
/// Absicht: die Fehlermeldung darf nicht verraten, dass es den Namen woanders
/// gibt.
pub async fn ensure_configured_remote_at(config_path: &Path, name: &str) -> anyhow::Result<()> {
    validate_remote_name(name)?;

    let contents = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| anyhow::anyhow!("rclone configuration is not readable: {}", e))?;

    if parse_conf_sections(&contents)
        .iter()
        .any(|section| section.name.eq_ignore_ascii_case(name))
    {
        Ok(())
    } else {
        // Der Name wird bewusst nicht wiederholt: er kommt vom Client.
        Err(anyhow::anyhow!("Unknown remote"))
    }
}

/// rclone-`type` und `vendor` aus dem Untertyp, den die Oberfläche schickt.
///
/// Die Abbildung stand wörtlich an zwei Stellen (`save_to_file`,
/// `render_configs_ini`) und wird seit `514ce5f5` an einer dritten gebraucht
/// (`request_reaches_host_filesystem`) – dort entscheidet sie über die
/// Zulässigkeit eines Backends. Drei Kopien einer Abbildung, von der eine
/// Sicherheitsprüfung abhängt, laufen auseinander; also nur noch eine.
fn rclone_type_and_vendor(config_type: &str) -> (&str, Option<&str>) {
    match config_type {
        "webdav-nextcloud" => ("webdav", Some("nextcloud")),
        "webdav-owncloud" => ("webdav", Some("owncloud")),
        "webdav-sharepoint" => ("webdav", Some("sharepoint")),
        "webdav-fastmail" => ("webdav", Some("fastmail")),
        "webdav-other" => ("webdav", Some("other")),
        other => (other, None),
    }
}

// ---------------------------------------------------------------------------
// Wo ein Remote im Dateisystem des Wirtssystems ansetzt (Ticket `514ce5f5`)
// ---------------------------------------------------------------------------
//
// Der Befund: der rechte Pane listete über ein Remote mit `type = local` ab
// `/`, während links `home_path` griff. Die Umgehung lief **nicht** über einen
// Pfad-Trick, sondern über die Wahl des Backends — ein `type=local`-Remote
// zeigt auf das lokale Dateisystem, und dort wandte niemand `user_root` an.
//
// Die getroffene Entscheidung: `type=local` bleibt **für alle** erlaubt, aber
// der Home-Pfad greift auch dort — kein Verbot, keine Admin-Ausnahme. Damit
// bricht kein bestehender Eintrag weg; er zeigt nur noch das Home des
// jeweiligen Nutzers.
//
// Durchsetzen kann das nur, wer weiss, **wo** ein Remote im Dateisystem
// ansetzt. Genau das liefert dieser Abschnitt; die Grenze selbst zieht
// `src/handlers/files.rs` mit `user_root` und `resolve_within_root` — denselben
// beiden Funktionen wie der lokale Pane.

/// Backends, die unmittelbar das Dateisystem des Wirtssystems ansprechen.
const HOST_FILESYSTEM_BACKENDS: &[&str] = &["local"];

/// Backends, die ein **anderes** Ziel umhüllen. Ihr Ziel steht in `remote =`
/// und kann selbst ein Dateisystempfad (`remote = /etc`) oder ein
/// `type=local`-Remote sein — dieselbe Lücke, nur eine Ebene tiefer. Deshalb
/// wird die Kette verfolgt.
const WRAPPING_BACKENDS: &[&str] = &["alias", "crypt", "chunker", "compress", "hasher", "cache"];

/// Backends, die **mehrere** Ziele umhüllen (`upstreams =`). Sie setzen
/// mehrere Bäume übereinander; welcher davon einen Pfad beantwortet, entscheidet
/// rclone. Ein einzelner Ansatzpunkt lässt sich daraus nicht ableiten.
const MULTI_WRAPPING_BACKENDS: &[&str] = &["union", "combine"];

/// Obergrenze für die Tiefe der Umhüllungskette. Wer sie überschreitet, gilt
/// als „erreicht das Wirtssystem an unbestimmter Stelle" — im Zweifel abweisen,
/// nicht durchlassen.
const MAX_WRAP_DEPTH: usize = 8;

/// Wo ein Remote im Dateisystem des Wirtssystems ansetzt.
///
/// `None` als Ergebnis von [`host_reach_of_remote_at`] heisst: das Remote
/// spricht kein lokales Dateisystem an (ein Netz-Backend). Dann gibt es hier
/// nichts zu begrenzen — der Pfad geht unverändert an rclone, so wie bisher.
#[derive(Clone, PartialEq, Eq)]
pub enum HostReach {
    /// `type = local`: der an rclone übergebene Pfad **ist** der Pfad im
    /// Wirtssystem. Damit lässt sich die Grenze vollständig durchsetzen — der
    /// Aufrufer übergibt einen bereits kanonisierten absoluten Pfad aus dem
    /// Home des Nutzers.
    Direct,
    /// Das Remote hängt an einem festen Punkt im Wirtssystem (`alias`, `crypt`
    /// … mit `remote = <pfad>`). Der übergebene Pfad ist relativ dazu, also
    /// muss dieser Ansatzpunkt selbst im Home liegen.
    Rooted(std::path::PathBuf),
    /// Erreicht das Wirtssystem, aber der Ansatzpunkt ist nicht bestimmbar:
    /// ein `union`/`combine` über mehrere Bäume, rclones On-the-fly-Syntax
    /// (`:local:`) in der Konfiguration, ein Abschnitt ohne `type`, ein
    /// Ringschluss, eine zu tiefe Kette. Hier ist keine Grenze durchsetzbar,
    /// also wird abgewiesen.
    Unbounded,
}

/// Ein `rclone.conf`-Abschnitt: Name und Schlüssel/Wert-Paare, so wie sie in
/// der Datei stehen.
///
/// Bewusst ein eigener, minimaler Parser statt `Ini`: `Ini` normalisiert Namen
/// und schluckt Doppelungen, hier wird über den Inhalt aber **entschieden**,
/// und dann muss der Parser sehen, was rclone sieht.
struct ConfSection {
    name: String,
    entries: Vec<(String, String)>,
}

fn parse_conf_sections(contents: &str) -> Vec<ConfSection> {
    let mut sections: Vec<ConfSection> = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                let name = name.trim().to_string();
                if !name.is_empty() {
                    sections.push(ConfSection {
                        name,
                        entries: Vec::new(),
                    });
                }
                continue;
            }
        }

        if let Some((key, value)) = line.split_once('=') {
            if let Some(section) = sections.last_mut() {
                section
                    .entries
                    .push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }

    sections
}

/// Der Wert eines Schlüssels im **ersten** Abschnitt dieses Namens. rclone
/// liest Namen ohne Rücksicht auf Gross-/Kleinschreibung, also hier auch.
fn section_value<'a>(sections: &'a [ConfSection], name: &str, key: &str) -> Option<&'a str> {
    sections
        .iter()
        .find(|section| section.name.eq_ignore_ascii_case(name))
        .and_then(|section| {
            section
                .entries
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.as_str())
        })
}

/// Setzt `name` – direkt oder über eine Kette von umhüllenden Backends – im
/// Dateisystem des Wirtssystems an, und wenn ja: wo?
///
/// Durchgehend **fail-closed**: was die Funktion nicht versteht (kein `type`,
/// ein unbekannter Name, eine zu tiefe Kette, ein Ringschluss), ist
/// [`HostReach::Unbounded`] und wird vom Aufrufer abgewiesen. Ein Irrtum in
/// diese Richtung kostet eine Funktion, ein Irrtum in die andere das Home jedes
/// Nutzers.
fn host_reach(sections: &[ConfSection], name: &str) -> Option<HostReach> {
    host_reach_inner(sections, name, Vec::new())
}

/// `chain` ist der Weg, über den dieser Abschnitt erreicht wurde – bewusst
/// **je Zweig** eine eigene Liste und nicht eine gemeinsame.
///
/// Real passiert: mit einer geteilten Liste galt bei einem `union` über
/// `cloud:a cloud:b` der zweite Zweig als Ringschluss, weil der erste `cloud`
/// schon eingetragen hatte — ein harmloses Netz-Backend wurde dadurch als
/// „unbestimmbar" abgewiesen. Die Tiefe ist auf [`MAX_WRAP_DEPTH`] begrenzt,
/// also kostet das Kopieren nichts.
fn host_reach_inner(
    sections: &[ConfSection],
    name: &str,
    mut chain: Vec<String>,
) -> Option<HostReach> {
    if chain.len() > MAX_WRAP_DEPTH {
        return Some(HostReach::Unbounded);
    }

    let lowered = name.to_ascii_lowercase();
    if chain.contains(&lowered) {
        // Ringschluss. rclone käme hier auch nicht weiter, aber „kommt nicht
        // weiter" ist keine Aussage über die Grenze — also abweisen.
        return Some(HostReach::Unbounded);
    }
    chain.push(lowered);

    let Some(backend) = section_value(sections, name, "type") else {
        // Kein Abschnitt oder kein `type`: unbekannte Form.
        return Some(HostReach::Unbounded);
    };
    let backend = backend.trim().to_ascii_lowercase();

    if backend.is_empty() {
        return Some(HostReach::Unbounded);
    }
    if HOST_FILESYSTEM_BACKENDS.contains(&backend.as_str()) {
        return Some(HostReach::Direct);
    }

    if WRAPPING_BACKENDS.contains(&backend.as_str()) {
        let Some(target) = section_value(sections, name, "remote") else {
            // Ein `alias` ohne `remote` steht in rclone für das
            // Arbeitsverzeichnis – also das Wirtssystem, an unbestimmter Stelle.
            return Some(HostReach::Unbounded);
        };
        return target_host_reach(sections, target, &chain);
    }

    if MULTI_WRAPPING_BACKENDS.contains(&backend.as_str()) {
        let Some(upstreams) = section_value(sections, name, "upstreams") else {
            return Some(HostReach::Unbounded);
        };
        let touches_host = upstreams.split_whitespace().any(|upstream| {
            // `combine` schreibt `verzeichnis=remote:pfad`. Der Teil vor dem
            // ersten `=` ist der Name im zusammengesetzten Baum, nicht das
            // Ziel; ein Ziel selbst enthält kein `=`.
            let target = upstream.split_once('=').map_or(upstream, |(_, rest)| rest);
            target_host_reach(sections, target, &chain).is_some()
        });
        // Mehrere Bäume übereinander: welcher einen Pfad beantwortet,
        // entscheidet rclone. Ein Ansatzpunkt ist daraus nicht ableitbar.
        return touches_host.then_some(HostReach::Unbounded);
    }

    None
}

/// Ein rclone-Ziel, wie es in `remote =` oder `upstreams =` steht: entweder
/// `name:pfad`, oder ein Dateisystempfad ohne Doppelpunkt, oder rclones
/// On-the-fly-Syntax `:backend:pfad`.
fn target_host_reach(
    sections: &[ConfSection],
    target: &str,
    chain: &[String],
) -> Option<HostReach> {
    let target = target.trim();

    if target.is_empty() {
        // Leeres Ziel ist das Arbeitsverzeichnis des Prozesses.
        return Some(HostReach::Unbounded);
    }
    if target.starts_with(':') {
        // `:local:/etc` – ein nicht konfiguriertes Backend, genau die Lücke aus
        // `5d31b2f7`. Hier steht sie in der Konfiguration statt in der Anfrage.
        return Some(HostReach::Unbounded);
    }

    match target.split_once(':') {
        // Kein Doppelpunkt: ein Pfad im Dateisystem des Wirtssystems. Ein
        // relativer Pfad ist gegen das Arbeitsverzeichnis zu lesen und damit
        // nicht verlässlich zu begrenzen.
        None => absolute_or_unbounded(target),
        Some((remote_name, sub_path)) => {
            if remote_name.is_empty()
                || remote_name.contains('/')
                || remote_name.contains('\\')
                || remote_name.contains(char::is_whitespace)
            {
                // Kein Remote-Name, den `validate_remote_name` durchliesse –
                // also kein Remote, sondern ein Pfad.
                return Some(HostReach::Unbounded);
            }

            match host_reach_inner(sections, remote_name, chain.to_vec())? {
                // `hostfs:/unterordner` – der Unterordner ist ein Pfad im
                // Wirtssystem. Ohne führendes `/` ist es das
                // Arbeitsverzeichnis.
                HostReach::Direct => absolute_or_unbounded(sub_path.trim()),
                HostReach::Rooted(base) => match join_below(&base, sub_path.trim()) {
                    Some(joined) => Some(HostReach::Rooted(joined)),
                    None => Some(HostReach::Unbounded),
                },
                HostReach::Unbounded => Some(HostReach::Unbounded),
            }
        }
    }
}

/// Ein absoluter Pfad ist ein bestimmbarer Ansatzpunkt, alles andere nicht.
fn absolute_or_unbounded(path: &str) -> Option<HostReach> {
    let path = std::path::PathBuf::from(path);
    if path.is_absolute()
        && path
            .components()
            .all(|c| !matches!(c, Component::ParentDir))
    {
        Some(HostReach::Rooted(path))
    } else {
        Some(HostReach::Unbounded)
    }
}

/// Hängt einen Unterpfad **unter** eine Basis. `None`, wenn der Unterpfad
/// nicht eindeutig darunter liegt.
///
/// `Path::join` mit einem absoluten Argument **ersetzt** die Basis — genau der
/// Fehler, der hier eine Grenze aufheben würde. Ein führender Trenner wird
/// deshalb übergangen: im Pfadraum eines umhüllenden Backends ist `/` dessen
/// eigene Wurzel, nicht die des Wirtssystems.
///
/// Ein `..` führt dagegen zu `None`, statt still zu verschwinden. Wegwerfen
/// wäre schlimmer als abweisen: rclone würde `..` **befolgen**, und die
/// Analyse hätte dann einen Ansatzpunkt gemeldet, der nicht der wirkliche ist —
/// eine Grenze, die am falschen Ort zieht.
fn join_below(base: &Path, sub_path: &str) -> Option<std::path::PathBuf> {
    let mut out = base.to_path_buf();
    for component in Path::new(sub_path).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Wo setzt dieses Remote in der Konfiguration `config_path` im Dateisystem des
/// Wirtssystems an? `Ok(None)` heisst: es tut es nicht.
///
/// Der Pfad muss **derselbe** sein, der anschliessend als `--config` an rclone
/// geht. Wer gegen eine andere Datei prüft als rclone liest, prüft nichts —
/// das war `5d31b2f7`.
pub async fn host_reach_of_remote_at(
    config_path: &Path,
    name: &str,
) -> anyhow::Result<Option<HostReach>> {
    let contents = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| anyhow::anyhow!("rclone configuration is not readable: {}", e))?;

    Ok(host_reach(&parse_conf_sections(&contents), name))
}

/// Dieselbe Frage gegen die **gemeinsame** Konfiguration.
pub async fn host_reach_of_remote(name: &str) -> anyhow::Result<Option<HostReach>> {
    host_reach_of_remote_at(&shared_config_path(), name).await
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

    /// Die Konfigurationsdatei, gegen die dieser Manager arbeitet.
    ///
    /// Bis hierher stand der Pfad an fünf Stellen im Dateibetrieb wörtlich im
    /// Code (`load_from_file`, `save_to_file`, `remove_key`,
    /// `delete_from_file`, `persist_to_file`). Jetzt gibt es **eine** Stelle –
    /// und damit auch nur eine, an der die nutzergebundene Auflösung
    /// ([`config_path_for`]) eingehängt wird, sobald der `ConfigManager` weiss,
    /// für welchen Nutzer er arbeitet (Ticket `ce385143`).
    fn config_path(&self) -> std::path::PathBuf {
        shared_config_path()
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
        let config_path = self.config_path();

        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Geschrieben wird ueber [`write_config_atomically`], nicht ueber
        // `Ini::write` — aus demselben Grund wie in `save_to_file`: `Ini::write`
        // schneidet die Zieldatei ab und schreibt dann neu, und dazwischen liegt
        // ein Fenster, in dem eine halbe `rclone.conf` auf Platte steht.
        write_config_atomically(&config_path, &render_configs_ini(&configs))
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
        let config_path = self.config_path();

        if !config_path.exists() {
            return Ok(Vec::new());
        }

        let mut conf = Ini::new();
        conf.load(&config_path)
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
        let config_path = self.config_path();

        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conf = Ini::new();

        if config_path.exists() {
            conf.load(&config_path)
                .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
        }

        // Handle WebDAV subtypes and set appropriate type and vendor
        let (actual_type, vendor) = rclone_type_and_vendor(&config_request.config_type);

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

        // Geschrieben wird ueber [`write_config_atomically`], nicht ueber
        // `Ini::write`: letzteres schneidet die Zieldatei ab und schreibt dann
        // neu. Waechst der Inhalt — ein neues Remote, laengere Zusatzfelder —,
        // liegt zwischen Abschneiden und vollstaendigem Schreiben ein Fenster,
        // in dem eine halbe `rclone.conf` auf Platte steht und dem Nutzer alle
        // Remotes fehlen.
        write_config_atomically(&config_path, &conf.writes())
    }

    /// Entfernt das gespeicherte Passwort eines Remotes.
    ///
    /// Der Weg über `save_config` gibt es nicht her: dort bedeutet „kein
    /// Passwort" *unverändert lassen*, nicht *löschen*. Wer ein Passwort
    /// loswerden wollte, musste deshalb den ganzen Abschnitt löschen und ohne
    /// `pass` neu schreiben — und zwischen beiden Schritten lag ein Fenster, in
    /// dem ein IO-Fehler nicht das Passwort, sondern die **ganze Verbindung**
    /// verlor.
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
        let config_path = self.config_path();

        if !config_path.exists() {
            return Ok(());
        }

        let contents = tokio::fs::read_to_string(&config_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read config: {}", e))?;

        let Some(updated) = remove_key_from_contents(&contents, section, key) else {
            // Der Schlüssel war nicht da. Dann wird auch nichts geschrieben —
            // ein Schreibvorgang ohne Änderung ist nur ein weiteres Risiko.
            return Ok(());
        };

        write_config_atomically(&config_path, &updated)
    }

    async fn delete_from_file(&self, name: &str) -> anyhow::Result<()> {
        let config_path = self.config_path();

        if !config_path.exists() {
            return Ok(());
        }

        delete_section_atomically(&config_path, name)
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

/// Rendert die im Speicher gehaltenen Remotes als `rclone.conf`-Text.
///
/// Ausgelagert aus `persist_to_file`, damit derselbe Text ohne globalen
/// Konfigurationspfad im Test erzeugt und über [`write_config_atomically`]
/// geschrieben werden kann.
fn render_configs_ini(configs: &HashMap<String, RcloneConfig>) -> String {
    let mut conf = Ini::new();

    for config in configs.values() {
        // Handle WebDAV subtypes and set appropriate type and vendor
        let (actual_type, vendor) = rclone_type_and_vendor(&config.config_type);

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

    conf.writes()
}

/// Entfernt einen Abschnitt aus der `rclone.conf` und schreibt das Ergebnis
/// über [`write_config_atomically`].
///
/// `Ini::write` wäre hier truncate + write. Dass der Inhalt beim Löschen
/// üblicherweise *schrumpft*, macht das Fenster kleiner, aber nicht kleiner als
/// null: das Abschneiden geschieht vor dem Schreiben, ein Fehler dazwischen
/// hinterlässt eine abgeschnittene Datei — also alle Remotes des Nutzers weg.
fn delete_section_atomically(config_path: &Path, name: &str) -> anyhow::Result<()> {
    let mut conf = Ini::new();
    conf.load(config_path)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    conf.remove_section(name);
    write_config_atomically(config_path, &conf.writes())
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
/// wird sie mit 0600 angelegt und anschliessend auf den Modus der bestehenden
/// **regulären** Datei am Pfad gesetzt. Gibt es dort keine — auch, wenn dort ein
/// Symlink liegt, dessen eigene Modusbits als Vorlage sinnlos wären —, bleibt es
/// bei 0600. Die Vorlage wird bewusst **nicht durch einen Symlink hindurch**
/// gelesen: sonst liesse sich über einen untergeschobenen Link auf eine
/// 0666-Datei eine weltlesbare `rclone.conf` erzwingen. Siehe
/// [`existing_file_mode`].
///
/// **Symlinks werden ersetzt — das ist eine bewusste Entscheidung.** War
/// `rclone.conf` ein Symlink (etwa auf eine Datei ausserhalb von `data/`), steht
/// nach dem `rename` eine *reguläre* Datei am alten Ort, und das ursprüngliche
/// Ziel wird nicht mehr beschrieben. Erhalten liesse sich der Symlink nur, indem
/// man ihm folgt und die Nebendatei neben dem *Ziel* anlegt — also indem man
/// aufgrund des Inhalts eines Verzeichniseintrags entscheidet, wohin geschrieben
/// wird. Genau das ist der klassische Symlink-Angriff: `data/cfg/` ist zur
/// Laufzeit beschreibbar, ein dort untergeschobener Symlink würde die
/// Konfiguration samt Zugangsdaten an einen fremden Ort schreiben, und die
/// TOCTOU-Lücke zwischen „Ziel auflösen" und „Nebendatei umbenennen" bleibt
/// grundsätzlich offen. Der Schutz ist mehr wert als die Auslagerung: wer
/// `rclone.conf` verlegen will, hängt `data/cfg` als Ganzes um (Bind-Mount,
/// Symlink auf das *Verzeichnis*) — dann greift das `rename` innerhalb des
/// verlegten Verzeichnisses und alles bleibt, wie es sein soll.
///
/// Damit niemand rätselt, warum seine Auslagerung nicht mehr wirkt, wird ein
/// vorgefundener Symlink einmal pro Schreibvorgang mit `warn` protokolliert.
///
/// **Dauerhaftigkeit:** nach dem `rename` wird auch das **Verzeichnis**
/// synchronisiert. Ohne das liegt der neue Inhalt zwar vollständig auf Platte,
/// der Verzeichniseintrag aber möglicherweise nur im Cache — ein Systemabsturz
/// direkt danach lässt die Änderung verschwinden. Eine halbe Datei kann es auch
/// ohne den `fsync` nie geben; er schliesst nur die Lücke „Änderung verloren".
fn write_config_atomically(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // `symlink_metadata` folgt dem Link nicht — genau das wird hier gebraucht.
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        tracing::warn!(
            path = %path.display(),
            "rclone configuration is a symlink and will be replaced by a regular file; \
             move the whole cfg directory instead of linking the single file"
        );
    }

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

    // Der Verzeichniseintrag ist jetzt umgehängt, aber noch nicht zwingend auf
    // Platte. Ein `fsync` auf das Verzeichnis macht ihn dauerhaft.
    //
    // Scheitert er, ist das **kein** Fehlschlag des Schreibvorgangs: die neue
    // Fassung liegt bereits am Ziel, und ein `Err` würde dem Aufrufer das
    // Gegenteil erzählen — der Nutzer bekäme eine Fehlermeldung für eine
    // Änderung, die in Wahrheit gespeichert ist. Also nur protokollieren.
    // (Auf Dateisystemen ohne Verzeichnis-`fsync` — etwa manchen
    // Netzwerkdateisystemen — ist ein `EINVAL` hier normal.)
    if let Err(e) = sync_directory(parent) {
        tracing::warn!(
            directory = %parent.display(),
            error = %e,
            "config written, but syncing its directory failed; \
             the rename may be lost if the system crashes now"
        );
    }

    Ok(())
}

/// `fsync` auf ein Verzeichnis. Zum Öffnen genügt Lesezugriff — geschrieben wird
/// nicht in das Verzeichnis, es wird nur seine bereits erfolgte Änderung
/// festgeschrieben.
fn sync_directory(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Der Rechte-Modus einer bestehenden **regulären** Datei, sofern lesbar.
/// `None` bedeutet „keine Vorlage" — der Aufrufer bleibt dann bei 0600, dem
/// engeren Wert.
///
/// Bewusst `symlink_metadata`, nicht `metadata`: `metadata` folgt dem Link und
/// hätte die Rechtebits des **Link-Ziels** als Vorlage genommen. Damit liess
/// sich der Riegel von [`write_config_atomically`] aushebeln — wer in `data/cfg`
/// schreiben darf, legt dort einen Symlink auf eine 0666-Datei, und die neu
/// entstandene, reguläre `rclone.conf` mit allen Zugangsdaten wäre weltlesbar
/// gewesen. Genau das ist gemessen worden.
///
/// Ein Symlink hat eigene Modusbits (üblicherweise 0777), die als Vorlage
/// sinnlos sind; alles, was keine reguläre Datei ist, liefert deshalb `None`
/// und fällt auf 0600 zurück.
fn existing_file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path)
            .ok()
            .filter(|meta| meta.file_type().is_file())
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

    // -----------------------------------------------------------------------
    // Ticket `514ce5f5`: wo setzt ein Remote im Wirtssystem an?
    // -----------------------------------------------------------------------

    fn reach_of(conf: &str, name: &str) -> Option<HostReach> {
        host_reach(&parse_conf_sections(conf), name)
    }

    const REACH_CONF: &str = "\
[hostfs]
type = local

[cloud]
type = webdav
url = https://example.org/dav

[alias_absolut]
type = alias
remote = /srv/daten

[alias_relativ]
type = alias
remote = daten

[alias_auf_local]
type = alias
remote = hostfs:/srv/daten

[alias_auf_local_ohne_pfad]
type = alias
remote = hostfs:

[crypt_auf_alias]
type = crypt
remote = alias_absolut:tief/er

[crypt_auf_cloud]
type = crypt
remote = cloud:verschluesselt

[onthefly]
type = alias
remote = :local:/etc

[alias_ohne_ziel]
type = alias

[sammlung]
type = union
upstreams = cloud:a cloud:b

[sammlung_mit_loch]
type = union
upstreams = cloud:a hostfs:/etc

[zusammengesetzt]
type = combine
upstreams = eins=cloud:a zwei=/srv
";

    /// Der gemeldete Befund: `type = local` spricht das Wirtssystem an, ein
    /// Netz-Backend nicht. Wer nur das eine oder nur das andere erkennt,
    /// begrenzt entweder zu wenig oder macht die App unbenutzbar.
    #[test]
    fn a_local_backend_is_direct_and_a_network_backend_is_nothing() {
        assert!(reach_of(REACH_CONF, "hostfs") == Some(HostReach::Direct));
        assert!(reach_of(REACH_CONF, "cloud").is_none());
        assert!(reach_of(REACH_CONF, "crypt_auf_cloud").is_none());
        assert!(reach_of(REACH_CONF, "sammlung").is_none());
        // Gross-/Kleinschreibung spielt keine Rolle — rclone liest die Datei
        // genauso.
        assert!(reach_of(REACH_CONF, "HOSTFS") == Some(HostReach::Direct));
    }

    /// Die Umhüllung ist der eigentlich gefährliche Teil: `alias`, `crypt` und
    /// Freunde tragen ihr Ziel in `remote =`, und das darf ein Pfad oder ein
    /// `type=local`-Remote sein. Wer nur `type` ansieht, übersieht es.
    #[test]
    fn wrapping_backends_yield_the_point_they_hang_at() {
        assert!(
            reach_of(REACH_CONF, "alias_absolut")
                == Some(HostReach::Rooted(std::path::PathBuf::from("/srv/daten")))
        );
        assert!(
            reach_of(REACH_CONF, "alias_auf_local")
                == Some(HostReach::Rooted(std::path::PathBuf::from("/srv/daten")))
        );
        // Die Kette wird zusammengesetzt, nicht abgebrochen.
        assert!(
            reach_of(REACH_CONF, "crypt_auf_alias")
                == Some(HostReach::Rooted(std::path::PathBuf::from(
                    "/srv/daten/tief/er"
                )))
        );
    }

    /// Alles, was der Ansatzpunkt nicht bestimmbar macht, ist `Unbounded` — und
    /// der Aufrufer weist es ab. Ein Irrtum in diese Richtung kostet eine
    /// Funktion, ein Irrtum in die andere das Home jedes Nutzers.
    #[test]
    fn the_unknown_is_unbounded() {
        for name in [
            // gar nicht konfiguriert
            "erfunden",
            // relativer Pfad: gegen das Arbeitsverzeichnis des Prozesses
            "alias_relativ",
            // `hostfs:` ohne Pfad ist ebenfalls das Arbeitsverzeichnis
            "alias_auf_local_ohne_pfad",
            // rclones On-the-fly-Syntax, in der Konfiguration statt im Namen
            "onthefly",
            // `alias` ohne `remote`
            "alias_ohne_ziel",
            // mehrere Bäume übereinander: welcher antwortet, entscheidet rclone
            "sammlung_mit_loch",
            "zusammengesetzt",
        ] {
            assert!(
                reach_of(REACH_CONF, name) == Some(HostReach::Unbounded),
                "{} muesste unbestimmbar sein, ist {:?}",
                name,
                reach_of(REACH_CONF, name).is_some()
            );
        }

        // Abschnitt ohne `type`, und `type` leer.
        assert!(reach_of("[leer]\nurl = https://x\n", "leer") == Some(HostReach::Unbounded));
        assert!(reach_of("[leer]\ntype =\n", "leer") == Some(HostReach::Unbounded));
    }

    /// Ein Ringschluss und eine zu tiefe Kette dürfen den Prozess nicht in eine
    /// Endlosschleife treiben — beides ist über `/api/configs` auslösbar.
    #[test]
    fn cycles_and_deep_chains_terminate_as_unbounded() {
        assert!(reach_of("[a]\ntype = alias\nremote = a:/x\n", "a") == Some(HostReach::Unbounded));
        assert!(
            reach_of(
                "[a]\ntype = alias\nremote = b:/x\n[b]\ntype = alias\nremote = a:/y\n",
                "a"
            ) == Some(HostReach::Unbounded)
        );

        let mut conf = String::new();
        for step in 0..(MAX_WRAP_DEPTH + 4) {
            conf.push_str(&format!(
                "[a{}]\ntype = alias\nremote = a{}:/x\n",
                step,
                step + 1
            ));
        }
        conf.push_str("[cloud]\ntype = webdav\n");
        assert!(reach_of(&conf, "a0") == Some(HostReach::Unbounded));
    }

    /// `Path::join` mit einem absoluten Argument **ersetzt** die Basis. Genau
    /// das würde hier eine Grenze aufheben, also tut `join_below` es nicht.
    /// `Path::join` mit einem absoluten Argument **ersetzt** die Basis. Genau
    /// das würde hier eine Grenze aufheben, also tut `join_below` es nicht —
    /// und ein `..` wird abgewiesen statt weggeworfen: rclone würde es
    /// befolgen, und ein weggeworfenes `..` hätte einen Ansatzpunkt gemeldet,
    /// der nicht der wirkliche ist.
    #[test]
    fn a_subpath_can_never_replace_or_leave_its_base() {
        let base = Path::new("/srv/daten");
        assert_eq!(
            join_below(base, "unten").as_deref(),
            Some(Path::new("/srv/daten/unten"))
        );
        assert_eq!(
            join_below(base, "/etc").as_deref(),
            Some(Path::new("/srv/daten/etc")),
            "ein absoluter Unterpfad darf die Basis nicht ersetzen"
        );
        assert_eq!(
            join_below(base, "./tief/").as_deref(),
            Some(Path::new("/srv/daten/tief"))
        );
        assert_eq!(join_below(base, "").as_deref(), Some(base));
        assert_eq!(join_below(base, "../../etc"), None);
        assert_eq!(join_below(base, "a/../b"), None);

        // Und dasselbe über die Konfiguration, denn dort kommt es an: ein `..`
        // in einer Kette macht den Ansatzpunkt unbestimmbar, nicht harmlos.
        assert!(
            reach_of(
                "[a]\ntype = local\n[b]\ntype = alias\nremote = a:/srv\n[c]\ntype = crypt\nremote = b:../../etc\n",
                "c"
            ) == Some(HostReach::Unbounded)
        );
        assert!(
            reach_of(
                "[a]\ntype = local\n[b]\ntype = alias\nremote = a:/srv\n[c]\ntype = crypt\nremote = b:/unten\n",
                "c"
            ) == Some(HostReach::Rooted(std::path::PathBuf::from("/srv/unten")))
        );
    }

    /// Gegenprobe zur Analyse selbst: gegen dieselbe Datei liefert die
    /// Bestandsprüfung `ensure_configured_remote_at` für ein
    /// `type=local`-Remote ein glattes `Ok` — genau der gemeldete Befund. Ohne
    /// diesen Test belegen die obigen nicht, dass überhaupt etwas fehlte.
    #[tokio::test]
    async fn the_existing_check_says_nothing_about_the_backend() {
        let dir = scratch_dir("514ce5f5-reach");
        let conf = dir.join("rclone.conf");
        std::fs::write(&conf, REACH_CONF).expect("conf schreibbar");

        assert!(
            ensure_configured_remote_at(&conf, "hostfs").await.is_ok(),
            "die Bestandspruefung laesst ein type=local-Remote durch"
        );
        assert!(
            host_reach_of_remote_at(&conf, "hostfs")
                .await
                .expect("lesbar")
                == Some(HostReach::Direct)
        );
        assert!(host_reach_of_remote_at(&conf, "cloud")
            .await
            .expect("lesbar")
            .is_none());

        // Und der Riegel aus `5d31b2f7` steht davor und unabhängig davon.
        assert!(ensure_configured_remote_at(&conf, ":local:").await.is_err());
        assert!(ensure_configured_remote_at(&conf, "[evil]").await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

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
        let names: Vec<String> = parse_conf_sections(conf)
            .into_iter()
            .map(|section| section.name)
            .collect();
        assert_eq!(names, vec!["gdrive", "MyBox"]);
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

    // -----------------------------------------------------------------------
    // Nutzergebundene Auflösung des Konfigurationspfads (Ticket bc7277d3)
    // -----------------------------------------------------------------------

    /// Der `const` und die Funktion müssen dasselbe bezeichnen. Läuft das
    /// auseinander, prüft die App gegen eine andere Datei, als rclone per
    /// `--config` liest — und genau das war `5d31b2f7`.
    #[test]
    fn shared_path_matches_the_constant() {
        assert_eq!(shared_config_path(), Path::new(RCLONE_CONFIG_PATH));
    }

    #[test]
    fn a_users_config_lives_under_its_own_directory() {
        let id = "3f2a1b4c-0000-4000-8000-abcdefabcdef";
        assert_eq!(
            config_path_for(id).unwrap(),
            Path::new("data/cfg/users").join(id).join("rclone.conf")
        );
        // Die gemeinsame Datei bleibt daneben stehen, nicht darunter.
        assert!(!config_path_for(id)
            .unwrap()
            .starts_with(shared_config_path()));
    }

    /// Die Kennung wird ein Verzeichnisname. Sie kommt aus der Datenbank, und
    /// eine von Hand bearbeitete `users`-Tabelle ist ein Pfad, den sonst
    /// niemand prüft.
    #[test]
    fn a_user_id_that_is_not_one_path_segment_is_rejected() {
        for id in [
            "",
            ".",
            "..",
            "../..",
            "../../etc",
            "/etc",
            "a/b",
            "a\\b",
            "a b",
            "a.b",
            "a_b",
            ".hidden",
            "a\0b",
            "üser",
            "a\nb",
        ] {
            assert!(
                config_path_for(id).is_err(),
                "{:?} haette abgelehnt werden muessen",
                id
            );
        }
        assert!(config_path_for(&"a".repeat(MAX_USER_ID_LEN + 1)).is_err());
        // Gegenprobe: die tatsächlich vorkommende Form geht durch.
        assert!(config_path_for(&uuid::Uuid::new_v4().to_string()).is_ok());
        assert!(config_path_for(&"a".repeat(MAX_USER_ID_LEN)).is_ok());
    }

    #[test]
    fn creating_a_user_config_uses_0700_and_0600() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_dir("usercfg");
        let id = "11111111-2222-4333-8444-555555555555";

        let path = ensure_user_config_in(&base, id).unwrap();
        assert_eq!(path, config_path_in(&base, id).unwrap());

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "Verzeichnis muss 0700 sein");
        assert_eq!(file_mode, 0o600, "Datei muss 0600 sein");
        // Auch das Zwischenverzeichnis `users/` listet Nutzerkennungen auf.
        let parents_mode = std::fs::metadata(base.join("users"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parents_mode, 0o700);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        // Idempotent, und die Rechte einer bestehenden Datei bleiben stehen.
        std::fs::write(&path, SAMPLE_CONF).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        ensure_user_config_in(&base, id).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SAMPLE_CONF);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640,
            "ein zweiter Aufruf darf bestehende Rechte nicht ueberschreiben"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn removing_a_user_config_takes_the_whole_directory() {
        let base = scratch_dir("usercfg-del");
        let id = "66666666-7777-4888-8999-aaaaaaaaaaaa";

        let path = ensure_user_config_in(&base, id).unwrap();
        std::fs::write(&path, SAMPLE_CONF).unwrap();

        remove_user_config_in(&base, id).unwrap();
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
        // Ein zweiter Aufruf ist kein Fehler …
        remove_user_config_in(&base, id).unwrap();
        // … eine unbrauchbare Kennung schon, statt irgendetwas zu loeschen.
        assert!(remove_user_config_in(&base, "../..").is_err());
        assert!(base.exists(), "die Wurzel darf nicht mitgeloescht werden");

        std::fs::remove_dir_all(&base).ok();
    }

    /// Der Kern der Isolation, und der Grund fuer die Gegenprobe: ein Remote,
    /// das nur in der Konfiguration eines **anderen** Nutzers steht, ist
    /// unbekannt. Ohne die Gegenprobe (dasselbe Remote in der **eigenen**
    /// Konfiguration wird angenommen) beweist ein "abgelehnt" nichts — es
    /// koennte auch heissen, dass die Pruefung immer ablehnt.
    #[tokio::test]
    async fn a_remote_of_another_user_is_unknown() {
        let base = scratch_dir("isolation");
        let alice = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let bob = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";

        let alice_conf = ensure_user_config_in(&base, alice).unwrap();
        let bob_conf = ensure_user_config_in(&base, bob).unwrap();

        // Nur Bob hat `bobbox`.
        std::fs::write(&bob_conf, "[bobbox]\ntype = webdav\n").unwrap();

        // Gegenprobe zuerst: bei Bob wird der Name angenommen. Erst damit ist
        // das folgende "abgelehnt" eine Aussage.
        assert!(
            ensure_configured_remote_at(&bob_conf, "bobbox")
                .await
                .is_ok(),
            "Gegenprobe: der Eigentuemer muss sein Remote benutzen duerfen"
        );

        // Und bei Alice nicht — ununterscheidbar von einem erfundenen Namen.
        let err = ensure_configured_remote_at(&alice_conf, "bobbox")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, "Unknown remote");
        assert_eq!(
            ensure_configured_remote_at(&alice_conf, "erfunden")
                .await
                .unwrap_err()
                .to_string(),
            err,
            "die Meldung darf nicht verraten, dass der Name woanders existiert"
        );

        // Sobald Alice ihr eigenes Remote hat, geht es — auch das eine
        // Gegenprobe: die Ablehnung kam vom Geltungsbereich, nicht vom Namen.
        std::fs::write(&alice_conf, "[bobbox]\ntype = local\n").unwrap();
        assert!(ensure_configured_remote_at(&alice_conf, "bobbox")
            .await
            .is_ok());

        // Die syntaktische Pruefung bleibt vorgeschaltet: `:local:` kommt in
        // keinem Geltungsbereich durch, auch nicht in der eigenen.
        assert!(ensure_configured_remote_at(&alice_conf, ":local:")
            .await
            .is_err());

        std::fs::remove_dir_all(&base).ok();
    }

    /// Eine Konfiguration, die es nicht gibt, kennt kein Remote — und sagt das
    /// als Lesefehler, nicht als "unknown". Die Unterscheidung ist der Grund,
    /// warum `ensure_user_config` die leere Datei anlegt.
    #[tokio::test]
    async fn a_missing_config_rejects_every_remote() {
        let base = scratch_dir("isolation-missing");
        let path = base.join("gibtsnicht").join("rclone.conf");
        let err = ensure_configured_remote_at(&path, "irgendwas")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not readable"), "{err}");
        std::fs::remove_dir_all(&base).ok();
    }

    /// Festgeschriebene Entscheidung, nicht nur beobachtetes Verhalten: ein
    /// Symlink an der Stelle der `rclone.conf` wird **ersetzt**, das
    /// ursprüngliche Ziel bleibt unverändert. Die Begründung steht an
    /// `write_config_atomically`. Schlägt dieser Test eines Tages um, hat jemand
    /// angefangen, Symlinks zu folgen — und das ist genau der Weg, auf dem die
    /// Zugangsdaten an einen fremden Ort geraten.
    #[test]
    fn a_symlinked_config_is_replaced_and_its_target_left_alone() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("symlink");
        let target = dir.join("ausgelagert.conf");
        let path = dir.join("rclone.conf");
        std::fs::write(&target, SAMPLE_CONF).unwrap();
        // Weit offenes Ziel: taugt es als Rechte-Vorlage, wird die neue Datei
        // weltlesbar. Genau das darf nicht passieren.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        write_config_atomically(&path, "neue Fassung\n").unwrap();

        // Am alten Ort steht jetzt eine reguläre Datei mit dem neuen Inhalt …
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(
            !meta.file_type().is_symlink(),
            "der Symlink muss durch eine reguläre Datei ersetzt sein"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "neue Fassung\n");
        // … die **nicht** die Rechte des Link-Ziels geerbt hat. `metadata`
        // statt `symlink_metadata` in `existing_file_mode` hätte hier 0666
        // ergeben — die Zugangsdaten wären für jeden lesbar. Ohne lesbare
        // Vorlage gilt 0600.
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "die ersetzte Datei darf die Rechte des Link-Ziels nicht übernehmen"
        );
        // … und das frühere Ziel ist unangetastet, auch in seinen Rechten.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), SAMPLE_CONF);
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o666
        );
        // Keine Nebendatei übrig (Ziel + ersetzte Datei = 2).
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Kriterium 2 des Tickets — der Verzeichnis-`fsync` — war bisher nur durch
    /// Codelesen belegt: ein Tester hat den Aufruf entfernt, und **kein** Test
    /// fiel durch. Ein gelungenes `fsync` ist von aussen nicht beobachtbar, ein
    /// **gescheitertes** aber schon: es wird protokolliert.
    ///
    /// Also wird es zum Scheitern gebracht. Das Zielverzeichnis bekommt `0300`
    /// (schreiben und betreten, aber nicht lesen): Nebendatei anlegen und
    /// `rename` gelingen weiterhin, das `File::open` des Verzeichnisses
    /// scheitert mit `EACCES`. Steht die Warnung im Protokoll, ist der Aufruf
    /// tatsächlich gelaufen; wird er entfernt, fällt dieser Test durch.
    ///
    /// Als root greifen die Rechtebits nicht — dann wird der Nachweis
    /// übersprungen statt falsch bestanden.
    #[test]
    fn the_write_path_really_syncs_the_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("dirfsync");
        let cfg = dir.join("cfg");
        std::fs::create_dir_all(&cfg).unwrap();
        let path = cfg.join("rclone.conf");
        // Schreibbar und betretbar, aber nicht lesbar.
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o300)).unwrap();

        // Probe: verweigert das Öffnen des Verzeichnisses hier überhaupt
        // jemandem den Dienst? Als root nicht.
        let enforced = std::fs::File::open(&cfg).is_err();

        if enforced {
            let captured = dir.join("tracing.log");
            let sink = captured.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&sink)
                        .expect("die Auffangdatei")
                })
                .finish();

            // `with_default` ist thread-lokal — im Gegensatz zu
            // `set_global_default` verträgt es parallel laufende Tests.
            let result = tracing::subscriber::with_default(subscriber, || {
                write_config_atomically(&path, "neue Fassung\n")
            });

            // Der Schreibvorgang selbst gelingt: ein gescheitertes
            // Verzeichnis-`fsync` ist kein Fehlschlag, die Datei liegt am Ziel.
            result.expect("der Schreibvorgang gelingt trotz fehlgeschlagenem fsync");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "neue Fassung\n");

            // Ohne Warnung entsteht die Auffangdatei nie — dann ist der Text
            // leer, und die Zusicherung nennt den Grund statt eines
            // rätselhaften `NotFound`.
            let text = std::fs::read_to_string(&captured).unwrap_or_default();
            assert!(
                text.contains("syncing its directory failed"),
                "ohne diese Warnung wurde `sync_directory` nie aufgerufen: {text}"
            );
        }

        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o700)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Der Verzeichnis-`fsync` muss auf einem gewöhnlichen Verzeichnis
    /// gelingen — sonst würde jeder Schreibvorgang eine Warnung erzeugen.
    #[test]
    fn syncing_a_directory_succeeds() {
        let dir = scratch_dir("dirsync");
        sync_directory(&dir).expect("fsync auf ein Verzeichnis muss gelingen");
        std::fs::remove_dir_all(&dir).ok();
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

    /// Der Fall, der bisher durchrutschte: die neue Fassung ist **groesser**
    /// als die alte. Gemessen wird derselbe Weg, den `save_to_file` nimmt —
    /// `Ini::writes()` erzeugt den Text, `write_config_atomically` schreibt ihn.
    ///
    /// Verglichen wird die **Zeilenmenge**, nicht der Bytestrom: `Ini` haelt die
    /// Schluessel in einer HashMap, die Reihenfolge ist also nicht zugesichert.
    ///
    /// Auf einem winzigen Dateisystem (siehe `large_write_is_all_or_nothing`)
    /// scheitert das `write_all` mit ENOSPC — dann muss die alte Datei
    /// vollstaendig dastehen.
    #[test]
    fn a_growing_configuration_is_written_all_or_nothing() {
        let dir = scratch_dir("grow");
        let path = dir.join("rclone.conf");
        std::fs::write(&path, SAMPLE_CONF).unwrap();

        // Neuer Abschnitt mit langen Zusatzfeldern: der Inhalt waechst deutlich.
        let mut conf = Ini::new();
        conf.load(&path).unwrap();
        conf.set("neu", "type", Some("webdav".to_string()));
        conf.set("neu", "url", Some("https://example.org/dav".to_string()));
        for index in 0..64 {
            conf.set("neu", &format!("field_{index}"), Some("v".repeat(1024)));
        }
        let rendered = conf.writes();
        assert!(
            rendered.len() > SAMPLE_CONF.len(),
            "der Testfall soll wachsenden Inhalt pruefen"
        );

        match write_config_atomically(&path, &rendered) {
            Ok(()) => {
                let on_disk = std::fs::read_to_string(&path).unwrap();
                let written: std::collections::BTreeSet<&str> = on_disk
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                let expected: std::collections::BTreeSet<&str> = rendered
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                assert_eq!(written, expected, "vollstaendige neue Fassung erwartet");
                // Der alte Abschnitt ist mitgewandert, nicht verloren gegangen.
                assert!(written.contains("[mybox]") || written.contains("[MyBox]"));
            }
            Err(err) => {
                assert!(err.to_string().contains("Failed to write config"));
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    SAMPLE_CONF,
                    "die alte Konfiguration muss vollstaendig zurueckbleiben"
                );
            }
        }
        // In beiden Faellen: keine Nebendatei uebrig.
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
    /// `delete_from_file` schreibt jetzt ueber `write_config_atomically`.
    /// Geprueft wird der ausgelagerte Kern `delete_section_atomically`, damit
    /// der globale `RCLONE_CONFIG_PATH` aus dem Test bleibt.
    ///
    /// Der Erfolgsfall: der genannte Abschnitt ist weg, der andere vollstaendig
    /// da. Verglichen wird die **Zeilenmenge**, nicht der Bytestrom — `Ini`
    /// haelt die Schluessel in einer HashMap, die Reihenfolge ist nicht
    /// zugesichert.
    #[test]
    fn deleting_a_section_removes_only_that_section() {
        let dir = scratch_dir("del-atomic");
        let path = dir.join("rclone.conf");
        std::fs::write(&path, SAMPLE_CONF).unwrap();

        delete_section_atomically(&path, "gdrive").unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("[gdrive]"));
        assert!(on_disk.contains("[mybox]") || on_disk.contains("[MyBox]"));
        assert!(on_disk.contains("https://example.org/dav"));
        // Keine Nebendatei uebrig.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Der eigentliche Punkt des Tickets fuer den Loeschweg: schlaegt das
    /// Schreiben fehl, liegt die **alte** Konfiguration vollstaendig da — nicht
    /// eine abgeschnittene, in der dem Nutzer alle Remotes fehlen.
    ///
    /// Erzwungen ueber ein Verzeichnis auf `0500` (EACCES). Als root greift das
    /// nicht — dann wird der Pruefteil uebersprungen statt falsch bestanden.
    #[test]
    fn a_failed_delete_leaves_the_old_configuration_complete() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("del-fail");
        let path = dir.join("rclone.conf");
        std::fs::write(&path, SAMPLE_CONF).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        // Probe: darf hier ueberhaupt niemand mehr schreiben?
        let probe = dir.join(".probe");
        let writable = std::fs::File::create(&probe).is_ok();
        std::fs::remove_file(&probe).ok();

        if !writable {
            let err = delete_section_atomically(&path, "gdrive").unwrap_err();
            // Der genommene Zweig gehoert in die Ausgabe: der Test besteht in
            // beiden Zweigen, nur die Ausgabe belegt, welcher lief.
            eprintln!("delete_section_atomically Zweig: Err({err})");
            assert!(err.to_string().contains("Failed to write config"));
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                SAMPLE_CONF,
                "die alte Konfiguration muss vollstaendig zurueckbleiben"
            );
        }

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Derselbe Nachweis fuer den vierten Schreibweg, `persist_to_file`:
    /// `render_configs_ini` erzeugt den Text, `write_config_atomically`
    /// schreibt ihn. Der Inhalt waechst hier deutlich — auf einem winzigen
    /// Dateisystem (`RCLONE_GUI_TEST_SCRATCH_DIR` auf ein 64k-tmpfs, siehe
    /// `large_write_is_all_or_nothing`) scheitert das `write_all` mit ENOSPC.
    #[test]
    fn persisting_memory_configs_is_all_or_nothing() {
        let dir = scratch_dir("persist");
        let path = dir.join("rclone.conf");
        std::fs::write(&path, SAMPLE_CONF).unwrap();

        let mut configs = HashMap::new();
        let mut additional_fields = HashMap::new();
        for index in 0..64 {
            additional_fields.insert(format!("field_{index}"), "v".repeat(1024));
        }
        configs.insert(
            "neu".to_string(),
            RcloneConfig {
                name: "neu".to_string(),
                config_type: "webdav-nextcloud".to_string(),
                url: Some("https://example.org/dav".to_string()),
                username: Some("frank".to_string()),
                password: Some("OBSCURED_C".to_string()),
                additional_fields,
            },
        );

        let rendered = render_configs_ini(&configs);
        assert!(
            rendered.len() > SAMPLE_CONF.len(),
            "der Testfall soll wachsenden Inhalt pruefen"
        );
        // Der WebDAV-Untertyp wird zu type + vendor aufgeloest.
        assert!(rendered.contains("type=webdav") || rendered.contains("type = webdav"));
        assert!(rendered.contains("nextcloud"));

        match write_config_atomically(&path, &rendered) {
            Ok(()) => {
                eprintln!("persist_to_file Zweig: Ok(()) — Schreiben ging durch");
                let on_disk = std::fs::read_to_string(&path).unwrap();
                let written: std::collections::BTreeSet<&str> = on_disk
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                let expected: std::collections::BTreeSet<&str> = rendered
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                assert_eq!(written, expected, "vollstaendige neue Fassung erwartet");
            }
            Err(err) => {
                eprintln!("persist_to_file Zweig: Err({err})");
                assert!(err.to_string().contains("Failed to write config"));
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    SAMPLE_CONF,
                    "die alte Konfiguration muss vollstaendig zurueckbleiben"
                );
            }
        }
        // In beiden Faellen: keine Nebendatei uebrig.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
