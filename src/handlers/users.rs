//! Benutzerverwaltung: die Backend-Seite.
//!
//! Bis hierher gab es **keinen** Weg, ein zweites Konto anzulegen. Wer eine
//! Zugriffsprüfung nachweisen musste, hat die Zeile per SQL in `data/tasks.db`
//! geschrieben und dabei den `password_hash` des Admins abgeschrieben, um sich
//! keinen Argon2-Hash erzeugen zu müssen. Das ist der Grund, warum dieses Modul
//! existiert.
//!
//! Zwei Dinge tragen das ganze Modul:
//!
//! 1. **Die Rollenprüfung steht vor allem anderen.** `require_admin` ist in
//!    jedem verwaltenden Handler die erste Anweisung — vor jedem Blick in die
//!    Datenbank, vor jeder Auswertung des Pfadparameters. Für einen
//!    Nicht-Admin ist die Antwort damit nicht nur *gleich*, sondern *dieselbe
//!    Arbeit*: es gibt keinen Zweig, in dem ein vorhandenes Konto anders
//!    behandelt würde als ein nicht vorhandenes, also auch kein Zeitsignal, an
//!    dem sich Benutzernamen abfragen liessen. Das ist stärker als ein
//!    nachträglicher Zeitausgleich wie in `shares.rs`, weil es die Verzweigung
//!    gar nicht erst gibt.
//!
//! 2. **Die Schutzregel gegen Aussperren liegt in der Datenbank**, nicht hier.
//!    `database::update_user_protected` und `database::delete_user_protected`
//!    sind je **eine** Anweisung mit dem Wächter im `WHERE`. Dieses Modul darf
//!    deshalb nie „erst zählen, dann schreiben" — die Begründung steht
//!    ausführlich an den beiden Funktionen.
//!
//! Was dieses Modul **nicht** tut: Oberfläche (Ticket `58adcf30`), Umbau der
//! bestehenden Wege auf nutzereigene rclone-Configs (Ticket `d8a12aa9`, darf
//! nicht vor `771319ce` landen). Neue Nutzer bekommen ihr Config-Verzeichnis,
//! bestehende Aufrufer bleiben unverändert.

use crate::database::{self, User};
use crate::handlers::auth;
use crate::handlers::auth_web::CurrentUser;
use crate::models::ApiResponse;
use axum::body::Bytes;
use axum::extract::{Json, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json as ResponseJson, Response};
use axum::Extension;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use std::collections::HashMap;

/// Rollenname mit Verwaltungsrechten. Derselbe Wert wie in
/// `handlers::download` — dort ist er privat, und diese Datei gehört einem
/// anderen Ticket.
const ADMIN_ROLE: &str = "admin";

/// Rollenname ohne Verwaltungsrechte.
const USER_ROLE: &str = "user";

/// Obergrenze für einen Benutzernamen. Er wird zum Anmeldenamen, steht in
/// Audit-Zeilen und in der Oberfläche; 64 Zeichen sind reichlich.
const MAX_USERNAME_LENGTH: usize = 64;

/// Obergrenze für den Home-Pfad. Dieselbe wie für die Pfadfelder eines Tasks.
const MAX_HOME_PATH_LENGTH: usize = 4096;

/// `target` aller Audit-Zeilen dieses Moduls, damit sich Rollenwechsel und
/// Löschungen aus einem Log herausfiltern lassen (`RUST_LOG=user_audit=info`).
/// Genauso macht es `rsyncd.rs` mit `rsync_audit`.
const AUDIT_TARGET: &str = "user_audit";

// ---------------------------------------------------------------------------
// Fehler
// ---------------------------------------------------------------------------

/// Ein abgelehnter Verwaltungsaufruf.
///
/// `Debug` ist abgeleitet und darf das bleiben: hier steht nur ein Status und
/// eine Meldung, die selbst schon für den Client bestimmt ist. Kein Geheimnis
/// kommt in diesen Typ — und wenn doch einmal eines dazukäme, hält
/// `error_debug_carries_no_secret` das fest.
#[derive(Debug)]
pub struct UserError {
    status: StatusCode,
    message: String,
}

impl UserError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "Kein solches Konto")
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// Ein Fehler, dessen Ursache **nicht** nach draussen geht. Die Ursache
    /// landet in `tracing`, der Client bekommt einen unbestimmten 500er.
    fn internal(context: &str, cause: impl std::fmt::Display) -> Self {
        tracing::error!("Benutzerverwaltung: {}: {:#}", context, cause);
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Interner Fehler in der Benutzerverwaltung",
        )
    }
}

impl IntoResponse for UserError {
    fn into_response(self) -> Response {
        // Nur die für den Client bestimmte Meldung, nie ein Passwort: die
        // Request-Typen weiter unten geben ihre Geheimnisse gar nicht her.
        tracing::warn!(
            "Benutzerverwaltung abgelehnt ({}): {}",
            self.status,
            self.message
        );
        (
            self.status,
            ResponseJson(ApiResponse::<String>::error(&self.message)),
        )
            .into_response()
    }
}

/// **Die** Rollenprüfung. Erste Anweisung jedes verwaltenden Handlers.
///
/// Serverseitig, nicht im Frontend: dass die Oberfläche den Bereich verbirgt,
/// ist Bequemlichkeit — verbindlich ist allein diese Funktion. Die Antwort ist
/// für jeden Nicht-Admin dieselbe, unabhängig davon, welches Konto er
/// anzusprechen versucht hat.
fn require_admin(current: &CurrentUser) -> Result<(), UserError> {
    if current.user.role.eq_ignore_ascii_case(ADMIN_ROLE) {
        return Ok(());
    }

    tracing::warn!(
        target: AUDIT_TARGET,
        event = "admin_route_refused",
        actor = %current.user.username,
        actor_id = %current.user.id,
        "Nicht-Admin hat eine Verwaltungsroute aufgerufen"
    );
    Err(UserError::forbidden(
        "Benutzerverwaltung ist Administratoren vorbehalten",
    ))
}

// ---------------------------------------------------------------------------
// Ein- und Ausgabetypen
// ---------------------------------------------------------------------------

/// Ein Konto, wie es nach draussen geht. Enthält den `password_hash`
/// **nicht** — nicht per `skip_serializing` am `User`, sondern weil dieser Typ
/// das Feld gar nicht hat. Ein zweiter Serde-Fehltritt kann ihn also nicht
/// wieder hereinholen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub role: String,
    pub home_path: String,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<&User> for UserView {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.clone(),
            role: user.role.clone(),
            home_path: user.home_path.clone(),
            is_active: user.is_active,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
        }
    }
}

/// Ein neues Konto.
///
/// `Debug` ist **von Hand** geschrieben. Ein abgeleitetes hätte `password` im
/// Klartext in die erste `tracing`-Zeile geschrieben, die diesen Wert
/// anfasst — dieselbe Fehlerklasse, die in diesem Projekt inzwischen sechsmal
/// aufgetreten ist (`LoginOutcome`, `ModuleConfig`, `RcloneConfig`,
/// `ConfigRequest`, `NewShare`, `SessionRefresh`). Der Name des Feldes ist
/// dabei nicht der Anker: bei `SessionRefresh` hiess es `set_cookie`. Anker ist
/// die Frage „trägt dieser Typ ein Geheimnis", und die Antwort hier ist ja.
/// `create_user_request_debug_is_redacted` hält es fest.
#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    /// Startpasswort. **Pflicht** — siehe `create_user`.
    pub password: String,
    /// `user` oder `admin`; fehlt es, wird `user` angelegt.
    pub role: Option<String>,
    /// Home-Verzeichnis; fehlt es, wird `<RCLONE_GUI_DEFAULT_PATH>/<name>`
    /// eingesetzt.
    pub home_path: Option<String>,
}

impl std::fmt::Debug for CreateUserRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateUserRequest")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("role", &self.role)
            .field("home_path", &self.home_path)
            .finish()
    }
}

/// Eine Änderung an einem bestehenden Konto. Nur die gesetzten Felder wirken.
///
/// `Debug` von Hand, aus demselben Grund wie bei [`CreateUserRequest`]:
/// `password` ist das Passwort, das ein Admin für ein fremdes Konto setzt.
#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub home_path: Option<String>,
    pub is_active: Option<bool>,
    /// Neues Passwort, vom Admin gesetzt. Für das **eigene** Konto abgelehnt —
    /// siehe `update_user`.
    pub password: Option<String>,
}

impl std::fmt::Debug for UpdateUserRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateUserRequest")
            .field("role", &self.role)
            .field("home_path", &self.home_path)
            .field("is_active", &self.is_active)
            .field(
                "password",
                &self
                    .password
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("None"),
            )
            .finish()
    }
}

/// Passwortwechsel durch den Nutzer selbst.
///
/// `Debug` von Hand: **beide** Felder sind Geheimnisse, und das alte ist das
/// schlimmere — es ist ein gültiges Passwort.
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

impl std::fmt::Debug for ChangePasswordRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordRequest")
            .field("current_password", &"<redacted>")
            .field("new_password", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Prüfungen der Eingaben
// ---------------------------------------------------------------------------

/// Benutzername als Positivliste.
///
/// Positivliste und nicht Sperrliste, aus demselben Grund wie bei den
/// Remote-Namen: der Name geht in Audit-Zeilen, in eine HTML-Seite und in
/// Vergleiche, und was hier nicht ausdrücklich erlaubt ist, kann dort nichts
/// anrichten. Erlaubt sind Buchstaben und Ziffern (ASCII), `.`, `_` und `-`;
/// beginnen muss er mit einem Buchstaben oder einer Ziffer, damit kein Name
/// wie `-rf` oder `.hidden` entsteht.
fn validate_username(username: &str) -> Result<String, UserError> {
    let name = username.trim();

    if name.is_empty() {
        return Err(UserError::bad_request("Benutzername darf nicht leer sein"));
    }
    if name.len() > MAX_USERNAME_LENGTH {
        return Err(UserError::bad_request(format!(
            "Benutzername darf höchstens {} Zeichen lang sein",
            MAX_USERNAME_LENGTH
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(UserError::bad_request(
            "Benutzername darf nur Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich enthalten",
        ));
    }
    if !name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(UserError::bad_request(
            "Benutzername muss mit einem Buchstaben oder einer Ziffer beginnen",
        ));
    }

    Ok(name.to_string())
}

/// Rolle einlesen und **normalisieren**.
///
/// Gespeichert wird immer klein. Der Wächter in der Datenbank vergleicht
/// zwar mit `LOWER(role)` und käme auch mit `Admin` zurecht — aber zwei
/// Schreibweisen derselben Rolle in einer Tabelle sind eine Falle für den
/// nächsten Leser, und ein unbekannter Wert wird hier abgelehnt statt still zu
/// `user` zu verfallen.
fn parse_role(role: &str) -> Result<String, UserError> {
    match role.trim().to_lowercase().as_str() {
        USER_ROLE => Ok(USER_ROLE.to_string()),
        ADMIN_ROLE => Ok(ADMIN_ROLE.to_string()),
        other => Err(UserError::bad_request(format!(
            "Unbekannte Rolle '{}' — erlaubt sind 'user' und 'admin'",
            other
        ))),
    }
}

/// Home-Pfad prüfen.
///
/// Kanonisiert wird hier **nicht**: das Verzeichnis muss beim Anlegen noch
/// nicht existieren, und `handlers::download::user_root` legt es beim ersten
/// Zugriff an und kanonisiert dort gegen die Jail-Prüfung. Was hier abgelehnt
/// wird, ist alles, was schon als Zeichenkette nicht taugt: leer, relativ,
/// `..` an irgendeiner Stelle, Steuerzeichen (die Logzeilen und
/// Konfigurationsdateien zerlegen), Überlänge.
fn validate_home_path(home_path: &str) -> Result<String, UserError> {
    let path = home_path.trim();

    if path.is_empty() {
        return Err(UserError::bad_request(
            "Home-Verzeichnis darf nicht leer sein",
        ));
    }
    if path.len() > MAX_HOME_PATH_LENGTH {
        return Err(UserError::bad_request(format!(
            "Home-Verzeichnis darf höchstens {} Zeichen lang sein",
            MAX_HOME_PATH_LENGTH
        )));
    }
    if let Some(c) = path.chars().find(|c| c.is_control()) {
        tracing::warn!(
            "Home-Verzeichnis abgelehnt: Steuerzeichen U+{:04X}",
            c as u32
        );
        return Err(UserError::bad_request(
            "Home-Verzeichnis darf keine Steuerzeichen enthalten",
        ));
    }
    if !std::path::Path::new(path).is_absolute() {
        return Err(UserError::bad_request(
            "Home-Verzeichnis muss ein absoluter Pfad sein",
        ));
    }
    if std::path::Path::new(path)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(UserError::bad_request(
            "Home-Verzeichnis darf kein '..' enthalten",
        ));
    }

    Ok(path.to_string())
}

/// Standard-Home eines neuen Kontos: `<RCLONE_GUI_DEFAULT_PATH>/<name>`.
///
/// Der Vorgabewert `/mnt/home` ist derselbe wie in `handlers::download`, wo er
/// in einer privaten Funktion steht — diese Datei gehört einem anderen Ticket,
/// deshalb hier noch einmal. Zusammenlegen, sobald eine der beiden Stellen frei
/// ist.
fn default_home_path(username: &str) -> String {
    let root = std::env::var("RCLONE_GUI_DEFAULT_PATH").unwrap_or_else(|_| "/mnt/home".to_string());
    format!("{}/{}", root.trim_end_matches('/'), username)
}

/// Was beim Löschen mit den Daten des Kontos geschieht. Wird **abgefragt**, es
/// gibt keinen Vorgabewert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteDataMode {
    /// Konto weg, die persönliche rclone-Konfiguration bleibt liegen — damit
    /// ein Nachfolger die dort eingetragenen Remotes übernehmen kann.
    Keep,
    /// Konto weg und die persönliche rclone-Konfiguration mit ihren
    /// Zugangsdaten wird entfernt.
    Delete,
}

/// `?data=keep|delete` einlesen.
///
/// **Pflichtparameter.** Das Ticket verlangt, dass der Umgang mit den Daten
/// ausdrücklich abgefragt wird; ein Vorgabewert wäre genau das nicht. Wer ihn
/// vergisst, bekommt 400 mit den erlaubten Werten.
///
/// `transfer` (Daten an einen anderen Nutzer übertragen) ist **nicht**
/// umgesetzt und wird ausdrücklich abgelehnt, statt still wie `keep` zu wirken.
/// Begründung: „übertragen" müsste die Freigaben des Kontos auf den Empfänger
/// umhängen, und deren `path` zeigt in das Home des alten Besitzers. Solange
/// die Datentrennung (`d8a12aa9`/`771319ce`) nicht durch ist, entstünden dabei
/// Freigaben, die aus dem Home des Empfängers herauszeigen — eine
/// Rechteausweitung als Nebenwirkung einer Aufräumaktion. Das gehört in das
/// Datentrennungs-Ticket, nicht hierher.
fn parse_delete_mode(raw: Option<&str>) -> Result<DeleteDataMode, UserError> {
    match raw.map(str::trim).unwrap_or("") {
        "keep" => Ok(DeleteDataMode::Keep),
        "delete" => Ok(DeleteDataMode::Delete),
        "" => Err(UserError::bad_request(
            "Beim Löschen muss der Umgang mit den Daten angegeben werden: ?data=keep oder ?data=delete",
        )),
        "transfer" => Err(UserError::bad_request(
            "Übertragen der Daten an einen anderen Nutzer ist noch nicht umgesetzt \
             (die Freigaben zeigen in das Home des alten Besitzers); \
             erlaubt sind 'keep' und 'delete'",
        )),
        other => Err(UserError::bad_request(format!(
            "Unbekannter Wert für 'data': {} — erlaubt sind 'keep' und 'delete'",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Argon2 abseits des Runtimes
// ---------------------------------------------------------------------------

/// Hashen läuft auf einem Blocking-Thread. Argon2id mit den Parametern aus
/// `handlers::auth` belegt 19 MiB und rechnet spürbar; inline würde es jeden
/// anderen Request auf demselben Worker anhalten.
async fn hash_password_off_thread(password: String) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(|e| anyhow::anyhow!("hashing task failed: {e}"))?
}

/// Prüfen ebenfalls, aus demselben Grund. Wie in `shares.rs`: kein
/// Passwortmaterial in der Fehlermeldung.
async fn verify_password_off_thread(password: String, stored_hash: String) -> bool {
    match tokio::task::spawn_blocking(move || auth::verify_password(&password, &stored_hash)).await
    {
        Ok(verified) => verified,
        Err(e) => {
            tracing::error!("Passwortprüfung fehlgeschlagen: {e}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /api/users` — alle Konten. Nur für Admins.
pub async fn list_users(
    Extension(pool): Extension<Pool<Sqlite>>,
    Extension(current): Extension<CurrentUser>,
) -> Result<Response, UserError> {
    require_admin(&current)?;

    let users = database::get_all_users(&pool)
        .await
        .map_err(|e| UserError::internal("Konten nicht lesbar", e))?;

    let view: Vec<UserView> = users.iter().map(UserView::from).collect();
    Ok(ResponseJson(ApiResponse::success(view)).into_response())
}

/// `GET /api/users/:id` — ein Konto. Nur für Admins.
pub async fn get_user(
    Extension(pool): Extension<Pool<Sqlite>>,
    Extension(current): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Response, UserError> {
    // Vor jedem Datenbankzugriff. Ein Nicht-Admin bekommt für ein vorhandenes
    // und ein nicht vorhandenes Konto dieselbe Antwort aus demselben Zweig.
    require_admin(&current)?;

    let user = database::get_user_by_id(&pool, &user_id)
        .await
        .map_err(|e| UserError::internal("Konto nicht lesbar", e))?
        .ok_or_else(UserError::not_found)?;

    Ok(ResponseJson(ApiResponse::success(UserView::from(&user))).into_response())
}

/// `POST /api/users` — Konto anlegen. Nur für Admins.
///
/// **Das Startpasswort ist Pflicht und wird nicht erzeugt.** Ein generiertes
/// Passwort müsste in der Antwort stehen, damit der Admin es weitergeben kann;
/// damit stünde ein gültiges Passwort in einem HTTP-Body, im
/// Netzwerk-Reiter jedes Browsers, in jedem Proxy-Log und in jedem
/// Fehlerbericht, der eine Antwort mitschickt. Es verlässt den Server hier
/// deshalb überhaupt nicht: der Admin gibt eines vor, und für ein vergessenes
/// gibt es `--reset-password`.
pub async fn create_user(
    Extension(pool): Extension<Pool<Sqlite>>,
    Extension(current): Extension<CurrentUser>,
    body: Bytes,
) -> Result<Response, UserError> {
    require_admin(&current)?;
    let request: CreateUserRequest = parse_body(&body)?;

    let username = validate_username(&request.username)?;
    let role = match request.role.as_deref() {
        Some(role) => parse_role(role)?,
        None => USER_ROLE.to_string(),
    };
    let home_path = match request.home_path.as_deref() {
        Some(path) => validate_home_path(path)?,
        None => validate_home_path(&default_home_path(&username))?,
    };

    // Dieselbe Richtlinie wie für jedes andere Passwort im System — kein
    // eigener, laxerer Weg für angelegte Konten.
    auth::validate_password(&request.password)
        .map_err(|policy| UserError::bad_request(policy.to_string()))?;

    if database::username_exists_ignoring_case(&pool, &username)
        .await
        .map_err(|e| UserError::internal("Namensprüfung fehlgeschlagen", e))?
    {
        return Err(UserError::conflict(
            "Ein Konto mit diesem Namen existiert bereits",
        ));
    }

    let password_hash = hash_password_off_thread(request.password.clone())
        .await
        .map_err(|e| UserError::internal("Passwort nicht hashbar", e))?;

    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.clone(),
        password_hash,
        role: role.clone(),
        home_path: home_path.clone(),
        is_active: true,
        created_at: chrono::Utc::now(),
        last_login_at: None,
    };

    // Das Config-Verzeichnis zuerst: schlägt es fehl, ist noch keine Zeile
    // geschrieben, und es bleibt kein Konto ohne Konfiguration zurück.
    // Umgekehrt (Zeile zuerst) müsste der Fehlerpfad die Zeile wieder
    // entfernen, während vielleicht schon jemand damit arbeitet.
    provision_user_config(&user.id).await?;

    if let Err(e) = database::create_user(&pool, &user).await {
        // Aufräumen, sonst liegt ein Verzeichnis unter einer Kennung, die es
        // nicht gibt.
        deprovision_user_config(&user.id).await;
        return Err(UserError::internal("Konto nicht anlegbar", e));
    }

    tracing::info!(
        target: AUDIT_TARGET,
        event = "user_created",
        actor = %current.user.username,
        actor_id = %current.user.id,
        target_user = %user.username,
        target_id = %user.id,
        role = %user.role,
        home_path = %user.home_path,
        "Konto angelegt"
    );

    Ok((
        StatusCode::CREATED,
        ResponseJson(ApiResponse::success(UserView::from(&user))),
    )
        .into_response())
}

/// `PATCH /api/users/:id` — Rolle, Home, Aktivierung, Passwort. Nur für Admins.
///
/// Die Schutzregeln stehen in zwei Schichten:
///
///   * **Selbstbezug** wird hier abgelehnt (Selbst-Degradierung,
///     Selbst-Deaktivierung, eigenes Passwort ohne das alte). Diese Prüfungen
///     brauchen keine Nebenläufigkeitssicherung: der Handelnde steht fest.
///   * **Letzter aktiver Admin** entscheidet `database::update_user_protected`
///     innerhalb einer Anweisung. Hier wird dafür *nichts* vorher gezählt.
pub async fn update_user(
    Extension(pool): Extension<Pool<Sqlite>>,
    Extension(current): Extension<CurrentUser>,
    Path(user_id): Path<String>,
    body: Bytes,
) -> Result<Response, UserError> {
    require_admin(&current)?;
    let request: UpdateUserRequest = parse_body(&body)?;

    let is_self = user_id == current.user.id;

    let role = match request.role.as_deref() {
        Some(role) => Some(parse_role(role)?),
        None => None,
    };
    let home_path = match request.home_path.as_deref() {
        Some(path) => Some(validate_home_path(path)?),
        None => None,
    };

    if role.is_none()
        && home_path.is_none()
        && request.is_active.is_none()
        && request.password.is_none()
    {
        return Err(UserError::bad_request(
            "Nichts zu ändern — erwartet wird mindestens eines von \
             'role', 'home_path', 'is_active', 'password'",
        ));
    }

    // --- Selbstbezogene Sperren ------------------------------------------
    //
    // Ein Admin, der sich selbst die Rechte nimmt oder sich abschaltet, sperrt
    // sich mit derselben Anfrage aus, mit der er sie stellt. Das ist auch dann
    // falsch, wenn noch andere Admins da sind: die Regel des Tickets ist nicht
    // „irgendwer bleibt Admin", sondern „ein Admin entzieht sich die Rechte
    // nicht selbst". Ein *anderer* Admin darf das jederzeit.
    if is_self {
        if role.as_deref() == Some(USER_ROLE) {
            return Err(UserError::forbidden(
                "Ein Administrator kann sich die Adminrechte nicht selbst entziehen — \
                 das muss ein anderer Administrator tun",
            ));
        }
        if request.is_active == Some(false) {
            return Err(UserError::forbidden(
                "Das eigene Konto kann nicht deaktiviert werden",
            ));
        }
        if request.password.is_some() {
            // Kein Verbot des Passwortwechsels, sondern ein Verweis auf den
            // Weg, der das alte Passwort abfragt. Sonst wäre eine gekaperte
            // Sitzung ein Passwortwechsel, und der rechtmässige Inhaber
            // ausgesperrt.
            return Err(UserError::forbidden(
                "Das eigene Passwort wird über POST /api/users/me/password geändert, \
                 dort mit Abfrage des alten Passworts",
            ));
        }
    }

    let mut changed: Vec<&str> = Vec::new();

    // --- Passwort ---------------------------------------------------------
    //
    // Vor dem geschützten Update, weil ein abgelehntes Passwort die Änderung
    // gar nicht erst anfangen soll. Bezieht sich nur auf ein fremdes Konto
    // (siehe oben).
    if let Some(new_password) = request.password.as_deref() {
        auth::validate_password(new_password)
            .map_err(|policy| UserError::bad_request(policy.to_string()))?;

        // Existiert das Konto überhaupt? Für einen Admin ist das keine
        // Preisgabe — er darf die Liste sowieso sehen.
        if database::get_user_by_id(&pool, &user_id)
            .await
            .map_err(|e| UserError::internal("Konto nicht lesbar", e))?
            .is_none()
        {
            return Err(UserError::not_found());
        }

        let hash = hash_password_off_thread(new_password.to_string())
            .await
            .map_err(|e| UserError::internal("Passwort nicht hashbar", e))?;

        if !database::update_user_password(&pool, &user_id, &hash)
            .await
            .map_err(|e| UserError::internal("Passwort nicht speicherbar", e))?
        {
            return Err(UserError::not_found());
        }

        // Ein zurückgesetztes Passwort muss jede bestehende Sitzung beenden,
        // sonst arbeitet derjenige weiter, dem man gerade den Zugang genommen
        // hat. Genauso macht es `auth::redeem_password_reset`.
        let dropped = auth::logout_all_sessions(&pool, &user_id)
            .await
            .map_err(|e| UserError::internal("Sitzungen nicht beendbar", e))?;

        tracing::info!(
            target: AUDIT_TARGET,
            event = "password_set_by_admin",
            actor = %current.user.username,
            actor_id = %current.user.id,
            target_id = %user_id,
            sessions_dropped = dropped,
            "Passwort durch Administrator gesetzt"
        );
        changed.push("password");
    }

    // --- Rolle, Home, Aktivierung ----------------------------------------
    let mut updated: Option<User> = None;
    if role.is_some() || home_path.is_some() || request.is_active.is_some() {
        let before = database::get_user_by_id(&pool, &user_id)
            .await
            .map_err(|e| UserError::internal("Konto nicht lesbar", e))?;

        let result = database::update_user_protected(
            &pool,
            &user_id,
            role.as_deref(),
            home_path.as_deref(),
            request.is_active,
        )
        .await
        .map_err(|e| UserError::internal("Änderung nicht speicherbar", e))?;

        let Some(after) = result else {
            // `None` heisst „abgelehnt **oder** nicht vorhanden". Welches von
            // beiden, entscheidet erst diese nachgelagerte Abfrage — die
            // Entscheidung selbst ist längst gefallen, hier geht es nur noch
            // um die Fehlermeldung. Andersherum (erst prüfen, dann ändern)
            // wäre das Rennen zurück.
            return Err(classify_rejection(&pool, &user_id).await);
        };

        if role.is_some() {
            let old_role = before.as_ref().map(|u| u.role.clone()).unwrap_or_default();
            tracing::info!(
                target: AUDIT_TARGET,
                event = "role_changed",
                actor = %current.user.username,
                actor_id = %current.user.id,
                target_user = %after.username,
                target_id = %after.id,
                old_role = %old_role,
                new_role = %after.role,
                "Rolle geändert"
            );
            changed.push("role");
        }
        if home_path.is_some() {
            tracing::info!(
                target: AUDIT_TARGET,
                event = "home_changed",
                actor = %current.user.username,
                actor_id = %current.user.id,
                target_user = %after.username,
                target_id = %after.id,
                home_path = %after.home_path,
                "Home-Verzeichnis geändert"
            );
            changed.push("home_path");
        }
        if let Some(is_active) = request.is_active {
            // Deaktivieren beendet **sofort** alle Sitzungen. Der
            // Sitzungswächter prüft `is_active` ohnehin bei jedem Request
            // (`auth::authenticate_session`), die Zeile allein genügte also
            // schon — aber dann bliebe der Sitzungsdatensatz stehen und wäre
            // beim Wiederaktivieren sofort wieder gültig. Das ist nicht, was
            // „Sitzungen beenden" heisst.
            let dropped = if is_active {
                0
            } else {
                auth::logout_all_sessions(&pool, &user_id)
                    .await
                    .map_err(|e| UserError::internal("Sitzungen nicht beendbar", e))?
            };
            tracing::info!(
                target: AUDIT_TARGET,
                event = if is_active { "user_enabled" } else { "user_disabled" },
                actor = %current.user.username,
                actor_id = %current.user.id,
                target_user = %after.username,
                target_id = %after.id,
                sessions_dropped = dropped,
                "Kontostatus geändert"
            );
            changed.push("is_active");
        }

        updated = Some(after);
    }

    let view = match updated {
        Some(user) => UserView::from(&user),
        // Nur das Passwort wurde gesetzt — der Zustand des Kontos ist
        // unverändert, wird aber für die Antwort noch einmal gelesen.
        None => {
            let user = database::get_user_by_id(&pool, &user_id)
                .await
                .map_err(|e| UserError::internal("Konto nicht lesbar", e))?
                .ok_or_else(UserError::not_found)?;
            UserView::from(&user)
        }
    };

    tracing::debug!("Konto {} geändert: {:?}", user_id, changed);
    Ok(ResponseJson(ApiResponse::success(view)).into_response())
}

/// `DELETE /api/users/:id?data=keep|delete` — Konto löschen. Nur für Admins.
///
/// **Selbstlöschung ist abgelehnt, auch wenn andere Admins da sind.**
/// Bewusste Entscheidung, und sie folgt aus der Regel des Tickets: wenn sich
/// ein Admin nicht einmal *degradieren* darf, kann er sich nicht löschen
/// dürfen — Löschen ist die stärkere Version derselben Handlung, nur ohne Weg
/// zurück. Ausserdem nimmt es dem Handelnden im gleichen Zug seine Sitzung,
/// sein Home und seine Freigaben, ohne dass ein zweites Konto zustimmen musste.
/// Wer wirklich weg will, lässt sich von einem anderen Administrator löschen —
/// und dass es einen gibt, ist gerade Sinn der Schutzregel.
pub async fn delete_user(
    Extension(pool): Extension<Pool<Sqlite>>,
    Extension(current): Extension<CurrentUser>,
    Path(user_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, UserError> {
    require_admin(&current)?;

    let mode = parse_delete_mode(params.get("data").map(|s| s.as_str()))?;

    if user_id == current.user.id {
        return Err(UserError::forbidden(
            "Das eigene Konto kann nicht gelöscht werden — \
             das muss ein anderer Administrator tun",
        ));
    }

    let Some(deleted) = database::delete_user_protected(&pool, &user_id)
        .await
        .map_err(|e| UserError::internal("Konto nicht löschbar", e))?
    else {
        return Err(classify_rejection(&pool, &user_id).await);
    };

    // Die Zeile ist weg; Sitzungen, Freigaben und offene Passwort-Resets sind
    // per `ON DELETE CASCADE` mitgegangen. `logout_all_sessions` würde hier
    // nichts mehr finden — der Aufruf steht deshalb nicht da, und das
    // Verschwinden der Sitzungen sichert
    // `database::deleting_user_cascades_to_sessions` ab.
    match mode {
        DeleteDataMode::Delete => deprovision_user_config(&deleted.id).await,
        DeleteDataMode::Keep => {}
    }

    tracing::info!(
        target: AUDIT_TARGET,
        event = "user_deleted",
        actor = %current.user.username,
        actor_id = %current.user.id,
        target_user = %deleted.username,
        target_id = %deleted.id,
        role = %deleted.role,
        data = ?mode,
        "Konto gelöscht"
    );

    Ok(ResponseJson(ApiResponse::success(UserView::from(&deleted))).into_response())
}

/// `POST /api/users/me/password` — eigenes Passwort ändern. Für **jedes**
/// angemeldete Konto, nicht nur für Admins.
///
/// Das alte Passwort wird abgefragt. Nicht als Formalie: ohne diese Abfrage
/// wäre jede gekaperte Sitzung ein dauerhafter Kontoübernahme-Knopf, und der
/// rechtmässige Inhaber ausgesperrt.
///
/// **Anschliessend ist der Aufrufer abgemeldet.** Alle Sitzungen des Kontos
/// werden beendet, die eigene eingeschlossen — genauso wie beim
/// Passwort-Reset (`auth::redeem_password_reset`). Die eigene stehen zu lassen
/// hiesse, ein neues Sitzungstoken auszustellen und in dieselbe Antwort zu
/// legen; das ist ein eigener Weg, und die Anmeldung mit dem neuen Passwort
/// ist der bereits geprüfte.
pub async fn change_own_password(
    Extension(pool): Extension<Pool<Sqlite>>,
    Extension(current): Extension<CurrentUser>,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Response, UserError> {
    // Das neue Passwort zuerst gegen die Richtlinie, bevor Argon2 überhaupt
    // anläuft.
    auth::validate_password(&request.new_password)
        .map_err(|policy| UserError::bad_request(policy.to_string()))?;

    // Gegen den Hash aus der Datenbank, nicht gegen den in `current`: der
    // stammt vom Beginn des Requests und wäre bei einem gleichzeitigen Reset
    // veraltet.
    let stored = database::get_user_by_id(&pool, &current.user.id)
        .await
        .map_err(|e| UserError::internal("Konto nicht lesbar", e))?
        .ok_or_else(UserError::not_found)?;

    if !verify_password_off_thread(
        request.current_password.clone(),
        stored.password_hash.clone(),
    )
    .await
    {
        tracing::warn!(
            target: AUDIT_TARGET,
            event = "password_change_refused",
            actor = %stored.username,
            actor_id = %stored.id,
            "Passwortwechsel mit falschem alten Passwort"
        );
        // Absichtlich unbestimmt und ohne Hinweis darauf, welches der beiden
        // Felder gestört hat.
        return Err(UserError::forbidden("Das alte Passwort ist nicht korrekt"));
    }

    let hash = hash_password_off_thread(request.new_password.clone())
        .await
        .map_err(|e| UserError::internal("Passwort nicht hashbar", e))?;

    if !database::update_user_password(&pool, &stored.id, &hash)
        .await
        .map_err(|e| UserError::internal("Passwort nicht speicherbar", e))?
    {
        return Err(UserError::not_found());
    }

    let dropped = auth::logout_all_sessions(&pool, &stored.id)
        .await
        .map_err(|e| UserError::internal("Sitzungen nicht beendbar", e))?;

    tracing::info!(
        target: AUDIT_TARGET,
        event = "password_changed",
        actor = %stored.username,
        actor_id = %stored.id,
        sessions_dropped = dropped,
        "Passwort durch den Nutzer selbst geändert"
    );

    Ok(ResponseJson(ApiResponse::success(
        "Passwort geändert — bitte neu anmelden".to_string(),
    ))
    .into_response())
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

/// Den JSON-Rumpf **nach** der Rollenprüfung einlesen.
///
/// Nicht über `Json<T>` als Argument: axum führt die Extraktoren in der
/// Reihenfolge der Argumente aus, ein Rumpf-Extraktor steht immer zuletzt und
/// scheitert damit *vor* dem Handler. Ein Nicht-Admin bekäme für einen
/// fehlerhaften Rumpf 422 und für einen gültigen 403 — zwei verschiedene
/// Antworten auf derselben verbotenen Route, aus denen sich ablesen lässt, wie
/// der Rumpf aussehen müsste. Mit `Bytes` (das nichts am Inhalt prüfen kann)
/// und einem Aufruf hierhin ist 403 die Antwort für jeden Rumpf.
///
/// Die Fehlermeldung nennt den Grund, aber nie den Rumpf: der kann ein
/// Passwort enthalten, und `serde_json` schreibt in seine Meldung nur Zeile
/// und Spalte — trotzdem wird sie nicht durchgereicht, weil eine spätere
/// Serde-Version das ändern könnte.
fn parse_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, UserError> {
    serde_json::from_slice(body).map_err(|e| {
        tracing::warn!(
            "Benutzerverwaltung: Rumpf nicht lesbar: {}",
            e.classify_for_log()
        );
        UserError::bad_request("Ungültiger JSON-Rumpf")
    })
}

/// Nur die *Art* des Serde-Fehlers ins Log, nicht seine Meldung. Siehe
/// [`parse_body`].
trait ClassifyForLog {
    fn classify_for_log(&self) -> &'static str;
}

impl ClassifyForLog for serde_json::Error {
    fn classify_for_log(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "E/A",
            serde_json::error::Category::Syntax => "Syntax",
            serde_json::error::Category::Data => "Feld fehlt oder falscher Typ",
            serde_json::error::Category::Eof => "Rumpf unvollständig",
        }
    }
}

/// Warum eine geschützte Änderung `None` geliefert hat.
///
/// Reine Formulierung einer Fehlermeldung, **keine** Entscheidung: die ist in
/// der einen Anweisung schon gefallen. Deshalb ist es unschädlich, hier
/// nachträglich zu lesen — im Gegensatz zu einer Prüfung *vor* der Änderung,
/// die genau das Rennen wäre, das `update_user_protected` schliesst.
async fn classify_rejection(pool: &Pool<Sqlite>, user_id: &str) -> UserError {
    match database::get_user_by_id(pool, user_id).await {
        Ok(Some(_)) => UserError::forbidden(
            "Das ist der letzte aktive Administrator — er kann nicht gelöscht, \
             deaktiviert oder herabgestuft werden",
        ),
        Ok(None) => UserError::not_found(),
        Err(e) => UserError::internal("Konto nicht lesbar", e),
    }
}

/// Persönliches rclone-Config-Verzeichnis eines neuen Kontos anlegen (0700,
/// darin eine leere `rclone.conf` mit 0600).
///
/// Ruft `config_manager::ensure_user_config` — die Funktion wartet seit dem
/// Datentrennungs-Ticket genau auf diesen Aufrufer. Bestehende Wege werden
/// dabei **nicht** umgestellt: das ist `d8a12aa9` und darf nicht vor `771319ce`
/// landen, sonst sind vorhandene Remotes aus Nutzersicht weg.
///
/// Blockierendes Dateisystem, deshalb `spawn_blocking`.
async fn provision_user_config(user_id: &str) -> Result<(), UserError> {
    let owned = user_id.to_string();
    match tokio::task::spawn_blocking(move || crate::config_manager::ensure_user_config(&owned))
        .await
    {
        Ok(Ok(path)) => {
            tracing::debug!("Konfiguration für {} angelegt: {}", user_id, path.display());
            Ok(())
        }
        Ok(Err(e)) => Err(UserError::internal("Konfiguration nicht anlegbar", e)),
        Err(e) => Err(UserError::internal("Konfigurationsaufgabe abgebrochen", e)),
    }
}

/// Persönliches Config-Verzeichnis entfernen. Es enthält Zugangsdaten, deshalb
/// bleibt es nicht liegen, wenn der Aufrufer das Löschen der Daten verlangt hat.
///
/// Kein `Result`: das ist ein Aufräumschritt. Schlägt er fehl, ist das Konto
/// dennoch gelöscht — die Meldung gehört ins Log, nicht in eine Fehlerantwort,
/// die eine schon erfolgte Löschung als Fehlschlag darstellt.
async fn deprovision_user_config(user_id: &str) {
    let owned = user_id.to_string();
    match tokio::task::spawn_blocking(move || crate::config_manager::remove_user_config(&owned))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(
            "Konfiguration von {} nicht entfernbar — sie enthält Zugangsdaten: {:#}",
            user_id,
            e
        ),
        Err(e) => tracing::error!("Aufräumaufgabe für {} abgebrochen: {e}", user_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Session;
    use axum::body::to_bytes;

    // -----------------------------------------------------------------------
    // Gerüst
    // -----------------------------------------------------------------------

    /// Wegwerf-Verzeichnis. Das Crate hat keine Dev-Abhängigkeit auf
    /// `tempfile`, und eine hinzuzufügen würde `Cargo.toml` anfassen — genau
    /// wie in `shares.rs` und `database.rs`.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rclone-gui-users-test-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn temp_pool() -> (Pool<Sqlite>, TempDir) {
        let dir = TempDir::new();
        let url = format!("sqlite:{}?mode=rwc", dir.path().join("test.db").display());
        let pool = database::connect(&url).await.expect("connect");
        database::run_migrations(&pool).await.expect("migrate");
        (pool, dir)
    }

    fn sample_user(id: &str, username: &str, role: &str) -> User {
        User {
            id: id.to_string(),
            username: username.to_string(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_string(),
            role: role.to_string(),
            home_path: format!("/data/home/{username}"),
            is_active: true,
            created_at: chrono::Utc::now(),
            last_login_at: None,
        }
    }

    fn current(user: &User) -> CurrentUser {
        CurrentUser {
            user: user.clone(),
            session: Session {
                id: "0".repeat(64),
                user_id: user.id.clone(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                user_agent: None,
                ip: None,
            },
        }
    }

    /// JSON-Rumpf für einen Handler, der ihn seit der Umstellung auf `Bytes`
    /// selbst einliest (siehe `parse_body`).
    fn body(value: serde_json::Value) -> Bytes {
        Bytes::from(serde_json::to_vec(&value).expect("serialise"))
    }

    async fn parts(response: Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn rendered(result: Result<Response, UserError>) -> (StatusCode, String) {
        match result {
            Ok(response) => parts(response).await,
            Err(e) => parts(e.into_response()).await,
        }
    }

    // -----------------------------------------------------------------------
    // Kein Geheimnis in `Debug`
    //
    // Sechsmal in diesem Projekt aufgetreten, jedes Mal mit einem anderen
    // Feldnamen. Deshalb je Typ ein Test, und geprüft wird nicht auf einen
    // Feldnamen, sondern darauf, dass der **Wert** nicht auftaucht.
    // -----------------------------------------------------------------------

    const SECRET: &str = "Sechs-Zeichen-Geheimnis-42";

    #[test]
    fn create_user_request_debug_is_redacted() {
        let request = CreateUserRequest {
            username: "alice".to_string(),
            password: SECRET.to_string(),
            role: Some("admin".to_string()),
            home_path: None,
        };
        let rendered = format!("{:?}", request);
        assert!(
            !rendered.contains(SECRET),
            "das Passwort steht in Debug: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Der brauchbare Teil bleibt sichtbar, sonst wäre der Wert zum
        // Debuggen nutzlos und jemand baut sich eine eigene Ausgabe.
        assert!(rendered.contains("alice"), "{rendered}");
    }

    #[test]
    fn update_user_request_debug_is_redacted() {
        let request = UpdateUserRequest {
            role: Some("user".to_string()),
            home_path: None,
            is_active: Some(false),
            password: Some(SECRET.to_string()),
        };
        let rendered = format!("{:?}", request);
        assert!(
            !rendered.contains(SECRET),
            "das Passwort steht in Debug: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("user"), "{rendered}");
    }

    /// Gegenprobe zum Test darüber: ohne Passwort im Feld darf `<redacted>`
    /// nicht erscheinen. Sonst könnte die Zusicherung „enthält `<redacted>`"
    /// auch von einer festen Zeichenkette erfüllt werden, die nie etwas
    /// verbirgt.
    #[test]
    fn update_user_request_debug_shows_absent_password_as_none() {
        let request = UpdateUserRequest {
            role: None,
            home_path: Some("/srv/home/bob".to_string()),
            is_active: None,
            password: None,
        };
        let rendered = format!("{:?}", request);
        assert!(!rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("None"), "{rendered}");
    }

    #[test]
    fn change_password_request_debug_is_redacted() {
        let request = ChangePasswordRequest {
            current_password: SECRET.to_string(),
            new_password: format!("neu-{SECRET}"),
        };
        let rendered = format!("{:?}", request);
        assert!(
            !rendered.contains(SECRET),
            "ein Passwort steht in Debug: {rendered}"
        );
        assert_eq!(rendered.matches("<redacted>").count(), 2, "{rendered}");
    }

    #[test]
    fn error_debug_carries_no_secret() {
        // Ein Fehler wird aus einer Meldung gebaut, die selbst für den Client
        // bestimmt ist. Der Test hält fest, dass der Typ kein weiteres Feld
        // bekommt, das ein Geheimnis tragen könnte.
        let e = UserError::bad_request("Benutzername darf nicht leer sein");
        let rendered = format!("{:?}", e);
        assert!(rendered.contains("400"), "{rendered}");
        assert!(rendered.contains("Benutzername"), "{rendered}");
    }

    #[test]
    fn user_view_has_no_hash_field() {
        let user = sample_user("u1", "alice", "user");
        let view = UserView::from(&user);
        let json = serde_json::to_string(&view).expect("serialise");
        assert!(!json.contains("argon2"), "{json}");
        assert!(!json.contains("password"), "{json}");
        assert!(!format!("{:?}", view).contains("argon2"));
    }

    // -----------------------------------------------------------------------
    // Eingabeprüfungen
    // -----------------------------------------------------------------------

    #[test]
    fn usernames_are_an_allowlist() {
        assert_eq!(validate_username("  alice  ").unwrap(), "alice");
        assert_eq!(validate_username("a.b_c-1").unwrap(), "a.b_c-1");

        for bad in [
            "", "   ", "-rf", ".hidden", "_x", "a b", "a/b", "a:b", "a\nb", "admin;--", "üser",
        ] {
            assert!(
                validate_username(bad).is_err(),
                "'{bad}' hätte abgelehnt werden müssen"
            );
        }
        assert!(validate_username(&"a".repeat(MAX_USERNAME_LENGTH)).is_ok());
        assert!(validate_username(&"a".repeat(MAX_USERNAME_LENGTH + 1)).is_err());
    }

    #[test]
    fn roles_are_normalised_and_unknown_ones_refused() {
        assert_eq!(parse_role("admin").unwrap(), "admin");
        assert_eq!(parse_role(" ADMIN ").unwrap(), "admin");
        assert_eq!(parse_role("User").unwrap(), "user");
        for bad in ["", "root", "administrator", "superuser", "admin,user"] {
            assert!(
                parse_role(bad).is_err(),
                "'{bad}' hätte nicht gelten dürfen"
            );
        }
    }

    #[test]
    fn home_paths_must_be_absolute_and_free_of_parent_segments() {
        assert_eq!(
            validate_home_path(" /srv/home/alice ").unwrap(),
            "/srv/home/alice"
        );
        for bad in [
            "",
            "   ",
            "home/alice",
            "./alice",
            "/srv/../etc",
            "/srv/home/../../etc",
            "/srv\0/x",
            "/srv/ho\nme",
        ] {
            assert!(
                validate_home_path(bad).is_err(),
                "'{}' hätte abgelehnt werden müssen",
                bad.escape_debug()
            );
        }
        assert!(validate_home_path(&format!("/{}", "a".repeat(MAX_HOME_PATH_LENGTH))).is_err());
    }

    #[test]
    fn the_data_handling_on_delete_has_no_default() {
        assert_eq!(
            parse_delete_mode(Some("keep")).unwrap(),
            DeleteDataMode::Keep
        );
        assert_eq!(
            parse_delete_mode(Some("delete")).unwrap(),
            DeleteDataMode::Delete
        );
        // Fehlend und leer sind ein Fehler, kein stiller Vorgabewert — das ist
        // das Akzeptanzkriterium „wird ausdrücklich abgefragt".
        assert!(parse_delete_mode(None).is_err());
        assert!(parse_delete_mode(Some("")).is_err());
        assert!(parse_delete_mode(Some("  ")).is_err());
        // Und ein nicht umgesetzter Wert wirkt nicht still wie `keep`.
        assert!(parse_delete_mode(Some("transfer")).is_err());
        assert!(parse_delete_mode(Some("purge")).is_err());
    }

    // -----------------------------------------------------------------------
    // Rollenprüfung
    // -----------------------------------------------------------------------

    #[test]
    fn require_admin_accepts_only_the_admin_role() {
        assert!(require_admin(&current(&sample_user("u1", "a", "admin"))).is_ok());
        // Gross-/Kleinschreibung: eine per Hand eingetragene Zeile `Admin`
        // soll nicht plötzlich ohne Rechte dastehen.
        assert!(require_admin(&current(&sample_user("u1", "a", "Admin"))).is_ok());
        assert!(require_admin(&current(&sample_user("u1", "a", "user"))).is_err());
        assert!(require_admin(&current(&sample_user("u1", "a", ""))).is_err());
        assert!(require_admin(&current(&sample_user("u1", "a", "adminx"))).is_err());
    }

    /// Der Kern der Ununterscheidbarkeit: für einen Nicht-Admin ist die
    /// Antwort auf ein **vorhandenes** und ein **nicht vorhandenes** Konto
    /// byte-gleich — auf jeder der drei Routen mit Pfadparameter.
    ///
    /// Byte-Gleichheit ist dabei nur die halbe Aussage; die zeitliche steht im
    /// Ticketkommentar. Sie ist hier deshalb strukturell gesichert und nicht
    /// nachträglich ausgeglichen: `require_admin` steht vor jedem
    /// Datenbankzugriff, es gibt für einen Nicht-Admin also gar keinen zweiten
    /// Zweig, der anders lange dauern könnte.
    #[tokio::test]
    async fn a_non_admin_cannot_tell_an_existing_account_from_a_missing_one() {
        let (pool, _dir) = temp_pool().await;
        let admin = sample_user("u-admin", "root", "admin");
        let plain = sample_user("u-plain", "mallory", "user");
        database::create_user(&pool, &admin).await.unwrap();
        database::create_user(&pool, &plain).await.unwrap();

        let existing = "u-admin";
        let missing = "u-does-not-exist";

        let get_existing = rendered(
            get_user(
                Extension(pool.clone()),
                Extension(current(&plain)),
                Path(existing.to_string()),
            )
            .await,
        )
        .await;
        let get_missing = rendered(
            get_user(
                Extension(pool.clone()),
                Extension(current(&plain)),
                Path(missing.to_string()),
            )
            .await,
        )
        .await;
        assert_eq!(get_existing, get_missing);
        assert_eq!(get_existing.0, StatusCode::FORBIDDEN);

        let patch = |id: &str| {
            let pool = pool.clone();
            let actor = current(&plain);
            let id = id.to_string();
            async move {
                rendered(
                    update_user(
                        Extension(pool),
                        Extension(actor),
                        Path(id),
                        body(serde_json::json!({"role": "admin"})),
                    )
                    .await,
                )
                .await
            }
        };
        assert_eq!(patch(existing).await, patch(missing).await);

        let del = |id: &str| {
            let pool = pool.clone();
            let actor = current(&plain);
            let id = id.to_string();
            async move {
                rendered(
                    delete_user(
                        Extension(pool),
                        Extension(actor),
                        Path(id),
                        Query(HashMap::from([("data".to_string(), "delete".to_string())])),
                    )
                    .await,
                )
                .await
            }
        };
        let (status, body) = del(existing).await;
        assert_eq!((status, body.clone()), del(missing).await);
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Und die Ablehnung nennt kein Konto — sonst wäre die Meldung selbst
        // das Orakel.
        assert!(!body.contains("root"), "{body}");
        assert!(!body.contains("u-admin"), "{body}");

        // Gegenprobe: derselbe Aufbau **erkennt** einen Unterschied. Für einen
        // Admin sind die beiden Antworten verschieden — ohne diesen Nachweis
        // wäre die Gleichheit oben auch dann erfüllt, wenn der Test in beiden
        // Fällen dasselbe Nichts vergleicht.
        let admin_existing = rendered(
            get_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Path(existing.to_string()),
            )
            .await,
        )
        .await;
        let admin_missing = rendered(
            get_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Path(missing.to_string()),
            )
            .await,
        )
        .await;
        assert_ne!(
            admin_existing, admin_missing,
            "der Vergleich kann einen Unterschied gar nicht sehen"
        );
        assert_eq!(admin_existing.0, StatusCode::OK);
        assert_eq!(admin_missing.0, StatusCode::NOT_FOUND);
    }

    /// `POST /api/users` und `GET /api/users` ohne Pfadparameter: auch dort
    /// 403, und ohne dass ein Konto entsteht.
    #[tokio::test]
    async fn a_non_admin_can_neither_list_nor_create() {
        let (pool, _dir) = temp_pool().await;
        let plain = sample_user("u-plain", "mallory", "user");
        database::create_user(&pool, &plain).await.unwrap();

        let (status, _) =
            rendered(list_users(Extension(pool.clone()), Extension(current(&plain))).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = rendered(
            create_user(
                Extension(pool.clone()),
                Extension(current(&plain)),
                body(serde_json::json!({
                    "username": "eve",
                    "password": "Ein-langes-Passwort-ohne-Muster-73",
                    "role": "admin",
                    "home_path": "/srv/home/eve"
                })),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            database::get_user_by_username(&pool, "eve")
                .await
                .unwrap()
                .is_none(),
            "die abgelehnte Anfrage hat trotzdem ein Konto angelegt"
        );
    }

    /// Der Rumpf darf die Antwort auf einer verbotenen Route nicht verändern.
    ///
    /// Real gemessen, bevor `parse_body` existierte: ein Nicht-Admin bekam auf
    /// `POST /api/users` mit `{}` **422** (axums `Json`-Extraktor lief vor dem
    /// Handler) und mit einem gültigen Rumpf **403**. Aus dem Unterschied liest
    /// man ab, welche Felder der Endpunkt erwartet — und ob man das Recht
    /// hätte, wenn der Rumpf nur stimmte.
    #[tokio::test]
    async fn a_non_admin_gets_the_same_403_for_every_body() {
        let (pool, _dir) = temp_pool().await;
        let plain = sample_user("u-plain", "mallory", "user");
        database::create_user(&pool, &plain).await.unwrap();

        let mut answers = Vec::new();
        for raw in [
            "{}",
            "nicht mal JSON",
            "",
            "[]",
            r#"{"username":"eve","password":"Ein-langes-Passwort-ohne-Muster-73"}"#,
            r#"{"username":"","password":""}"#,
        ] {
            answers.push(
                rendered(
                    create_user(
                        Extension(pool.clone()),
                        Extension(current(&plain)),
                        Bytes::from(raw),
                    )
                    .await,
                )
                .await,
            );
        }
        for answer in &answers {
            assert_eq!(
                answer, &answers[0],
                "der Rumpf verändert die Antwort auf einer verbotenen Route"
            );
            assert_eq!(answer.0, StatusCode::FORBIDDEN);
        }

        // Gegenprobe: für einen **Admin** unterscheiden sich dieselben Rümpfe
        // sehr wohl — der Vergleich oben vergleicht also nicht nur Nichts.
        let admin = sample_user("u-admin", "root", "admin");
        database::create_user(&pool, &admin).await.unwrap();
        let broken = rendered(
            create_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Bytes::from("nicht mal JSON"),
            )
            .await,
        )
        .await;
        // Ein leerer Name ist syntaktisch lesbar und scheitert erst an der
        // Prüfung — also eine andere Meldung. (Ein *gültiger* Rumpf wäre der
        // deutlichere Gegensatz, würde aber `ensure_user_config` auslösen und
        // damit unter `data/cfg/` des Projektverzeichnisses schreiben; siehe
        // den Kommentar am Abschnitt „Anlegen".)
        let empty_name = rendered(
            create_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Bytes::from(r#"{"username":"","password":"kurz"}"#),
            )
            .await,
        )
        .await;
        assert_eq!(broken.0, StatusCode::BAD_REQUEST);
        assert_eq!(empty_name.0, StatusCode::BAD_REQUEST);
        assert_ne!(
            broken, empty_name,
            "der Vergleich kann einen Unterschied gar nicht sehen"
        );
    }

    // -----------------------------------------------------------------------
    // Anlegen
    // -----------------------------------------------------------------------

    /// Anlegen läuft über `config_manager::ensure_user_config`, und das
    /// schreibt nach `data/cfg/users/<id>` **relativ zum Arbeitsverzeichnis**.
    /// In `cargo test` ist das das Projektverzeichnis; ein Test, der den
    /// Handler ganz durchlaufen lässt, würde also im echten `data/` Verzeichnisse
    /// anlegen. Deshalb prüfen die Tests hier den Weg **bis** zu diesem Schritt
    /// (Ablehnungen) sowie den Schritt danach; der vollständige Durchlauf steht
    /// als gemessener Server-Lauf im Ticketkommentar.
    #[tokio::test]
    async fn creating_refuses_a_weak_password_before_touching_anything() {
        let (pool, _dir) = temp_pool().await;
        let admin = sample_user("u-admin", "root", "admin");
        database::create_user(&pool, &admin).await.unwrap();

        let (status, body) = rendered(
            create_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                body(serde_json::json!({
                    "username": "bob",
                    "password": "password123",
                    "home_path": "/srv/home/bob"
                })),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Die Meldung erklärt das Problem, ohne das Passwort zu wiederholen.
        assert!(!body.contains("password123"), "{body}");
        assert!(database::get_user_by_username(&pool, "bob")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn creating_refuses_a_name_that_differs_only_in_case() {
        let (pool, _dir) = temp_pool().await;
        let admin = sample_user("u-admin", "root", "admin");
        database::create_user(&pool, &admin).await.unwrap();

        let (status, _) = rendered(
            create_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                body(serde_json::json!({
                    "username": "Root",
                    "password": "Ein-langes-Passwort-ohne-Muster-73",
                    "home_path": "/srv/home/root2"
                })),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[test]
    fn the_default_home_is_below_the_configured_root() {
        // `RCLONE_GUI_DEFAULT_PATH` wird hier nicht gesetzt: `std::env::set_var`
        // wirkt prozessweit und würde die parallel laufenden Tests stören.
        // Geprüft wird deshalb die Form, die aus dem eingebauten Vorgabewert
        // oder aus der bereits gesetzten Variable entsteht.
        let home = default_home_path("alice");
        assert!(home.ends_with("/alice"), "{home}");
        assert!(!home.contains("//"), "{home}");
        assert!(validate_home_path(&home).is_ok(), "{home}");
    }

    // -----------------------------------------------------------------------
    // Ändern
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_empty_patch_is_refused() {
        let (pool, _dir) = temp_pool().await;
        let admin = sample_user("u-admin", "root", "admin");
        let bob = sample_user("u-bob", "bob", "user");
        database::create_user(&pool, &admin).await.unwrap();
        database::create_user(&pool, &bob).await.unwrap();

        let (status, _) = rendered(
            update_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Path("u-bob".to_string()),
                body(serde_json::json!({})),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn disabling_an_account_ends_its_sessions_at_once() {
        let (pool, _dir) = temp_pool().await;
        let admin = sample_user("u-admin", "root", "admin");
        let bob = sample_user("u-bob", "bob", "user");
        database::create_user(&pool, &admin).await.unwrap();
        database::create_user(&pool, &bob).await.unwrap();

        for n in 0..3 {
            database::create_session(
                &pool,
                &Session {
                    id: format!("{n}{}", "a".repeat(63)),
                    user_id: "u-bob".to_string(),
                    created_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(5),
                    user_agent: None,
                    ip: None,
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(
            database::get_sessions_for_user(&pool, "u-bob")
                .await
                .unwrap()
                .len(),
            3
        );

        let (status, _) = rendered(
            update_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Path("u-bob".to_string()),
                body(serde_json::json!({"is_active": false})),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            database::get_sessions_for_user(&pool, "u-bob")
                .await
                .unwrap()
                .is_empty(),
            "Deaktivieren hat die Sitzungen stehen lassen"
        );
        assert!(
            !database::get_user_by_id(&pool, "u-bob")
                .await
                .unwrap()
                .unwrap()
                .is_active
        );
    }

    /// Ein vom Admin gesetztes Passwort beendet die Sitzungen des Betroffenen —
    /// sonst arbeitet weiter, wem man den Zugang gerade genommen hat.
    #[tokio::test]
    async fn an_admin_set_password_logs_the_account_out() {
        let (pool, _dir) = temp_pool().await;
        let admin = sample_user("u-admin", "root", "admin");
        let bob = sample_user("u-bob", "bob", "user");
        database::create_user(&pool, &admin).await.unwrap();
        database::create_user(&pool, &bob).await.unwrap();
        database::create_session(
            &pool,
            &Session {
                id: "b".repeat(64),
                user_id: "u-bob".to_string(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(5),
                user_agent: None,
                ip: None,
            },
        )
        .await
        .unwrap();

        let new_password = "Ein-langes-Passwort-ohne-Muster-73";
        let (status, body) = rendered(
            update_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Path("u-bob".to_string()),
                body(serde_json::json!({"password": new_password})),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Das Passwort geht nicht in der Antwort zurück.
        assert!(!body.contains(new_password), "{body}");
        assert!(!body.contains("argon2"), "{body}");

        assert!(database::get_sessions_for_user(&pool, "u-bob")
            .await
            .unwrap()
            .is_empty());
        let stored = database::get_user_by_id(&pool, "u-bob")
            .await
            .unwrap()
            .unwrap();
        assert!(auth::verify_password(new_password, &stored.password_hash));
    }

    #[tokio::test]
    async fn setting_a_password_for_a_missing_account_is_a_404() {
        let (pool, _dir) = temp_pool().await;
        let admin = sample_user("u-admin", "root", "admin");
        database::create_user(&pool, &admin).await.unwrap();

        let (status, _) = rendered(
            update_user(
                Extension(pool.clone()),
                Extension(current(&admin)),
                Path("u-ghost".to_string()),
                body(serde_json::json!({"password": "Ein-langes-Passwort-ohne-Muster-73"})),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // Eigenes Passwort
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn changing_the_own_password_needs_the_old_one() {
        let (pool, _dir) = temp_pool().await;
        let old = "Ein-langes-Altpasswort-ohne-Muster-19";
        let new = "Ein-langes-Neupasswort-ohne-Muster-46";

        let mut bob = sample_user("u-bob", "bob", "user");
        bob.password_hash = auth::hash_password(old).unwrap();
        database::create_user(&pool, &bob).await.unwrap();
        database::create_session(
            &pool,
            &Session {
                id: "b".repeat(64),
                user_id: "u-bob".to_string(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(5),
                user_agent: None,
                ip: None,
            },
        )
        .await
        .unwrap();

        // Falsches altes Passwort: abgelehnt, nichts geändert, Sitzung bleibt.
        let (status, body) = rendered(
            change_own_password(
                Extension(pool.clone()),
                Extension(current(&bob)),
                Json(ChangePasswordRequest {
                    current_password: "Ein-ganz-anderes-Passwort-91".to_string(),
                    new_password: new.to_string(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!body.contains(new), "{body}");
        let stored = database::get_user_by_id(&pool, "u-bob")
            .await
            .unwrap()
            .unwrap();
        assert!(auth::verify_password(old, &stored.password_hash));
        assert_eq!(
            database::get_sessions_for_user(&pool, "u-bob")
                .await
                .unwrap()
                .len(),
            1,
            "ein fehlgeschlagener Versuch darf nicht abmelden"
        );

        // Richtiges altes Passwort: geändert, und alle Sitzungen beendet.
        let (status, _) = rendered(
            change_own_password(
                Extension(pool.clone()),
                Extension(current(&bob)),
                Json(ChangePasswordRequest {
                    current_password: old.to_string(),
                    new_password: new.to_string(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let stored = database::get_user_by_id(&pool, "u-bob")
            .await
            .unwrap()
            .unwrap();
        assert!(auth::verify_password(new, &stored.password_hash));
        assert!(!auth::verify_password(old, &stored.password_hash));
        assert!(database::get_sessions_for_user(&pool, "u-bob")
            .await
            .unwrap()
            .is_empty());
    }

    /// Ein schwaches neues Passwort wird abgelehnt, **bevor** das alte geprüft
    /// wird — und daran ändert sich nichts, wenn das alte falsch ist. Sonst
    /// entstünde aus der Reihenfolge ein Orakel für das alte Passwort.
    #[tokio::test]
    async fn a_weak_new_password_is_refused_for_the_own_account_too() {
        let (pool, _dir) = temp_pool().await;
        let old = "Ein-langes-Altpasswort-ohne-Muster-19";
        let mut bob = sample_user("u-bob", "bob", "user");
        bob.password_hash = auth::hash_password(old).unwrap();
        database::create_user(&pool, &bob).await.unwrap();

        let with_right_old = rendered(
            change_own_password(
                Extension(pool.clone()),
                Extension(current(&bob)),
                Json(ChangePasswordRequest {
                    current_password: old.to_string(),
                    new_password: "kurz".to_string(),
                }),
            )
            .await,
        )
        .await;
        let with_wrong_old = rendered(
            change_own_password(
                Extension(pool.clone()),
                Extension(current(&bob)),
                Json(ChangePasswordRequest {
                    current_password: "Ein-ganz-anderes-Passwort-91".to_string(),
                    new_password: "kurz".to_string(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(with_right_old.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            with_right_old, with_wrong_old,
            "die Reihenfolge verrät, ob das alte Passwort stimmte"
        );
        // und das alte gilt weiter
        let stored = database::get_user_by_id(&pool, "u-bob")
            .await
            .unwrap()
            .unwrap();
        assert!(auth::verify_password(old, &stored.password_hash));
    }

    // -----------------------------------------------------------------------
    // Schutzregeln gegen Aussperren (Ticket 3d8e3a8c)
    //
    // Zwei Schichten, und beide sind hier geprüft:
    //   * selbstbezogene Sperren im Handler,
    //   * letzter aktiver Admin in `database::update_user_protected` /
    //     `delete_user_protected` (dort liegen auch die
    //     Nebenläufigkeitstests samt Gegenprobe).
    // -----------------------------------------------------------------------

    fn sample_admin(id: &str, username: &str) -> User {
        sample_user(id, username, "admin")
    }

    /// Alle drei selbstbezogenen Wege, und zwar **obwohl** ein zweiter
    /// Administrator existiert: die Regel ist nicht „irgendwer bleibt Admin",
    /// sondern „ein Admin entzieht sich die Rechte nicht selbst".
    #[tokio::test]
    async fn an_admin_cannot_demote_disable_or_delete_himself() {
        let (pool, _dir) = temp_pool().await;
        let root = sample_admin("u-root", "root");
        database::create_user(&pool, &root).await.unwrap();
        database::create_user(&pool, &sample_admin("u-carol", "carol"))
            .await
            .unwrap();
        assert_eq!(database::count_active_admins(&pool).await.unwrap(), 2);

        for patch in [
            serde_json::json!({"role": "user"}),
            serde_json::json!({"is_active": false}),
        ] {
            let (status, _) = rendered(
                update_user(
                    Extension(pool.clone()),
                    Extension(current(&root)),
                    Path("u-root".to_string()),
                    body(patch.clone()),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{patch}");
        }

        let (status, _) = rendered(
            delete_user(
                Extension(pool.clone()),
                Extension(current(&root)),
                Path("u-root".to_string()),
                Query(HashMap::from([("data".to_string(), "keep".to_string())])),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Unverändert und noch da.
        let after = database::get_user_by_id(&pool, "u-root")
            .await
            .unwrap()
            .expect("row");
        assert_eq!(after.role, "admin");
        assert!(after.is_active);
    }

    /// Gegenprobe zum Test darüber: **ein anderer** Administrator darf all das.
    /// Ohne diesen Nachweis könnte der Handler auch schlicht jede Änderung an
    /// einem Admin ablehnen.
    #[tokio::test]
    async fn another_admin_may_do_what_the_account_itself_may_not() {
        let (pool, _dir) = temp_pool().await;
        let carol = sample_admin("u-carol", "carol");
        database::create_user(&pool, &sample_admin("u-root", "root"))
            .await
            .unwrap();
        database::create_user(&pool, &carol).await.unwrap();

        let (status, _) = rendered(
            update_user(
                Extension(pool.clone()),
                Extension(current(&carol)),
                Path("u-root".to_string()),
                body(serde_json::json!({"role": "user"})),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            database::get_user_by_id(&pool, "u-root")
                .await
                .unwrap()
                .unwrap()
                .role,
            "user"
        );

        let (status, _) = rendered(
            delete_user(
                Extension(pool.clone()),
                Extension(current(&carol)),
                Path("u-root".to_string()),
                Query(HashMap::from([("data".to_string(), "keep".to_string())])),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(database::count_active_admins(&pool).await.unwrap(), 1);
    }

    /// Der letzte aktive Administrator: über die API auf allen drei Wegen 403,
    /// und die Meldung erklärt warum.
    #[tokio::test]
    async fn the_last_admin_is_refused_on_all_three_ways_through_the_api() {
        let (pool, _dir) = temp_pool().await;
        // Zwei Admins, damit der Handelnde *nicht* das Ziel ist — sonst würde
        // die selbstbezogene Sperre zuschlagen und dieser Test bewiese die
        // andere Schicht nicht. `carol` wird gleich deaktiviert, damit `root`
        // der letzte **aktive** ist.
        let carol = sample_admin("u-carol", "carol");
        database::create_user(&pool, &sample_admin("u-root", "root"))
            .await
            .unwrap();
        database::create_user(&pool, &carol).await.unwrap();

        let (status, _) = rendered(
            update_user(
                Extension(pool.clone()),
                Extension(current(&carol)),
                Path("u-root".to_string()),
                body(serde_json::json!({"is_active": false})),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Jetzt ist `carol` der letzte aktive Admin und `root` schläft.
        assert_eq!(database::count_active_admins(&pool).await.unwrap(), 1);

        // `root` (deaktiviert, aber als Handelnder konstruiert) versucht,
        // `carol` zu entfernen. Das ist der Fall, den die Datenbank ablehnen
        // muss: `carol` ist der letzte aktive Administrator.
        let sleeping_root = database::get_user_by_id(&pool, "u-root")
            .await
            .unwrap()
            .unwrap();

        for patch in [
            serde_json::json!({"role": "user"}),
            serde_json::json!({"is_active": false}),
        ] {
            let (status, message) = rendered(
                update_user(
                    Extension(pool.clone()),
                    Extension(current(&sleeping_root)),
                    Path("u-carol".to_string()),
                    body(patch.clone()),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{patch}");
            assert!(
                message.contains("letzte aktive Administrator"),
                "die Meldung erklärt den Grund nicht: {message}"
            );
        }

        let (status, message) = rendered(
            delete_user(
                Extension(pool.clone()),
                Extension(current(&sleeping_root)),
                Path("u-carol".to_string()),
                Query(HashMap::from([(
                    "data".to_string(),
                    "delete".to_string(),
                )])),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(message.contains("letzte aktive Administrator"), "{message}");

        assert_eq!(database::count_active_admins(&pool).await.unwrap(), 1);
    }

    /// „Abgelehnt" und „gibt es nicht" sind für einen Admin verschiedene
    /// Antworten — 403 gegen 404. Für einen Nicht-Admin sind sie es nicht
    /// (siehe `a_non_admin_cannot_tell_an_existing_account_from_a_missing_one`);
    /// gegenüber einem Admin ist die Unterscheidung keine Preisgabe, er darf
    /// die Liste sowieso sehen, und ohne sie sucht er den Fehler in der
    /// falschen Ecke.
    #[tokio::test]
    async fn a_rejection_and_a_missing_account_are_told_apart_for_an_admin() {
        let (pool, _dir) = temp_pool().await;
        let root = sample_admin("u-root", "root");
        database::create_user(&pool, &root).await.unwrap();

        let (protected, _) = rendered(
            delete_user(
                Extension(pool.clone()),
                Extension(current(&sample_admin("u-other", "other"))),
                Path("u-root".to_string()),
                Query(HashMap::from([("data".to_string(), "keep".to_string())])),
            )
            .await,
        )
        .await;
        let (missing, _) = rendered(
            delete_user(
                Extension(pool.clone()),
                Extension(current(&root)),
                Path("u-ghost".to_string()),
                Query(HashMap::from([("data".to_string(), "keep".to_string())])),
            )
            .await,
        )
        .await;
        assert_eq!(protected, StatusCode::FORBIDDEN);
        assert_eq!(missing, StatusCode::NOT_FOUND);
    }

    /// Der Umgang mit den Daten wird abgefragt, **bevor** irgendetwas
    /// geschieht: ohne `?data=` bleibt das Konto stehen.
    #[tokio::test]
    async fn deleting_without_saying_what_happens_to_the_data_changes_nothing() {
        let (pool, _dir) = temp_pool().await;
        let root = sample_admin("u-root", "root");
        database::create_user(&pool, &root).await.unwrap();
        database::create_user(&pool, &sample_user("u-bob", "bob", "user"))
            .await
            .unwrap();

        for query in [
            HashMap::new(),
            HashMap::from([("data".to_string(), "".to_string())]),
            HashMap::from([("data".to_string(), "transfer".to_string())]),
            HashMap::from([("data".to_string(), "yes".to_string())]),
        ] {
            let (status, _) = rendered(
                delete_user(
                    Extension(pool.clone()),
                    Extension(current(&root)),
                    Path("u-bob".to_string()),
                    Query(query.clone()),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query:?}");
            assert!(
                database::get_user_by_id(&pool, "u-bob")
                    .await
                    .unwrap()
                    .is_some(),
                "das Konto wurde trotz abgelehnter Angabe gelöscht: {query:?}"
            );
        }

        // Gegenprobe: mit einer gültigen Angabe geht es durch.
        let (status, _) = rendered(
            delete_user(
                Extension(pool.clone()),
                Extension(current(&root)),
                Path("u-bob".to_string()),
                Query(HashMap::from([("data".to_string(), "keep".to_string())])),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(database::get_user_by_id(&pool, "u-bob")
            .await
            .unwrap()
            .is_none());
    }

    /// Rollenwechsel und Löschungen landen im Audit-Log.
    ///
    /// Geprüft wird die tatsächliche `tracing`-Ausgabe unter dem `target`
    /// `user_audit`, nicht der Quelltext: eine Zeile, die niemand einsammelt,
    /// ist kein Audit-Log. Und ausdrücklich mitgeprüft, dass die alte **und**
    /// die neue Rolle darinstehen — „Rolle geändert" ohne Vorher ist als
    /// Nachweis wertlos.
    #[tokio::test]
    async fn role_changes_and_deletions_reach_the_audit_log() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        /// Sammelt die Ausgabe des Abonnenten in einem Puffer.
        #[derive(Clone)]
        struct Collector(Arc<Mutex<Vec<u8>>>);

        impl Write for Collector {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Collector {
            type Writer = Collector;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Collector(buffer.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();

        let (pool, _dir) = temp_pool().await;
        let root = sample_admin("u-root", "root");
        database::create_user(&pool, &root).await.unwrap();
        database::create_user(&pool, &sample_admin("u-carol", "carol"))
            .await
            .unwrap();
        database::create_user(&pool, &sample_user("u-bob", "bob", "user"))
            .await
            .unwrap();

        // `with_default` gilt nur für diesen Bereich, damit der Test die
        // globale Ausgabe der anderen Tests nicht an sich zieht.
        let _guard = tracing::subscriber::set_default(subscriber);

        rendered(
            update_user(
                Extension(pool.clone()),
                Extension(current(&root)),
                Path("u-bob".to_string()),
                body(serde_json::json!({"role": "admin"})),
            )
            .await,
        )
        .await;
        rendered(
            delete_user(
                Extension(pool.clone()),
                Extension(current(&root)),
                Path("u-carol".to_string()),
                Query(HashMap::from([(
                    "data".to_string(),
                    "delete".to_string(),
                )])),
            )
            .await,
        )
        .await;
        drop(_guard);

        let log = String::from_utf8_lossy(&buffer.lock().expect("lock")).to_string();

        // Rollenwechsel: Ereignis, Handelnder, Ziel, alte und neue Rolle.
        assert!(log.contains("role_changed"), "{log}");
        assert!(log.contains("old_role=\"user\"") || log.contains("old_role=user"), "{log}");
        assert!(log.contains("new_role=\"admin\"") || log.contains("new_role=admin"), "{log}");
        // Löschung: Ereignis, Ziel, gewählter Datenumgang.
        assert!(log.contains("user_deleted"), "{log}");
        assert!(log.contains("carol"), "{log}");
        assert!(log.contains("Delete"), "der Datenumgang fehlt: {log}");
        // Der Handelnde steht in beiden Zeilen.
        assert_eq!(log.matches("actor=root").count(), 2, "{log}");

        // Und nichts Geheimes: der gespeicherte Hash taucht nicht auf.
        assert!(!log.contains("argon2"), "{log}");
    }

    /// Ein normaler Nutzer darf sein Passwort ändern — die Route ist die
    /// **einzige** in diesem Modul ohne Rollenprüfung, und das ist Absicht.
    #[tokio::test]
    async fn the_own_password_route_is_open_to_every_role() {
        let (pool, _dir) = temp_pool().await;
        let old = "Ein-langes-Altpasswort-ohne-Muster-19";
        let mut plain = sample_user("u-plain", "mallory", "user");
        plain.password_hash = auth::hash_password(old).unwrap();
        database::create_user(&pool, &plain).await.unwrap();

        let (status, _) = rendered(
            change_own_password(
                Extension(pool.clone()),
                Extension(current(&plain)),
                Json(ChangePasswordRequest {
                    current_password: old.to_string(),
                    new_password: "Ein-langes-Neupasswort-ohne-Muster-46".to_string(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}
