use axum::{
    extract::{Path, Request},
    http::{header, HeaderValue, Method},
    middleware::{self, Next},
    response::Html,
    routing::{delete, get, patch, post},
    Extension, Router,
};
use chrono;
use clap::Parser;
use dotenvy::{dotenv, from_filename_override};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod config_manager;
mod database;
mod handlers;
mod models;

#[derive(Parser)]
#[command(name = "rclone-gui")]
#[command(about = "A web GUI for rclone")]
struct Args {
    #[arg(
        long,
        help = "Use in-memory configuration (changes not saved to file until explicitly saved)"
    )]
    memory_mode: bool,
    /// Address the server listens on.
    ///
    /// Deliberately an `Option` without a clap `default_value`: only that way
    /// can "the user passed `--bind`" be told apart from "nobody said
    /// anything", and the precedence
    /// `--bind` > `RCLONE_GUI_BIND` > [`BIND_DEFAULT`] needs exactly that
    /// distinction. clap's own `env =` would do the same, but that lives behind
    /// the `env` feature which this crate does not enable — and `Cargo.toml`
    /// belongs to another ticket. Resolved by [`resolve_bind_address`]; the
    /// default is named in the help text so `--help` stays truthful.
    #[arg(
        long,
        help = "Address to bind the server to (default: 127.0.0.1:8080, env: RCLONE_GUI_BIND)"
    )]
    bind: Option<String>,
    #[arg(long, help = "Start a task by name and exit")]
    start_task: Option<String>,
    #[arg(
        long,
        help = "User name the CLI run is attributed to (required with --start-task when more than one account exists)"
    )]
    user: Option<String>,
    /// Issue a one-shot password reset token for an account and exit.
    ///
    /// Takes the *user name*, never a secret: `argv` is readable by every
    /// process on the machine, so nothing confidential may be passed this way.
    /// The token is printed on stdout, once.
    #[arg(
        long,
        value_name = "USERNAME",
        help = "Print a one-time password reset token for the given account and exit"
    )]
    reset_password: Option<String>,
}

/// Environment variable holding the listen address, e.g. `0.0.0.0:9000`.
const BIND_ENV: &str = "RCLONE_GUI_BIND";

/// Listen address when neither `--bind` nor [`BIND_ENV`] says anything.
///
/// Loopback on purpose: an unconfigured start must not expose the interface to
/// the network. The container overrides it via `CMD --bind 0.0.0.0:8080`.
const BIND_DEFAULT: &str = "127.0.0.1:8080";

/// Resolve the listen address and say where it came from.
///
/// Precedence is `--bind` > [`BIND_ENV`] > [`BIND_DEFAULT`]. **The command
/// line argument wins**, and that is not a detail: every agent working on this
/// project binds its test server to its own loopback address via `--bind`,
/// because session cookies are not separated by port. An environment variable
/// that could override `--bind` — from a `.env` in the working directory, no
/// less — would silently drag those servers onto one address and make parallel
/// runs overwrite each other's sessions.
///
/// An empty or whitespace-only variable counts as unset. `RCLONE_GUI_BIND=`
/// in a `.env` is how one comments a setting out; treating it as an address
/// would only produce a parse error further down.
///
/// The returned second element is the source, for the startup line. Before
/// this existed, the variable was *printed* but never read, so the startup
/// output confirmed a bind address the server did not use.
fn resolve_bind_address(arg: Option<&str>) -> (String, &'static str) {
    if let Some(addr) = arg {
        return (addr.to_string(), "from --bind");
    }

    match env::var(BIND_ENV) {
        Ok(addr) if !addr.trim().is_empty() => (addr.trim().to_string(), "from RCLONE_GUI_BIND"),
        _ => (BIND_DEFAULT.to_string(), "default"),
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables with detailed feedback
    load_environment_config();

    // Clean up any leftover log files from previous runs
    cleanup_orphaned_log_files().await;

    // Initialize enhanced tracing
    setup_tracing();
    let args = Args::parse();

    // Muss nach `load_environment_config()` stehen: `.env`/`.env.local` sind
    // erst dort in der Prozessumgebung, und `RCLONE_GUI_BIND` darf von dort
    // kommen wie jede andere Variable der Anwendung.
    let (bind, bind_source) = resolve_bind_address(args.bind.as_deref());

    println!("⚙️  Command line arguments:");
    println!("   Memory mode: {}", args.memory_mode);
    println!("   Bind address: {} ({})", bind, bind_source);
    if let Some(ref task_name) = args.start_task {
        println!("   Start task: {}", task_name);
    }
    println!("");

    // Initialize database
    let db_pool = match database::init_database().await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("❌ Failed to initialize database: {}", e);
            std::process::exit(1);
        }
    };

    // Handle CLI task execution.
    //
    // This branch returns before the router is built, so the session guard is
    // not involved at all: the CLI calls `handlers::sync` directly and never
    // speaks HTTP to itself. What it does need is the *user* the run belongs
    // to, which is resolved from the database — see `resolve_cli_user`.
    if let Some(task_name) = args.start_task {
        return handle_cli_task_execution(db_pool, task_name, args.user).await;
    }

    // Password reset from the terminal.
    //
    // Also before the router is built, and for the same reason as above: the
    // person running this is locked out of the web interface, which is the
    // whole point. What comes back is printed and then dropped — the token
    // exists in this process's memory and nowhere else in plaintext.
    if let Some(username) = args.reset_password {
        return handle_cli_password_reset(db_pool, &username, &bind).await;
    }

    // Jobs, die einen Neustart nicht überlebt haben, in einen Endzustand
    // bringen — sonst blieben sie unlöschbar und für den Cleanup unsichtbar.
    handlers::sync::recover_stranded_jobs().await;

    let config_manager = Arc::new(config_manager::ConfigManager::new(args.memory_mode));

    // Authentication. The session configuration is read once here so that a
    // malformed environment variable is reported at startup and not on the
    // first login.
    let session_config = handlers::auth::SessionConfig::from_env();
    println!("🔐 Authentication:");
    println!(
        "   🍪 Cookie: {} (Secure: {}, TTL: {} h)",
        session_config.cookie_name, session_config.secure, session_config.ttl_hours
    );
    if let Err(e) = ensure_bootstrap_user(&db_pool).await {
        eprintln!("❌ Could not prepare the initial account: {}", e);
        std::process::exit(1);
    }
    println!();

    let auth_state = handlers::auth_web::AuthState::new(db_pool.clone(), session_config);

    // Expired sessions have to disappear even when nobody logs in, so this runs
    // on a timer rather than on a request.
    handlers::auth::spawn_session_cleanup(db_pool.clone());

    // Peer-to-peer rsync transport: the daemon runs as a child of this process
    // for as long as the server does. Off unless switched on, see below.
    let rsyncd = start_rsync_daemon().await;

    if args.memory_mode {
        println!("💾 Running in memory mode:");
        println!("   ⚠️  Configurations will not be saved to file automatically");
        println!("   📥 Loading existing configs from file into memory...");

        // Load existing configs from file into memory
        if let Err(e) = config_manager.load_from_file_to_memory().await {
            eprintln!(
                "   ❌ Warning: Could not load existing configs from file: {}",
                e
            );
        } else {
            println!("   ✅ Existing configs loaded successfully");
        }
        println!("");
    } else {
        println!("💾 Running in persistent mode:");
        println!("   ✅ Configurations will be saved to file automatically");
        println!("");
    }

    // Fail loudly at startup, not only per request, if the index lost its marker.
    check_index_marker();

    // Log all registered routes
    println!("📋 Registering API routes:");
    println!("   GET    /                              -> serve_index");
    println!("   GET    /api/configs                   -> get_configs");
    println!("   POST   /api/configs                   -> save_config");
    println!("   DELETE /api/configs/:name             -> delete_config");
    println!("   GET    /api/configs/:name/edit        -> get_config_for_edit");
    println!("   POST   /api/configs/persist           -> persist_configs");
    println!("   GET    /api/files/local               -> list_local_files");
    println!("   GET    /api/files/remote              -> list_remote_files");
    println!("   POST   /api/files/remote/mkdir        -> create_remote_directory");
    println!("   GET    /api/download/file             -> download_file");
    println!("   GET    /api/download/zip              -> download_zip");
    println!("   GET    /api/thumb                     -> get_thumbnail");
    println!("   GET    /api/preview/info              -> preview_info");
    println!("   GET    /api/preview/text              -> preview_text");
    println!("   GET    /api/preview/image             -> preview_image");
    println!("   GET    /api/preview/video             -> preview_video");
    println!("   POST   /api/sync                      -> start_sync");
    println!("   GET    /api/sync                      -> list_sync_jobs");
    println!("   GET    /api/sync-log/:job_id          -> get_sync_log_for (temp route)");
    println!("   DELETE /api/sync-delete/:job_id       -> delete_sync_job (temp route)");
    println!("   GET    /api/sync/:job_id/log          -> get_sync_log_for");
    println!("   GET    /api/sync/:job_id              -> get_sync_progress");
    println!("   DELETE /api/sync/:job_id              -> delete_sync_job");
    println!("   GET    /api/tasks                     -> get_tasks");
    println!("   POST   /api/tasks                     -> create_task");
    println!("   DELETE /api/tasks/:task_id            -> delete_task");
    println!("   POST   /api/tasks/start               -> start_task");
    println!("   GET    /api/rsyncd/status             -> rsyncd_status");
    println!("   GET    /api/users                     -> list_users            [admin]");
    println!("   POST   /api/users                     -> create_user           [admin]");
    println!("   GET    /api/users/:id                 -> get_user              [admin]");
    println!("   PATCH  /api/users/:id                 -> update_user           [admin]");
    println!("   DELETE /api/users/:id?data=keep|delete -> delete_user          [admin]");
    println!("   POST   /api/users/me/password          -> change_own_password");
    println!("   GET    /login                         -> login_page            [public]");
    println!("   POST   /login                         -> login_form_submit     [public]");
    println!("   POST   /api/auth/login                -> login_json_submit     [public]");
    println!("   GET    /reset                         -> reset_page             [public]");
    println!("   POST   /reset                         -> reset_submit           [public]");
    println!("   GET    /logout                        -> logout_page");
    println!("   POST   /logout                        -> logout_page");
    println!("   POST   /api/auth/logout               -> logout_json");
    println!("   GET    /api/auth/me                   -> me");
    println!("   STATIC /static/*                      -> serve static files    [public]");
    println!("");

    // Login and logout. Merged into the same router as everything else so the
    // guard below wraps them too — `require_session` lets the two public ones
    // through by path, the logout routes stay protected.
    let auth_routes = Router::new()
        .route(
            handlers::auth_web::LOGIN_PATH,
            get(handlers::auth_web::login_page).post(handlers::auth_web::login_form_submit),
        )
        .route(
            "/logout",
            get(handlers::auth_web::logout_page).post(handlers::auth_web::logout_page),
        )
        .route(
            "/api/auth/login",
            post(handlers::auth_web::login_json_submit),
        )
        .route("/api/auth/logout", post(handlers::auth_web::logout_json))
        .route(
            handlers::auth_web::RESET_PATH,
            get(handlers::auth_web::reset_page).post(handlers::auth_web::reset_submit),
        )
        .route("/api/auth/me", get(handlers::auth_web::me))
        .with_state(auth_state.clone());

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/configs", get(handlers::config::get_configs))
        .route("/api/configs", post(handlers::config::save_config))
        .route("/api/configs/:name", delete(delete_config_handler))
        .route("/api/configs/:name/edit", get(get_config_for_edit_handler))
        .route(
            "/api/configs/persist",
            post(handlers::config::persist_configs),
        )
        .route("/api/files/local", get(handlers::files::list_local_files))
        .route("/api/files/remote", get(handlers::files::list_remote_files))
        .route(
            "/api/files/remote/mkdir",
            post(handlers::files::create_remote_directory),
        )
        .route("/api/download/file", get(handlers::download::download_file))
        .route("/api/download/zip", get(handlers::download::download_zip))
        .route("/api/thumb", get(handlers::thumbs::get_thumbnail))
        .route("/api/preview/info", get(handlers::preview::preview_info))
        .route("/api/preview/text", get(handlers::preview::preview_text))
        .route("/api/preview/image", get(handlers::preview::preview_image))
        .route("/api/preview/video", get(handlers::preview::preview_video))
        .route("/api/sync", post(handlers::sync::start_sync))
        .route("/api/sync", get(list_jobs_handler))
        // „Von URL holen": der Server holt eine vom Nutzer angegebene URL ab.
        // Der Abruf läuft als Job und erscheint deshalb in derselben Liste
        // wie ein Sync (siehe `list_jobs_handler`).
        .route(
            "/api/download-url",
            post(handlers::downloader::start_url_fetch),
        )
        .route(
            "/api/download-url/:job_id/cancel",
            post(cancel_url_fetch_handler),
        )
        .route("/api/sync-log/:job_id", get(get_sync_log_handler))
        .route("/api/sync-delete/:job_id", delete(delete_sync_job_handler))
        .route("/api/sync/:job_id/log", get(get_sync_log_handler))
        .route("/api/sync/:job_id", get(get_sync_progress_handler))
        .route("/api/sync/:job_id", delete(delete_sync_job_handler))
        .route("/api/tasks", get(handlers::tasks::get_tasks))
        .route("/api/tasks", post(handlers::tasks::create_task))
        .route("/api/tasks/:task_id", delete(handlers::tasks::delete_task))
        .route("/api/tasks/start", post(handlers::tasks::start_task))
        .route("/api/rsyncd/status", get(rsyncd_status_handler))
        // Benutzerverwaltung. Die Rollenprüfung steht **im Handler**
        // (`handlers::users::require_admin`) und nicht hier: eine Route sieht
        // man beim Lesen des Routers, eine fehlende Prüfung im Handler nicht —
        // und die Prüfung muss vor dem ersten Datenbankzugriff liegen, damit
        // ein Nicht-Admin einem vorhandenen Konto nichts ansehen kann. Der
        // Sitzungswächter weiter unten deckt diese Routen ohnehin mit ab.
        .route("/api/users", get(handlers::users::list_users))
        .route("/api/users", post(handlers::users::create_user))
        // Vor `/api/users/:id`, obwohl axum die vier Segmente ohnehin
        // unterscheidet — die Reihenfolge macht beim Lesen klar, dass `me`
        // kein Konto-Bezeichner ist.
        .route(
            "/api/users/me/password",
            post(handlers::users::change_own_password),
        )
        .route("/api/users/:id", get(handlers::users::get_user))
        .route("/api/users/:id", patch(handlers::users::update_user))
        .route("/api/users/:id", delete(handlers::users::delete_user))
        .nest_service("/static", ServeDir::new("static"))
        .merge(auth_routes)
        // ------------------------------------------------------------------
        // The session guard.
        //
        // ONE layer around the whole router — every route above, the static
        // service, and every path that matches no route at all. It is
        // deliberately not a per-handler extractor: a route added later is
        // protected because it is part of a router that is already wrapped,
        // not because whoever added it remembered to ask.
        //
        // The exception list lives in `handlers::auth_web::is_public_path` and
        // is an allowlist: unknown paths are refused, so forgetting to think
        // about a new route fails closed. There is exactly one way to open
        // something up, and it is an edit to that function.
        //
        // Two placement rules, both load-bearing:
        //   * it must stay BELOW `CorsLayer` (i.e. added before it), so a CORS
        //     preflight is answered by that layer instead of being refused for
        //     carrying no cookie;
        //   * nothing may be added with `.route()` AFTER this line — axum only
        //     wraps what the router already holds. New routes go above.
        // ------------------------------------------------------------------
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            handlers::auth_web::require_session,
        ))
        .layer(middleware::from_fn(request_logging_middleware))
        // The default span of `TraceLayer` records the raw URI, which at
        // `RUST_LOG=debug` would put a reset token into the log. Same
        // redaction as the printed line above.
        .layer(TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
            tracing::info_span!(
                "request",
                method = %req.method(),
                uri = %log_safe_uri(req.uri()),
                version = ?req.version(),
            )
        }))
        .layer(Extension(config_manager))
        .layer(Extension(db_pool))
        .layer(Extension(rsyncd.clone()));

    // ----------------------------------------------------------------------
    // One wrapper around the finished router, for the two things that have to
    // sit outside it.
    //
    // `fallback_service` and not `.layer()`: axum writes the `Allow` header of
    // a method mismatch in the future its *own* method router returns, which is
    // outside everything `Router::layer` can reach — a middleware added above
    // never sees that header and cannot take it off. An empty router whose
    // fallback is the real one does get outside it.
    // ----------------------------------------------------------------------
    let app = Router::new()
        .fallback_service(app)
        .layer(middleware::from_fn(strip_allow_header_from_401));

    // ----------------------------------------------------------------------
    // CORS, and only if somebody asked for it.
    //
    // The frontend is served from this very process (`serve_index` and
    // `/static`), so it is same-origin and needs no CORS at all. The default
    // is therefore *no layer*: no `Access-Control-Allow-Origin`, and an
    // `OPTIONS` on a protected path falls through to the session guard (401)
    // instead of being answered 200 by the CORS layer before the guard runs.
    //
    // It stays the OUTERMOST layer — added after the session guard, so a
    // preflight (which carries no cookie, by specification) is answered here
    // instead of being refused by the guard. Measured; do not reorder. See the
    // block above the guard.
    // ----------------------------------------------------------------------
    let app = match build_cors_layer() {
        Some(cors) => app.layer(cors),
        None => app,
    };

    // Kein `expect()` mehr: seit `RCLONE_GUI_BIND` wirkt, kann der Wert aus
    // einer `.env` stammen, und ein Tippfehler dort soll eine Meldung ergeben,
    // die die Quelle nennt — nicht einen Panik-Backtrace.
    let addr: SocketAddr = match bind.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("❌ Invalid bind address '{}' ({}): {}", bind, bind_source, e);
            eprintln!("   Expected something like 127.0.0.1:8080 or [::1]:8080");
            std::process::exit(1);
        }
    };

    println!("🌐 Starting server...");
    println!("   📍 Binding to: {}", addr);
    println!("   🔗 URL: http://{}", addr);
    println!("   📁 Serving static files from: ./static/");
    println!("   📊 Request logging: enabled");
    println!("");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!(
        "✅ Server successfully started and listening on http://{}",
        addr
    );
    println!("🎯 Ready to accept connections!");
    println!("💡 Press Ctrl+C to stop the server");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("");

    // Setup graceful shutdown.
    //
    // `signalled` fires the moment a signal arrives, so the drain deadline
    // below can start counting from *then* rather than from the start of the
    // process.
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_signal = async move {
        let signal = wait_for_shutdown_signal().await;
        println!("");
        println!("🛑 Shutdown signal received ({})", signal);
        println!("🔄 Gracefully shutting down server...");
        let _ = signalled_tx.send(());
    };

    // Run server with graceful shutdown — but not for longer than
    // `SERVER_DRAIN_DEADLINE`.
    //
    // A graceful shutdown waits for every open connection, and a request that
    // is itself waiting on a slow remote holds one for up to its own timeout.
    // Waiting that out costs more than it buys: `docker stop` gives the process
    // ten seconds and then sends SIGKILL — and a process killed there never
    // reaches the daemon cleanup below, which is precisely how an orphaned
    // daemon with a locked pid file comes about. So the drain is bounded and
    // the cleanup happens either way.
    // `into_future()`: `with_graceful_shutdown` yields an `IntoFuture`, and
    // only a real future can be selected on alongside the deadline.
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(shutdown_signal),
    );
    tokio::pin!(server);

    let drain_deadline = async {
        let _ = signalled_rx.await;
        tokio::time::sleep(SERVER_DRAIN_DEADLINE).await;
    };

    tokio::select! {
        result = &mut server => {
            if let Err(e) = result {
                eprintln!("❌ The server stopped with an error: {}", e);
            }
        }
        _ = drain_deadline => {
            println!(
                "   ⚠️  connections were still open after {} s; continuing with the shutdown",
                SERVER_DRAIN_DEADLINE.as_secs()
            );
        }
    }

    // After the server, not inside the shutdown signal: the daemon has to
    // outlive the last request that might still be using it. `shutdown` sends
    // SIGTERM and waits for the process to be gone, so no daemon survives this
    // process — and it is SIGTERM rather than SIGKILL because a hard kill
    // leaves partial `.name.XXXXXX` files behind in the shares.
    //
    // Capped nonetheless: `shutdown` escalates to SIGKILL after its own grace
    // period, but a daemon whose pid vanished under it could leave the wait
    // open, and a shutdown that never ends is the same failure as one that
    // never runs.
    if let RsyncdState::Running(daemon) = rsyncd {
        println!("🔄 Stopping the rsync daemon...");
        match tokio::time::timeout(DAEMON_SHUTDOWN_DEADLINE, daemon.shutdown()).await {
            Ok(()) => println!("   ✅ rsync daemon stopped"),
            Err(_) => eprintln!(
                "   ⚠️  the rsync daemon did not stop within {} s; giving up on waiting",
                DAEMON_SHUTDOWN_DEADLINE.as_secs()
            ),
        }
    }

    println!("✅ Server shutdown completed");
    println!("👋 Goodbye!");
}

async fn delete_config_handler(
    Extension(config_manager): Extension<Arc<config_manager::ConfigManager>>,
    Path(name): Path<String>,
) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::config::delete_config(Extension(config_manager), name).await
}

// ---------------------------------------------------------------------------
// Job-Wege: Sync und URL-Abruf in einer Liste
//
// Der URL-Abruf ist ein regulärer Job, führt seine Einträge aber in
// `handlers::downloader` — die Tabelle des Syncs (`SYNC_JOBS`) ist modulprivat,
// und `sync.rs` gehört in diesem Ticket einem anderen Ticket. Für den Client
// ist das unsichtbar: die Liste wird hier zusammengeführt, und Fortschritt und
// Löschen fallen auf den Downloader zurück, wenn der Sync die ID nicht kennt.
// Der Log-Weg braucht keine Verzweigung — beide schreiben nach
// `data/log/<job_id>.log`.
// ---------------------------------------------------------------------------

/// `GET /api/sync` — Sync-Jobs **und** URL-Abrufe.
///
/// Sortiert nach Startzeit, neueste zuerst. Die Sync-Liste allein war nach
/// Job-ID sortiert; das ist bei UUIDs eine willkürliche Reihenfolge und taugt
/// nicht als gemeinsame Ordnung für zwei Quellen.
async fn list_jobs_handler() -> axum::response::Json<models::ApiResponse<Vec<models::SyncProgress>>>
{
    let mut response = handlers::sync::list_sync_jobs().await.0;
    let mut fetches = handlers::downloader::job_list();
    if let Some(list) = response.data.as_mut() {
        list.append(&mut fetches);
        list.sort_by(|a, b| b.start_time.cmp(&a.start_time).then(b.id.cmp(&a.id)));
    }
    axum::response::Json(response)
}

async fn cancel_url_fetch_handler(
    Path(job_id): Path<String>,
) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::downloader::cancel_job(job_id).await
}

async fn get_sync_progress_handler(
    Path(job_id): Path<String>,
) -> axum::response::Json<models::ApiResponse<models::SyncProgress>> {
    if let Some(progress) = handlers::downloader::job_progress(&job_id) {
        return axum::response::Json(models::ApiResponse::success(progress));
    }
    handlers::sync::get_sync_progress(job_id).await
}

/// `GET /api/sync/:job_id/log` — das Log eines Jobs, **mit** Besitzprüfung.
///
/// Der angemeldete Nutzer kommt aus `Extension<CurrentUser>`, das die
/// Sitzungsprüfung in die Request-Extensions gelegt hat — dasselbe Muster wie
/// `start_sync`. `get_sync_log_for` prüft fail closed: ein Job ohne bekannten
/// Eigentümer ist so unlesbar wie der eines fremden Kontos, und beide Fälle
/// antworten byte-gleich, damit der Endpunkt keine fremden Job-IDs bestätigt.
///
/// **Folge für den URL-Abruf:** dessen Jobs liegen in
/// `handlers::downloader::JOBS`, das keinen Eigentümer mitführt, und ihre Logs
/// werden dadurch für *jeden* unlesbar. Das ist die richtige Richtung — bisher
/// waren sie für jedes angemeldete Konto lesbar —, aber es ist ein
/// Funktionsverlust, der eine Eigentümerspalte im Downloader braucht. Beides
/// liegt in fremden Dateien und ist im Bericht vermerkt.
async fn get_sync_log_handler(
    Extension(current): Extension<handlers::auth_web::CurrentUser>,
    Path(job_id): Path<String>,
) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::sync::get_sync_log_for(&current, job_id).await
}

async fn delete_sync_job_handler(
    Path(job_id): Path<String>,
) -> axum::response::Json<models::ApiResponse<String>> {
    if let Some(response) = handlers::downloader::delete_job(&job_id).await {
        return axum::response::Json(response);
    }
    handlers::sync::delete_sync_job(job_id).await
}

async fn get_config_for_edit_handler(
    Extension(config_manager): Extension<Arc<config_manager::ConfigManager>>,
    Path(name): Path<String>,
) -> axum::response::Json<models::ApiResponse<models::RcloneConfig>> {
    handlers::config::get_config_for_edit(Extension(config_manager), name).await
}

/// Take the `Allow` header off a `401`.
///
/// axum answers a method it does not serve with `405` plus `Allow: GET,HEAD,…`,
/// and it attaches that header late enough that it survives the session guard's
/// `401`. The result is an unauthenticated request that gets told the route
/// exists and which methods it has — the same route disclosure the permissive
/// CORS layer used to hand out through its `200` preflight, only quieter.
///
/// `401` means "I am not telling you anything", so nothing is told: the header
/// is removed. A `405` for an authenticated caller, and for the public login
/// page, keeps it — there it is a correct answer to a legitimate question.
async fn strip_allow_header_from_401(req: Request, next: Next) -> axum::response::Response {
    let mut response = next.run(req).await;
    if response.status() == axum::http::StatusCode::UNAUTHORIZED {
        response.headers_mut().remove(header::ALLOW);
    }
    response
}

/// Environment variable holding the cross-origin allowlist, comma separated
/// (`https://a.example,https://b.example`). Unset or empty means: no foreign
/// origin, which is the default and the right answer for a same-origin app.
const CORS_ORIGINS_ENV: &str = "RCLONE_GUI_CORS_ORIGINS";

/// Build the CORS layer from [`CORS_ORIGINS_ENV`], or `None` when no origin is
/// configured.
///
/// Replaces `CorsLayer::permissive()`, which sent
/// `Access-Control-Allow-Origin: *` for every method and header across the
/// whole application. Two things were wrong with it even after the session
/// guard arrived — the guard makes `*` harmless for reading, because without
/// `allow_credentials` a browser sends no cookie and a foreign page gets 401:
///
///   * `permissive()` answers the preflight itself, so `OPTIONS` on a
///     protected path came back 200 with `allow: GET,HEAD,POST` *before* the
///     guard ran. Nothing leaked — there are no `OPTIONS` handlers — but the
///     existence of a route did
///   * the protection was a side effect of using cookies. A later switch to a
///     token in the `Authorization` header has no cookie rule behind it, and
///     `*` would be an open door again on the day of that change
///
/// What is allowed here is what the frontend actually uses: the three methods
/// the router serves (axum answers `HEAD` through the `GET` handler) and
/// `content-type` for JSON bodies. Nothing is granted "just in case" —
/// `Authorization` deliberately is not in the list, and adding it is a
/// decision for whoever introduces token auth.
///
/// # Do the share links from epic 4 (`/s/<token>`) need an exception?
///
/// Checked, and the answer is **no** — no exception now, and none expected:
///
///   * a share link is *navigated to*. A top-level navigation and a plain
///     `<img>`/`<video>`/download of the target are not subject to CORS at
///     all; the browser fetches them regardless of any allow-origin header. A
///     link mailed to somebody works with this layer absent
///   * CORS would only enter the picture if a foreign page read a share
///     through `fetch`, and allowing that is the opposite of what an anonymous
///     link needs: it would let any site in the world script-read the shared
///     content of a token it happened to learn
///
/// Should embedding ever be wanted, it belongs on that route alone — a second,
/// nested `CorsLayer` on `/s/` with `AllowOrigin::any()` and *no* credentials,
/// as a deliberate opt-in — not by widening this one.
/// Whether `candidate` is a serialised origin as a browser sends it:
/// `scheme://host` with an optional `:port`, and nothing after that.
fn is_origin(candidate: &str) -> bool {
    let Some(rest) = candidate
        .strip_prefix("https://")
        .or_else(|| candidate.strip_prefix("http://"))
    else {
        return false;
    };
    !rest.is_empty()
        && !rest.contains('/')
        && !rest.contains(|c: char| c.is_whitespace() || c.is_control())
}

fn build_cors_layer() -> Option<CorsLayer> {
    let configured = env::var(CORS_ORIGINS_ENV).unwrap_or_default();

    let mut origins: Vec<HeaderValue> = Vec::new();
    for entry in configured
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        // `*` is refused rather than translated: combined with credentials it
        // is not even a legal value, and silently turning it into "any origin"
        // would reinstate exactly what this replaced.
        if entry == "*" {
            eprintln!(
                "⚠️  CORS: '*' is not accepted in {CORS_ORIGINS_ENV}; list origins explicitly"
            );
            continue;
        }
        // An origin is scheme + host + optional port and nothing else — no
        // path, no trailing slash, no spaces. `HeaderValue::from_str` accepts
        // far more than that, and an entry that merely *looks* configured but
        // never matches a browser's `Origin` is worse than a rejected one,
        // because it fails silently at request time instead of loudly here.
        match is_origin(entry).then(|| HeaderValue::from_str(entry).ok()).flatten() {
            Some(value) => origins.push(value),
            None => eprintln!(
                "⚠️  CORS: ignoring '{entry}' — expected scheme://host[:port], e.g. https://gui.example"
            ),
        }
    }

    if origins.is_empty() {
        println!("🔒 CORS: no foreign origin allowed (set {CORS_ORIGINS_ENV} to change)");
        return None;
    }

    for origin in &origins {
        let shown = origin.to_str().unwrap_or("<unprintable>");
        println!("🔓 CORS: allowing origin {}", shown);
        tracing::info!(origin = %shown, "CORS: origin allowed");
    }

    Some(
        CorsLayer::new()
            .allow_origin(origins)
            // Credentials are on because a configured origin is a companion
            // frontend of this same installation, and it needs the session
            // cookie to get past the guard. It is only ever paired with an
            // explicit origin list, never with a wildcard.
            .allow_credentials(true)
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_headers([header::CONTENT_TYPE])
            .max_age(Duration::from_secs(600)),
    )
}

/// How long open connections get to finish after a shutdown signal.
///
/// Deliberately short: `docker stop` allows ten seconds in total before it
/// sends SIGKILL, and everything after the drain — stopping the rsync daemon —
/// has to fit into what is left.
const SERVER_DRAIN_DEADLINE: Duration = Duration::from_secs(3);

/// Upper bound for stopping the rsync daemon. `DaemonHandle::shutdown` has its
/// own SIGTERM grace period and escalates to SIGKILL; this is only the guard
/// against a wait that never returns.
const DAEMON_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(25);

/// Waits for the first shutdown signal and names it.
///
/// **SIGTERM belongs here just as much as Ctrl+C.** `docker stop`,
/// `systemctl stop` and every process manager send SIGTERM, and while only
/// `ctrl_c` was awaited, none of them reached the cleanup path: the rsync
/// daemon stayed behind as an orphan holding an flock on its pid file, and the
/// next start failed with `failed to lock pid file: Resource temporarily
/// unavailable`. Reproduced twice before this was written.
///
/// A signal handler that cannot be installed must not take the server down —
/// it simply never fires, and the other one still works.
async fn wait_for_shutdown_signal() -> &'static str {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            eprintln!("⚠️  Ctrl+C handler could not be installed: {}", e);
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => {
                eprintln!("⚠️  SIGTERM handler could not be installed: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => "SIGINT",
        _ = terminate => "SIGTERM",
    }
}

/// What became of the rsync transport at startup.
///
/// Three states, and telling them apart is the point: a default installation
/// has the transport switched off and must not look like a fault, while a
/// deployment that switched it on and got no daemon has a problem that used to
/// be invisible — both collapsed into `None` and were reported as "switched
/// off" by `/api/rsyncd/status`.
#[derive(Clone)]
enum RsyncdState {
    /// `RCLONE_GUI_RSYNCD` is not `1`. The normal state, not an error.
    Disabled,
    /// Switched on, but `DaemonHandle::start` failed. Carries the cause.
    StartFailed {
        /// Whether another process holds the port and the pid file lock — the
        /// one failure a restart cannot fix.
        already_running_elsewhere: bool,
        /// The reason, verbatim, for the status display.
        error: String,
    },
    /// Switched on and listening.
    Running(Arc<handlers::rsyncd::DaemonHandle>),
}

/// Start the rsync daemon alongside the application, if it is switched on.
///
/// **Off unless `RCLONE_GUI_RSYNCD=1`.** The peer-to-peer transport has no
/// pairing storage yet, so the module registry starts empty and the daemon
/// would serve nothing; a process holding a port for no reason is a liability,
/// not a feature. The switch goes away with the ticket that stores pairings,
/// which is also the one that fills the registry from the database before this
/// is called.
///
/// A daemon that cannot be started is logged and does not stop the server: the
/// web GUI is the product, the rsync transport is one feature of it, and losing
/// the whole application because rsync is missing from the image would be the
/// wrong trade. The failure is visible at `/api/rsyncd/status`, as a *start
/// failure with its cause* — not as "switched off", which is what a caller
/// would otherwise read out of an absent handle.
async fn start_rsync_daemon() -> RsyncdState {
    if env::var("RCLONE_GUI_RSYNCD").unwrap_or_default() != "1" {
        return RsyncdState::Disabled;
    }

    // The layout the image creates (see the Dockerfile): /etc/rsyncd for the
    // configuration, /etc/rsyncd/secrets (mode 700) for the secrets file.
    let base = env::var("RCLONE_GUI_RSYNCD_DIR").unwrap_or_else(|_| "/etc/rsyncd".to_string());
    let conf = format!("{base}/rsyncd.conf");
    let secrets = format!("{base}/secrets/rsyncd.secrets");
    let run_dir = format!("{base}/run");

    println!("🔗 Starting the rsync daemon:");
    println!("   📄 Configuration: {}", conf);
    println!("   📂 Run directory: {}", run_dir);

    let registry = Arc::new(tokio::sync::Mutex::new(
        handlers::rsyncd::ModuleRegistry::new(&conf, &secrets),
    ));
    let settings = handlers::rsyncd::DaemonSettings::new(&conf, &run_dir);

    match handlers::rsyncd::DaemonHandle::start(settings, registry).await {
        Ok(handle) => {
            let status = handle.status().await;

            // "Running" has to mean the port is held, not merely that a
            // process was spawned. `Ok` here already means the daemon's own
            // log said "listening on port", but that is the daemon talking
            // about itself into a file, and a state that claims to be one of
            // three clean cases must not be the one that lies. So: connect.
            //
            // A refused connection is the honest answer to "is it listening",
            // and the handle is shut down rather than left as an untracked
            // child — this process reports no daemon, so it holds none.
            if !daemon_accepts_connections(&status.address, status.port).await {
                let error = format!(
                    "the rsync daemon was started (pid {}) but nothing accepts connections on {}:{}",
                    status
                        .pid
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    status.address,
                    status.port
                );
                eprintln!("   ❌ {}", error);
                eprintln!("      stopping it again; see GET /api/rsyncd/status");
                handle.shutdown().await;
                println!();
                return RsyncdState::StartFailed {
                    already_running_elsewhere: status.already_running_elsewhere,
                    error,
                };
            }

            println!(
                "   ✅ rsync daemon listening on {}:{} (pid {})",
                status.address,
                status.port,
                status.pid.unwrap_or(0)
            );
            println!();
            RsyncdState::Running(handle)
        }
        Err(e) => {
            // `{:#}` so the anyhow context chain ends up in the message the
            // status endpoint hands out — "cannot create the daemon run
            // directory /x: Permission denied" is actionable, the outer
            // sentence alone is not.
            let error = format!("{e:#}");
            eprintln!("   ❌ the rsync daemon did not start: {}", error);
            eprintln!("      the server continues without the rsync transport");
            eprintln!("      the reason is reported at GET /api/rsyncd/status");
            println!();
            // `DaemonHandle::start` reports this case as prose and does not
            // hand the handle back, so the one distinction the display makes
            // ("blocked" versus "not running") has to be recovered from the
            // message. Recognising it is a nicety; failing to recognise it
            // still yields a start failure with its cause, never "disabled".
            let already_running_elsewhere = error.contains("pid file lock");
            RsyncdState::StartFailed {
                already_running_elsewhere,
                error,
            }
        }
    }
}

/// Whether anything accepts a TCP connection at `address:port`.
///
/// The proof that the daemon really holds its port. Retried a few times rather
/// than asked once: the listener is opened by a freshly forked process, and a
/// single refused connect a few milliseconds too early would take a working
/// daemon down. Only a port that stays refused for the whole window counts as
/// "not listening".
///
/// The connection is closed immediately. rsync's daemon forks a child per
/// connection and logs a `connect from`, so this shows up once as a connection
/// that ends at the handshake — noise at startup, and the price of not
/// reporting a state that is untrue.
async fn daemon_accepts_connections(address: &str, port: u16) -> bool {
    const ATTEMPTS: usize = 5;
    const GAP: Duration = Duration::from_millis(300);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

    for attempt in 0..ATTEMPTS {
        let connect = tokio::net::TcpStream::connect((address, port));
        if let Ok(Ok(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            drop(stream);
            return true;
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(GAP).await;
        }
    }
    false
}

/// Whether the daemon is running, where, and which modules it serves.
///
/// The three startup states of [`RsyncdState`] map onto the three cases the
/// configuration display already tells apart, and they map onto them without
/// asking the frontend to learn anything new:
///
///   * **disabled** — `data: null` plus the explanatory `error`. The panel
///     decides on `data === null` and shows the grey "disabled" badge
///   * **start failure** — a `DaemonStatus` with `running: false` and the cause
///     in `last_error`. The panel renders "not running" (or "blocked", when the
///     port belongs to another process) *and* the error box, which is exactly
///     the wanted outcome
///   * **running** — the live status, unchanged
async fn rsyncd_status_handler(
    Extension(rsyncd): Extension<RsyncdState>,
) -> axum::response::Json<models::ApiResponse<handlers::rsyncd::DaemonStatus>> {
    match rsyncd {
        RsyncdState::Running(daemon) => axum::response::Json(models::ApiResponse {
            success: true,
            data: Some(daemon.status().await),
            error: None,
        }),
        // Switched on and broken. Reported as a daemon that is not running,
        // with the reason attached — never as "switched off", which describes
        // the normal state and would hide the fault entirely.
        RsyncdState::StartFailed {
            already_running_elsewhere,
            error,
        } => axum::response::Json(models::ApiResponse {
            success: true,
            data: Some(handlers::rsyncd::DaemonStatus {
                running: false,
                pid: None,
                address: handlers::rsyncd::DAEMON_ADDRESS.to_string(),
                port: handlers::rsyncd::DAEMON_PORT,
                modules: Vec::new(),
                active_modules: Vec::new(),
                connections: 0,
                restarts: 0,
                already_running_elsewhere,
                zombie_children: 0,
                last_error: Some(error),
            }),
            error: None,
        }),
        // Switched off is not an error: the configuration display shows
        // "disabled" rather than a failure the user cannot act on.
        RsyncdState::Disabled => axum::response::Json(models::ApiResponse {
            success: true,
            data: None,
            error: Some("the rsync transport is switched off (RCLONE_GUI_RSYNCD)".to_string()),
        }),
    }
}

/// Placeholder in `static/index.html` that `serve_index()` replaces with the
/// script tags. It is an HTML comment on purpose: unlike the former
/// `<script src="app.js"></script>` it cannot be mistaken for a dangling
/// reference to a deleted file. Whoever changes it here must change it there —
/// `index_html_ships_the_script_marker` guards the embedded copy.
const SCRIPT_MARKER: &str = "<!-- RCLONE_GUI_SCRIPTS -->";

/// Read `static/index.html`, falling back to the copy embedded at build time.
///
/// The embedded copy only covers a missing/unreadable `static/index.html`. The
/// JS modules themselves are served from disk by ServeDir under `/static` and
/// are not embedded — the deployment always ships the whole `static/` tree (see
/// the Dockerfile), so there is nothing to fall back to per module.
fn read_index_html() -> String {
    std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| include_str!("../static/index.html").to_string())
}

/// Render `default_path` as a JavaScript string literal that is safe inside an
/// inline `<script>`.
///
/// `serde_json` quotes backslashes and quotes, but it does not escape `<`, so a
/// path containing `</script>` would break out of the element. Escaping `<`,
/// `>` and `&` (plus the two line separators JavaScript treats as newlines)
/// keeps the literal inert in every HTML context.
fn js_string_literal(value: &str) -> String {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "\"/mnt/home\"".to_string());
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Replace [`SCRIPT_MARKER`] with the script tags, or `None` if the marker is
/// gone.
///
/// Returning `None` instead of the untouched HTML is the whole point of this
/// function: a page without the module tag looks fine and fails silently in the
/// browser, so the caller has to turn the missing marker into a visible error.
fn render_index(html: &str, default_path: &str) -> Option<String> {
    if !html.contains(SCRIPT_MARKER) {
        return None;
    }

    // The default path goes into a classic inline script, which the browser runs
    // before any deferred module script, so the value is set by the time
    // static/js/main.js is evaluated.
    let replacement = format!(
        "<script>window.DEFAULT_PATH = {};</script>\n    <script type=\"module\" src=\"/static/js/main.js\"></script>",
        js_string_literal(default_path)
    );

    Some(html.replace(SCRIPT_MARKER, &replacement))
}

/// Log loudly if the index we would serve has lost its script marker. Called at
/// startup so the operator sees the problem before the first request, not only
/// as a dead page in the browser.
fn check_index_marker() {
    if render_index(&read_index_html(), "/mnt/home").is_none() {
        eprintln!(
            "❌ static/index.html is missing the marker {} — the GUI will be served as an error page",
            SCRIPT_MARKER
        );
        tracing::error!(
            marker = SCRIPT_MARKER,
            "static/index.html is missing the script marker; the GUI cannot be assembled"
        );
    }
}

/// Serve the application shell.
///
/// `window.DEFAULT_PATH` is the directory the file browser opens on
/// (`static/js/state.js`). Since the data separation that is **not** the global
/// `RCLONE_GUI_DEFAULT_PATH` any more: every listing resolves against
/// `users.home_path` and answers 403 for anything else, so injecting the global
/// path handed every non-admin a foreign directory and a 403 on the very first
/// request.
///
/// The account comes from `Extension<CurrentUser>`, which the session guard put
/// into the request extensions — the route registration is unchanged, an
/// `Extension` is just another extractor.
///
/// Note on escaping: the value now originates from the **database** and is
/// therefore settable by an administrator rather than by whoever runs the
/// process. `js_string_literal()` was already written for that case (it escapes
/// `<`, `>`, `&` and the two JavaScript line separators on top of the JSON
/// quoting), which is why a home path containing `</script>` cannot break out.
async fn serve_index(
    Extension(current): Extension<handlers::auth_web::CurrentUser>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let default_path = current.user.home_path.trim().to_string();
    if default_path.is_empty() {
        // No 500 here: an account without a home still gets the shell, and the
        // first listing reports the misconfiguration with a proper message.
        tracing::warn!(
            user = %current.user.username,
            "account has no home path; the file browser will open without a start directory"
        );
    }
    println!(
        "🏠 Using home path of '{}': {}",
        current.user.username, default_path
    );

    match render_index(&read_index_html(), &default_path) {
        Some(html) => Html(html).into_response(),
        None => {
            tracing::error!(
                marker = SCRIPT_MARKER,
                "index.html has no script marker — refusing to serve a page without JavaScript"
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!(
                    "<h1>rclone GUI is misconfigured</h1><p>The marker <code>{}</code> is missing from <code>static/index.html</code>. Without it the interface would load without any JavaScript, so it is not served at all. See the server log.</p>",
                    SCRIPT_MARKER.replace('<', "&lt;").replace('>', "&gt;")
                )),
            )
                .into_response()
        }
    }
}

/// Load environment configuration with detailed feedback
fn load_environment_config() {
    println!("🚀 Starting Rclone GUI...");
    println!(
        "📁 Working directory: {}",
        env::current_dir().unwrap_or_default().display()
    );
    println!("📋 Environment configuration:");

    // Load .env file first
    let env_loaded = match dotenv() {
        Ok(_) => {
            println!("   ✅ .env found and loaded");
            true
        }
        Err(_) => {
            println!("   ❌ .env not found");
            false
        }
    };

    // Load .env.local file (overrides .env)
    let env_local_loaded = match from_filename_override(".env.local") {
        Ok(_) => {
            println!("   ✅ .env.local found and loaded (local overrides)");
            true
        }
        Err(_) => {
            println!(
                "   ℹ️  .env.local not found (create from .env.local.example for local settings)"
            );
            false
        }
    };

    // Show current effective configuration
    let current_path =
        env::var("RCLONE_GUI_DEFAULT_PATH").unwrap_or_else(|_| "/mnt/home".to_string());

    // Determine the actual source of the current value
    let source = if env_local_loaded && current_path != "/mnt/home" {
        "from .env.local"
    } else if env_loaded && current_path != "/mnt/home" {
        "from .env"
    } else {
        "fallback default"
    };

    println!("   🎯 Active default path: {} ({})", current_path, source);

    // Show other relevant environment variables
    if let Ok(rust_log) = env::var("RUST_LOG") {
        println!("   🐛 Log level: {}", rust_log);
    }

    println!("");
}

/// Clean up any orphaned log files from previous application runs
async fn cleanup_orphaned_log_files() {
    use tokio::fs;

    let log_dir = "data/log";

    // Create log directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(log_dir).await {
        eprintln!("Warning: Could not create log directory: {}", e);
        return;
    }

    match fs::read_dir(log_dir).await {
        Ok(mut entries) => {
            let mut removed_count = 0;

            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();

                // Only remove .log files, keep .gitkeep and other files
                if let Some(extension) = path.extension() {
                    if extension == "log" {
                        if let Err(e) = fs::remove_file(&path).await {
                            eprintln!(
                                "Warning: Could not remove orphaned log file {:?}: {}",
                                path, e
                            );
                        } else {
                            removed_count += 1;
                            println!(
                                "🧹 Removed orphaned log file: {:?}",
                                path.file_name().unwrap_or_default()
                            );
                        }
                    }
                }
            }

            if removed_count > 0 {
                println!(
                    "🗑️  Cleaned up {} orphaned log files from previous runs",
                    removed_count
                );
            } else {
                println!("✅ No orphaned log files found");
            }
        }
        Err(e) => {
            eprintln!("Warning: Could not read log directory: {}", e);
        }
    }
}

/// Middleware function to log all HTTP requests
/// A request URI that is safe to write down.
///
/// The reset link carries its token in the query string — that is what a link
/// can do — so every place that logs a URI would otherwise write a live
/// account-takeover token into stdout, into the log file the operator redirects
/// it to, and into every backup of that file. Measured, not assumed: before
/// this existed, the token showed up four times per page view in the server
/// log of a test run.
///
/// Any query parameter named `token` loses its value; everything else is kept,
/// because a redacted log that hides the path helps nobody.
fn log_safe_uri(uri: &axum::http::Uri) -> String {
    let path = uri.path();
    let Some(query) = uri.query() else {
        return path.to_string();
    };

    let redacted = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if key.eq_ignore_ascii_case("token") => {
                format!("{key}=<redacted>")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");

    format!("{path}?{redacted}")
}

async fn request_logging_middleware(req: Request, next: Next) -> axum::response::Response {
    let method = req.method().clone();
    let uri = log_safe_uri(req.uri());
    let headers = req.headers().clone();

    // Extract client IP (simplified)
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("unknown");

    let start_time = std::time::Instant::now();

    // Log the incoming request
    println!(
        "📨 {} {} from {} at {}",
        method,
        uri,
        client_ip,
        chrono::Utc::now().format("%H:%M:%S")
    );

    // Process the request
    let response = next.run(req).await;

    let duration = start_time.elapsed();
    let status = response.status();

    // Log the response
    let status_emoji = match status.as_u16() {
        200..=299 => "✅",
        300..=399 => "🔄",
        400..=499 => "❌",
        500..=599 => "💥",
        _ => "❓",
    };

    println!(
        "📤 {} {} {} - {}ms",
        status_emoji,
        status.as_u16(),
        uri,
        duration.as_millis()
    );

    response
}

/// Setup enhanced tracing with environment-based filtering
fn setup_tracing() {
    // Default to INFO level, but allow override via RUST_LOG environment variable
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_file(false)
                .with_line_number(false)
                .compact(),
        )
        .init();

    tracing::info!("🔍 Tracing initialized");
}

/// Make sure at least one account exists, so the login page is not a dead end.
///
/// Once the guard is in place, an empty `users` table means nobody can reach
/// the application at all — and the user-management screens that would create
/// the first account live behind that same guard. So the first start creates an
/// administrator:
///
///   * `RCLONE_GUI_ADMIN_USER` / `RCLONE_GUI_ADMIN_PASSWORD` when both are set,
///   * otherwise `admin` with a freshly drawn random password, printed **once**
///     to stdout.
///
/// The generated password goes to stdout with `println!`, never through
/// `tracing`: it must be readable in the console of a first start and must not
/// end up in a log file, in a shipped log bundle or in a backup of one. It is
/// also never put in `argv`, which is why there is no `--admin-password` flag.
///
/// Nothing happens when accounts already exist — this can never overwrite a
/// `--reset-password=<user>`: issue a one-shot reset token and print it.
///
/// The token goes out with `println!` and **never** through `tracing`, for the
/// same reason as the bootstrap password a few functions down: `tracing` output
/// ends up in a log file, in a log bundle and in every backup of it, and a live
/// reset token there is an account takeover waiting to be found. stdout belongs
/// to the person standing at the terminal and disappears with it.
///
/// Unlike the web page, this side names the problem plainly — an unknown or
/// disabled account gets a clear message. Whoever can run this command already
/// has server access, so there is nothing left to hide from them, and a silent
/// no-op would just get the operator to reissue tokens for a typo forever.
async fn handle_cli_password_reset(db_pool: sqlx::Pool<sqlx::Sqlite>, username: &str, bind: &str) {
    match handlers::auth::issue_password_reset(&db_pool, username).await {
        Ok(issued) => {
            println!("🔑 Password reset for '{}':", issued.username);
            println!("   Reset-Token: {}", issued.token.expose());
            println!(
                "   ⏳ Valid until {} UTC, usable exactly once",
                issued.expires_at.format("%Y-%m-%d %H:%M")
            );
            println!(
                "   🔗 http://{}/reset?token={}",
                bind,
                issued.token.expose()
            );
            println!();
            println!("   ⚠️  Shown once and not written to any log. Anyone who reads it can");
            println!("       take over the account until it is used or expires.");
        }
        Err(e) => {
            if let handlers::auth::ResetIssueError::Internal(ref cause) = e {
                eprintln!("❌ Could not issue a reset token: {:#}", cause);
            } else {
                eprintln!("❌ Could not issue a reset token: {}", e);
            }
            std::process::exit(1);
        }
    }
}

/// password or resurrect a deleted account.
async fn ensure_bootstrap_user(pool: &sqlx::Pool<sqlx::Sqlite>) -> anyhow::Result<()> {
    let existing = database::count_users(pool).await?;
    if existing > 0 {
        println!("   👤 {} account(s) present", existing);
        return Ok(());
    }

    let username = env::var("RCLONE_GUI_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    let (password, generated) = match env::var("RCLONE_GUI_ADMIN_PASSWORD") {
        Ok(value) if !value.is_empty() => (value, false),
        _ => (handlers::auth::generate_initial_password()?, true),
    };

    handlers::auth::validate_password(&password)
        .map_err(|e| anyhow::anyhow!("RCLONE_GUI_ADMIN_PASSWORD is not acceptable: {e}"))?;

    let hash = handlers::auth::hash_password(&password)?;
    let user = database::User {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.clone(),
        password_hash: hash,
        role: "admin".to_string(),
        home_path: env::var("RCLONE_GUI_DEFAULT_PATH").unwrap_or_else(|_| "/mnt/home".to_string()),
        is_active: true,
        created_at: chrono::Utc::now(),
        last_login_at: None,
    };
    database::create_user(pool, &user).await?;

    println!(
        "   🆕 No account existed, created the administrator '{}'",
        username
    );
    if generated {
        println!("   🔑 One-time password: {}", password);
        println!("   ⚠️  Shown once, not written to any log — change it after signing in.");
    } else {
        println!("   🔑 Password taken from RCLONE_GUI_ADMIN_PASSWORD");
    }

    Ok(())
}

/// Decide which account a `--start-task` run belongs to.
///
/// **Decision: `--user`, not "owner of the task".** A stored task has no owner
/// today — `models::Task` has no user column and `src/database.rs` belongs to
/// the data-separation ticket, so "owner of the task" is not a field that
/// exists and could not be read without changing a table this ticket does not
/// own. `--user` also stays correct once that column arrives: it is then the
/// account whose tasks are looked up, rather than a second source of truth.
///
/// Resolution, deliberately fail-closed:
///   * `--user` given → that account, and it must exist and be enabled,
///   * omitted with exactly one account → that one; the single-user
///     installation, which is the common case, keeps working unchanged,
///   * omitted with several accounts → refused, because guessing which user a
///     scripted run acts as is exactly the decision a person has to make.
///
/// No password is asked for. The CLI runs locally with the process owner's
/// rights and can read `data/tasks.db` anyway; authenticating against a
/// database the caller could simply edit would be theatre. The account is an
/// *attribution*, and that is what it is used for.
async fn resolve_cli_user(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    requested: Option<String>,
) -> anyhow::Result<database::User> {
    if let Some(name) = requested {
        let user = database::get_user_by_username(pool, name.trim())
            .await?
            .ok_or_else(|| anyhow::anyhow!("no such user: '{}'", name))?;
        if !user.is_active {
            anyhow::bail!("the account '{}' is disabled", user.username);
        }
        return Ok(user);
    }

    let mut users: Vec<database::User> = database::get_all_users(pool)
        .await?
        .into_iter()
        .filter(|u| u.is_active)
        .collect();

    match users.len() {
        0 => anyhow::bail!(
            "no account exists yet — start the server once so the initial administrator is created"
        ),
        1 => Ok(users.remove(0)),
        n => anyhow::bail!(
            "{} accounts exist, so the run is ambiguous — pass --user=<name>",
            n
        ),
    }
}

/// Handle CLI task execution
async fn handle_cli_task_execution(
    db_pool: sqlx::Pool<sqlx::Sqlite>,
    task_name: String,
    requested_user: Option<String>,
) {
    use crate::models::SyncRequest;

    println!("🚀 Starting task '{}' from command line...", task_name);

    // Resolved before anything is started: a run that cannot be attributed to
    // an account does not run at all.
    let user = match resolve_cli_user(&db_pool, requested_user).await {
        Ok(user) => user,
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    };
    println!("👤 Running as: {} ({})", user.username, user.role);
    tracing::info!(user_id = %user.id, task = %task_name, "CLI task run");

    // Get task from database
    let task = match database::get_task_by_name(&db_pool, &task_name).await {
        Ok(Some(task)) => task,
        Ok(None) => {
            eprintln!("❌ Task '{}' not found", task_name);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Failed to retrieve task '{}': {}", task_name, e);
            std::process::exit(1);
        }
    };

    println!("📋 Task details:");
    println!("   Name: {}", task.name);
    println!("   Source: {}", task.source_path);
    println!("   Remote: {}:{}", task.remote_name, task.remote_path);
    println!(
        "   Chunking: {}",
        if task.use_chunking {
            "enabled"
        } else {
            "disabled"
        }
    );
    if let Some(ref chunk_size) = task.chunk_size {
        println!("   Chunk size: {}", chunk_size);
    }
    println!("");

    // Convert task to sync request
    // Die Löschoption trägt ein Task heute nicht mit (Spalte fehlt in
    // `tasks`); `--start-task` kopiert deshalb, es spiegelt nicht.
    let sync_request = SyncRequest {
        source_path: task.source_path,
        remote_name: task.remote_name,
        remote_path: task.remote_path,
        chunk_size: task.chunk_size,
        use_chunking: Some(task.use_chunking),
        delete_target: None,
        delete_confirmed: None,
        dry_run: None,
        backup_dir: None,
    };

    // Start the sync job.
    //
    // The CLI bypasses the router and therefore the session guard, so the
    // `CurrentUser` the guard would have inserted is assembled here from the
    // account resolved above. `start_sync_for` is the same core the HTTP
    // handler calls — the source path goes through `resolve_within_root()`
    // against this user's home either way, so `--start-task` cannot reach
    // outside it any more than `POST /api/sync` can.
    //
    // The session is a stand-in: it is never written to the database, never
    // handed out and never looked up. It exists because `CurrentUser` carries
    // one; only `user` is read on this path.
    let current = handlers::auth_web::CurrentUser {
        session: database::Session {
            id: String::new(),
            user_id: user.id.clone(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
            user_agent: Some("rclone-gui --start-task".to_string()),
            ip: None,
        },
        user,
    };

    let job_response = handlers::sync::start_sync_for(&current, sync_request).await;
    let job_id = match job_response.0.data {
        Some(id) => id,
        None => {
            eprintln!("❌ Failed to start sync job: {:?}", job_response.0.error);
            std::process::exit(1);
        }
    };

    println!("✅ Sync job started with ID: {}", job_id);
    println!("📊 Monitoring progress...");
    println!("");

    // Monitor progress
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let progress_response = handlers::sync::get_sync_progress(job_id.clone()).await;
        if let Some(progress) = progress_response.0.data {
            println!(
                "📈 Progress: {:.1}% | Status: {} | Transferred: {} / {}",
                progress.progress,
                progress.status,
                format_bytes(progress.transferred),
                format_bytes(progress.total)
            );

            // Abbruchbedingung ist der Typ, nicht der Wortlaut: die Schleife
            // endet bei *jedem* Endzustand. Früher wurde auf "Failed" bzw.
            // "Error" verglichen — eine anders formulierte Meldung (etwa
            // "Failed to spawn rclone process: … (os error 2)") lief endlos.
            if progress.status.is_terminal() {
                println!("");
                if progress.status.is_success() {
                    println!("✅ Task '{}' completed successfully!", task_name);
                    break;
                }
                // Teilerfolg ist ein eigener Ausgang, kein Fehlschlag.
                //
                // Ein Skript, das `--start-task` aufruft, muss „ein Teil der
                // Daten ist angekommen" von „nichts ist angekommen"
                // unterscheiden können; mit einem gemeinsamen Exit 1 kann es
                // das nicht. Deshalb **4**: nicht 0 (kein Erfolg), nicht 1
                // (Fehlschlag), nicht 2 (Aufruffehler). Die Meldung geht auf
                // **stdout** — es ist kein Fehler, sondern ein Ergebnis.
                //
                // Der rsync-Code selbst (23 oder 24) wird bewusst **nicht**
                // durchgereicht: `JobStatus::Partial` fasst beide zusammen, und
                // ein durchgereichter Code würde behaupten, ein Skript könne
                // sie unterscheiden. Der Grund steht im Klartext in der
                // Meldung und ausführlich im Job-Log.
                if progress.status.is_partial() {
                    println!(
                        "◑ Task '{}' finished partially: {}",
                        task_name, progress.status
                    );
                    std::process::exit(4);
                }
                eprintln!("❌ Task '{}' failed: {}", task_name, progress.status);
                std::process::exit(1);
            }
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }

    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let base = 1024_f64;
    let log = (bytes as f64).log(base).floor() as usize;
    let unit_index = log.min(UNITS.len() - 1);
    let value = bytes as f64 / base.powi(unit_index as i32);

    if unit_index >= 3 {
        format!("{:.1} {}", value, UNITS[unit_index])
    } else {
        format!("{:.0} {}", value, UNITS[unit_index])
    }
}

#[cfg(test)]
mod index_tests {
    use super::*;

    /// The shipped index.html must carry the marker — this is the test that
    /// turns "someone tidied the placeholder away" into a red build.
    #[test]
    fn index_html_ships_the_script_marker() {
        let embedded = include_str!("../static/index.html");
        assert!(
            embedded.contains(SCRIPT_MARKER),
            "static/index.html lost the marker {SCRIPT_MARKER}"
        );
        assert!(
            read_index_html().contains(SCRIPT_MARKER),
            "the index.html on disk lost the marker {SCRIPT_MARKER}"
        );
    }

    /// The served HTML must actually contain the module tag; a page without it
    /// loads no JavaScript at all.
    #[test]
    fn served_html_contains_the_module_tag() {
        let rendered =
            render_index(read_index_html().as_str(), "/mnt/home").expect("marker must be present");

        assert!(rendered.contains("type=\"module\""));
        assert!(rendered.contains("/static/js/main.js"));
        assert!(rendered.contains("window.DEFAULT_PATH = \"/mnt/home\";"));
        assert!(!rendered.contains(SCRIPT_MARKER));
    }

    /// A missing marker must be reported, not silently passed through.
    #[test]
    fn missing_marker_is_reported() {
        assert!(render_index("<html><body>no marker here</body></html>", "/mnt/home").is_none());
    }

    /// A default path containing `</script>` must not break out of the inline
    /// script. serde_json alone does not escape `<`.
    #[test]
    fn default_path_cannot_break_out_of_the_inline_script() {
        let rendered = render_index(
            SCRIPT_MARKER,
            "/mnt/</script><script>window.__PWNED__=1;</script>",
        )
        .expect("marker must be present");

        assert!(!rendered.contains("</script><script>window.__PWNED__"));
        assert!(rendered.contains("\\u003c/script\\u003e"));
        // Exactly the two tags we inject, no smuggled third one.
        assert_eq!(rendered.matches("<script").count(), 2);
    }

    /// Quotes, backslashes and apostrophes stay inside the literal.
    #[test]
    fn default_path_quoting_survives_json_encoding() {
        assert_eq!(
            js_string_literal("/mnt/it's \"here\"\\x"),
            "\"/mnt/it's \\\"here\\\"\\\\x\""
        );
        assert_eq!(js_string_literal("/a&b"), "\"/a\\u0026b\"");
    }
}

#[cfg(test)]
mod reset_logging_tests {
    use super::*;

    /// The reset token must not survive its trip through the request log. This
    /// is not hypothetical: a measured test run wrote the live token into the
    /// server log four times before [`log_safe_uri`] existed.
    #[test]
    fn a_reset_token_is_redacted_from_a_logged_uri() {
        let token = "5d5b56a584d753f29f940ab7dde302eaae2e773473ce1812a418275cfb6c0771";
        let uri: axum::http::Uri = format!("/reset?token={token}").parse().unwrap();

        let logged = log_safe_uri(&uri);
        assert!(!logged.contains(token), "the token survived: {logged}");
        assert_eq!(logged, "/reset?token=<redacted>");
    }

    #[test]
    fn everything_else_about_a_uri_is_kept() {
        let plain: axum::http::Uri = "/api/files/local".parse().unwrap();
        assert_eq!(log_safe_uri(&plain), "/api/files/local");

        let mixed: axum::http::Uri = "/x?path=/tmp/a&token=secret&depth=2".parse().unwrap();
        assert_eq!(log_safe_uri(&mixed), "/x?path=/tmp/a&token=<redacted>&depth=2");

        // Case is not a hiding place.
        let upper: axum::http::Uri = "/x?TOKEN=secret".parse().unwrap();
        assert_eq!(log_safe_uri(&upper), "/x?TOKEN=<redacted>");

        // A parameter that merely ends in "token" is a different parameter.
        let other: axum::http::Uri = "/x?next_token=abc".parse().unwrap();
        assert_eq!(log_safe_uri(&other), "/x?next_token=abc");
    }
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    /// Everything in one test on purpose: `RCLONE_GUI_BIND` is process-wide
    /// state, and cargo runs tests of a module on several threads. Two tests
    /// setting and clearing the same variable would flake against each other.
    #[test]
    fn bind_precedence_is_argument_then_variable_then_default() {
        // No variable, no argument: the loopback default.
        env::remove_var(BIND_ENV);
        assert_eq!(
            resolve_bind_address(None),
            (BIND_DEFAULT.to_string(), "default")
        );

        // Variable alone: it takes effect. This is the whole point of the
        // ticket — it used to be printed and ignored.
        env::set_var(BIND_ENV, "0.0.0.0:9000");
        assert_eq!(
            resolve_bind_address(None),
            ("0.0.0.0:9000".to_string(), "from RCLONE_GUI_BIND")
        );

        // Argument against variable: **the argument wins.** If this ever flips,
        // every agent's `--bind 127.0.1.<n>:<port>` test server silently moves
        // to whatever a stray `.env` says, and parallel runs start overwriting
        // each other's session cookies.
        assert_eq!(
            resolve_bind_address(Some("127.0.1.9:8099")),
            ("127.0.1.9:8099".to_string(), "from --bind")
        );

        // An empty or blank variable is "unset", the way one comments a line
        // out in a `.env`. It must not become a parse error further down.
        env::set_var(BIND_ENV, "");
        assert_eq!(
            resolve_bind_address(None),
            (BIND_DEFAULT.to_string(), "default")
        );
        env::set_var(BIND_ENV, "   ");
        assert_eq!(
            resolve_bind_address(None),
            (BIND_DEFAULT.to_string(), "default")
        );

        // Surrounding whitespace is trimmed, not passed to the parser.
        env::set_var(BIND_ENV, "  127.0.0.1:8081\n");
        assert_eq!(
            resolve_bind_address(None),
            ("127.0.0.1:8081".to_string(), "from RCLONE_GUI_BIND")
        );

        env::remove_var(BIND_ENV);
    }

    /// The default must not be reachable from outside the machine. A typo that
    /// turns it into `0.0.0.0` would expose an unconfigured start to the
    /// network, and nothing else in the code would complain.
    #[test]
    fn the_default_is_loopback_only() {
        let addr: SocketAddr = BIND_DEFAULT.parse().expect("default must parse");
        assert!(
            addr.ip().is_loopback(),
            "default bind address {BIND_DEFAULT} is not loopback"
        );
    }
}
