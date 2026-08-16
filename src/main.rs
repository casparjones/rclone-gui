use axum::{
    extract::{Path, Request},
    middleware::{self, Next},
    response::Html,
    routing::{delete, get, post},
    Extension, Router,
};
use chrono;
use clap::Parser;
use dotenvy::{dotenv, from_filename_override};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
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
    #[arg(
        long,
        default_value = "127.0.0.1:8080",
        help = "Address to bind the server to"
    )]
    bind: String,
    #[arg(long, help = "Start a task by name and exit")]
    start_task: Option<String>,
    #[arg(
        long,
        help = "User name the CLI run is attributed to (required with --start-task when more than one account exists)"
    )]
    user: Option<String>,
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

    println!("⚙️  Command line arguments:");
    println!("   Memory mode: {}", args.memory_mode);
    println!("   Bind address: {}", args.bind);
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
    println!("   GET    /api/download/file             -> download_file");
    println!("   GET    /api/download/zip              -> download_zip");
    println!("   GET    /api/thumb                     -> get_thumbnail");
    println!("   GET    /api/preview/info              -> preview_info");
    println!("   GET    /api/preview/text              -> preview_text");
    println!("   GET    /api/preview/image             -> preview_image");
    println!("   POST   /api/sync                      -> start_sync");
    println!("   GET    /api/sync                      -> list_sync_jobs");
    println!("   GET    /api/sync-log/:job_id          -> get_sync_log (temp route)");
    println!("   DELETE /api/sync-delete/:job_id       -> delete_sync_job (temp route)");
    println!("   GET    /api/sync/:job_id/log          -> get_sync_log");
    println!("   GET    /api/sync/:job_id              -> get_sync_progress");
    println!("   DELETE /api/sync/:job_id              -> delete_sync_job");
    println!("   GET    /api/tasks                     -> get_tasks");
    println!("   POST   /api/tasks                     -> create_task");
    println!("   DELETE /api/tasks/:task_id            -> delete_task");
    println!("   POST   /api/tasks/start               -> start_task");
    println!("   GET    /api/rsyncd/status             -> rsyncd_status");
    println!("   GET    /login                         -> login_page            [public]");
    println!("   POST   /login                         -> login_form_submit     [public]");
    println!("   POST   /api/auth/login                -> login_json_submit     [public]");
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
        .route("/api/download/file", get(handlers::download::download_file))
        .route("/api/download/zip", get(handlers::download::download_zip))
        .route("/api/thumb", get(handlers::thumbs::get_thumbnail))
        .route("/api/preview/info", get(handlers::preview::preview_info))
        .route("/api/preview/text", get(handlers::preview::preview_text))
        .route("/api/preview/image", get(handlers::preview::preview_image))
        .route("/api/sync", post(handlers::sync::start_sync))
        .route("/api/sync", get(handlers::sync::list_sync_jobs))
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
        .layer(TraceLayer::new_for_http())
        .layer(Extension(config_manager))
        .layer(Extension(db_pool))
        .layer(Extension(rsyncd.clone()))
        .layer(ServiceBuilder::new().layer(CorsLayer::permissive()));

    let addr: SocketAddr = args.bind.parse().expect("Invalid bind address");

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

    // Setup graceful shutdown
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        println!("");
        println!("🛑 Shutdown signal received");
        println!("🔄 Gracefully shutting down server...");
    };

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .unwrap();

    // After the server, not inside the shutdown signal: the daemon has to
    // outlive the last request that might still be using it. `shutdown` sends
    // SIGTERM and waits for the process to be gone, so no daemon survives this
    // process — and it is SIGTERM rather than SIGKILL because a hard kill
    // leaves partial `.name.XXXXXX` files behind in the shares.
    if let Some(daemon) = rsyncd {
        println!("🔄 Stopping the rsync daemon...");
        daemon.shutdown().await;
        println!("   ✅ rsync daemon stopped");
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

async fn get_sync_progress_handler(
    Path(job_id): Path<String>,
) -> axum::response::Json<models::ApiResponse<models::SyncProgress>> {
    handlers::sync::get_sync_progress(job_id).await
}

async fn get_sync_log_handler(
    Path(job_id): Path<String>,
) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::sync::get_sync_log(job_id).await
}

async fn delete_sync_job_handler(
    Path(job_id): Path<String>,
) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::sync::delete_sync_job(job_id).await
}

async fn get_config_for_edit_handler(
    Extension(config_manager): Extension<Arc<config_manager::ConfigManager>>,
    Path(name): Path<String>,
) -> axum::response::Json<models::ApiResponse<models::RcloneConfig>> {
    handlers::config::get_config_for_edit(Extension(config_manager), name).await
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
/// wrong trade. The failure is visible at `/api/rsyncd/status`.
async fn start_rsync_daemon() -> Option<Arc<handlers::rsyncd::DaemonHandle>> {
    if env::var("RCLONE_GUI_RSYNCD").unwrap_or_default() != "1" {
        return None;
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
            println!(
                "   ✅ rsync daemon listening on {}:{} (pid {})",
                status.address,
                status.port,
                status.pid.unwrap_or(0)
            );
            println!();
            Some(handle)
        }
        Err(e) => {
            eprintln!("   ❌ the rsync daemon did not start: {}", e);
            eprintln!("      the server continues without the rsync transport");
            println!();
            None
        }
    }
}

/// Whether the daemon is running, where, and which modules it serves.
async fn rsyncd_status_handler(
    Extension(daemon): Extension<Option<Arc<handlers::rsyncd::DaemonHandle>>>,
) -> axum::response::Json<models::ApiResponse<handlers::rsyncd::DaemonStatus>> {
    match daemon {
        Some(daemon) => axum::response::Json(models::ApiResponse {
            success: true,
            data: Some(daemon.status().await),
            error: None,
        }),
        // Switched off is not an error: the configuration display shows "not
        // running" rather than a failure the user cannot act on.
        None => axum::response::Json(models::ApiResponse {
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

async fn serve_index() -> axum::response::Response {
    use axum::response::IntoResponse;

    let default_path =
        env::var("RCLONE_GUI_DEFAULT_PATH").unwrap_or_else(|_| "/mnt/home".to_string());
    println!("🏠 Using default path: {}", default_path);

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

    if let Ok(bind_addr) = env::var("RCLONE_GUI_BIND") {
        println!("   🌐 Custom bind address: {}", bind_addr);
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
async fn request_logging_middleware(req: Request, next: Next) -> axum::response::Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
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
    use axum::extract::Json;

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
    let sync_request = SyncRequest {
        source_path: task.source_path,
        remote_name: task.remote_name,
        remote_path: task.remote_path,
        chunk_size: task.chunk_size,
        use_chunking: Some(task.use_chunking),
    };

    // Start the sync job
    let job_response = handlers::sync::start_sync(Json(sync_request)).await;
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
