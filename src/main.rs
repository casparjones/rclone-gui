use axum::{
    extract::{Path, Request},
    routing::{get, post, delete},
    Router,
    Extension,
    response::Html,
    middleware::{self, Next},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use tracing;
use clap::Parser;
use std::env;
use dotenvy::{dotenv, from_filename_override};
use chrono;

mod handlers;
mod models;
mod config_manager;

#[derive(Parser)]
#[command(name = "rclone-gui")]
#[command(about = "A web GUI for rclone")]
struct Args {
    #[arg(long, help = "Use in-memory configuration (changes not saved to file until explicitly saved)")]
    memory_mode: bool,
    #[arg(long, default_value = "127.0.0.1:8080", help = "Address to bind the server to")]
    bind: String,
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
    println!("");

    let config_manager = Arc::new(config_manager::ConfigManager::new(args.memory_mode));
    
    if args.memory_mode {
        println!("💾 Running in memory mode:");
        println!("   ⚠️  Configurations will not be saved to file automatically");
        println!("   📥 Loading existing configs from file into memory...");
        
        // Load existing configs from file into memory
        if let Err(e) = config_manager.load_from_file_to_memory().await {
            eprintln!("   ❌ Warning: Could not load existing configs from file: {}", e);
        } else {
            println!("   ✅ Existing configs loaded successfully");
        }
        println!("");
    } else {
        println!("💾 Running in persistent mode:");
        println!("   ✅ Configurations will be saved to file automatically");
        println!("");
    }

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
    println!("   POST   /api/sync                      -> start_sync");
    println!("   GET    /api/sync                      -> list_sync_jobs");
    println!("   GET    /api/sync-log/:job_id          -> get_sync_log (temp route)");
    println!("   DELETE /api/sync-delete/:job_id       -> delete_sync_job (temp route)");
    println!("   GET    /api/sync/:job_id/log          -> get_sync_log");
    println!("   GET    /api/sync/:job_id              -> get_sync_progress");
    println!("   DELETE /api/sync/:job_id              -> delete_sync_job");
    println!("   STATIC /static/*                      -> serve static files");
    println!("");

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/configs", get(handlers::config::get_configs))
        .route("/api/configs", post(handlers::config::save_config))
        .route("/api/configs/:name", delete(delete_config_handler))
        .route("/api/configs/:name/edit", get(get_config_for_edit_handler))
        .route("/api/configs/persist", post(handlers::config::persist_configs))
        .route("/api/files/local", get(handlers::files::list_local_files))
        .route("/api/files/remote", get(handlers::files::list_remote_files))
        .route("/api/sync", post(handlers::sync::start_sync))
        .route("/api/sync", get(handlers::sync::list_sync_jobs))
        .route("/api/sync-log/:job_id", get(get_sync_log_handler))
        .route("/api/sync-delete/:job_id", delete(delete_sync_job_handler))
        .route("/api/sync/:job_id/log", get(get_sync_log_handler))
        .route("/api/sync/:job_id", get(get_sync_progress_handler))
        .route("/api/sync/:job_id", delete(delete_sync_job_handler))
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn(request_logging_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(config_manager))
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
        );

    let addr: SocketAddr = args.bind.parse().expect("Invalid bind address");
    
    println!("🌐 Starting server...");
    println!("   📍 Binding to: {}", addr);
    println!("   🔗 URL: http://{}", addr);
    println!("   📁 Serving static files from: ./static/");
    println!("   📊 Request logging: enabled");
    println!("");
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("✅ Server successfully started and listening on http://{}", addr);
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
        
    println!("✅ Server shutdown completed");
    println!("👋 Goodbye!");
}

async fn delete_config_handler(
    Extension(config_manager): Extension<Arc<config_manager::ConfigManager>>,
    Path(name): Path<String>,
) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::config::delete_config(Extension(config_manager), name).await
}

async fn get_sync_progress_handler(Path(job_id): Path<String>) -> axum::response::Json<models::ApiResponse<models::SyncProgress>> {
    handlers::sync::get_sync_progress(job_id).await
}

async fn get_sync_log_handler(Path(job_id): Path<String>) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::sync::get_sync_log(job_id).await
}

async fn delete_sync_job_handler(Path(job_id): Path<String>) -> axum::response::Json<models::ApiResponse<String>> {
    handlers::sync::delete_sync_job(job_id).await
}

async fn get_config_for_edit_handler(
    Extension(config_manager): Extension<Arc<config_manager::ConfigManager>>,
    Path(name): Path<String>,
) -> axum::response::Json<models::ApiResponse<models::RcloneConfig>> {
    handlers::config::get_config_for_edit(Extension(config_manager), name).await
}

async fn serve_index() -> Html<String> {
    let default_path = env::var("RCLONE_GUI_DEFAULT_PATH").unwrap_or_else(|_| "/mnt/home".to_string());
    println!("🏠 Using default path: {}", default_path);
    
    let html_content = std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| include_str!("../static/index.html").to_string());
    
    let js_content = std::fs::read_to_string("static/app.js")
        .unwrap_or_else(|_| include_str!("../static/app.js").to_string());
    
    let modified_html = html_content.replace(
        "<script src=\"app.js\"></script>",
        &format!(
            "<script>window.DEFAULT_PATH = '{}';</script>\n    <script>{}</script>",
            default_path, js_content
        )
    );
    
    Html(modified_html)
}

/// Load environment configuration with detailed feedback
fn load_environment_config() {
    println!("🚀 Starting Rclone GUI...");
    println!("📁 Working directory: {}", env::current_dir().unwrap_or_default().display());
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
            println!("   ℹ️  .env.local not found (create from .env.local.example for local settings)");
            false
        }
    };

    // Show current effective configuration
    let current_path = env::var("RCLONE_GUI_DEFAULT_PATH")
        .unwrap_or_else(|_| "/mnt/home".to_string());
    
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
                            eprintln!("Warning: Could not remove orphaned log file {:?}: {}", path, e);
                        } else {
                            removed_count += 1;
                            println!("🧹 Removed orphaned log file: {:?}", path.file_name().unwrap_or_default());
                        }
                    }
                }
            }
            
            if removed_count > 0 {
                println!("🗑️  Cleaned up {} orphaned log files from previous runs", removed_count);
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
    println!("📨 {} {} from {} at {}", 
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
    
    println!("📤 {} {} {} - {}ms", 
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
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_file(false)
                .with_line_number(false)
                .compact()
        )
        .init();
        
    tracing::info!("🔍 Tracing initialized");
}