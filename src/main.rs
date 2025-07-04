use axum::{
    extract::Path,
    routing::{get, post, delete},
    Router,
    Extension,
    response::Html,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
};
use tracing_subscriber;
use clap::Parser;
use std::env;
use dotenvy::{dotenv, from_filename_override};

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
    
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let config_manager = Arc::new(config_manager::ConfigManager::new(args.memory_mode));
    
    if args.memory_mode {
        println!("Running in memory mode - configurations will not be saved to file automatically");
        // Load existing configs from file into memory
        if let Err(e) = config_manager.load_from_file_to_memory().await {
            eprintln!("Warning: Could not load existing configs from file: {}", e);
        }
    }

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
        .layer(Extension(config_manager))
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
        );

    let addr: SocketAddr = args.bind.parse().expect("Invalid bind address");
    println!("Server running on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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