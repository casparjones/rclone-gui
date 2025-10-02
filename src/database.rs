use sqlx::{Pool, Sqlite, SqlitePool};
use anyhow::Result;
use crate::models::Task;
use tracing::info;

pub async fn init_database() -> Result<Pool<Sqlite>> {
    // Create data directory if it doesn't exist
    tokio::fs::create_dir_all("data").await?;
    
    let database_url = "sqlite:data/tasks.db?mode=rwc";
    let pool = SqlitePool::connect(database_url).await?;
    
    // Create tasks table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            source_path TEXT NOT NULL,
            remote_name TEXT NOT NULL,
            remote_path TEXT NOT NULL,
            chunk_size TEXT,
            use_chunking BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    "#)
    .execute(&pool)
    .await?;
    
    info!("✅ Database initialized successfully");
    Ok(pool)
}

pub async fn create_task(pool: &Pool<Sqlite>, task: &Task) -> Result<()> {
    sqlx::query(r#"
        INSERT INTO tasks (id, name, source_path, remote_name, remote_path, chunk_size, use_chunking, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    "#)
    .bind(&task.id)
    .bind(&task.name)
    .bind(&task.source_path)
    .bind(&task.remote_name)
    .bind(&task.remote_path)
    .bind(&task.chunk_size)
    .bind(task.use_chunking)
    .bind(task.created_at)
    .execute(pool)
    .await?;
    
    Ok(())
}

pub async fn get_all_tasks(pool: &Pool<Sqlite>) -> Result<Vec<Task>> {
    let tasks = sqlx::query_as::<_, Task>(r#"
        SELECT id, name, source_path, remote_name, remote_path, chunk_size, use_chunking, created_at
        FROM tasks
        ORDER BY created_at DESC
    "#)
    .fetch_all(pool)
    .await?;
    
    Ok(tasks)
}

pub async fn get_task_by_name(pool: &Pool<Sqlite>, name: &str) -> Result<Option<Task>> {
    let task = sqlx::query_as::<_, Task>(r#"
        SELECT id, name, source_path, remote_name, remote_path, chunk_size, use_chunking, created_at
        FROM tasks
        WHERE name = ?
    "#)
    .bind(name)
    .fetch_optional(pool)
    .await?;
    
    Ok(task)
}

pub async fn delete_task(pool: &Pool<Sqlite>, task_id: &str) -> Result<bool> {
    let result = sqlx::query(r#"
        DELETE FROM tasks WHERE id = ?
    "#)
    .bind(task_id)
    .execute(pool)
    .await?;
    
    Ok(result.rows_affected() > 0)
}

pub async fn task_name_exists(pool: &Pool<Sqlite>, name: &str) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(r#"
        SELECT COUNT(*) FROM tasks WHERE name = ?
    "#)
    .bind(name)
    .fetch_one(pool)
    .await?;
    
    Ok(count.0 > 0)
}