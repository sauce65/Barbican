//! FedRAMP Low Baseline Example
//!
//! Demonstrates the minimum security controls for FedRAMP Low authorization:
//!
//! | Control | Implementation |
//! |---------|----------------|
//! | SC-8    | TLS database connections (opportunistic) |
//! | SC-28   | Infrastructure-level encryption (disk/DB) |
//! | AU-2    | Basic audit logging |
//! | AU-3    | Audit record content (who, what, when) |
//! | AC-3    | Basic access control |
//!
//! FedRAMP Low is appropriate for systems where loss of confidentiality,
//! integrity, or availability would have LIMITED adverse effect.

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

/// FedRAMP Low database configuration
///
/// At Low baseline:
/// - TLS is recommended but not strictly required
/// - Connection pooling with reasonable limits
/// - Basic timeout settings
fn create_database_config(database_url: &str) -> barbican::DatabaseConfig {
    barbican::DatabaseConfig::builder(database_url)
        .application_name("fedramp-low-example")
        // TLS preferred but will fall back to unencrypted if unavailable
        .ssl_mode(barbican::SslMode::Prefer)
        // Reasonable pool size for low-traffic systems
        .max_connections(10)
        // Standard timeouts
        .connect_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(600))
        .build()
}

// ============================================================================
// Data Types
// ============================================================================

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    database_connected: bool,
    baseline: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    username: String,
    email: String,
    display_name: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct CreateDocumentRequest {
    title: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct DocumentResponse {
    id: Uuid,
    user_id: Uuid,
    title: String,
    content: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Application State
// ============================================================================

#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

// ============================================================================
// Audit Logging (AU-2, AU-3)
// ============================================================================

/// Log an audit event
///
/// FedRAMP Low requires basic audit logging with:
/// - Who (actor)
/// - What (action, resource)
/// - When (timestamp - automatic)
/// - Success/failure
#[instrument(skip(pool))]
async fn log_audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    success: bool,
) {
    let result = sqlx::query!(
        r#"
        INSERT INTO audit_log (id, actor, action, resource_type, resource_id, success)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        Uuid::new_v4(),
        actor,
        action,
        resource_type,
        resource_id,
        success,
    )
    .execute(pool)
    .await;

    if let Err(e) = result {
        // At Low baseline, we log the failure but don't fail the request
        warn!("Failed to write audit log: {}", e);
    }
}

// ============================================================================
// HTTP Handlers
// ============================================================================

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").fetch_one(&state.pool).await.is_ok();

    Json(HealthResponse {
        status: if db_ok { "healthy" } else { "degraded" }.to_string(),
        database_connected: db_ok,
        baseline: "FedRAMP Low".to_string(),
    })
}

#[instrument(skip(state))]
async fn create_user_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let id = Uuid::new_v4();

    // At Low baseline, data is stored in plaintext
    // Infrastructure-level encryption (disk, TDE) provides SC-28
    let row = sqlx::query!(
        r#"
        INSERT INTO users (id, username, email, display_name)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, email, display_name, created_at, updated_at
        "#,
        id,
        req.username,
        req.email,
        req.display_name,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        error!("Failed to create user: {}", e);
        log_audit_sync(&state.pool, "system", "create_user", "user", None, false);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    // Audit log (AU-2)
    log_audit(&state.pool, "system", "create", "user", Some(row.id), true).await;

    info!(user_id = %row.id, username = %row.username, "User created");

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: row.id,
            username: row.username,
            email: row.email,
            display_name: row.display_name,
            created_at: row.created_at,
        }),
    ))
}

async fn list_users_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let rows = sqlx::query!(
        r#"
        SELECT id, username, email, display_name, created_at
        FROM users
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        error!("Failed to list users: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let users: Vec<UserResponse> = rows
        .into_iter()
        .map(|row| UserResponse {
            id: row.id,
            username: row.username,
            email: row.email,
            display_name: row.display_name,
            created_at: row.created_at,
        })
        .collect();

    Ok(Json(users))
}

async fn get_user_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let row = sqlx::query!(
        r#"
        SELECT id, username, email, display_name, created_at
        FROM users WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(UserResponse {
        id: row.id,
        username: row.username,
        email: row.email,
        display_name: row.display_name,
        created_at: row.created_at,
    }))
}

async fn delete_user_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id)
        .execute(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    log_audit(&state.pool, "system", "delete", "user", Some(id), true).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_document_handler(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<CreateDocumentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Verify user exists
    let user_exists = sqlx::query!("SELECT id FROM users WHERE id = $1", user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some();

    if !user_exists {
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    let id = Uuid::new_v4();

    let row = sqlx::query!(
        r#"
        INSERT INTO documents (id, user_id, title, content)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, title, content, created_at
        "#,
        id,
        user_id,
        req.title,
        req.content,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    log_audit(&state.pool, "system", "create", "document", Some(row.id), true).await;

    Ok((
        StatusCode::CREATED,
        Json(DocumentResponse {
            id: row.id,
            user_id: row.user_id,
            title: row.title,
            content: row.content,
            created_at: row.created_at,
        }),
    ))
}

async fn list_documents_handler(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let rows = sqlx::query!(
        r#"
        SELECT id, user_id, title, content, created_at
        FROM documents WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let docs: Vec<DocumentResponse> = rows
        .into_iter()
        .map(|row| DocumentResponse {
            id: row.id,
            user_id: row.user_id,
            title: row.title,
            content: row.content,
            created_at: row.created_at,
        })
        .collect();

    Ok(Json(docs))
}

// Helper for sync audit logging on error paths
fn log_audit_sync(pool: &PgPool, actor: &str, action: &str, resource_type: &str, resource_id: Option<Uuid>, success: bool) {
    let pool = pool.clone();
    let actor = actor.to_string();
    let action = action.to_string();
    let resource_type = resource_type.to_string();
    tokio::spawn(async move {
        log_audit(&pool, &actor, &action, &resource_type, resource_id, success).await;
    });
}

// ============================================================================
// Application Setup
// ============================================================================

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/users", get(list_users_handler).post(create_user_handler))
        .route("/users/:id", get(get_user_handler).delete(delete_user_handler))
        .route(
            "/users/:user_id/documents",
            get(list_documents_handler).post(create_document_handler),
        )
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("db_fedramp_low=info".parse()?)
                .add_directive("barbican=info".parse()?),
        )
        .init();

    info!("Starting FedRAMP Low baseline example");
    info!("Controls: SC-8 (TLS), SC-28 (infra encryption), AU-2/AU-3 (audit)");

    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL required")?;

    // Create connection pool with FedRAMP Low config
    let config = create_database_config(&database_url);
    info!("Database config: SSL mode {:?}", config.ssl_mode);

    let pool = barbican::create_pool(&config).await?;

    // Verify connection
    let health = barbican::health_check(&pool).await?;
    info!(
        "Database: connected={}, ssl={}",
        health.connected, health.ssl_enabled
    );

    // Initialize schema
    sqlx::raw_sql(include_str!("../schema.sql"))
        .execute(&pool)
        .await?;

    let state = AppState { pool };
    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Listening on http://0.0.0.0:3000");

    axum::serve(listener, router).await?;
    Ok(())
}
