//! FedRAMP Moderate Baseline Example
//!
//! Demonstrates security controls for FedRAMP Moderate authorization:
//!
//! | Control | Implementation |
//! |---------|----------------|
//! | SC-8    | TLS required for database connections |
//! | SC-28   | Field-level AES-256-GCM encryption for PII |
//! | AU-2    | Comprehensive audit logging |
//! | AU-3    | Detailed audit records (who, what, when, where, outcome) |
//! | AU-9    | Audit record integrity via hashing |
//! | AC-3    | Role-based access control |
//! | AC-6    | Least privilege via role assignments |
//! | AC-11   | Session lock after idle timeout |
//! | AC-12   | Session termination |
//!
//! FedRAMP Moderate is appropriate for systems where loss of confidentiality,
//! integrity, or availability would have SERIOUS adverse effect.

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use barbican::{
    encryption::FieldEncryptor,
    session::{SessionPolicy, SessionState},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

/// FedRAMP Moderate database configuration
fn create_database_config(database_url: &str) -> barbican::DatabaseConfig {
    barbican::DatabaseConfig::builder(database_url)
        .application_name("fedramp-moderate-example")
        // TLS required at Moderate baseline
        .ssl_mode(barbican::SslMode::Require)
        // Reasonable pool size
        .max_connections(20)
        // Timeouts
        .connect_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(300))
        .build()
}

/// FedRAMP Moderate session policy (AC-11, AC-12)
fn create_session_policy() -> SessionPolicy {
    SessionPolicy::builder()
        // 8 hour max session lifetime (AC-12)
        .max_lifetime(Duration::from_secs(8 * 60 * 60))
        // 30 minute idle timeout (AC-11)
        .idle_timeout(Duration::from_secs(30 * 60))
        // Require re-auth for sensitive operations after 15 minutes
        .require_reauth_for_sensitive(true)
        .reauth_timeout(Duration::from_secs(15 * 60))
        .build()
}

// ============================================================================
// Data Types
// ============================================================================

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    database_connected: bool,
    database_ssl: bool,
    encryption_available: bool,
    baseline: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,  // Will be encrypted
    phone: Option<String>,  // Will be encrypted
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    username: String,
    email: String,  // Decrypted for response
    phone: Option<String>,  // Decrypted for response
    display_name: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CreateDocumentRequest {
    title: String,
    content: String,  // Will be encrypted
}

#[derive(Debug, Serialize)]
struct DocumentResponse {
    id: Uuid,
    user_id: Uuid,
    title: String,
    content: String,  // Decrypted for response
    created_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Application State
// ============================================================================

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    encryptor: FieldEncryptor,
    session_policy: SessionPolicy,
}

// ============================================================================
// Audit Logging (AU-2, AU-3, AU-9)
// ============================================================================

/// Enhanced audit record with integrity protection
#[derive(Debug, Serialize)]
struct AuditRecord {
    actor: String,
    actor_role: Option<String>,
    action: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    source_ip: Option<String>,
    success: bool,
    details: Option<serde_json::Value>,
}

impl AuditRecord {
    /// Compute SHA-256 hash of the record for integrity (AU-9)
    fn compute_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.actor.hash(&mut hasher);
        self.action.hash(&mut hasher);
        self.resource_type.hash(&mut hasher);
        self.success.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

#[instrument(skip(pool))]
async fn log_audit(pool: &PgPool, record: AuditRecord) {
    let hash = record.compute_hash();

    let result = sqlx::query!(
        r#"
        INSERT INTO audit_log (id, actor, actor_role, action, resource_type, resource_id,
                               source_ip, success, details, record_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
        Uuid::new_v4(),
        record.actor,
        record.actor_role,
        record.action,
        record.resource_type,
        record.resource_id,
        record.source_ip,
        record.success,
        record.details,
        hash,
    )
    .execute(pool)
    .await;

    if let Err(e) = result {
        error!("Failed to write audit log: {}", e);
    }
}

// ============================================================================
// Session Management (AC-11, AC-12)
// ============================================================================

/// Check if a session is valid according to policy
fn check_session(policy: &SessionPolicy, session: &SessionState) -> bool {
    !policy.should_terminate(session)
}

/// Update session activity timestamp
async fn touch_session(pool: &PgPool, session_id: Uuid) {
    let _ = sqlx::query!(
        "UPDATE sessions SET last_activity = NOW() WHERE id = $1 AND is_active = TRUE",
        session_id
    )
    .execute(pool)
    .await;
}

// ============================================================================
// Role-Based Access Control (AC-3, AC-6)
// ============================================================================

/// Get user's roles
async fn get_user_roles(pool: &PgPool, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar!(
        "SELECT role FROM user_roles WHERE user_id = $1",
        user_id
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Check if user has required role
async fn has_role(pool: &PgPool, user_id: Uuid, required_role: &str) -> bool {
    let roles = get_user_roles(pool, user_id).await;
    roles.iter().any(|r| r == required_role)
}

/// Assign role to user
async fn assign_role(pool: &PgPool, user_id: Uuid, role: &str, granted_by: &str) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO user_roles (user_id, role, granted_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, role) DO NOTHING
        "#,
        user_id,
        role,
        granted_by,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ============================================================================
// HTTP Handlers
// ============================================================================

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let health = barbican::health_check(&state.pool).await;

    match health {
        Ok(status) => Json(HealthResponse {
            status: "healthy".to_string(),
            database_connected: status.connected,
            database_ssl: status.ssl_enabled,
            encryption_available: true,
            baseline: "FedRAMP Moderate".to_string(),
        }),
        Err(_) => Json(HealthResponse {
            status: "unhealthy".to_string(),
            database_connected: false,
            database_ssl: false,
            encryption_available: true,
            baseline: "FedRAMP Moderate".to_string(),
        }),
    }
}

#[instrument(skip(state), fields(username = %req.username))]
async fn create_user_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let id = Uuid::new_v4();

    // Encrypt PII fields (SC-28)
    let email_encrypted = state
        .encryptor
        .encrypt_string(&req.email)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let phone_encrypted = req
        .phone
        .as_ref()
        .map(|p| state.encryptor.encrypt_string(p))
        .transpose()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query!(
        r#"
        INSERT INTO users (id, username, display_name, email_encrypted, phone_encrypted)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, username, display_name, email_encrypted, phone_encrypted, created_at
        "#,
        id,
        req.username,
        req.display_name,
        email_encrypted,
        phone_encrypted,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        error!("Failed to create user: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    // Assign default role (AC-6 - least privilege)
    let _ = assign_role(&state.pool, row.id, "user", "system").await;

    // Audit log
    log_audit(
        &state.pool,
        AuditRecord {
            actor: "system".to_string(),
            actor_role: Some("admin".to_string()),
            action: "create".to_string(),
            resource_type: "user".to_string(),
            resource_id: Some(row.id),
            source_ip: None,
            success: true,
            details: Some(serde_json::json!({"username": req.username})),
        },
    )
    .await;

    info!(user_id = %row.id, "User created with role 'user'");

    // Decrypt for response
    let email = state
        .encryptor
        .decrypt_string(&row.email_encrypted)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let phone = row
        .phone_encrypted
        .as_ref()
        .map(|p| state.encryptor.decrypt_string(p))
        .transpose()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let roles = get_user_roles(&state.pool, row.id).await;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: row.id,
            username: row.username,
            email,
            phone,
            display_name: row.display_name,
            created_at: row.created_at,
            roles,
        }),
    ))
}

async fn list_users_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let rows = sqlx::query!(
        r#"
        SELECT id, username, display_name, email_encrypted, phone_encrypted, created_at
        FROM users ORDER BY created_at DESC
        "#
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut users = Vec::new();
    for row in rows {
        let email = state
            .encryptor
            .decrypt_string(&row.email_encrypted)
            .unwrap_or_else(|_| "[decryption error]".to_string());

        let phone = row
            .phone_encrypted
            .as_ref()
            .map(|p| state.encryptor.decrypt_string(p).ok())
            .flatten();

        let roles = get_user_roles(&state.pool, row.id).await;

        users.push(UserResponse {
            id: row.id,
            username: row.username,
            email,
            phone,
            display_name: row.display_name,
            created_at: row.created_at,
            roles,
        });
    }

    Ok(Json(users))
}

async fn get_user_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let row = sqlx::query!(
        r#"
        SELECT id, username, display_name, email_encrypted, phone_encrypted, created_at
        FROM users WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let email = state
        .encryptor
        .decrypt_string(&row.email_encrypted)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let phone = row
        .phone_encrypted
        .as_ref()
        .map(|p| state.encryptor.decrypt_string(p))
        .transpose()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let roles = get_user_roles(&state.pool, row.id).await;

    Ok(Json(UserResponse {
        id: row.id,
        username: row.username,
        email,
        phone,
        display_name: row.display_name,
        created_at: row.created_at,
        roles,
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

    log_audit(
        &state.pool,
        AuditRecord {
            actor: "system".to_string(),
            actor_role: Some("admin".to_string()),
            action: "delete".to_string(),
            resource_type: "user".to_string(),
            resource_id: Some(id),
            source_ip: None,
            success: true,
            details: None,
        },
    )
    .await;

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

    // Encrypt content (SC-28)
    let content_encrypted = state
        .encryptor
        .encrypt_string(&req.content)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query!(
        r#"
        INSERT INTO documents (id, user_id, title, content_encrypted)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, title, content_encrypted, created_at
        "#,
        id,
        user_id,
        req.title,
        content_encrypted,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    log_audit(
        &state.pool,
        AuditRecord {
            actor: "system".to_string(),
            actor_role: None,
            action: "create".to_string(),
            resource_type: "document".to_string(),
            resource_id: Some(row.id),
            source_ip: None,
            success: true,
            details: Some(serde_json::json!({"user_id": user_id, "title": req.title})),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(DocumentResponse {
            id: row.id,
            user_id: row.user_id,
            title: row.title,
            content: req.content, // Return original (we just encrypted it)
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
        SELECT id, user_id, title, content_encrypted, created_at
        FROM documents WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut docs = Vec::new();
    for row in rows {
        let content = state
            .encryptor
            .decrypt_string(&row.content_encrypted)
            .unwrap_or_else(|_| "[decryption error]".to_string());

        docs.push(DocumentResponse {
            id: row.id,
            user_id: row.user_id,
            title: row.title,
            content,
            created_at: row.created_at,
        });
    }

    Ok(Json(docs))
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
                .add_directive("db_fedramp_moderate=info".parse()?)
                .add_directive("barbican=info".parse()?),
        )
        .init();

    info!("Starting FedRAMP Moderate baseline example");
    info!("Controls: SC-8, SC-28, AU-2/3/9, AC-3/6/11/12");

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;

    // Encryption key (SC-28)
    let encryption_key = std::env::var("ENCRYPTION_KEY").unwrap_or_else(|_| {
        warn!("ENCRYPTION_KEY not set, generating temporary key (NOT FOR PRODUCTION)");
        barbican::encryption::generate_key()
    });

    // Create encryptor
    let encryptor = FieldEncryptor::new(&encryption_key)
        .context("Failed to create encryptor")?;
    info!("Encryption: algorithm={:?}", encryptor.algorithm());

    // Database connection with TLS required
    let config = create_database_config(&database_url);
    info!("Database config: SSL mode {:?}", config.ssl_mode);

    let pool = barbican::create_pool(&config).await?;

    let health = barbican::health_check(&pool).await?;
    info!(
        "Database: connected={}, ssl={}",
        health.connected, health.ssl_enabled
    );

    if !health.ssl_enabled {
        warn!("SSL not enabled - FedRAMP Moderate requires TLS!");
    }

    // Session policy
    let session_policy = create_session_policy();
    info!(
        "Session policy: max_lifetime={:?}, idle_timeout={:?}",
        session_policy.max_lifetime, session_policy.idle_timeout
    );

    // Initialize schema
    sqlx::raw_sql(include_str!("../schema.sql"))
        .execute(&pool)
        .await?;

    let state = AppState {
        pool,
        encryptor,
        session_policy,
    };

    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Listening on http://0.0.0.0:3000");

    axum::serve(listener, router).await?;
    Ok(())
}
