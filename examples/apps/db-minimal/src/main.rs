//! Barbican db-minimal Example
//!
//! Demonstrates secure PostgreSQL with Barbican's NixOS modules and field-level
//! encryption. Uses compile-time checked SQL queries via sqlx.
//!
//! # Development Setup
//!
//! ```bash
//! # Enter development shell (starts PostgreSQL automatically)
//! nix develop
//!
//! # Set encryption key
//! export ENCRYPTION_KEY=$(openssl rand -hex 32)
//!
//! # Run the application
//! cargo run
//! ```
//!
//! # Production Deployment
//!
//! Import the flake module in your NixOS configuration:
//!
//! ```nix
//! {
//!   imports = [ db-minimal.nixosModules.default ];
//! }
//! ```

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use barbican::{create_pool, generate_key, health_check, DatabaseConfig, FieldEncryptor, SslMode};

// ============================================================================
// Application State
// ============================================================================

/// Shared application state containing database pool and encryptor
#[derive(Clone)]
struct AppState {
    pool: PgPool,
    encryptor: Arc<FieldEncryptor>,
}

// ============================================================================
// Domain Models
// ============================================================================

/// User with sensitive fields decrypted (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub email: String,
    pub phone: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new user
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub email: String,
    pub phone: Option<String>,
    pub ssn: Option<String>, // Highly sensitive - encrypted, never returned
}

/// Request to update a user
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

/// Document with decrypted content (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: Uuid,
    pub user_id: Uuid,
    pub title: String,
    pub content_type: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

/// Request to create a document
#[derive(Debug, Deserialize)]
pub struct CreateDocumentRequest {
    pub title: String,
    pub content_type: Option<String>,
    pub content: String,
}

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub database_connected: bool,
    pub database_ssl: bool,
    pub encryption_available: bool,
}

// ============================================================================
// Database Operations - Users
// ============================================================================

/// Repository for user operations with encryption
struct UserRepository;

impl UserRepository {
    /// Create a new user with encrypted sensitive fields
    #[instrument(skip(pool, encryptor, req), fields(username = %req.username))]
    async fn create(
        pool: &PgPool,
        encryptor: &FieldEncryptor,
        req: CreateUserRequest,
    ) -> Result<User> {
        let id = Uuid::new_v4();

        // Encrypt sensitive fields before storage
        let email_encrypted = encryptor
            .encrypt_string(&req.email)
            .context("Failed to encrypt email")?;

        let phone_encrypted = req
            .phone
            .as_ref()
            .map(|p| encryptor.encrypt_string(p))
            .transpose()
            .context("Failed to encrypt phone")?;

        let ssn_encrypted = req
            .ssn
            .as_ref()
            .map(|s| encryptor.encrypt_string(s))
            .transpose()
            .context("Failed to encrypt SSN")?;

        // Insert with encrypted values - compile-time checked query
        let row = sqlx::query!(
            r#"
            INSERT INTO users (id, username, display_name, email_encrypted, phone_encrypted, ssn_encrypted)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, username, display_name, email_encrypted, phone_encrypted, created_at, updated_at
            "#,
            id,
            req.username,
            req.display_name,
            email_encrypted,
            phone_encrypted,
            ssn_encrypted,
        )
        .fetch_one(pool)
        .await
        .context("Failed to insert user")?;

        // Decrypt for response
        let email = encryptor
            .decrypt_string(&row.email_encrypted)
            .context("Failed to decrypt email")?;

        let phone = row
            .phone_encrypted
            .as_ref()
            .map(|p| encryptor.decrypt_string(p))
            .transpose()
            .context("Failed to decrypt phone")?;

        info!(user_id = %id, "User created successfully");

        Ok(User {
            id: row.id,
            username: row.username,
            display_name: row.display_name,
            email,
            phone,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    /// Get a user by ID, decrypting sensitive fields
    #[instrument(skip(pool, encryptor))]
    async fn get_by_id(
        pool: &PgPool,
        encryptor: &FieldEncryptor,
        id: Uuid,
    ) -> Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT id, username, display_name, email_encrypted, phone_encrypted, created_at, updated_at
            FROM users WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await
        .context("Failed to fetch user")?;

        match row {
            Some(row) => {
                let email = encryptor
                    .decrypt_string(&row.email_encrypted)
                    .context("Failed to decrypt email")?;

                let phone = row
                    .phone_encrypted
                    .as_ref()
                    .map(|p| encryptor.decrypt_string(p))
                    .transpose()
                    .context("Failed to decrypt phone")?;

                Ok(Some(User {
                    id: row.id,
                    username: row.username,
                    display_name: row.display_name,
                    email,
                    phone,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// List all users (with decrypted fields)
    #[instrument(skip(pool, encryptor))]
    async fn list(pool: &PgPool, encryptor: &FieldEncryptor) -> Result<Vec<User>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, username, display_name, email_encrypted, phone_encrypted, created_at, updated_at
            FROM users ORDER BY created_at DESC LIMIT 100
            "#
        )
        .fetch_all(pool)
        .await
        .context("Failed to list users")?;

        let mut users = Vec::with_capacity(rows.len());
        for row in rows {
            let email = encryptor
                .decrypt_string(&row.email_encrypted)
                .context("Failed to decrypt email")?;

            let phone = row
                .phone_encrypted
                .as_ref()
                .map(|p| encryptor.decrypt_string(p))
                .transpose()
                .context("Failed to decrypt phone")?;

            users.push(User {
                id: row.id,
                username: row.username,
                display_name: row.display_name,
                email,
                phone,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }

        Ok(users)
    }

    /// Update a user's fields (re-encrypting any changed sensitive data)
    #[instrument(skip(pool, encryptor, req))]
    async fn update(
        pool: &PgPool,
        encryptor: &FieldEncryptor,
        id: Uuid,
        req: UpdateUserRequest,
    ) -> Result<Option<User>> {
        // Encrypt new values if provided
        let email_encrypted = req
            .email
            .as_ref()
            .map(|e| encryptor.encrypt_string(e))
            .transpose()
            .context("Failed to encrypt email")?;

        let phone_encrypted = req
            .phone
            .as_ref()
            .map(|p| encryptor.encrypt_string(p))
            .transpose()
            .context("Failed to encrypt phone")?;

        let row = sqlx::query!(
            r#"
            UPDATE users SET
                display_name = COALESCE($2, display_name),
                email_encrypted = COALESCE($3, email_encrypted),
                phone_encrypted = COALESCE($4, phone_encrypted),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, username, display_name, email_encrypted, phone_encrypted, created_at, updated_at
            "#,
            id,
            req.display_name,
            email_encrypted,
            phone_encrypted,
        )
        .fetch_optional(pool)
        .await
        .context("Failed to update user")?;

        match row {
            Some(row) => {
                let email = encryptor
                    .decrypt_string(&row.email_encrypted)
                    .context("Failed to decrypt email")?;

                let phone = row
                    .phone_encrypted
                    .as_ref()
                    .map(|p| encryptor.decrypt_string(p))
                    .transpose()
                    .context("Failed to decrypt phone")?;

                info!(user_id = %id, "User updated successfully");

                Ok(Some(User {
                    id: row.id,
                    username: row.username,
                    display_name: row.display_name,
                    email,
                    phone,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// Delete a user by ID
    #[instrument(skip(pool))]
    async fn delete(pool: &PgPool, id: Uuid) -> Result<bool> {
        let result = sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(pool)
            .await
            .context("Failed to delete user")?;

        if result.rows_affected() > 0 {
            info!(user_id = %id, "User deleted");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ============================================================================
// Database Operations - Documents
// ============================================================================

struct DocumentRepository;

impl DocumentRepository {
    /// Create a document with encrypted content
    #[instrument(skip(pool, encryptor, req), fields(title = %req.title))]
    async fn create(
        pool: &PgPool,
        encryptor: &FieldEncryptor,
        user_id: Uuid,
        req: CreateDocumentRequest,
    ) -> Result<Document> {
        let id = Uuid::new_v4();
        let content_type = req.content_type.unwrap_or_else(|| "text/plain".to_string());

        // Encrypt document content
        let content_encrypted = encryptor
            .encrypt_string(&req.content)
            .context("Failed to encrypt document content")?;

        let row = sqlx::query!(
            r#"
            INSERT INTO documents (id, user_id, title, content_type, content_encrypted)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, title, content_type, content_encrypted, created_at
            "#,
            id,
            user_id,
            req.title,
            content_type,
            content_encrypted,
        )
        .fetch_one(pool)
        .await
        .context("Failed to insert document")?;

        let content = encryptor
            .decrypt_string(&row.content_encrypted)
            .context("Failed to decrypt content")?;

        info!(document_id = %id, "Document created");

        Ok(Document {
            id: row.id,
            user_id: row.user_id,
            title: row.title,
            content_type: row.content_type,
            content,
            created_at: row.created_at,
        })
    }

    /// Get a document by ID
    #[instrument(skip(pool, encryptor))]
    async fn get_by_id(
        pool: &PgPool,
        encryptor: &FieldEncryptor,
        id: Uuid,
    ) -> Result<Option<Document>> {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, title, content_type, content_encrypted, created_at
            FROM documents WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await
        .context("Failed to fetch document")?;

        match row {
            Some(row) => {
                let content = encryptor
                    .decrypt_string(&row.content_encrypted)
                    .context("Failed to decrypt content")?;

                Ok(Some(Document {
                    id: row.id,
                    user_id: row.user_id,
                    title: row.title,
                    content_type: row.content_type,
                    content,
                    created_at: row.created_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// List documents for a user
    #[instrument(skip(pool, encryptor))]
    async fn list_by_user(
        pool: &PgPool,
        encryptor: &FieldEncryptor,
        user_id: Uuid,
    ) -> Result<Vec<Document>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, title, content_type, content_encrypted, created_at
            FROM documents WHERE user_id = $1 ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(pool)
        .await
        .context("Failed to list documents")?;

        let mut docs = Vec::with_capacity(rows.len());
        for row in rows {
            let content = encryptor
                .decrypt_string(&row.content_encrypted)
                .context("Failed to decrypt content")?;

            docs.push(Document {
                id: row.id,
                user_id: row.user_id,
                title: row.title,
                content_type: row.content_type,
                content,
                created_at: row.created_at,
            });
        }

        Ok(docs)
    }
}

// ============================================================================
// Audit Logging
// ============================================================================

/// Log an audit event (for compliance: AU-2, AU-3)
#[instrument(skip(pool))]
async fn log_audit_event(
    pool: &PgPool,
    actor: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    details: Option<serde_json::Value>,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO audit_log (id, actor, action, resource_type, resource_id, details)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        Uuid::new_v4(),
        actor,
        action,
        resource_type,
        resource_id,
        details,
    )
    .execute(pool)
    .await
    .context("Failed to log audit event")?;

    Ok(())
}

// ============================================================================
// HTTP Handlers
// ============================================================================

/// Health check endpoint
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    match health_check(&state.pool).await {
        Ok(status) => Json(HealthResponse {
            status: "healthy".to_string(),
            database_connected: status.connected,
            database_ssl: status.ssl_enabled,
            encryption_available: true,
        }),
        Err(e) => {
            error!("Health check failed: {}", e);
            Json(HealthResponse {
                status: "unhealthy".to_string(),
                database_connected: false,
                database_ssl: false,
                encryption_available: true,
            })
        }
    }
}

/// Create a user
async fn create_user_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = UserRepository::create(&state.pool, &state.encryptor, req)
        .await
        .map_err(|e| {
            error!("Failed to create user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    let _ = log_audit_event(&state.pool, "system", "create", "user", Some(user.id), None).await;

    Ok((StatusCode::CREATED, Json(user)))
}

/// Get a user by ID
async fn get_user_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    match UserRepository::get_by_id(&state.pool, &state.encryptor, id).await {
        Ok(Some(user)) => Ok(Json(user)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get user: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// List all users
async fn list_users_handler(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    match UserRepository::list(&state.pool, &state.encryptor).await {
        Ok(users) => Ok(Json(users)),
        Err(e) => {
            error!("Failed to list users: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Update a user
async fn update_user_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    match UserRepository::update(&state.pool, &state.encryptor, id, req).await {
        Ok(Some(user)) => {
            let _ = log_audit_event(&state.pool, "system", "update", "user", Some(id), None).await;
            Ok(Json(user))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to update user: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Delete a user
async fn delete_user_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    match UserRepository::delete(&state.pool, id).await {
        Ok(true) => {
            let _ = log_audit_event(&state.pool, "system", "delete", "user", Some(id), None).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to delete user: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create a document for a user
async fn create_document_handler(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<CreateDocumentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Verify user exists
    if UserRepository::get_by_id(&state.pool, &state.encryptor, user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    let doc = DocumentRepository::create(&state.pool, &state.encryptor, user_id, req)
        .await
        .map_err(|e| {
            error!("Failed to create document: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    let _ = log_audit_event(
        &state.pool,
        "system",
        "create",
        "document",
        Some(doc.id),
        Some(serde_json::json!({"user_id": user_id})),
    )
    .await;

    Ok((StatusCode::CREATED, Json(doc)))
}

/// List documents for a user
async fn list_documents_handler(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    match DocumentRepository::list_by_user(&state.pool, &state.encryptor, user_id).await {
        Ok(docs) => Ok(Json(docs)),
        Err(e) => {
            error!("Failed to list documents: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get a specific document
async fn get_document_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    match DocumentRepository::get_by_id(&state.pool, &state.encryptor, id).await {
        Ok(Some(doc)) => Ok(Json(doc)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get document: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ============================================================================
// Application Setup
// ============================================================================

/// Initialize the database schema
async fn init_schema(pool: &PgPool) -> Result<()> {
    info!("Initializing database schema...");

    sqlx::raw_sql(include_str!("../schema.sql"))
        .execute(pool)
        .await
        .context("Failed to initialize schema")?;

    info!("Database schema initialized");
    Ok(())
}

/// Build the application router
fn build_router(state: AppState) -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_handler))
        // User CRUD
        .route("/users", get(list_users_handler).post(create_user_handler))
        .route(
            "/users/{id}",
            get(get_user_handler)
                .put(update_user_handler)
                .delete(delete_user_handler),
        )
        // Document CRUD
        .route(
            "/users/{user_id}/documents",
            get(list_documents_handler).post(create_document_handler),
        )
        .route("/documents/{id}", get(get_document_handler))
        .with_state(state)
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("db_minimal=info".parse()?)
                .add_directive("barbican=info".parse()?),
        )
        .init();

    info!("Starting db-minimal example application");

    // =========================================================================
    // Step 1: Load configuration from environment
    // =========================================================================

    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL environment variable is required")?;

    let encryption_key = std::env::var("ENCRYPTION_KEY").unwrap_or_else(|_| {
        warn!("ENCRYPTION_KEY not set, generating a temporary key (NOT FOR PRODUCTION)");
        let key = generate_key();
        info!("Generated temporary key: {}...", &key[..16]);
        key
    });

    // =========================================================================
    // Step 2: Create secure database configuration
    // =========================================================================
    //
    // When using Barbican's securePostgres NixOS module, the database is already
    // configured with:
    // - TLS encryption (SC-8)
    // - scram-sha-256 authentication
    // - Connection limits and timeouts (SC-5)
    // - Audit logging (AU-2)
    //
    // This config connects to that secure database.

    let db_config = DatabaseConfig::builder(&database_url)
        .application_name("db-minimal")
        // Use Prefer for local dev, VerifyFull for production
        .ssl_mode(SslMode::Prefer)
        .max_connections(5)
        .min_connections(1)
        .statement_timeout(std::time::Duration::from_secs(30))
        .lock_timeout(std::time::Duration::from_secs(10))
        .build();

    info!("Database config: SSL mode {:?}", db_config.ssl_mode);

    // =========================================================================
    // Step 3: Create database connection pool
    // =========================================================================

    let pool = create_pool(&db_config)
        .await
        .context("Failed to create database pool")?;

    let health = health_check(&pool).await?;
    info!(
        "Database: connected={}, ssl={}, latency={:?}",
        health.connected, health.ssl_enabled, health.latency
    );

    // =========================================================================
    // Step 4: Initialize field encryptor for sensitive data
    // =========================================================================
    //
    // FieldEncryptor provides AES-256-GCM encryption for PII fields.
    // Each encryption uses a unique nonce to prevent pattern analysis.

    let encryptor = FieldEncryptor::new(&encryption_key)
        .context("Invalid ENCRYPTION_KEY format")?;

    info!("Encryption: algorithm={:?}", encryptor.algorithm());

    // =========================================================================
    // Step 5: Initialize schema and start server
    // =========================================================================

    init_schema(&pool).await?;

    let state = AppState {
        pool,
        encryptor: Arc::new(encryptor),
    };

    let app = build_router(state);

    let addr = "0.0.0.0:3000";
    info!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = generate_key();
        let encryptor = FieldEncryptor::new(&key).unwrap();

        let plaintext = "sensitive@email.com";
        let encrypted = encryptor.encrypt_string(plaintext).unwrap();
        let decrypted = encryptor.decrypt_string(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, encrypted);
    }

    #[test]
    fn test_encryption_unique_nonces() {
        let key = generate_key();
        let encryptor = FieldEncryptor::new(&key).unwrap();

        let plaintext = "test@example.com";
        let encrypted1 = encryptor.encrypt_string(plaintext).unwrap();
        let encrypted2 = encryptor.encrypt_string(plaintext).unwrap();

        // Each encryption produces different ciphertext
        assert_ne!(encrypted1, encrypted2);

        // Both decrypt to the same value
        assert_eq!(
            encryptor.decrypt_string(&encrypted1).unwrap(),
            encryptor.decrypt_string(&encrypted2).unwrap()
        );
    }
}
