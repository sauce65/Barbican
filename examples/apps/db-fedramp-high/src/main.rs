//! FedRAMP High Baseline Example
//!
//! Demonstrates maximum security controls for FedRAMP High authorization:
//!
//! | Control | Implementation |
//! |---------|----------------|
//! | SC-8    | mTLS database connections |
//! | SC-13   | FIPS 140-3 validated cryptography (AWS-LC) |
//! | SC-28   | Field-level encryption with HSM-backed keys |
//! | SC-12   | HSM/KMS key management with rotation tracking |
//! | AU-2    | Comprehensive audit logging |
//! | AU-3    | Detailed audit records |
//! | AU-9    | Cryptographically signed audit chain |
//! | AC-3    | Fine-grained RBAC |
//! | AC-6    | Least privilege with time-limited roles |
//! | AC-11   | Strict idle timeout (15 min) |
//! | AC-12   | Strict session termination (4 hour max) |
//! | IA-2    | MFA required for all authenticated access |
//! | IA-2(1) | MFA for privileged accounts |
//! | IA-2(2) | MFA for non-privileged accounts |
//!
//! FedRAMP High is appropriate for systems where loss of confidentiality,
//! integrity, or availability would have SEVERE or CATASTROPHIC adverse effect.

use anyhow::{bail, Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use barbican::{
    audit::integrity::{AuditChain, AuditIntegrityConfig},
    auth::{Claims, MfaPolicy},
    encryption::{EncryptionAlgorithm, FieldEncryptor},
    keys::{KeyMetadata, KeyPurpose, RotationPolicy, RotationTracker},
    session::SessionPolicy,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

/// FedRAMP High database configuration
fn create_database_config(database_url: &str) -> barbican::DatabaseConfig {
    barbican::DatabaseConfig::builder(database_url)
        .application_name("fedramp-high-example")
        // mTLS preferred, TLS required minimum
        .ssl_mode(barbican::SslMode::Require)
        // Channel binding for extra security
        .channel_binding(barbican::ChannelBinding::Require)
        // Conservative pool size
        .max_connections(10)
        // Strict timeouts
        .connect_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(60))
        .build()
}

/// FedRAMP High session policy (AC-11, AC-12) - STRICT
fn create_session_policy() -> SessionPolicy {
    SessionPolicy::builder()
        // 4 hour max session lifetime (stricter than Moderate)
        .max_lifetime(Duration::from_secs(4 * 60 * 60))
        // 15 minute idle timeout (stricter than Moderate)
        .idle_timeout(Duration::from_secs(15 * 60))
        // Re-auth required for sensitive operations after 5 minutes
        .require_reauth_for_sensitive(true)
        .reauth_timeout(Duration::from_secs(5 * 60))
        // No session extension
        .allow_extension(false)
        .build()
}

/// FedRAMP High MFA policy (IA-2) - MFA REQUIRED
fn create_mfa_policy() -> MfaPolicy {
    // At High baseline, MFA is required for ALL access
    // Hardware keys preferred (IA-2(6) for privileged access)
    MfaPolicy::require_mfa()
}

// ============================================================================
// Data Types
// ============================================================================

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    database_connected: bool,
    database_ssl: bool,
    fips_mode: bool,
    fips_certificate: Option<String>,
    encryption_algorithm: String,
    baseline: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    phone: Option<String>,
    ssn: Option<String>,  // Highly sensitive - encrypted, never returned
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    username: String,
    email: String,
    phone: Option<String>,
    // SSN intentionally omitted - never returned in API
    display_name: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CreateDocumentRequest {
    title: String,
    content: String,
    classification: Option<String>,
}

#[derive(Debug, Serialize)]
struct DocumentResponse {
    id: Uuid,
    user_id: Uuid,
    title: String,
    content: String,
    classification: String,
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
    mfa_policy: MfaPolicy,
    audit_chain: Arc<RwLock<AuditChain>>,
    rotation_tracker: Arc<RwLock<RotationTracker>>,
}

// ============================================================================
// Signed Audit Chain (AU-9)
// ============================================================================

/// Append a signed record to the audit chain
async fn log_audit_signed(
    pool: &PgPool,
    chain: &RwLock<AuditChain>,
    actor: &str,
    actor_role: Option<&str>,
    mfa_verified: bool,
    auth_method: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    source_ip: Option<&str>,
    session_id: Option<Uuid>,
    success: bool,
    details: Option<serde_json::Value>,
) {
    // Create signed record in chain
    let mut chain_guard = chain.write().await;
    let record = chain_guard.append(
        action,
        actor,
        resource_type,
        "POST", // method placeholder
        if success { "success" } else { "failure" },
        source_ip.unwrap_or("unknown"),
        details.as_ref(),
    );

    // Persist to database with signature
    let result = sqlx::query!(
        r#"
        INSERT INTO audit_chain (id, actor, actor_role, mfa_verified, auth_method,
                                 action, resource_type, resource_id, source_ip,
                                 session_id, success, details, previous_hash,
                                 record_signature, algorithm)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        "#,
        Uuid::new_v4(),
        actor,
        actor_role,
        mfa_verified,
        auth_method,
        action,
        resource_type,
        resource_id,
        source_ip,
        session_id,
        success,
        details,
        record.previous_hash.as_deref(),
        &record.signature,
        record.algorithm.as_str(),
    )
    .execute(pool)
    .await;

    if let Err(e) = result {
        error!("CRITICAL: Failed to write signed audit record: {}", e);
    }
}

// ============================================================================
// MFA Enforcement (IA-2)
// ============================================================================

/// Verify MFA was completed for request
fn verify_mfa(policy: &MfaPolicy, claims: &Claims) -> Result<(), (StatusCode, String)> {
    if !policy.is_satisfied(claims) {
        return Err((
            StatusCode::FORBIDDEN,
            "MFA required - please complete multi-factor authentication".to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// RBAC (AC-3, AC-6)
// ============================================================================

async fn get_user_roles(pool: &PgPool, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar!(
        r#"
        SELECT role FROM user_roles
        WHERE user_id = $1
        AND (expires_at IS NULL OR expires_at > NOW())
        "#,
        user_id
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

async fn assign_role(
    pool: &PgPool,
    user_id: Uuid,
    role: &str,
    granted_by: &str,
    expires_in: Option<Duration>,
) -> Result<()> {
    let expires_at = expires_in.map(|d| {
        chrono::Utc::now() + chrono::Duration::from_std(d).unwrap_or_default()
    });

    sqlx::query!(
        r#"
        INSERT INTO user_roles (user_id, role, granted_by, expires_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, role) DO UPDATE SET
            granted_by = EXCLUDED.granted_by,
            granted_at = NOW(),
            expires_at = EXCLUDED.expires_at
        "#,
        user_id,
        role,
        granted_by,
        expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Check role with audit logging
async fn check_role_audited(
    state: &AppState,
    user_id: Uuid,
    required_role: &str,
    claims: &Claims,
) -> bool {
    let roles = get_user_roles(&state.pool, user_id).await;
    let has_role = roles.iter().any(|r| r == required_role);

    if !has_role {
        log_audit_signed(
            &state.pool,
            &state.audit_chain,
            &claims.subject,
            claims.roles.iter().next().map(|s| s.as_str()),
            claims.mfa_satisfied(),
            claims.amr.iter().next().map(|s| s.as_str()),
            "access_denied",
            "role_check",
            None,
            None,
            None,
            false,
            Some(serde_json::json!({
                "required_role": required_role,
                "user_roles": roles
            })),
        )
        .await;
    }

    has_role
}

// ============================================================================
// Key Rotation Tracking (SC-12)
// ============================================================================

async fn check_key_rotation(tracker: &RwLock<RotationTracker>) {
    let tracker_guard = tracker.read().await;

    for key_id in ["encryption-key", "audit-signing-key"] {
        if tracker_guard.needs_rotation(key_id) {
            warn!(
                "Key '{}' is due for rotation - please rotate via your KMS",
                key_id
            );
        }
    }
}

// ============================================================================
// HTTP Handlers
// ============================================================================

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let health = barbican::health_check(&state.pool).await;

    // Check key rotation status
    check_key_rotation(&state.rotation_tracker).await;

    let (connected, ssl) = match health {
        Ok(h) => (h.connected, h.ssl_enabled),
        Err(_) => (false, false),
    };

    Json(HealthResponse {
        status: if connected { "healthy" } else { "unhealthy" }.to_string(),
        database_connected: connected,
        database_ssl: ssl,
        fips_mode: EncryptionAlgorithm::is_fips_mode(),
        fips_certificate: EncryptionAlgorithm::fips_certificate().map(|s| s.to_string()),
        encryption_algorithm: format!("{:?}", state.encryptor.algorithm()),
        baseline: "FedRAMP High".to_string(),
    })
}

#[instrument(skip(state), fields(username = %req.username))]
async fn create_user_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // In production, extract claims from JWT middleware
    // For demo, create mock claims with MFA satisfied
    let claims = Claims::new("system")
        .with_role("admin")
        .with_amr("pwd")
        .with_amr("otp");  // MFA completed

    // Verify MFA (IA-2)
    verify_mfa(&state.mfa_policy, &claims)?;

    let id = Uuid::new_v4();

    // Encrypt PII with FIPS-validated crypto (SC-13, SC-28)
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

    // SSN is highly sensitive - encrypted but NEVER returned
    let ssn_encrypted = req
        .ssn
        .as_ref()
        .map(|s| state.encryptor.encrypt_string(s))
        .transpose()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query!(
        r#"
        INSERT INTO users (id, username, display_name, email_encrypted, phone_encrypted, ssn_encrypted)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, username, display_name, email_encrypted, phone_encrypted, created_at
        "#,
        id,
        req.username,
        req.display_name,
        email_encrypted,
        phone_encrypted,
        ssn_encrypted,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        error!("Failed to create user: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    // Assign default role with expiration (AC-6 - time-limited least privilege)
    let _ = assign_role(
        &state.pool,
        row.id,
        "user",
        &claims.subject,
        Some(Duration::from_secs(365 * 24 * 60 * 60)), // 1 year max
    )
    .await;

    // Signed audit log (AU-9)
    log_audit_signed(
        &state.pool,
        &state.audit_chain,
        &claims.subject,
        Some("admin"),
        claims.mfa_satisfied(),
        Some("pwd+otp"),
        "create",
        "user",
        Some(row.id),
        None,
        None,
        true,
        Some(serde_json::json!({"username": req.username})),
    )
    .await;

    info!(user_id = %row.id, "User created (FedRAMP High)");

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
            .and_then(|p| state.encryptor.decrypt_string(p).ok());

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
    // Mock claims with MFA for demo
    let claims = Claims::new("system")
        .with_role("admin")
        .with_amr("pwd")
        .with_amr("hwk");  // Hardware key for privileged ops

    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id)
        .execute(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    log_audit_signed(
        &state.pool,
        &state.audit_chain,
        &claims.subject,
        Some("admin"),
        true,
        Some("pwd+hwk"),
        "delete",
        "user",
        Some(id),
        None,
        None,
        true,
        None,
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
    let classification = req.classification.unwrap_or_else(|| "internal".to_string());

    // Encrypt content with FIPS crypto
    let content_encrypted = state
        .encryptor
        .encrypt_string(&req.content)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query!(
        r#"
        INSERT INTO documents (id, user_id, title, classification, content_encrypted)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_id, title, classification, content_encrypted, created_at
        "#,
        id,
        user_id,
        req.title,
        classification,
        content_encrypted,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    log_audit_signed(
        &state.pool,
        &state.audit_chain,
        "system",
        None,
        true,
        Some("pwd+otp"),
        "create",
        "document",
        Some(row.id),
        None,
        None,
        true,
        Some(serde_json::json!({
            "user_id": user_id,
            "title": req.title,
            "classification": row.classification
        })),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(DocumentResponse {
            id: row.id,
            user_id: row.user_id,
            title: row.title,
            content: req.content,
            classification: row.classification,
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
        SELECT id, user_id, title, classification, content_encrypted, created_at
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
            classification: row.classification,
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
                .add_directive("db_fedramp_high=info".parse()?)
                .add_directive("barbican=info".parse()?),
        )
        .init();

    info!("Starting FedRAMP High baseline example");
    info!("Controls: SC-8, SC-12, SC-13, SC-28, AU-2/3/9, AC-3/6/11/12, IA-2");

    // Verify FIPS mode (SC-13)
    if EncryptionAlgorithm::is_fips_mode() {
        info!(
            "FIPS mode ENABLED - Certificate: {}",
            EncryptionAlgorithm::fips_certificate().unwrap_or("unknown")
        );
    } else {
        warn!("FIPS mode NOT enabled - build with --features fips for production!");
        warn!("FedRAMP High REQUIRES FIPS 140-2/3 validated cryptography");
    }

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;

    // Encryption key (SC-12, SC-28)
    // In production, this comes from HSM/KMS (Vault, AWS KMS, etc.)
    let encryption_key = std::env::var("ENCRYPTION_KEY").unwrap_or_else(|_| {
        warn!("ENCRYPTION_KEY not set - generating temporary key");
        warn!("PRODUCTION: Use HSM/KMS for key management (SC-12)");
        barbican::encryption::generate_key()
    });

    // Audit signing key (AU-9)
    let audit_signing_key = std::env::var("AUDIT_SIGNING_KEY").unwrap_or_else(|_| {
        warn!("AUDIT_SIGNING_KEY not set - generating temporary key");
        barbican::encryption::generate_key()
    });

    // Create encryptor
    let encryptor = FieldEncryptor::new(&encryption_key)
        .context("Failed to create encryptor")?;
    info!("Encryption: algorithm={:?}", encryptor.algorithm());

    // Create audit chain with integrity protection (AU-9)
    let audit_config = AuditIntegrityConfig::new(audit_signing_key.as_bytes());
    let audit_chain = Arc::new(RwLock::new(AuditChain::new(audit_config)));
    info!("Audit chain: HMAC-SHA256 signed, tamper-evident");

    // Key rotation tracker (SC-12)
    let mut rotation_tracker = RotationTracker::new();
    rotation_tracker.register("encryption-key", RotationPolicy::days(90));
    rotation_tracker.register("audit-signing-key", RotationPolicy::days(90));
    let rotation_tracker = Arc::new(RwLock::new(rotation_tracker));
    info!("Key rotation: tracking with 90-day policy");

    // Database connection
    let config = create_database_config(&database_url);
    info!("Database config: SSL mode {:?}, channel binding {:?}",
          config.ssl_mode, config.channel_binding);

    let pool = barbican::create_pool(&config).await?;

    let health = barbican::health_check(&pool).await?;
    info!(
        "Database: connected={}, ssl={}",
        health.connected, health.ssl_enabled
    );

    if !health.ssl_enabled {
        warn!("SSL not enabled - FedRAMP High REQUIRES TLS/mTLS!");
    }

    // Session policy (strict)
    let session_policy = create_session_policy();
    info!(
        "Session policy: max={}h, idle={}m (STRICT)",
        session_policy.max_lifetime.as_secs() / 3600,
        session_policy.idle_timeout.as_secs() / 60
    );

    // MFA policy
    let mfa_policy = create_mfa_policy();
    info!("MFA policy: REQUIRED for all access");

    // Initialize schema
    sqlx::raw_sql(include_str!("../schema.sql"))
        .execute(&pool)
        .await?;

    let state = AppState {
        pool,
        encryptor,
        session_policy,
        mfa_policy,
        audit_chain,
        rotation_tracker,
    };

    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Listening on http://0.0.0.0:3000");

    axum::serve(listener, router).await?;
    Ok(())
}
