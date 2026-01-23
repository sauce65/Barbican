//! Realistic Barbican Example Application
//!
//! A complete task management API demonstrating all Barbican security features.
//!
//! Security Controls Implemented:
//! - AC-7:  Login attempt limiting with lockout
//! - AC-11: Session idle timeout
//! - AC-12: Session maximum lifetime
//! - AU-2:  Audit event logging
//! - AU-3:  Audit record content
//! - IA-5:  Password policy enforcement
//! - SC-5:  Rate limiting
//! - SC-28: Field encryption for sensitive data
//! - SI-10: Input validation
//! - SI-11: Secure error handling

mod auth;
mod config;
mod db;
mod error;
mod tasks;

use axum::{
    routing::{get, post, put, delete},
    Router,
    middleware,
};
use barbican::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use crate::config::AppConfig;
use crate::auth::middleware::auth_middleware;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub login_tracker: Arc<LoginTracker>,
    pub password_policy: PasswordPolicy,
    pub session_policy: SessionPolicy,
    pub encryptor: Arc<FieldEncryptor>,
    // In production, use a real database pool:
    // pub db: sqlx::PgPool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging (AU-2)
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,realistic_app=debug".into())
        )
        .json()
        .init();

    // Load configuration
    let config = Arc::new(AppConfig::from_env()?);
    info!(
        profile = %config.profile.name(),
        "Starting application"
    );

    // Initialize security components based on compliance profile
    let state = AppState {
        login_tracker: Arc::new(LoginTracker::new(config.profile.lockout_policy())),
        password_policy: config.profile.password_policy(),
        session_policy: config.profile.session_policy(),
        encryptor: Arc::new(FieldEncryptor::new(config.encryption_config.clone())),
        config,
    };

    // Build router with security layers
    let app = build_router(state);

    // Start server
    let addr = "0.0.0.0:3000";
    info!(address = %addr, "Server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn build_router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/health/ready", get(health_ready))
        .route("/auth/register", post(auth::handlers::register))
        .route("/auth/login", post(auth::handlers::login));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/auth/logout", post(auth::handlers::logout))
        .route("/tasks", get(tasks::handlers::list_tasks))
        .route("/tasks", post(tasks::handlers::create_task))
        .route("/tasks/:id", get(tasks::handlers::get_task))
        .route("/tasks/:id", put(tasks::handlers::update_task))
        .route("/tasks/:id", delete(tasks::handlers::delete_task))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Combine and apply security layers
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        // Barbican security layers
        .layer(audit_middleware())                    // AU-2, AU-3: Audit logging
        .with_security_headers()                      // CM-6: Security headers
        .with_rate_limiting(100, 10)                  // SC-5: Rate limiting
        .with_request_timeout(Duration::from_secs(30))
        .with_body_limit(1024 * 1024)                // 1MB max
}

/// Liveness check - always returns OK if server is running
async fn health() -> &'static str {
    "OK"
}

/// Readiness check - verifies dependencies are available
async fn health_ready() -> Result<&'static str, AppError> {
    // In production, check database connectivity:
    // state.db.acquire().await.map_err(|e| AppError::internal("Database unavailable"))?;
    Ok("OK")
}
