//! FedRAMP High Example - Hello World
//!
//! Demonstrates maximum security controls for FedRAMP High authorization.
//! Suitable for systems where loss of confidentiality, integrity, or
//! availability would have SEVERE or CATASTROPHIC adverse effect.
//!
//! Key Controls:
//! - SC-8:   mTLS required (mutual TLS with client certificates)
//! - SC-13:  FIPS 140-2/3 validated cryptography required
//! - SC-28:  Encryption at rest required
//! - AC-7:   Login attempt limiting (3 attempts, 60min lockout)
//! - AC-11:  Session idle timeout (5 minutes)
//! - AC-12:  Session termination (10 minutes max)
//! - AU-2:   Comprehensive audit logging with integrity
//! - AU-9:   Audit record integrity protection
//! - AU-11:  365-day log retention
//! - IA-2:   MFA required for all access
//! - IA-5:   Password policy (14 char minimum)

mod generated;

use axum::{routing::get, Json, Router};
use generated::{BarbicanApp, GeneratedConfig};
use serde::Serialize;
use tracing::info;

#[derive(Serialize)]
struct HelloResponse {
    message: String,
    profile: String,
    session_idle_timeout_mins: u64,
    session_max_lifetime_mins: u64,
    mfa_required: bool,
    min_password_length: usize,
    log_retention_days: u32,
    mtls_required: bool,
    fips_required: bool,
}

async fn hello() -> Json<HelloResponse> {
    Json(HelloResponse {
        message: "Hello from FedRAMP High!".to_string(),
        profile: GeneratedConfig::PROFILE.name().to_string(),
        session_idle_timeout_mins: GeneratedConfig::IDLE_TIMEOUT_SECS / 60,
        session_max_lifetime_mins: GeneratedConfig::SESSION_TIMEOUT_SECS / 60,
        mfa_required: GeneratedConfig::MFA_REQUIRED,
        min_password_length: GeneratedConfig::MIN_PASSWORD_LENGTH,
        log_retention_days: GeneratedConfig::MIN_RETENTION_DAYS,
        mtls_required: true,  // FedRAMP High requires mTLS
        fips_required: true,  // FedRAMP High requires FIPS crypto
    })
}

async fn health() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!(
        app = GeneratedConfig::APP_NAME,
        version = GeneratedConfig::APP_VERSION,
        profile = GeneratedConfig::PROFILE.name(),
        "Starting FedRAMP High example"
    );

    // Note: In production, FedRAMP High requires:
    // - FIPS 140-2/3 validated crypto (build with --features fips)
    // - mTLS with client certificates
    // - HSM/KMS for key management

    let app = Router::new()
        .route("/", get(hello))
        .route("/health", get(health))
        .with_barbican();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Listening on http://0.0.0.0:3000");

    axum::serve(listener, app).await?;
    Ok(())
}
