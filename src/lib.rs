//! # Barbican
//!
//! NIST 800-53 compliant security infrastructure for Axum applications.
//!
//! This crate provides reusable, secure-by-default middleware and configuration
//! for building production-ready Axum web applications with PostgreSQL.
//!
//! ## Features
//!
//! - **Security Headers** (SC-2): HSTS, CSP, X-Frame-Options, X-Content-Type-Options
//! - **Rate Limiting** (SC-3): Token bucket per IP via tower-governor
//! - **Request Size Limits** (SC-4): Configurable body size limits
//! - **Request Timeouts** (SC-5): Configurable request timeouts
//! - **CORS Policy** (SC-6): Configurable origin allowlist
//! - **Structured Logging** (SC-7): JSON audit logs with tracing
//! - **Database Security** (SC-8): SSL, pooling, health checks
//! - **Cryptographic Utilities**: Constant-time comparison
//!
//! ## Quick Start
//!
//! ```ignore
//! use axum::{Router, routing::get};
//! use barbican::{SecurityConfig, SecureRouter, DatabaseConfig, create_pool};
//! use barbican::observability::{ObservabilityConfig, init};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialize observability
//!     let obs_config = ObservabilityConfig::from_env();
//!     init(obs_config).await?;
//!
//!     // Create database pool
//!     let db_config = DatabaseConfig::from_env();
//!     let pool = create_pool(&db_config).await?;
//!
//!     // Build app with security layers
//!     let config = SecurityConfig::from_env();
//!     let app = Router::new()
//!         .route("/", get(|| async { "Hello, secure world!" }))
//!         .with_state(pool)
//!         .with_security(config);
//!
//!     // Serve with TLS...
//!     Ok(())
//! }
//! ```
//!
//! ## Compliance
//!
//! This crate is designed for compliance with:
//! - NIST SP 800-53 Rev 5
//! - SOC 2 Type II
//! - FedRAMP

mod config;
mod crypto;
#[cfg(feature = "postgres")]
mod database;
mod layers;
pub mod observability;
mod parse;

// Re-exports
pub use config::{SecurityConfig, SecurityConfigBuilder};
pub use observability::ObservabilityConfigBuilder;
pub use crypto::{constant_time_eq, constant_time_str_eq};
pub use layers::SecureRouter;
pub use parse::{parse_duration, parse_size};

#[cfg(feature = "postgres")]
pub use database::{
    create_pool, health_check, DatabaseConfig, DatabaseConfigBuilder, DatabaseError,
    HealthStatus, SslMode,
};
