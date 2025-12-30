//! Barbican Prelude - Common imports for secure applications
//!
//! This module re-exports the most commonly used types from Barbican,
//! providing a convenient single import for applications using the
//! barbican CLI's generated configuration.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::prelude::*;
//!
//! let app = Router::new()
//!     .route("/", get(handler))
//!     .with_security(SecurityConfig::from_env());
//! ```
//!
//! # What's Included
//!
//! ## Core Configuration
//! - [`SecurityConfig`], [`SecurityConfigBuilder`] - Main security configuration
//! - [`ComplianceProfile`] - FedRAMP/SOC2 profile selection
//!
//! ## Session Management (AC-11, AC-12)
//! - [`SessionConfig`], [`SessionPolicy`], [`SessionState`]
//!
//! ## Login Tracking (AC-7)
//! - [`LoginTrackingConfig`], [`LockoutPolicy`], [`LoginTracker`]
//!
//! ## Authentication (IA-2)
//! - [`MfaPolicy`], [`Claims`]
//!
//! ## Password Policy (IA-5)
//! - [`PasswordPolicy`], [`PasswordError`]
//!
//! ## TLS Enforcement (SC-8)
//! - [`TlsMode`]
//!
//! ## Database (with `postgres` feature)
//! - [`DatabaseConfig`], [`DatabaseConfigBuilder`], [`SslMode`]
//!
//! ## Observability
//! - [`ObservabilityConfig`], [`ObservabilityConfigBuilder`]
//!
//! ## Error Handling (SI-11)
//! - [`AppError`], [`ErrorConfig`]
//!
//! ## Router Extension
//! - [`SecureRouter`] - Extension trait for applying security layers

// =============================================================================
// Core Configuration
// =============================================================================

pub use crate::config::{SecurityConfig, SecurityConfigBuilder};
pub use crate::compliance::{ComplianceConfig, ComplianceProfile, ComplianceValidator};
pub use crate::layers::SecureRouter;

// =============================================================================
// Session Management (AC-11, AC-12)
// =============================================================================

pub use crate::session::{
    SessionConfig,
    SessionPolicy,
    SessionState,
    SessionTerminationReason,
    SessionExtension,
    session_enforcement_middleware,
};

// =============================================================================
// Login Tracking (AC-7)
// =============================================================================

pub use crate::login::{
    LoginTrackingConfig,
    LockoutPolicy,
    LoginTracker,
    AttemptResult,
    LockoutInfo,
    LoginTrackerExtension,
    login_tracking_middleware,
};

// =============================================================================
// Authentication (IA-2)
// =============================================================================

pub use crate::auth::{
    Claims,
    MfaPolicy,
    log_access_decision,
    log_access_denied,
    log_mfa_success,
    log_mfa_required,
};

// =============================================================================
// Password Policy (IA-5)
// =============================================================================

pub use crate::password::{
    PasswordPolicy,
    PasswordError,
    PasswordStrength,
};

// =============================================================================
// TLS Enforcement (SC-8)
// =============================================================================

pub use crate::tls::{
    TlsMode,
    TlsInfo,
    MtlsMode,
    detect_tls,
    tls_enforcement_middleware,
};

// =============================================================================
// Observability (AU-2, AU-3, AU-12)
// =============================================================================

pub use crate::observability::{
    ObservabilityConfig,
    SecurityEvent,
};
pub use crate::ObservabilityConfigBuilder;

// =============================================================================
// Audit (AU-2, AU-3, AU-9, AU-12)
// =============================================================================

pub use crate::audit::{
    audit_middleware,
    AuditRecord,
    AuditOutcome,
};

// =============================================================================
// Error Handling (SI-11)
// =============================================================================

pub use crate::error::{
    AppError,
    ErrorConfig,
    ErrorKind,
};

// =============================================================================
// Validation (SI-10)
// =============================================================================

pub use crate::validation::{
    Validate,
    ValidationError,
    ValidatedJson,
    ValidatedQuery,
    ValidatedPath,
    validate_email,
    validate_length,
    validate_required,
    sanitize_html,
};

// =============================================================================
// Health Checks (CA-7)
// =============================================================================

pub use crate::health::{
    HealthChecker,
    HealthCheck,
    HealthStatus,
    HealthReport,
    health_routes,
};

// =============================================================================
// Alerting (IR-4, IR-5)
// =============================================================================

pub use crate::alerting::{
    AlertManager,
    AlertConfig,
    Alert,
    AlertSeverity,
    AlertCategory,
};

// =============================================================================
// Key Management (SC-12)
// =============================================================================

pub use crate::keys::{
    KeyStore,
    KeyMetadata,
    KeyMaterial,
    KeyError,
    RotationTracker,
    RotationPolicy,
    EnvKeyStore,
};

// =============================================================================
// Encryption (SC-28)
// =============================================================================

pub use crate::encryption::{
    FieldEncryptor,
    EncryptedField,
    EncryptionConfig,
    EncryptionAlgorithm,
};

// =============================================================================
// Database (feature: postgres)
// =============================================================================

#[cfg(feature = "postgres")]
pub use crate::database::{
    DatabaseConfig,
    DatabaseConfigBuilder,
    SslMode,
    ChannelBinding,
    create_pool,
};

// =============================================================================
// External Re-exports for Convenience
// =============================================================================

// Axum types commonly used with Barbican
pub use axum::{
    Router,
    routing::{get, post, put, delete, patch},
    extract::{State, Path, Query, Json},
    response::IntoResponse,
    http::StatusCode,
    middleware,
};

// Tracing for logging
pub use tracing::{info, warn, error, debug, trace, instrument};
