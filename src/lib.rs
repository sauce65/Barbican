//! # Barbican
//!
//! NIST 800-53 compliant security infrastructure for Axum applications.
//!
//! Barbican provides 12 pluggable security modules implementing 52+ NIST 800-53 controls
//! for building production-ready, compliance-aware web applications.
//!
//! ## Security Modules
//!
//! ### Infrastructure Layer
//! - **[`layers`]**: Security headers, rate limiting, CORS, timeouts (SC-5, SC-8, SC-28)
//! - **[`observability`]**: Structured logging, metrics, distributed tracing (AU-2, AU-3, AU-12)
//! - **Database** (feature: `postgres`): SSL/TLS, connection pooling, health checks (SC-8, IA-5)
//!
//! ### Authentication & Authorization
//! - **[`auth`]**: OAuth/OIDC JWT claims, MFA policy enforcement (IA-2, IA-5, AC-2)
//! - **[`password`]**: NIST 800-63B compliant password validation (IA-5(1))
//! - **[`login`]**: Login attempt tracking, account lockout (AC-7)
//! - **[`session`]**: Session management, idle/absolute timeout (AC-11, AC-12)
//!
//! ### Operational Security
//! - **[`alerting`]**: Security incident alerting with rate limiting (IR-4, IR-5)
//! - **[`health`]**: Health check framework with aggregation (CA-7)
//! - **[`keys`]**: Key management with KMS integration traits (SC-12)
//! - **[`supply_chain`]**: SBOM generation, license compliance, vulnerability audit (SR-3, SR-4)
//! - **[`testing`]**: Security test utilities (XSS, SQLi payloads) (SA-11, CA-8)
//!
//! ### Data Protection
//! - **[`validation`]**: Input validation and sanitization (SI-10)
//! - **[`error`]**: Secure error handling, no info leakage (SI-11)
//! - **Cryptographic utilities**: Constant-time comparison (SC-13)
//!
//! ## Quick Start
//!
//! ```ignore
//! use axum::{Router, routing::get};
//! use barbican::{SecurityConfig, SecureRouter};
//! use barbican::observability::{ObservabilityConfig, init};
//! use barbican::error::{AppError, ErrorConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialize observability and error handling
//!     let obs_config = ObservabilityConfig::from_env();
//!     init(obs_config).await?;
//!     barbican::error::init(ErrorConfig::from_env());
//!
//!     // Build app with security layers
//!     let config = SecurityConfig::from_env();
//!     let app = Router::new()
//!         .route("/", get(|| async { "Hello, secure world!" }))
//!         .with_security(config);
//!
//!     // Serve with TLS...
//!     Ok(())
//! }
//! ```
//!
//! ## Session Management (AC-11, AC-12)
//!
//! ```ignore
//! use barbican::session::{SessionPolicy, SessionState, SessionTerminationReason};
//! use std::time::Duration;
//!
//! let policy = SessionPolicy::builder()
//!     .idle_timeout(Duration::from_secs(900))     // 15 min idle
//!     .absolute_timeout(Duration::from_secs(28800)) // 8 hour max
//!     .build();
//!
//! let mut session = SessionState::new("session-id", "user-123");
//! if policy.is_idle_timeout_exceeded(&session) {
//!     session.terminate(SessionTerminationReason::IdleTimeout);
//! }
//! ```
//!
//! ## Login Tracking (AC-7)
//!
//! ```ignore
//! use barbican::login::{LockoutPolicy, LoginTracker, AttemptResult};
//!
//! let policy = LockoutPolicy::nist_compliant(); // 3 attempts, 15 min lockout
//! let mut tracker = LoginTracker::new(policy);
//!
//! match tracker.record_attempt("user@example.com", false) {
//!     AttemptResult::Allowed => { /* continue */ }
//!     AttemptResult::AccountLocked(info) => {
//!         // Account locked until info.lockout_until
//!     }
//! }
//! ```
//!
//! ## Security Alerting (IR-4, IR-5)
//!
//! ```ignore
//! use barbican::alerting::{AlertManager, AlertConfig, Alert, AlertSeverity, AlertCategory};
//!
//! let config = AlertConfig::default();
//! let manager = AlertManager::new(config);
//!
//! manager.alert(Alert::new(
//!     AlertSeverity::High,
//!     "Brute force attack detected",
//!     AlertCategory::Security,
//! ));
//! ```
//!
//! ## Health Checks (CA-7)
//!
//! ```ignore
//! use barbican::health::{HealthChecker, HealthCheck, HealthStatus};
//!
//! let mut checker = HealthChecker::new();
//! checker.add_check("database", HealthCheck::new(|| async {
//!     HealthStatus::healthy()
//! }));
//!
//! let report = checker.check_all().await;
//! ```
//!
//! ## Key Management (SC-12)
//!
//! ```ignore
//! use barbican::keys::{KeyStore, EnvKeyStore, RotationTracker, RotationPolicy};
//!
//! // Development: environment-based keys
//! let store = EnvKeyStore::new("MYAPP_")?;
//! let key = store.get_key("encryption_key").await?;
//!
//! // Production: implement KeyStore trait for Vault/AWS KMS
//! let tracker = RotationTracker::new(RotationPolicy::default());
//! if tracker.needs_rotation("api-key")? {
//!     // Trigger key rotation
//! }
//! ```
//!
//! ## Supply Chain Security (SR-3, SR-4)
//!
//! ```ignore
//! use barbican::supply_chain::{parse_cargo_lock, generate_cyclonedx_sbom, SbomMetadata};
//!
//! let deps = parse_cargo_lock("Cargo.lock")?;
//! let sbom = generate_cyclonedx_sbom(&deps, SbomMetadata::new("myapp", "1.0.0"));
//! ```
//!
//! ## Security Testing (SA-11, CA-8)
//!
//! ```ignore
//! use barbican::testing::{xss_payloads, sql_injection_payloads, SecurityHeaders};
//!
//! // Fuzz test your endpoints
//! for payload in xss_payloads() {
//!     let response = client.post("/api/comment").body(payload).send().await?;
//!     assert!(!response.text().contains(payload));
//! }
//!
//! // Validate security headers
//! let headers = SecurityHeaders::from_response(&response);
//! assert!(headers.validate().is_empty());
//! ```
//!
//! ## Input Validation (SI-10)
//!
//! ```ignore
//! use barbican::validation::{validate_email, validate_length, sanitize_html};
//!
//! fn validate_user_input(email: &str, bio: &str) -> Result<(), ValidationError> {
//!     validate_email(email)?;
//!     validate_length(bio, 0, 500, "bio")?;
//!     let safe_bio = sanitize_html(bio);
//!     Ok(())
//! }
//! ```
//!
//! ## Password Validation (IA-5(1))
//!
//! ```ignore
//! use barbican::password::PasswordPolicy;
//!
//! let policy = PasswordPolicy::default(); // NIST 800-63B compliant
//! policy.validate_with_context(password, Some(username), Some(email))?;
//! ```
//!
//! ## Error Handling (SI-11)
//!
//! ```ignore
//! use barbican::error::{AppError, Result};
//!
//! async fn handler() -> Result<String> {
//!     let data = fetch_data()
//!         .map_err(|e| AppError::internal("Failed to fetch data", e))?;
//!     Ok(data)
//! }
//! // In production: {"error": "internal_error", "message": "An internal error occurred"}
//! // In development: full error details included
//! ```
//!
//! ## OAuth/OIDC Integration (IA-2)
//!
//! ```ignore
//! use barbican::auth::{Claims, log_access_decision, MfaPolicy};
//!
//! async fn admin_handler(claims: Claims) -> Result<&'static str, StatusCode> {
//!     // Verify MFA for sensitive operations
//!     let mfa_policy = MfaPolicy::required();
//!     if !mfa_policy.is_satisfied(&claims) {
//!         return Err(StatusCode::FORBIDDEN);
//!     }
//!
//!     if claims.has_role("admin") {
//!         log_access_decision(&claims, "admin_panel", true);
//!         Ok("Welcome!")
//!     } else {
//!         log_access_decision(&claims, "admin_panel", false);
//!         Err(StatusCode::FORBIDDEN)
//!     }
//! }
//! ```
//!
//! ## Compliance Coverage
//!
//! Barbican implements 52 NIST 800-53 Rev 5 controls and facilitates 32 additional controls:
//!
//! | Framework | Coverage |
//! |-----------|----------|
//! | NIST SP 800-53 Rev 5 | 52 controls implemented |
//! | NIST SP 800-63B | Password policy compliance |
//! | SOC 2 Type II | ~75% of applicable criteria |
//! | FedRAMP | ~70% of applicable controls |
//! | OAuth 2.0 / OIDC | JWT claims with MFA support |
//! | OWASP Top 10 | Input validation, secure error handling |
//!
//! See `.claudedocs/SECURITY_CONTROL_REGISTRY.md` for the complete control matrix.

mod config;
mod crypto;
#[cfg(feature = "postgres")]
mod database;
mod layers;
mod parse;

// Authentication & Authorization modules
pub mod auth;
pub mod login;
pub mod password;
pub mod session;

// Data Protection modules
pub mod error;
pub mod validation;

// Operational Security modules
pub mod alerting;
pub mod health;
pub mod keys;
pub mod observability;
pub mod supply_chain;
pub mod testing;

// Re-exports for convenience
pub use config::{SecurityConfig, SecurityConfigBuilder};
pub use crypto::{constant_time_eq, constant_time_str_eq};
pub use layers::SecureRouter;
pub use observability::ObservabilityConfigBuilder;
pub use parse::{parse_duration, parse_size};

// Error handling re-exports
pub use error::{AppError, ErrorConfig, ErrorKind};

// Validation re-exports
pub use validation::{ValidationError, ValidationErrorCode, Validate};

// Password policy re-exports
pub use password::{PasswordError, PasswordPolicy, PasswordStrength};

// Auth re-exports
pub use auth::{Claims, log_access_decision, log_access_denied, MfaPolicy, log_mfa_success, log_mfa_required};

// Session management re-exports (AC-11, AC-12)
pub use session::{SessionPolicy, SessionState, SessionTerminationReason};

// Login tracking re-exports (AC-7)
pub use login::{LockoutPolicy, LoginTracker, AttemptResult, LockoutInfo};

// Alerting re-exports (IR-4, IR-5)
pub use alerting::{AlertConfig, AlertManager, Alert, AlertSeverity, AlertCategory};

// Health check re-exports (CA-7)
pub use health::{HealthChecker, HealthCheck, HealthStatus, HealthReport, Status as HealthStatusKind};

// Key management re-exports (SC-12)
pub use keys::{KeyStore, KeyMetadata, KeyPurpose, KeyState, RotationTracker, RotationPolicy};

// Supply chain re-exports (SR-3, SR-4)
pub use supply_chain::{
    Dependency, DependencySource, AuditResult, VulnerabilitySeverity,
    SbomMetadata, LicensePolicy, parse_cargo_lock, generate_cyclonedx_sbom,
};

// Security testing re-exports (SA-11, CA-8)
pub use testing::{
    xss_payloads, sql_injection_payloads, command_injection_payloads,
    SecurityHeaders, HeaderIssue, RateLimitTestResult,
};

#[cfg(feature = "postgres")]
pub use database::{
    create_pool, health_check, DatabaseConfig, DatabaseConfigBuilder, DatabaseError,
    HealthStatus, SslMode,
};
