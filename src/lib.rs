//! # Barbican
//!
//! NIST 800-53 compliant security infrastructure for Axum applications.
//!
//! Barbican provides 18 pluggable security modules implementing 56+ NIST 800-53 controls
//! for building production-ready, compliance-aware web applications.
//!
//! ## Security Modules
//!
//! ### Infrastructure Layer
//! - **[`layers`]**: Security headers, rate limiting, CORS, timeouts (SC-5, SC-8, CM-6, AC-4)
//! - **[`rate_limit`]**: Tiered rate limiting with lockout support (SC-5, AC-7)
//! - **[`tls`]**: HTTP TLS enforcement middleware (SC-8, SC-8(1))
//! - **[`audit`]**: Security-aware HTTP audit middleware (AU-2, AU-3, AU-12)
//! - **[`observability`]**: Structured logging, metrics, distributed tracing (AU-2, AU-3, AU-12)
//! - **[`observability::stack`]**: FedRAMP-compliant observability infrastructure generator (20 controls)
//! - **Database** (feature: `postgres`): SSL/TLS, connection pooling, health checks (SC-8, IA-5)
//!
//! ### Authentication & Authorization
//! - **[`auth`]**: OAuth/OIDC JWT claims, MFA policy enforcement (IA-2, IA-5, AC-2)
//! - **[`jwt_secret`]**: JWT secret validation with entropy checks and weak pattern detection (IA-5, SC-12)
//! - **[`password`]**: NIST 800-63B compliant password validation (IA-5(1))
//! - **[`login`]**: Login attempt tracking, account lockout (AC-7)
//! - **[`session`]**: Session management, idle/absolute timeout (AC-11, AC-12, SC-10)
//!
//! ### Operational Security
//! - **[`alerting`]**: Security incident alerting with rate limiting (IR-4, IR-5)
//! - **[`health`]**: Health check framework with aggregation (CA-7)
//! - **[`keys`]**: Key management with KMS integration traits (SC-12)
//! - **[`secrets`]**: Secret detection scanner for embedded authenticators (IA-5(7))
//! - **[`supply_chain`]**: SBOM generation, license compliance, vulnerability audit (SR-3, SR-4)
//! - **[`testing`]**: Security test utilities, header verification and generation (SA-11, CA-8, SC-8, CM-6)
//! - **[`integration`]**: Application integration helpers (profile detection, config builders)
//!
//! ### Data Protection
//! - **[`encryption`]**: Field-level encryption for data at rest (SC-28)
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
//! ## JWT Secret Validation (IA-5, SC-12)
//!
//! ```ignore
//! use barbican::jwt_secret::{JwtSecretValidator, JwtSecretPolicy};
//! use barbican::compliance::config;
//!
//! // Derive policy from compliance profile (recommended)
//! let policy = JwtSecretPolicy::for_compliance(config().profile);
//!
//! // Or use environment-aware defaults
//! let policy = JwtSecretPolicy::for_environment("production");
//!
//! // Validate a secret
//! let validator = JwtSecretValidator::new(policy);
//! validator.validate("my-jwt-secret")?;
//!
//! // Generate a cryptographically secure secret
//! let secret = JwtSecretValidator::generate_secure_secret(64);
//! ```
//!
//! ## Security Headers (SC-8, CM-6)
//!
//! ```ignore
//! use barbican::testing::SecurityHeaders;
//! use barbican::compliance::ComplianceProfile;
//!
//! // Generate headers for API endpoints
//! let headers = SecurityHeaders::api();
//! for (name, value) in headers.to_header_pairs() {
//!     response.headers_mut().insert(name, value.parse().unwrap());
//! }
//!
//! // Production headers with HSTS preload
//! let headers = SecurityHeaders::production();
//!
//! // Compliance-aware headers (FedRAMP High uses strict())
//! let headers = SecurityHeaders::for_compliance(ComplianceProfile::FedRampHigh);
//!
//! // Verify response headers meet security requirements
//! let expected = SecurityHeaders::strict();
//! let issues = expected.verify(&response_headers);
//! assert!(issues.is_empty());
//! ```
//!
//! ## Security Testing (SA-11, CA-8)
//!
//! ```ignore
//! use barbican::testing::{xss_payloads, sql_injection_payloads, SecurityHeaders};
//!
//! // Fuzz test your endpoints for XSS vulnerabilities
//! for payload in xss_payloads() {
//!     let response = client.post("/api/comment").body(payload).send().await?;
//!     assert!(!response.text().contains(payload)); // Should be escaped
//! }
//!
//! // Validate security headers on responses
//! let expected = SecurityHeaders::default();
//! let issues = expected.verify(&response_headers);
//! assert!(issues.is_empty());
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
//! Barbican implements 56 NIST 800-53 Rev 5 controls and facilitates 50+ additional controls:
//!
//! | Framework | Coverage |
//! |-----------|----------|
//! | NIST SP 800-53 Rev 5 | 56 controls implemented |
//! | NIST SP 800-63B | Password policy compliance |
//! | SOC 2 Type II | ~85% of applicable criteria |
//! | FedRAMP Moderate | ~80% ready (up from 75%) |
//! | OAuth 2.0 / OIDC | JWT claims with MFA support |
//! | OWASP Top 10 | Input validation, secure error handling |
//!
//! **Compliance Artifacts**: 29 control tests generate auditor-verifiable JSON artifacts with HMAC signatures.
//!
//! See `.claudedocs/SECURITY_CONTROL_REGISTRY.md` for the complete control matrix.
//! See `.claudedocs/NIST_800_53_CROSSWALK.md` for auditor-friendly control-to-code mappings.

mod config;
mod crypto;
#[cfg(feature = "postgres")]
mod database;
mod layers;
mod parse;
pub mod tls;

// Rate limiting with tiered support (SC-5, AC-7)
pub mod rate_limit;

// Security audit middleware (AU-2, AU-3, AU-12)
pub mod audit;

// Compliance framework
pub mod compliance;

// Authentication & Authorization modules
pub mod auth;
pub mod jwt_secret;
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
pub mod encryption;
pub mod secrets;
pub mod supply_chain;
pub mod testing;

// Integration support module
pub mod integration;

// Re-exports for convenience
pub use config::{SecurityConfig, SecurityConfigBuilder};
pub use crypto::{constant_time_eq, constant_time_str_eq};
pub use layers::SecureRouter;
pub use observability::ObservabilityConfigBuilder;
pub use parse::{parse_duration, parse_size};

// Error handling re-exports
pub use error::{AppError, ErrorConfig, ErrorKind};

// Validation re-exports (SI-10)
pub use validation::{
    ValidationError, ValidationErrorCode, Validate,
    // SI-10 Enforcement Extractors
    ValidationConfig, ValidationRejection, ValidatedJson, ValidatedQuery, ValidatedPath,
    // Validator functions
    validate_required, validate_length, validate_email, validate_url,
    validate_alphanumeric_underscore, validate_slug, validate_ascii_printable,
    validate_one_of, validate_range, validate_positive,
    validate_collection_size, validate_unique, validate_safe_content,
    // Sanitization functions
    sanitize_html, escape_html, escape_sql_like, strip_null_bytes,
    contains_dangerous_patterns,
};

// Password policy re-exports
pub use password::{PasswordError, PasswordPolicy, PasswordStrength};

// JWT secret validation re-exports (IA-5, SC-12)
pub use jwt_secret::{JwtSecretError, JwtSecretPolicy, JwtSecretValidator};

// Auth re-exports
pub use auth::{Claims, log_access_decision, log_access_denied, MfaPolicy, log_mfa_success, log_mfa_required};

// Session management re-exports (AC-11, AC-12)
pub use session::{
    SessionPolicy, SessionState, SessionTerminationReason,
    // AC-11/AC-12 Enforcement Middleware
    SessionConfig, SessionExtension, session_enforcement_middleware,
};

// Login tracking re-exports (AC-7)
pub use login::{
    AttemptResult, LockoutInfo, LockoutPolicy, LoginTracker,
    // AC-7 Enforcement Middleware
    LoginTrackingConfig, LoginTrackerExtension, login_tracking_middleware,
    LOGIN_IDENTIFIER_HEADER,
};

// Alerting re-exports (IR-4, IR-5)
pub use alerting::{
    AlertConfig, AlertManager, Alert, AlertSeverity, AlertCategory,
    alert_critical, alert_brute_force, alert_account_locked,
    alert_suspicious_activity, alert_database_disconnected,
    // IR-4 Enforcement: Axum Integration
    AlertingExtension, alerting_middleware, alerting_layer,
    // IR-5 Enforcement: Incident Tracking
    Incident, IncidentStatus, IncidentError, IncidentStore,
    InMemoryIncidentStore, IncidentTracker, IncidentTrackerConfig,
    IncidentTrackerExtension, incident_tracking_middleware,
};

// Health check re-exports (CA-7)
pub use health::{
    HealthChecker, HealthCheck, HealthStatus, HealthReport, Status as HealthStatusKind,
    HealthCheckConfig, always_healthy, always_unhealthy, memory_check, http_check,
    // CA-7 Enforcement: Axum Health Endpoints
    HealthEndpointConfig, HealthResponse, CheckResult, HealthState, HealthExtension,
    health_routes,
};

// Key management re-exports (SC-12)
pub use keys::{
    KeyStore, KeyMetadata, KeyPurpose, KeyState, KeyMaterial, KeyError,
    RotationTracker, RotationPolicy, RotationStatus, EnvKeyStore,
    // SC-12 Enforcement: Axum Integration
    InMemoryKeyStore, KeyStoreExtension, key_store_middleware,
};

// Encryption at rest re-exports (SC-28)
pub use encryption::{
    FieldEncryptor, EncryptedField, EncryptionConfig, EncryptionAlgorithm,
    EncryptionStatus, EncryptionError, generate_key, is_fips_mode, fips_certificate,
    verify_encryption_config,
    // SC-28 Enforcement Middleware
    EncryptionEnforcementConfig, EncryptionExtension, encryption_enforcement_middleware,
    validate_encryption_startup,
};
#[cfg(feature = "postgres")]
pub use encryption::verify_encryption_with_database;

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
    create_pool, health_check, ChannelBinding, DatabaseConfig, DatabaseConfigBuilder,
    DatabaseError, HealthStatus as DbHealthStatus, SslMode,
};

// Compliance re-exports
pub use compliance::{ComplianceConfig, ComplianceProfile, ComplianceValidator};

// Audit middleware re-exports (AU-2, AU-3, AU-12)
pub use audit::{audit_middleware, extract_client_ip, AuditRecord, AuditOutcome};

// Audit integrity re-exports (AU-9)
pub use audit::integrity::{
    AuditChain, AuditIntegrityConfig, AuditIntegrityError, AuditLogDestination,
    ChainVerificationResult, SignatureAlgorithm, SignedAuditRecord,
    verify_record, verify_records_from_json,
    // AU-9 Enforcement: Axum Integration
    AuditChainExtension,
};

// TLS enforcement re-exports (SC-8, SC-8(1))
pub use tls::{TlsMode, TlsInfo, detect_tls, tls_enforcement_middleware};

// mTLS enforcement re-exports (IA-3, SC-8 for FedRAMP High)
pub use tls::{MtlsMode, ClientCertInfo, detect_client_cert, mtls_enforcement_middleware};

// Tiered rate limiting re-exports (SC-5, AC-7)
pub use rate_limit::{
    RateLimitTier, RateLimitTierConfig, RateLimitStatus, RateLimitError,
    TieredRateLimiter, TieredRateLimiterBuilder, TierResolver, DefaultTierResolver,
    tiered_rate_limit_middleware, tiered_rate_limit_middleware_with_proxy,
};
