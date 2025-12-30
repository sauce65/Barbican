// AUTO-GENERATED FROM barbican.toml - DO NOT EDIT
// Regenerate with: barbican generate rust
// Profile: FedRAMP Low
// Generated: 2025-12-30 18:57:36 UTC

use barbican::prelude::*;
use std::time::Duration;

/// Configuration constants from barbican.toml
pub struct GeneratedConfig;

impl GeneratedConfig {
    // =========================================================================
    // Application Metadata
    // =========================================================================

    /// Application name
    pub const APP_NAME: &'static str = "hello-fedramp-low";

    /// Application version
    pub const APP_VERSION: &'static str = "0.1.0";

    /// Compliance profile
    pub const PROFILE: ComplianceProfile = ComplianceProfile::FedRampLow;

    // =========================================================================
    // Session Timeouts (AC-11, AC-12)
    // =========================================================================

    /// Idle timeout in seconds (AC-11)
    pub const IDLE_TIMEOUT_SECS: u64 = 900;

    /// Maximum session lifetime in seconds (AC-12)
    pub const SESSION_TIMEOUT_SECS: u64 = 1800;

    /// Create session policy with profile-appropriate timeouts
    pub fn session_policy() -> SessionPolicy {
        SessionPolicy::builder()
            .idle_timeout(Duration::from_secs(Self::IDLE_TIMEOUT_SECS))
            .max_lifetime(Duration::from_secs(Self::SESSION_TIMEOUT_SECS))
            .build()
    }

    // =========================================================================
    // Login Security (AC-7)
    // =========================================================================

    /// Maximum failed login attempts before lockout
    pub const MAX_LOGIN_ATTEMPTS: u32 = 5;

    /// Lockout duration in seconds
    pub const LOCKOUT_DURATION_SECS: u64 = 900;

    /// Create lockout policy
    pub fn lockout_policy() -> LockoutPolicy {
        LockoutPolicy::builder()
            .max_attempts(Self::MAX_LOGIN_ATTEMPTS)
            .lockout_duration(Duration::from_secs(Self::LOCKOUT_DURATION_SECS))
            .build()
    }

    // =========================================================================
    // Authentication (IA-2, IA-5)
    // =========================================================================

    /// Whether MFA is required for this profile
    pub const MFA_REQUIRED: bool = false;

    /// Minimum password length (IA-5)
    pub const MIN_PASSWORD_LENGTH: usize = 8;

    /// Create MFA policy
    pub fn mfa_policy() -> MfaPolicy {
        if Self::MFA_REQUIRED {
            MfaPolicy::require_mfa()
        } else {
            MfaPolicy::none()
        }
    }

    /// Create password policy
    pub fn password_policy() -> PasswordPolicy {
        PasswordPolicy::builder()
            .min_length(Self::MIN_PASSWORD_LENGTH)
            .build()
    }

    // =========================================================================
    // TLS/Transport Security (SC-8)
    // =========================================================================

    /// Create security configuration with TLS enforcement
    pub fn security_config() -> SecurityConfig {
        SecurityConfig::builder()
            .tls_mode(TlsMode::Required)
            .audit(true)
            .build()
    }

    // =========================================================================
    // Audit/Observability (AU-11)
    // =========================================================================

    /// Minimum log retention in days
    pub const MIN_RETENTION_DAYS: u32 = 30;

    // =========================================================================
    // Database (SC-8)
    // =========================================================================

    /// Database pool size
    pub const DB_POOL_SIZE: u32 = 10;

    /// Database connection URL from environment
    #[cfg(feature = "postgres")]
    pub fn database_url() -> String {
        std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set")
    }

    /// Create database configuration
    #[cfg(feature = "postgres")]
    pub fn database_config(url: &str) -> DatabaseConfig {
        DatabaseConfig::builder(url)
            .ssl_mode(SslMode::Require)
            .max_connections(Self::DB_POOL_SIZE)
            .build()
    }
}

// =============================================================================
// Router Extension
// =============================================================================

/// Extension trait for applying Barbican security to an Axum router
pub trait BarbicanApp {
    /// Apply all security middleware from the generated configuration
    fn with_barbican(self) -> Self;
}

impl<S> BarbicanApp for axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn with_barbican(self) -> Self {
        self.with_security(GeneratedConfig::security_config())
    }
}
