//! Unified Compliance Configuration
//!
//! Central configuration derived from compliance profile.
//! Uses global OnceLock pattern (like ErrorConfig) for app-wide access.
//!
//! # Initialization
//!
//! Initialize once at application startup:
//!
//! ```ignore
//! use barbican::compliance::{ComplianceConfig, init};
//!
//! let config = ComplianceConfig::from_env();
//! init(config);
//! ```
//!
//! # Global Access
//!
//! Access the configuration anywhere in the application:
//!
//! ```ignore
//! use barbican::compliance::config;
//!
//! let compliance = config();
//! if compliance.require_mfa {
//!     // Enforce MFA
//! }
//! ```

use std::sync::OnceLock;
use std::time::Duration;

use super::ComplianceProfile;

static COMPLIANCE_CONFIG: OnceLock<ComplianceConfig> = OnceLock::new();

/// Initialize global compliance configuration (call once at startup)
///
/// This should be called early in application initialization, before
/// any components that depend on compliance settings are created.
///
/// # Example
///
/// ```ignore
/// let config = ComplianceConfig::from_env();
/// barbican::compliance::init(config);
/// ```
pub fn init(config: ComplianceConfig) {
    if COMPLIANCE_CONFIG.set(config.clone()).is_err() {
        tracing::warn!("Compliance configuration already initialized");
        return;
    }
    tracing::info!(
        profile = %config.profile.name(),
        framework = %config.profile.framework(),
        require_mfa = config.require_mfa,
        require_encryption_at_rest = config.require_encryption_at_rest,
        session_timeout_mins = config.session_max_lifetime.as_secs() / 60,
        "Compliance configuration initialized"
    );
}

/// Get the global compliance configuration
///
/// If called before `init()`, this will initialize with defaults from
/// environment variables and log a warning.
///
/// # Example
///
/// ```ignore
/// let compliance = barbican::compliance::config();
/// let password_policy = PasswordPolicy::from_compliance(compliance);
/// ```
pub fn config() -> &'static ComplianceConfig {
    COMPLIANCE_CONFIG.get_or_init(|| {
        tracing::warn!(
            "Compliance config accessed before init(), using defaults from environment"
        );
        ComplianceConfig::from_env()
    })
}

/// Unified compliance configuration for the application
///
/// This struct contains all security settings derived from the selected
/// compliance profile. Use `from_profile()` or `from_env()` to create,
/// then pass to security module `from_compliance()` methods.
///
/// # Example
///
/// ```ignore
/// use barbican::compliance::{ComplianceConfig, ComplianceProfile};
///
/// // From explicit profile
/// let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
///
/// // From environment variable
/// let config = ComplianceConfig::from_env();
/// ```
#[derive(Debug, Clone)]
pub struct ComplianceConfig {
    /// The active compliance profile
    pub profile: ComplianceProfile,

    // =========================================================================
    // Session settings (AC-11, AC-12)
    // =========================================================================
    /// Maximum session lifetime from creation (AC-12)
    pub session_max_lifetime: Duration,

    /// Idle timeout before session lock/termination (AC-11)
    pub session_idle_timeout: Duration,

    /// Timeout for re-authentication on sensitive operations
    pub reauth_timeout: Duration,

    // =========================================================================
    // Authentication settings (IA-2)
    // =========================================================================
    /// Whether any form of MFA is required
    pub require_mfa: bool,

    /// Whether hardware MFA tokens are required (FIDO2, etc.)
    pub require_hardware_mfa: bool,

    // =========================================================================
    // Password settings (IA-5)
    // =========================================================================
    /// Minimum password length
    pub password_min_length: usize,

    /// Whether to check passwords against breach databases
    pub password_check_breach_db: bool,

    // =========================================================================
    // Login security (AC-7)
    // =========================================================================
    /// Maximum failed login attempts before lockout
    pub max_login_attempts: u32,

    /// Duration of account lockout
    pub lockout_duration: Duration,

    // =========================================================================
    // Key management (SC-12)
    // =========================================================================
    /// Cryptographic key rotation interval
    pub key_rotation_interval: Duration,

    // =========================================================================
    // Data protection (SC-8, SC-28)
    // =========================================================================
    /// Whether TLS is required for all communications
    pub require_tls: bool,

    /// Whether mutual TLS is required for service-to-service
    pub require_mtls: bool,

    /// Whether encryption at rest is required
    pub require_encryption_at_rest: bool,

    // =========================================================================
    // Multi-tenancy
    // =========================================================================
    /// Whether tenant data isolation is required
    pub require_tenant_isolation: bool,

    // =========================================================================
    // Audit (AU-11)
    // =========================================================================
    /// Minimum audit log retention in days
    pub min_retention_days: u32,
}

impl ComplianceConfig {
    /// Create configuration from a compliance profile
    ///
    /// All settings are derived from the profile's requirements.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
    /// assert!(config.require_mfa);
    /// assert!(config.require_hardware_mfa);
    /// ```
    pub fn from_profile(profile: ComplianceProfile) -> Self {
        Self {
            profile,
            session_max_lifetime: profile.session_timeout(),
            session_idle_timeout: profile.idle_timeout(),
            reauth_timeout: match profile {
                ComplianceProfile::FedRampLow | ComplianceProfile::Development => Duration::from_secs(60 * 60), // 1 hour
                ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => {
                    Duration::from_secs(15 * 60) // 15 minutes
                }
                ComplianceProfile::FedRampHigh => Duration::from_secs(5 * 60), // 5 minutes
                ComplianceProfile::Custom => Duration::from_secs(15 * 60),     // 15 minutes
            },
            require_mfa: profile.requires_mfa(),
            require_hardware_mfa: matches!(profile, ComplianceProfile::FedRampHigh),
            password_min_length: profile.min_password_length(),
            password_check_breach_db: profile.requires_breach_checking(),
            max_login_attempts: profile.max_login_attempts(),
            lockout_duration: profile.lockout_duration(),
            key_rotation_interval: profile.key_rotation_interval(),
            require_tls: profile.requires_tls(),
            require_mtls: profile.requires_mtls(),
            require_encryption_at_rest: profile.requires_encryption_at_rest(),
            require_tenant_isolation: profile.requires_tenant_isolation(),
            min_retention_days: profile.min_retention_days(),
        }
    }

    /// Load from environment variable COMPLIANCE_PROFILE
    ///
    /// # Environment Variables
    ///
    /// - `COMPLIANCE_PROFILE`: Profile selection
    ///   - `"fedramp-low"` or `"low"` → FedRAMP Low
    ///   - `"fedramp-moderate"` or `"moderate"` → FedRAMP Moderate (default)
    ///   - `"fedramp-high"` or `"high"` → FedRAMP High
    ///   - `"soc2"` → SOC 2 Type II
    ///   - `"custom"` → Custom profile
    ///
    /// # Example
    ///
    /// ```ignore
    /// std::env::set_var("COMPLIANCE_PROFILE", "fedramp-high");
    /// let config = ComplianceConfig::from_env();
    /// assert_eq!(config.profile, ComplianceProfile::FedRampHigh);
    /// ```
    pub fn from_env() -> Self {
        let profile = std::env::var("COMPLIANCE_PROFILE")
            .map(|s| match s.to_lowercase().as_str() {
                "fedramp-low" | "low" => ComplianceProfile::FedRampLow,
                "fedramp-high" | "high" => ComplianceProfile::FedRampHigh,
                "soc2" | "soc-2" => ComplianceProfile::Soc2,
                "custom" => ComplianceProfile::Custom,
                // Default to Moderate for unrecognized values
                _ => ComplianceProfile::FedRampModerate,
            })
            .unwrap_or(ComplianceProfile::FedRampModerate);

        Self::from_profile(profile)
    }

    /// Check if this configuration represents a high-security profile
    pub fn is_high_security(&self) -> bool {
        matches!(self.profile, ComplianceProfile::FedRampHigh)
    }

    /// Check if this is a FedRAMP profile
    pub fn is_fedramp(&self) -> bool {
        self.profile.is_fedramp()
    }
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self::from_profile(ComplianceProfile::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_profile_low() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampLow);
        assert!(!config.require_mfa);
        assert!(!config.require_hardware_mfa);
        assert!(!config.require_encryption_at_rest);
        assert_eq!(config.password_min_length, 8);
        // STIG UBTU-22-411045: 3 attempts for ALL FedRAMP levels
        assert_eq!(config.max_login_attempts, 3);
        assert_eq!(config.min_retention_days, 30);
    }

    #[test]
    fn test_from_profile_moderate() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        assert!(config.require_mfa);
        assert!(!config.require_hardware_mfa);
        assert!(config.require_encryption_at_rest);
        // STIG UBTU-22-611035: 15 characters for FedRAMP Moderate/High
        assert_eq!(config.password_min_length, 15);
        assert_eq!(config.max_login_attempts, 3);
        assert_eq!(config.min_retention_days, 90);
    }

    #[test]
    fn test_from_profile_high() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
        assert!(config.require_mfa);
        assert!(config.require_hardware_mfa);
        assert!(config.require_encryption_at_rest);
        assert!(config.require_mtls);
        // STIG UBTU-22-611035: 15 characters for FedRAMP Moderate/High
        assert_eq!(config.password_min_length, 15);
        assert_eq!(config.max_login_attempts, 3);
        assert_eq!(config.min_retention_days, 365);
        // FedRAMP High: 10-minute max session and idle timeout
        assert_eq!(
            config.session_max_lifetime,
            Duration::from_secs(10 * 60)
        );
        assert_eq!(config.session_idle_timeout, Duration::from_secs(10 * 60));
    }

    #[test]
    fn test_from_profile_soc2() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::Soc2);
        assert!(config.require_mfa);
        assert!(config.require_encryption_at_rest);
        // SOC 2 aligns with FedRAMP Moderate: 15 characters
        assert_eq!(config.password_min_length, 15);
        assert_eq!(config.min_retention_days, 90);
    }

    #[test]
    fn test_default_is_moderate() {
        let config = ComplianceConfig::default();
        assert_eq!(config.profile, ComplianceProfile::FedRampModerate);
    }

    #[test]
    fn test_is_high_security() {
        assert!(
            ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh).is_high_security()
        );
        assert!(
            !ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate).is_high_security()
        );
    }

    #[test]
    fn test_is_fedramp() {
        assert!(ComplianceConfig::from_profile(ComplianceProfile::FedRampLow).is_fedramp());
        assert!(ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate).is_fedramp());
        assert!(ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh).is_fedramp());
        assert!(!ComplianceConfig::from_profile(ComplianceProfile::Soc2).is_fedramp());
    }
}
