//! Compliance Profile Definitions
//!
//! Defines security profiles for multiple compliance frameworks including
//! FedRAMP, SOC 2, and custom configurations.
//!
//! # Profile Selection
//!
//! Each profile defines security requirements that cascade through the application:
//!
//! | Profile | Session Timeout | Idle Timeout | MFA | Password Min | Key Rotation |
//! |---------|-----------------|--------------|-----|--------------|--------------|
//! | FedRAMP Low | 30 min | 15 min | No | 8 | 90 days |
//! | FedRAMP Moderate | 15 min | 10 min | Yes | 12 | 90 days |
//! | FedRAMP High | 10 min | 5 min | Yes | 14 | 30 days |
//! | SOC 2 | 15 min | 10 min | Yes | 12 | 90 days |

use std::time::Duration;

/// Compliance framework and impact level
///
/// Determines security settings across the entire application based on
/// the selected compliance framework and impact level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComplianceProfile {
    /// FedRAMP Low impact - basic security controls
    ///
    /// Suitable for systems where loss of confidentiality, integrity, or
    /// availability would have limited adverse effect.
    FedRampLow,

    /// FedRAMP Moderate impact - enhanced security controls (most common)
    ///
    /// Suitable for systems where loss would have serious adverse effect.
    /// This is the most common FedRAMP authorization level.
    #[default]
    FedRampModerate,

    /// FedRAMP High impact - maximum security controls
    ///
    /// Suitable for systems where loss would have severe or catastrophic
    /// adverse effect. Requires the most stringent controls.
    FedRampHigh,

    /// SOC 2 Type II baseline
    ///
    /// Aligned with AICPA Trust Services Criteria for security,
    /// availability, processing integrity, confidentiality, and privacy.
    Soc2,

    /// Custom profile with explicit settings
    ///
    /// Use when compliance requirements don't fit standard profiles.
    /// Settings default to FedRAMP Moderate equivalents.
    Custom,

    /// Development profile - no security hardening
    ///
    /// Use for local development only. Disables container user restrictions,
    /// read-only filesystems, and capability dropping to avoid Docker volume
    /// permission issues. Never use in production.
    Development,
}

impl ComplianceProfile {
    /// Human-readable name for display and logging
    pub fn name(&self) -> &'static str {
        match self {
            Self::FedRampLow => "FedRAMP Low",
            Self::FedRampModerate => "FedRAMP Moderate",
            Self::FedRampHigh => "FedRAMP High",
            Self::Soc2 => "SOC 2 Type II",
            Self::Custom => "Custom",
            Self::Development => "Development",
        }
    }

    /// Framework family for grouping and reporting
    pub fn framework(&self) -> &'static str {
        match self {
            Self::FedRampLow | Self::FedRampModerate | Self::FedRampHigh => "FedRAMP",
            Self::Soc2 => "SOC 2",
            Self::Custom => "Custom",
            Self::Development => "None",
        }
    }

    /// Whether this is a FedRAMP profile
    pub fn is_fedramp(&self) -> bool {
        matches!(
            self,
            Self::FedRampLow | Self::FedRampModerate | Self::FedRampHigh
        )
    }

    /// Whether this is a development-only profile with no security hardening
    pub fn is_development(&self) -> bool {
        matches!(self, Self::Development)
    }

    // =========================================================================
    // Audit Controls (AU Family)
    // =========================================================================

    /// Minimum log retention in days (AU-11)
    ///
    /// FedRAMP requirements:
    /// - Low: 30 days minimum
    /// - Moderate: 90 days minimum
    /// - High: 365 days minimum (1 year)
    pub fn min_retention_days(&self) -> u32 {
        match self {
            Self::FedRampLow | Self::Development => 30,
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 90,
            Self::FedRampHigh => 365,
        }
    }

    // =========================================================================
    // System and Communications Protection (SC Family)
    // =========================================================================

    /// Whether TLS is required for all communications (SC-8)
    ///
    /// All compliance profiles require TLS for data in transit.
    pub fn requires_tls(&self) -> bool {
        !matches!(self, Self::Development) // Development mode skips TLS
    }

    /// Whether mutual TLS (mTLS) is required for service-to-service (SC-8)
    ///
    /// Only FedRAMP High requires mTLS for all service communications.
    pub fn requires_mtls(&self) -> bool {
        matches!(self, Self::FedRampHigh)
    }

    /// Whether SSL certificate verification is required (SC-8)
    ///
    /// FedRAMP Moderate and above require full certificate verification
    /// (VerifyFull mode) to prevent MITM attacks on database connections.
    /// FedRAMP Low allows Require mode (encryption without cert validation).
    pub fn requires_ssl_verify_full(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Whether encryption at rest is required (SC-28)
    ///
    /// FedRAMP Moderate and High require encryption of data at rest.
    /// SOC 2 also requires it for sensitive data.
    pub fn requires_encryption_at_rest(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Key rotation interval (SC-12)
    ///
    /// Cryptographic keys must be rotated periodically:
    /// - Low/Moderate/SOC 2: 90 days
    /// - High: 30 days for increased security
    pub fn key_rotation_interval(&self) -> Duration {
        match self {
            Self::FedRampHigh => Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            _ => Duration::from_secs(90 * 24 * 60 * 60),                 // 90 days
        }
    }

    // =========================================================================
    // Identification and Authentication (IA Family)
    // =========================================================================

    /// Whether MFA is required for user authentication (IA-2)
    ///
    /// FedRAMP Moderate and High require MFA for all users.
    /// FedRAMP Low only requires MFA for privileged users.
    pub fn requires_mfa(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Password minimum length requirement (IA-5)
    ///
    /// NIST SP 800-63B recommends:
    /// - Minimum 8 characters (baseline)
    /// - 12+ characters for higher security
    /// - No arbitrary complexity requirements
    pub fn min_password_length(&self) -> usize {
        match self {
            Self::FedRampLow | Self::Development => 8,
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 12,
            Self::FedRampHigh => 14,
        }
    }

    /// Whether breach database checking is required (IA-5)
    ///
    /// NIST SP 800-63B requires checking passwords against known breaches.
    /// Required for Moderate and above.
    pub fn requires_breach_checking(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    // =========================================================================
    // Access Control (AC Family)
    // =========================================================================

    /// Session timeout / maximum lifetime (AC-12)
    ///
    /// Maximum duration a session can remain active regardless of activity.
    pub fn session_timeout(&self) -> Duration {
        match self {
            Self::FedRampLow => Duration::from_secs(30 * 60),  // 30 minutes
            Self::FedRampModerate | Self::Soc2 | Self::Custom => Duration::from_secs(15 * 60), // 15 minutes
            Self::FedRampHigh => Duration::from_secs(10 * 60), // 10 minutes
            Self::Development => Duration::from_secs(24 * 60 * 60), // 24 hours for dev
        }
    }

    /// Idle timeout duration (AC-11)
    ///
    /// Duration of inactivity before session lock/termination.
    pub fn idle_timeout(&self) -> Duration {
        match self {
            Self::FedRampLow => Duration::from_secs(15 * 60), // 15 minutes
            Self::FedRampModerate | Self::Soc2 | Self::Custom => Duration::from_secs(10 * 60), // 10 minutes
            Self::FedRampHigh => Duration::from_secs(5 * 60), // 5 minutes
            Self::Development => Duration::from_secs(24 * 60 * 60), // 24 hours for dev
        }
    }

    /// Max failed login attempts before lockout (AC-7)
    ///
    /// Number of consecutive failed authentication attempts before
    /// the account is temporarily locked.
    pub fn max_login_attempts(&self) -> u32 {
        match self {
            Self::FedRampLow => 5,
            _ => 3,
        }
    }

    /// Lockout duration after failed attempts (AC-7)
    ///
    /// Duration an account remains locked after exceeding max attempts.
    pub fn lockout_duration(&self) -> Duration {
        match self {
            Self::FedRampLow => Duration::from_secs(15 * 60), // 15 minutes
            _ => Duration::from_secs(30 * 60),                // 30 minutes
        }
    }

    /// Whether tenant isolation is required
    ///
    /// Multi-tenant systems must isolate data between tenants
    /// for Moderate and above.
    pub fn requires_tenant_isolation(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_names() {
        assert_eq!(ComplianceProfile::FedRampLow.name(), "FedRAMP Low");
        assert_eq!(ComplianceProfile::FedRampModerate.name(), "FedRAMP Moderate");
        assert_eq!(ComplianceProfile::FedRampHigh.name(), "FedRAMP High");
        assert_eq!(ComplianceProfile::Soc2.name(), "SOC 2 Type II");
        assert_eq!(ComplianceProfile::Custom.name(), "Custom");
    }

    #[test]
    fn test_framework_grouping() {
        assert_eq!(ComplianceProfile::FedRampLow.framework(), "FedRAMP");
        assert_eq!(ComplianceProfile::FedRampModerate.framework(), "FedRAMP");
        assert_eq!(ComplianceProfile::FedRampHigh.framework(), "FedRAMP");
        assert_eq!(ComplianceProfile::Soc2.framework(), "SOC 2");
    }

    #[test]
    fn test_retention_requirements() {
        assert_eq!(ComplianceProfile::FedRampLow.min_retention_days(), 30);
        assert_eq!(ComplianceProfile::FedRampModerate.min_retention_days(), 90);
        assert_eq!(ComplianceProfile::FedRampHigh.min_retention_days(), 365);
        assert_eq!(ComplianceProfile::Soc2.min_retention_days(), 90);
    }

    #[test]
    fn test_session_timeouts() {
        assert_eq!(
            ComplianceProfile::FedRampLow.session_timeout(),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampModerate.session_timeout(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampHigh.session_timeout(),
            Duration::from_secs(10 * 60)
        );
    }

    #[test]
    fn test_idle_timeouts() {
        assert_eq!(
            ComplianceProfile::FedRampLow.idle_timeout(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampHigh.idle_timeout(),
            Duration::from_secs(5 * 60)
        );
    }

    #[test]
    fn test_mfa_requirements() {
        assert!(!ComplianceProfile::FedRampLow.requires_mfa());
        assert!(ComplianceProfile::FedRampModerate.requires_mfa());
        assert!(ComplianceProfile::FedRampHigh.requires_mfa());
        assert!(ComplianceProfile::Soc2.requires_mfa());
    }

    #[test]
    fn test_encryption_requirements() {
        assert!(!ComplianceProfile::FedRampLow.requires_encryption_at_rest());
        assert!(ComplianceProfile::FedRampModerate.requires_encryption_at_rest());
        assert!(ComplianceProfile::FedRampHigh.requires_encryption_at_rest());
    }

    #[test]
    fn test_mtls_requirements() {
        assert!(!ComplianceProfile::FedRampLow.requires_mtls());
        assert!(!ComplianceProfile::FedRampModerate.requires_mtls());
        assert!(ComplianceProfile::FedRampHigh.requires_mtls());
    }

    #[test]
    fn test_ssl_verify_full_requirements() {
        // FedRAMP Low allows Require mode (encryption without cert validation)
        assert!(!ComplianceProfile::FedRampLow.requires_ssl_verify_full());
        // FedRAMP Moderate and above require VerifyFull (SC-8)
        assert!(ComplianceProfile::FedRampModerate.requires_ssl_verify_full());
        assert!(ComplianceProfile::FedRampHigh.requires_ssl_verify_full());
        assert!(ComplianceProfile::Soc2.requires_ssl_verify_full());
    }

    #[test]
    fn test_password_requirements() {
        assert_eq!(ComplianceProfile::FedRampLow.min_password_length(), 8);
        assert_eq!(ComplianceProfile::FedRampModerate.min_password_length(), 12);
        assert_eq!(ComplianceProfile::FedRampHigh.min_password_length(), 14);
    }

    #[test]
    fn test_key_rotation() {
        assert_eq!(
            ComplianceProfile::FedRampModerate.key_rotation_interval(),
            Duration::from_secs(90 * 24 * 60 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampHigh.key_rotation_interval(),
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    #[test]
    fn test_lockout_policy() {
        assert_eq!(ComplianceProfile::FedRampLow.max_login_attempts(), 5);
        assert_eq!(ComplianceProfile::FedRampHigh.max_login_attempts(), 3);
        assert_eq!(
            ComplianceProfile::FedRampLow.lockout_duration(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampHigh.lockout_duration(),
            Duration::from_secs(30 * 60)
        );
    }

    #[test]
    fn test_default_is_moderate() {
        assert_eq!(
            ComplianceProfile::default(),
            ComplianceProfile::FedRampModerate
        );
    }
}
