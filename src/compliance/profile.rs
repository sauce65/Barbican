//! Compliance Profile Definitions
//!
//! Security profiles for FedRAMP, SOC 2, and custom configurations.
//! Values derived from NIST 800-53 Rev 5, FedRAMP Baseline Rev 5, and DISA STIGs.
//!
//! # Profile Summary
//!
//! | Profile | Session | Idle | MFA | Password | Attempts | Lockout | Retention |
//! |---------|---------|------|-----|----------|----------|---------|-----------|
//! | Low | 30m | 15m | No | 8 | 3 | 30m | 30d |
//! | Moderate | 15m | 15m | Yes | 15 | 3 | 30m | 90d |
//! | High | 10m | 10m | Yes+HW | 15 | 3 | 3h | 365d |

use std::time::Duration;

/// Compliance framework and impact level.
///
/// Determines security settings based on FedRAMP impact level or SOC 2 requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComplianceProfile {
    /// FedRAMP Low - limited adverse effect on loss
    FedRampLow,

    /// FedRAMP Moderate - serious adverse effect (most common)
    #[default]
    FedRampModerate,

    /// FedRAMP High - severe/catastrophic adverse effect
    FedRampHigh,

    /// SOC 2 Type II - AICPA Trust Services Criteria
    Soc2,

    /// Custom profile (defaults to Moderate equivalents)
    Custom,

    /// Development only - no security hardening
    Development,
}

impl ComplianceProfile {
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

    pub fn framework(&self) -> &'static str {
        match self {
            Self::FedRampLow | Self::FedRampModerate | Self::FedRampHigh => "FedRAMP",
            Self::Soc2 => "SOC 2",
            Self::Custom => "Custom",
            Self::Development => "None",
        }
    }

    pub fn is_fedramp(&self) -> bool {
        matches!(
            self,
            Self::FedRampLow | Self::FedRampModerate | Self::FedRampHigh
        )
    }

    pub fn is_development(&self) -> bool {
        matches!(self, Self::Development)
    }

    // =========================================================================
    // Audit Controls (AU)
    // =========================================================================

    /// Minimum log retention in days.
    /// Control: AU-11 | STIG: UBTU-22-653045
    pub fn min_retention_days(&self) -> u32 {
        match self {
            Self::FedRampLow | Self::Development => 30,
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 90,
            Self::FedRampHigh => 365,
        }
    }

    // =========================================================================
    // System and Communications Protection (SC)
    // =========================================================================

    /// Whether TLS is required.
    /// Control: SC-8 | STIG: UBTU-22-255050
    pub fn requires_tls(&self) -> bool {
        !matches!(self, Self::Development)
    }

    /// Whether mutual TLS is required for service-to-service.
    /// Control: SC-8(1) | STIG: UBTU-22-612035
    pub fn requires_mtls(&self) -> bool {
        matches!(self, Self::FedRampHigh)
    }

    /// Whether SSL certificate verification (VerifyFull) is required.
    /// Control: SC-8, SC-17
    pub fn requires_ssl_verify_full(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Whether encryption at rest is required.
    /// Control: SC-28 | STIG: UBTU-22-231010
    pub fn requires_encryption_at_rest(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Key rotation interval.
    /// Control: SC-12 | STIG: UBTU-22-671010
    pub fn key_rotation_interval(&self) -> Duration {
        match self {
            Self::FedRampHigh => Duration::from_secs(30 * 24 * 60 * 60),
            _ => Duration::from_secs(90 * 24 * 60 * 60),
        }
    }

    // =========================================================================
    // Identification and Authentication (IA)
    // =========================================================================

    /// Whether MFA is required for all users.
    /// Control: IA-2 | STIG: UBTU-22-612010
    /// Note: Low only requires MFA for privileged users.
    pub fn requires_mfa(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Password minimum length.
    /// Control: IA-5(1) | STIG: UBTU-22-611035 (15 chars)
    /// Low uses 8 chars per SP 800-63B with MFA compensation.
    pub fn min_password_length(&self) -> usize {
        match self {
            Self::FedRampLow | Self::Development => 8,
            _ => 15,
        }
    }

    /// Whether breach database checking is required.
    /// Control: IA-5(1)(a) | SP 800-63B Section 5.1.1.2
    pub fn requires_breach_checking(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    // =========================================================================
    // Access Control (AC)
    // =========================================================================

    /// Session maximum lifetime.
    /// Control: AC-12 | SP 800-63B AAL requirements
    pub fn session_timeout(&self) -> Duration {
        match self {
            Self::FedRampLow => Duration::from_secs(30 * 60),
            Self::FedRampModerate | Self::Soc2 | Self::Custom => Duration::from_secs(15 * 60),
            Self::FedRampHigh => Duration::from_secs(10 * 60),
            Self::Development => Duration::from_secs(24 * 60 * 60),
        }
    }

    /// Idle timeout before session lock.
    /// Control: AC-11 | STIG: UBTU-22-412020 (15 min)
    pub fn idle_timeout(&self) -> Duration {
        match self {
            Self::FedRampLow | Self::FedRampModerate | Self::Soc2 | Self::Custom => {
                Duration::from_secs(15 * 60)
            }
            Self::FedRampHigh => Duration::from_secs(10 * 60),
            Self::Development => Duration::from_secs(24 * 60 * 60),
        }
    }

    /// Max failed login attempts before lockout.
    /// Control: AC-7 | STIG: UBTU-22-411045 (3 attempts)
    pub fn max_login_attempts(&self) -> u32 {
        3
    }

    /// Lockout duration after failed attempts.
    /// Control: AC-7(b) | STIG: UBTU-22-411050
    /// High uses 3 hours per FedRAMP baseline (admin release).
    pub fn lockout_duration(&self) -> Duration {
        match self {
            Self::FedRampLow | Self::FedRampModerate | Self::Soc2 | Self::Custom => {
                Duration::from_secs(30 * 60)
            }
            Self::FedRampHigh => Duration::from_secs(3 * 60 * 60),
            Self::Development => Duration::from_secs(60),
        }
    }

    /// Whether tenant isolation is required.
    /// Control: AC-4
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
    }

    #[test]
    fn test_framework_grouping() {
        assert_eq!(ComplianceProfile::FedRampLow.framework(), "FedRAMP");
        assert_eq!(ComplianceProfile::Soc2.framework(), "SOC 2");
    }

    #[test]
    fn test_retention_au11() {
        assert_eq!(ComplianceProfile::FedRampLow.min_retention_days(), 30);
        assert_eq!(ComplianceProfile::FedRampModerate.min_retention_days(), 90);
        assert_eq!(ComplianceProfile::FedRampHigh.min_retention_days(), 365);
    }

    #[test]
    fn test_session_timeouts_ac12() {
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
    fn test_idle_timeouts_ac11() {
        assert_eq!(
            ComplianceProfile::FedRampLow.idle_timeout(),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampHigh.idle_timeout(),
            Duration::from_secs(10 * 60)
        );
    }

    #[test]
    fn test_mfa_ia2() {
        assert!(!ComplianceProfile::FedRampLow.requires_mfa());
        assert!(ComplianceProfile::FedRampModerate.requires_mfa());
        assert!(ComplianceProfile::FedRampHigh.requires_mfa());
    }

    #[test]
    fn test_encryption_sc8_sc28() {
        assert!(ComplianceProfile::FedRampLow.requires_tls());
        assert!(!ComplianceProfile::Development.requires_tls());
        assert!(!ComplianceProfile::FedRampLow.requires_encryption_at_rest());
        assert!(ComplianceProfile::FedRampModerate.requires_encryption_at_rest());
    }

    #[test]
    fn test_mtls_sc8() {
        assert!(!ComplianceProfile::FedRampModerate.requires_mtls());
        assert!(ComplianceProfile::FedRampHigh.requires_mtls());
    }

    #[test]
    fn test_ssl_verify_full() {
        assert!(!ComplianceProfile::FedRampLow.requires_ssl_verify_full());
        assert!(ComplianceProfile::FedRampModerate.requires_ssl_verify_full());
    }

    #[test]
    fn test_password_ia5() {
        assert_eq!(ComplianceProfile::FedRampLow.min_password_length(), 8);
        assert_eq!(ComplianceProfile::FedRampModerate.min_password_length(), 15);
        assert_eq!(ComplianceProfile::FedRampHigh.min_password_length(), 15);
    }

    #[test]
    fn test_key_rotation_sc12() {
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
    fn test_lockout_ac7() {
        assert_eq!(ComplianceProfile::FedRampLow.max_login_attempts(), 3);
        assert_eq!(ComplianceProfile::FedRampModerate.max_login_attempts(), 3);
        assert_eq!(ComplianceProfile::FedRampHigh.max_login_attempts(), 3);
        assert_eq!(
            ComplianceProfile::FedRampLow.lockout_duration(),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampHigh.lockout_duration(),
            Duration::from_secs(3 * 60 * 60)
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
