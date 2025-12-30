//! Compliance profile definitions
//!
//! Defines security requirements for each compliance profile (FedRAMP, SOC 2, etc.)
//! These profiles drive default values throughout the configuration.

use std::fmt;

/// Compliance framework and impact level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComplianceProfile {
    /// FedRAMP Low impact - basic security controls
    FedRampLow,

    /// FedRAMP Moderate impact - enhanced security controls (most common)
    #[default]
    FedRampModerate,

    /// FedRAMP High impact - maximum security controls
    FedRampHigh,

    /// SOC 2 Type II baseline
    Soc2,

    /// Custom profile with explicit settings
    Custom,
}

impl ComplianceProfile {
    /// Parse from string (case-insensitive, flexible formats)
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(['-', '_', ' '], "").as_str() {
            "fedramplow" | "low" => Some(Self::FedRampLow),
            "fedrampmoderate" | "moderate" | "fedrampmed" | "med" => Some(Self::FedRampModerate),
            "fedramphigh" | "high" => Some(Self::FedRampHigh),
            "soc2" | "soc2type2" | "soc2typeii" => Some(Self::Soc2),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// Human-readable name for display
    pub fn name(&self) -> &'static str {
        match self {
            Self::FedRampLow => "FedRAMP Low",
            Self::FedRampModerate => "FedRAMP Moderate",
            Self::FedRampHigh => "FedRAMP High",
            Self::Soc2 => "SOC 2 Type II",
            Self::Custom => "Custom",
        }
    }

    /// Configuration file identifier
    pub fn config_name(&self) -> &'static str {
        match self {
            Self::FedRampLow => "fedramp-low",
            Self::FedRampModerate => "fedramp-moderate",
            Self::FedRampHigh => "fedramp-high",
            Self::Soc2 => "soc2",
            Self::Custom => "custom",
        }
    }

    /// Framework family for grouping
    pub fn framework(&self) -> &'static str {
        match self {
            Self::FedRampLow | Self::FedRampModerate | Self::FedRampHigh => "FedRAMP",
            Self::Soc2 => "SOC 2",
            Self::Custom => "Custom",
        }
    }

    // =========================================================================
    // Access Control (AC Family)
    // =========================================================================

    /// Maximum failed login attempts before lockout (AC-7)
    pub fn max_login_attempts(&self) -> u32 {
        match self {
            Self::FedRampLow => 5,
            _ => 3,
        }
    }

    /// Lockout duration in minutes (AC-7)
    pub fn lockout_duration_minutes(&self) -> u32 {
        match self {
            Self::FedRampLow => 15,
            _ => 30,
        }
    }

    /// Session timeout in minutes (AC-12)
    pub fn session_timeout_minutes(&self) -> u32 {
        match self {
            Self::FedRampLow => 30,
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 15,
            Self::FedRampHigh => 10,
        }
    }

    /// Idle timeout in minutes (AC-11)
    pub fn idle_timeout_minutes(&self) -> u32 {
        match self {
            Self::FedRampLow => 15,
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 10,
            Self::FedRampHigh => 5,
        }
    }

    // =========================================================================
    // Audit (AU Family)
    // =========================================================================

    /// Minimum log retention in days (AU-11)
    pub fn min_retention_days(&self) -> u32 {
        match self {
            Self::FedRampLow => 30,
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 90,
            Self::FedRampHigh => 365,
        }
    }

    // =========================================================================
    // Identification and Authentication (IA Family)
    // =========================================================================

    /// Whether MFA is required for all users (IA-2)
    pub fn requires_mfa(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Minimum password length (IA-5)
    pub fn min_password_length(&self) -> usize {
        match self {
            Self::FedRampLow => 8,
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 12,
            Self::FedRampHigh => 14,
        }
    }

    /// Whether breach database checking is required (IA-5)
    pub fn requires_breach_checking(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    // =========================================================================
    // System and Communications Protection (SC Family)
    // =========================================================================

    /// Whether TLS is required (SC-8) - always true
    pub fn requires_tls(&self) -> bool {
        true
    }

    /// Whether mutual TLS is required for service-to-service (SC-8)
    pub fn requires_mtls(&self) -> bool {
        matches!(self, Self::FedRampHigh)
    }

    /// Whether encryption at rest is required (SC-28)
    pub fn requires_encryption_at_rest(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Key rotation interval in days (SC-12)
    pub fn key_rotation_days(&self) -> u32 {
        match self {
            Self::FedRampHigh => 30,
            _ => 90,
        }
    }

    /// Whether egress filtering is required (SC-7(5))
    pub fn requires_egress_filtering(&self) -> bool {
        matches!(self, Self::FedRampHigh)
    }

    /// Whether SSL certificate verification is required (SC-8)
    pub fn requires_ssl_verify_full(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    // =========================================================================
    // Control Counts for Reporting
    // =========================================================================

    /// Approximate number of NIST 800-53 controls applicable at this level
    pub fn applicable_control_count(&self) -> usize {
        match self {
            Self::FedRampLow => 125,
            Self::FedRampModerate => 325,
            Self::FedRampHigh => 421,
            Self::Soc2 => 64, // Trust Services Criteria
            Self::Custom => 0,
        }
    }
}

impl fmt::Display for ComplianceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for ComplianceProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("Unknown compliance profile: {}", s))
    }
}

/// Profile comparison result for validation
#[derive(Debug, Clone)]
pub struct ProfileRequirement {
    /// Control identifier (e.g., "AC-7")
    pub control: &'static str,

    /// Control name
    pub name: &'static str,

    /// Whether this control is required for the profile
    pub required: bool,

    /// Current configuration satisfies the requirement
    pub satisfied: bool,

    /// Description of the requirement
    pub description: String,
}

impl ProfileRequirement {
    pub fn new(
        control: &'static str,
        name: &'static str,
        required: bool,
        satisfied: bool,
        description: impl Into<String>,
    ) -> Self {
        Self {
            control,
            name,
            required,
            satisfied,
            description: description.into(),
        }
    }

    /// Check if this is a failure (required but not satisfied)
    pub fn is_failure(&self) -> bool {
        self.required && !self.satisfied
    }

    /// Check if this is a warning (recommended but not satisfied)
    pub fn is_warning(&self) -> bool {
        !self.required && !self.satisfied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_parsing() {
        assert_eq!(
            ComplianceProfile::parse("fedramp-moderate"),
            Some(ComplianceProfile::FedRampModerate)
        );
        assert_eq!(
            ComplianceProfile::parse("FEDRAMP_HIGH"),
            Some(ComplianceProfile::FedRampHigh)
        );
        assert_eq!(
            ComplianceProfile::parse("soc2"),
            Some(ComplianceProfile::Soc2)
        );
        assert_eq!(ComplianceProfile::parse("invalid"), None);
    }

    #[test]
    fn test_profile_requirements() {
        let low = ComplianceProfile::FedRampLow;
        let moderate = ComplianceProfile::FedRampModerate;
        let high = ComplianceProfile::FedRampHigh;

        // MFA requirements
        assert!(!low.requires_mfa());
        assert!(moderate.requires_mfa());
        assert!(high.requires_mfa());

        // mTLS requirements
        assert!(!low.requires_mtls());
        assert!(!moderate.requires_mtls());
        assert!(high.requires_mtls());

        // Encryption at rest
        assert!(!low.requires_encryption_at_rest());
        assert!(moderate.requires_encryption_at_rest());
        assert!(high.requires_encryption_at_rest());
    }

    #[test]
    fn test_session_timeouts() {
        assert_eq!(ComplianceProfile::FedRampLow.session_timeout_minutes(), 30);
        assert_eq!(ComplianceProfile::FedRampModerate.session_timeout_minutes(), 15);
        assert_eq!(ComplianceProfile::FedRampHigh.session_timeout_minutes(), 10);
    }

    #[test]
    fn test_password_requirements() {
        assert_eq!(ComplianceProfile::FedRampLow.min_password_length(), 8);
        assert_eq!(ComplianceProfile::FedRampModerate.min_password_length(), 12);
        assert_eq!(ComplianceProfile::FedRampHigh.min_password_length(), 14);
    }
}
