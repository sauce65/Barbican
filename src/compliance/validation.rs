//! Compliance Validation Framework
//!
//! Validates that application components meet profile requirements.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::{ComplianceConfig, ComplianceValidator};
//!
//! let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
//! let mut validator = ComplianceValidator::new(&config);
//!
//! validator.validate_database(&db_config);
//! validator.validate_session(&session_policy);
//!
//! let report = validator.finish();
//! if !report.is_compliant() {
//!     for control in report.failed_controls() {
//!         eprintln!("Failed: {} - {}", control.control_id, control.message.unwrap_or_default());
//!     }
//! }
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use super::ComplianceConfig;
use crate::tls::TlsMode;

/// Status of a single compliance control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatus {
    /// NIST 800-53 control identifier (e.g., "SC-8", "AC-7")
    pub control_id: String,

    /// Human-readable control name
    pub name: String,

    /// Whether the control is satisfied
    pub satisfied: bool,

    /// Optional message with details (especially for failures)
    pub message: Option<String>,
}

impl ControlStatus {
    /// Create a satisfied control status
    pub fn satisfied(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            control_id: id.into(),
            name: name.into(),
            satisfied: true,
            message: None,
        }
    }

    /// Create a failed control status with a message
    pub fn failed(
        id: impl Into<String>,
        name: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            control_id: id.into(),
            name: name.into(),
            satisfied: false,
            message: Some(message.into()),
        }
    }
}

/// Compliance validation report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Status of individual controls
    pub controls: Vec<ControlStatus>,

    /// Non-blocking warnings
    pub warnings: Vec<String>,
}

impl ComplianceReport {
    /// Create a new empty report
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if all controls are satisfied
    pub fn is_compliant(&self) -> bool {
        self.controls.iter().all(|c| c.satisfied)
    }

    /// Get iterator over failed controls
    pub fn failed_controls(&self) -> impl Iterator<Item = &ControlStatus> {
        self.controls.iter().filter(|c| !c.satisfied)
    }

    /// Get iterator over satisfied controls
    pub fn satisfied_controls(&self) -> impl Iterator<Item = &ControlStatus> {
        self.controls.iter().filter(|c| c.satisfied)
    }

    /// Count of failed controls
    pub fn failure_count(&self) -> usize {
        self.controls.iter().filter(|c| !c.satisfied).count()
    }

    /// Count of satisfied controls
    pub fn success_count(&self) -> usize {
        self.controls.iter().filter(|c| c.satisfied).count()
    }

    /// Add a control status
    pub fn add_control(&mut self, status: ControlStatus) {
        self.controls.push(status);
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// Export report as JSON string
    ///
    /// Returns a pretty-printed JSON representation of the report.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let report = validator.finish();
    /// let json = report.to_json()?;
    /// std::fs::write("compliance_report.json", json)?;
    /// ```
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export report as compact JSON string (for signing)
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Export report as serde_json::Value
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Write report to a file
    ///
    /// # Example
    ///
    /// ```ignore
    /// let report = validator.finish();
    /// report.write_to_file(Path::new("compliance_report.json"))?;
    /// ```
    pub fn write_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = self
            .to_json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }
}

impl fmt::Display for ComplianceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Compliance Report")?;
        writeln!(f, "=================")?;
        writeln!(
            f,
            "Status: {}",
            if self.is_compliant() {
                "COMPLIANT"
            } else {
                "NON-COMPLIANT"
            }
        )?;
        writeln!(
            f,
            "Controls: {}/{} passed",
            self.success_count(),
            self.controls.len()
        )?;

        if !self.controls.is_empty() {
            writeln!(f, "\nControl Status:")?;
            for control in &self.controls {
                let status = if control.satisfied { "✓" } else { "✗" };
                write!(f, "  {} {} - {}", status, control.control_id, control.name)?;
                if let Some(ref msg) = control.message {
                    write!(f, ": {}", msg)?;
                }
                writeln!(f)?;
            }
        }

        if !self.warnings.is_empty() {
            writeln!(f, "\nWarnings:")?;
            for warning in &self.warnings {
                writeln!(f, "  ⚠ {}", warning)?;
            }
        }

        Ok(())
    }
}

/// Compliance validation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceError {
    /// SC-8 violation: Transmission confidentiality/integrity
    Sc8Violation(String),

    /// SC-28 violation: Protection of information at rest
    Sc28Violation(String),

    /// AC-7 violation: Unsuccessful login attempts
    Ac7Violation(String),

    /// AC-11 violation: Session lock (idle timeout)
    Ac11Violation(String),

    /// AC-12 violation: Session termination
    Ac12Violation(String),

    /// IA-2 violation: Identification and authentication
    Ia2Violation(String),

    /// IA-5 violation: Authenticator management (password policy)
    Ia5Violation(String),

    /// SC-12 violation: Cryptographic key management
    Sc12Violation(String),

    /// AU-11 violation: Audit record retention
    Au11Violation(String),

    /// Generic compliance violation
    Generic(String),
}

impl fmt::Display for ComplianceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sc8Violation(msg) => {
                write!(f, "SC-8 (Transmission Confidentiality) violation: {}", msg)
            }
            Self::Sc28Violation(msg) => {
                write!(f, "SC-28 (Protection at Rest) violation: {}", msg)
            }
            Self::Ac7Violation(msg) => {
                write!(f, "AC-7 (Unsuccessful Login Attempts) violation: {}", msg)
            }
            Self::Ac11Violation(msg) => write!(f, "AC-11 (Session Lock) violation: {}", msg),
            Self::Ac12Violation(msg) => {
                write!(f, "AC-12 (Session Termination) violation: {}", msg)
            }
            Self::Ia2Violation(msg) => {
                write!(f, "IA-2 (Identification and Authentication) violation: {}", msg)
            }
            Self::Ia5Violation(msg) => {
                write!(f, "IA-5 (Authenticator Management) violation: {}", msg)
            }
            Self::Sc12Violation(msg) => {
                write!(f, "SC-12 (Cryptographic Key Management) violation: {}", msg)
            }
            Self::Au11Violation(msg) => {
                write!(f, "AU-11 (Audit Record Retention) violation: {}", msg)
            }
            Self::Generic(msg) => write!(f, "Compliance violation: {}", msg),
        }
    }
}

impl std::error::Error for ComplianceError {}

/// Validates application components against compliance requirements
///
/// Use this to verify that your configuration meets the selected
/// compliance profile's requirements at startup or during testing.
///
/// # Example
///
/// ```ignore
/// let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
/// let mut validator = ComplianceValidator::new(&config);
///
/// // Validate various components
/// validator.validate_database(&db_config);
/// validator.validate_session(&session_policy);
/// validator.validate_password(&password_policy);
///
/// let report = validator.finish();
/// assert!(report.is_compliant(), "Configuration does not meet FedRAMP High requirements");
/// ```
pub struct ComplianceValidator<'a> {
    config: &'a ComplianceConfig,
    report: ComplianceReport,
}

impl<'a> ComplianceValidator<'a> {
    /// Create a new validator for the given compliance configuration
    pub fn new(config: &'a ComplianceConfig) -> Self {
        Self {
            config,
            report: ComplianceReport::new(),
        }
    }

    /// Validate that TLS is configured if required
    pub fn validate_tls(&mut self, tls_enabled: bool) {
        if self.config.require_tls && !tls_enabled {
            self.report.add_control(ControlStatus::failed(
                "SC-8",
                "Transmission Confidentiality",
                "TLS is required but not enabled",
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "SC-8",
                "Transmission Confidentiality",
            ));
        }
    }

    /// Validate that mTLS is configured if required
    pub fn validate_mtls(&mut self, mtls_enabled: bool) {
        if self.config.require_mtls && !mtls_enabled {
            self.report.add_control(ControlStatus::failed(
                "SC-8(1)",
                "Cryptographic Protection",
                "Mutual TLS is required for this profile but not enabled",
            ));
        } else if self.config.require_mtls {
            self.report.add_control(ControlStatus::satisfied(
                "SC-8(1)",
                "Cryptographic Protection",
            ));
        }
    }

    /// Validate HTTP TLS enforcement mode (SC-8)
    ///
    /// Checks that the TLS mode meets the profile's requirements:
    /// - All profiles require TLS enforcement (Required or Strict mode)
    /// - Disabled and Opportunistic modes fail compliance
    ///
    /// # Example
    ///
    /// ```ignore
    /// use barbican::tls::TlsMode;
    ///
    /// let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
    /// let mut validator = ComplianceValidator::new(&config);
    ///
    /// validator.validate_http_tls(TlsMode::Required);
    /// let report = validator.finish();
    /// assert!(report.is_compliant());
    /// ```
    pub fn validate_http_tls(&mut self, mode: TlsMode) {
        if self.config.require_tls && !mode.is_compliant() {
            self.report.add_control(ControlStatus::failed(
                "SC-8",
                "HTTP TLS Enforcement",
                format!(
                    "TLS mode '{}' is not compliant - Required or Strict mode needed",
                    mode
                ),
            ));
        } else if self.config.require_tls {
            self.report.add_control(ControlStatus::satisfied(
                "SC-8",
                "HTTP TLS Enforcement",
            ));
        }

        // Additional warning for Strict mode benefits
        if mode == TlsMode::Required {
            self.report.add_warning(
                "SC-8(1): Consider using TlsMode::Strict for TLS version validation",
            );
        }
    }

    /// Validate encryption at rest configuration
    pub fn validate_encryption_at_rest(&mut self, encryption_enabled: bool) {
        if self.config.require_encryption_at_rest && !encryption_enabled {
            self.report.add_control(ControlStatus::failed(
                "SC-28",
                "Protection at Rest",
                "Encryption at rest is required but not verified",
            ));
        } else if self.config.require_encryption_at_rest {
            self.report.add_control(ControlStatus::satisfied(
                "SC-28",
                "Protection at Rest",
            ));
        }

        // Always add a warning about verifying infrastructure encryption
        if self.config.require_encryption_at_rest {
            self.report.add_warning(
                "SC-28: Verify that PostgreSQL TDE or disk-level encryption is enabled",
            );
        }
    }

    /// Validate MFA configuration
    pub fn validate_mfa(&mut self, mfa_enabled: bool, hardware_mfa: bool) {
        if self.config.require_mfa && !mfa_enabled {
            self.report.add_control(ControlStatus::failed(
                "IA-2(1)",
                "Multi-Factor Authentication",
                "MFA is required but not enabled",
            ));
        } else if self.config.require_mfa {
            self.report.add_control(ControlStatus::satisfied(
                "IA-2(1)",
                "Multi-Factor Authentication",
            ));
        }

        if self.config.require_hardware_mfa && !hardware_mfa {
            self.report.add_control(ControlStatus::failed(
                "IA-2(12)",
                "Hardware Token Authentication",
                "Hardware MFA tokens are required for this profile",
            ));
        } else if self.config.require_hardware_mfa {
            self.report.add_control(ControlStatus::satisfied(
                "IA-2(12)",
                "Hardware Token Authentication",
            ));
        }
    }

    /// Validate session timeout configuration
    pub fn validate_session_timeout(
        &mut self,
        max_lifetime: std::time::Duration,
        idle_timeout: std::time::Duration,
    ) {
        // AC-12: Session termination (max lifetime)
        if max_lifetime > self.config.session_max_lifetime {
            self.report.add_control(ControlStatus::failed(
                "AC-12",
                "Session Termination",
                format!(
                    "Session lifetime {}m exceeds maximum {}m for this profile",
                    max_lifetime.as_secs() / 60,
                    self.config.session_max_lifetime.as_secs() / 60
                ),
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "AC-12",
                "Session Termination",
            ));
        }

        // AC-11: Session lock (idle timeout)
        if idle_timeout > self.config.session_idle_timeout {
            self.report.add_control(ControlStatus::failed(
                "AC-11",
                "Session Lock",
                format!(
                    "Idle timeout {}m exceeds maximum {}m for this profile",
                    idle_timeout.as_secs() / 60,
                    self.config.session_idle_timeout.as_secs() / 60
                ),
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "AC-11",
                "Session Lock",
            ));
        }
    }

    /// Validate password policy
    pub fn validate_password_policy(
        &mut self,
        min_length: usize,
        check_breach_db: bool,
    ) {
        if min_length < self.config.password_min_length {
            self.report.add_control(ControlStatus::failed(
                "IA-5(1)",
                "Password-Based Authentication",
                format!(
                    "Password minimum length {} is below required {} for this profile",
                    min_length, self.config.password_min_length
                ),
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "IA-5(1)",
                "Password-Based Authentication",
            ));
        }

        if self.config.password_check_breach_db && !check_breach_db {
            self.report.add_warning(
                "IA-5: Breach database checking is recommended for this profile",
            );
        }
    }

    /// Validate login lockout policy
    pub fn validate_lockout_policy(
        &mut self,
        max_attempts: u32,
        lockout_duration: std::time::Duration,
    ) {
        if max_attempts > self.config.max_login_attempts {
            self.report.add_control(ControlStatus::failed(
                "AC-7",
                "Unsuccessful Login Attempts",
                format!(
                    "Max attempts {} exceeds allowed {} for this profile",
                    max_attempts, self.config.max_login_attempts
                ),
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "AC-7",
                "Unsuccessful Login Attempts",
            ));
        }

        if lockout_duration < self.config.lockout_duration {
            self.report.add_warning(format!(
                "AC-7: Lockout duration {}m is shorter than recommended {}m",
                lockout_duration.as_secs() / 60,
                self.config.lockout_duration.as_secs() / 60
            ));
        }
    }

    /// Validate key rotation policy
    pub fn validate_key_rotation(&mut self, rotation_interval: std::time::Duration) {
        if rotation_interval > self.config.key_rotation_interval {
            self.report.add_control(ControlStatus::failed(
                "SC-12",
                "Cryptographic Key Management",
                format!(
                    "Key rotation interval {}d exceeds maximum {}d for this profile",
                    rotation_interval.as_secs() / (24 * 60 * 60),
                    self.config.key_rotation_interval.as_secs() / (24 * 60 * 60)
                ),
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "SC-12",
                "Cryptographic Key Management",
            ));
        }
    }

    /// Validate audit retention configuration
    pub fn validate_retention(&mut self, retention_days: u32) {
        if retention_days < self.config.min_retention_days {
            self.report.add_control(ControlStatus::failed(
                "AU-11",
                "Audit Record Retention",
                format!(
                    "Retention {}d is below minimum {}d for this profile",
                    retention_days, self.config.min_retention_days
                ),
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "AU-11",
                "Audit Record Retention",
            ));
        }
    }

    /// Validate security layer configuration (SC-5, CM-6, AC-4, AU-2)
    ///
    /// Validates that the HTTP security layers meet compliance requirements:
    /// - SC-5: Rate limiting enabled for DoS protection
    /// - CM-6: Security headers enabled for secure configuration
    /// - AC-4: CORS not in permissive mode for production
    /// - AU-2: Tracing enabled for audit logging
    pub fn validate_security_layers(&mut self, config: &crate::config::SecurityConfig) {
        // SC-5: Rate limiting must be enabled for DoS protection
        if !config.rate_limit_enabled {
            self.report.add_control(ControlStatus::failed(
                "SC-5",
                "Denial of Service Protection",
                "Rate limiting is disabled - required for DoS protection",
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "SC-5",
                "Denial of Service Protection",
            ));
        }

        // CM-6: Security headers must be enabled
        if !config.security_headers_enabled {
            self.report.add_control(ControlStatus::failed(
                "CM-6",
                "Configuration Settings",
                "Security headers are disabled - required for secure defaults",
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "CM-6",
                "Configuration Settings",
            ));
        }

        // AC-4: CORS must not be permissive in production
        if config.cors_is_permissive() {
            self.report.add_control(ControlStatus::failed(
                "AC-4",
                "Information Flow Enforcement",
                "CORS allows any origin (*) - not suitable for production",
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "AC-4",
                "Information Flow Enforcement",
            ));
        }

        // AU-2: Tracing must be enabled for audit logging
        if !config.tracing_enabled {
            self.report.add_control(ControlStatus::failed(
                "AU-2",
                "Audit Events",
                "Request tracing is disabled - required for audit logging",
            ));
        } else {
            self.report.add_control(ControlStatus::satisfied(
                "AU-2",
                "Audit Events",
            ));
        }

        // Additional warnings for configuration review
        if config.request_timeout.as_secs() > 120 {
            self.report.add_warning(format!(
                "SC-5: Request timeout {}s is longer than recommended 120s",
                config.request_timeout.as_secs()
            ));
        }

        if config.max_request_size > 10 * 1024 * 1024 {
            self.report.add_warning(format!(
                "SC-5: Max request size {}MB exceeds recommended 10MB limit",
                config.max_request_size / (1024 * 1024)
            ));
        }
    }

    /// Finish validation and return the report
    pub fn finish(self) -> ComplianceReport {
        self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::ComplianceProfile;
    use std::time::Duration;

    #[test]
    fn test_control_status_satisfied() {
        let status = ControlStatus::satisfied("SC-8", "Transmission Confidentiality");
        assert!(status.satisfied);
        assert!(status.message.is_none());
    }

    #[test]
    fn test_control_status_failed() {
        let status = ControlStatus::failed("SC-8", "Transmission Confidentiality", "TLS not enabled");
        assert!(!status.satisfied);
        assert_eq!(status.message, Some("TLS not enabled".to_string()));
    }

    #[test]
    fn test_report_is_compliant() {
        let mut report = ComplianceReport::new();
        report.add_control(ControlStatus::satisfied("SC-8", "TLS"));
        report.add_control(ControlStatus::satisfied("IA-2", "MFA"));
        assert!(report.is_compliant());

        report.add_control(ControlStatus::failed("SC-28", "Encryption", "Not enabled"));
        assert!(!report.is_compliant());
    }

    #[test]
    fn test_report_counts() {
        let mut report = ComplianceReport::new();
        report.add_control(ControlStatus::satisfied("SC-8", "TLS"));
        report.add_control(ControlStatus::failed("SC-28", "Encryption", "Not enabled"));
        report.add_control(ControlStatus::satisfied("IA-2", "MFA"));

        assert_eq!(report.success_count(), 2);
        assert_eq!(report.failure_count(), 1);
    }

    #[test]
    fn test_validator_tls() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        validator.validate_tls(true);
        let report = validator.finish();
        assert!(report.is_compliant());
    }

    #[test]
    fn test_validator_tls_failure() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        validator.validate_tls(false);
        let report = validator.finish();
        assert!(!report.is_compliant());
    }

    #[test]
    fn test_validator_session_timeout() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
        let mut validator = ComplianceValidator::new(&config);

        // FedRAMP High requires 10min session, 5min idle
        validator.validate_session_timeout(
            Duration::from_secs(10 * 60), // OK
            Duration::from_secs(5 * 60),  // OK
        );
        let report = validator.finish();
        assert!(report.is_compliant());
    }

    #[test]
    fn test_validator_session_timeout_failure() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
        let mut validator = ComplianceValidator::new(&config);

        // Exceeds FedRAMP High limits
        validator.validate_session_timeout(
            Duration::from_secs(30 * 60), // Too long
            Duration::from_secs(15 * 60), // Too long
        );
        let report = validator.finish();
        assert!(!report.is_compliant());
        assert_eq!(report.failure_count(), 2);
    }

    #[test]
    fn test_validator_password_policy() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        // FedRAMP Moderate requires 15 character minimum per STIG UBTU-22-611035
        validator.validate_password_policy(15, true);
        let report = validator.finish();
        assert!(report.is_compliant());
    }

    #[test]
    fn test_validator_password_policy_failure() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        validator.validate_password_policy(8, false); // Below 12 char minimum
        let report = validator.finish();
        assert!(!report.is_compliant());
    }

    #[test]
    fn test_compliance_error_display() {
        let err = ComplianceError::Sc8Violation("TLS not enabled".to_string());
        assert!(err.to_string().contains("SC-8"));
        assert!(err.to_string().contains("TLS not enabled"));
    }

    #[test]
    fn test_validator_security_layers_compliant() {
        let compliance_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&compliance_config);

        // Default SecurityConfig should be compliant
        let security_config = crate::config::SecurityConfig::default();
        validator.validate_security_layers(&security_config);

        let report = validator.finish();
        assert!(report.is_compliant());
        assert_eq!(report.success_count(), 4); // SC-5, CM-6, AC-4, AU-2
    }

    #[test]
    fn test_validator_security_layers_rate_limit_disabled() {
        let compliance_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&compliance_config);

        let security_config = crate::config::SecurityConfig::builder()
            .disable_rate_limiting()
            .build();
        validator.validate_security_layers(&security_config);

        let report = validator.finish();
        assert!(!report.is_compliant());
        assert!(report.failed_controls().any(|c| c.control_id == "SC-5"));
    }

    #[test]
    fn test_validator_security_layers_headers_disabled() {
        let compliance_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&compliance_config);

        let security_config = crate::config::SecurityConfig::builder()
            .disable_security_headers()
            .build();
        validator.validate_security_layers(&security_config);

        let report = validator.finish();
        assert!(!report.is_compliant());
        assert!(report.failed_controls().any(|c| c.control_id == "CM-6"));
    }

    #[test]
    fn test_validator_security_layers_cors_permissive() {
        let compliance_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&compliance_config);

        let security_config = crate::config::SecurityConfig::builder()
            .cors_permissive()
            .build();
        validator.validate_security_layers(&security_config);

        let report = validator.finish();
        assert!(!report.is_compliant());
        assert!(report.failed_controls().any(|c| c.control_id == "AC-4"));
    }

    #[test]
    fn test_validator_security_layers_tracing_disabled() {
        let compliance_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&compliance_config);

        let security_config = crate::config::SecurityConfig::builder()
            .disable_tracing()
            .build();
        validator.validate_security_layers(&security_config);

        let report = validator.finish();
        assert!(!report.is_compliant());
        assert!(report.failed_controls().any(|c| c.control_id == "AU-2"));
    }

    // Serialization tests for Phase 1 compliance artifacts

    #[test]
    fn test_control_status_serialization_roundtrip() {
        let satisfied = ControlStatus::satisfied("SC-8", "Transmission Confidentiality");
        let json = serde_json::to_string(&satisfied).expect("serialize satisfied");
        let deserialized: ControlStatus = serde_json::from_str(&json).expect("deserialize satisfied");
        assert_eq!(satisfied.control_id, deserialized.control_id);
        assert_eq!(satisfied.satisfied, deserialized.satisfied);
        assert_eq!(satisfied.message, deserialized.message);

        let failed = ControlStatus::failed("IA-5", "Authenticator Management", "Weak password policy");
        let json = serde_json::to_string(&failed).expect("serialize failed");
        let deserialized: ControlStatus = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(failed.control_id, deserialized.control_id);
        assert_eq!(failed.satisfied, deserialized.satisfied);
        assert_eq!(failed.message, deserialized.message);
    }

    #[test]
    fn test_compliance_report_serialization_roundtrip() {
        let mut report = ComplianceReport::new();
        report.add_control(ControlStatus::satisfied("SC-8", "TLS"));
        report.add_control(ControlStatus::failed("SC-28", "Encryption", "Not enabled"));
        report.add_warning("Review session timeout".to_string());

        let json = serde_json::to_string(&report).expect("serialize report");
        let deserialized: ComplianceReport = serde_json::from_str(&json).expect("deserialize report");

        assert_eq!(report.controls.len(), deserialized.controls.len());
        assert_eq!(report.warnings.len(), deserialized.warnings.len());
        assert_eq!(report.is_compliant(), deserialized.is_compliant());
    }

    #[test]
    fn test_compliance_error_serialization_roundtrip() {
        let errors = vec![
            ComplianceError::Sc8Violation("TLS disabled".to_string()),
            ComplianceError::Ac11Violation("Session too long".to_string()),
            ComplianceError::Ia5Violation("Weak password".to_string()),
            ComplianceError::Sc28Violation("Encryption at rest".to_string()),
            ComplianceError::Ac7Violation("Too many failed logins".to_string()),
        ];

        for error in errors {
            let json = serde_json::to_string(&error).expect("serialize error");
            let deserialized: ComplianceError = serde_json::from_str(&json).expect("deserialize error");
            assert_eq!(format!("{:?}", error), format!("{:?}", deserialized));
        }
    }

    #[test]
    fn test_compliance_report_to_json() {
        let mut report = ComplianceReport::new();
        report.add_control(ControlStatus::satisfied("SC-8", "TLS"));

        let json = report.to_json().expect("to_json");
        assert!(json.contains("SC-8"));
        assert!(json.contains("TLS"));
        assert!(json.contains('\n')); // Pretty-printed
    }

    #[test]
    fn test_compliance_report_to_json_compact() {
        let mut report = ComplianceReport::new();
        report.add_control(ControlStatus::satisfied("SC-8", "TLS"));

        let json = report.to_json_compact().expect("to_json_compact");
        assert!(json.contains("SC-8"));
        assert!(!json.contains("\n  ")); // Not pretty-printed
    }

    #[test]
    fn test_compliance_report_to_json_value() {
        let mut report = ComplianceReport::new();
        report.add_control(ControlStatus::satisfied("SC-8", "TLS"));
        report.add_control(ControlStatus::failed("IA-5", "Password", "Too short"));

        let value = report.to_json_value();
        assert!(value.is_object());
        let controls = value.get("controls").expect("controls field");
        assert!(controls.is_array());
        assert_eq!(controls.as_array().unwrap().len(), 2);
    }

    // TLS Mode validation tests

    #[test]
    fn test_validator_http_tls_required_mode() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        validator.validate_http_tls(TlsMode::Required);
        let report = validator.finish();
        assert!(report.is_compliant());
    }

    #[test]
    fn test_validator_http_tls_strict_mode() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        validator.validate_http_tls(TlsMode::Strict);
        let report = validator.finish();
        assert!(report.is_compliant());
    }

    #[test]
    fn test_validator_http_tls_disabled_fails() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        validator.validate_http_tls(TlsMode::Disabled);
        let report = validator.finish();
        assert!(!report.is_compliant());
        assert!(report.failed_controls().any(|c| c.control_id == "SC-8"));
    }

    #[test]
    fn test_validator_http_tls_opportunistic_fails() {
        let config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        let mut validator = ComplianceValidator::new(&config);

        validator.validate_http_tls(TlsMode::Opportunistic);
        let report = validator.finish();
        assert!(!report.is_compliant());
        assert!(report.failed_controls().any(|c| c.control_id == "SC-8"));
    }
}
