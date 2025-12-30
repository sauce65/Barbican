//! Configuration validation against compliance profiles
//!
//! This module validates a barbican.toml configuration against the selected
//! compliance profile, checking that all required controls are satisfied.

use crate::config::BarbicanConfig;
use crate::error::{CliError, Result};
use crate::profile::{ComplianceProfile, ProfileRequirement};

/// Validation result containing all checks performed
#[derive(Debug)]
pub struct ValidationResult {
    /// The compliance profile being validated against
    pub profile: ComplianceProfile,

    /// All requirement checks performed
    pub requirements: Vec<ProfileRequirement>,

    /// Overall validation passed
    pub passed: bool,

    /// Number of errors (required but not satisfied)
    pub error_count: usize,

    /// Number of warnings (recommended but not satisfied)
    pub warning_count: usize,
}

impl ValidationResult {
    /// Get all failed requirements
    pub fn failures(&self) -> Vec<&ProfileRequirement> {
        self.requirements.iter().filter(|r| r.is_failure()).collect()
    }

    /// Get all warnings
    pub fn warnings(&self) -> Vec<&ProfileRequirement> {
        self.requirements.iter().filter(|r| r.is_warning()).collect()
    }

    /// Get all satisfied requirements
    pub fn satisfied(&self) -> Vec<&ProfileRequirement> {
        self.requirements.iter().filter(|r| r.satisfied).collect()
    }
}

/// Validate a configuration against its compliance profile
pub fn validate_config(config: &BarbicanConfig) -> Result<ValidationResult> {
    let profile = config.profile();
    let mut requirements = Vec::new();

    // Validate profile is recognized
    if ComplianceProfile::parse(&config.app.profile).is_none() {
        return Err(CliError::InvalidProfile {
            profile: config.app.profile.clone(),
        });
    }

    // SC-8: TLS Requirements
    requirements.push(validate_tls(config, profile));

    // SC-8: Database SSL
    if config.database.is_some() {
        requirements.push(validate_database_ssl(config, profile));
        requirements.push(validate_database_audit(config, profile));
    }

    // SC-28: Encryption at Rest
    if profile.requires_encryption_at_rest() {
        requirements.push(validate_encryption_at_rest(config, profile));
    }

    // IA-2: MFA Requirements
    requirements.push(validate_mfa(config, profile));

    // IA-5: Password Policy
    requirements.push(validate_password_policy(config, profile));

    // AC-7: Account Lockout
    requirements.push(validate_account_lockout(config, profile));

    // AC-11/AC-12: Session Management
    requirements.push(validate_session_timeouts(config, profile));

    // AU-11: Log Retention
    if config.observability.is_some() {
        requirements.push(validate_log_retention(config, profile));
    }

    // SC-7(5): Egress Filtering (High only)
    if profile.requires_egress_filtering() {
        requirements.push(validate_egress_filtering(config, profile));
    }

    // SC-12: Key Rotation
    if config.secrets.is_some() {
        requirements.push(validate_key_rotation(config, profile));
    }

    // CP-9: Backup Configuration
    if config.database.is_some() {
        requirements.push(validate_backup(config, profile));
    }

    // Network Configuration
    if config.network.is_some() {
        requirements.push(validate_network_config(config, profile));
    }

    // Calculate results
    let error_count = requirements.iter().filter(|r| r.is_failure()).count();
    let warning_count = requirements.iter().filter(|r| r.is_warning()).count();
    let passed = error_count == 0;

    Ok(ValidationResult {
        profile,
        requirements,
        passed,
        error_count,
        warning_count,
    })
}

// =============================================================================
// Individual Validation Functions
// =============================================================================

fn validate_tls(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    // TLS is always required - check if any explicit disable
    let satisfied = true; // Barbican defaults to TLS required

    ProfileRequirement::new(
        "SC-8",
        "Transmission Confidentiality",
        profile.requires_tls(),
        satisfied,
        "TLS encryption required for all communications",
    )
}

fn validate_database_ssl(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let satisfied = config
        .database
        .as_ref()
        .map(|db| db.enable_ssl.unwrap_or(true))
        .unwrap_or(true);

    let requires_client_cert = profile.requires_mtls();
    let has_client_cert = config
        .database
        .as_ref()
        .map(|db| db.enable_client_cert.unwrap_or(false))
        .unwrap_or(false);

    let description = if requires_client_cert {
        format!(
            "Database requires SSL with client certificates (mTLS). Current: SSL={}, ClientCert={}",
            satisfied, has_client_cert
        )
    } else {
        format!("Database requires SSL encryption. Current: SSL={}", satisfied)
    };

    let fully_satisfied = satisfied && (!requires_client_cert || has_client_cert);

    ProfileRequirement::new(
        "SC-8",
        "Database Transport Security",
        true,
        fully_satisfied,
        description,
    )
}

fn validate_database_audit(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let has_audit = config
        .database
        .as_ref()
        .map(|db| db.enable_audit_log.unwrap_or(true))
        .unwrap_or(true);

    let has_pgaudit = config
        .database
        .as_ref()
        .map(|db| db.enable_pgaudit.unwrap_or(true))
        .unwrap_or(true);

    ProfileRequirement::new(
        "AU-2",
        "Database Audit Logging",
        true,
        has_audit && has_pgaudit,
        format!(
            "Database audit logging required. Current: audit_log={}, pgaudit={}",
            has_audit, has_pgaudit
        ),
    )
}

fn validate_encryption_at_rest(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let backup_encrypted = config
        .backup
        .as_ref()
        .map(|b| b.encryption.unwrap_or(false))
        .unwrap_or(false);

    // For now, we check backup encryption as a proxy for encryption at rest
    // Full SC-28 would also check database-level encryption
    ProfileRequirement::new(
        "SC-28",
        "Encryption at Rest",
        profile.requires_encryption_at_rest(),
        backup_encrypted || !config.backup.as_ref().map(|b| b.enabled).unwrap_or(false),
        format!(
            "Data at rest must be encrypted. Backup encryption: {}",
            backup_encrypted
        ),
    )
}

fn validate_mfa(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let mfa_configured = config
        .auth
        .as_ref()
        .map(|a| a.require_mfa.unwrap_or(profile.requires_mfa()))
        .unwrap_or(profile.requires_mfa());

    ProfileRequirement::new(
        "IA-2",
        "Multi-Factor Authentication",
        profile.requires_mfa(),
        mfa_configured,
        format!(
            "MFA required for {} profile. Configured: {}",
            profile.name(),
            mfa_configured
        ),
    )
}

fn validate_password_policy(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let min_length = config
        .auth
        .as_ref()
        .and_then(|a| a.min_password_length)
        .unwrap_or(profile.min_password_length());

    let required_length = profile.min_password_length();
    let satisfied = min_length >= required_length;

    ProfileRequirement::new(
        "IA-5",
        "Password Policy",
        true,
        satisfied,
        format!(
            "Minimum password length: {} (required: {})",
            min_length, required_length
        ),
    )
}

fn validate_account_lockout(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let max_attempts = config
        .auth
        .as_ref()
        .and_then(|a| a.max_login_attempts)
        .unwrap_or(profile.max_login_attempts());

    let required_max = profile.max_login_attempts();
    let satisfied = max_attempts <= required_max;

    ProfileRequirement::new(
        "AC-7",
        "Account Lockout",
        true,
        satisfied,
        format!(
            "Max login attempts: {} (required: <= {})",
            max_attempts, required_max
        ),
    )
}

fn validate_session_timeouts(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    // Parse session timeout if configured
    let session_timeout = config
        .session
        .as_ref()
        .and_then(|s| s.absolute_timeout.as_ref())
        .and_then(|t| parse_duration_minutes(t))
        .unwrap_or(profile.session_timeout_minutes());

    let idle_timeout = config
        .session
        .as_ref()
        .and_then(|s| s.idle_timeout.as_ref())
        .and_then(|t| parse_duration_minutes(t))
        .unwrap_or(profile.idle_timeout_minutes());

    let required_session = profile.session_timeout_minutes();
    let required_idle = profile.idle_timeout_minutes();

    let satisfied = session_timeout <= required_session && idle_timeout <= required_idle;

    ProfileRequirement::new(
        "AC-11/AC-12",
        "Session Management",
        true,
        satisfied,
        format!(
            "Session timeout: {}m (required: <= {}m), Idle: {}m (required: <= {}m)",
            session_timeout, required_session, idle_timeout, required_idle
        ),
    )
}

fn validate_log_retention(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let retention = config
        .observability
        .as_ref()
        .and_then(|o| o.retention_days)
        .unwrap_or(profile.min_retention_days());

    let required = profile.min_retention_days();
    let satisfied = retention >= required;

    ProfileRequirement::new(
        "AU-11",
        "Audit Record Retention",
        true,
        satisfied,
        format!(
            "Log retention: {} days (required: >= {} days)",
            retention, required
        ),
    )
}

fn validate_egress_filtering(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let egress_enabled = config
        .network
        .as_ref()
        .map(|n| n.egress_filtering.unwrap_or(false))
        .unwrap_or(false);

    let has_egress_rules = config
        .network
        .as_ref()
        .map(|n| !n.allowed_egress.is_empty())
        .unwrap_or(false);

    let satisfied = egress_enabled && has_egress_rules;

    ProfileRequirement::new(
        "SC-7(5)",
        "Egress Filtering",
        profile.requires_egress_filtering(),
        satisfied,
        format!(
            "Egress filtering required for {}. Enabled: {}, Rules defined: {}",
            profile.name(),
            egress_enabled,
            has_egress_rules
        ),
    )
}

fn validate_key_rotation(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let rotation_days = config
        .secrets
        .as_ref()
        .and_then(|s| s.rotation_days)
        .unwrap_or(profile.key_rotation_days());

    let required = profile.key_rotation_days();
    let satisfied = rotation_days <= required;

    ProfileRequirement::new(
        "SC-12",
        "Key Rotation",
        true,
        satisfied,
        format!(
            "Key rotation interval: {} days (required: <= {} days)",
            rotation_days, required
        ),
    )
}

fn validate_backup(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let backup_enabled = config
        .backup
        .as_ref()
        .map(|b| b.enabled)
        .unwrap_or(false);

    // Backups are recommended but not strictly required by profile
    // However, for production systems they should be enabled
    ProfileRequirement::new(
        "CP-9",
        "Information System Backup",
        false, // Recommended, not required
        backup_enabled,
        format!("Database backups: {}", if backup_enabled { "enabled" } else { "disabled" }),
    )
}

fn validate_network_config(config: &BarbicanConfig, profile: ComplianceProfile) -> ProfileRequirement {
    let has_ingress_rules = config
        .network
        .as_ref()
        .map(|n| !n.allowed_ingress.is_empty())
        .unwrap_or(false);

    ProfileRequirement::new(
        "SC-7",
        "Boundary Protection",
        true,
        has_ingress_rules,
        format!(
            "Firewall ingress rules defined: {}",
            has_ingress_rules
        ),
    )
}

// =============================================================================
// Helpers
// =============================================================================

/// Parse a duration string like "15m" or "1h" into minutes
fn parse_duration_minutes(s: &str) -> Option<u32> {
    let s = s.trim().to_lowercase();

    if let Some(mins) = s.strip_suffix('m') {
        return mins.trim().parse().ok();
    }

    if let Some(hours) = s.strip_suffix('h') {
        return hours.trim().parse::<u32>().ok().map(|h| h * 60);
    }

    if let Some(secs) = s.strip_suffix('s') {
        return secs.trim().parse::<u32>().ok().map(|s| s / 60);
    }

    // Try parsing as plain number (assume minutes)
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration_minutes("15m"), Some(15));
        assert_eq!(parse_duration_minutes("1h"), Some(60));
        assert_eq!(parse_duration_minutes("30"), Some(30));
        assert_eq!(parse_duration_minutes("900s"), Some(15));
    }

    #[test]
    fn test_validation_fedramp_moderate() {
        let toml = r#"
[app]
name = "test"
profile = "fedramp-moderate"

[database]
type = "postgres"
url = "postgres://localhost/test"
enable_ssl = true
enable_audit_log = true
enable_pgaudit = true

[observability]
retention_days = 90

[auth]
require_mfa = true
min_password_length = 12
max_login_attempts = 3

[session]
idle_timeout = "10m"
absolute_timeout = "15m"
"#;

        let config = crate::config::BarbicanConfig::from_str(toml, std::path::Path::new("test.toml")).unwrap();
        let result = validate_config(&config).unwrap();

        assert!(result.passed, "Validation should pass for compliant config");
        assert_eq!(result.error_count, 0);
    }

    #[test]
    fn test_validation_fedramp_high_missing_mtls() {
        let toml = r#"
[app]
name = "test"
profile = "fedramp-high"

[database]
type = "postgres"
url = "postgres://localhost/test"
enable_ssl = true
enable_client_cert = false  # Should be true for High

[network]
egress_filtering = false  # Should be true for High
"#;

        let config = crate::config::BarbicanConfig::from_str(toml, std::path::Path::new("test.toml")).unwrap();
        let result = validate_config(&config).unwrap();

        assert!(!result.passed, "Validation should fail for non-compliant High config");
        assert!(result.error_count > 0);
    }
}
