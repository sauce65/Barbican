//! NIST Control to Barbican Parameter Mapping Registry
//!
//! Defines mappings from ComplianceAsCode variables and NIST 800-53 controls
//! to Barbican `ComplianceConfig` parameters.

use std::collections::HashMap;
use std::time::Duration;

use super::variable::VariableValue;

/// Barbican configuration parameter identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BarbicanParam {
    /// Maximum session lifetime (AC-12)
    SessionMaxLifetime,

    /// Idle timeout before session lock (AC-11)
    SessionIdleTimeout,

    /// Re-authentication timeout for sensitive operations
    ReauthTimeout,

    /// Whether MFA is required (IA-2)
    RequireMfa,

    /// Whether hardware MFA tokens are required (IA-2(6))
    RequireHardwareMfa,

    /// Minimum password length (IA-5)
    PasswordMinLength,

    /// Whether to check passwords against breach databases (IA-5)
    PasswordCheckBreachDb,

    /// Maximum failed login attempts (AC-7)
    MaxLoginAttempts,

    /// Duration of account lockout (AC-7)
    LockoutDuration,

    /// Key rotation interval (SC-12)
    KeyRotationInterval,

    /// Whether TLS is required (SC-8)
    RequireTls,

    /// Whether mutual TLS is required (SC-8)
    RequireMtls,

    /// Whether encryption at rest is required (SC-28)
    RequireEncryptionAtRest,

    /// Whether tenant isolation is required
    RequireTenantIsolation,

    /// Minimum audit log retention in days (AU-11)
    MinRetentionDays,
}

impl BarbicanParam {
    /// Get all parameter variants
    pub fn all() -> &'static [BarbicanParam] {
        &[
            Self::SessionMaxLifetime,
            Self::SessionIdleTimeout,
            Self::ReauthTimeout,
            Self::RequireMfa,
            Self::RequireHardwareMfa,
            Self::PasswordMinLength,
            Self::PasswordCheckBreachDb,
            Self::MaxLoginAttempts,
            Self::LockoutDuration,
            Self::KeyRotationInterval,
            Self::RequireTls,
            Self::RequireMtls,
            Self::RequireEncryptionAtRest,
            Self::RequireTenantIsolation,
            Self::MinRetentionDays,
        ]
    }

    /// Get the NIST control this parameter maps to
    pub fn nist_control(&self) -> &'static str {
        match self {
            Self::SessionMaxLifetime => "AC-12",
            Self::SessionIdleTimeout => "AC-11",
            Self::ReauthTimeout => "AC-12",
            Self::RequireMfa => "IA-2",
            Self::RequireHardwareMfa => "IA-2(6)",
            Self::PasswordMinLength => "IA-5",
            Self::PasswordCheckBreachDb => "IA-5",
            Self::MaxLoginAttempts => "AC-7",
            Self::LockoutDuration => "AC-7",
            Self::KeyRotationInterval => "SC-12",
            Self::RequireTls => "SC-8",
            Self::RequireMtls => "SC-8",
            Self::RequireEncryptionAtRest => "SC-28",
            Self::RequireTenantIsolation => "AC-4",
            Self::MinRetentionDays => "AU-11",
        }
    }

    /// Get the TOML key name for this parameter
    pub fn toml_key(&self) -> &'static str {
        match self {
            Self::SessionMaxLifetime => "session_max_lifetime",
            Self::SessionIdleTimeout => "session_idle_timeout",
            Self::ReauthTimeout => "reauth_timeout",
            Self::RequireMfa => "require_mfa",
            Self::RequireHardwareMfa => "require_hardware_mfa",
            Self::PasswordMinLength => "password_min_length",
            Self::PasswordCheckBreachDb => "password_check_breach_db",
            Self::MaxLoginAttempts => "max_login_attempts",
            Self::LockoutDuration => "lockout_duration",
            Self::KeyRotationInterval => "key_rotation_interval",
            Self::RequireTls => "require_tls",
            Self::RequireMtls => "require_mtls",
            Self::RequireEncryptionAtRest => "require_encryption_at_rest",
            Self::RequireTenantIsolation => "require_tenant_isolation",
            Self::MinRetentionDays => "min_retention_days",
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::SessionMaxLifetime => "Maximum session lifetime from creation",
            Self::SessionIdleTimeout => "Idle timeout before session lock/termination",
            Self::ReauthTimeout => "Timeout for re-authentication on sensitive operations",
            Self::RequireMfa => "Whether any form of MFA is required",
            Self::RequireHardwareMfa => "Whether hardware MFA tokens are required",
            Self::PasswordMinLength => "Minimum password length",
            Self::PasswordCheckBreachDb => "Whether to check passwords against breach databases",
            Self::MaxLoginAttempts => "Maximum failed login attempts before lockout",
            Self::LockoutDuration => "Duration of account lockout",
            Self::KeyRotationInterval => "Cryptographic key rotation interval",
            Self::RequireTls => "Whether TLS is required for all communications",
            Self::RequireMtls => "Whether mutual TLS is required for service-to-service",
            Self::RequireEncryptionAtRest => "Whether encryption at rest is required",
            Self::RequireTenantIsolation => "Whether tenant data isolation is required",
            Self::MinRetentionDays => "Minimum audit log retention in days",
        }
    }
}

impl std::fmt::Display for BarbicanParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.toml_key())
    }
}

/// Value transformation types
#[derive(Debug, Clone)]
pub enum ValueTransform {
    /// Pass through without modification
    Identity,

    /// Convert seconds to Duration
    SecondsToDuration,

    /// Boolean derived from rule existence
    BoolFromRule(String),

    /// Calculate as multiplier of another parameter
    Multiplier {
        source: BarbicanParam,
        factor: f64,
    },

    /// Custom calculation based on source value
    Custom(fn(&VariableValue) -> Option<VariableValue>),
}

impl ValueTransform {
    /// Apply this transform to a value
    pub fn apply(&self, value: &VariableValue) -> Option<VariableValue> {
        match self {
            Self::Identity => Some(value.clone()),
            Self::SecondsToDuration => value.as_integer().map(|secs| {
                VariableValue::Duration(Duration::from_secs(secs.max(0) as u64))
            }),
            Self::BoolFromRule(_) => {
                // Rule existence check - handled by generator
                Some(value.clone())
            }
            Self::Multiplier { factor, .. } => {
                if let Some(duration) = value.as_duration() {
                    let new_secs = (duration.as_secs_f64() * factor) as u64;
                    Some(VariableValue::Duration(Duration::from_secs(new_secs)))
                } else if let Some(n) = value.as_integer() {
                    Some(VariableValue::Integer((n as f64 * factor) as i64))
                } else {
                    None
                }
            }
            Self::Custom(f) => f(value),
        }
    }
}

/// A mapping from a ComplianceAsCode variable to a Barbican parameter
#[derive(Debug, Clone)]
pub struct ParameterMapping {
    /// ComplianceAsCode variable name (e.g., "var_password_pam_minlen")
    /// None if derived from rule existence
    pub cac_variable: Option<String>,

    /// NIST 800-53 control reference
    pub nist_control: String,

    /// Target Barbican parameter
    pub barbican_param: BarbicanParam,

    /// Value transformation
    pub transform: ValueTransform,

    /// Default value if variable is not found
    pub default: Option<VariableValue>,
}

impl ParameterMapping {
    /// Create a simple identity mapping
    pub fn identity(cac_var: &str, nist: &str, param: BarbicanParam) -> Self {
        Self {
            cac_variable: Some(cac_var.to_string()),
            nist_control: nist.to_string(),
            barbican_param: param,
            transform: ValueTransform::Identity,
            default: None,
        }
    }

    /// Create a seconds-to-duration mapping
    pub fn duration(cac_var: &str, nist: &str, param: BarbicanParam) -> Self {
        Self {
            cac_variable: Some(cac_var.to_string()),
            nist_control: nist.to_string(),
            barbican_param: param,
            transform: ValueTransform::SecondsToDuration,
            default: None,
        }
    }

    /// Create a boolean-from-rule mapping
    pub fn bool_from_rule(rule_id: &str, nist: &str, param: BarbicanParam) -> Self {
        Self {
            cac_variable: None,
            nist_control: nist.to_string(),
            barbican_param: param,
            transform: ValueTransform::BoolFromRule(rule_id.to_string()),
            default: Some(VariableValue::Boolean(false)),
        }
    }

    /// Add a default value
    pub fn with_default(mut self, default: VariableValue) -> Self {
        self.default = Some(default);
        self
    }
}

/// Registry of parameter mappings
#[derive(Debug, Clone)]
pub struct MappingRegistry {
    /// Mappings indexed by Barbican parameter
    by_param: HashMap<BarbicanParam, ParameterMapping>,

    /// Mappings indexed by CAC variable name
    by_variable: HashMap<String, BarbicanParam>,
}

impl MappingRegistry {
    /// Create a registry with default STIG-to-Barbican mappings
    pub fn default_mappings() -> Self {
        let mappings = vec![
            // AC-7: Unsuccessful Logon Attempts
            ParameterMapping::identity(
                "var_accounts_passwords_pam_faillock_deny",
                "AC-7",
                BarbicanParam::MaxLoginAttempts,
            )
            .with_default(VariableValue::Integer(3)),
            ParameterMapping::duration(
                "var_accounts_passwords_pam_faillock_unlock_time",
                "AC-7",
                BarbicanParam::LockoutDuration,
            )
            .with_default(VariableValue::Duration(Duration::from_secs(900))),
            // AC-11: Session Lock
            ParameterMapping::duration(
                "var_screensaver_lock_delay",
                "AC-11",
                BarbicanParam::SessionIdleTimeout,
            )
            .with_default(VariableValue::Duration(Duration::from_secs(900))),
            // AC-12: Session Termination - derived from AC-11
            // This is handled specially in the generator as 1.5x idle timeout
            // IA-2: Identification and Authentication
            ParameterMapping::bool_from_rule(
                "enable_fips_mode",
                "IA-2",
                BarbicanParam::RequireMfa,
            )
            .with_default(VariableValue::Boolean(true)),
            ParameterMapping::bool_from_rule(
                "smartcard_auth",
                "IA-2(6)",
                BarbicanParam::RequireHardwareMfa,
            )
            .with_default(VariableValue::Boolean(false)),
            // IA-5: Authenticator Management
            ParameterMapping::identity(
                "var_password_pam_minlen",
                "IA-5",
                BarbicanParam::PasswordMinLength,
            )
            .with_default(VariableValue::Integer(15)),
            ParameterMapping::bool_from_rule(
                "accounts_passwords_pam_pwquality",
                "IA-5",
                BarbicanParam::PasswordCheckBreachDb,
            )
            .with_default(VariableValue::Boolean(false)),
            // SC-8: Transmission Confidentiality and Integrity
            ParameterMapping::bool_from_rule(
                "configure_crypto_policy",
                "SC-8",
                BarbicanParam::RequireTls,
            )
            .with_default(VariableValue::Boolean(true)),
            ParameterMapping::bool_from_rule(
                "package_nss-tools_installed",
                "SC-8",
                BarbicanParam::RequireMtls,
            )
            .with_default(VariableValue::Boolean(false)),
            // SC-12: Cryptographic Key Establishment and Management
            // Key rotation interval - derived from crypto policy
            ParameterMapping {
                cac_variable: Some("var_system_crypto_policy".to_string()),
                nist_control: "SC-12".to_string(),
                barbican_param: BarbicanParam::KeyRotationInterval,
                transform: ValueTransform::Custom(|value| {
                    // FIPS policy suggests 365 days, others 730 days
                    let days = match value.as_string() {
                        Some("FIPS") | Some("FIPS:OSPP") => 365,
                        _ => 730,
                    };
                    Some(VariableValue::Duration(Duration::from_secs(
                        days * 24 * 60 * 60,
                    )))
                }),
                default: Some(VariableValue::Duration(Duration::from_secs(
                    365 * 24 * 60 * 60,
                ))),
            },
            // SC-28: Protection of Information at Rest
            ParameterMapping::bool_from_rule(
                "encrypt_partitions",
                "SC-28",
                BarbicanParam::RequireEncryptionAtRest,
            )
            .with_default(VariableValue::Boolean(true)),
            // AU-11: Audit Record Retention
            ParameterMapping {
                cac_variable: Some("var_auditd_max_log_file".to_string()),
                nist_control: "AU-11".to_string(),
                barbican_param: BarbicanParam::MinRetentionDays,
                transform: ValueTransform::Custom(|value| {
                    // Convert max log file size to approximate retention days
                    // This is a rough estimate; actual retention depends on log volume
                    // For FedRAMP, we default to 90 days regardless
                    match value.as_integer() {
                        Some(_) => Some(VariableValue::Integer(90)),
                        None => None,
                    }
                }),
                default: Some(VariableValue::Integer(90)),
            },
            // Re-auth timeout (no direct CAC variable, derived from profile)
            ParameterMapping {
                cac_variable: None,
                nist_control: "AC-12".to_string(),
                barbican_param: BarbicanParam::ReauthTimeout,
                transform: ValueTransform::Identity,
                default: Some(VariableValue::Duration(Duration::from_secs(15 * 60))),
            },
            // Tenant isolation (no direct CAC variable)
            ParameterMapping {
                cac_variable: None,
                nist_control: "AC-4".to_string(),
                barbican_param: BarbicanParam::RequireTenantIsolation,
                transform: ValueTransform::Identity,
                default: Some(VariableValue::Boolean(true)),
            },
        ];

        Self::from_mappings(mappings)
    }

    /// Create from a list of mappings
    pub fn from_mappings(mappings: Vec<ParameterMapping>) -> Self {
        let mut by_param = HashMap::new();
        let mut by_variable = HashMap::new();

        for mapping in mappings {
            if let Some(ref var) = mapping.cac_variable {
                by_variable.insert(var.clone(), mapping.barbican_param);
            }
            by_param.insert(mapping.barbican_param, mapping);
        }

        Self {
            by_param,
            by_variable,
        }
    }

    /// Get mapping for a Barbican parameter
    pub fn get_by_param(&self, param: BarbicanParam) -> Option<&ParameterMapping> {
        self.by_param.get(&param)
    }

    /// Get mapping for a CAC variable
    pub fn get_by_variable(&self, variable: &str) -> Option<&ParameterMapping> {
        self.by_variable
            .get(variable)
            .and_then(|param| self.by_param.get(param))
    }

    /// Get the Barbican parameter for a CAC variable
    pub fn param_for_variable(&self, variable: &str) -> Option<BarbicanParam> {
        self.by_variable.get(variable).copied()
    }

    /// Get all mappings
    pub fn iter(&self) -> impl Iterator<Item = &ParameterMapping> {
        self.by_param.values()
    }

    /// Get all CAC variables that have mappings
    pub fn mapped_variables(&self) -> impl Iterator<Item = &str> {
        self.by_variable.keys().map(|s| s.as_str())
    }

    /// Add or replace a mapping
    pub fn add(&mut self, mapping: ParameterMapping) {
        if let Some(ref var) = mapping.cac_variable {
            self.by_variable.insert(var.clone(), mapping.barbican_param);
        }
        self.by_param.insert(mapping.barbican_param, mapping);
    }
}

impl Default for MappingRegistry {
    fn default() -> Self {
        Self::default_mappings()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_registry() {
        let registry = MappingRegistry::default_mappings();

        // Check key mappings exist
        assert!(registry.get_by_param(BarbicanParam::MaxLoginAttempts).is_some());
        assert!(registry.get_by_param(BarbicanParam::PasswordMinLength).is_some());
        assert!(registry.get_by_param(BarbicanParam::LockoutDuration).is_some());
    }

    #[test]
    fn test_identity_transform() {
        let value = VariableValue::Integer(15);
        let result = ValueTransform::Identity.apply(&value);
        assert_eq!(result, Some(VariableValue::Integer(15)));
    }

    #[test]
    fn test_seconds_to_duration_transform() {
        let value = VariableValue::Integer(900);
        let result = ValueTransform::SecondsToDuration.apply(&value);
        assert_eq!(
            result,
            Some(VariableValue::Duration(Duration::from_secs(900)))
        );
    }

    #[test]
    fn test_multiplier_transform() {
        let transform = ValueTransform::Multiplier {
            source: BarbicanParam::SessionIdleTimeout,
            factor: 1.5,
        };

        let value = VariableValue::Duration(Duration::from_secs(600));
        let result = transform.apply(&value);
        assert_eq!(
            result,
            Some(VariableValue::Duration(Duration::from_secs(900)))
        );
    }

    #[test]
    fn test_custom_transform() {
        let transform = ValueTransform::Custom(|v| {
            v.as_integer().map(|n| VariableValue::Integer(n * 2))
        });

        let value = VariableValue::Integer(5);
        let result = transform.apply(&value);
        assert_eq!(result, Some(VariableValue::Integer(10)));
    }

    #[test]
    fn test_variable_to_param_lookup() {
        let registry = MappingRegistry::default_mappings();

        assert_eq!(
            registry.param_for_variable("var_password_pam_minlen"),
            Some(BarbicanParam::PasswordMinLength)
        );
        assert_eq!(
            registry.param_for_variable("var_accounts_passwords_pam_faillock_deny"),
            Some(BarbicanParam::MaxLoginAttempts)
        );
    }

    #[test]
    fn test_barbican_param_metadata() {
        assert_eq!(BarbicanParam::MaxLoginAttempts.nist_control(), "AC-7");
        assert_eq!(BarbicanParam::MaxLoginAttempts.toml_key(), "max_login_attempts");
        assert!(!BarbicanParam::MaxLoginAttempts.description().is_empty());
    }
}
