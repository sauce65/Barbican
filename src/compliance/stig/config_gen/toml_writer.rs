//! TOML Writer for Barbican Configuration
//!
//! Generates `barbican.toml` files from resolved STIG values with
//! proper formatting, documentation comments, and generation metadata.

use std::collections::HashMap;
use std::time::Duration;

use super::error::Result;
use super::profile_parser::StigProfile;
use super::registry::BarbicanParam;
use super::variable::VariableValue;

/// Write resolved values to TOML format
pub fn write_toml(
    resolved: &HashMap<BarbicanParam, VariableValue>,
    profile: Option<&StigProfile>,
    warnings: &[String],
) -> Result<String> {
    let mut output = String::new();

    // Header with generation metadata
    output.push_str("# Barbican Compliance Configuration\n");
    output.push_str("# ==================================\n");
    output.push_str("#\n");
    output.push_str("# Generated from STIG/ComplianceAsCode content\n");

    if let Some(profile) = profile {
        output.push_str(&format!("# Profile: {}\n", profile.id));
        if let Some(ref title) = profile.title {
            output.push_str(&format!("# Title: {}\n", title));
        }
    }

    output.push_str(&format!(
        "# Generated: {}\n",
        chrono_lite_timestamp()
    ));
    output.push_str("#\n\n");

    // Session settings (AC-11, AC-12)
    output.push_str("# ===========================================================================\n");
    output.push_str("# Session Settings (AC-11, AC-12)\n");
    output.push_str("# ===========================================================================\n\n");

    write_duration_param(
        &mut output,
        resolved,
        BarbicanParam::SessionMaxLifetime,
        "Maximum session lifetime from creation (AC-12)",
    );

    write_duration_param(
        &mut output,
        resolved,
        BarbicanParam::SessionIdleTimeout,
        "Idle timeout before session lock/termination (AC-11)",
    );

    write_duration_param(
        &mut output,
        resolved,
        BarbicanParam::ReauthTimeout,
        "Timeout for re-authentication on sensitive operations",
    );

    output.push('\n');

    // Authentication settings (IA-2)
    output.push_str("# ===========================================================================\n");
    output.push_str("# Authentication Settings (IA-2)\n");
    output.push_str("# ===========================================================================\n\n");

    write_bool_param(
        &mut output,
        resolved,
        BarbicanParam::RequireMfa,
        "Whether any form of MFA is required",
    );

    write_bool_param(
        &mut output,
        resolved,
        BarbicanParam::RequireHardwareMfa,
        "Whether hardware MFA tokens are required (FIDO2, etc.)",
    );

    output.push('\n');

    // Password settings (IA-5)
    output.push_str("# ===========================================================================\n");
    output.push_str("# Password Settings (IA-5)\n");
    output.push_str("# ===========================================================================\n\n");

    write_int_param(
        &mut output,
        resolved,
        BarbicanParam::PasswordMinLength,
        "Minimum password length",
    );

    write_bool_param(
        &mut output,
        resolved,
        BarbicanParam::PasswordCheckBreachDb,
        "Whether to check passwords against breach databases",
    );

    output.push('\n');

    // Login security (AC-7)
    output.push_str("# ===========================================================================\n");
    output.push_str("# Login Security (AC-7)\n");
    output.push_str("# ===========================================================================\n\n");

    write_int_param(
        &mut output,
        resolved,
        BarbicanParam::MaxLoginAttempts,
        "Maximum failed login attempts before lockout",
    );

    write_duration_param(
        &mut output,
        resolved,
        BarbicanParam::LockoutDuration,
        "Duration of account lockout",
    );

    output.push('\n');

    // Key management (SC-12)
    output.push_str("# ===========================================================================\n");
    output.push_str("# Key Management (SC-12)\n");
    output.push_str("# ===========================================================================\n\n");

    write_duration_param(
        &mut output,
        resolved,
        BarbicanParam::KeyRotationInterval,
        "Cryptographic key rotation interval",
    );

    output.push('\n');

    // Data protection (SC-8, SC-28)
    output.push_str("# ===========================================================================\n");
    output.push_str("# Data Protection (SC-8, SC-28)\n");
    output.push_str("# ===========================================================================\n\n");

    write_bool_param(
        &mut output,
        resolved,
        BarbicanParam::RequireTls,
        "Whether TLS is required for all communications",
    );

    write_bool_param(
        &mut output,
        resolved,
        BarbicanParam::RequireMtls,
        "Whether mutual TLS is required for service-to-service",
    );

    write_bool_param(
        &mut output,
        resolved,
        BarbicanParam::RequireEncryptionAtRest,
        "Whether encryption at rest is required",
    );

    output.push('\n');

    // Multi-tenancy
    output.push_str("# ===========================================================================\n");
    output.push_str("# Multi-tenancy\n");
    output.push_str("# ===========================================================================\n\n");

    write_bool_param(
        &mut output,
        resolved,
        BarbicanParam::RequireTenantIsolation,
        "Whether tenant data isolation is required",
    );

    output.push('\n');

    // Audit (AU-11)
    output.push_str("# ===========================================================================\n");
    output.push_str("# Audit (AU-11)\n");
    output.push_str("# ===========================================================================\n\n");

    write_int_param(
        &mut output,
        resolved,
        BarbicanParam::MinRetentionDays,
        "Minimum audit log retention in days",
    );

    // Warnings section
    if !warnings.is_empty() {
        output.push('\n');
        output.push_str("# ===========================================================================\n");
        output.push_str("# Generation Warnings\n");
        output.push_str("# ===========================================================================\n");
        for warning in warnings {
            output.push_str(&format!("# WARNING: {}\n", warning));
        }
    }

    Ok(output)
}

/// Write a duration parameter in human-readable format
fn write_duration_param(
    output: &mut String,
    resolved: &HashMap<BarbicanParam, VariableValue>,
    param: BarbicanParam,
    description: &str,
) {
    output.push_str(&format!("# {}\n", description));

    if let Some(value) = resolved.get(&param) {
        if let Some(duration) = value.as_duration() {
            let formatted = format_duration(duration);
            output.push_str(&format!("{} = \"{}\"\n", param.toml_key(), formatted));
        } else {
            output.push_str(&format!("# {} = (no value)\n", param.toml_key()));
        }
    } else {
        output.push_str(&format!("# {} = (not configured)\n", param.toml_key()));
    }
    output.push('\n');
}

/// Write a boolean parameter
fn write_bool_param(
    output: &mut String,
    resolved: &HashMap<BarbicanParam, VariableValue>,
    param: BarbicanParam,
    description: &str,
) {
    output.push_str(&format!("# {}\n", description));

    if let Some(value) = resolved.get(&param) {
        if let Some(b) = value.as_boolean() {
            output.push_str(&format!("{} = {}\n", param.toml_key(), b));
        } else {
            output.push_str(&format!("# {} = (no value)\n", param.toml_key()));
        }
    } else {
        output.push_str(&format!("# {} = (not configured)\n", param.toml_key()));
    }
    output.push('\n');
}

/// Write an integer parameter
fn write_int_param(
    output: &mut String,
    resolved: &HashMap<BarbicanParam, VariableValue>,
    param: BarbicanParam,
    description: &str,
) {
    output.push_str(&format!("# {}\n", description));

    if let Some(value) = resolved.get(&param) {
        if let Some(n) = value.as_integer() {
            output.push_str(&format!("{} = {}\n", param.toml_key(), n));
        } else {
            output.push_str(&format!("# {} = (no value)\n", param.toml_key()));
        }
    } else {
        output.push_str(&format!("# {} = (not configured)\n", param.toml_key()));
    }
    output.push('\n');
}

/// Format a duration in human-readable format
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();

    if secs == 0 {
        return "0s".to_string();
    }

    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();

    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if seconds > 0 {
        parts.push(format!("{}s", seconds));
    }

    parts.join("")
}

/// Simple timestamp without external dependencies
fn chrono_lite_timestamp() -> String {
    use std::time::SystemTime;

    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            // Format as ISO 8601 (approximate)
            let days_since_epoch = secs / 86400;
            let year = 1970 + (days_since_epoch / 365);
            format!("{}-XX-XX (Unix timestamp: {})", year, secs)
        }
        Err(_) => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(3660)), "1h1m");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d");
        assert_eq!(format_duration(Duration::from_secs(90061)), "1d1h1m1s");
    }

    #[test]
    fn test_write_toml() {
        let mut resolved = HashMap::new();
        resolved.insert(
            BarbicanParam::PasswordMinLength,
            VariableValue::Integer(15),
        );
        resolved.insert(
            BarbicanParam::RequireMfa,
            VariableValue::Boolean(true),
        );
        resolved.insert(
            BarbicanParam::SessionIdleTimeout,
            VariableValue::Duration(Duration::from_secs(600)),
        );

        let toml = write_toml(&resolved, None, &[]).unwrap();

        assert!(toml.contains("password_min_length = 15"));
        assert!(toml.contains("require_mfa = true"));
        assert!(toml.contains("session_idle_timeout = \"10m\""));
    }

    #[test]
    fn test_write_toml_with_profile() {
        use super::super::profile_parser::StigProfile;

        let profile = StigProfile {
            id: "test_stig".to_string(),
            title: Some("Test STIG Profile".to_string()),
            description: None,
            variables: HashMap::new(),
            selections: vec![],
            unselections: vec![],
            extends: None,
        };

        let resolved = HashMap::new();
        let toml = write_toml(&resolved, Some(&profile), &[]).unwrap();

        assert!(toml.contains("Profile: test_stig"));
        assert!(toml.contains("Title: Test STIG Profile"));
    }

    #[test]
    fn test_write_toml_with_warnings() {
        let resolved = HashMap::new();
        let warnings = vec!["Missing var_password_pam_minlen".to_string()];

        let toml = write_toml(&resolved, None, &warnings).unwrap();

        assert!(toml.contains("Generation Warnings"));
        assert!(toml.contains("WARNING: Missing var_password_pam_minlen"));
    }
}
