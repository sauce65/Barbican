//! Profile Verification Against STIG Content
//!
//! Compares Barbican's hardcoded `ComplianceProfile` values against
//! values derived from official STIG content to identify discrepancies.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::stig::config_gen::{StigConfigGenerator, ProfileVerifier};
//! use barbican::compliance::ComplianceProfile;
//!
//! let mut generator = StigConfigGenerator::new()
//!     .load_profile_file("stig.profile")?;
//!
//! let report = ProfileVerifier::verify(&mut generator, ComplianceProfile::FedRampModerate)?;
//! println!("{}", report);
//! ```

use std::time::Duration;

use crate::compliance::config::ComplianceConfig;
use crate::compliance::ComplianceProfile;

use super::error::Result;
use super::generator::StigConfigGenerator;
use super::registry::BarbicanParam;
use super::variable::VariableValue;

/// Verifies Barbican profiles against STIG-derived values
pub struct ProfileVerifier;

impl ProfileVerifier {
    /// Verify a single profile against STIG-derived values
    ///
    /// Generates config from the STIG generator and compares against
    /// the hardcoded profile values.
    pub fn verify(
        generator: &mut StigConfigGenerator,
        profile: ComplianceProfile,
    ) -> Result<VerificationReport> {
        let stig_config = generator.generate_config()?;
        let profile_config = ComplianceConfig::from_profile(profile);

        let mut comparisons = Vec::new();

        // Compare each parameter
        comparisons.push(Self::compare_duration(
            BarbicanParam::SessionMaxLifetime,
            stig_config.session_max_lifetime,
            profile_config.session_max_lifetime,
        ));

        comparisons.push(Self::compare_duration(
            BarbicanParam::SessionIdleTimeout,
            stig_config.session_idle_timeout,
            profile_config.session_idle_timeout,
        ));

        comparisons.push(Self::compare_duration(
            BarbicanParam::ReauthTimeout,
            stig_config.reauth_timeout,
            profile_config.reauth_timeout,
        ));

        comparisons.push(Self::compare_bool(
            BarbicanParam::RequireMfa,
            stig_config.require_mfa,
            profile_config.require_mfa,
        ));

        comparisons.push(Self::compare_bool(
            BarbicanParam::RequireHardwareMfa,
            stig_config.require_hardware_mfa,
            profile_config.require_hardware_mfa,
        ));

        comparisons.push(Self::compare_usize(
            BarbicanParam::PasswordMinLength,
            stig_config.password_min_length,
            profile_config.password_min_length,
        ));

        comparisons.push(Self::compare_bool(
            BarbicanParam::PasswordCheckBreachDb,
            stig_config.password_check_breach_db,
            profile_config.password_check_breach_db,
        ));

        comparisons.push(Self::compare_u32(
            BarbicanParam::MaxLoginAttempts,
            stig_config.max_login_attempts,
            profile_config.max_login_attempts,
        ));

        comparisons.push(Self::compare_duration(
            BarbicanParam::LockoutDuration,
            stig_config.lockout_duration,
            profile_config.lockout_duration,
        ));

        comparisons.push(Self::compare_duration(
            BarbicanParam::KeyRotationInterval,
            stig_config.key_rotation_interval,
            profile_config.key_rotation_interval,
        ));

        comparisons.push(Self::compare_bool(
            BarbicanParam::RequireTls,
            stig_config.require_tls,
            profile_config.require_tls,
        ));

        comparisons.push(Self::compare_bool(
            BarbicanParam::RequireMtls,
            stig_config.require_mtls,
            profile_config.require_mtls,
        ));

        comparisons.push(Self::compare_bool(
            BarbicanParam::RequireEncryptionAtRest,
            stig_config.require_encryption_at_rest,
            profile_config.require_encryption_at_rest,
        ));

        comparisons.push(Self::compare_bool(
            BarbicanParam::RequireTenantIsolation,
            stig_config.require_tenant_isolation,
            profile_config.require_tenant_isolation,
        ));

        comparisons.push(Self::compare_u32(
            BarbicanParam::MinRetentionDays,
            stig_config.min_retention_days,
            profile_config.min_retention_days,
        ));

        // Attach justifications for STIG-more-restrictive cases
        for comp in &mut comparisons {
            if matches!(comp.status, ComparisonStatus::StigMoreRestrictive) {
                comp.justification = Self::get_justification(comp.param, profile);
            }
        }

        let matches = comparisons.iter().filter(|c| c.matches()).count();
        let mismatches = comparisons.iter().filter(|c| !c.matches()).count();

        Ok(VerificationReport {
            profile,
            stig_profile_name: generator
                .active_profile()
                .map(|p| p.id.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            comparisons,
            total_parameters: 15,
            matches,
            mismatches,
            warnings: generator.warnings().to_vec(),
        })
    }

    /// Verify all standard FedRAMP profiles
    pub fn verify_all(
        generator: &mut StigConfigGenerator,
    ) -> Result<Vec<VerificationReport>> {
        let profiles = [
            ComplianceProfile::FedRampLow,
            ComplianceProfile::FedRampModerate,
            ComplianceProfile::FedRampHigh,
        ];

        let mut reports = Vec::new();
        for profile in profiles {
            reports.push(Self::verify(generator, profile)?);
        }
        Ok(reports)
    }

    fn compare_duration(
        param: BarbicanParam,
        stig_value: Duration,
        profile_value: Duration,
    ) -> ParameterComparison {
        ParameterComparison {
            param,
            stig_value: VariableValue::Duration(stig_value),
            profile_value: VariableValue::Duration(profile_value),
            status: if stig_value == profile_value {
                ComparisonStatus::Match
            } else if stig_value < profile_value {
                ComparisonStatus::StigMoreRestrictive
            } else {
                ComparisonStatus::ProfileMoreRestrictive
            },
            justification: None,
        }
    }

    fn compare_bool(
        param: BarbicanParam,
        stig_value: bool,
        profile_value: bool,
    ) -> ParameterComparison {
        ParameterComparison {
            param,
            stig_value: VariableValue::Boolean(stig_value),
            profile_value: VariableValue::Boolean(profile_value),
            status: if stig_value == profile_value {
                ComparisonStatus::Match
            } else if stig_value && !profile_value {
                ComparisonStatus::StigMoreRestrictive
            } else {
                ComparisonStatus::ProfileMoreRestrictive
            },
            justification: None,
        }
    }

    fn compare_usize(
        param: BarbicanParam,
        stig_value: usize,
        profile_value: usize,
    ) -> ParameterComparison {
        // For password length, higher is more restrictive
        let status = if stig_value == profile_value {
            ComparisonStatus::Match
        } else if stig_value > profile_value {
            ComparisonStatus::StigMoreRestrictive
        } else {
            ComparisonStatus::ProfileMoreRestrictive
        };

        ParameterComparison {
            param,
            stig_value: VariableValue::Integer(stig_value as i64),
            profile_value: VariableValue::Integer(profile_value as i64),
            status,
            justification: None,
        }
    }

    fn compare_u32(
        param: BarbicanParam,
        stig_value: u32,
        profile_value: u32,
    ) -> ParameterComparison {
        // Context-dependent: for max_login_attempts, lower is more restrictive
        // For min_retention_days, higher is more restrictive
        let status = if stig_value == profile_value {
            ComparisonStatus::Match
        } else {
            match param {
                BarbicanParam::MaxLoginAttempts => {
                    if stig_value < profile_value {
                        ComparisonStatus::StigMoreRestrictive
                    } else {
                        ComparisonStatus::ProfileMoreRestrictive
                    }
                }
                BarbicanParam::MinRetentionDays => {
                    if stig_value > profile_value {
                        ComparisonStatus::StigMoreRestrictive
                    } else {
                        ComparisonStatus::ProfileMoreRestrictive
                    }
                }
                _ => ComparisonStatus::Mismatch,
            }
        };

        ParameterComparison {
            param,
            stig_value: VariableValue::Integer(stig_value as i64),
            profile_value: VariableValue::Integer(profile_value as i64),
            status,
            justification: None,
        }
    }

    /// Get deviation justification for a parameter at a given profile level
    ///
    /// Returns justification only for FedRAMP Low deviations where the profile
    /// is intentionally less restrictive than STIG due to FedRAMP baseline requirements.
    fn get_justification(
        param: BarbicanParam,
        profile: ComplianceProfile,
    ) -> Option<DeviationJustification> {
        // Only FedRAMP Low has documented deviations from STIG
        if !matches!(profile, ComplianceProfile::FedRampLow) {
            return None;
        }

        match param {
            BarbicanParam::RequireMfa => Some(DeviationJustification {
                category: DeviationCategory::ControlNotSelected,
                control_id: "IA-2(1)",
                reference: "FedRAMP Rev 5 Security Controls Baseline, Table 4-1",
                rationale: "IA-2(1) MFA for network access to privileged accounts only \
                           at Low baseline. MFA for all users not required.",
            }),
            BarbicanParam::RequireHardwareMfa => Some(DeviationJustification {
                category: DeviationCategory::ControlNotSelected,
                control_id: "IA-2(12)",
                reference: "FedRAMP Rev 5 Security Controls Baseline",
                rationale: "IA-2(12) hardware token MFA not selected at Low baseline.",
            }),
            BarbicanParam::RequireEncryptionAtRest => Some(DeviationJustification {
                category: DeviationCategory::ControlNotSelected,
                control_id: "SC-28",
                reference: "FedRAMP Rev 5 Security Controls Baseline, Table 4-1",
                rationale: "SC-28 Protection of Information at Rest not selected at \
                           Low baseline. Encryption at rest is recommended but not required.",
            }),
            BarbicanParam::RequireTenantIsolation => Some(DeviationJustification {
                category: DeviationCategory::ControlNotSelected,
                control_id: "SC-4",
                reference: "FedRAMP Rev 5 Security Controls Baseline",
                rationale: "SC-4 Information in Shared System Resources less stringent \
                           at Low. Logical isolation acceptable.",
            }),
            BarbicanParam::PasswordMinLength => Some(DeviationJustification {
                category: DeviationCategory::ExplicitBaselineValue,
                control_id: "IA-5(1)",
                reference: "NIST SP 800-63B Section 5.1.1.1",
                rationale: "With MFA (required for privileged at Low), 8-character \
                           minimum is acceptable per SP 800-63B. STIG 15-char requirement \
                           assumes single-factor authentication.",
            }),
            BarbicanParam::MinRetentionDays => Some(DeviationJustification {
                category: DeviationCategory::OrgDefined,
                control_id: "AU-11",
                reference: "FedRAMP Rev 5 Security Controls Baseline",
                rationale: "AU-11 at Low baseline specifies organization-defined \
                           retention period. 30 days meets minimum incident response needs.",
            }),
            BarbicanParam::SessionIdleTimeout => Some(DeviationJustification {
                category: DeviationCategory::ExplicitBaselineValue,
                control_id: "AC-11",
                reference: "FedRAMP Rev 5 Security Controls Baseline",
                rationale: "AC-11 at Low permits up to 15-minute idle timeout \
                           (900 seconds). Profile value of 900s is compliant.",
            }),
            BarbicanParam::SessionMaxLifetime => Some(DeviationJustification {
                category: DeviationCategory::OrgDefined,
                control_id: "AC-12",
                reference: "FedRAMP Rev 5 Security Controls Baseline",
                rationale: "AC-12 at Low baseline permits organization-defined session \
                           termination. 30-minute maximum lifetime is acceptable.",
            }),
            BarbicanParam::ReauthTimeout => Some(DeviationJustification {
                category: DeviationCategory::OrgDefined,
                control_id: "IA-11",
                reference: "FedRAMP Rev 5 Security Controls Baseline",
                rationale: "IA-11 Re-authentication at Low permits organization-defined \
                           circumstances. 1-hour reauth timeout acceptable for Low impact.",
            }),
            BarbicanParam::LockoutDuration => Some(DeviationJustification {
                category: DeviationCategory::ExplicitBaselineValue,
                control_id: "AC-7",
                reference: "FedRAMP Rev 5 Security Controls Baseline",
                rationale: "AC-7 at Low permits 30-minute lockout or administrator release. \
                           Profile value of 30 minutes meets baseline requirement.",
            }),
            _ => None,
        }
    }
}

/// Verification report comparing STIG vs profile values
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// The Barbican profile being verified
    pub profile: ComplianceProfile,

    /// The STIG profile name used for comparison
    pub stig_profile_name: String,

    /// Individual parameter comparisons
    pub comparisons: Vec<ParameterComparison>,

    /// Total number of parameters compared
    pub total_parameters: usize,

    /// Number of matching parameters
    pub matches: usize,

    /// Number of mismatching parameters
    pub mismatches: usize,

    /// Warnings from the generator
    pub warnings: Vec<String>,
}

impl VerificationReport {
    /// Check if all parameters match
    pub fn all_match(&self) -> bool {
        self.mismatches == 0
    }

    /// Get only mismatched comparisons
    pub fn mismatches(&self) -> Vec<&ParameterComparison> {
        self.comparisons.iter().filter(|c| !c.matches()).collect()
    }

    /// Get comparisons where STIG is more restrictive
    pub fn stig_more_restrictive(&self) -> Vec<&ParameterComparison> {
        self.comparisons
            .iter()
            .filter(|c| matches!(c.status, ComparisonStatus::StigMoreRestrictive))
            .collect()
    }

    /// Get comparisons where profile is more restrictive
    pub fn profile_more_restrictive(&self) -> Vec<&ParameterComparison> {
        self.comparisons
            .iter()
            .filter(|c| matches!(c.status, ComparisonStatus::ProfileMoreRestrictive))
            .collect()
    }

    /// Generate a summary suitable for CI/CD output
    pub fn ci_summary(&self) -> String {
        if self.all_match() {
            format!(
                "✓ {} matches STIG profile '{}' ({}/{})",
                self.profile.name(),
                self.stig_profile_name,
                self.matches,
                self.total_parameters
            )
        } else {
            format!(
                "✗ {} has {} discrepancies with STIG profile '{}'",
                self.profile.name(),
                self.mismatches,
                self.stig_profile_name
            )
        }
    }
}

impl std::fmt::Display for VerificationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Profile Verification Report")?;
        writeln!(f, "===========================")?;
        writeln!(f, "Barbican Profile: {}", self.profile.name())?;
        writeln!(f, "STIG Profile: {}", self.stig_profile_name)?;
        writeln!(
            f,
            "Result: {}/{} parameters match",
            self.matches, self.total_parameters
        )?;
        writeln!(f)?;

        // Group by status
        let matches: Vec<_> = self.comparisons.iter().filter(|c| c.matches()).collect();
        let stig_stricter: Vec<_> = self.stig_more_restrictive();
        let profile_stricter: Vec<_> = self.profile_more_restrictive();

        if !matches.is_empty() {
            writeln!(f, "Matching Parameters ({}):", matches.len())?;
            for comp in matches {
                writeln!(f, "  ✓ {} = {}", comp.param, comp.stig_value)?;
            }
            writeln!(f)?;
        }

        if !stig_stricter.is_empty() {
            // Separate justified vs unjustified deviations
            let justified: Vec<_> = stig_stricter
                .iter()
                .filter(|c| c.justification.is_some())
                .collect();
            let unjustified: Vec<_> = stig_stricter
                .iter()
                .filter(|c| c.justification.is_none())
                .collect();

            if !justified.is_empty() {
                writeln!(
                    f,
                    "Accepted Deviations ({}) - Justified per FedRAMP baseline:",
                    justified.len()
                )?;
                for comp in justified {
                    let j = comp.justification.as_ref().unwrap();
                    writeln!(
                        f,
                        "  ✓ {} : Profile={} vs STIG={}",
                        comp.param, comp.profile_value, comp.stig_value
                    )?;
                    writeln!(f, "    Control: {} | Category: {:?}", j.control_id, j.category)?;
                    writeln!(f, "    Reference: {}", j.reference)?;
                    writeln!(f, "    Rationale: {}", j.rationale)?;
                }
                writeln!(f)?;
            }

            if !unjustified.is_empty() {
                writeln!(
                    f,
                    "STIG More Restrictive ({}) - Review needed:",
                    unjustified.len()
                )?;
                for comp in unjustified {
                    writeln!(
                        f,
                        "  ⚠ {} : STIG={} vs Profile={}",
                        comp.param, comp.stig_value, comp.profile_value
                    )?;
                }
                writeln!(f)?;
            }
        }

        if !profile_stricter.is_empty() {
            writeln!(
                f,
                "Profile More Restrictive ({}) - OK, exceeds STIG requirements:",
                profile_stricter.len()
            )?;
            for comp in profile_stricter {
                writeln!(
                    f,
                    "  ✓ {} : Profile={} vs STIG={}",
                    comp.param, comp.profile_value, comp.stig_value
                )?;
            }
            writeln!(f)?;
        }

        if !self.warnings.is_empty() {
            writeln!(f, "Warnings:")?;
            for warning in &self.warnings {
                writeln!(f, "  - {}", warning)?;
            }
        }

        Ok(())
    }
}

/// Comparison of a single parameter
#[derive(Debug, Clone)]
pub struct ParameterComparison {
    /// The parameter being compared
    pub param: BarbicanParam,

    /// Value derived from STIG
    pub stig_value: VariableValue,

    /// Value from Barbican profile
    pub profile_value: VariableValue,

    /// Comparison status
    pub status: ComparisonStatus,

    /// Justification for deviations (populated for STIG-more-restrictive cases)
    pub justification: Option<DeviationJustification>,
}

/// Justification for why a profile value deviates from STIG
///
/// Used to document acceptable deviations for auditor review.
#[derive(Debug, Clone)]
pub struct DeviationJustification {
    /// Category of acceptance
    pub category: DeviationCategory,

    /// NIST 800-53 control ID (e.g., "IA-2(1)", "SC-28")
    pub control_id: &'static str,

    /// Authoritative reference document
    pub reference: &'static str,

    /// Human-readable explanation
    pub rationale: &'static str,
}

/// Category of deviation acceptance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviationCategory {
    /// Control is not selected in the FedRAMP baseline for this impact level
    ControlNotSelected,

    /// Parameter is organization-defined at this impact level
    OrgDefined,

    /// FedRAMP baseline explicitly permits this value
    ExplicitBaselineValue,

    /// Profile exceeds requirements (no justification needed)
    ExceedsRequirement,
}

impl ParameterComparison {
    /// Check if values match
    pub fn matches(&self) -> bool {
        matches!(self.status, ComparisonStatus::Match)
    }
}

/// Status of a parameter comparison
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonStatus {
    /// Values match exactly
    Match,

    /// STIG value is more restrictive than profile
    StigMoreRestrictive,

    /// Profile value is more restrictive than STIG
    ProfileMoreRestrictive,

    /// Values differ but direction is unclear
    Mismatch,
}

impl std::fmt::Display for ComparisonStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Match => write!(f, "match"),
            Self::StigMoreRestrictive => write!(f, "STIG stricter"),
            Self::ProfileMoreRestrictive => write!(f, "profile stricter"),
            Self::Mismatch => write!(f, "mismatch"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::stig::config_gen::StigProfile;

    fn sample_stig_profile() -> &'static str {
        r#"
id: test_stig
title: Test STIG
selections:
  - var_password_pam_minlen=15
  - var_accounts_passwords_pam_faillock_deny=3
  - var_accounts_passwords_pam_faillock_unlock_time=900
  - var_screensaver_lock_delay=600
  - enable_fips_mode
  - configure_crypto_policy
  - encrypt_partitions
"#
    }

    #[test]
    fn test_verify_report_generation() {
        let profile = StigProfile::from_yaml(sample_stig_profile(), "test_stig".into()).unwrap();

        let mut generator = StigConfigGenerator::new().with_profile(profile);

        let report = ProfileVerifier::verify(&mut generator, ComplianceProfile::FedRampModerate)
            .unwrap();

        assert_eq!(report.profile, ComplianceProfile::FedRampModerate);
        assert_eq!(report.total_parameters, 15);
        assert!(report.matches + report.mismatches == 15);

        // Check display doesn't panic
        let _ = format!("{}", report);
    }

    #[test]
    fn test_comparison_status() {
        // For password length, higher STIG value = more restrictive
        let comp = ProfileVerifier::compare_usize(
            BarbicanParam::PasswordMinLength,
            15, // STIG
            12, // Profile
        );
        assert!(matches!(comp.status, ComparisonStatus::StigMoreRestrictive));

        // For max login attempts, lower STIG value = more restrictive
        let comp = ProfileVerifier::compare_u32(
            BarbicanParam::MaxLoginAttempts,
            3, // STIG
            5, // Profile
        );
        assert!(matches!(comp.status, ComparisonStatus::StigMoreRestrictive));
    }

    #[test]
    fn test_ci_summary() {
        let profile = StigProfile::from_yaml(sample_stig_profile(), "test_stig".into()).unwrap();

        let mut generator = StigConfigGenerator::new().with_profile(profile);

        let report = ProfileVerifier::verify(&mut generator, ComplianceProfile::FedRampModerate)
            .unwrap();

        let summary = report.ci_summary();
        assert!(summary.contains("FedRAMP Moderate"));
        assert!(summary.contains("test_stig"));
    }
}
