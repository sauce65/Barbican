//! STIG Loader for ComplianceAsCode Content
//!
//! Parses STIG definitions from ComplianceAsCode YAML files and maps them
//! to NIST 800-53 controls for integration with Barbican's compliance framework.
//!
//! # Overview
//!
//! ComplianceAsCode is an open-source project that provides machine-readable
//! security compliance content. This module parses their YAML format and
//! correlates STIG controls to NIST 800-53 controls that Barbican validates.
//!
//! # STIG Traceability
//!
//! Barbican implements controls from the following STIGs:
//!
//! - **Ubuntu 22.04 LTS STIG V2R3** (UBTU-22-*): OS-level security
//! - **PostgreSQL 15 STIG V2R6** (PGS15-00-*): Database security
//! - **Application Security STIG V5R3** (APSC-DV-*): Application security
//!
//! See the [`mappings`] module for complete rule definitions and traceability.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::stig::{StigLoader, StigControl};
//!
//! // Load a STIG control file
//! let loader = StigLoader::from_file("controls/stig_ubuntu2204.yml")?;
//!
//! // Get all controls
//! for control in loader.controls() {
//!     println!("{}: {} -> {:?}", control.id, control.title, control.nist_controls());
//! }
//!
//! // Find controls by NIST mapping
//! let ac7_controls = loader.controls_for_nist("AC-7");
//! ```
//!
//! # Configuration Generation
//!
//! Use the `config_gen` submodule to generate Barbican configuration from
//! STIG content:
//!
//! ```ignore
//! use barbican::compliance::stig::config_gen::StigConfigGenerator;
//!
//! let mut generator = StigConfigGenerator::new()
//!     .load_stig("controls/stig_ubuntu2204.yml")?
//!     .load_variables("content/")?
//!     .load_profiles("content/")?
//!     .select_profile("stig")?;
//!
//! let config = generator.generate_config()?;
//! ```
//!
//! # Data Sources
//!
//! Clone ComplianceAsCode content from:
//! ```bash
//! git clone --depth 1 https://github.com/ComplianceAsCode/content.git
//! ```
//!
//! Key paths:
//! - `controls/*.yml` - Control mapping files (STIG, CIS, NIST)
//! - `linux_os/guide/**/**/rule.yml` - Rule definitions with NIST references
//! - `products/*/profiles/*.profile` - Profile files with variable assignments
//! - `linux_os/guide/**/var_*.var` - Variable definition files

pub mod config_gen;
pub mod mappings;

mod control;
mod loader;
mod rule;
mod types;
mod validator;

pub use control::{ControlFile, StigControl, ControlLevel, ControlStatus as StigControlStatus};
pub use loader::{StigLoader, StigLoaderError, StigStats, NistMappingReport};
pub use rule::{Rule, RuleReferences, Severity};
pub use types::{NistControl, StigMapping, StigSeverity};
pub use validator::{StigValidation, StigComplianceSummary};

#[cfg(test)]
mod tests {
    use super::config_gen::BarbicanParam;
    use super::mappings::{self, StigCoverage};

    /// Verify all BarbicanParam variants have STIG mappings
    #[test]
    fn test_all_params_have_stig_mappings() {
        for param in BarbicanParam::all() {
            let rules = param.stig_rules();
            assert!(
                !rules.is_empty(),
                "BarbicanParam::{:?} has no STIG rule mappings",
                param
            );
        }
    }

    /// Verify STIG rule IDs follow expected naming conventions
    #[test]
    fn test_stig_rule_id_format() {
        for rule in mappings::all_rules() {
            let valid_format = rule.id.starts_with("UBTU-22-")
                || rule.id.starts_with("PGS15-")
                || rule.id.starts_with("APSC-DV-")
                || rule.id.starts_with("CIS-NGINX-")
                || rule.id.starts_with("V-268");  // Anduril NixOS STIG
            assert!(
                valid_format,
                "Invalid STIG rule ID format: {}",
                rule.id
            );
        }
    }

    /// Verify all rules have implementation references
    #[test]
    fn test_all_rules_have_implementations() {
        for rule in mappings::all_rules() {
            assert!(
                !rule.barbican_impl.is_empty(),
                "Rule {} has no Barbican implementation reference",
                rule.id
            );
            assert!(
                !rule.implementation_notes.is_empty(),
                "Rule {} has no implementation notes",
                rule.id
            );
        }
    }

    /// Verify all rules map to at least one NIST control
    #[test]
    fn test_all_rules_have_nist_mappings() {
        for rule in mappings::all_rules() {
            assert!(
                !rule.nist_controls.is_empty(),
                "Rule {} has no NIST control mappings",
                rule.id
            );
        }
    }

    /// Verify critical NIST controls have STIG coverage
    #[test]
    fn test_critical_nist_controls_have_coverage() {
        let critical_controls = [
            "AC-7",  // Login attempts
            "AC-11", // Session lock
            "IA-2",  // Authentication
            "IA-5",  // Authenticator management
            "SC-8",  // Transmission confidentiality
            "AU-2",  // Audit events
            "SI-10", // Input validation
        ];

        for control in critical_controls {
            let rules = mappings::rules_for_nist(control);
            assert!(
                !rules.is_empty(),
                "Critical NIST control {} has no STIG rule mappings",
                control
            );
        }
    }

    /// Verify coverage statistics are non-zero
    #[test]
    fn test_coverage_statistics() {
        let coverage = StigCoverage::calculate();
        assert!(coverage.total > 0, "No STIG rules defined");
        assert!(coverage.ubuntu_22_04_count > 0, "No Ubuntu STIG rules");
        assert!(coverage.postgresql_15_count > 0, "No PostgreSQL STIG rules");
        assert!(coverage.application_security_count > 0, "No AppSec STIG rules");
        assert!(coverage.high_severity > 0, "No high severity rules");
        assert!(coverage.medium_severity > 0, "No medium severity rules");
    }

    /// Verify BarbicanParam STIG rules can be looked up in mappings
    #[test]
    fn test_param_stig_rules_exist_in_mappings() {
        for param in BarbicanParam::all() {
            for rule_id in param.stig_rules() {
                let rule = mappings::get_rule(rule_id);
                assert!(
                    rule.is_some(),
                    "Rule {} referenced by {:?} not found in mappings",
                    rule_id, param
                );
            }
        }
    }

    /// Verify specific known mappings as regression test
    #[test]
    fn test_known_mappings() {
        // AC-7 lockout controls
        let lockout = BarbicanParam::MaxLoginAttempts.stig_rules();
        assert!(lockout.contains(&"UBTU-22-411045"));
        assert!(lockout.contains(&"APSC-DV-000210"));

        // IA-5 password controls
        let password = BarbicanParam::PasswordMinLength.stig_rules();
        assert!(password.contains(&"UBTU-22-611035"));
        assert!(password.contains(&"APSC-DV-000220"));

        // SC-8 TLS controls
        let tls = BarbicanParam::RequireTls.stig_rules();
        assert!(tls.contains(&"UBTU-22-255050"));
        assert!(tls.contains(&"PGS15-00-000100"));
    }
}
