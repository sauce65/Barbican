//! STIG Integration with ComplianceValidator
//!
//! Extends Barbican's ComplianceValidator to validate against STIG controls.

use std::collections::HashSet;

use super::loader::StigLoader;
use super::types::StigSeverity;
use crate::compliance::{ComplianceReport, ControlStatus};

/// Extension trait for STIG validation
pub trait StigValidation {
    /// Add STIG control validation results to the report
    fn validate_stig_controls(
        &mut self,
        loader: &StigLoader,
        satisfied_nist_controls: &HashSet<String>,
    );

    /// Validate specific STIG control
    fn validate_stig_control(&mut self, stig_id: &str, title: &str, satisfied: bool);
}

impl StigValidation for ComplianceReport {
    fn validate_stig_controls(
        &mut self,
        loader: &StigLoader,
        satisfied_nist_controls: &HashSet<String>,
    ) {
        for mapping in loader.mappings() {
            // A STIG control is satisfied if all its NIST controls are satisfied
            let nist_ids = mapping.nist_base_ids();

            let satisfied = if nist_ids.is_empty() {
                // No NIST mapping - can't determine automatically
                false
            } else {
                nist_ids
                    .iter()
                    .all(|nist_id| satisfied_nist_controls.contains(nist_id))
            };

            let control_id = format!("STIG:{}", mapping.stig_id);
            let severity_tag = match mapping.severity {
                StigSeverity::High => "[CAT I]",
                StigSeverity::Medium => "[CAT II]",
                StigSeverity::Low => "[CAT III]",
                StigSeverity::Unknown => "",
            };
            let name = format!("{} {}", severity_tag, mapping.title);

            if satisfied {
                self.add_control(ControlStatus::satisfied(control_id, name));
            } else if nist_ids.is_empty() {
                // No NIST mapping - add as warning instead of failure
                self.add_warning(format!(
                    "STIG {} has no NIST mapping - manual verification required: {}",
                    mapping.stig_id, mapping.title
                ));
            } else {
                let missing: Vec<&str> = nist_ids
                    .iter()
                    .filter(|id| !satisfied_nist_controls.contains(*id))
                    .map(|s| s.as_str())
                    .collect();
                self.add_control(ControlStatus::failed(
                    control_id,
                    name,
                    format!("Missing NIST controls: {}", missing.join(", ")),
                ));
            }
        }
    }

    fn validate_stig_control(&mut self, stig_id: &str, title: &str, satisfied: bool) {
        let control_id = format!("STIG:{}", stig_id);
        if satisfied {
            self.add_control(ControlStatus::satisfied(control_id, title));
        } else {
            self.add_control(ControlStatus::failed(
                control_id,
                title,
                "STIG control not satisfied",
            ));
        }
    }
}

/// STIG compliance summary
#[derive(Debug, Clone)]
pub struct StigComplianceSummary {
    /// Total STIG controls evaluated
    pub total_controls: usize,
    /// Controls that passed
    pub passed_controls: usize,
    /// Controls that failed
    pub failed_controls: usize,
    /// CAT I (High) passed
    pub cat_i_passed: usize,
    /// CAT I (High) failed
    pub cat_i_failed: usize,
    /// CAT II (Medium) passed
    pub cat_ii_passed: usize,
    /// CAT II (Medium) failed
    pub cat_ii_failed: usize,
    /// CAT III (Low) passed
    pub cat_iii_passed: usize,
    /// CAT III (Low) failed
    pub cat_iii_failed: usize,
}

impl StigComplianceSummary {
    /// Create a summary from a loader and satisfied NIST controls
    pub fn from_validation(loader: &StigLoader, satisfied_nist: &HashSet<String>) -> Self {
        let mut summary = Self {
            total_controls: 0,
            passed_controls: 0,
            failed_controls: 0,
            cat_i_passed: 0,
            cat_i_failed: 0,
            cat_ii_passed: 0,
            cat_ii_failed: 0,
            cat_iii_passed: 0,
            cat_iii_failed: 0,
        };

        for mapping in loader.mappings() {
            summary.total_controls += 1;

            let nist_ids = mapping.nist_base_ids();
            let satisfied = !nist_ids.is_empty()
                && nist_ids.iter().all(|id| satisfied_nist.contains(id));

            if satisfied {
                summary.passed_controls += 1;
                match mapping.severity {
                    StigSeverity::High => summary.cat_i_passed += 1,
                    StigSeverity::Medium => summary.cat_ii_passed += 1,
                    StigSeverity::Low => summary.cat_iii_passed += 1,
                    StigSeverity::Unknown => {}
                }
            } else {
                summary.failed_controls += 1;
                match mapping.severity {
                    StigSeverity::High => summary.cat_i_failed += 1,
                    StigSeverity::Medium => summary.cat_ii_failed += 1,
                    StigSeverity::Low => summary.cat_iii_failed += 1,
                    StigSeverity::Unknown => {}
                }
            }
        }

        summary
    }

    /// Check if all CAT I controls passed
    pub fn cat_i_compliant(&self) -> bool {
        self.cat_i_failed == 0
    }

    /// Check if all CAT I and CAT II controls passed
    pub fn cat_ii_compliant(&self) -> bool {
        self.cat_i_failed == 0 && self.cat_ii_failed == 0
    }

    /// Check if all controls passed
    pub fn fully_compliant(&self) -> bool {
        self.failed_controls == 0
    }

    /// Compliance percentage
    pub fn compliance_percentage(&self) -> f64 {
        if self.total_controls == 0 {
            100.0
        } else {
            (self.passed_controls as f64 / self.total_controls as f64) * 100.0
        }
    }
}

impl std::fmt::Display for StigComplianceSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "STIG Compliance Summary")?;
        writeln!(f, "=======================")?;
        writeln!(
            f,
            "Overall: {}/{} ({:.1}%)",
            self.passed_controls,
            self.total_controls,
            self.compliance_percentage()
        )?;
        writeln!(f)?;
        writeln!(
            f,
            "CAT I (High):   {}/{} {}",
            self.cat_i_passed,
            self.cat_i_passed + self.cat_i_failed,
            if self.cat_i_compliant() { "✓" } else { "✗" }
        )?;
        writeln!(
            f,
            "CAT II (Medium): {}/{}",
            self.cat_ii_passed,
            self.cat_ii_passed + self.cat_ii_failed
        )?;
        writeln!(
            f,
            "CAT III (Low):   {}/{}",
            self.cat_iii_passed,
            self.cat_iii_passed + self.cat_iii_failed
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::stig::{Rule, StigLoader};

    fn create_test_loader() -> StigLoader {
        let yaml = r#"
policy: 'Test STIG'
id: test
controls:
  - id: TEST-001
    title: 'Test AC-7 control'
    levels: [high]
    rules: [test_rule_ac7]
    status: automated
  - id: TEST-002
    title: 'Test IA-5 control'
    levels: [medium]
    rules: [test_rule_ia5]
    status: automated
"#;

        let rule_ac7 = r#"
title: 'Test rule for AC-7'
references:
  nist: AC-7
"#;

        let rule_ia5 = r#"
title: 'Test rule for IA-5'
references:
  nist: IA-5(1)
"#;

        let mut loader = StigLoader::from_yaml(yaml).unwrap();
        loader.add_rule("test_rule_ac7", Rule::from_yaml(rule_ac7).unwrap());
        loader.add_rule("test_rule_ia5", Rule::from_yaml(rule_ia5).unwrap());
        loader
    }

    #[test]
    fn test_stig_validation_all_pass() {
        let loader = create_test_loader();
        let satisfied: HashSet<String> =
            ["AC-7", "IA-5"].iter().map(|s| s.to_string()).collect();

        let mut report = ComplianceReport::new();
        report.validate_stig_controls(&loader, &satisfied);

        assert!(report.is_compliant());
        assert_eq!(report.success_count(), 2);
    }

    #[test]
    fn test_stig_validation_partial_pass() {
        let loader = create_test_loader();
        let satisfied: HashSet<String> = ["AC-7"].iter().map(|s| s.to_string()).collect();

        let mut report = ComplianceReport::new();
        report.validate_stig_controls(&loader, &satisfied);

        assert!(!report.is_compliant());
        assert_eq!(report.success_count(), 1);
        assert_eq!(report.failure_count(), 1);
    }

    #[test]
    fn test_stig_compliance_summary() {
        let loader = create_test_loader();
        let satisfied: HashSet<String> = ["AC-7"].iter().map(|s| s.to_string()).collect();

        let summary = StigComplianceSummary::from_validation(&loader, &satisfied);

        assert_eq!(summary.total_controls, 2);
        assert_eq!(summary.passed_controls, 1);
        assert_eq!(summary.failed_controls, 1);
        assert_eq!(summary.cat_i_passed, 1); // AC-7 is high severity
        assert_eq!(summary.cat_ii_failed, 1); // IA-5 is medium severity
        assert!(summary.cat_i_compliant());
        assert!(!summary.fully_compliant());
    }
}
