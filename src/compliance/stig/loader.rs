//! STIG Loader - Main Entry Point
//!
//! Loads and correlates STIG controls with NIST 800-53 mappings
//! from ComplianceAsCode content.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::control::{ControlFile, ControlFileError, StigControl};
use super::rule::{Rule, RuleError};
use super::types::{NistControl, StigMapping, StigSeverity};

/// STIG Loader for ComplianceAsCode content
///
/// Loads control files and rules, then correlates them to produce
/// STIG-to-NIST mappings that integrate with Barbican's compliance framework.
///
/// # Usage
///
/// ```ignore
/// use barbican::compliance::stig::StigLoader;
///
/// // Load from a control file
/// let loader = StigLoader::from_control_file("controls/stig_ubuntu2204.yml")?;
///
/// // Query controls by NIST mapping
/// for mapping in loader.controls_for_nist("AC-7") {
///     println!("{}: {}", mapping.stig_id, mapping.title);
/// }
///
/// // Get all NIST controls covered
/// let nist_controls = loader.covered_nist_controls();
/// ```
#[derive(Debug, Clone)]
pub struct StigLoader {
    /// The loaded control file
    control_file: ControlFile,

    /// Rules loaded from rule.yml files (keyed by rule ID)
    rules: HashMap<String, Rule>,

    /// Computed STIG-to-NIST mappings
    mappings: Vec<StigMapping>,
}

impl StigLoader {
    /// Load from a control file path
    pub fn from_control_file(path: impl AsRef<Path>) -> Result<Self, StigLoaderError> {
        let control_file = ControlFile::from_file(path)?;
        let mut loader = Self {
            control_file,
            rules: HashMap::new(),
            mappings: Vec::new(),
        };
        loader.build_mappings();
        Ok(loader)
    }

    /// Load from YAML content
    pub fn from_yaml(yaml: &str) -> Result<Self, StigLoaderError> {
        let control_file = ControlFile::from_yaml(yaml)?;
        let mut loader = Self {
            control_file,
            rules: HashMap::new(),
            mappings: Vec::new(),
        };
        loader.build_mappings();
        Ok(loader)
    }

    /// Load rules from a ComplianceAsCode content directory
    ///
    /// Searches for `rule.yml` files that match the rule IDs in the control file.
    ///
    /// # Arguments
    ///
    /// * `content_dir` - Path to ComplianceAsCode content root (containing `linux_os/`)
    pub fn load_rules_from_content(&mut self, content_dir: impl AsRef<Path>) -> Result<(), StigLoaderError> {
        let content_dir = content_dir.as_ref();

        // Get all rule IDs we need (collect to owned strings to avoid borrow issues)
        let rule_ids: HashSet<String> = self
            .control_file
            .all_rule_ids()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        // Search for rule.yml files
        let search_paths = [
            content_dir.join("linux_os/guide"),
            content_dir.join("applications"),
            content_dir.join("shared"),
        ];

        for search_path in &search_paths {
            if search_path.exists() {
                self.find_rules_recursive(search_path, &rule_ids)?;
            }
        }

        // Rebuild mappings with the loaded rules
        self.build_mappings();

        Ok(())
    }

    /// Recursively search for rule.yml files
    fn find_rules_recursive(
        &mut self,
        dir: &Path,
        rule_ids: &HashSet<String>,
    ) -> Result<(), StigLoaderError> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| StigLoaderError::Io(e.to_string()))?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                // Check if this directory name matches a rule ID we're looking for
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if rule_ids.contains(dir_name) {
                        let rule_yml = path.join("rule.yml");
                        if rule_yml.exists() {
                            if let Ok(rule) = Rule::from_file(&rule_yml) {
                                self.rules.insert(dir_name.to_string(), rule);
                            }
                        }
                    }
                }

                // Continue searching subdirectories
                self.find_rules_recursive(&path, rule_ids)?;
            }
        }

        Ok(())
    }

    /// Manually add a rule
    pub fn add_rule(&mut self, rule_id: impl Into<String>, rule: Rule) {
        self.rules.insert(rule_id.into(), rule);
        self.build_mappings();
    }

    /// Build STIG-to-NIST mappings from loaded controls and rules
    fn build_mappings(&mut self) {
        self.mappings = self
            .control_file
            .controls
            .iter()
            .map(|ctrl| {
                // Collect NIST controls from all rules
                let nist_controls: HashSet<NistControl> = ctrl
                    .rules
                    .iter()
                    .filter_map(|rule_id| self.rules.get(rule_id))
                    .flat_map(|rule| rule.nist_controls())
                    .collect();

                // Determine severity from control levels
                let severity = StigSeverity::from_level(ctrl.max_severity());

                StigMapping {
                    stig_id: ctrl.id.clone(),
                    title: ctrl.title.clone().unwrap_or_default(),
                    severity,
                    nist_controls,
                    rule_ids: ctrl.rules.clone(),
                    automated: ctrl.is_automated(),
                }
            })
            .collect();
    }

    /// Get the control file
    pub fn control_file(&self) -> &ControlFile {
        &self.control_file
    }

    /// Get all loaded rules
    pub fn rules(&self) -> &HashMap<String, Rule> {
        &self.rules
    }

    /// Get all STIG controls
    pub fn controls(&self) -> &[StigControl] {
        &self.control_file.controls
    }

    /// Get all computed STIG mappings
    pub fn mappings(&self) -> &[StigMapping] {
        &self.mappings
    }

    /// Get STIG controls that map to a specific NIST control
    pub fn controls_for_nist(&self, nist_id: &str) -> Vec<&StigMapping> {
        self.mappings
            .iter()
            .filter(|m| m.maps_to_nist(nist_id))
            .collect()
    }

    /// Get all NIST control IDs covered by loaded STIGs
    pub fn covered_nist_controls(&self) -> HashSet<String> {
        self.mappings
            .iter()
            .flat_map(|m| m.nist_base_ids())
            .collect()
    }

    /// Get controls at a specific severity level
    pub fn controls_at_severity(&self, severity: StigSeverity) -> Vec<&StigMapping> {
        self.mappings
            .iter()
            .filter(|m| m.severity == severity)
            .collect()
    }

    /// Get all high-severity (CAT I) controls
    pub fn cat_i_controls(&self) -> Vec<&StigMapping> {
        self.controls_at_severity(StigSeverity::High)
    }

    /// Get all medium-severity (CAT II) controls
    pub fn cat_ii_controls(&self) -> Vec<&StigMapping> {
        self.controls_at_severity(StigSeverity::Medium)
    }

    /// Get all low-severity (CAT III) controls
    pub fn cat_iii_controls(&self) -> Vec<&StigMapping> {
        self.controls_at_severity(StigSeverity::Low)
    }

    /// Get statistics about the loaded content
    pub fn stats(&self) -> StigStats {
        let total = self.mappings.len();
        let automated = self.mappings.iter().filter(|m| m.automated).count();
        let cat_i = self.cat_i_controls().len();
        let cat_ii = self.cat_ii_controls().len();
        let cat_iii = self.cat_iii_controls().len();
        let with_nist = self
            .mappings
            .iter()
            .filter(|m| !m.nist_controls.is_empty())
            .count();
        let rules_loaded = self.rules.len();
        let rules_referenced = self.control_file.all_rule_ids().len();

        StigStats {
            total_controls: total,
            automated_controls: automated,
            cat_i_controls: cat_i,
            cat_ii_controls: cat_ii,
            cat_iii_controls: cat_iii,
            controls_with_nist_mapping: with_nist,
            rules_loaded,
            rules_referenced,
            nist_controls_covered: self.covered_nist_controls().len(),
        }
    }

    /// Generate a mapping report
    pub fn nist_mapping_report(&self) -> NistMappingReport {
        let mut by_nist: HashMap<String, Vec<&StigMapping>> = HashMap::new();

        for mapping in &self.mappings {
            for nist_id in mapping.nist_base_ids() {
                by_nist.entry(nist_id).or_default().push(mapping);
            }
        }

        NistMappingReport {
            policy: self.control_file.policy.clone(),
            version: self.control_file.version.clone(),
            by_nist_control: by_nist
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.into_iter()
                            .map(|m| NistMappingEntry {
                                stig_id: m.stig_id.clone(),
                                title: m.title.clone(),
                                severity: m.severity,
                                automated: m.automated,
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

/// Statistics about loaded STIG content
#[derive(Debug, Clone)]
pub struct StigStats {
    /// Total number of STIG controls
    pub total_controls: usize,
    /// Number of automated controls
    pub automated_controls: usize,
    /// Number of CAT I (high) controls
    pub cat_i_controls: usize,
    /// Number of CAT II (medium) controls
    pub cat_ii_controls: usize,
    /// Number of CAT III (low) controls
    pub cat_iii_controls: usize,
    /// Controls with at least one NIST mapping
    pub controls_with_nist_mapping: usize,
    /// Number of rules loaded from rule.yml files
    pub rules_loaded: usize,
    /// Number of unique rules referenced by controls
    pub rules_referenced: usize,
    /// Number of unique NIST controls covered
    pub nist_controls_covered: usize,
}

impl std::fmt::Display for StigStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "STIG Statistics")?;
        writeln!(f, "===============")?;
        writeln!(f, "Total Controls:     {}", self.total_controls)?;
        writeln!(f, "  CAT I (High):     {}", self.cat_i_controls)?;
        writeln!(f, "  CAT II (Medium):  {}", self.cat_ii_controls)?;
        writeln!(f, "  CAT III (Low):    {}", self.cat_iii_controls)?;
        writeln!(f, "Automated:          {}", self.automated_controls)?;
        writeln!(f, "With NIST Mapping:  {}", self.controls_with_nist_mapping)?;
        writeln!(f, "Rules Referenced:   {}", self.rules_referenced)?;
        writeln!(f, "Rules Loaded:       {}", self.rules_loaded)?;
        writeln!(f, "NIST Controls:      {}", self.nist_controls_covered)?;
        Ok(())
    }
}

/// Report of STIG-to-NIST mappings
#[derive(Debug, Clone)]
pub struct NistMappingReport {
    /// Policy name
    pub policy: String,
    /// Policy version
    pub version: Option<String>,
    /// Mappings grouped by NIST control ID
    pub by_nist_control: HashMap<String, Vec<NistMappingEntry>>,
}

/// A single entry in the NIST mapping report
#[derive(Debug, Clone)]
pub struct NistMappingEntry {
    /// STIG control ID
    pub stig_id: String,
    /// Control title
    pub title: String,
    /// Severity level
    pub severity: StigSeverity,
    /// Whether automated
    pub automated: bool,
}

/// Errors that can occur when loading STIGs
#[derive(Debug)]
pub enum StigLoaderError {
    /// IO error
    Io(String),
    /// Control file parse error
    ControlFile(ControlFileError),
    /// Rule parse error
    Rule(RuleError),
}

impl std::fmt::Display for StigLoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "IO error: {}", msg),
            Self::ControlFile(e) => write!(f, "Control file error: {}", e),
            Self::Rule(e) => write!(f, "Rule error: {}", e),
        }
    }
}

impl std::error::Error for StigLoaderError {}

impl From<ControlFileError> for StigLoaderError {
    fn from(e: ControlFileError) -> Self {
        Self::ControlFile(e)
    }
}

impl From<RuleError> for StigLoaderError {
    fn from(e: RuleError) -> Self {
        Self::Rule(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_control_yaml() -> &'static str {
        r#"
policy: 'Test STIG'
id: test_stig
version: V1R0
reference_type: stigid

levels:
  - id: high
  - id: medium
  - id: low

controls:
  - id: TEST-001
    title: 'Disable Ctrl-Alt-Delete'
    levels:
      - high
    rules:
      - disable_ctrlaltdel_reboot
    status: automated

  - id: TEST-002
    title: 'Require boot authentication'
    levels:
      - high
    rules:
      - grub2_password
    status: automated

  - id: TEST-003
    title: 'Enable audit logging'
    levels:
      - medium
    rules:
      - grub2_audit_argument
    status: automated
"#
    }

    fn sample_rule_yaml() -> &'static str {
        r#"
documentation_complete: true
title: 'Disable Ctrl-Alt-Delete Reboot'
description: Prevent reboot via Ctrl-Alt-Delete
severity: high

references:
  nist: AC-6,CM-6
"#
    }

    #[test]
    fn test_load_from_yaml() {
        let loader = StigLoader::from_yaml(sample_control_yaml()).unwrap();
        assert_eq!(loader.control_file.id, "test_stig");
        assert_eq!(loader.controls().len(), 3);
    }

    #[test]
    fn test_add_rule_and_mapping() {
        let mut loader = StigLoader::from_yaml(sample_control_yaml()).unwrap();

        // Add a rule manually
        let rule = Rule::from_yaml(sample_rule_yaml()).unwrap();
        loader.add_rule("disable_ctrlaltdel_reboot", rule);

        // Check that mapping was built
        let mappings = loader.mappings();
        assert!(!mappings.is_empty());

        // First mapping should now have NIST controls
        let first = &mappings[0];
        assert_eq!(first.stig_id, "TEST-001");
        assert!(!first.nist_controls.is_empty());
        assert!(first.maps_to_nist("AC-6"));
        assert!(first.maps_to_nist("CM-6"));
    }

    #[test]
    fn test_controls_for_nist() {
        let mut loader = StigLoader::from_yaml(sample_control_yaml()).unwrap();

        let rule = Rule::from_yaml(sample_rule_yaml()).unwrap();
        loader.add_rule("disable_ctrlaltdel_reboot", rule);

        let ac6_controls = loader.controls_for_nist("AC-6");
        assert_eq!(ac6_controls.len(), 1);
        assert_eq!(ac6_controls[0].stig_id, "TEST-001");
    }

    #[test]
    fn test_covered_nist_controls() {
        let mut loader = StigLoader::from_yaml(sample_control_yaml()).unwrap();

        let rule = Rule::from_yaml(sample_rule_yaml()).unwrap();
        loader.add_rule("disable_ctrlaltdel_reboot", rule);

        let covered = loader.covered_nist_controls();
        assert!(covered.contains("AC-6"));
        assert!(covered.contains("CM-6"));
    }

    #[test]
    fn test_severity_filtering() {
        let loader = StigLoader::from_yaml(sample_control_yaml()).unwrap();

        // Without rules loaded, mappings still exist but without NIST data
        let cat_i = loader.cat_i_controls();
        assert_eq!(cat_i.len(), 2); // TEST-001 and TEST-002 are high severity

        let cat_ii = loader.cat_ii_controls();
        assert_eq!(cat_ii.len(), 1); // TEST-003 is medium
    }

    #[test]
    fn test_stats() {
        let mut loader = StigLoader::from_yaml(sample_control_yaml()).unwrap();

        let rule = Rule::from_yaml(sample_rule_yaml()).unwrap();
        loader.add_rule("disable_ctrlaltdel_reboot", rule);

        let stats = loader.stats();
        assert_eq!(stats.total_controls, 3);
        assert_eq!(stats.automated_controls, 3);
        assert_eq!(stats.cat_i_controls, 2);
        assert_eq!(stats.cat_ii_controls, 1);
        assert_eq!(stats.rules_loaded, 1);
        assert_eq!(stats.rules_referenced, 3); // 3 unique rule IDs in controls
    }
}
