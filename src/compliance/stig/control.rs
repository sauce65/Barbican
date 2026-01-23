//! ComplianceAsCode Control File Parser
//!
//! Parses control mapping files like `stig_ubuntu2204.yml` from ComplianceAsCode.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// A ComplianceAsCode control file
///
/// Control files map STIG/CIS/NIST controls to ComplianceAsCode rules.
/// Located in `controls/` directory of the ComplianceAsCode content repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFile {
    /// Policy name (e.g., "Canonical Ubuntu 22.04 LTS STIG")
    pub policy: String,

    /// Policy title
    #[serde(default)]
    pub title: Option<String>,

    /// Control file identifier (e.g., "stig_ubuntu2204")
    pub id: String,

    /// Policy version (e.g., "V2R3")
    #[serde(default)]
    pub version: Option<String>,

    /// Source URL for the policy
    #[serde(default)]
    pub source: Option<String>,

    /// Reference type (e.g., "stigid", "cis")
    #[serde(default)]
    pub reference_type: Option<String>,

    /// Target product (e.g., "ubuntu2204")
    #[serde(default)]
    pub product: Option<String>,

    /// Severity/tier levels defined by this policy
    #[serde(default)]
    pub levels: Vec<ControlLevel>,

    /// Individual controls
    #[serde(default)]
    pub controls: Vec<StigControl>,
}

impl ControlFile {
    /// Load a control file from a YAML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ControlFileError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ControlFileError::Io(e.to_string()))?;
        Self::from_yaml(&content)
    }

    /// Parse a control file from YAML content
    pub fn from_yaml(yaml: &str) -> Result<Self, ControlFileError> {
        serde_yaml::from_str(yaml).map_err(|e| ControlFileError::Parse(e.to_string()))
    }

    /// Get controls by severity level
    pub fn controls_at_level(&self, level: &str) -> Vec<&StigControl> {
        self.controls
            .iter()
            .filter(|c| c.levels.iter().any(|l| l.eq_ignore_ascii_case(level)))
            .collect()
    }

    /// Get all unique rule IDs referenced by controls
    pub fn all_rule_ids(&self) -> Vec<&str> {
        let mut rule_ids: Vec<&str> = self
            .controls
            .iter()
            .flat_map(|c| c.rules.iter().map(|s| s.as_str()))
            .collect();
        rule_ids.sort();
        rule_ids.dedup();
        rule_ids
    }

    /// Check if this is a STIG control file
    pub fn is_stig(&self) -> bool {
        self.reference_type
            .as_ref()
            .map(|r| r.eq_ignore_ascii_case("stigid"))
            .unwrap_or(false)
            || self.policy.to_lowercase().contains("stig")
    }

    /// Check if this is a CIS control file
    pub fn is_cis(&self) -> bool {
        self.reference_type
            .as_ref()
            .map(|r| r.eq_ignore_ascii_case("cis"))
            .unwrap_or(false)
            || self.policy.to_lowercase().contains("cis")
    }

    /// Get total control count
    pub fn control_count(&self) -> usize {
        self.controls.len()
    }

    /// Get count of automated controls
    pub fn automated_count(&self) -> usize {
        self.controls.iter().filter(|c| c.is_automated()).count()
    }
}

/// A severity/tier level definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlLevel {
    /// Level identifier (e.g., "high", "medium", "low", "l1_server")
    pub id: String,

    /// Levels this inherits from
    #[serde(default)]
    pub inherits_from: Vec<String>,
}

/// A single control from a control file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigControl {
    /// Control identifier (e.g., "UBTU-22-211015" for STIG, "1.1.1.1" for CIS)
    pub id: String,

    /// Control title/description
    #[serde(default)]
    pub title: Option<String>,

    /// Severity levels this control applies to
    #[serde(default)]
    pub levels: Vec<String>,

    /// ComplianceAsCode rule IDs that implement this control
    #[serde(default)]
    pub rules: Vec<String>,

    /// Control status (automated, manual, supported)
    #[serde(default)]
    pub status: ControlStatus,

    /// Profile-specific variables
    #[serde(default)]
    pub variables: Vec<String>,

    /// Implementation notes
    #[serde(default)]
    pub notes: Option<String>,

    /// Related rule references
    #[serde(default)]
    pub related_rules: Vec<String>,
}

impl StigControl {
    /// Check if this control is automated
    pub fn is_automated(&self) -> bool {
        matches!(self.status, ControlStatus::Automated)
    }

    /// Check if this is a high-severity control
    pub fn is_high_severity(&self) -> bool {
        self.levels
            .iter()
            .any(|l| l.eq_ignore_ascii_case("high") || l.eq_ignore_ascii_case("cat_i"))
    }

    /// Get the highest severity level for this control
    pub fn max_severity(&self) -> &'static str {
        for level in &self.levels {
            let l = level.to_lowercase();
            if l.contains("high") || l.contains("cat_i") || l == "cati" {
                return "high";
            }
        }
        for level in &self.levels {
            let l = level.to_lowercase();
            if l.contains("medium") || l.contains("cat_ii") || l == "catii" {
                return "medium";
            }
        }
        "low"
    }
}

/// Control implementation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlStatus {
    /// Fully automated with checks and remediation
    #[default]
    Automated,
    /// Requires manual verification
    Manual,
    /// Partially supported
    Supported,
    /// Planned but not implemented
    Planned,
    /// Not applicable
    #[serde(rename = "not applicable")]
    NotApplicable,
    /// Other/unknown status
    #[serde(other)]
    Unknown,
}

impl ControlStatus {
    /// Check if this status indicates automation
    pub fn is_automated(&self) -> bool {
        matches!(self, Self::Automated)
    }
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Automated => write!(f, "automated"),
            Self::Manual => write!(f, "manual"),
            Self::Supported => write!(f, "supported"),
            Self::Planned => write!(f, "planned"),
            Self::NotApplicable => write!(f, "not applicable"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Errors that can occur when loading control files
#[derive(Debug, Clone)]
pub enum ControlFileError {
    /// IO error reading file
    Io(String),
    /// YAML parse error
    Parse(String),
}

impl std::fmt::Display for ControlFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "IO error: {}", msg),
            Self::Parse(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for ControlFileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stig_control_file() {
        let yaml = r#"
policy: 'Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide (STIG)'
title: 'Canonical Ubuntu 22.04 LTS STIG'
id: stig_ubuntu2204
version: V2R3
source: https://www.cyber.mil/stigs/downloads/
reference_type: stigid
product: ubuntu2204

levels:
  - id: high
  - id: medium
  - id: low

controls:
  - id: UBTU-22-211015
    title: 'Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.'
    levels:
      - high
    rules:
      - disable_ctrlaltdel_reboot
    status: automated

  - id: UBTU-22-212010
    title: 'Ubuntu 22.04 LTS, when booted, must require authentication upon booting.'
    levels:
      - high
    rules:
      - grub2_password
      - grub2_uefi_password
    status: automated

  - id: UBTU-22-212015
    title: 'Ubuntu 22.04 LTS must initiate session audits at system startup.'
    levels:
      - medium
    rules:
      - grub2_audit_argument
    status: automated
"#;

        let file = ControlFile::from_yaml(yaml).unwrap();
        assert_eq!(file.id, "stig_ubuntu2204");
        assert_eq!(file.version, Some("V2R3".to_string()));
        assert!(file.is_stig());
        assert!(!file.is_cis());

        assert_eq!(file.levels.len(), 3);
        assert_eq!(file.controls.len(), 3);
        assert_eq!(file.control_count(), 3);
        assert_eq!(file.automated_count(), 3);

        // Check high severity controls
        let high_controls = file.controls_at_level("high");
        assert_eq!(high_controls.len(), 2);

        // Check specific control
        let ctrl = &file.controls[0];
        assert_eq!(ctrl.id, "UBTU-22-211015");
        assert!(ctrl.is_high_severity());
        assert!(ctrl.is_automated());
        assert_eq!(ctrl.rules, vec!["disable_ctrlaltdel_reboot"]);
    }

    #[test]
    fn test_parse_cis_control_file() {
        let yaml = r#"
policy: 'CIS Benchmark for Amazon Linux 2023'
title: 'CIS Benchmark for Amazon Linux 2023'
id: cis_al2023
version: '1.0.0'
source: https://www.cisecurity.org/benchmark/amazon_linux
reference_type: cis
product: al2023

levels:
  - id: l1_server
  - id: l2_server
    inherits_from:
      - l1_server

controls:
  - id: 1.1.1.1
    title: 'Ensure mounting of squashfs filesystems is disabled (Automated)'
    levels:
      - l2_server
    status: automated
    rules:
      - kernel_module_squashfs_disabled
"#;

        let file = ControlFile::from_yaml(yaml).unwrap();
        assert!(!file.is_stig());
        assert!(file.is_cis());
        assert_eq!(file.levels[1].inherits_from, vec!["l1_server"]);
    }

    #[test]
    fn test_all_rule_ids() {
        let yaml = r#"
policy: Test
id: test
controls:
  - id: C1
    rules:
      - rule_a
      - rule_b
  - id: C2
    rules:
      - rule_b
      - rule_c
"#;

        let file = ControlFile::from_yaml(yaml).unwrap();
        let rules = file.all_rule_ids();
        assert_eq!(rules, vec!["rule_a", "rule_b", "rule_c"]);
    }

    #[test]
    fn test_control_max_severity() {
        let high_ctrl = StigControl {
            id: "C1".to_string(),
            levels: vec!["high".to_string()],
            ..Default::default()
        };
        assert_eq!(high_ctrl.max_severity(), "high");

        let mixed_ctrl = StigControl {
            id: "C2".to_string(),
            levels: vec!["medium".to_string(), "low".to_string()],
            ..Default::default()
        };
        assert_eq!(mixed_ctrl.max_severity(), "medium");
    }
}

impl Default for StigControl {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: None,
            levels: Vec::new(),
            rules: Vec::new(),
            status: ControlStatus::default(),
            variables: Vec::new(),
            notes: None,
            related_rules: Vec::new(),
        }
    }
}
