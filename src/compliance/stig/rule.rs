//! ComplianceAsCode Rule Definition Parser
//!
//! Parses rule.yml files from ComplianceAsCode content.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::types::NistControl;

/// A ComplianceAsCode rule definition
///
/// Parsed from `rule.yml` files in the ComplianceAsCode content repository.
/// Rules contain the actual security requirements and their NIST control mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Whether the rule documentation is complete
    #[serde(default)]
    pub documentation_complete: bool,

    /// Rule title
    pub title: String,

    /// Detailed description of what the rule checks/enforces
    #[serde(default)]
    pub description: String,

    /// Rationale for why this rule is important
    #[serde(default)]
    pub rationale: Option<String>,

    /// Severity level: low, medium, high
    #[serde(default)]
    pub severity: Severity,

    /// CCE identifiers by product (e.g., "cce@rhel8": "CCE-80671-1")
    #[serde(default)]
    pub identifiers: HashMap<String, String>,

    /// Compliance framework references
    #[serde(default)]
    pub references: RuleReferences,

    /// Platform applicability constraint
    #[serde(default)]
    pub platform: Option<String>,

    /// OCIL (Open Checklist Interactive Language) test clause
    #[serde(default)]
    pub ocil_clause: Option<String>,

    /// OCIL test procedure
    #[serde(default)]
    pub ocil: Option<String>,

    /// STIG-style fix text
    #[serde(default)]
    pub fixtext: Option<String>,

    /// STIG-style check text
    #[serde(default)]
    pub checktext: Option<String>,

    /// SRG requirement text
    #[serde(default)]
    pub srg_requirement: Option<String>,

    /// Warning messages
    #[serde(default)]
    pub warnings: Option<HashMap<String, String>>,

    /// Rule IDs this rule conflicts with
    #[serde(default)]
    pub conflicts: Vec<String>,

    /// Rule IDs this rule requires
    #[serde(default)]
    pub requires: Vec<String>,
}

impl Rule {
    /// Load a rule from a YAML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| RuleError::Io(e.to_string()))?;
        Self::from_yaml(&content)
    }

    /// Parse a rule from YAML content
    pub fn from_yaml(yaml: &str) -> Result<Self, RuleError> {
        serde_yaml::from_str(yaml).map_err(|e| RuleError::Parse(e.to_string()))
    }

    /// Get all NIST controls referenced by this rule
    pub fn nist_controls(&self) -> Vec<NistControl> {
        self.references.nist_controls()
    }

    /// Check if this rule maps to a specific NIST control
    pub fn maps_to_nist(&self, control_id: &str) -> bool {
        self.nist_controls()
            .iter()
            .any(|c| c.matches_base(control_id))
    }

    /// Get the CCE identifier for a specific product
    pub fn cce_for_product(&self, product: &str) -> Option<&str> {
        let key = format!("cce@{}", product);
        self.identifiers.get(&key).map(|s| s.as_str())
    }
}

/// Rule severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity
    Low,
    /// Medium severity (default)
    #[default]
    Medium,
    /// High severity
    High,
    /// Unknown severity
    #[serde(other)]
    Unknown,
}

impl Severity {
    /// Convert to STIG CAT level
    pub fn to_cat(&self) -> &'static str {
        match self {
            Self::High => "CAT I",
            Self::Medium => "CAT II",
            Self::Low => "CAT III",
            Self::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Compliance framework references from a rule
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleReferences {
    /// NIST 800-53 control references (e.g., "IA-5(f),IA-5(1)(d),CM-6(a)")
    #[serde(default)]
    pub nist: Option<String>,

    /// NIST CSF references
    #[serde(default, rename = "nist-csf")]
    pub nist_csf: Option<String>,

    /// CIS benchmark references (product-specific)
    #[serde(default, rename = "cis-csc")]
    pub cis_csc: Option<String>,

    /// CUI (Controlled Unclassified Information) references
    #[serde(default)]
    pub cui: Option<String>,

    /// PCI-DSS references
    #[serde(default)]
    pub pcidss: Option<String>,

    /// HIPAA references
    #[serde(default)]
    pub hipaa: Option<String>,

    /// ISO 27001 references
    #[serde(default, rename = "iso27001-2013")]
    pub iso27001: Option<String>,

    /// COBIT5 references
    #[serde(default)]
    pub cobit5: Option<String>,

    /// ISA 62443 references
    #[serde(default, rename = "isa-62443-2009")]
    pub isa_62443: Option<String>,

    /// STIG ID references
    #[serde(default)]
    pub stigid: Option<String>,

    /// SRG (Security Requirements Guide) references
    #[serde(default)]
    pub srg: Option<String>,

    /// DISA CCI references (legacy, mostly removed from ComplianceAsCode)
    #[serde(default)]
    pub cci: Option<String>,

    /// Additional product-specific CIS references are captured via flatten
    #[serde(flatten)]
    pub other: HashMap<String, serde_yaml::Value>,
}

impl RuleReferences {
    /// Parse NIST control references into structured controls
    pub fn nist_controls(&self) -> Vec<NistControl> {
        let Some(ref nist_str) = self.nist else {
            return vec![];
        };

        nist_str
            .split(',')
            .filter_map(|s| NistControl::parse(s.trim()))
            .collect()
    }

    /// Get all framework reference keys that are present
    pub fn frameworks(&self) -> Vec<&'static str> {
        let mut frameworks = Vec::new();
        if self.nist.is_some() {
            frameworks.push("NIST 800-53");
        }
        if self.nist_csf.is_some() {
            frameworks.push("NIST CSF");
        }
        if self.pcidss.is_some() {
            frameworks.push("PCI-DSS");
        }
        if self.hipaa.is_some() {
            frameworks.push("HIPAA");
        }
        if self.iso27001.is_some() {
            frameworks.push("ISO 27001");
        }
        if self.cui.is_some() {
            frameworks.push("CUI");
        }
        frameworks
    }
}

/// Errors that can occur when loading rules
#[derive(Debug, Clone)]
pub enum RuleError {
    /// IO error reading file
    Io(String),
    /// YAML parse error
    Parse(String),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "IO error: {}", msg),
            Self::Parse(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for RuleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule_yaml() {
        let yaml = r#"
documentation_complete: true
title: 'Set Password Warning Age'
description: |-
  To specify how many days prior to password expiration
  that a warning will be issued to users.
rationale: |-
  Setting the password warning age enables users to make
  the change at a practical time.
severity: medium

identifiers:
  cce@rhel8: CCE-80671-1
  cce@rhel9: CCE-83609-8

references:
  nist: IA-5(f),IA-5(1)(d),CM-6(a)
  pcidss: Req-8.2.4
  cis-csc: 1,12,15

platform: package[shadow-utils]
ocil_clause: 'it is not set to the required value'
ocil: |-
  To check the password warning age, run the command:
  $ grep PASS_WARN_AGE /etc/login.defs
"#;

        let rule = Rule::from_yaml(yaml).unwrap();
        assert!(rule.documentation_complete);
        assert_eq!(rule.title, "Set Password Warning Age");
        assert_eq!(rule.severity, Severity::Medium);

        // Check identifiers
        assert_eq!(rule.cce_for_product("rhel8"), Some("CCE-80671-1"));
        assert_eq!(rule.cce_for_product("rhel9"), Some("CCE-83609-8"));

        // Check NIST references
        let nist = rule.nist_controls();
        assert_eq!(nist.len(), 3);
        assert!(rule.maps_to_nist("IA-5"));
        assert!(rule.maps_to_nist("CM-6"));
        assert!(!rule.maps_to_nist("AC-7"));
    }

    #[test]
    fn test_rule_references_frameworks() {
        let refs = RuleReferences {
            nist: Some("AC-7".to_string()),
            pcidss: Some("8.1.6".to_string()),
            ..Default::default()
        };

        let frameworks = refs.frameworks();
        assert!(frameworks.contains(&"NIST 800-53"));
        assert!(frameworks.contains(&"PCI-DSS"));
        assert!(!frameworks.contains(&"HIPAA"));
    }

    #[test]
    fn test_severity_to_cat() {
        assert_eq!(Severity::High.to_cat(), "CAT I");
        assert_eq!(Severity::Medium.to_cat(), "CAT II");
        assert_eq!(Severity::Low.to_cat(), "CAT III");
    }
}
