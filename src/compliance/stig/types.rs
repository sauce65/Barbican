//! Core types for STIG/NIST control mapping

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// A NIST 800-53 control reference
///
/// Parsed from ComplianceAsCode rule references like "AC-7", "IA-5(1)(d)", "CM-6(a)"
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NistControl {
    /// Control family (e.g., "AC", "IA", "SC")
    pub family: String,

    /// Control number (e.g., "7", "5", "28")
    pub number: String,

    /// Control enhancements (e.g., ["1", "d"] for IA-5(1)(d))
    pub enhancements: Vec<String>,
}

impl NistControl {
    /// Parse a NIST control string like "AC-7", "IA-5(1)(d)", "CM-6(a)"
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        // Find the dash separating family from number
        let dash_pos = s.find('-')?;
        let family = s[..dash_pos].to_uppercase();

        // Parse number and enhancements
        let rest = &s[dash_pos + 1..];

        // Split on '(' to separate number from enhancements
        let (number, enhancement_str) = if let Some(paren_pos) = rest.find('(') {
            (&rest[..paren_pos], Some(&rest[paren_pos..]))
        } else {
            // Handle trailing letter like "CM-6 b" -> enhancement "b"
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() == 2 {
                (parts[0], Some(parts[1]))
            } else {
                (rest, None)
            }
        };

        // Parse enhancements from "(1)(d)" or "(1, 2)" formats
        let enhancements = if let Some(enh) = enhancement_str {
            parse_enhancements(enh)
        } else {
            vec![]
        };

        Some(Self {
            family,
            number: number.to_string(),
            enhancements,
        })
    }

    /// Returns the base control ID without enhancements (e.g., "AC-7")
    pub fn base_id(&self) -> String {
        format!("{}-{}", self.family, self.number)
    }

    /// Returns the full control ID with enhancements (e.g., "IA-5(1)(d)")
    pub fn full_id(&self) -> String {
        if self.enhancements.is_empty() {
            self.base_id()
        } else {
            let enh_str = self.enhancements
                .iter()
                .map(|e| format!("({})", e))
                .collect::<String>();
            format!("{}{}", self.base_id(), enh_str)
        }
    }

    /// Check if this control matches a base control ID
    ///
    /// Returns true if the base IDs match, ignoring enhancements.
    /// E.g., "IA-5(1)(d)".matches_base("IA-5") returns true
    pub fn matches_base(&self, base_id: &str) -> bool {
        self.base_id().eq_ignore_ascii_case(base_id)
    }
}

impl std::fmt::Display for NistControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_id())
    }
}

/// Parse enhancement strings like "(1)(d)", "(1, 2)", or just "b"
fn parse_enhancements(s: &str) -> Vec<String> {
    let mut enhancements = Vec::new();
    let mut current = String::new();
    let mut in_paren = false;

    for c in s.chars() {
        match c {
            '(' => {
                in_paren = true;
                current.clear();
            }
            ')' => {
                if in_paren && !current.is_empty() {
                    // Handle comma-separated within parens: "(1, 2)"
                    for part in current.split(',') {
                        let trimmed = part.trim();
                        if !trimmed.is_empty() {
                            enhancements.push(trimmed.to_string());
                        }
                    }
                }
                in_paren = false;
                current.clear();
            }
            ' ' | ',' => {
                if in_paren {
                    current.push(c);
                } else if !current.is_empty() {
                    enhancements.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    // Handle trailing content not in parens (like "b" in "CM-6 b")
    if !current.is_empty() && !in_paren {
        enhancements.push(current);
    }

    enhancements
}

/// Mapping between a STIG control and its associated NIST 800-53 controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigMapping {
    /// STIG control identifier (e.g., "UBTU-22-211015")
    pub stig_id: String,

    /// STIG control title
    pub title: String,

    /// Severity level
    pub severity: StigSeverity,

    /// Associated NIST 800-53 controls
    pub nist_controls: HashSet<NistControl>,

    /// ComplianceAsCode rule IDs that implement this control
    pub rule_ids: Vec<String>,

    /// Whether this control is automated or manual
    pub automated: bool,
}

impl StigMapping {
    /// Check if this STIG maps to a specific NIST control base
    pub fn maps_to_nist(&self, base_id: &str) -> bool {
        self.nist_controls.iter().any(|c| c.matches_base(base_id))
    }

    /// Get all base NIST control IDs
    pub fn nist_base_ids(&self) -> HashSet<String> {
        self.nist_controls.iter().map(|c| c.base_id()).collect()
    }
}

/// STIG severity categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StigSeverity {
    /// CAT I - High severity
    High,
    /// CAT II - Medium severity
    Medium,
    /// CAT III - Low severity
    Low,
    /// Unknown severity
    Unknown,
}

impl StigSeverity {
    /// Parse from ComplianceAsCode level string
    pub fn from_level(level: &str) -> Self {
        match level.to_lowercase().as_str() {
            "high" | "cat_i" | "cat1" | "cati" => Self::High,
            "medium" | "cat_ii" | "cat2" | "catii" => Self::Medium,
            "low" | "cat_iii" | "cat3" | "catiii" => Self::Low,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for StigSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "CAT I (High)"),
            Self::Medium => write!(f, "CAT II (Medium)"),
            Self::Low => write!(f, "CAT III (Low)"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_control() {
        let ctrl = NistControl::parse("AC-7").unwrap();
        assert_eq!(ctrl.family, "AC");
        assert_eq!(ctrl.number, "7");
        assert!(ctrl.enhancements.is_empty());
        assert_eq!(ctrl.base_id(), "AC-7");
        assert_eq!(ctrl.full_id(), "AC-7");
    }

    #[test]
    fn test_parse_control_with_enhancement() {
        let ctrl = NistControl::parse("IA-5(1)").unwrap();
        assert_eq!(ctrl.family, "IA");
        assert_eq!(ctrl.number, "5");
        assert_eq!(ctrl.enhancements, vec!["1"]);
        assert_eq!(ctrl.full_id(), "IA-5(1)");
    }

    #[test]
    fn test_parse_control_with_multiple_enhancements() {
        let ctrl = NistControl::parse("IA-5(1)(d)").unwrap();
        assert_eq!(ctrl.family, "IA");
        assert_eq!(ctrl.number, "5");
        assert_eq!(ctrl.enhancements, vec!["1", "d"]);
        assert_eq!(ctrl.full_id(), "IA-5(1)(d)");
    }

    #[test]
    fn test_parse_control_with_space_enhancement() {
        let ctrl = NistControl::parse("CM-6 b").unwrap();
        assert_eq!(ctrl.family, "CM");
        assert_eq!(ctrl.number, "6");
        assert_eq!(ctrl.enhancements, vec!["b"]);
    }

    #[test]
    fn test_matches_base() {
        let ctrl = NistControl::parse("IA-5(1)(d)").unwrap();
        assert!(ctrl.matches_base("IA-5"));
        assert!(ctrl.matches_base("ia-5")); // case insensitive
        assert!(!ctrl.matches_base("IA-2"));
    }

    #[test]
    fn test_severity_from_level() {
        assert_eq!(StigSeverity::from_level("high"), StigSeverity::High);
        assert_eq!(StigSeverity::from_level("HIGH"), StigSeverity::High);
        assert_eq!(StigSeverity::from_level("medium"), StigSeverity::Medium);
        assert_eq!(StigSeverity::from_level("low"), StigSeverity::Low);
        assert_eq!(StigSeverity::from_level("unknown"), StigSeverity::Unknown);
    }
}
