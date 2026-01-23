//! ComplianceAsCode Profile Parser
//!
//! Parses `.profile` YAML files from ComplianceAsCode content to extract
//! profile selections and variable assignments.
//!
//! # Profile File Format
//!
//! ComplianceAsCode profile files follow this structure:
//!
//! ```yaml
//! documentation_complete: true
//! title: 'DISA STIG for Ubuntu 22.04 LTS'
//! description: |-
//!   This profile contains configuration checks that align to the
//!   DISA STIG for Ubuntu 22.04 LTS.
//! extends: stig
//! selections:
//!   - var_password_pam_minlen=15
//!   - var_accounts_passwords_pam_faillock_deny=3
//!   - accounts_password_pam_minlen
//!   - accounts_passwords_pam_faillock_deny
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use super::error::{GeneratorError, Result};

/// A ComplianceAsCode profile definition
#[derive(Debug, Clone)]
pub struct StigProfile {
    /// Profile identifier (derived from filename or id field)
    pub id: String,

    /// Human-readable title
    pub title: Option<String>,

    /// Detailed description
    pub description: Option<String>,

    /// Variable assignments (var_name -> value as string)
    pub variables: HashMap<String, String>,

    /// Selected rule IDs
    pub selections: Vec<String>,

    /// Unselected (disabled) rule IDs
    pub unselections: Vec<String>,

    /// Profile this extends from
    pub extends: Option<String>,
}

/// Raw YAML structure for ComplianceAsCode profile files
#[derive(Debug, Deserialize)]
struct RawProfileFile {
    #[serde(default)]
    id: Option<String>,

    #[serde(default)]
    title: Option<String>,

    #[serde(default)]
    description: Option<String>,

    #[serde(default)]
    extends: Option<String>,

    #[serde(default)]
    selections: Vec<String>,
}

impl StigProfile {
    /// Load a profile from a file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| GeneratorError::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        let id = Self::id_from_path(path);
        Self::from_yaml(&content, id).map_err(|e| match e {
            GeneratorError::Yaml { path: _, message } => GeneratorError::ProfileParse {
                path: path.to_path_buf(),
                message,
            },
            other => other,
        })
    }

    /// Parse from YAML content with a given ID
    pub fn from_yaml(yaml: &str, default_id: String) -> Result<Self> {
        let raw: RawProfileFile = serde_yaml::from_str(yaml)?;

        let id = raw.id.unwrap_or(default_id);
        let (variables, selections, unselections) = Self::parse_selections(&raw.selections);

        Ok(Self {
            id,
            title: raw.title,
            description: raw.description,
            variables,
            selections,
            unselections,
            extends: raw.extends,
        })
    }

    /// Extract profile ID from file path
    ///
    /// e.g., "/path/to/stig.profile" -> "stig"
    fn id_from_path(path: &Path) -> String {
        path.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Parse selections to extract variable assignments and rule selections
    fn parse_selections(
        selections: &[String],
    ) -> (HashMap<String, String>, Vec<String>, Vec<String>) {
        let mut variables = HashMap::new();
        let mut rule_selections = Vec::new();
        let mut unselections = Vec::new();

        for entry in selections {
            let entry = entry.trim();

            // Check for unselection (prefixed with !)
            if let Some(unsel) = entry.strip_prefix('!') {
                unselections.push(unsel.to_string());
                continue;
            }

            // Check for variable assignment (contains =)
            if let Some((var_name, value)) = entry.split_once('=') {
                variables.insert(var_name.to_string(), value.to_string());
            } else {
                // It's a rule selection
                rule_selections.push(entry.to_string());
            }
        }

        (variables, rule_selections, unselections)
    }

    /// Get a variable value from this profile
    pub fn get_variable(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(|s| s.as_str())
    }

    /// Check if a rule is selected in this profile
    pub fn has_rule(&self, rule_id: &str) -> bool {
        self.selections.contains(&rule_id.to_string())
            && !self.unselections.contains(&rule_id.to_string())
    }
}

/// Profile collection with inheritance resolution
#[derive(Debug, Default, Clone)]
pub struct ProfileCollection {
    /// Profiles keyed by ID
    profiles: HashMap<String, StigProfile>,
}

impl ProfileCollection {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Load profiles from a ComplianceAsCode content directory
    ///
    /// Searches for `*.profile` files in standard locations.
    pub fn load_from_content(content_dir: impl AsRef<Path>) -> Result<Self> {
        let content_dir = content_dir.as_ref();
        let mut collection = Self::new();

        // Standard paths where profiles are stored (product-specific)
        let search_paths = [
            content_dir.join("products"),
            content_dir.join("linux_os"),
            content_dir.to_path_buf(),
        ];

        for search_path in &search_paths {
            if search_path.exists() {
                collection.find_profiles_recursive(search_path)?;
            }
        }

        Ok(collection)
    }

    /// Load profiles specifically for a product
    pub fn load_for_product(content_dir: impl AsRef<Path>, product: &str) -> Result<Self> {
        let content_dir = content_dir.as_ref();
        let mut collection = Self::new();

        // Product-specific profile location
        let product_path = content_dir.join("products").join(product).join("profiles");
        if product_path.exists() {
            collection.find_profiles_recursive(&product_path)?;
        }

        // Also check shared profiles
        let shared_path = content_dir.join("shared").join("profiles");
        if shared_path.exists() {
            collection.find_profiles_recursive(&shared_path)?;
        }

        Ok(collection)
    }

    /// Recursively search for .profile files
    fn find_profiles_recursive(&mut self, dir: &Path) -> Result<()> {
        let entries = std::fs::read_dir(dir).map_err(|e| GeneratorError::Io {
            path: dir.to_path_buf(),
            message: e.to_string(),
        })?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                self.find_profiles_recursive(&path)?;
            } else if path.extension().map(|e| e == "profile").unwrap_or(false) {
                match StigProfile::from_file(&path) {
                    Ok(profile) => {
                        self.profiles.insert(profile.id.clone(), profile);
                    }
                    Err(e) => {
                        // Log but continue - some profile files may have unusual formats
                        tracing::debug!("Skipping profile file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a profile to the collection
    pub fn add(&mut self, profile: StigProfile) {
        self.profiles.insert(profile.id.clone(), profile);
    }

    /// Get a profile by ID
    pub fn get(&self, id: &str) -> Option<&StigProfile> {
        self.profiles.get(id)
    }

    /// Get a profile with resolved inheritance
    ///
    /// Variables and selections from parent profiles are merged,
    /// with child profile values taking precedence.
    pub fn get_resolved(&self, id: &str) -> Option<StigProfile> {
        let profile = self.profiles.get(id)?;

        if let Some(ref extends) = profile.extends {
            // Get parent profile (recursively resolved)
            if let Some(parent) = self.get_resolved(extends) {
                // Merge: parent + child (child takes precedence)
                let mut merged_variables = parent.variables.clone();
                merged_variables.extend(profile.variables.clone());

                let mut merged_selections = parent.selections.clone();
                merged_selections.extend(profile.selections.clone());
                merged_selections.dedup();

                let mut merged_unselections = parent.unselections.clone();
                merged_unselections.extend(profile.unselections.clone());
                merged_unselections.dedup();

                return Some(StigProfile {
                    id: profile.id.clone(),
                    title: profile.title.clone().or(parent.title),
                    description: profile.description.clone().or(parent.description),
                    variables: merged_variables,
                    selections: merged_selections,
                    unselections: merged_unselections,
                    extends: None, // Already resolved
                });
            }
        }

        Some(profile.clone())
    }

    /// Get all profiles
    pub fn iter(&self) -> impl Iterator<Item = &StigProfile> {
        self.profiles.values()
    }

    /// Get all profile IDs
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(|s| s.as_str())
    }

    /// Number of loaded profiles
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the collection is empty
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile_yaml() -> &'static str {
        r#"
documentation_complete: true
id: stig
title: 'DISA STIG for Ubuntu 22.04 LTS'
description: |-
  This profile contains configuration checks that align to the
  DISA STIG for Ubuntu 22.04 LTS.
selections:
  - var_password_pam_minlen=15
  - var_accounts_passwords_pam_faillock_deny=3
  - var_accounts_passwords_pam_faillock_unlock_time=900
  - accounts_password_pam_minlen
  - accounts_passwords_pam_faillock_deny
  - "!disable_some_rule"
"#
    }

    fn sample_child_profile_yaml() -> &'static str {
        r#"
id: stig_high
title: 'STIG with High Security'
extends: stig
selections:
  - var_password_pam_minlen=20
  - additional_rule
"#
    }

    #[test]
    fn test_parse_profile() {
        let profile = StigProfile::from_yaml(sample_profile_yaml(), "stig".into()).unwrap();

        assert_eq!(profile.id, "stig");
        assert_eq!(profile.title.as_deref(), Some("DISA STIG for Ubuntu 22.04 LTS"));
        assert!(profile.description.is_some());
        assert!(profile.extends.is_none());

        // Check variables
        assert_eq!(profile.variables.len(), 3);
        assert_eq!(profile.get_variable("var_password_pam_minlen"), Some("15"));
        assert_eq!(
            profile.get_variable("var_accounts_passwords_pam_faillock_deny"),
            Some("3")
        );
        assert_eq!(
            profile.get_variable("var_accounts_passwords_pam_faillock_unlock_time"),
            Some("900")
        );

        // Check selections
        assert_eq!(profile.selections.len(), 2);
        assert!(profile.has_rule("accounts_password_pam_minlen"));
        assert!(profile.has_rule("accounts_passwords_pam_faillock_deny"));

        // Check unselections
        assert_eq!(profile.unselections.len(), 1);
        assert!(profile.unselections.contains(&"disable_some_rule".to_string()));
    }

    #[test]
    fn test_profile_inheritance() {
        let mut collection = ProfileCollection::new();

        let parent = StigProfile::from_yaml(sample_profile_yaml(), "stig".into()).unwrap();
        let child = StigProfile::from_yaml(sample_child_profile_yaml(), "stig_high".into()).unwrap();

        collection.add(parent);
        collection.add(child);

        // Get resolved child profile
        let resolved = collection.get_resolved("stig_high").unwrap();

        // Child overrides parent variable
        assert_eq!(resolved.get_variable("var_password_pam_minlen"), Some("20"));

        // Parent variables are inherited
        assert_eq!(
            resolved.get_variable("var_accounts_passwords_pam_faillock_deny"),
            Some("3")
        );

        // Selections are merged
        assert!(resolved.has_rule("accounts_password_pam_minlen"));
        assert!(resolved.has_rule("additional_rule"));
    }

    #[test]
    fn test_collection_operations() {
        let mut collection = ProfileCollection::new();
        assert!(collection.is_empty());

        let profile = StigProfile::from_yaml(sample_profile_yaml(), "stig".into()).unwrap();
        collection.add(profile);

        assert_eq!(collection.len(), 1);
        assert!(!collection.is_empty());
        assert!(collection.get("stig").is_some());
        assert!(collection.get("nonexistent").is_none());
    }

    #[test]
    fn test_has_rule_with_unselection() {
        let yaml = r#"
selections:
  - rule_a
  - rule_b
  - "!rule_b"
"#;
        let profile = StigProfile::from_yaml(yaml, "test".into()).unwrap();

        assert!(profile.has_rule("rule_a"));
        assert!(!profile.has_rule("rule_b")); // Unselected
    }
}
