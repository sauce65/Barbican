//! ComplianceAsCode Variable Definition Parser
//!
//! Parses `var_*.var` YAML files from ComplianceAsCode content to extract
//! variable definitions with their types, defaults, and allowed options.
//!
//! # Variable File Format
//!
//! ComplianceAsCode variable files follow this structure:
//!
//! ```yaml
//! documentation_complete: true
//! title: 'Password Minimum Length'
//! description: |-
//!   Minimum number of characters for passwords.
//! type: number
//! operator: equals
//! interactive: true
//! options:
//!   default: 14
//!   8: 8
//!   12: 12
//!   14: 14
//!   15: 15
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::error::{GeneratorError, Result};

/// A ComplianceAsCode variable definition (from var_*.var files)
#[derive(Debug, Clone)]
pub struct VariableDefinition {
    /// Variable identifier (derived from filename, e.g., "var_password_pam_minlen")
    pub id: String,

    /// Human-readable title
    pub title: Option<String>,

    /// Detailed description
    pub description: Option<String>,

    /// Variable type
    pub var_type: VariableType,

    /// Default value (if specified in options)
    pub default: Option<VariableValue>,

    /// Available options (key is the selector, value is the actual value)
    pub options: HashMap<String, VariableValue>,

    /// Whether this is an interactive variable
    pub interactive: bool,
}

/// Type of a variable
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum VariableType {
    /// Numeric value (integer)
    #[default]
    Number,

    /// String value
    String,

    /// Boolean value
    Boolean,
}

impl VariableType {
    /// Parse from ComplianceAsCode type string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "number" => Self::Number,
            "string" => Self::String,
            "boolean" | "bool" => Self::Boolean,
            _ => Self::String, // Default to string for unknown types
        }
    }
}

/// Parsed variable value
#[derive(Debug, Clone, PartialEq)]
pub enum VariableValue {
    /// Integer value
    Integer(i64),

    /// String value
    String(String),

    /// Boolean value
    Boolean(bool),

    /// Duration value (converted from seconds)
    Duration(Duration),
}

impl VariableValue {
    /// Try to convert a YAML value to a VariableValue
    pub fn from_yaml(value: &serde_yaml::Value, var_type: &VariableType) -> Option<Self> {
        match var_type {
            VariableType::Number => {
                // Try integer first, then float converted to integer
                if let Some(n) = value.as_i64() {
                    Some(Self::Integer(n))
                } else if let Some(n) = value.as_f64() {
                    Some(Self::Integer(n as i64))
                } else if let Some(s) = value.as_str() {
                    s.parse::<i64>().ok().map(Self::Integer)
                } else {
                    None
                }
            }
            VariableType::String => {
                if let Some(s) = value.as_str() {
                    Some(Self::String(s.to_string()))
                } else {
                    // Convert other types to string
                    Some(Self::String(format!("{:?}", value)))
                }
            }
            VariableType::Boolean => {
                if let Some(b) = value.as_bool() {
                    Some(Self::Boolean(b))
                } else if let Some(s) = value.as_str() {
                    match s.to_lowercase().as_str() {
                        "true" | "yes" | "1" | "on" => Some(Self::Boolean(true)),
                        "false" | "no" | "0" | "off" => Some(Self::Boolean(false)),
                        _ => None,
                    }
                } else {
                    None
                }
            }
        }
    }

    /// Get as integer, if applicable
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as string, if applicable
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as boolean, if applicable
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as duration (interpreting integer as seconds)
    pub fn as_duration(&self) -> Option<Duration> {
        match self {
            Self::Integer(n) if *n >= 0 => Some(Duration::from_secs(*n as u64)),
            Self::Duration(d) => Some(*d),
            _ => None,
        }
    }

    /// Convert integer to duration (seconds)
    pub fn to_duration(self) -> Self {
        match self {
            Self::Integer(n) if n >= 0 => Self::Duration(Duration::from_secs(n as u64)),
            other => other,
        }
    }
}

impl std::fmt::Display for VariableValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(n) => write!(f, "{}", n),
            Self::String(s) => write!(f, "{}", s),
            Self::Boolean(b) => write!(f, "{}", b),
            Self::Duration(d) => write!(f, "{}s", d.as_secs()),
        }
    }
}

/// Raw YAML structure for ComplianceAsCode variable files
#[derive(Debug, Deserialize)]
struct RawVariableFile {
    #[serde(default)]
    title: Option<String>,

    #[serde(default)]
    description: Option<String>,

    #[serde(default, rename = "type")]
    var_type: Option<String>,

    #[serde(default)]
    interactive: Option<bool>,

    #[serde(default)]
    options: Option<serde_yaml::Value>,
}

impl VariableDefinition {
    /// Load a variable definition from a file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| GeneratorError::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        let id = Self::id_from_path(path);
        Self::from_yaml(&content, id).map_err(|e| match e {
            GeneratorError::Yaml { path: _, message } => GeneratorError::VariableParse {
                path: path.to_path_buf(),
                message,
            },
            other => other,
        })
    }

    /// Parse from YAML content with a given ID
    pub fn from_yaml(yaml: &str, id: String) -> Result<Self> {
        let raw: RawVariableFile = serde_yaml::from_str(yaml)?;

        let var_type = raw
            .var_type
            .as_deref()
            .map(VariableType::from_str)
            .unwrap_or_default();

        let (default, options) = Self::parse_options(&raw.options, &var_type);

        Ok(Self {
            id,
            title: raw.title,
            description: raw.description,
            var_type,
            default,
            options,
            interactive: raw.interactive.unwrap_or(false),
        })
    }

    /// Extract variable ID from file path
    ///
    /// e.g., "/path/to/var_password_pam_minlen.var" -> "var_password_pam_minlen"
    fn id_from_path(path: &Path) -> String {
        path.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Parse the options field from a variable file
    fn parse_options(
        options: &Option<serde_yaml::Value>,
        var_type: &VariableType,
    ) -> (Option<VariableValue>, HashMap<String, VariableValue>) {
        let mut parsed_options = HashMap::new();
        let mut default = None;

        if let Some(serde_yaml::Value::Mapping(map)) = options {
            for (key, value) in map {
                // Handle both string and numeric keys
                let key_str = if let Some(s) = key.as_str() {
                    s.to_string()
                } else if let Some(n) = key.as_i64() {
                    n.to_string()
                } else if let Some(n) = key.as_f64() {
                    (n as i64).to_string()
                } else {
                    continue;
                };

                if let Some(parsed_value) = VariableValue::from_yaml(value, var_type) {
                    if key_str == "default" {
                        // The "default" key points to another key, not a direct value
                        // Try to resolve as string reference first, then as number
                        let default_key = if let Some(s) = value.as_str() {
                            Some(s.to_string())
                        } else if let Some(n) = value.as_i64() {
                            Some(n.to_string())
                        } else {
                            None
                        };

                        if let Some(ref_key) = default_key {
                            // We'll resolve this after parsing all options
                            parsed_options.insert(
                                "_default_ref".to_string(),
                                VariableValue::String(ref_key),
                            );
                        } else {
                            // Direct default value
                            default = Some(parsed_value.clone());
                            parsed_options.insert(key_str, parsed_value);
                        }
                    } else {
                        parsed_options.insert(key_str, parsed_value);
                    }
                }
            }

            // Resolve default reference if present
            if let Some(VariableValue::String(ref_key)) = parsed_options.remove("_default_ref") {
                if let Some(value) = parsed_options.get(&ref_key) {
                    default = Some(value.clone());
                }
            }
        }

        (default, parsed_options)
    }

    /// Get the default value, or the first option if no default is specified
    pub fn default_or_first(&self) -> Option<&VariableValue> {
        self.default.as_ref().or_else(|| self.options.values().next())
    }
}

/// Collection of variable definitions loaded from a content directory
#[derive(Debug, Default, Clone)]
pub struct VariableCollection {
    /// Variables keyed by ID
    variables: HashMap<String, VariableDefinition>,
}

impl VariableCollection {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Load variables from a ComplianceAsCode content directory
    ///
    /// Searches for `*.var` files in standard locations.
    pub fn load_from_content(content_dir: impl AsRef<Path>) -> Result<Self> {
        let content_dir = content_dir.as_ref();
        let mut collection = Self::new();

        // Standard paths where variables are stored
        let search_paths = [
            content_dir.join("linux_os/guide"),
            content_dir.join("applications"),
            content_dir.join("shared"),
        ];

        for search_path in &search_paths {
            if search_path.exists() {
                collection.find_variables_recursive(search_path)?;
            }
        }

        Ok(collection)
    }

    /// Recursively search for .var files
    fn find_variables_recursive(&mut self, dir: &Path) -> Result<()> {
        let entries = std::fs::read_dir(dir).map_err(|e| GeneratorError::Io {
            path: dir.to_path_buf(),
            message: e.to_string(),
        })?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                self.find_variables_recursive(&path)?;
            } else if path.extension().map(|e| e == "var").unwrap_or(false) {
                match VariableDefinition::from_file(&path) {
                    Ok(var) => {
                        self.variables.insert(var.id.clone(), var);
                    }
                    Err(e) => {
                        // Log but continue - some var files may have unusual formats
                        tracing::debug!("Skipping variable file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a variable to the collection
    pub fn add(&mut self, var: VariableDefinition) {
        self.variables.insert(var.id.clone(), var);
    }

    /// Get a variable by ID
    pub fn get(&self, id: &str) -> Option<&VariableDefinition> {
        self.variables.get(id)
    }

    /// Get all variables
    pub fn iter(&self) -> impl Iterator<Item = &VariableDefinition> {
        self.variables.values()
    }

    /// Number of loaded variables
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Whether the collection is empty
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_variable_yaml() -> &'static str {
        r#"
documentation_complete: true
title: 'Password Minimum Length'
description: |-
  Minimum number of characters for passwords.
type: number
operator: equals
interactive: true
options:
  default: 14
  8: 8
  12: 12
  14: 14
  15: 15
"#
    }

    fn sample_string_variable_yaml() -> &'static str {
        r#"
documentation_complete: true
title: 'System Crypto Policy'
description: System-wide crypto policy selection
type: string
options:
  default: FIPS
  DEFAULT: DEFAULT
  FIPS: FIPS
  FUTURE: FUTURE
"#
    }

    #[test]
    fn test_parse_number_variable() {
        let var =
            VariableDefinition::from_yaml(sample_variable_yaml(), "var_password_pam_minlen".into())
                .unwrap();

        assert_eq!(var.id, "var_password_pam_minlen");
        assert_eq!(var.title.as_deref(), Some("Password Minimum Length"));
        assert_eq!(var.var_type, VariableType::Number);
        assert!(var.interactive);

        // Check default
        assert_eq!(var.default, Some(VariableValue::Integer(14)));

        // Check options
        assert!(var.options.contains_key("8"));
        assert!(var.options.contains_key("12"));
        assert!(var.options.contains_key("14"));
        assert!(var.options.contains_key("15"));
    }

    #[test]
    fn test_parse_string_variable() {
        let var = VariableDefinition::from_yaml(
            sample_string_variable_yaml(),
            "var_system_crypto_policy".into(),
        )
        .unwrap();

        assert_eq!(var.id, "var_system_crypto_policy");
        assert_eq!(var.var_type, VariableType::String);
        assert_eq!(
            var.default,
            Some(VariableValue::String("FIPS".to_string()))
        );
    }

    #[test]
    fn test_variable_value_conversions() {
        let int_val = VariableValue::Integer(300);
        assert_eq!(int_val.as_integer(), Some(300));
        assert_eq!(int_val.as_duration(), Some(Duration::from_secs(300)));

        let str_val = VariableValue::String("test".to_string());
        assert_eq!(str_val.as_string(), Some("test"));

        let bool_val = VariableValue::Boolean(true);
        assert_eq!(bool_val.as_boolean(), Some(true));

        // Duration conversion
        let dur_val = int_val.to_duration();
        assert_eq!(dur_val.as_duration(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_variable_value_display() {
        assert_eq!(format!("{}", VariableValue::Integer(42)), "42");
        assert_eq!(format!("{}", VariableValue::String("foo".into())), "foo");
        assert_eq!(format!("{}", VariableValue::Boolean(true)), "true");
        assert_eq!(
            format!("{}", VariableValue::Duration(Duration::from_secs(300))),
            "300s"
        );
    }

    #[test]
    fn test_variable_type_from_str() {
        assert_eq!(VariableType::from_str("number"), VariableType::Number);
        assert_eq!(VariableType::from_str("Number"), VariableType::Number);
        assert_eq!(VariableType::from_str("string"), VariableType::String);
        assert_eq!(VariableType::from_str("boolean"), VariableType::Boolean);
        assert_eq!(VariableType::from_str("bool"), VariableType::Boolean);
        assert_eq!(VariableType::from_str("unknown"), VariableType::String);
    }

    #[test]
    fn test_collection_operations() {
        let mut collection = VariableCollection::new();
        assert!(collection.is_empty());

        let var =
            VariableDefinition::from_yaml(sample_variable_yaml(), "var_password_pam_minlen".into())
                .unwrap();

        collection.add(var);
        assert_eq!(collection.len(), 1);
        assert!(!collection.is_empty());
        assert!(collection.get("var_password_pam_minlen").is_some());
    }
}
