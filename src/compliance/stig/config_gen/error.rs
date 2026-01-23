//! Error types for STIG configuration generation
//!
//! Defines error types for variable parsing, profile parsing, value transformation,
//! and the overall generation pipeline.

use std::path::PathBuf;

use super::super::loader::StigLoaderError;

/// Errors that can occur during configuration generation
#[derive(Debug)]
pub enum GeneratorError {
    /// Error loading STIG control file
    StigLoad(StigLoaderError),

    /// Error parsing a variable definition file
    VariableParse {
        path: PathBuf,
        message: String,
    },

    /// Error parsing a profile file
    ProfileParse {
        path: PathBuf,
        message: String,
    },

    /// Variable not found in loaded definitions
    VariableNotFound {
        variable: String,
    },

    /// Profile not found
    ProfileNotFound {
        profile: String,
        searched_paths: Vec<PathBuf>,
    },

    /// Error transforming a variable value
    Transform {
        variable: String,
        message: String,
    },

    /// IO error
    Io {
        path: PathBuf,
        message: String,
    },

    /// YAML parsing error
    Yaml {
        path: Option<PathBuf>,
        message: String,
    },

    /// TOML serialization error
    Toml {
        message: String,
    },
}

impl std::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StigLoad(e) => write!(f, "STIG load error: {}", e),
            Self::VariableParse { path, message } => {
                write!(f, "Variable parse error in {:?}: {}", path, message)
            }
            Self::ProfileParse { path, message } => {
                write!(f, "Profile parse error in {:?}: {}", path, message)
            }
            Self::VariableNotFound { variable } => {
                write!(f, "Variable not found: {}", variable)
            }
            Self::ProfileNotFound {
                profile,
                searched_paths,
            } => {
                write!(
                    f,
                    "Profile '{}' not found in paths: {:?}",
                    profile, searched_paths
                )
            }
            Self::Transform { variable, message } => {
                write!(f, "Transform error for '{}': {}", variable, message)
            }
            Self::Io { path, message } => {
                write!(f, "IO error for {:?}: {}", path, message)
            }
            Self::Yaml { path, message } => match path {
                Some(p) => write!(f, "YAML error in {:?}: {}", p, message),
                None => write!(f, "YAML error: {}", message),
            },
            Self::Toml { message } => {
                write!(f, "TOML serialization error: {}", message)
            }
        }
    }
}

impl std::error::Error for GeneratorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StigLoad(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StigLoaderError> for GeneratorError {
    fn from(e: StigLoaderError) -> Self {
        Self::StigLoad(e)
    }
}

impl From<std::io::Error> for GeneratorError {
    fn from(e: std::io::Error) -> Self {
        Self::Io {
            path: PathBuf::new(),
            message: e.to_string(),
        }
    }
}

impl From<serde_yaml::Error> for GeneratorError {
    fn from(e: serde_yaml::Error) -> Self {
        Self::Yaml {
            path: None,
            message: e.to_string(),
        }
    }
}

/// Result type alias for generator operations
pub type Result<T> = std::result::Result<T, GeneratorError>;
