//! Error types for the Barbican CLI

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias for CLI operations
pub type Result<T> = std::result::Result<T, CliError>;

/// CLI error types
#[derive(Error, Debug)]
pub enum CliError {
    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    /// Configuration file read error
    #[error("Failed to read configuration file {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Configuration parse error
    #[error("Failed to parse configuration file {path}: {message}")]
    ConfigParse { path: PathBuf, message: String },

    /// Invalid compliance profile
    #[error("Invalid compliance profile: {profile}. Valid options: fedramp-low, fedramp-moderate, fedramp-high, soc2, custom")]
    InvalidProfile { profile: String },

    /// Validation failure
    #[error("Configuration validation failed: {message}")]
    ValidationFailed { message: String },

    /// Multiple validation failures
    #[error("Configuration validation failed with {count} errors")]
    MultipleValidationFailures { count: usize },

    /// Output directory creation failed
    #[error("Failed to create output directory {path}: {source}")]
    OutputDirCreation {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// File write error
    #[error("Failed to write file {path}: {source}")]
    FileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Template rendering error
    #[error("Failed to render template {template}: {message}")]
    TemplateRender { template: String, message: String },

    /// Drift detected between config and generated files
    #[error("Drift detected: generated files are out of sync with configuration")]
    DriftDetected,

    /// Missing required configuration
    #[error("Missing required configuration: {field}")]
    MissingRequired { field: String },

    /// Invalid configuration value
    #[error("Invalid value for {field}: {message}")]
    InvalidValue { field: String, message: String },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl CliError {
    /// Create a validation failure error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::ValidationFailed {
            message: message.into(),
        }
    }

    /// Create a missing required field error
    pub fn missing(field: impl Into<String>) -> Self {
        Self::MissingRequired {
            field: field.into(),
        }
    }

    /// Create an invalid value error
    pub fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::InvalidValue {
            field: field.into(),
            message: message.into(),
        }
    }
}
