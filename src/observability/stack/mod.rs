//! Observability Stack Generation
//!
//! Generate FedRAMP-compliant observability infrastructure configurations
//! for Loki, Prometheus, Grafana, and supporting components.
//!
//! # Example
//!
//! ```rust,ignore
//! use barbican::observability::stack::{ObservabilityStack, ComplianceProfile};
//!
//! let stack = ObservabilityStack::builder()
//!     .app_name("my-app")
//!     .app_port(3443)
//!     .output_dir("./observability")
//!     .compliance_profile(ComplianceProfile::FedRampModerate)
//!     .build()?;
//!
//! // Generate all configuration files
//! stack.generate()?;
//!
//! // Validate against FedRAMP requirements
//! let report = stack.validate()?;
//! ```

mod alerts;
mod compose;
mod fedramp;
mod grafana;
mod loki;
mod prometheus;
mod scripts;

// Re-export compliance types for convenience
pub use crate::compliance::ComplianceProfile;
pub use fedramp::ObservabilityComplianceConfig;
pub use loki::LokiConfig;
pub use prometheus::PrometheusConfig;
pub use grafana::{GrafanaConfig, GrafanaSso};
pub use compose::ComposeConfig;
pub use alerts::AlertRules;

use std::path::{Path, PathBuf};
use std::fs;
use std::fmt;
use std::error::Error;

/// Errors that can occur during stack generation
#[derive(Debug)]
pub enum StackError {
    /// Configuration error
    Config(String),

    /// IO error
    Io(std::io::Error),

    /// Validation error
    Validation(String),

    /// Missing required field
    MissingField(String),
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StackError::Config(msg) => write!(f, "Configuration error: {}", msg),
            StackError::Io(err) => write!(f, "IO error: {}", err),
            StackError::Validation(msg) => write!(f, "Validation error: {}", msg),
            StackError::MissingField(field) => write!(f, "Missing required field: {}", field),
        }
    }
}

impl Error for StackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            StackError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StackError {
    fn from(err: std::io::Error) -> Self {
        StackError::Io(err)
    }
}

/// Result type for stack operations
pub type StackResult<T> = Result<T, StackError>;

/// Complete observability stack configuration
#[derive(Debug, Clone)]
pub struct ObservabilityStack {
    /// Application name (used for labels, service names)
    pub app_name: String,

    /// Application metrics port
    pub app_port: u16,

    /// Output directory for generated configs
    pub output_dir: PathBuf,

    /// Compliance configuration for observability
    pub fedramp: ObservabilityComplianceConfig,

    /// Loki configuration
    pub loki: LokiConfig,

    /// Prometheus configuration
    pub prometheus: PrometheusConfig,

    /// Grafana configuration
    pub grafana: GrafanaConfig,

    /// Docker Compose configuration
    pub compose: ComposeConfig,

    /// Alert rules configuration
    pub alerts: AlertRules,
}

impl ObservabilityStack {
    /// Create a new builder for ObservabilityStack
    pub fn builder() -> ObservabilityStackBuilder {
        ObservabilityStackBuilder::default()
    }

    /// Generate all configuration files
    pub fn generate(&self) -> StackResult<GenerationReport> {
        let mut report = GenerationReport::new(&self.output_dir);

        // Create directory structure
        self.create_directories()?;

        // Generate each component
        report.add_files(self.generate_loki()?);
        report.add_files(self.generate_prometheus()?);
        report.add_files(self.generate_grafana()?);
        report.add_files(self.generate_alerts()?);
        report.add_files(self.generate_compose()?);
        report.add_files(self.generate_scripts()?);
        report.add_files(self.generate_docs()?);

        Ok(report)
    }

    /// Validate configuration against FedRAMP requirements
    pub fn validate(&self) -> StackResult<ValidationReport> {
        fedramp::validate_stack(self)
    }

    fn create_directories(&self) -> StackResult<()> {
        let dirs = [
            "",
            "loki",
            "prometheus",
            "prometheus/rules",
            "grafana",
            "grafana/provisioning",
            "grafana/provisioning/datasources",
            "grafana/provisioning/dashboards",
            "grafana/provisioning/dashboards/json",
            "alertmanager",
            "certs",
            "certs/loki",
            "certs/prometheus",
            "certs/grafana",
            "certs/alertmanager",
            "certs/clients",
            "scripts",
            "secrets",
            "docs",
        ];

        for dir in dirs {
            let path = self.output_dir.join(dir);
            fs::create_dir_all(&path)?;
        }

        Ok(())
    }

    fn generate_loki(&self) -> StackResult<Vec<GeneratedFile>> {
        loki::generate(&self.output_dir, &self.loki, &self.fedramp, &self.app_name)
    }

    fn generate_prometheus(&self) -> StackResult<Vec<GeneratedFile>> {
        prometheus::generate(
            &self.output_dir,
            &self.prometheus,
            &self.fedramp,
            &self.app_name,
            self.app_port,
        )
    }

    fn generate_grafana(&self) -> StackResult<Vec<GeneratedFile>> {
        grafana::generate(&self.output_dir, &self.grafana, &self.fedramp, &self.app_name)
    }

    fn generate_alerts(&self) -> StackResult<Vec<GeneratedFile>> {
        alerts::generate(&self.output_dir, &self.alerts, &self.fedramp, &self.app_name)
    }

    fn generate_compose(&self) -> StackResult<Vec<GeneratedFile>> {
        compose::generate(&self.output_dir, &self.compose, &self.fedramp, &self.app_name)
    }

    fn generate_scripts(&self) -> StackResult<Vec<GeneratedFile>> {
        scripts::generate(&self.output_dir, &self.fedramp, &self.app_name)
    }

    fn generate_docs(&self) -> StackResult<Vec<GeneratedFile>> {
        fedramp::generate_docs(&self.output_dir, &self.fedramp, &self.app_name)
    }
}

/// Builder for ObservabilityStack
#[derive(Default)]
pub struct ObservabilityStackBuilder {
    app_name: Option<String>,
    app_port: Option<u16>,
    output_dir: Option<PathBuf>,
    compliance_profile: Option<ComplianceProfile>,
    loki: Option<LokiConfig>,
    prometheus: Option<PrometheusConfig>,
    grafana: Option<GrafanaConfig>,
    compose: Option<ComposeConfig>,
    alerts: Option<AlertRules>,
}

impl ObservabilityStackBuilder {
    /// Set the application name (required)
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }

    /// Set the application metrics port (required)
    pub fn app_port(mut self, port: u16) -> Self {
        self.app_port = Some(port);
        self
    }

    /// Set the output directory for generated configs (required)
    pub fn output_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(path.into());
        self
    }

    /// Set the compliance profile
    pub fn compliance_profile(mut self, profile: ComplianceProfile) -> Self {
        self.compliance_profile = Some(profile);
        self
    }

    /// Alias for backwards compatibility - prefer compliance_profile()
    #[deprecated(since = "0.2.0", note = "Use compliance_profile() instead")]
    pub fn fedramp_profile(mut self, profile: ComplianceProfile) -> Self {
        self.compliance_profile = Some(profile);
        self
    }

    /// Override Loki configuration
    pub fn loki(mut self, config: LokiConfig) -> Self {
        self.loki = Some(config);
        self
    }

    /// Override Prometheus configuration
    pub fn prometheus(mut self, config: PrometheusConfig) -> Self {
        self.prometheus = Some(config);
        self
    }

    /// Override Grafana configuration
    pub fn grafana(mut self, config: GrafanaConfig) -> Self {
        self.grafana = Some(config);
        self
    }

    /// Override Docker Compose configuration
    pub fn compose(mut self, config: ComposeConfig) -> Self {
        self.compose = Some(config);
        self
    }

    /// Override alert rules configuration
    pub fn alerts(mut self, config: AlertRules) -> Self {
        self.alerts = Some(config);
        self
    }

    /// Build the ObservabilityStack
    pub fn build(self) -> StackResult<ObservabilityStack> {
        let app_name = self
            .app_name
            .ok_or_else(|| StackError::MissingField("app_name".to_string()))?;
        let app_port = self
            .app_port
            .ok_or_else(|| StackError::MissingField("app_port".to_string()))?;
        let output_dir = self
            .output_dir
            .ok_or_else(|| StackError::MissingField("output_dir".to_string()))?;

        let profile = self
            .compliance_profile
            .unwrap_or(ComplianceProfile::FedRampModerate);
        let fedramp = ObservabilityComplianceConfig::from_profile(profile);

        let loki = self
            .loki
            .unwrap_or_else(|| LokiConfig::default_for_profile(profile));
        let prometheus = self
            .prometheus
            .unwrap_or_else(|| PrometheusConfig::default_for_profile(profile));
        let grafana = self
            .grafana
            .unwrap_or_else(|| GrafanaConfig::default_for_profile(profile));
        let compose = self.compose.unwrap_or_default();
        let alerts = self
            .alerts
            .unwrap_or_else(|| AlertRules::default_for_profile(profile));

        Ok(ObservabilityStack {
            app_name,
            app_port,
            output_dir,
            fedramp,
            loki,
            prometheus,
            grafana,
            compose,
            alerts,
        })
    }
}

/// Report of generated files
#[derive(Debug)]
pub struct GenerationReport {
    pub output_dir: PathBuf,
    pub files: Vec<GeneratedFile>,
}

impl GenerationReport {
    fn new(output_dir: &Path) -> Self {
        Self {
            output_dir: output_dir.to_path_buf(),
            files: Vec::new(),
        }
    }

    fn add_files(&mut self, files: Vec<GeneratedFile>) {
        self.files.extend(files);
    }

    /// Get total number of files generated
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Print a summary of generated files
    pub fn print_summary(&self) {
        println!("Generated {} files in {:?}:", self.files.len(), self.output_dir);
        for file in &self.files {
            println!("  {} - {}", file.path.display(), file.description);
        }
    }
}

/// Information about a generated file
#[derive(Debug)]
pub struct GeneratedFile {
    pub path: PathBuf,
    pub description: String,
    pub fedramp_controls: Vec<String>,
}

impl GeneratedFile {
    pub fn new(path: impl Into<PathBuf>, description: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            description: description.into(),
            fedramp_controls: Vec::new(),
        }
    }

    pub fn with_controls(mut self, controls: Vec<&str>) -> Self {
        self.fedramp_controls = controls.into_iter().map(String::from).collect();
        self
    }
}

/// Validation report for FedRAMP compliance
#[derive(Debug)]
pub struct ValidationReport {
    pub passed: bool,
    pub controls: Vec<ControlStatus>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self {
            passed: true,
            controls: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn add_control(&mut self, control: ControlStatus) {
        if !control.satisfied {
            self.passed = false;
        }
        self.controls.push(control);
    }

    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    pub fn add_error(&mut self, error: impl Into<String>) {
        self.passed = false;
        self.errors.push(error.into());
    }

    pub fn print_summary(&self) {
        let status = if self.passed { "PASSED" } else { "FAILED" };
        println!("FedRAMP Validation: {}", status);
        println!();

        println!("Controls ({} total):", self.controls.len());
        for control in &self.controls {
            let icon = if control.satisfied { "✓" } else { "✗" };
            println!("  {} {} - {}", icon, control.id, control.name);
            if !control.satisfied {
                println!("      {}", control.message);
            }
        }

        if !self.warnings.is_empty() {
            println!();
            println!("Warnings:");
            for warning in &self.warnings {
                println!("  ⚠ {}", warning);
            }
        }

        if !self.errors.is_empty() {
            println!();
            println!("Errors:");
            for error in &self.errors {
                println!("  ✗ {}", error);
            }
        }
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Status of a FedRAMP control
#[derive(Debug)]
pub struct ControlStatus {
    pub id: String,
    pub name: String,
    pub satisfied: bool,
    pub message: String,
}

impl ControlStatus {
    pub fn satisfied(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            satisfied: true,
            message: String::new(),
        }
    }

    pub fn failed(id: impl Into<String>, name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            satisfied: false,
            message: message.into(),
        }
    }
}
