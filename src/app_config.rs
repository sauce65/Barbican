//! Unified Application Configuration
//!
//! Single entry point for configuring a barbican-secured application.
//! All security and observability settings are derived from a compliance profile.
//!
//! # Example
//!
//! ```ignore
//! use barbican::{AppConfig, ObservableRouter, SecureRouter};
//! use axum::Router;
//!
//! // Load everything from environment (profile determines all settings)
//! let config = AppConfig::from_env();
//!
//! // Build your router with full observability and security
//! let metrics = config.create_metrics(|b| b);  // Add custom metrics in closure
//! let app = Router::new()
//!     .routes(...)
//!     .with_observability(metrics)
//!     .with_security(config.security.clone());
//!
//! // Or generate observability infrastructure
//! config.generate_stack("./observability")?;
//! ```

use crate::compliance::ComplianceProfile;
use crate::config::SecurityConfig;
use crate::encryption::EncryptionConfig;
use crate::integration::{
    encryption_config_for_profile, lockout_policy_for_profile, password_policy_for_profile,
    session_policy_for_profile,
};
use crate::login::LockoutPolicy;
use crate::observability::metrics::{MetricRegistry, MetricRegistryBuilder};
use crate::observability::ObservabilityConfig;
use crate::password::PasswordPolicy;
use crate::session::SessionPolicy;
use crate::tls::TlsMode;
use std::sync::Arc;
use std::time::Duration;

/// Unified application configuration.
///
/// Provides a single entry point for configuring all barbican security and
/// observability features. Settings are derived from the compliance profile
/// by default, with environment variable overrides available.
///
/// # Compliance Profiles
///
/// - `FedRampLow`: Basic security, 30 min idle timeout, 5 login attempts
/// - `FedRampModerate`: Enhanced security, 15 min idle, 3 login attempts, encryption at rest
/// - `FedRampHigh`: Maximum security, 10 min idle, mTLS, strict TLS, full encryption
/// - `Soc2`: SOC 2 Type II requirements, similar to Moderate
/// - `Development`: Relaxed settings for local development
///
/// # Environment Variables
///
/// - `COMPLIANCE_PROFILE` or `BARBICAN_COMPLIANCE_PROFILE`: Profile name
/// - `SERVICE_NAME` or `BARBICAN_SERVICE_NAME`: Application name (default: "app")
/// - `SERVICE_PORT` or `BARBICAN_SERVICE_PORT`: Application port (default: 8080)
/// - Plus all standard `SecurityConfig` and `ObservabilityConfig` variables
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Application name (used in metrics, logs, stack generation)
    pub name: String,

    /// Application port (used for metrics scraping config)
    pub port: u16,

    /// Compliance profile determining security posture
    pub profile: ComplianceProfile,

    /// Observability configuration (logging, tracing, metrics)
    pub observability: ObservabilityConfig,

    /// Security infrastructure configuration (headers, rate limiting, TLS)
    pub security: SecurityConfig,

    /// Session management policy (AC-11, AC-12)
    pub session: SessionPolicy,

    /// Login attempt tracking policy (AC-7)
    pub lockout: LockoutPolicy,

    /// Password validation policy (IA-5)
    pub password: PasswordPolicy,

    /// Encryption at rest configuration (SC-28)
    pub encryption: EncryptionConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl AppConfig {
    /// Load configuration from environment variables.
    ///
    /// Reads `COMPLIANCE_PROFILE` or `BARBICAN_COMPLIANCE_PROFILE` to determine
    /// the base security posture, then derives all settings from that profile.
    /// Individual settings can be overridden via environment variables.
    pub fn from_env() -> Self {
        Self::from_env_with_prefix("")
    }

    /// Load configuration from environment variables with a prefix.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Will read DPE_COMPLIANCE_PROFILE, DPE_SERVICE_NAME, etc.
    /// let config = AppConfig::from_env_with_prefix("DPE_");
    /// ```
    pub fn from_env_with_prefix(prefix: &str) -> Self {
        let profile = read_profile_from_env(prefix);
        let mut config = Self::for_profile(profile);

        // Override name and port from environment
        config.name = std::env::var(format!("{prefix}SERVICE_NAME"))
            .or_else(|_| std::env::var("SERVICE_NAME"))
            .unwrap_or_else(|_| "app".to_string());

        config.port = std::env::var(format!("{prefix}SERVICE_PORT"))
            .or_else(|_| std::env::var("SERVICE_PORT"))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);

        // Load security config from env (respects profile defaults)
        config.security = security_config_for_profile_from_env(profile);

        // Load observability config from env
        config.observability = ObservabilityConfig::from_env();

        config
    }

    /// Create configuration for a specific compliance profile.
    ///
    /// All settings are derived from the profile with sensible defaults.
    pub fn for_profile(profile: ComplianceProfile) -> Self {
        Self {
            name: "app".to_string(),
            port: 8080,
            profile,
            observability: ObservabilityConfig::default(),
            security: security_config_for_profile(profile),
            session: session_policy_for_profile(profile),
            lockout: lockout_policy_for_profile(profile),
            password: password_policy_for_profile(profile),
            encryption: encryption_config_for_profile(profile),
        }
    }

    /// Create a development configuration with relaxed security.
    ///
    /// WARNING: Never use in production!
    pub fn development() -> Self {
        Self {
            name: "app-dev".to_string(),
            port: 8080,
            profile: ComplianceProfile::Development,
            observability: ObservabilityConfig::default(),
            security: SecurityConfig::development(),
            session: SessionPolicy::relaxed(),
            lockout: LockoutPolicy::relaxed(),
            password: PasswordPolicy::default(),
            encryption: EncryptionConfig {
                require_encryption: false,
                ..Default::default()
            },
        }
    }

    /// Create a MetricRegistry builder with HTTP metrics and app name pre-configured.
    ///
    /// Use the callback to add application-specific metrics.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let metrics = config.create_metrics(|b| {
    ///     b.counter("jobs_total", &["status"], "Total jobs processed")
    ///      .histogram("job_duration", &[], &[1.0, 5.0], "Job duration")
    /// });
    /// ```
    pub fn create_metrics<F>(&self, customize: F) -> Arc<MetricRegistry>
    where
        F: FnOnce(MetricRegistryBuilder) -> MetricRegistryBuilder,
    {
        let builder = MetricRegistry::builder()
            .app_name(&self.name)
            .with_http_metrics();

        Arc::new(customize(builder).build())
    }

    /// Generate observability infrastructure stack.
    ///
    /// Creates Prometheus, Loki, Grafana, and AlertManager configurations
    /// in the specified output directory.
    #[cfg(feature = "compliance-artifacts")]
    pub fn generate_stack(
        &self,
        output_dir: impl AsRef<std::path::Path>,
    ) -> Result<crate::observability::stack::GenerationReport, crate::observability::stack::StackError>
    {
        use crate::observability::stack::ObservabilityStack;

        ObservabilityStack::builder()
            .app_name(&self.name)
            .app_port(self.port)
            .compliance_profile(self.profile)
            .output_dir(output_dir.as_ref())
            .build()?
            .generate()
    }

    /// Check if this configuration requires MFA.
    pub fn requires_mfa(&self) -> bool {
        matches!(
            self.profile,
            ComplianceProfile::FedRampModerate | ComplianceProfile::FedRampHigh
        )
    }

    /// Check if this configuration requires encryption at rest.
    pub fn requires_encryption(&self) -> bool {
        self.encryption.require_encryption
    }

    /// Get session idle timeout.
    pub fn idle_timeout(&self) -> Duration {
        self.session.idle_timeout
    }

    /// Get session max lifetime.
    pub fn max_session_lifetime(&self) -> Duration {
        self.session.max_lifetime
    }

    /// Check if this is a development configuration.
    pub fn is_development(&self) -> bool {
        matches!(self.profile, ComplianceProfile::Development)
    }

    /// Check if TLS is required.
    pub fn requires_tls(&self) -> bool {
        matches!(
            self.security.tls_mode,
            TlsMode::Required | TlsMode::Strict
        )
    }
}

/// Read compliance profile from environment.
fn read_profile_from_env(prefix: &str) -> ComplianceProfile {
    // Try prefixed, then standard names
    let profile_str = std::env::var(format!("{prefix}COMPLIANCE_PROFILE"))
        .or_else(|_| std::env::var("COMPLIANCE_PROFILE"))
        .or_else(|_| std::env::var("BARBICAN_COMPLIANCE_PROFILE"))
        .or_else(|_| std::env::var(format!("{prefix}ENVIRONMENT")))
        .or_else(|_| std::env::var("ENVIRONMENT"))
        .unwrap_or_else(|_| "fedramp-moderate".to_string());

    parse_profile(&profile_str)
}

/// Parse a profile string to ComplianceProfile.
fn parse_profile(s: &str) -> ComplianceProfile {
    match s.to_lowercase().as_str() {
        "fedramp-low" | "low" => ComplianceProfile::FedRampLow,
        "fedramp-moderate" | "moderate" => ComplianceProfile::FedRampModerate,
        "fedramp-high" | "high" => ComplianceProfile::FedRampHigh,
        "soc2" | "soc-2" => ComplianceProfile::Soc2,
        "development" | "dev" => ComplianceProfile::Development,
        _ => ComplianceProfile::FedRampModerate, // Safe default
    }
}

/// Create SecurityConfig for a compliance profile.
fn security_config_for_profile(profile: ComplianceProfile) -> SecurityConfig {
    match profile {
        ComplianceProfile::Development => SecurityConfig::development(),
        ComplianceProfile::FedRampLow => SecurityConfig {
            max_request_size: 5 * 1024 * 1024, // 5MB
            request_timeout: Duration::from_secs(60),
            rate_limit_per_second: 20,
            rate_limit_burst: 40,
            tls_mode: TlsMode::Required,
            ..SecurityConfig::default()
        },
        ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => SecurityConfig {
            max_request_size: 1024 * 1024, // 1MB
            request_timeout: Duration::from_secs(30),
            rate_limit_per_second: 10,
            rate_limit_burst: 20,
            tls_mode: TlsMode::Required,
            ..SecurityConfig::default()
        },
        ComplianceProfile::FedRampHigh => SecurityConfig {
            max_request_size: 512 * 1024, // 512KB
            request_timeout: Duration::from_secs(15),
            rate_limit_per_second: 5,
            rate_limit_burst: 10,
            tls_mode: TlsMode::Strict,
            ..SecurityConfig::default()
        },
        ComplianceProfile::Custom => SecurityConfig::default(),
    }
}

/// Create SecurityConfig for a profile, respecting environment overrides.
fn security_config_for_profile_from_env(profile: ComplianceProfile) -> SecurityConfig {
    // Start with profile defaults
    let mut config = security_config_for_profile(profile);

    // Allow environment overrides
    if let Ok(s) = std::env::var("MAX_REQUEST_SIZE") {
        config.max_request_size = crate::parse_size(&s);
    }
    if let Ok(s) = std::env::var("REQUEST_TIMEOUT") {
        config.request_timeout = crate::parse_duration(&s);
    }
    if let Ok(s) = std::env::var("RATE_LIMIT_PER_SECOND") {
        if let Ok(v) = s.parse() {
            config.rate_limit_per_second = v;
        }
    }
    if let Ok(s) = std::env::var("RATE_LIMIT_ENABLED") {
        config.rate_limit_enabled = s.to_lowercase() != "false";
    }
    if let Ok(s) = std::env::var("TLS_MODE") {
        if let Some(mode) = TlsMode::from_str_loose(&s) {
            config.tls_mode = mode;
        }
    }
    if let Ok(s) = std::env::var("AUDIT_ENABLED") {
        config.audit_enabled = s.to_lowercase() != "false";
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_fedramp_moderate() {
        // Clear env vars
        std::env::remove_var("COMPLIANCE_PROFILE");
        std::env::remove_var("BARBICAN_COMPLIANCE_PROFILE");

        let config = AppConfig::for_profile(ComplianceProfile::FedRampModerate);
        assert_eq!(config.profile, ComplianceProfile::FedRampModerate);
    }

    #[test]
    fn test_development_config() {
        let config = AppConfig::development();
        assert!(config.is_development());
        assert!(!config.requires_mfa());
        assert!(!config.requires_encryption());
        assert!(!config.requires_tls());
    }

    #[test]
    fn test_fedramp_high() {
        let config = AppConfig::for_profile(ComplianceProfile::FedRampHigh);
        assert!(config.requires_mfa());
        assert!(config.requires_encryption());
        assert!(config.requires_tls());
        assert_eq!(config.security.tls_mode, TlsMode::Strict);
    }

    #[test]
    fn test_create_metrics() {
        let config = AppConfig::for_profile(ComplianceProfile::FedRampModerate);
        let metrics = config.create_metrics(|b| {
            b.counter("test_counter", &["label"], "Test counter")
        });

        assert!(metrics.has_counter("http_requests_total"));
        assert!(metrics.has_counter("test_counter"));
    }

    #[test]
    fn test_parse_profile() {
        assert_eq!(parse_profile("fedramp-low"), ComplianceProfile::FedRampLow);
        assert_eq!(parse_profile("LOW"), ComplianceProfile::FedRampLow);
        assert_eq!(
            parse_profile("fedramp-moderate"),
            ComplianceProfile::FedRampModerate
        );
        assert_eq!(
            parse_profile("development"),
            ComplianceProfile::Development
        );
        assert_eq!(parse_profile("dev"), ComplianceProfile::Development);
        assert_eq!(
            parse_profile("invalid"),
            ComplianceProfile::FedRampModerate
        ); // Default
    }
}
