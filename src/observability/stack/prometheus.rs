//! Prometheus Configuration Generation
//!
//! Generates FedRAMP-compliant Prometheus configuration files.

use std::path::Path;
use std::fs;

use super::{StackResult, GeneratedFile, FedRampConfig, FedRampProfile};

/// Prometheus-specific configuration
#[derive(Debug, Clone)]
pub struct PrometheusConfig {
    /// HTTP listen port
    pub http_port: u16,

    /// Scrape interval
    pub scrape_interval_secs: u32,

    /// Evaluation interval for rules
    pub evaluation_interval_secs: u32,

    /// Storage retention time (days)
    pub retention_days: u32,

    /// Storage retention size (GB)
    pub retention_size_gb: u32,

    /// Enable basic authentication
    pub basic_auth_enabled: bool,

    /// Basic auth username
    pub basic_auth_user: String,

    /// Basic auth password hash (bcrypt)
    pub basic_auth_password_hash: Option<String>,

    /// Additional scrape targets
    pub additional_targets: Vec<ScrapeTarget>,
}

/// A Prometheus scrape target
#[derive(Debug, Clone)]
pub struct ScrapeTarget {
    /// Job name
    pub job_name: String,
    /// Target addresses
    pub targets: Vec<String>,
    /// Metrics path
    pub metrics_path: String,
    /// Scrape interval override
    pub scrape_interval_secs: Option<u32>,
}

impl PrometheusConfig {
    /// Create default configuration for a FedRAMP profile
    pub fn default_for_profile(profile: &FedRampProfile) -> Self {
        match profile {
            FedRampProfile::Low => Self {
                http_port: 9090,
                scrape_interval_secs: 30,
                evaluation_interval_secs: 30,
                retention_days: 30,
                retention_size_gb: 10,
                basic_auth_enabled: false,
                basic_auth_user: "admin".to_string(),
                basic_auth_password_hash: None,
                additional_targets: Vec::new(),
            },
            FedRampProfile::Moderate => Self {
                http_port: 9090,
                scrape_interval_secs: 15,
                evaluation_interval_secs: 15,
                retention_days: 90,
                retention_size_gb: 50,
                basic_auth_enabled: true,
                basic_auth_user: "admin".to_string(),
                basic_auth_password_hash: None,
                additional_targets: Vec::new(),
            },
            FedRampProfile::High => Self {
                http_port: 9090,
                scrape_interval_secs: 10,
                evaluation_interval_secs: 10,
                retention_days: 365,
                retention_size_gb: 200,
                basic_auth_enabled: true,
                basic_auth_user: "admin".to_string(),
                basic_auth_password_hash: None,
                additional_targets: Vec::new(),
            },
        }
    }

    /// Set HTTP port
    pub fn with_http_port(mut self, port: u16) -> Self {
        self.http_port = port;
        self
    }

    /// Set basic auth credentials
    pub fn with_basic_auth(mut self, user: impl Into<String>, password_hash: impl Into<String>) -> Self {
        self.basic_auth_enabled = true;
        self.basic_auth_user = user.into();
        self.basic_auth_password_hash = Some(password_hash.into());
        self
    }

    /// Add a scrape target
    pub fn with_target(mut self, target: ScrapeTarget) -> Self {
        self.additional_targets.push(target);
        self
    }
}

/// Generate Prometheus configuration files
pub fn generate(
    output_dir: &Path,
    config: &PrometheusConfig,
    fedramp: &FedRampConfig,
    app_name: &str,
    app_port: u16,
) -> StackResult<Vec<GeneratedFile>> {
    let mut files = Vec::new();
    let prom_dir = output_dir.join("prometheus");

    // Main Prometheus configuration
    let prom_config = generate_prometheus_config(config, fedramp, app_name, app_port);
    let config_path = prom_dir.join("prometheus.yml");
    fs::write(&config_path, prom_config)?;
    files.push(
        GeneratedFile::new(&config_path, "Prometheus server configuration")
            .with_controls(vec!["SI-4", "AU-6"])
    );

    // Web configuration (TLS + auth)
    if fedramp.tls_enabled || config.basic_auth_enabled {
        let web_config = generate_web_config(config, fedramp);
        let web_path = prom_dir.join("web.yml");
        fs::write(&web_path, web_config)?;
        files.push(
            GeneratedFile::new(&web_path, "Prometheus web/TLS configuration")
                .with_controls(vec!["SC-8", "IA-2"])
        );
    }

    Ok(files)
}

fn generate_prometheus_config(
    config: &PrometheusConfig,
    fedramp: &FedRampConfig,
    app_name: &str,
    app_port: u16,
) -> String {
    let scheme = if fedramp.tls_enabled { "https" } else { "http" };

    let tls_config = if fedramp.tls_enabled {
        format!(
            r#"
    tls_config:
      ca_file: /certs/ca.crt
      cert_file: /certs/prometheus/client.crt
      key_file: /certs/prometheus/client.key
      insecure_skip_verify: false"#
        )
    } else {
        String::new()
    };

    let mut scrape_configs = format!(
        r#"  # Application metrics
  - job_name: '{app_name}'
    static_configs:
      - targets: ['{app_name}:{app_port}']
    scheme: {scheme}{tls_config}
    scrape_interval: {interval}s
    metrics_path: /metrics

  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:{prom_port}']
    scrape_interval: {interval}s

  # Loki metrics
  - job_name: 'loki'
    static_configs:
      - targets: ['loki:3100']
    scheme: {scheme}{tls_config}
    scrape_interval: {interval}s
    metrics_path: /metrics

  # Grafana metrics
  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']
    scheme: {scheme}{tls_config}
    scrape_interval: {interval}s
    metrics_path: /metrics
"#,
        app_name = app_name,
        app_port = app_port,
        scheme = scheme,
        tls_config = tls_config,
        interval = config.scrape_interval_secs,
        prom_port = config.http_port,
    );

    // Add additional targets
    for target in &config.additional_targets {
        let target_interval = target.scrape_interval_secs.unwrap_or(config.scrape_interval_secs);
        scrape_configs.push_str(&format!(
            r#"
  - job_name: '{job_name}'
    static_configs:
      - targets: [{targets}]
    scheme: {scheme}{tls_config}
    scrape_interval: {interval}s
    metrics_path: {metrics_path}
"#,
            job_name = target.job_name,
            targets = target.targets.iter()
                .map(|t| format!("'{}'", t))
                .collect::<Vec<_>>()
                .join(", "),
            scheme = scheme,
            tls_config = tls_config,
            interval = target_interval,
            metrics_path = target.metrics_path,
        ));
    }

    format!(
        r#"# Prometheus Configuration - FedRAMP {profile} Profile
# Generated by barbican observability stack
# Controls: SI-4 (Monitoring), AU-6 (Audit Analysis)

global:
  scrape_interval: {scrape_interval}s
  evaluation_interval: {eval_interval}s
  external_labels:
    monitor: '{app_name}-observability'
    environment: 'production'
    fedramp_profile: '{profile}'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093
      scheme: {scheme}{tls_config}

# Load rules
rule_files:
  - /etc/prometheus/rules/*.yml

# Scrape configurations
scrape_configs:
{scrape_configs}
"#,
        profile = fedramp.profile.name(),
        scrape_interval = config.scrape_interval_secs,
        eval_interval = config.evaluation_interval_secs,
        app_name = app_name,
        scheme = scheme,
        tls_config = if fedramp.tls_enabled {
            format!(
                r#"
      tls_config:
        ca_file: /certs/ca.crt"#
            )
        } else {
            String::new()
        },
        scrape_configs = scrape_configs,
    )
}

fn generate_web_config(config: &PrometheusConfig, fedramp: &FedRampConfig) -> String {
    let tls_section = if fedramp.tls_enabled {
        r#"tls_server_config:
  cert_file: /certs/prometheus/server.crt
  key_file: /certs/prometheus/server.key
  client_ca_file: /certs/ca.crt
  client_auth_type: RequestClientCert
  min_version: TLS12
  cipher_suites:
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

"#
    } else {
        ""
    };

    let auth_section = if config.basic_auth_enabled {
        let password_hash = config.basic_auth_password_hash.as_deref()
            .unwrap_or("$2y$10$PLACEHOLDER_HASH_REPLACE_ME");
        format!(
            r#"basic_auth_users:
  # Generate hash with: htpasswd -nBC 10 "" | tr -d ':\n'
  {user}: '{hash}'
"#,
            user = config.basic_auth_user,
            hash = password_hash,
        )
    } else {
        String::new()
    };

    format!(
        r#"# Prometheus Web Configuration - FedRAMP {profile} Profile
# Controls: SC-8 (TLS), IA-2 (Authentication)

{tls_section}{auth_section}"#,
        profile = fedramp.profile.name(),
        tls_section = tls_section,
        auth_section = auth_section,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_moderate() {
        let config = PrometheusConfig::default_for_profile(&FedRampProfile::Moderate);
        assert!(config.basic_auth_enabled);
        assert_eq!(config.retention_days, 90);
    }

    #[test]
    fn test_config_with_target() {
        let config = PrometheusConfig::default_for_profile(&FedRampProfile::Moderate)
            .with_target(ScrapeTarget {
                job_name: "custom".to_string(),
                targets: vec!["custom-app:8080".to_string()],
                metrics_path: "/metrics".to_string(),
                scrape_interval_secs: Some(30),
            });

        assert_eq!(config.additional_targets.len(), 1);
    }
}
