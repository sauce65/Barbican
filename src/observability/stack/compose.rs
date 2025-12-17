//! Docker Compose Configuration Generation
//!
//! Generates FedRAMP-compliant Docker Compose configurations for the
//! observability stack.

use std::fs;
use std::path::Path;

use super::{ComplianceProfile, GeneratedFile, ObservabilityComplianceConfig, StackResult};

/// Docker Compose-specific configuration
#[derive(Debug, Clone, Default)]
pub struct ComposeConfig {
    /// Network name
    pub network_name: String,

    /// Use external network (don't create)
    pub external_network: bool,

    /// Volume prefix
    pub volume_prefix: String,

    /// Restart policy
    pub restart_policy: RestartPolicy,

    /// Resource limits
    pub resource_limits: ResourceLimits,

    /// Additional environment variables for services
    pub extra_env: Vec<(String, String)>,
}

/// Container restart policy
#[derive(Debug, Clone, Default)]
pub enum RestartPolicy {
    No,
    #[default]
    Always,
    OnFailure,
    UnlessStopped,
}

impl RestartPolicy {
    fn as_str(&self) -> &'static str {
        match self {
            RestartPolicy::No => "no",
            RestartPolicy::Always => "always",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::UnlessStopped => "unless-stopped",
        }
    }
}

/// Resource limits for containers
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Loki memory limit
    pub loki_memory: String,
    /// Prometheus memory limit
    pub prometheus_memory: String,
    /// Grafana memory limit
    pub grafana_memory: String,
    /// Alertmanager memory limit
    pub alertmanager_memory: String,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            loki_memory: "1g".to_string(),
            prometheus_memory: "1g".to_string(),
            grafana_memory: "512m".to_string(),
            alertmanager_memory: "256m".to_string(),
        }
    }
}

impl ComposeConfig {
    /// Set network name
    pub fn with_network(mut self, name: impl Into<String>) -> Self {
        self.network_name = name.into();
        self
    }

    /// Use external network
    pub fn with_external_network(mut self, external: bool) -> Self {
        self.external_network = external;
        self
    }

    /// Set resource limits
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    /// Add environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }
}

/// Generate Docker Compose configuration files
pub fn generate(
    output_dir: &Path,
    config: &ComposeConfig,
    fedramp: &ObservabilityComplianceConfig,
    app_name: &str,
) -> StackResult<Vec<GeneratedFile>> {
    let mut files = Vec::new();

    // Main Docker Compose file
    let compose = generate_compose(config, fedramp, app_name);
    let compose_path = output_dir.join("docker-compose.yml");
    fs::write(&compose_path, compose)?;
    files.push(
        GeneratedFile::new(&compose_path, "Docker Compose configuration")
            .with_controls(vec!["AC-6", "SC-8"])
    );

    // Environment file template
    let env_template = generate_env_template(fedramp, app_name);
    let env_path = output_dir.join(".env.example");
    fs::write(&env_path, env_template)?;
    files.push(
        GeneratedFile::new(&env_path, "Environment variables template")
            .with_controls(vec!["IA-2"])
    );

    Ok(files)
}

fn generate_compose(config: &ComposeConfig, fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    let network_name = if config.network_name.is_empty() {
        format!("{}-observability", app_name)
    } else {
        config.network_name.clone()
    };

    let volume_prefix = if config.volume_prefix.is_empty() {
        app_name.to_string()
    } else {
        config.volume_prefix.clone()
    };

    let security_opts = r#"
    security_opt:
      - no-new-privileges:true"#;

    let cap_drop = r#"
    cap_drop:
      - ALL"#;

    let read_only = if !fedramp.is_low_security() {
        "\n    read_only: true"
    } else {
        ""
    };

    let loki_tmpfs = if !fedramp.is_low_security() {
        r#"
    tmpfs:
      - /tmp:size=100M,mode=1777"#
    } else {
        ""
    };

    let network_config = if config.external_network {
        format!(
            r#"networks:
  {network_name}:
    external: true"#,
            network_name = network_name
        )
    } else {
        format!(
            r#"networks:
  {network_name}:
    driver: bridge
    ipam:
      driver: default"#,
            network_name = network_name
        )
    };

    let healthcheck_interval = match fedramp.profile() {
        ComplianceProfile::FedRampLow => "30s",
        ComplianceProfile::FedRampHigh => "10s",
        _ => "15s",
    };

    format!(
        r#"# Docker Compose - {app_name} Observability Stack
# FedRAMP {profile} Profile
# Generated by barbican observability stack
#
# Controls: AC-6 (Least Privilege), SC-8 (TLS)
#
# Usage:
#   docker-compose up -d
#
# Prerequisites:
#   1. Generate certificates: ./scripts/gen-certs.sh
#   2. Create .env file from .env.example
#   3. Set secure passwords in .env

services:
  loki:
    image: grafana/loki:2.9.2
    container_name: {app_name}-loki
    restart: {restart}{security_opts}{cap_drop}{read_only}
    user: "10001:10001"
    command: -config.file=/etc/loki/loki-config.yml
    volumes:
      - ./loki/loki-config.yml:/etc/loki/loki-config.yml:ro
      - ./loki/tenant-limits.yml:/etc/loki/tenant-limits.yml:ro
      - {volume_prefix}_loki_data:/loki/data
      - ./certs:/certs:ro{loki_tmpfs}
    ports:
      - "3100:3100"
    networks:
      - {network_name}
    healthcheck:
      test: ["CMD-SHELL", "wget -q --spider http://localhost:3100/ready || exit 1"]
      interval: {healthcheck_interval}
      timeout: 5s
      retries: 3
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: {loki_memory}

  prometheus:
    image: prom/prometheus:v2.47.2
    container_name: {app_name}-prometheus
    restart: {restart}{security_opts}{cap_drop}{read_only}
    user: "65534:65534"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time={retention}d'
      - '--storage.tsdb.retention.size={retention_size}GB'
      - '--web.config.file=/etc/prometheus/web.yml'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/web.yml:/etc/prometheus/web.yml:ro
      - ./prometheus/rules:/etc/prometheus/rules:ro
      - {volume_prefix}_prometheus_data:/prometheus
      - ./certs:/certs:ro
    ports:
      - "9090:9090"
    networks:
      - {network_name}
    healthcheck:
      test: ["CMD-SHELL", "wget -q --spider http://localhost:9090/-/ready || exit 1"]
      interval: {healthcheck_interval}
      timeout: 5s
      retries: 3
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: {prometheus_memory}

  grafana:
    image: grafana/grafana:10.2.2
    container_name: {app_name}-grafana
    restart: {restart}{security_opts}{cap_drop}
    user: "472:472"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${{GRAFANA_ADMIN_PASSWORD}}
      - GF_SECURITY_SECRET_KEY=${{GRAFANA_SECRET_KEY}}
      - GF_METRICS_BASIC_AUTH_PASSWORD=${{GRAFANA_METRICS_PASSWORD}}
      - GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=${{GRAFANA_OAUTH_CLIENT_SECRET:-}}
      - PROMETHEUS_PASSWORD=${{PROMETHEUS_PASSWORD}}
    volumes:
      - ./grafana/grafana.ini:/etc/grafana/grafana.ini:ro
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - {volume_prefix}_grafana_data:/var/lib/grafana
      - ./certs:/certs:ro
    ports:
      - "3000:3000"
    networks:
      - {network_name}
    depends_on:
      loki:
        condition: service_healthy
      prometheus:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -q --spider http://localhost:3000/api/health || exit 1"]
      interval: {healthcheck_interval}
      timeout: 5s
      retries: 3
      start_period: 60s
    deploy:
      resources:
        limits:
          memory: {grafana_memory}

  alertmanager:
    image: prom/alertmanager:v0.26.0
    container_name: {app_name}-alertmanager
    restart: {restart}{security_opts}{cap_drop}{read_only}
    user: "65534:65534"
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.config.file=/etc/alertmanager/web.yml'
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - ./alertmanager/web.yml:/etc/alertmanager/web.yml:ro
      - {volume_prefix}_alertmanager_data:/alertmanager
      - ./certs:/certs:ro
    ports:
      - "9093:9093"
    networks:
      - {network_name}
    healthcheck:
      test: ["CMD-SHELL", "wget -q --spider http://localhost:9093/-/ready || exit 1"]
      interval: {healthcheck_interval}
      timeout: 5s
      retries: 3
      start_period: 15s
    deploy:
      resources:
        limits:
          memory: {alertmanager_memory}

volumes:
  {volume_prefix}_loki_data:
  {volume_prefix}_prometheus_data:
  {volume_prefix}_grafana_data:
  {volume_prefix}_alertmanager_data:

{network_config}
"#,
        app_name = app_name,
        profile = fedramp.profile().name(),
        restart = config.restart_policy.as_str(),
        security_opts = security_opts,
        cap_drop = cap_drop,
        read_only = read_only,
        loki_tmpfs = loki_tmpfs,
        volume_prefix = volume_prefix,
        network_name = network_name,
        healthcheck_interval = healthcheck_interval,
        retention = fedramp.retention_days(),
        retention_size = match fedramp.profile() {
            ComplianceProfile::FedRampLow => 10,
            ComplianceProfile::FedRampHigh => 200,
            _ => 50,
        },
        loki_memory = config.resource_limits.loki_memory,
        prometheus_memory = config.resource_limits.prometheus_memory,
        grafana_memory = config.resource_limits.grafana_memory,
        alertmanager_memory = config.resource_limits.alertmanager_memory,
        network_config = network_config,
    )
}

fn generate_env_template(fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    format!(
        r#"# Environment Variables - {app_name} Observability Stack
# FedRAMP {profile} Profile
#
# IMPORTANT: Copy this file to .env and set secure values
# Do NOT commit .env to version control
#
# Control: IA-2 (Identification and Authentication)

# Grafana admin password (CHANGE THIS!)
# Generate with: openssl rand -base64 32
GRAFANA_ADMIN_PASSWORD=CHANGE_ME_INSECURE

# Grafana secret key for signing cookies
# Generate with: openssl rand -base64 32
GRAFANA_SECRET_KEY=CHANGE_ME_INSECURE

# Grafana metrics endpoint password
# Generate with: openssl rand -base64 32
GRAFANA_METRICS_PASSWORD=CHANGE_ME_INSECURE

# Prometheus basic auth password
# Generate with: openssl rand -base64 32
# Then hash with: htpasswd -nBC 10 "" | tr -d ':\n'
PROMETHEUS_PASSWORD=CHANGE_ME_INSECURE

# Backup encryption password (if using encrypted backups)
# Generate with: openssl rand -base64 32
BACKUP_ENCRYPTION_KEY=CHANGE_ME_INSECURE

# OAuth client secret for Grafana SSO (if using SSO)
# Obtain from your OAuth provider
GRAFANA_OAUTH_CLIENT_SECRET=

# Loki tenant ID for multi-tenant mode
LOKI_TENANT_ID={tenant_id}
"#,
        app_name = app_name,
        profile = fedramp.profile().name(),
        tenant_id = fedramp.tenant_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ComposeConfig::default();
        assert!(config.network_name.is_empty());
        assert!(!config.external_network);
    }

    #[test]
    fn test_config_builder() {
        let config = ComposeConfig::default()
            .with_network("my-network")
            .with_external_network(true)
            .with_env("MY_VAR", "my_value");

        assert_eq!(config.network_name, "my-network");
        assert!(config.external_network);
        assert_eq!(config.extra_env.len(), 1);
    }
}
