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

    // Development mode uses host networking for Prometheus and Grafana
    // to allow them to scrape localhost services (app running on host)
    let is_dev = fedramp.is_development();

    // Pre-compute network strings to avoid temporary borrow issues
    let prometheus_networks_str = format!("\n    networks:\n      - {}", network_name);
    let grafana_networks_str = format!("\n    networks:\n      - {}", network_name);

    // Skip all security hardening in Development mode
    let (security_opts, cap_drop, read_only, loki_tmpfs, loki_user, prometheus_user, grafana_user, alertmanager_user) =
        if is_dev {
            // Development mode: no security hardening, containers run as default users
            ("", "", "", "", "", "", "", "")
        } else {
            (
                "\n    security_opt:\n      - no-new-privileges:true",
                "\n    cap_drop:\n      - ALL",
                if !fedramp.is_low_security() { "\n    read_only: true" } else { "" },
                if !fedramp.is_low_security() { "\n    tmpfs:\n      - /tmp:size=100M,mode=1777" } else { "" },
                "\n    user: \"10001:10001\"",
                "\n    user: \"65534:65534\"",
                "\n    user: \"472:472\"",
                "\n    user: \"65534:65534\"",
            )
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
  # Init containers to set up volume permissions
  # These run once and exit, allowing main services to start with correct ownership
  loki-init:
    image: alpine:3.19
    container_name: {app_name}-loki-init
    command: sh -c "mkdir -p /data/chunks /data/rules /data/tsdb-index /data/tsdb-cache /data/compactor && chown -R 10001:10001 /data"
    volumes:
      - {volume_prefix}_loki_data:/data
    user: root
    restart: "no"

  prometheus-init:
    image: alpine:3.19
    container_name: {app_name}-prometheus-init
    command: sh -c "chown -R 65534:65534 /data"
    volumes:
      - {volume_prefix}_prometheus_data:/data
    user: root
    restart: "no"

  grafana-init:
    image: alpine:3.19
    container_name: {app_name}-grafana-init
    command: sh -c "chown -R 472:472 /data"
    volumes:
      - {volume_prefix}_grafana_data:/data
    user: root
    restart: "no"

  alertmanager-init:
    image: alpine:3.19
    container_name: {app_name}-alertmanager-init
    command: sh -c "chown -R 65534:65534 /data"
    volumes:
      - {volume_prefix}_alertmanager_data:/data
    user: root
    restart: "no"

  loki:
    image: grafana/loki:2.9.2
    container_name: {app_name}-loki
    restart: {restart}{security_opts}{cap_drop}{read_only}{loki_user}
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
    depends_on:
      loki-init:
        condition: service_completed_successfully
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
    restart: {restart}{prometheus_network_mode}{security_opts}{cap_drop}{read_only}{prometheus_user}
    depends_on:
      prometheus-init:
        condition: service_completed_successfully
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
      - ./certs:/certs:ro{prometheus_ports}{prometheus_networks}
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
    restart: {restart}{grafana_network_mode}{security_opts}{cap_drop}{grafana_user}
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
      - ./certs:/certs:ro{grafana_ports}{grafana_networks}
    depends_on:
      grafana-init:
        condition: service_completed_successfully{grafana_depends}
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
    restart: {restart}{security_opts}{cap_drop}{read_only}{alertmanager_user}
    depends_on:
      alertmanager-init:
        condition: service_completed_successfully
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
        loki_user = loki_user,
        prometheus_user = prometheus_user,
        grafana_user = grafana_user,
        alertmanager_user = alertmanager_user,
        volume_prefix = volume_prefix,
        network_name = network_name,
        healthcheck_interval = healthcheck_interval,
        retention = fedramp.retention_days(),
        retention_size = match fedramp.profile() {
            ComplianceProfile::FedRampLow | ComplianceProfile::Development => 10,
            ComplianceProfile::FedRampHigh => 200,
            _ => 50,
        },
        loki_memory = config.resource_limits.loki_memory,
        prometheus_memory = config.resource_limits.prometheus_memory,
        grafana_memory = config.resource_limits.grafana_memory,
        alertmanager_memory = config.resource_limits.alertmanager_memory,
        network_config = network_config,
        // Development mode: use host networking for Prometheus and Grafana
        prometheus_network_mode = if is_dev { "\n    network_mode: host" } else { "" },
        prometheus_ports = if is_dev { "" } else { "\n    ports:\n      - \"9090:9090\"" },
        prometheus_networks = if is_dev { "" } else { prometheus_networks_str.as_str() },
        grafana_network_mode = if is_dev { "\n    network_mode: host" } else { "" },
        grafana_ports = if is_dev { "" } else { "\n    ports:\n      - \"3000:3000\"" },
        grafana_networks = if is_dev { "" } else { grafana_networks_str.as_str() },
        grafana_depends = if is_dev { "" } else { "\n      loki:\n        condition: service_healthy\n      prometheus:\n        condition: service_healthy" },
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
