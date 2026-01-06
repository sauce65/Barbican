//! Loki Configuration Generation
//!
//! Generates FedRAMP-compliant Loki configuration files.

use std::fs;
use std::path::Path;

use super::{ComplianceProfile, GeneratedFile, ObservabilityComplianceConfig, StackResult};

/// Loki-specific configuration
#[derive(Debug, Clone)]
pub struct LokiConfig {
    /// HTTP listen port
    pub http_port: u16,

    /// gRPC listen port
    pub grpc_port: u16,

    /// Storage path for chunks and indexes
    pub storage_path: String,

    /// Enable authentication
    pub auth_enabled: bool,

    /// Maximum streams per user
    pub max_streams_per_user: u32,

    /// Maximum entries per query
    pub max_entries_limit: u32,

    /// Ingestion rate limit (MB/s)
    pub ingestion_rate_mb: u32,

    /// Ingestion burst size (MB)
    pub ingestion_burst_mb: u32,

    /// Per-stream rate limit (MB/s)
    pub per_stream_rate_mb: u32,

    /// Reject old samples (hours)
    pub reject_old_samples_max_age_hours: u32,

    /// Enable structured metadata
    pub structured_metadata_enabled: bool,
}

impl LokiConfig {
    /// Create default configuration for a compliance profile
    pub fn default_for_profile(profile: ComplianceProfile) -> Self {
        match profile {
            ComplianceProfile::FedRampLow | ComplianceProfile::Development => Self {
                http_port: 3100,
                grpc_port: 9096,
                storage_path: "/loki/data".to_string(),
                auth_enabled: false,
                max_streams_per_user: 5000,
                max_entries_limit: 5000,
                ingestion_rate_mb: 8,
                ingestion_burst_mb: 16,
                per_stream_rate_mb: 4,
                reject_old_samples_max_age_hours: 168, // 7 days
                structured_metadata_enabled: true,
            },
            ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 | ComplianceProfile::Custom => Self {
                http_port: 3100,
                grpc_port: 9096,
                storage_path: "/loki/data".to_string(),
                auth_enabled: true, // Required for AU-9
                max_streams_per_user: 10000,
                max_entries_limit: 10000,
                ingestion_rate_mb: 16,
                ingestion_burst_mb: 32,
                per_stream_rate_mb: 8,
                reject_old_samples_max_age_hours: 168,
                structured_metadata_enabled: true,
            },
            ComplianceProfile::FedRampHigh => Self {
                http_port: 3100,
                grpc_port: 9096,
                storage_path: "/loki/data".to_string(),
                auth_enabled: true,
                max_streams_per_user: 20000,
                max_entries_limit: 20000,
                ingestion_rate_mb: 32,
                ingestion_burst_mb: 64,
                per_stream_rate_mb: 16,
                reject_old_samples_max_age_hours: 72, // Stricter for High
                structured_metadata_enabled: true,
            },
        }
    }

    /// Set the storage path
    pub fn with_storage_path(mut self, path: impl Into<String>) -> Self {
        self.storage_path = path.into();
        self
    }

    /// Set HTTP port
    pub fn with_http_port(mut self, port: u16) -> Self {
        self.http_port = port;
        self
    }

    /// Enable or disable authentication
    pub fn with_auth(mut self, enabled: bool) -> Self {
        self.auth_enabled = enabled;
        self
    }
}

/// Generate Loki configuration files
pub fn generate(
    output_dir: &Path,
    config: &LokiConfig,
    fedramp: &ObservabilityComplianceConfig,
    app_name: &str,
) -> StackResult<Vec<GeneratedFile>> {
    let mut files = Vec::new();
    let loki_dir = output_dir.join("loki");

    // Main Loki configuration
    let loki_config = generate_loki_config(config, fedramp);
    let config_path = loki_dir.join("loki-config.yml");
    fs::write(&config_path, loki_config)?;
    files.push(
        GeneratedFile::new(&config_path, "Loki server configuration")
            .with_controls(vec!["AU-2", "AU-4", "AU-9", "AU-11"]),
    );

    // Tenant limits configuration (for multi-tenant mode)
    if fedramp.tenant_isolation() {
        let tenant_limits = generate_tenant_limits(config, fedramp, app_name);
        let limits_path = loki_dir.join("tenant-limits.yml");
        fs::write(&limits_path, tenant_limits)?;
        files.push(
            GeneratedFile::new(&limits_path, "Per-tenant rate limits and quotas")
                .with_controls(vec!["AU-9", "AC-3"]),
        );
    }

    Ok(files)
}

fn generate_loki_config(config: &LokiConfig, fedramp: &ObservabilityComplianceConfig) -> String {
    let tls_config = if fedramp.tls_enabled() {
        r#"
  http_tls_config:
    cert_file: /certs/loki/server.crt
    key_file: /certs/loki/server.key
    client_ca_file: /certs/ca.crt
    client_auth_type: RequestClientCert

  grpc_tls_config:
    cert_file: /certs/loki/server.crt
    key_file: /certs/loki/server.key
    client_ca_file: /certs/ca.crt
    client_auth_type: RequestClientCert"#
    } else {
        ""
    };

    let runtime_config = if fedramp.tenant_isolation() {
        "\nruntime_config:\n  file: /etc/loki/tenant-limits.yml"
    } else {
        ""
    };

    format!(
        r#"# Loki Configuration - FedRAMP {profile} Profile
# Generated by barbican observability stack
# Controls: AU-2, AU-4, AU-9, AU-11

auth_enabled: {auth_enabled}

server:
  http_listen_port: {http_port}
  grpc_listen_port: {grpc_port}
  log_level: info
  grpc_server_max_recv_msg_size: 104857600
  grpc_server_max_send_msg_size: 104857600{tls_config}
{runtime_config}

common:
  instance_addr: 127.0.0.1
  path_prefix: {storage_path}
  storage:
    filesystem:
      chunks_directory: {storage_path}/chunks
      rules_directory: {storage_path}/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

storage_config:
  filesystem:
    directory: {storage_path}/chunks
  tsdb_shipper:
    active_index_directory: {storage_path}/tsdb-index
    cache_location: {storage_path}/tsdb-cache

limits_config:
  retention_period: {retention}d
  reject_old_samples: true
  reject_old_samples_max_age: {reject_old_samples_max_age}h
  max_query_parallelism: 32
  max_streams_per_user: {max_streams}
  max_entries_limit_per_query: {max_entries}
  ingestion_rate_mb: {ingestion_rate}
  ingestion_burst_size_mb: {ingestion_burst}
  per_stream_rate_limit: {per_stream_rate}MB
  per_stream_rate_limit_burst: {per_stream_burst}MB
  allow_structured_metadata: {structured_metadata}

compactor:
  working_directory: {storage_path}/compactor
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 150
  delete_request_store: filesystem

analytics:
  reporting_enabled: false
"#,
        profile = fedramp.profile().name(),
        auth_enabled = config.auth_enabled,
        http_port = config.http_port,
        grpc_port = config.grpc_port,
        tls_config = tls_config,
        runtime_config = runtime_config,
        storage_path = config.storage_path,
        retention = fedramp.retention_days(),
        reject_old_samples_max_age = config.reject_old_samples_max_age_hours,
        max_streams = config.max_streams_per_user,
        max_entries = config.max_entries_limit,
        ingestion_rate = config.ingestion_rate_mb,
        ingestion_burst = config.ingestion_burst_mb,
        per_stream_rate = config.per_stream_rate_mb,
        per_stream_burst = config.per_stream_rate_mb * 2,
        structured_metadata = config.structured_metadata_enabled,
    )
}

fn generate_tenant_limits(
    config: &LokiConfig,
    fedramp: &ObservabilityComplianceConfig,
    _app_name: &str,
) -> String {
    // Calculate tenant-specific limits (can be customized per tenant)
    let tenant_streams = config.max_streams_per_user;
    let tenant_ingestion_rate = config.ingestion_rate_mb;
    let tenant_burst = config.ingestion_burst_mb;

    format!(
        r#"# Per-Tenant Limits - FedRAMP {profile} Profile
# Controls: AU-9 (Audit Protection), AC-3 (Access Enforcement)
#
# Add additional tenants as needed. Each tenant is isolated
# and cannot access other tenants' logs.

overrides:
  # Primary application tenant
  {tenant_id}:
    max_streams_per_user: {tenant_streams}
    ingestion_rate_mb: {tenant_ingestion_rate}
    ingestion_burst_size_mb: {tenant_burst}
    retention_period: {retention}d

  # System tenant for infrastructure logs
  system:
    max_streams_per_user: {system_streams}
    ingestion_rate_mb: {system_rate}
    ingestion_burst_size_mb: {system_burst}
    retention_period: {retention}d

  # Security tenant for audit logs (higher retention for compliance)
  security:
    max_streams_per_user: {security_streams}
    ingestion_rate_mb: {security_rate}
    ingestion_burst_size_mb: {security_burst}
    retention_period: {security_retention}d

# Note: Tenants are identified by the X-Scope-OrgID header.
# Application should send logs with:
#   X-Scope-OrgID: {tenant_id}
#
# Example with tracing-loki:
#   LOKI_TENANT_ID={tenant_id}
"#,
        profile = fedramp.profile().name(),
        tenant_id = fedramp.tenant_id,
        tenant_streams = tenant_streams,
        tenant_ingestion_rate = tenant_ingestion_rate,
        tenant_burst = tenant_burst,
        retention = fedramp.retention_days(),
        system_streams = tenant_streams / 2,
        system_rate = tenant_ingestion_rate / 2,
        system_burst = tenant_burst / 2,
        security_streams = tenant_streams,
        security_rate = tenant_ingestion_rate,
        security_burst = tenant_burst,
        // Security logs get longer retention for High profile
        security_retention = if matches!(fedramp.profile(), ComplianceProfile::FedRampHigh) {
            fedramp.retention_days() * 2
        } else {
            fedramp.retention_days()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_moderate() {
        let config = LokiConfig::default_for_profile(ComplianceProfile::FedRampModerate);
        assert!(config.auth_enabled);
        assert_eq!(config.http_port, 3100);
    }

    #[test]
    fn test_config_builder() {
        let config = LokiConfig::default_for_profile(ComplianceProfile::FedRampModerate)
            .with_http_port(3200)
            .with_storage_path("/data/loki");

        assert_eq!(config.http_port, 3200);
        assert_eq!(config.storage_path, "/data/loki");
    }
}
