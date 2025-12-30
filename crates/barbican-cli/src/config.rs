//! Configuration parsing for barbican.toml
//!
//! This module defines the schema for barbican.toml and handles
//! parsing, validation, and default value derivation from compliance profiles.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::{CliError, Result};
use crate::profile::ComplianceProfile;

/// Root configuration structure for barbican.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarbicanConfig {
    /// Application metadata
    pub app: AppConfig,

    /// Deployment target configuration
    #[serde(default)]
    pub deployment: DeploymentConfig,

    /// Database configuration
    #[serde(default)]
    pub database: Option<DatabaseConfig>,

    /// Observability stack configuration
    #[serde(default)]
    pub observability: Option<ObservabilityConfig>,

    /// Secrets management configuration
    #[serde(default)]
    pub secrets: Option<SecretsConfig>,

    /// Network and firewall configuration
    #[serde(default)]
    pub network: Option<NetworkConfig>,

    /// Backup configuration
    #[serde(default)]
    pub backup: Option<BackupConfig>,

    /// Session management overrides
    #[serde(default)]
    pub session: Option<SessionConfig>,

    /// Authentication overrides
    #[serde(default)]
    pub auth: Option<AuthConfig>,

    /// Custom environment variables to pass through
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl BarbicanConfig {
    /// Load configuration from a file path
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| CliError::ConfigRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        Self::from_str(&content, path)
    }

    /// Parse configuration from a string
    pub fn from_str(content: &str, path: &Path) -> Result<Self> {
        toml::from_str(content).map_err(|e| CliError::ConfigParse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }

    /// Get the compliance profile
    pub fn profile(&self) -> ComplianceProfile {
        self.app.profile.parse().unwrap_or_default()
    }

    /// Resolve all default values based on the compliance profile
    pub fn resolve_defaults(&mut self) {
        let profile = self.profile();

        // Resolve database defaults
        if let Some(ref mut db) = self.database {
            db.resolve_defaults(profile);
        }

        // Resolve observability defaults
        if let Some(ref mut obs) = self.observability {
            obs.resolve_defaults(profile);
        }

        // Resolve network defaults
        if let Some(ref mut net) = self.network {
            net.resolve_defaults(profile);
        }

        // Resolve backup defaults
        if let Some(ref mut backup) = self.backup {
            backup.resolve_defaults(profile);
        }

        // Resolve session defaults
        if let Some(ref mut session) = self.session {
            session.resolve_defaults(profile);
        }

        // Resolve auth defaults
        if let Some(ref mut auth) = self.auth {
            auth.resolve_defaults(profile);
        }
    }
}

/// Application metadata configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Application name (used for service names, logging, etc.)
    pub name: String,

    /// Compliance profile: "fedramp-low", "fedramp-moderate", "fedramp-high", "soc2", "custom"
    pub profile: String,

    /// Application version (optional, defaults to "0.1.0")
    #[serde(default = "default_version")]
    pub version: String,

    /// Description for documentation
    #[serde(default)]
    pub description: Option<String>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

/// Deployment target configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentConfig {
    /// Platform: "nixos", "docker", "kubernetes"
    #[serde(default = "default_platform")]
    pub platform: String,

    /// VM type for NixOS: "microvm", "qemu", "ec2"
    #[serde(default)]
    pub vm_type: Option<String>,

    /// Output directory for generated files
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
}

fn default_platform() -> String {
    "nixos".to_string()
}

fn default_output_dir() -> String {
    "generated".to_string()
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database type: "postgres" (only postgres supported currently)
    #[serde(rename = "type", default = "default_db_type")]
    pub db_type: String,

    /// Connection URL (can use ${VAR} syntax for env vars)
    pub url: String,

    /// Connection pool size
    #[serde(default)]
    pub pool_size: Option<u32>,

    /// Statement timeout (e.g., "30s")
    #[serde(default)]
    pub statement_timeout: Option<String>,

    /// Listen address for PostgreSQL
    #[serde(default)]
    pub listen_address: Option<String>,

    /// Allowed client CIDR ranges
    #[serde(default)]
    pub allowed_clients: Option<Vec<String>>,

    /// Enable SSL/TLS (derived from profile if not set)
    #[serde(default)]
    pub enable_ssl: Option<bool>,

    /// Require client certificates (derived from profile if not set)
    #[serde(default)]
    pub enable_client_cert: Option<bool>,

    /// Enable audit logging (derived from profile if not set)
    #[serde(default)]
    pub enable_audit_log: Option<bool>,

    /// Enable pgaudit extension (derived from profile if not set)
    #[serde(default)]
    pub enable_pgaudit: Option<bool>,

    /// pgaudit log classes
    #[serde(default)]
    pub pgaudit_log_classes: Option<Vec<String>>,

    /// Maximum connections
    #[serde(default)]
    pub max_connections: Option<u32>,
}

fn default_db_type() -> String {
    "postgres".to_string()
}

impl DatabaseConfig {
    pub fn resolve_defaults(&mut self, profile: ComplianceProfile) {
        if self.listen_address.is_none() {
            self.listen_address = Some("127.0.0.1".to_string());
        }
        if self.enable_ssl.is_none() {
            self.enable_ssl = Some(true); // Always require SSL
        }
        if self.enable_client_cert.is_none() {
            self.enable_client_cert = Some(profile.requires_mtls());
        }
        if self.enable_audit_log.is_none() {
            self.enable_audit_log = Some(true); // Always enable audit
        }
        if self.enable_pgaudit.is_none() {
            self.enable_pgaudit = Some(true);
        }
        if self.pgaudit_log_classes.is_none() {
            self.pgaudit_log_classes = Some(vec![
                "write".to_string(),
                "role".to_string(),
                "ddl".to_string(),
            ]);
        }
        if self.max_connections.is_none() {
            self.max_connections = Some(50);
        }
        if self.pool_size.is_none() {
            self.pool_size = Some(10);
        }
        if self.statement_timeout.is_none() {
            self.statement_timeout = Some("30s".to_string());
        }
    }
}

/// Observability stack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Metrics provider: "prometheus", "none"
    #[serde(default)]
    pub metrics: Option<String>,

    /// Logging provider: "loki", "stdout", "none"
    #[serde(default)]
    pub logging: Option<String>,

    /// Enable distributed tracing
    #[serde(default)]
    pub tracing: Option<bool>,

    /// Log retention in days (derived from profile if not set)
    #[serde(default)]
    pub retention_days: Option<u32>,

    /// Prometheus scrape port
    #[serde(default)]
    pub metrics_port: Option<u16>,

    /// Loki endpoint
    #[serde(default)]
    pub loki_url: Option<String>,
}

impl ObservabilityConfig {
    pub fn resolve_defaults(&mut self, profile: ComplianceProfile) {
        if self.metrics.is_none() {
            self.metrics = Some("prometheus".to_string());
        }
        if self.logging.is_none() {
            self.logging = Some("loki".to_string());
        }
        if self.tracing.is_none() {
            self.tracing = Some(true);
        }
        if self.retention_days.is_none() {
            self.retention_days = Some(profile.min_retention_days());
        }
        if self.metrics_port.is_none() {
            self.metrics_port = Some(9090);
        }
    }
}

/// Secrets management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Provider: "vault", "aws-secrets-manager", "env"
    pub provider: String,

    /// Provider address (for Vault)
    #[serde(default)]
    pub address: Option<String>,

    /// Key rotation interval (derived from profile if not set)
    #[serde(default)]
    pub rotation_days: Option<u32>,

    /// PKI configuration for Vault
    #[serde(default)]
    pub pki: Option<PkiConfig>,
}

/// PKI configuration for certificate management
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PkiConfig {
    /// Root CA TTL (e.g., "87600h" for 10 years)
    #[serde(default)]
    pub root_ca_ttl: Option<String>,

    /// Intermediate CA TTL
    #[serde(default)]
    pub intermediate_ca_ttl: Option<String>,

    /// Default certificate TTL
    #[serde(default)]
    pub default_cert_ttl: Option<String>,

    /// Organization name for certificates
    #[serde(default)]
    pub organization: Option<String>,
}

/// Network and firewall configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listen address and port (e.g., "0.0.0.0:8080")
    #[serde(default)]
    pub listen: Option<String>,

    /// Allowed inbound connections
    #[serde(default)]
    pub allowed_ingress: Vec<FirewallRule>,

    /// Enable egress filtering (derived from profile if not set)
    #[serde(default)]
    pub egress_filtering: Option<bool>,

    /// Allowed outbound connections (only used if egress_filtering is true)
    #[serde(default)]
    pub allowed_egress: Vec<FirewallRule>,

    /// Log dropped packets
    #[serde(default)]
    pub log_dropped: Option<bool>,
}

impl NetworkConfig {
    pub fn resolve_defaults(&mut self, profile: ComplianceProfile) {
        if self.listen.is_none() {
            self.listen = Some("0.0.0.0:8080".to_string());
        }
        if self.egress_filtering.is_none() {
            // FedRAMP High requires egress filtering
            self.egress_filtering = Some(profile.requires_egress_filtering());
        }
        if self.log_dropped.is_none() {
            self.log_dropped = Some(true);
        }
    }
}

/// Firewall rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Port number
    pub port: u16,

    /// Source/destination CIDR or "any"
    #[serde(default = "default_any")]
    pub from: Option<String>,

    #[serde(default = "default_any")]
    pub to: Option<String>,

    /// Protocol: "tcp", "udp"
    #[serde(default = "default_tcp")]
    pub proto: String,
}

fn default_any() -> Option<String> {
    Some("any".to_string())
}

fn default_tcp() -> String {
    "tcp".to_string()
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable backups
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Backup schedule (HH:MM format)
    #[serde(default = "default_backup_schedule")]
    pub schedule: String,

    /// Local retention in days
    #[serde(default)]
    pub retention_days: Option<u32>,

    /// Enable backup encryption
    #[serde(default)]
    pub encryption: Option<bool>,

    /// Encryption key file path
    #[serde(default)]
    pub encryption_key_file: Option<String>,

    /// Enable offsite backups
    #[serde(default)]
    pub offsite: Option<bool>,

    /// Offsite destination (S3 bucket, rclone remote)
    #[serde(default)]
    pub offsite_destination: Option<String>,

    /// Offsite retention in days
    #[serde(default)]
    pub offsite_retention_days: Option<u32>,
}

fn default_true() -> bool {
    true
}

fn default_backup_schedule() -> String {
    "02:00".to_string()
}

impl BackupConfig {
    pub fn resolve_defaults(&mut self, profile: ComplianceProfile) {
        if self.retention_days.is_none() {
            self.retention_days = Some(30);
        }
        if self.encryption.is_none() {
            // Encryption required for Moderate and above
            self.encryption = Some(profile.requires_encryption_at_rest());
        }
        if self.offsite_retention_days.is_none() {
            self.offsite_retention_days = Some(90);
        }
    }
}

/// Session management configuration overrides
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionConfig {
    /// Idle timeout (e.g., "10m", "15m")
    #[serde(default)]
    pub idle_timeout: Option<String>,

    /// Absolute session timeout (e.g., "15m", "30m")
    #[serde(default)]
    pub absolute_timeout: Option<String>,
}

impl SessionConfig {
    pub fn resolve_defaults(&mut self, profile: ComplianceProfile) {
        if self.idle_timeout.is_none() {
            self.idle_timeout = Some(format!("{}m", profile.idle_timeout_minutes()));
        }
        if self.absolute_timeout.is_none() {
            self.absolute_timeout = Some(format!("{}m", profile.session_timeout_minutes()));
        }
    }
}

/// Authentication configuration overrides
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// Require MFA (derived from profile if not set)
    #[serde(default)]
    pub require_mfa: Option<bool>,

    /// Maximum login attempts before lockout
    #[serde(default)]
    pub max_login_attempts: Option<u32>,

    /// Lockout duration (e.g., "15m", "30m")
    #[serde(default)]
    pub lockout_duration: Option<String>,

    /// Minimum password length
    #[serde(default)]
    pub min_password_length: Option<usize>,

    /// Require breach database checking
    #[serde(default)]
    pub breach_checking: Option<bool>,
}

impl AuthConfig {
    pub fn resolve_defaults(&mut self, profile: ComplianceProfile) {
        if self.require_mfa.is_none() {
            self.require_mfa = Some(profile.requires_mfa());
        }
        if self.max_login_attempts.is_none() {
            self.max_login_attempts = Some(profile.max_login_attempts());
        }
        if self.lockout_duration.is_none() {
            self.lockout_duration = Some(format!("{}m", profile.lockout_duration_minutes()));
        }
        if self.min_password_length.is_none() {
            self.min_password_length = Some(profile.min_password_length());
        }
        if self.breach_checking.is_none() {
            self.breach_checking = Some(profile.requires_breach_checking());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[app]
name = "test-service"
profile = "fedramp-moderate"
"#;

        let config = BarbicanConfig::from_str(toml, Path::new("test.toml")).unwrap();
        assert_eq!(config.app.name, "test-service");
        assert_eq!(config.app.profile, "fedramp-moderate");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[app]
name = "order-service"
profile = "fedramp-high"
version = "1.0.0"

[database]
type = "postgres"
url = "${DATABASE_URL}"
pool_size = 20

[observability]
metrics = "prometheus"
logging = "loki"
tracing = true

[network]
listen = "0.0.0.0:8080"

[[network.allowed_ingress]]
port = 8080
from = "10.0.0.0/8"

[[network.allowed_egress]]
port = 443
to = "any"
"#;

        let config = BarbicanConfig::from_str(toml, Path::new("test.toml")).unwrap();
        assert_eq!(config.app.name, "order-service");
        assert_eq!(config.profile(), ComplianceProfile::FedRampHigh);
        assert!(config.database.is_some());
        assert!(config.network.is_some());
    }

    #[test]
    fn test_resolve_defaults() {
        let toml = r#"
[app]
name = "test-service"
profile = "fedramp-moderate"

[database]
type = "postgres"
url = "postgres://localhost/test"
"#;

        let mut config = BarbicanConfig::from_str(toml, Path::new("test.toml")).unwrap();
        config.resolve_defaults();

        let db = config.database.as_ref().unwrap();
        assert_eq!(db.enable_ssl, Some(true));
        assert_eq!(db.enable_client_cert, Some(false)); // Moderate doesn't require mTLS
        assert_eq!(db.enable_audit_log, Some(true));
    }
}
