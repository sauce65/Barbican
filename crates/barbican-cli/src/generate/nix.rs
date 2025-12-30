//! Nix configuration generator
//!
//! Generates NixOS module configuration from barbican.toml

use crate::config::BarbicanConfig;
use crate::error::Result;
use crate::profile::ComplianceProfile;

use super::GeneratedFile;

/// Generate all Nix configuration files
pub fn generate(config: &BarbicanConfig) -> Result<Vec<GeneratedFile>> {
    let mut files = Vec::new();

    // Main barbican.nix configuration
    files.push(generate_main_config(config)?);

    Ok(files)
}

/// Generate the main barbican.nix file
fn generate_main_config(config: &BarbicanConfig) -> Result<GeneratedFile> {
    let profile = config.profile();
    let app_name = &config.app.name;
    let snake_name = to_snake_case(app_name);

    let mut nix = String::new();

    // Header
    // NOTE: The consuming flake.nix must import barbican.nixosModules.all
    // This generated file only contains the configuration values, not imports
    nix.push_str(&format!(
        r#"# AUTO-GENERATED FROM barbican.toml - DO NOT EDIT
# Regenerate with: barbican generate nix
# Profile: {}
# Generated: {}
#
# USAGE: Your flake.nix must import barbican's NixOS modules:
#   modules = [
#     barbican.nixosModules.all      # Provides the barbican.* options
#     ./nix/generated/barbican.nix   # This file (configuration values)
#   ];
{{ config, lib, pkgs, ... }}:

{{
"#,
        profile.name(),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Generate database configuration
    if let Some(ref db) = config.database {
        nix.push_str(&generate_postgres_config(db, &snake_name, profile));
    }

    // Generate firewall configuration
    if let Some(ref network) = config.network {
        nix.push_str(&generate_firewall_config(network, profile));
    }

    // Generate kernel hardening
    nix.push_str(&generate_kernel_hardening(profile));

    // Generate intrusion detection
    nix.push_str(&generate_intrusion_detection(profile));

    // Generate backup configuration
    if let Some(ref backup) = config.backup {
        if config.database.is_some() {
            nix.push_str(&generate_backup_config(backup, &snake_name, profile));
        }
    }

    // Generate resource limits
    nix.push_str(&generate_resource_limits(profile));

    // Generate Vault PKI if configured
    if let Some(ref secrets) = config.secrets {
        if secrets.provider == "vault" {
            nix.push_str(&generate_vault_config(secrets, profile));
        }
    }

    // Generate systemd service for the application
    nix.push_str(&generate_systemd_service(config, &snake_name));

    // Close the module
    nix.push_str("}\n");

    Ok(GeneratedFile::new("nix/generated/barbican.nix", nix))
}

fn generate_postgres_config(
    db: &crate::config::DatabaseConfig,
    app_name: &str,
    profile: ComplianceProfile,
) -> String {
    let listen_addr = db.listen_address.as_deref().unwrap_or("127.0.0.1");
    let enable_ssl = db.enable_ssl.unwrap_or(true);
    let enable_client_cert = db.enable_client_cert.unwrap_or(profile.requires_mtls());
    let enable_audit = db.enable_audit_log.unwrap_or(true);
    let enable_pgaudit = db.enable_pgaudit.unwrap_or(true);
    let max_connections = db.max_connections.unwrap_or(50);

    let pgaudit_classes = db
        .pgaudit_log_classes
        .as_ref()
        .map(|v| v.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "\"write\" \"role\" \"ddl\"".to_string());

    let allowed_clients = db
        .allowed_clients
        .as_ref()
        .filter(|v| !v.is_empty())
        .map(|v| v.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();

    format!(
        r#"
  # Database Configuration (SC-8, AU-2, IA-5)
  # Derived from profile: {}
  barbican.securePostgres = {{
    enable = true;
    listenAddress = "{}";
    allowedClients = [ {} ];
    database = "{}";
    username = "{}";
    passwordFile = config.age.secrets.db-password.path;

    # Transport Security (SC-8)
    enableSSL = {};
    enableClientCert = {};  # mTLS: {} for {}

    # Audit Logging (AU-2, AU-9)
    enableAuditLog = {};
    enablePgaudit = {};
    pgauditLogClasses = [ {} ];
    logFileMode = "0600";

    # Connection Limits
    maxConnections = {};

    # Process Isolation (SC-39)
    enableProcessIsolation = true;
  }};
"#,
        profile.name(),
        listen_addr,
        allowed_clients,
        app_name,
        app_name,
        enable_ssl,
        enable_client_cert,
        if profile.requires_mtls() { "required" } else { "not required" },
        profile.name(),
        enable_audit,
        enable_pgaudit,
        pgaudit_classes,
        max_connections,
    )
}

fn generate_firewall_config(network: &crate::config::NetworkConfig, profile: ComplianceProfile) -> String {
    let egress_filtering = network.egress_filtering.unwrap_or(profile.requires_egress_filtering());
    let log_dropped = network.log_dropped.unwrap_or(true);

    let mut ingress_rules = String::new();
    for rule in &network.allowed_ingress {
        let from = rule.from.as_deref().unwrap_or("any");
        ingress_rules.push_str(&format!(
            "    {{ port = {}; from = \"{}\"; proto = \"{}\"; }}\n",
            rule.port, from, rule.proto
        ));
    }

    let mut egress_rules = String::new();
    for rule in &network.allowed_egress {
        let to = rule.to.as_deref().unwrap_or("any");
        egress_rules.push_str(&format!(
            "    {{ port = {}; to = \"{}\"; proto = \"{}\"; }}\n",
            rule.port, to, rule.proto
        ));
    }

    format!(
        r#"
  # Firewall Configuration (SC-7, SC-7(5))
  barbican.vmFirewall = {{
    enable = true;
    defaultPolicy = "drop";

    allowedInbound = [
{}    ];

    # Egress Filtering: {} for {}
    enableEgressFiltering = {};
    allowedOutbound = [
{}    ];

    logDropped = {};
  }};
"#,
        ingress_rules,
        if profile.requires_egress_filtering() { "required" } else { "recommended" },
        profile.name(),
        egress_filtering,
        egress_rules,
        log_dropped,
    )
}

fn generate_kernel_hardening(profile: ComplianceProfile) -> String {
    format!(
        r#"
  # Kernel Hardening (SI-16)
  barbican.kernelHardening = {{
    enable = true;
    enableNetworkHardening = true;
    enableMemoryProtection = true;
    enableProcessRestrictions = true;
    enableAudit = true;
  }};
"#
    )
}

fn generate_intrusion_detection(profile: ComplianceProfile) -> String {
    format!(
        r#"
  # Intrusion Detection (SI-4, SI-7)
  barbican.intrusionDetection = {{
    enable = true;
    enableAIDE = true;
    enableAuditd = true;
  }};
"#
    )
}

fn generate_backup_config(
    backup: &crate::config::BackupConfig,
    app_name: &str,
    profile: ComplianceProfile,
) -> String {
    let retention = backup.retention_days.unwrap_or(30);
    let encryption = backup.encryption.unwrap_or(profile.requires_encryption_at_rest());

    let mut config = format!(
        r#"
  # Database Backup (CP-9)
  barbican.databaseBackup = {{
    enable = {};
    schedule = "{}";
    retentionDays = {};
    databases = [ "{}" ];

    # Encryption (SC-28)
    enableEncryption = {};
"#,
        backup.enabled,
        backup.schedule,
        retention,
        app_name,
        encryption,
    );

    if let Some(ref key_file) = backup.encryption_key_file {
        config.push_str(&format!("    encryptionKeyFile = {};\n", key_file));
    }

    if backup.offsite.unwrap_or(false) {
        config.push_str(&format!(
            r#"
    # Offsite Backup (MP-5)
    enableOffsiteBackup = true;
    offsiteBucket = "{}";
    offsiteRetentionDays = {};
"#,
            backup.offsite_destination.as_deref().unwrap_or("# Configure in barbican.toml"),
            backup.offsite_retention_days.unwrap_or(90),
        ));
    }

    config.push_str("  };\n");
    config
}

fn generate_resource_limits(profile: ComplianceProfile) -> String {
    format!(
        r#"
  # Resource Limits (SC-5, SC-6)
  barbican.resourceLimits = {{
    enable = true;
    defaultMemoryMax = "1G";
    defaultCPUQuota = "100%";
    limitCoredump = true;
  }};
"#
    )
}

fn generate_vault_config(secrets: &crate::config::SecretsConfig, profile: ComplianceProfile) -> String {
    let address = secrets.address.as_deref().unwrap_or("http://127.0.0.1:8200");

    format!(
        r#"
  # Vault PKI (SC-12, SC-17)
  barbican.vault = {{
    enable = true;
    mode = "production";
    address = "{}";

    pki = {{
      rootCaTtl = "87600h";  # 10 years
      intermediateCaTtl = "43800h";  # 5 years
      defaultCertTtl = "720h";  # 30 days
    }};

    audit.enable = true;
  }};
"#,
        address,
    )
}

fn generate_systemd_service(config: &BarbicanConfig, snake_name: &str) -> String {
    let app_name = &config.app.name;

    let mut after = vec!["network.target".to_string()];
    if config.database.is_some() {
        after.push("postgresql.service".to_string());
    }

    let after_str = after.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(" ");

    // Package name uses original app name (with hyphens), binary uses snake_case
    // Nix attribute access for hyphenated names requires quoted syntax
    let pkg_attr = if app_name.contains('-') {
        format!("pkgs.\"{}\"", app_name)
    } else {
        format!("pkgs.{}", app_name)
    };

    format!(
        r#"
  # Application Service
  systemd.services.{} = {{
    description = "{}";
    wantedBy = [ "multi-user.target" ];
    after = [ {} ];

    serviceConfig = config.barbican.systemdHardening.presets.networkService // {{
      ExecStart = "${{{}}}/bin/{}";
      EnvironmentFile = config.age.secrets.{}-env.path;

      # Resource Limits
      MemoryMax = "1G";
      CPUQuota = "100%";

      # Paths
      ReadWritePaths = [ "/var/lib/{}" ];
    }};
  }};
"#,
        snake_name,
        app_name,
        after_str,
        pkg_attr,
        snake_name,
        snake_name,
        snake_name,
    )
}

/// Convert a string to snake_case
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_lower = false;

    for c in s.chars() {
        if c == '-' || c == ' ' {
            result.push('_');
            prev_lower = false;
        } else if c.is_uppercase() {
            if prev_lower {
                result.push('_');
            }
            result.push(c.to_lowercase().next().unwrap());
            prev_lower = false;
        } else {
            result.push(c);
            prev_lower = c.is_lowercase();
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("order-service"), "order_service");
        assert_eq!(to_snake_case("OrderService"), "order_service");
        assert_eq!(to_snake_case("myApp"), "my_app");
    }

    #[test]
    fn test_generate_config() {
        let toml = r#"
[app]
name = "test-service"
profile = "fedramp-moderate"

[database]
type = "postgres"
url = "postgres://localhost/test"

[network]
listen = "0.0.0.0:8080"

[[network.allowed_ingress]]
port = 8080
from = "10.0.0.0/8"
"#;

        let config = crate::config::BarbicanConfig::from_str(toml, std::path::Path::new("test.toml")).unwrap();
        let files = generate(&config).unwrap();

        assert_eq!(files.len(), 1);
        assert!(files[0].content.contains("barbican.securePostgres"));
        assert!(files[0].content.contains("barbican.vmFirewall"));
    }
}
