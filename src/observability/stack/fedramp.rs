//! FedRAMP Compliance for Observability Stack
//!
//! Extends core compliance configuration with observability-specific settings.
//! This module provides the bridge between the application-wide `ComplianceConfig`
//! and observability infrastructure requirements.

use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::compliance::{ComplianceConfig, ComplianceProfile};

use super::{ControlStatus, GeneratedFile, ObservabilityStack, StackResult, ValidationReport};

/// Observability-specific configuration extending ComplianceConfig
///
/// Wraps the core `ComplianceConfig` and adds observability-specific settings
/// like tenant identification, CA certificates, and backup configuration.
#[derive(Debug, Clone)]
pub struct ObservabilityComplianceConfig {
    /// Base compliance configuration (from crate::compliance)
    base: ComplianceConfig,

    /// Organization/tenant identifier (for Loki multi-tenancy)
    pub tenant_id: String,

    /// CA certificate path (for TLS verification)
    pub ca_cert_path: Option<String>,

    /// Backup encryption enabled
    pub backup_encryption: bool,

    /// Backup retention days
    pub backup_retention_days: u32,
}

impl ObservabilityComplianceConfig {
    /// Create from the global compliance configuration
    pub fn from_global() -> Self {
        Self::from_compliance(crate::compliance::config().clone())
    }

    /// Create from explicit compliance configuration
    pub fn from_compliance(config: ComplianceConfig) -> Self {
        let backup_encryption = config.require_encryption_at_rest;
        let backup_retention_days = config.min_retention_days;
        Self {
            base: config,
            tenant_id: "default".to_string(),
            ca_cert_path: None,
            backup_encryption,
            backup_retention_days,
        }
    }

    /// Create from a compliance profile
    pub fn from_profile(profile: ComplianceProfile) -> Self {
        Self::from_compliance(ComplianceConfig::from_profile(profile))
    }

    /// Set the tenant identifier
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = tenant_id.into();
        self
    }

    /// Set the CA certificate path
    pub fn with_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Override retention days (must meet minimum for profile)
    pub fn with_retention_days(mut self, days: u32) -> Self {
        let min = self.base.min_retention_days;
        self.backup_retention_days = days.max(min);
        self
    }

    // Convenience accessors that delegate to base compliance config

    /// Get the active compliance profile
    pub fn profile(&self) -> ComplianceProfile {
        self.base.profile
    }

    /// Get log retention days
    pub fn retention_days(&self) -> u32 {
        self.base.min_retention_days
    }

    /// Whether TLS is required
    pub fn tls_enabled(&self) -> bool {
        self.base.require_tls
    }

    /// Whether mTLS is required
    pub fn mtls_enabled(&self) -> bool {
        self.base.require_mtls
    }

    /// Whether encryption at rest is required
    pub fn encryption_at_rest(&self) -> bool {
        self.base.require_encryption_at_rest
    }

    /// Whether tenant isolation is required
    pub fn tenant_isolation(&self) -> bool {
        self.base.require_tenant_isolation
    }

    /// Whether MFA is required
    pub fn require_mfa(&self) -> bool {
        self.base.require_mfa
    }

    /// Get session timeout
    pub fn session_timeout(&self) -> Duration {
        self.base.session_max_lifetime
    }

    /// Get idle timeout
    pub fn idle_timeout(&self) -> Duration {
        self.base.session_idle_timeout
    }

    /// Check if this is a low-security profile (for conditional logic)
    pub fn is_low_security(&self) -> bool {
        matches!(self.base.profile, ComplianceProfile::FedRampLow)
    }
}

/// NIST 800-53 control families relevant to observability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFamily {
    /// AC - Access Control
    AccessControl,
    /// AU - Audit and Accountability
    Audit,
    /// IA - Identification and Authentication
    IdentAuth,
    /// SC - System and Communications Protection
    SysComm,
    /// SI - System and Information Integrity
    SysInfo,
    /// CP - Contingency Planning
    Contingency,
    /// IR - Incident Response
    IncidentResponse,
}

/// Individual NIST 800-53 controls
#[derive(Debug, Clone)]
pub struct Control {
    pub id: &'static str,
    pub name: &'static str,
    pub family: ControlFamily,
    pub description: &'static str,
    pub implementation: &'static str,
}

/// All controls implemented by the observability stack
pub const CONTROLS: &[Control] = &[
    Control {
        id: "AU-2",
        name: "Audit Events",
        family: ControlFamily::Audit,
        description: "The organization determines auditable events",
        implementation: "Loki collects all application logs; Prometheus collects metrics",
    },
    Control {
        id: "AU-3",
        name: "Content of Audit Records",
        family: ControlFamily::Audit,
        description: "Audit records contain required information",
        implementation: "Structured JSON logs with timestamp, source, user, action, outcome",
    },
    Control {
        id: "AU-4",
        name: "Audit Storage Capacity",
        family: ControlFamily::Audit,
        description: "Allocate sufficient audit storage",
        implementation: "Configurable retention with automatic cleanup; alerting on capacity",
    },
    Control {
        id: "AU-5",
        name: "Response to Audit Processing Failures",
        family: ControlFamily::Audit,
        description: "Alert on audit processing failures",
        implementation: "Prometheus alerts on Loki ingestion failures",
    },
    Control {
        id: "AU-6",
        name: "Audit Review, Analysis, and Reporting",
        family: ControlFamily::Audit,
        description: "Review and analyze audit records",
        implementation: "Grafana dashboards for log analysis and security monitoring",
    },
    Control {
        id: "AU-9",
        name: "Protection of Audit Information",
        family: ControlFamily::Audit,
        description: "Protect audit information from unauthorized access",
        implementation: "Multi-tenant isolation in Loki; TLS encryption; access controls",
    },
    Control {
        id: "AU-11",
        name: "Audit Record Retention",
        family: ControlFamily::Audit,
        description: "Retain audit records for required period",
        implementation: "Configurable retention (90 days for Moderate, 365 for High)",
    },
    Control {
        id: "AU-12",
        name: "Audit Generation",
        family: ControlFamily::Audit,
        description: "Generate audit records for auditable events",
        implementation: "Application-level structured logging via tracing-loki",
    },
    Control {
        id: "SC-8",
        name: "Transmission Confidentiality and Integrity",
        family: ControlFamily::SysComm,
        description: "Protect transmitted information",
        implementation: "TLS 1.2+ for all communications; optional mTLS",
    },
    Control {
        id: "SC-13",
        name: "Cryptographic Protection",
        family: ControlFamily::SysComm,
        description: "Implement cryptographic mechanisms",
        implementation: "FIPS-compliant TLS ciphers; AES-256 for backup encryption",
    },
    Control {
        id: "SC-28",
        name: "Protection of Information at Rest",
        family: ControlFamily::SysComm,
        description: "Protect information at rest",
        implementation: "Encrypted storage volumes; encrypted backups",
    },
    Control {
        id: "IA-2",
        name: "Identification and Authentication",
        family: ControlFamily::IdentAuth,
        description: "Uniquely identify and authenticate users",
        implementation: "Grafana SSO via OIDC; Prometheus/Loki basic auth or mTLS",
    },
    Control {
        id: "IA-2(1)",
        name: "Multi-Factor Authentication",
        family: ControlFamily::IdentAuth,
        description: "MFA for privileged access",
        implementation: "OIDC provider handles MFA; Grafana session management",
    },
    Control {
        id: "AC-2",
        name: "Account Management",
        family: ControlFamily::AccessControl,
        description: "Manage information system accounts",
        implementation: "Grafana RBAC; tenant-based access in Loki",
    },
    Control {
        id: "AC-3",
        name: "Access Enforcement",
        family: ControlFamily::AccessControl,
        description: "Enforce access control policies",
        implementation: "Grafana permissions; Loki tenant isolation",
    },
    Control {
        id: "AC-6",
        name: "Least Privilege",
        family: ControlFamily::AccessControl,
        description: "Employ least privilege principle",
        implementation: "Read-only filesystem; dropped capabilities; non-root containers",
    },
    Control {
        id: "CP-9",
        name: "Information System Backup",
        family: ControlFamily::Contingency,
        description: "Conduct backups of information",
        implementation: "Automated encrypted backup scripts",
    },
    Control {
        id: "IR-4",
        name: "Incident Handling",
        family: ControlFamily::IncidentResponse,
        description: "Implement incident handling capability",
        implementation: "Alertmanager for incident routing; Grafana for investigation",
    },
    Control {
        id: "IR-5",
        name: "Incident Monitoring",
        family: ControlFamily::IncidentResponse,
        description: "Track and document incidents",
        implementation: "Security alerts in Prometheus; audit trail in Loki",
    },
    Control {
        id: "SI-4",
        name: "Information System Monitoring",
        family: ControlFamily::SysInfo,
        description: "Monitor the information system",
        implementation: "Prometheus metrics; Grafana dashboards; security alerts",
    },
];

/// Validate the observability stack configuration against FedRAMP requirements
pub fn validate_stack(stack: &ObservabilityStack) -> StackResult<ValidationReport> {
    let mut report = ValidationReport::new();

    // AU-9: Protection of Audit Information
    if stack.fedramp.tenant_isolation() {
        report.add_control(ControlStatus::satisfied("AU-9", "Protection of Audit Information"));
    } else if !stack.fedramp.is_low_security() {
        report.add_control(ControlStatus::failed(
            "AU-9",
            "Protection of Audit Information",
            "Tenant isolation required for Moderate/High profiles",
        ));
    }

    // AU-11: Audit Record Retention
    let min_retention = stack.fedramp.retention_days();
    let configured_retention = stack.fedramp.backup_retention_days;
    if configured_retention >= min_retention {
        report.add_control(ControlStatus::satisfied("AU-11", "Audit Record Retention"));
    } else {
        report.add_control(ControlStatus::failed(
            "AU-11",
            "Audit Record Retention",
            format!(
                "Retention {} days is below minimum {} days for {} profile",
                configured_retention,
                min_retention,
                stack.fedramp.profile().name()
            ),
        ));
    }

    // SC-8: Transmission Confidentiality and Integrity
    if stack.fedramp.tls_enabled() {
        report.add_control(ControlStatus::satisfied("SC-8", "Transmission Confidentiality"));
    } else {
        report.add_control(ControlStatus::failed(
            "SC-8",
            "Transmission Confidentiality",
            "TLS must be enabled for FedRAMP compliance",
        ));
    }

    // SC-28: Protection of Information at Rest
    if stack.fedramp.encryption_at_rest() || stack.fedramp.is_low_security() {
        report.add_control(ControlStatus::satisfied("SC-28", "Protection at Rest"));
    } else {
        report.add_control(ControlStatus::failed(
            "SC-28",
            "Protection at Rest",
            "Encryption at rest required for Moderate/High profiles",
        ));
    }

    // IA-2(1): Multi-Factor Authentication
    if stack.fedramp.require_mfa() || stack.fedramp.is_low_security() {
        report.add_control(ControlStatus::satisfied("IA-2(1)", "Multi-Factor Authentication"));
    } else {
        report.add_control(ControlStatus::failed(
            "IA-2(1)",
            "Multi-Factor Authentication",
            "MFA required for Moderate/High profiles",
        ));
    }

    // mTLS for High profile
    if matches!(stack.fedramp.profile(), ComplianceProfile::FedRampHigh)
        && !stack.fedramp.mtls_enabled()
    {
        report.add_control(ControlStatus::failed(
            "SC-8(1)",
            "Cryptographic Protection",
            "mTLS required for High impact profile",
        ));
    }

    // Add controls that are always satisfied by the generated configs
    for control in CONTROLS
        .iter()
        .filter(|c| !["AU-9", "AU-11", "SC-8", "SC-28", "IA-2(1)"].contains(&c.id))
    {
        report.add_control(ControlStatus::satisfied(control.id, control.name));
    }

    // Warnings for best practices
    if stack.fedramp.ca_cert_path.is_none() && stack.fedramp.tls_enabled() {
        report.add_warning("No CA certificate path configured; TLS verification may be incomplete");
    }

    if !stack.fedramp.backup_encryption && !stack.fedramp.is_low_security() {
        report.add_warning("Backup encryption recommended for Moderate/High profiles");
    }

    Ok(report)
}

/// Generate FedRAMP compliance documentation
pub fn generate_docs(
    output_dir: &Path,
    config: &ObservabilityComplianceConfig,
    app_name: &str,
) -> StackResult<Vec<GeneratedFile>> {
    let mut files = Vec::new();
    let docs_dir = output_dir.join("docs");

    // Generate control matrix
    let control_matrix = generate_control_matrix(config, app_name);
    let matrix_path = docs_dir.join("FEDRAMP_CONTROLS.md");
    fs::write(&matrix_path, control_matrix)?;
    files.push(
        GeneratedFile::new(&matrix_path, "FedRAMP control mapping documentation")
            .with_controls(vec!["AU-2", "AU-3"])
    );

    // Generate SSO setup guide if MFA is required
    if config.require_mfa() {
        let sso_guide = generate_sso_guide(app_name);
        let sso_path = docs_dir.join("SSO_SETUP.md");
        fs::write(&sso_path, sso_guide)?;
        files.push(
            GeneratedFile::new(&sso_path, "SSO/OIDC setup guide for Grafana")
                .with_controls(vec!["IA-2", "IA-2(1)"])
        );
    }

    // Generate operations runbook
    let runbook = generate_operations_runbook(config, app_name);
    let runbook_path = docs_dir.join("OPERATIONS.md");
    fs::write(&runbook_path, runbook)?;
    files.push(
        GeneratedFile::new(&runbook_path, "Operations runbook")
            .with_controls(vec!["CP-9", "IR-4", "IR-5"])
    );

    Ok(files)
}

fn generate_control_matrix(config: &ObservabilityComplianceConfig, app_name: &str) -> String {
    let mut doc = format!(
        r#"# FedRAMP Control Matrix - {} Observability Stack

**Impact Level**: {} ({} profile)
**Generated**: Auto-generated by barbican

## Control Implementation Summary

| Control ID | Control Name | Status | Implementation |
|------------|--------------|--------|----------------|
"#,
        app_name,
        config.profile().name(),
        config.profile().name()
    );

    for control in CONTROLS {
        doc.push_str(&format!(
            "| {} | {} | ✅ | {} |\n",
            control.id, control.name, control.implementation
        ));
    }

    doc.push_str(&format!(
        r#"
## Configuration Details

### Audit Settings (AU Family)
- **Retention Period**: {} days
- **Tenant Isolation**: {}
- **Backup Encryption**: {}

### Security Settings (SC Family)
- **TLS Enabled**: {}
- **mTLS Enabled**: {}
- **Encryption at Rest**: {}

### Authentication Settings (IA Family)
- **MFA Required**: {}
- **Session Timeout**: {} minutes
- **Idle Timeout**: {} minutes

## Compliance Notes

This observability stack is configured for FedRAMP {} compliance.
"#,
        config.retention_days(),
        if config.tenant_isolation() { "Enabled" } else { "Disabled" },
        if config.backup_encryption { "Enabled" } else { "Disabled" },
        if config.tls_enabled() { "Enabled" } else { "Disabled" },
        if config.mtls_enabled() { "Enabled" } else { "Disabled" },
        if config.encryption_at_rest() { "Enabled" } else { "Disabled" },
        if config.require_mfa() { "Enabled" } else { "Disabled" },
        config.session_timeout().as_secs() / 60,
        config.idle_timeout().as_secs() / 60,
        config.profile().name()
    ));

    if matches!(config.profile(), ComplianceProfile::FedRampHigh) {
        doc.push_str(r#"
### High Impact Additional Requirements

- All service-to-service communication uses mTLS
- Maximum session timeout of 10 minutes
- 365-day log retention
- Encrypted backups required
"#);
    }

    doc
}

fn generate_sso_guide(app_name: &str) -> String {
    format!(
        r#"# SSO Setup Guide - {} Observability Stack

## Prerequisites

1. An OAuth 2.0/OIDC provider (e.g., the {} application itself, Keycloak, Okta)
2. MFA enabled on the OIDC provider (FedRAMP IA-2(1))
3. TLS certificates for Grafana

## Grafana OIDC Configuration

### 1. Register Grafana as an OAuth Client

In your OIDC provider, register a new client with:

- **Client ID**: `grafana-observability`
- **Client Type**: Confidential
- **Redirect URI**: `https://grafana.yourdomain.com/login/generic_oauth`
- **Scopes**: `openid email profile`

### 2. Configure Grafana

The generated `grafana.ini` includes OIDC settings. Update these placeholders:

```ini
[auth.generic_oauth]
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
auth_url = https://your-oidc-provider/authorize
token_url = https://your-oidc-provider/token
api_url = https://your-oidc-provider/userinfo
```

### 3. Role Mapping

Configure role mapping based on OIDC claims:

```ini
role_attribute_path = contains(groups[*], 'admins') && 'Admin' || contains(groups[*], 'editors') && 'Editor' || 'Viewer'
```

### 4. MFA Enforcement

Ensure your OIDC provider enforces MFA for all users accessing Grafana.
This satisfies FedRAMP IA-2(1) requirements.

## Verification

1. Access Grafana at `https://grafana.yourdomain.com`
2. Click "Sign in with OAuth"
3. Authenticate with MFA
4. Verify correct role assignment
"#,
        app_name, app_name
    )
}

fn generate_operations_runbook(config: &ObservabilityComplianceConfig, app_name: &str) -> String {
    format!(
        r#"# Operations Runbook - {} Observability Stack

## Daily Operations

### Health Checks

1. Verify all services are running:
   ```bash
   docker-compose ps
   ```

2. Check Loki ingestion:
   ```bash
   curl -s https://localhost:3100/ready
   ```

3. Check Prometheus:
   ```bash
   curl -s https://localhost:9090/-/ready
   ```

4. Check Grafana:
   ```bash
   curl -s https://localhost:3000/api/health
   ```

## Backup Procedures (CP-9)

### Automated Backups

Backups run automatically via the included backup script.
Retention: {} days

### Manual Backup

```bash
./scripts/backup-audit-logs.sh
```

### Restore Procedure

```bash
./scripts/restore-audit-logs.sh /path/to/backup.tar.gz.enc
```

## Incident Response (IR-4, IR-5)

### Alert Response

1. Check Alertmanager for active alerts
2. Review Grafana dashboards for anomalies
3. Query Loki for relevant logs:
   ```logql
   {{app="{}"}} |= "error" | json
   ```

### Log Investigation

1. Access Grafana Explore
2. Select Loki datasource
3. Use LogQL to filter relevant events

## Certificate Renewal

TLS certificates should be renewed before expiration:

```bash
./scripts/gen-certs.sh
docker-compose restart
```

## Retention Management (AU-11)

Current retention: {} days

Logs older than the retention period are automatically deleted.
To verify retention is working:

```bash
# Check oldest logs
curl -G -s "https://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode "query={{{{app=\"{}\"}}}}" \
  --data-urlencode "start=$(date -d '-{}days' +%s)000000000" \
  --data-urlencode "limit=1"
```
"#,
        app_name,
        config.backup_retention_days,
        app_name,
        config.retention_days(),
        app_name,
        config.retention_days() + 1
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_retention() {
        // Tests now use ComplianceProfile from crate::compliance
        assert_eq!(ComplianceProfile::FedRampLow.min_retention_days(), 30);
        assert_eq!(ComplianceProfile::FedRampModerate.min_retention_days(), 90);
        assert_eq!(ComplianceProfile::FedRampHigh.min_retention_days(), 365);
    }

    #[test]
    fn test_profile_requirements() {
        assert!(!ComplianceProfile::FedRampLow.requires_mtls());
        assert!(!ComplianceProfile::FedRampModerate.requires_mtls());
        assert!(ComplianceProfile::FedRampHigh.requires_mtls());

        assert!(ComplianceProfile::FedRampModerate.requires_encryption_at_rest());
        assert!(ComplianceProfile::FedRampHigh.requires_encryption_at_rest());
    }

    #[test]
    fn test_config_from_profile() {
        let config = ObservabilityComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
        assert_eq!(config.retention_days(), 90);
        assert!(config.tls_enabled());
        assert!(config.tenant_isolation());
        assert!(config.require_mfa());
    }

    #[test]
    fn test_config_retention_minimum() {
        let config = ObservabilityComplianceConfig::from_profile(ComplianceProfile::FedRampModerate)
            .with_retention_days(30); // Try to set below minimum
        assert_eq!(config.backup_retention_days, 90); // Should be clamped to minimum
    }
}
