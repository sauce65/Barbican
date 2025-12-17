//! Grafana Configuration Generation
//!
//! Generates FedRAMP-compliant Grafana configuration files.

use std::fs;
use std::path::Path;

use super::{ComplianceProfile, GeneratedFile, ObservabilityComplianceConfig, StackResult};

/// Grafana-specific configuration
#[derive(Debug, Clone)]
pub struct GrafanaConfig {
    /// HTTP listen port
    pub http_port: u16,

    /// Root URL for Grafana (for OAuth callbacks)
    pub root_url: String,

    /// Admin username
    pub admin_user: String,

    /// Disable anonymous access
    pub disable_anonymous: bool,

    /// SSO/OIDC configuration
    pub sso: Option<GrafanaSso>,

    /// Allowed iframe embedding domains (empty = deny all)
    pub allowed_origins: Vec<String>,

    /// Enable alerting
    pub alerting_enabled: bool,
}

/// Grafana SSO/OIDC configuration
#[derive(Debug, Clone)]
pub struct GrafanaSso {
    /// OIDC client ID
    pub client_id: String,

    /// OIDC client secret (placeholder - should be set via env)
    pub client_secret_env: String,

    /// Authorization URL
    pub auth_url: String,

    /// Token URL
    pub token_url: String,

    /// API/UserInfo URL
    pub api_url: String,

    /// Scopes to request
    pub scopes: Vec<String>,

    /// Role attribute path (JMESPath expression)
    pub role_attribute_path: Option<String>,

    /// Auto-login with SSO
    pub auto_login: bool,
}

impl GrafanaConfig {
    /// Create default configuration for a compliance profile
    pub fn default_for_profile(profile: ComplianceProfile) -> Self {
        match profile {
            ComplianceProfile::FedRampLow => Self {
                http_port: 3000,
                root_url: "http://localhost:3000".to_string(),
                admin_user: "admin".to_string(),
                disable_anonymous: true,
                sso: None,
                allowed_origins: Vec::new(),
                alerting_enabled: true,
            },
            ComplianceProfile::FedRampModerate
            | ComplianceProfile::FedRampHigh
            | ComplianceProfile::Soc2
            | ComplianceProfile::Custom => Self {
                http_port: 3000,
                root_url: "https://grafana.localhost".to_string(),
                admin_user: "admin".to_string(),
                disable_anonymous: true,
                sso: None, // Must be configured by user
                allowed_origins: Vec::new(),
                alerting_enabled: true,
            },
        }
    }

    /// Set the root URL
    pub fn with_root_url(mut self, url: impl Into<String>) -> Self {
        self.root_url = url.into();
        self
    }

    /// Set SSO configuration
    pub fn with_sso(mut self, sso: GrafanaSso) -> Self {
        self.sso = Some(sso);
        self
    }

    /// Set HTTP port
    pub fn with_http_port(mut self, port: u16) -> Self {
        self.http_port = port;
        self
    }
}

/// Generate Grafana configuration files
pub fn generate(
    output_dir: &Path,
    config: &GrafanaConfig,
    fedramp: &ObservabilityComplianceConfig,
    app_name: &str,
) -> StackResult<Vec<GeneratedFile>> {
    let mut files = Vec::new();
    let grafana_dir = output_dir.join("grafana");

    // Main Grafana configuration
    let grafana_config = generate_grafana_ini(config, fedramp);
    let config_path = grafana_dir.join("grafana.ini");
    fs::write(&config_path, grafana_config)?;
    files.push(
        GeneratedFile::new(&config_path, "Grafana server configuration")
            .with_controls(vec!["IA-2", "IA-2(1)", "AC-2", "AC-11", "AC-12"])
    );

    // Datasource provisioning
    let datasources = generate_datasources(fedramp, app_name);
    let ds_path = grafana_dir.join("provisioning/datasources/datasources.yml");
    fs::write(&ds_path, datasources)?;
    files.push(
        GeneratedFile::new(&ds_path, "Grafana datasource provisioning")
            .with_controls(vec!["AU-6"])
    );

    // Dashboard provisioning config
    let dash_config = generate_dashboard_provisioning();
    let dash_path = grafana_dir.join("provisioning/dashboards/dashboards.yml");
    fs::write(&dash_path, dash_config)?;
    files.push(
        GeneratedFile::new(&dash_path, "Grafana dashboard provisioning config")
            .with_controls(vec!["AU-6", "SI-4"])
    );

    // Security dashboard
    let security_dash = generate_security_dashboard(app_name);
    let security_dash_path = grafana_dir.join("provisioning/dashboards/json/security.json");
    fs::write(&security_dash_path, security_dash)?;
    files.push(
        GeneratedFile::new(&security_dash_path, "Security monitoring dashboard")
            .with_controls(vec!["SI-4", "IR-4", "IR-5"])
    );

    Ok(files)
}

fn generate_grafana_ini(config: &GrafanaConfig, fedramp: &ObservabilityComplianceConfig) -> String {
    let protocol = if fedramp.tls_enabled() { "https" } else { "http" };

    let tls_section = if fedramp.tls_enabled() {
        r#"
cert_file = /certs/grafana/server.crt
cert_key = /certs/grafana/server.key"#
    } else {
        ""
    };

    let sso_section = if let Some(sso) = &config.sso {
        let scopes = sso.scopes.join(" ");
        let role_mapping = sso.role_attribute_path.as_deref()
            .unwrap_or("contains(groups[*], 'admins') && 'Admin' || contains(groups[*], 'editors') && 'Editor' || 'Viewer'");

        format!(
            r#"
[auth.generic_oauth]
enabled = true
name = OAuth
allow_sign_up = true
auto_login = {auto_login}
client_id = {client_id}
client_secret = ${client_secret_env}
scopes = {scopes}
auth_url = {auth_url}
token_url = {token_url}
api_url = {api_url}
role_attribute_path = {role_mapping}
role_attribute_strict = true
allow_assign_grafana_admin = false
"#,
            auto_login = sso.auto_login,
            client_id = sso.client_id,
            client_secret_env = sso.client_secret_env,
            scopes = scopes,
            auth_url = sso.auth_url,
            token_url = sso.token_url,
            api_url = sso.api_url,
            role_mapping = role_mapping,
        )
    } else {
        String::new()
    };

    let session_timeout_mins = fedramp.session_timeout().as_secs() / 60;
    let idle_timeout_mins = fedramp.idle_timeout().as_secs() / 60;

    format!(
        r#"# Grafana Configuration - FedRAMP {profile} Profile
# Generated by barbican observability stack
# Controls: IA-2, IA-2(1), AC-2, AC-11, AC-12

[server]
protocol = {protocol}
http_port = {http_port}
root_url = {root_url}{tls_section}
enable_gzip = true

[database]
type = sqlite3
path = /var/lib/grafana/grafana.db

[security]
admin_user = {admin_user}
admin_password = ${{GF_SECURITY_ADMIN_PASSWORD}}
secret_key = ${{GF_SECURITY_SECRET_KEY}}
disable_initial_admin_creation = false
cookie_secure = {cookie_secure}
cookie_samesite = strict
strict_transport_security = {hsts}
strict_transport_security_max_age_seconds = 31536000
strict_transport_security_preload = true
strict_transport_security_subdomains = true
x_content_type_options = true
x_xss_protection = true
content_security_policy = true
content_security_policy_template = """script-src 'self' 'unsafe-eval' 'unsafe-inline'; object-src 'none'; font-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none';"""

[users]
allow_sign_up = false
auto_assign_org = true
auto_assign_org_role = Viewer
default_theme = dark

[auth]
disable_login_form = {disable_login_form}
disable_signout_menu = false
oauth_auto_login = {oauth_auto_login}

[auth.anonymous]
enabled = {anonymous_enabled}
{sso_section}
[session]
# AC-11: Session Lock (idle timeout)
# AC-12: Session Termination (absolute timeout)
provider = file
provider_config = sessions
cookie_name = grafana_session
cookie_secure = {cookie_secure}
session_life_time = {session_timeout}
# Note: Grafana doesn't have separate idle timeout; use login_maximum_inactive_lifetime_duration
login_maximum_inactive_lifetime_duration = {idle_timeout}m
login_maximum_lifetime_duration = {session_timeout}m

[alerting]
enabled = {alerting}

[unified_alerting]
enabled = {alerting}

[log]
mode = console
level = info
filters =

[log.console]
format = json

[metrics]
enabled = true
basic_auth_username = metrics
basic_auth_password = ${{GF_METRICS_BASIC_AUTH_PASSWORD}}

[analytics]
reporting_enabled = false
check_for_updates = false
"#,
        profile = fedramp.profile().name(),
        protocol = protocol,
        http_port = config.http_port,
        root_url = config.root_url,
        tls_section = tls_section,
        admin_user = config.admin_user,
        cookie_secure = fedramp.tls_enabled(),
        hsts = fedramp.tls_enabled(),
        disable_login_form = config.sso.is_some(),
        oauth_auto_login = config.sso.as_ref().map(|s| s.auto_login).unwrap_or(false),
        anonymous_enabled = !config.disable_anonymous,
        sso_section = sso_section,
        session_timeout = session_timeout_mins,
        idle_timeout = idle_timeout_mins,
        alerting = config.alerting_enabled,
    )
}

fn generate_datasources(fedramp: &ObservabilityComplianceConfig, _app_name: &str) -> String {
    let scheme = if fedramp.tls_enabled() { "https" } else { "http" };

    let tls_config = if fedramp.tls_enabled() {
        r#"
      tlsAuth: true
      tlsAuthWithCACert: true
      tlsCACert: /certs/ca.crt
      tlsClientCert: /certs/grafana/client.crt
      tlsClientKey: /certs/grafana/client.key"#
    } else {
        ""
    };

    let loki_header = if fedramp.tenant_isolation() {
        format!(
            r#"
      httpHeaderName1: X-Scope-OrgID
      httpHeaderValue1: {}"#,
            fedramp.tenant_id
        )
    } else {
        String::new()
    };

    format!(
        r#"# Grafana Datasource Provisioning - FedRAMP {profile} Profile
# Control: AU-6 (Audit Review, Analysis, Reporting)

apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: {scheme}://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
      httpMethod: POST{tls_config}
    secureJsonData:
      basicAuthPassword: ${{PROMETHEUS_PASSWORD}}
    basicAuth: true
    basicAuthUser: admin

  - name: Loki
    type: loki
    access: proxy
    url: {scheme}://loki:3100
    isDefault: false
    editable: false
    jsonData:
      maxLines: 1000{tls_config}{loki_header}

  - name: Alertmanager
    type: alertmanager
    access: proxy
    url: {scheme}://alertmanager:9093
    isDefault: false
    editable: false
    jsonData:
      implementation: prometheus{tls_config}
"#,
        profile = fedramp.profile().name(),
        scheme = scheme,
        tls_config = tls_config,
        loki_header = loki_header,
    )
}

fn generate_dashboard_provisioning() -> String {
    r#"# Grafana Dashboard Provisioning
# Control: AU-6, SI-4

apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: 'Security'
    folderUid: 'security'
    type: file
    disableDeletion: true
    updateIntervalSeconds: 30
    allowUiUpdates: false
    options:
      path: /var/lib/grafana/dashboards
"#.to_string()
}

fn generate_security_dashboard(app_name: &str) -> String {
    format!(
        r#"{{
  "annotations": {{
    "list": []
  }},
  "editable": false,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "liveNow": false,
  "panels": [
    {{
      "datasource": {{
        "type": "prometheus",
        "uid": "prometheus"
      }},
      "fieldConfig": {{
        "defaults": {{
          "color": {{
            "mode": "palette-classic"
          }},
          "mappings": [],
          "thresholds": {{
            "mode": "absolute",
            "steps": [
              {{ "color": "green", "value": null }},
              {{ "color": "yellow", "value": 5 }},
              {{ "color": "red", "value": 10 }}
            ]
          }}
        }},
        "overrides": []
      }},
      "gridPos": {{ "h": 4, "w": 6, "x": 0, "y": 0 }},
      "id": 1,
      "options": {{
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {{
          "calcs": ["lastNotNull"],
          "fields": "",
          "values": false
        }},
        "textMode": "auto"
      }},
      "title": "Failed Logins (24h)",
      "type": "stat",
      "targets": [
        {{
          "expr": "sum(increase(security_events_total{{app=\"{app_name}\",event_type=\"login_failed\"}}[24h]))",
          "refId": "A"
        }}
      ]
    }},
    {{
      "datasource": {{
        "type": "prometheus",
        "uid": "prometheus"
      }},
      "fieldConfig": {{
        "defaults": {{
          "mappings": [],
          "thresholds": {{
            "mode": "absolute",
            "steps": [
              {{ "color": "green", "value": null }},
              {{ "color": "red", "value": 1 }}
            ]
          }}
        }}
      }},
      "gridPos": {{ "h": 4, "w": 6, "x": 6, "y": 0 }},
      "id": 2,
      "options": {{
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {{
          "calcs": ["lastNotNull"],
          "fields": "",
          "values": false
        }}
      }},
      "title": "Account Lockouts (24h)",
      "type": "stat",
      "targets": [
        {{
          "expr": "sum(increase(security_events_total{{app=\"{app_name}\",event_type=\"account_locked\"}}[24h]))",
          "refId": "A"
        }}
      ]
    }},
    {{
      "datasource": {{
        "type": "loki",
        "uid": "loki"
      }},
      "gridPos": {{ "h": 12, "w": 24, "x": 0, "y": 4 }},
      "id": 3,
      "options": {{
        "dedupStrategy": "none",
        "enableLogDetails": true,
        "prettifyLogMessage": false,
        "showCommonLabels": false,
        "showLabels": false,
        "showTime": true,
        "sortOrder": "Descending",
        "wrapLogMessage": true
      }},
      "title": "Security Events",
      "type": "logs",
      "targets": [
        {{
          "expr": "{{app=\"{app_name}\"}} |= \"security_event\" | json",
          "refId": "A"
        }}
      ]
    }}
  ],
  "refresh": "30s",
  "schemaVersion": 38,
  "style": "dark",
  "tags": ["security", "fedramp"],
  "templating": {{
    "list": []
  }},
  "time": {{
    "from": "now-24h",
    "to": "now"
  }},
  "timepicker": {{}},
  "timezone": "utc",
  "title": "Security Dashboard",
  "uid": "security-dashboard",
  "version": 1
}}"#,
        app_name = app_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_moderate() {
        let config = GrafanaConfig::default_for_profile(ComplianceProfile::FedRampModerate);
        assert!(config.disable_anonymous);
        assert!(config.sso.is_none());
    }

    #[test]
    fn test_config_with_sso() {
        let config = GrafanaConfig::default_for_profile(ComplianceProfile::FedRampModerate)
            .with_sso(GrafanaSso {
                client_id: "grafana".to_string(),
                client_secret_env: "GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET".to_string(),
                auth_url: "https://auth.example.com/authorize".to_string(),
                token_url: "https://auth.example.com/token".to_string(),
                api_url: "https://auth.example.com/userinfo".to_string(),
                scopes: vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ],
                role_attribute_path: None,
                auto_login: true,
            });

        assert!(config.sso.is_some());
    }
}
