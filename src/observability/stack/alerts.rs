//! Security Alert Rules Generation
//!
//! Generates FedRAMP-compliant Prometheus alerting rules for security monitoring.

use std::fs;
use std::path::Path;

use super::{ComplianceProfile, GeneratedFile, ObservabilityComplianceConfig, StackResult};

/// Alert rules configuration
#[derive(Debug, Clone)]
pub struct AlertRules {
    /// Enable login failure alerts
    pub login_failure_alerts: bool,

    /// Login failure threshold for warning
    pub login_failure_warn_threshold: u32,

    /// Login failure threshold for critical
    pub login_failure_crit_threshold: u32,

    /// Enable rate limiting alerts
    pub rate_limit_alerts: bool,

    /// Enable certificate expiry alerts
    pub cert_expiry_alerts: bool,

    /// Days before cert expiry to warn
    pub cert_expiry_warn_days: u32,

    /// Days before cert expiry to alert critical
    pub cert_expiry_crit_days: u32,

    /// Enable service health alerts
    pub service_health_alerts: bool,

    /// Enable log ingestion alerts
    pub log_ingestion_alerts: bool,

    /// Custom alert rules
    pub custom_rules: Vec<AlertRule>,
}

/// A custom alert rule
#[derive(Debug, Clone)]
pub struct AlertRule {
    /// Alert name
    pub name: String,
    /// PromQL expression
    pub expr: String,
    /// Duration before firing
    pub for_duration: String,
    /// Severity (warning, critical)
    pub severity: String,
    /// Description template
    pub description: String,
    /// Summary template
    pub summary: String,
}

impl AlertRules {
    /// Create default alert rules for a compliance profile
    pub fn default_for_profile(profile: ComplianceProfile) -> Self {
        match profile {
            ComplianceProfile::FedRampLow => Self {
                login_failure_alerts: true,
                login_failure_warn_threshold: 10,
                login_failure_crit_threshold: 25,
                rate_limit_alerts: true,
                cert_expiry_alerts: true,
                cert_expiry_warn_days: 30,
                cert_expiry_crit_days: 7,
                service_health_alerts: true,
                log_ingestion_alerts: true,
                custom_rules: Vec::new(),
            },
            ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 | ComplianceProfile::Custom => Self {
                login_failure_alerts: true,
                login_failure_warn_threshold: 5,
                login_failure_crit_threshold: 15,
                rate_limit_alerts: true,
                cert_expiry_alerts: true,
                cert_expiry_warn_days: 30,
                cert_expiry_crit_days: 14,
                service_health_alerts: true,
                log_ingestion_alerts: true,
                custom_rules: Vec::new(),
            },
            ComplianceProfile::FedRampHigh => Self {
                login_failure_alerts: true,
                login_failure_warn_threshold: 3,
                login_failure_crit_threshold: 10,
                rate_limit_alerts: true,
                cert_expiry_alerts: true,
                cert_expiry_warn_days: 60,
                cert_expiry_crit_days: 30,
                service_health_alerts: true,
                log_ingestion_alerts: true,
                custom_rules: Vec::new(),
            },
        }
    }

    /// Add a custom alert rule
    pub fn with_rule(mut self, rule: AlertRule) -> Self {
        self.custom_rules.push(rule);
        self
    }

    /// Set login failure thresholds
    pub fn with_login_thresholds(mut self, warn: u32, crit: u32) -> Self {
        self.login_failure_warn_threshold = warn;
        self.login_failure_crit_threshold = crit;
        self
    }

    /// Set certificate expiry thresholds
    pub fn with_cert_expiry_thresholds(mut self, warn_days: u32, crit_days: u32) -> Self {
        self.cert_expiry_warn_days = warn_days;
        self.cert_expiry_crit_days = crit_days;
        self
    }
}

/// Generate alert rules and Alertmanager configuration
pub fn generate(
    output_dir: &Path,
    config: &AlertRules,
    fedramp: &ObservabilityComplianceConfig,
    app_name: &str,
) -> StackResult<Vec<GeneratedFile>> {
    let mut files = Vec::new();

    // Prometheus alert rules
    let rules = generate_prometheus_rules(config, fedramp, app_name);
    let rules_path = output_dir.join("prometheus/rules/security-alerts.yml");
    fs::write(&rules_path, rules)?;
    files.push(
        GeneratedFile::new(&rules_path, "Security alert rules")
            .with_controls(vec!["IR-4", "IR-5", "SI-4"]),
    );

    // Alertmanager configuration
    let alertmanager = generate_alertmanager_config(fedramp, app_name);
    let am_path = output_dir.join("alertmanager/alertmanager.yml");
    fs::write(&am_path, alertmanager)?;
    files.push(
        GeneratedFile::new(&am_path, "Alertmanager configuration")
            .with_controls(vec!["IR-4", "IR-5"]),
    );

    // Alertmanager web config (TLS)
    if fedramp.tls_enabled() {
        let web_config = generate_alertmanager_web_config();
        let web_path = output_dir.join("alertmanager/web.yml");
        fs::write(&web_path, web_config)?;
        files.push(
            GeneratedFile::new(&web_path, "Alertmanager TLS configuration")
                .with_controls(vec!["SC-8"]),
        );
    }

    Ok(files)
}

fn generate_prometheus_rules(
    config: &AlertRules,
    fedramp: &ObservabilityComplianceConfig,
    app_name: &str,
) -> String {
    let mut rules = format!(
        r#"# Security Alert Rules - FedRAMP {profile} Profile
# Generated by barbican observability stack
# Controls: IR-4 (Incident Handling), IR-5 (Incident Monitoring), SI-4 (Monitoring)

groups:
"#,
        profile = fedramp.profile().name()
    );

    // Security Events Group
    if config.login_failure_alerts {
        rules.push_str(&format!(
            r#"
  - name: security_events
    interval: 30s
    rules:
      # Failed Login Attempts - Warning
      - alert: HighFailedLogins
        expr: sum(increase(security_events_total{{app="{app_name}",event_type="login_failed"}}[5m])) > {warn_threshold}
        for: 2m
        labels:
          severity: warning
          fedramp_control: "AC-7"
        annotations:
          summary: "High number of failed login attempts"
          description: "{{{{ $value | printf \"%.0f\" }}}} failed login attempts in the last 5 minutes"

      # Failed Login Attempts - Critical
      - alert: CriticalFailedLogins
        expr: sum(increase(security_events_total{{app="{app_name}",event_type="login_failed"}}[5m])) > {crit_threshold}
        for: 1m
        labels:
          severity: critical
          fedramp_control: "AC-7"
        annotations:
          summary: "Critical number of failed login attempts - possible brute force attack"
          description: "{{{{ $value | printf \"%.0f\" }}}} failed login attempts in the last 5 minutes"

      # Account Lockouts
      - alert: AccountLockout
        expr: increase(security_events_total{{app="{app_name}",event_type="account_locked"}}[5m]) > 0
        for: 0m
        labels:
          severity: warning
          fedramp_control: "AC-7"
        annotations:
          summary: "Account lockout detected"
          description: "An account has been locked due to excessive failed login attempts"

      # Privilege Escalation Attempts
      - alert: PrivilegeEscalationAttempt
        expr: increase(security_events_total{{app="{app_name}",event_type="privilege_escalation_attempt"}}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          fedramp_control: "AC-6"
        annotations:
          summary: "Privilege escalation attempt detected"
          description: "A user attempted to access resources beyond their authorization"

      # Token Theft Detection (DPoP/MTLS binding violations)
      - alert: TokenBindingViolation
        expr: increase(security_events_total{{app="{app_name}",event_type="token_binding_violation"}}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          fedramp_control: "SC-11"
        annotations:
          summary: "Token binding violation detected - possible token theft"
          description: "A token was used without proper sender-constraint binding"
"#,
            app_name = app_name,
            warn_threshold = config.login_failure_warn_threshold,
            crit_threshold = config.login_failure_crit_threshold,
        ));
    }

    // Rate Limiting Group
    if config.rate_limit_alerts {
        rules.push_str(&format!(
            r#"
  - name: rate_limiting
    interval: 30s
    rules:
      # Rate Limit Exceeded
      - alert: RateLimitExceeded
        expr: sum(increase(http_requests_total{{app="{app_name}",status="429"}}[5m])) > 50
        for: 2m
        labels:
          severity: warning
          fedramp_control: "SC-5"
        annotations:
          summary: "High rate of rate-limited requests"
          description: "{{{{ $value | printf \"%.0f\" }}}} requests were rate limited in the last 5 minutes"

      # Sustained Rate Limit Attack
      - alert: SustainedRateLimitAttack
        expr: sum(rate(http_requests_total{{app="{app_name}",status="429"}}[10m])) > 1
        for: 10m
        labels:
          severity: critical
          fedramp_control: "SC-5"
        annotations:
          summary: "Sustained rate limit attack detected"
          description: "Continuous rate limiting for over 10 minutes - possible DoS attempt"
"#,
            app_name = app_name,
        ));
    }

    // Certificate Expiry Group
    if config.cert_expiry_alerts {
        rules.push_str(&format!(
            r#"
  - name: certificates
    interval: 1h
    rules:
      # Certificate Expiry Warning
      - alert: CertificateExpiryWarning
        expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < {warn_days}
        for: 1h
        labels:
          severity: warning
          fedramp_control: "SC-12"
        annotations:
          summary: "TLS certificate expiring soon"
          description: "Certificate expires in {{{{ $value | printf \"%.0f\" }}}} days"

      # Certificate Expiry Critical
      - alert: CertificateExpiryCritical
        expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < {crit_days}
        for: 1h
        labels:
          severity: critical
          fedramp_control: "SC-12"
        annotations:
          summary: "TLS certificate expiring very soon!"
          description: "Certificate expires in {{{{ $value | printf \"%.0f\" }}}} days - immediate action required"
"#,
            warn_days = config.cert_expiry_warn_days,
            crit_days = config.cert_expiry_crit_days,
        ));
    }

    // Service Health Group
    if config.service_health_alerts {
        rules.push_str(&format!(
            r#"
  - name: service_health
    interval: 30s
    rules:
      # Application Down
      - alert: ApplicationDown
        expr: up{{job="{app_name}"}} == 0
        for: 1m
        labels:
          severity: critical
          fedramp_control: "CA-7"
        annotations:
          summary: "{app_name} is down"
          description: "The application has been unreachable for over 1 minute"

      # High Error Rate
      - alert: HighErrorRate
        expr: sum(rate(http_requests_total{{app="{app_name}",status=~"5.."}}[5m])) / sum(rate(http_requests_total{{app="{app_name}"}}[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
          fedramp_control: "SI-4"
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{{{ $value | printf \"%.1f\" }}}}%% over the last 5 minutes"

      # Very High Error Rate
      - alert: VeryHighErrorRate
        expr: sum(rate(http_requests_total{{app="{app_name}",status=~"5.."}}[5m])) / sum(rate(http_requests_total{{app="{app_name}"}}[5m])) > 0.10
        for: 2m
        labels:
          severity: critical
          fedramp_control: "SI-4"
        annotations:
          summary: "Very high error rate - service degradation"
          description: "Error rate is {{{{ $value | printf \"%.1f\" }}}}%% - immediate investigation required"

      # High Response Time
      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{{app="{app_name}"}}[5m])) > 2
        for: 5m
        labels:
          severity: warning
          fedramp_control: "SI-4"
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{{{ $value | printf \"%.2f\" }}}}s"
"#,
            app_name = app_name,
        ));
    }

    // Log Ingestion Group
    if config.log_ingestion_alerts {
        rules.push_str(&format!(
            r#"
  - name: log_ingestion
    interval: 1m
    rules:
      # Loki Ingestion Errors
      - alert: LokiIngestionErrors
        expr: rate(loki_distributor_ingester_append_failures_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
          fedramp_control: "AU-5"
        annotations:
          summary: "Loki log ingestion failures"
          description: "Logs are failing to be ingested into Loki - audit trail may be incomplete"

      # Loki Down
      - alert: LokiDown
        expr: up{{job="loki"}} == 0
        for: 1m
        labels:
          severity: critical
          fedramp_control: "AU-5"
        annotations:
          summary: "Loki is down - audit logging compromised"
          description: "Loki has been unreachable for over 1 minute. Audit logs are not being collected."

      # Log Rate Drop
      - alert: LogRateDrop
        expr: sum(rate(loki_distributor_lines_received_total[10m])) < sum(avg_over_time(rate(loki_distributor_lines_received_total[10m])[1h:10m])) * 0.5
        for: 15m
        labels:
          severity: warning
          fedramp_control: "AU-5"
        annotations:
          summary: "Significant drop in log ingestion rate"
          description: "Log ingestion has dropped by more than 50%% compared to normal - possible logging failure"

      # Prometheus Down
      - alert: PrometheusDown
        expr: up{{job="prometheus"}} == 0
        for: 1m
        labels:
          severity: critical
          fedramp_control: "SI-4"
        annotations:
          summary: "Prometheus is down - monitoring compromised"
          description: "Prometheus self-monitoring indicates a problem"
"#
        ));
    }

    // Custom rules
    for rule in &config.custom_rules {
        rules.push_str(&format!(
            r#"
      # Custom Rule: {name}
      - alert: {name}
        expr: {expr}
        for: {for_duration}
        labels:
          severity: {severity}
        annotations:
          summary: "{summary}"
          description: "{description}"
"#,
            name = rule.name,
            expr = rule.expr,
            for_duration = rule.for_duration,
            severity = rule.severity,
            summary = rule.summary,
            description = rule.description,
        ));
    }

    rules
}

fn generate_alertmanager_config(fedramp: &ObservabilityComplianceConfig, app_name: &str) -> String {
    format!(
        r#"# Alertmanager Configuration - FedRAMP {profile} Profile
# Generated by barbican observability stack
# Controls: IR-4 (Incident Handling), IR-5 (Incident Monitoring)
#
# Configure receivers below with your notification endpoints.

global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'default'
  routes:
    # Critical alerts - immediate notification
    - match:
        severity: critical
      receiver: 'critical'
      group_wait: 10s
      repeat_interval: 1h
      continue: true

    # Security-related alerts - security team
    - match_re:
        fedramp_control: "AC-.*|IA-.*|SC-.*"
      receiver: 'security'
      continue: true

    # Audit-related alerts - compliance team
    - match_re:
        fedramp_control: "AU-.*"
      receiver: 'compliance'
      continue: true

receivers:
  - name: 'default'
    # Configure your default notification channel
    # Example webhook:
    # webhook_configs:
    #   - url: 'http://alerthandler:8080/alerts'
    #     send_resolved: true

  - name: 'critical'
    # Configure critical alert notifications
    # Example PagerDuty:
    # pagerduty_configs:
    #   - service_key: 'YOUR_PAGERDUTY_KEY'
    #     description: '{{ .CommonAnnotations.summary }}'

  - name: 'security'
    # Configure security team notifications
    # Example Slack:
    # slack_configs:
    #   - api_url: 'https://hooks.slack.com/services/XXX/YYY/ZZZ'
    #     channel: '#security-alerts'
    #     title: 'Security Alert: {{ .CommonAnnotations.summary }}'

  - name: 'compliance'
    # Configure compliance team notifications
    # Example email:
    # email_configs:
    #   - to: 'compliance@example.com'
    #     from: 'alerts@{app_name}'
    #     smarthost: 'smtp.example.com:587'

inhibit_rules:
  # Don't send warning if critical is already firing
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname']

  # Don't alert on application errors if the app is down
  - source_match:
      alertname: 'ApplicationDown'
    target_match_re:
      alertname: '(HighErrorRate|HighResponseTime)'
    equal: ['app']
"#,
        profile = fedramp.profile().name(),
        app_name = app_name,
    )
}

fn generate_alertmanager_web_config() -> String {
    r#"# Alertmanager Web Configuration
# Control: SC-8 (Transmission Confidentiality)

tls_server_config:
  cert_file: /certs/alertmanager/server.crt
  key_file: /certs/alertmanager/server.key
  client_ca_file: /certs/ca.crt
  client_auth_type: RequestClientCert
  min_version: TLS12
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_moderate() {
        let config = AlertRules::default_for_profile(ComplianceProfile::FedRampModerate);
        assert!(config.login_failure_alerts);
        assert_eq!(config.login_failure_warn_threshold, 5);
    }

    #[test]
    fn test_config_with_custom_rule() {
        let config = AlertRules::default_for_profile(ComplianceProfile::FedRampModerate).with_rule(
            AlertRule {
                name: "CustomAlert".to_string(),
                expr: "up == 0".to_string(),
                for_duration: "1m".to_string(),
                severity: "critical".to_string(),
                summary: "Custom alert".to_string(),
                description: "Custom description".to_string(),
            },
        );

        assert_eq!(config.custom_rules.len(), 1);
    }
}
