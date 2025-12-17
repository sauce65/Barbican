# barbican

NIST 800-53 compliant security infrastructure for Axum applications. A pluggable, secure-by-default library providing 52+ security controls for building production-ready web services.

## Quick Start

```rust
use axum::{Router, routing::get};
use barbican::{SecurityConfig, SecureRouter, DatabaseConfig, create_pool};
use barbican::compliance::{ComplianceConfig, init as init_compliance};
use barbican::observability::{ObservabilityConfig, init};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize compliance configuration (single source of truth)
    init_compliance(ComplianceConfig::from_env());

    // Initialize observability
    init(ObservabilityConfig::from_env()).await?;

    // Create database pool
    let pool = create_pool(&DatabaseConfig::from_env()).await?;

    // Build app with security layers
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .with_state(pool)
        .with_security(SecurityConfig::from_env());

    // Serve with TLS...
    Ok(())
}
```

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `default` | Includes `observability-stdout` | Yes |
| `postgres` | PostgreSQL connection pooling with SSL | No |
| `observability-stdout` | Log to stdout (development) | Yes |
| `observability-loki` | Send logs to Grafana Loki | No |
| `observability-otlp` | OpenTelemetry Protocol tracing | No |
| `metrics-prometheus` | Prometheus metrics endpoint | No |

Enable features in `Cargo.toml`:

```toml
[dependencies]
barbican = { version = "0.1", features = ["postgres", "observability-loki", "metrics-prometheus"] }
```

## Security Modules

Barbican provides 13 security modules covering 52+ NIST 800-53 controls:

### Compliance Configuration

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `compliance` | Unified compliance profiles (FedRAMP, SOC 2) - single source of truth | AC-7, AC-11, AC-12, AU-11, IA-2, IA-5, SC-8, SC-12, SC-28 |

### Infrastructure Layer

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `layers` | Security headers, rate limiting, CORS, timeouts | SC-5, SC-8, SC-28, AC-4 |
| `database` | SSL/TLS, connection pooling, health checks | SC-8, SC-28, IA-5 |
| `observability` | Structured logging, metrics, distributed tracing | AU-2, AU-3, AU-12 |
| `observability::stack` | FedRAMP-compliant observability infrastructure generator | AU-9, AU-11, SC-8, SC-28, IR-4, IR-5 |

### Authentication & Authorization

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `auth` | OAuth/OIDC JWT claims, MFA policy enforcement | IA-2, IA-5, AC-2 |
| `password` | NIST 800-63B compliant password validation | IA-5(1) |
| `login` | Login attempt tracking, account lockout | AC-7 |
| `session` | Session management, idle timeout, termination | AC-11, AC-12 |

### Operational Security

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `alerting` | Security incident alerting with rate limiting | IR-4, IR-5 |
| `health` | Health check framework with aggregation | CA-7 |
| `keys` | Key management with KMS integration traits | SC-12 |
| `supply_chain` | SBOM generation, license compliance, vulnerability audit | SR-3, SR-4 |
| `testing` | Security test utilities (XSS, SQLi payloads) | SA-11, CA-8 |

### Data Protection

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `validation` | Input validation and sanitization | SI-10 |
| `error` | Secure error handling, no info leakage | SI-11 |
| `crypto` | Constant-time comparison utilities | SC-13 |

## Environment Variables

### Compliance Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `COMPLIANCE_PROFILE` | string | `fedramp-moderate` | Compliance profile: `fedramp-low`, `fedramp-moderate`, `fedramp-high`, `soc2`, `custom` |

The compliance profile determines security settings across all modules:

| Setting | Low | Moderate | High | SOC 2 |
|---------|-----|----------|------|-------|
| Session Timeout | 30 min | 15 min | 10 min | 15 min |
| Idle Timeout | 15 min | 10 min | 5 min | 10 min |
| MFA Required | No | Yes | Yes | Yes |
| Password Min | 8 | 12 | 14 | 12 |
| Encryption at Rest | No | Yes | Yes | Yes |
| mTLS Required | No | No | Yes | No |
| Key Rotation | 90 days | 90 days | 30 days | 90 days |
| Max Login Attempts | 5 | 3 | 3 | 3 |
| Lockout Duration | 15 min | 30 min | 30 min | 30 min |
| Log Retention | 30 days | 90 days | 365 days | 90 days |

### Security Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAX_REQUEST_SIZE` | size | `1MB` | Maximum request body size (e.g., "10MB", "1GB") |
| `REQUEST_TIMEOUT` | duration | `30s` | Request timeout (e.g., "30s", "5m") |
| `RATE_LIMIT_PER_SECOND` | int | `5` | Requests per second per IP |
| `RATE_LIMIT_BURST` | int | `10` | Burst capacity for rate limiter |
| `RATE_LIMIT_ENABLED` | bool | `true` | Enable rate limiting |
| `CORS_ALLOWED_ORIGINS` | csv | (empty) | Comma-separated origins or `*` (dev only) |
| `SECURITY_HEADERS_ENABLED` | bool | `true` | Enable security headers |
| `TRACING_ENABLED` | bool | `true` | Enable request tracing |

### Database Configuration (requires `postgres` feature)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | string | (required) | PostgreSQL connection URL |
| `DB_MAX_CONNECTIONS` | int | `10` | Maximum pool size |
| `DB_MIN_CONNECTIONS` | int | `1` | Minimum idle connections |
| `DB_ACQUIRE_TIMEOUT` | duration | `30s` | Connection acquire timeout |
| `DB_MAX_LIFETIME` | duration | `30m` | Maximum connection lifetime |
| `DB_IDLE_TIMEOUT` | duration | `10m` | Idle connection timeout |
| `DB_SSL_MODE` | string | `require` | `disable`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `DB_SSL_ROOT_CERT` | path | (none) | Path to CA certificate for SSL verification |
| `DB_STATEMENT_LOGGING` | bool | `false` | Enable SQL statement logging |
| `DB_AUTO_MIGRATE` | bool | `true` | Run migrations on startup |

### Observability Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `LOG_PROVIDER` | string | `stdout` | `stdout`, `loki`, or `otlp` |
| `LOG_FORMAT` | string | `pretty` | `pretty`, `json`, or `compact` |
| `RUST_LOG` | string | `info` | Log filter (e.g., `debug`, `myapp=debug,tower_http=info`) |
| `TRACING_ENABLED` | bool | `true` | Enable request/response tracing |

**For Loki** (`LOG_PROVIDER=loki`, requires `observability-loki` feature):
- `LOKI_ENDPOINT`: Loki push URL (e.g., `http://loki:3100`)
- `LOKI_LABELS`: Comma-separated `key=value` pairs (optional)
- `LOKI_TENANT_ID`: Tenant ID for multi-tenant Loki (sets `X-Scope-OrgID` header, required when Loki has `auth_enabled: true`)

**For OTLP** (`LOG_PROVIDER=otlp`, requires `observability-otlp` feature):
- `OTLP_ENDPOINT`: OTLP collector URL (e.g., `http://jaeger:4317`)
- `OTEL_SERVICE_NAME`: Service name for traces (default: `app`)

**For Prometheus** (requires `metrics-prometheus` feature):
- `METRICS_PROVIDER`: Set to `prometheus` to enable
- `PROMETHEUS_LISTEN`: Listen address (default: `0.0.0.0:9090`)

## Programmatic Configuration

All configuration can be set via builder pattern:

```rust
use std::time::Duration;
use barbican::{SecurityConfig, DatabaseConfig, SslMode};

// Security config
let security = SecurityConfig::builder()
    .max_request_size(5 * 1024 * 1024) // 5MB
    .request_timeout(Duration::from_secs(60))
    .rate_limit(10, 20) // 10/sec, burst 20
    .cors_origins(vec!["https://app.example.com"])
    .build();

// Database config
let db = DatabaseConfig::builder("postgres://localhost/mydb")
    .max_connections(20)
    .ssl_mode(SslMode::VerifyFull)
    .with_statement_logging()
    .build();

// Observability config
use barbican::observability::{ObservabilityConfig, LogFormat, LogProvider};

let obs = ObservabilityConfig::builder()
    .log_format(LogFormat::Json)
    .log_filter("debug")
    .log_provider(LogProvider::Stdout)
    .build();
```

## Security Event Logging

Log security events with structured fields for compliance:

```rust
use barbican::observability::{SecurityEvent, security_event};

security_event!(
    SecurityEvent::AuthenticationSuccess,
    user_id = %user.id,
    ip_address = %client_ip,
    "User authenticated successfully"
);

security_event!(
    SecurityEvent::RateLimitExceeded,
    ip_address = %client_ip,
    endpoint = "/api/login",
    "Rate limit exceeded"
);
```

Available events: `AuthenticationSuccess`, `AuthenticationFailure`, `AccessDenied`, `UserRegistered`, `RateLimitExceeded`, `BruteForceDetected`, `AccountLocked`, and more. See `SecurityEvent` enum for full list.

## Observability Stack Generator

Generate FedRAMP-compliant observability infrastructure (Loki, Prometheus, Grafana, Alertmanager) with a single command:

```rust
use barbican::observability::stack::{ObservabilityStack, FedRampProfile};

let stack = ObservabilityStack::builder()
    .app_name("my-app")
    .app_port(3443)
    .output_dir("./observability")
    .fedramp_profile(FedRampProfile::Moderate)
    .build()?;

// Validate FedRAMP compliance
let validation = stack.validate()?;
validation.print_summary();

// Generate all configuration files
let report = stack.generate()?;
report.print_summary(); // 21 files generated
```

Or use the example binary:

```bash
cargo run --example generate_observability_stack -- my-app ./observability
```

### Generated Files (21 total)

| Directory | Files | Purpose |
|-----------|-------|---------|
| `loki/` | `loki-config.yml`, `tenant-limits.yml` | Multi-tenant log aggregation with 90-day retention |
| `prometheus/` | `prometheus.yml`, `web.yml`, `rules/security-alerts.yml` | Metrics with TLS, 15+ security alerts |
| `grafana/` | `grafana.ini`, datasources, dashboards | OIDC SSO, security dashboard |
| `alertmanager/` | `alertmanager.yml`, `web.yml` | Alert routing with TLS |
| `scripts/` | `gen-certs.sh`, `backup-audit-logs.sh`, `restore-audit-logs.sh`, `health-check.sh` | Cert generation, encrypted backups |
| `docs/` | `FEDRAMP_CONTROLS.md`, `SSO_SETUP.md`, `OPERATIONS.md` | Compliance documentation |
| Root | `docker-compose.yml`, `.env.example` | Hardened container deployment |

### FedRAMP Profiles

| Setting | Low | Moderate | High |
|---------|-----|----------|------|
| Log retention | 30 days | 90 days | 365 days |
| TLS required | Yes | Yes | Yes |
| mTLS required | No | No | Yes |
| MFA required | No | Yes | Yes |
| Session timeout | 30 min | 15 min | 10 min |
| Container read-only | No | Yes | Yes |

### FedRAMP Controls Implemented (20)

AU-2, AU-3, AU-4, AU-5, AU-6, AU-9, AU-11, AU-12, SC-8, SC-13, SC-28, IA-2, IA-2(1), AC-2, AC-3, AC-6, CP-9, IR-4, IR-5, SI-4

## Module Usage Examples

### Compliance Configuration

```rust
use barbican::compliance::{ComplianceConfig, ComplianceProfile, config, init};

// Initialize at application startup (call once)
let compliance = ComplianceConfig::from_env(); // Reads COMPLIANCE_PROFILE env var
init(compliance);

// Or initialize with explicit profile
let compliance = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
init(compliance);

// Access globally anywhere in the application
let compliance = config();
if compliance.require_mfa {
    // Enforce MFA
}

// Security modules derive settings from compliance config
use barbican::password::PasswordPolicy;
let password_policy = PasswordPolicy::from_compliance(config());

use barbican::session::SessionPolicy;
let session_policy = SessionPolicy::from_compliance(config());

use barbican::login::LockoutPolicy;
let lockout_policy = LockoutPolicy::from_compliance(config());
```

### Password Validation (IA-5)

```rust
use barbican::password::PasswordPolicy;
use barbican::compliance::config;

// Derive policy from compliance profile (recommended)
let policy = PasswordPolicy::from_compliance(config());

// Or use NIST 800-63B compliant defaults
let policy = PasswordPolicy::default();

policy.validate_with_context(password, Some(username), Some(email))?;
```

### Input Validation (SI-10)

```rust
use barbican::validation::{validate_email, validate_length, sanitize_html};

validate_email(email)?;
validate_length(bio, 0, 500, "bio")?;
let safe_bio = sanitize_html(bio);
```

### Session Management (AC-11, AC-12)

```rust
use barbican::session::{SessionPolicy, SessionState, SessionTerminationReason};
use barbican::compliance::config;
use std::time::Duration;

// Derive from compliance profile (recommended)
let policy = SessionPolicy::from_compliance(config());

// Or configure manually
let policy = SessionPolicy::builder()
    .idle_timeout(Duration::from_secs(900))     // 15 min idle
    .absolute_timeout(Duration::from_secs(28800)) // 8 hour max
    .build();

let mut session = SessionState::new("session-id", "user-123");
if policy.is_idle_timeout_exceeded(&session) {
    session.terminate(SessionTerminationReason::IdleTimeout);
}
```

### Login Attempt Tracking (AC-7)

```rust
use barbican::login::{LockoutPolicy, LoginTracker, AttemptResult};
use barbican::compliance::config;

// Derive from compliance profile (recommended)
let policy = LockoutPolicy::from_compliance(config());

// Or use NIST defaults
let policy = LockoutPolicy::nist_compliant(); // 3 attempts, 15 min lockout

let mut tracker = LoginTracker::new(policy);

match tracker.record_attempt("user@example.com", false) {
    AttemptResult::Allowed => { /* continue */ }
    AttemptResult::AccountLocked(info) => {
        // Account locked, show lockout_until time
    }
}
```

### Security Alerting (IR-4, IR-5)

```rust
use barbican::alerting::{AlertManager, AlertConfig, Alert, AlertSeverity};

let config = AlertConfig::default();
let manager = AlertManager::new(config);

manager.alert(Alert::new(
    AlertSeverity::High,
    "Brute force attack detected",
    AlertCategory::Security,
));
```

### Health Checks (CA-7)

```rust
use barbican::health::{HealthChecker, HealthCheck, HealthStatus};

let mut checker = HealthChecker::new();
checker.add_check("database", HealthCheck::new(|| async {
    // Check database connectivity
    HealthStatus::healthy()
}));

let report = checker.check_all().await;
```

### Key Management (SC-12)

```rust
use barbican::keys::{KeyStore, EnvKeyStore, RotationTracker, RotationPolicy};
use barbican::compliance::config;

// Development: environment-based keys
let store = EnvKeyStore::new("MYAPP_")?;
let key = store.get_key("encryption_key").await?;

// Production: implement KeyStore trait for Vault/AWS KMS
// Derive rotation policy from compliance profile
let tracker = RotationTracker::new(RotationPolicy::from_compliance(config()));
if tracker.needs_rotation("api-key")? {
    // Trigger key rotation
}
```

### Supply Chain Security (SR-3, SR-4)

```rust
use barbican::supply_chain::{parse_cargo_lock, generate_cyclonedx_sbom, LicensePolicy};

let deps = parse_cargo_lock("Cargo.lock")?;
let sbom = generate_cyclonedx_sbom(&deps, SbomMetadata::new("myapp", "1.0.0"));

// Check license compliance
let policy = LicensePolicy::default();
for dep in &deps {
    policy.check(&dep.license)?;
}
```

### Security Testing (SA-11, CA-8)

```rust
use barbican::testing::{xss_payloads, sql_injection_payloads, SecurityHeaders};

// Fuzz test your endpoints
for payload in xss_payloads() {
    let response = client.post("/api/comment").body(payload).send().await?;
    assert!(!response.text().contains(payload)); // Should be escaped
}

// Validate security headers
let headers = SecurityHeaders::from_response(&response);
let issues = headers.validate();
assert!(issues.is_empty());
```

### OAuth/OIDC Integration

```rust
use barbican::auth::{Claims, log_access_decision, log_mfa_required, MfaPolicy};
use barbican::compliance::config;
use axum::http::StatusCode;

async fn admin_handler(claims: Claims) -> Result<&'static str, StatusCode> {
    // Check MFA requirement based on compliance profile
    let mfa_policy = MfaPolicy::from_compliance(config());
    if !mfa_policy.is_satisfied(&claims) {
        log_mfa_required(&claims, "admin_panel");
        return Err(StatusCode::FORBIDDEN);
    }

    if claims.has_role("admin") {
        log_access_decision(&claims, "admin_panel", true);
        Ok("Welcome!")
    } else {
        log_access_decision(&claims, "admin_panel", false);
        Err(StatusCode::FORBIDDEN)
    }
}
```

### Secure Error Handling (SI-11)

```rust
use barbican::error::{AppError, Result};

async fn handler() -> Result<String> {
    let data = fetch_data()
        .map_err(|e| AppError::internal("Failed to fetch data", e))?;
    Ok(data)
}
// Production: {"error": "internal_error", "message": "An internal error occurred"}
// Development: full error details included
```

### Cryptographic Utilities

```rust
use barbican::{constant_time_eq, constant_time_str_eq};

// Prevent timing attacks on secret comparisons
let stored_hash = b"abc123...";
let provided_hash = b"abc123...";
if constant_time_eq(stored_hash, provided_hash) {
    // Secrets match
}

// String variant
if constant_time_str_eq(&stored_token, &provided_token) {
    // Tokens match
}
```

## Compliance

Barbican implements 52 NIST 800-53 Rev 5 controls (47.7% of applicable controls) and facilitates 32 additional controls (29.4%):

**Control Families Covered:**
- **Access Control (AC)**: AC-2, AC-4, AC-7, AC-11, AC-12
- **Audit (AU)**: AU-2, AU-3, AU-6, AU-7, AU-12
- **Security Assessment (CA)**: CA-7, CA-8
- **Identification & Authentication (IA)**: IA-2, IA-5, IA-5(1)
- **Incident Response (IR)**: IR-4, IR-5, IR-6
- **System & Communications (SC)**: SC-5, SC-8, SC-10, SC-12, SC-13, SC-28
- **System & Information Integrity (SI)**: SI-10, SI-11
- **Supply Chain (SR)**: SR-3, SR-4
- **System & Services Acquisition (SA)**: SA-11

**Framework Support:**
- **NIST SP 800-53 Rev 5**: 52 controls implemented
- **NIST SP 800-63B**: Password policy compliance
- **SOC 2 Type II**: ~75% of applicable criteria
- **FedRAMP**: ~70% of applicable controls
- **OAuth 2.0 / OIDC**: JWT claims extraction with MFA support
- **OWASP Top 10**: Input validation, secure error handling

See `.claudedocs/SECURITY_CONTROL_REGISTRY.md` for detailed control mappings.

## NixOS Modules

Barbican provides NixOS modules for hardening MicroVMs and NixOS systems. These modules implement NIST 800-53 controls at the infrastructure level.

### Quick Start (NixOS Flake)

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    barbican.url = "github:your-org/barbican";
  };

  outputs = { self, nixpkgs, barbican, ... }: {
    nixosConfigurations.myvm = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        # Use a security profile (minimal, standard, or hardened)
        barbican.nixosModules.hardened

        # Or import individual modules
        # barbican.nixosModules.secureUsers
        # barbican.nixosModules.hardenedSSH
        # barbican.nixosModules.kernelHardening

        {
          # Configure module options
          barbican.secureUsers = {
            enable = true;
            authorizedKeys = [ "ssh-ed25519 AAAA... user@host" ];
          };
          barbican.hardenedSSH = {
            enable = true;
            enableFail2ban = true;
          };
        }
      ];
    };
  };
}
```

### Security Profiles

| Profile | Use Case | Modules Enabled |
|---------|----------|-----------------|
| `minimal` | Development/testing | secureUsers, kernelHardening (basic) |
| `standard` | Staging, internal prod | Above + hardenedSSH, timeSync, resourceLimits |
| `hardened` | Production, compliance | All modules with strict defaults |

### Available Modules

| Module | Description | Controls Addressed |
|--------|-------------|-------------------|
| `secureUsers` | No empty passwords, SSH-only auth, login banners | CRT-001, CRT-002 |
| `hardenedSSH` | Strong ciphers, fail2ban, key-only auth | CRT-010 |
| `kernelHardening` | Sysctl hardening, ASLR, audit | MED-001 |
| `securePostgres` | scram-sha-256, SSL, audit logging, restricted listen | CRT-003, CRT-011-013 |
| `timeSync` | Chrony NTP with secure servers | HIGH-011 |
| `resourceLimits` | Cgroups, ulimits, core dump prevention | HIGH-001 |
| `intrusionDetection` | AIDE file integrity, auditd | CRT-015, CRT-016 |
| `vmFirewall` | Network segmentation, egress filtering | CRT-007, HIGH-005 |
| `databaseBackup` | Encrypted automated backups | CRT-009 |
| `secretsManagement` | sops-nix integration | CRT-004, CRT-005 |
| `observabilityAuth` | Loki/Prometheus/Grafana auth | CRT-008, CRT-014 |
| `systemdHardening` | Service sandboxing presets | MED-003 |

### Module Configuration Example

```nix
{ config, ... }: {
  barbican.vmFirewall = {
    enable = true;
    defaultPolicy = "drop";
    allowedInbound = [
      { port = 22; from = "10.0.0.0/8"; proto = "tcp"; }
      { port = 443; from = "any"; proto = "tcp"; }
    ];
    allowedOutbound = [
      { port = 443; to = "any"; proto = "tcp"; }
    ];
    enableEgressFiltering = true;
    allowDNS = true;
    logDropped = true;
  };

  barbican.intrusionDetection = {
    enable = true;
    enableAIDE = true;
    enableAuditd = true;
    auditRules = [
      "-a always,exit -F arch=b64 -S execve -k exec"
      "-w /etc/passwd -p wa -k identity"
    ];
  };
}
```

### Library Helpers

```nix
let
  barbican = inputs.barbican;
in {
  # Network zone helpers for segmentation
  networking = barbican.lib.networkZones.mkZones {
    dmz = { subnet = "10.0.10.0/24"; vlan = 10; };
    backend = { subnet = "10.0.20.0/24"; vlan = 20; };
    monitoring = { subnet = "10.0.30.0/24"; vlan = 30; };
  };

  # PKI certificate generation scripts
  environment.systemPackages = [
    (barbican.lib.pki.mkCAScript { org = "MyOrg"; })
    (barbican.lib.pki.mkServerCertScript { ca = "/etc/ssl/ca"; })
  ];

  # Systemd hardening presets
  systemd.services.myapp = barbican.lib.systemdHardening.webService // {
    # ... your service config
  };
}
```

## Security Audit & Testing

Run self-contained NixOS VM tests to validate security controls:

```bash
# Run all security tests
nix build .#checks.x86_64-linux.all -L

# Run individual module tests
nix build .#checks.x86_64-linux.secure-users -L
nix build .#checks.x86_64-linux.hardened-ssh -L
nix build .#checks.x86_64-linux.kernel-hardening -L
nix build .#checks.x86_64-linux.secure-postgres -L
nix build .#checks.x86_64-linux.time-sync -L
nix build .#checks.x86_64-linux.intrusion-detection -L
nix build .#checks.x86_64-linux.vm-firewall -L
nix build .#checks.x86_64-linux.resource-limits -L

# Run audit with report generation
nix run .#audit
```

### Test Coverage

| Test | Controls | What It Validates |
|------|----------|-------------------|
| `secure-users` | CRT-001, CRT-002 | No empty passwords, no auto-login, SSH keys |
| `hardened-ssh` | CRT-010 | Strong ciphers, fail2ban, password auth disabled |
| `kernel-hardening` | MED-001 | ASLR, kptr_restrict, sysctl values |
| `secure-postgres` | CRT-003, CRT-011-013 | scram-sha-256, restricted listen, audit logs |
| `time-sync` | HIGH-011 | Chrony service, NTP sources |
| `intrusion-detection` | CRT-015, CRT-016 | Auditd rules, AIDE installation |
| `vm-firewall` | CRT-007, HIGH-005 | iptables rules, egress filtering |
| `resource-limits` | HIGH-001 | Core dumps blocked, ulimits |

The combined test suite generates a JSON audit report with compliance rate.

## Documentation

- [SECURITY.md](./SECURITY.md) - Security controls and audit procedures
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Architecture and development guide
- [.claudedocs/SECURITY_CONTROL_REGISTRY.md](./.claudedocs/SECURITY_CONTROL_REGISTRY.md) - Full NIST 800-53 control registry
- [.claudedocs/NIST_800_53_IMPLEMENTATION_GUIDE.md](./.claudedocs/NIST_800_53_IMPLEMENTATION_GUIDE.md) - Implementation guide with examples
- [.claudedocs/OAUTH_INTEGRATION.md](./.claudedocs/OAUTH_INTEGRATION.md) - OAuth/OIDC integration guide
- [API docs](https://docs.rs/barbican) - Full API reference

## License

Licensed under either of Apache License 2.0 or MIT license at your option.
