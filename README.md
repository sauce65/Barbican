# barbican

NIST 800-53 compliant security infrastructure for Axum applications. A pluggable, secure-by-default library providing 56+ security controls for building production-ready, compliance-ready web services.

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

Barbican provides 18 security modules covering 56+ NIST 800-53 controls:

### Compliance Configuration

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `compliance` | Unified compliance profiles (FedRAMP, SOC 2) - single source of truth | AC-7, AC-11, AC-12, AU-11, IA-2, IA-5, SC-8, SC-12, SC-28 |

### Infrastructure Layer

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `layers` | Security headers, rate limiting, CORS, timeouts | SC-5, SC-8, CM-6, AC-4 |
| `tls` | TLS/mTLS enforcement middleware | SC-8, SC-8(1), IA-3 |
| `audit` | Security-aware HTTP audit middleware with integrity protection | AU-2, AU-3, AU-9, AU-12, AU-14, AU-16 |
| `database` | SSL/TLS with VerifyFull default, connection pooling, health checks | SC-8, SC-28, IA-5 |
| `observability` | Structured logging, metrics, distributed tracing | AU-2, AU-3, AU-8, AU-12 |
| `observability::stack` | FedRAMP-compliant observability infrastructure generator | AU-9, AU-11, SC-8, SC-28, IR-4, IR-5 |

### Authentication & Authorization

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `auth` | OAuth/OIDC JWT claims, MFA policy enforcement | IA-2, IA-5, AC-2 |
| `jwt_secret` | JWT secret validation (entropy, weak patterns, policy) | IA-5, SC-12 |
| `password` | NIST 800-63B compliant password validation | IA-5(1) |
| `login` | Login attempt tracking, account lockout | AC-7 |
| `session` | Session management, idle timeout, termination | AC-11, AC-12, SC-10 |

### Operational Security

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `alerting` | Security incident alerting with rate limiting | IR-4, IR-5 |
| `health` | Health check framework with aggregation | CA-7 |
| `keys` | Key management with KMS integration traits | SC-12 |
| `secrets` | Secret detection scanner for embedded credentials | IA-5(7) |
| `supply_chain` | SBOM generation, license compliance, vulnerability audit | SR-3, SR-4 |
| `testing` | Security test utilities, header verification, header generation | SA-11, CA-8, SC-8, CM-6 |
| `integration` | Application integration helpers (profile detection, config builders) | - |

### Data Protection

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `encryption` | Field-level encryption for data at rest (AES-256-GCM) | SC-28 |
| `validation` | Input validation and sanitization | SI-10 |
| `error` | Secure error handling, no info leakage | SI-11, IA-6 |
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

### JWT Secret Validation (IA-5, SC-12)

```rust
use barbican::jwt_secret::{JwtSecretValidator, JwtSecretPolicy};
use barbican::compliance::config;

// Derive policy from compliance profile (recommended)
let policy = JwtSecretPolicy::for_compliance(config().profile);

// Or use environment-aware defaults
let policy = JwtSecretPolicy::for_environment("production");

// Validate a secret
let validator = JwtSecretValidator::new(policy);
validator.validate("my-jwt-secret")?;

// Generate a secure secret
let secret = JwtSecretValidator::generate_secure_secret(64);
```

### Security Headers (SC-8, CM-6)

```rust
use barbican::testing::SecurityHeaders;
use barbican::compliance::ComplianceProfile;

// Generate headers for API endpoints
let headers = SecurityHeaders::api();
for (name, value) in headers.to_header_pairs() {
    response.headers_mut().insert(name, value.parse().unwrap());
}

// Production headers with HSTS preload
let headers = SecurityHeaders::production();

// Compliance-aware headers
let headers = SecurityHeaders::for_compliance(ComplianceProfile::FedRampHigh);

// Verify headers on responses
let expected = SecurityHeaders::strict();
let issues = expected.verify(&response_headers);
assert!(issues.is_empty());
```

### Security Testing (SA-11, CA-8)

```rust
use barbican::testing::{xss_payloads, sql_injection_payloads, SecurityHeaders};

// Fuzz test your endpoints
for payload in xss_payloads() {
    let response = client.post("/api/comment").body(payload).send().await?;
    assert!(!response.text().contains(payload)); // Should be escaped
}

// Validate security headers on responses
let expected = SecurityHeaders::default();
let issues = expected.verify(&response_headers);
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

### Integration Helpers

```rust
use barbican::integration::{
    profile_from_env,
    database_config_for_profile,
    validate_database_config,
    SbomBuilder,
    run_security_audit,
};
use barbican::compliance::ComplianceProfile;

// Detect compliance profile from environment (DPE_COMPLIANCE_PROFILE or COMPLIANCE_PROFILE)
let profile = profile_from_env(); // Returns ComplianceProfile

// Build database config based on compliance requirements
let db_config = database_config_for_profile(
    "postgres://localhost/mydb",
    ComplianceProfile::FedRampModerate,
);

// Validate database config meets compliance requirements
validate_database_config(&db_config, ComplianceProfile::FedRampHigh)?;

// Build SBOM with fluent API
let sbom = SbomBuilder::new("my-app", "1.0.0")
    .cargo_lock("Cargo.lock")?
    .license_policy(LicensePolicy::default())
    .build()?;

// Run comprehensive security audit
let report = run_security_audit("Cargo.lock", LicensePolicy::default())?;
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

Barbican implements 56 NIST 800-53 Rev 5 controls and facilitates 50+ additional controls. The library provides both runtime security enforcement and compliance artifact generation for auditors.

**Control Families Covered:**
- **Access Control (AC)**: AC-2, AC-3, AC-4, AC-6, AC-7, AC-11, AC-12
- **Audit (AU)**: AU-2, AU-3, AU-8, AU-9, AU-12, AU-14, AU-16
- **Security Assessment (CA)**: CA-7, CA-8
- **Identification & Authentication (IA)**: IA-2, IA-2(1), IA-3, IA-5, IA-5(1), IA-5(7), IA-6
- **Incident Response (IR)**: IR-4, IR-5
- **System & Communications (SC)**: SC-5, SC-8, SC-8(1), SC-10, SC-12, SC-13, SC-23, SC-28
- **System & Information Integrity (SI)**: SI-10, SI-11
- **Supply Chain (SR)**: SR-3, SR-4
- **System & Services Acquisition (SA)**: SA-11

**Framework Support:**
- **NIST SP 800-53 Rev 5**: 56 controls implemented
- **NIST SP 800-63B**: Password policy compliance
- **SOC 2 Type II**: ~85% of applicable criteria
- **FedRAMP Moderate**: ~80% ready (up from 75%)
- **OAuth 2.0 / OIDC**: JWT claims extraction with MFA support
- **OWASP Top 10**: Input validation, secure error handling

**Compliance Artifact Tests:**
- 29 artifact-generating control tests (Phase 1 complete)
- JSON-serialized, HMAC-signed audit evidence
- Covers: AU-8, AU-9, AU-14, AU-16, IA-5, IA-5(7), IA-6, SC-8, SC-13, SC-23, SC-28, and more

See `.claudedocs/SECURITY_CONTROL_REGISTRY.md` for detailed control mappings.
See `.claudedocs/NIST_800_53_CROSSWALK.md` for auditor-friendly control-to-code mappings.

---

## Nix Flake Integration

Barbican is a Nix flake that provides both Rust middleware (as a crate) and NixOS infrastructure modules. Client applications can integrate Barbican at multiple levels:

### Flake Outputs

```
barbican
├── packages
│   ├── default (barbican)           # Rust library package
│   └── observability-stack-generator # FedRAMP observability generator
├── nixosModules
│   ├── minimal / standard / hardened # Security profiles
│   ├── secureUsers, hardenedSSH, ...  # Individual modules (14 total)
│   └── all                           # All modules combined
├── lib
│   ├── networkZones                  # Network segmentation helpers
│   ├── pki                          # Certificate generation scripts
│   └── systemdHardening             # Service sandboxing presets
├── apps
│   ├── audit                        # Security audit runner
│   ├── vault-dev                    # Start Vault PKI dev server
│   ├── vault-cert-*                 # Certificate issuance (server, client, postgres)
│   ├── observability-stack          # Generate observability infrastructure
│   └── test-*                       # Individual VM test runners
├── checks
│   ├── flake-lock-check             # Verify flake input integrity
│   ├── cargo-audit                  # Rust dependency vulnerabilities
│   └── secure-users, hardened-ssh...# NixOS VM security tests (10 total)
└── templates
    └── microvm-stack                # Secure MicroVM template
```

### Integration Levels

| Level | What You Get | Use Case |
|-------|--------------|----------|
| **Rust Crate** | Axum middleware, compliance modules | Application security |
| **NixOS Modules** | System hardening, service config | Infrastructure security |
| **Library Helpers** | Nix functions for PKI, networking | Configuration helpers |
| **Observability Stack** | Loki, Prometheus, Grafana configs | FedRAMP-compliant monitoring |
| **Vault PKI** | Certificate authority, mTLS certs | Zero-trust networking |

### Basic Flake Integration

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    barbican.url = "github:your-org/barbican";
  };

  outputs = { self, nixpkgs, barbican, ... }: {
    # For NixOS systems
    nixosConfigurations.myserver = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        barbican.nixosModules.hardened  # Apply hardened security profile
        ./configuration.nix
      ];
    };

    # For development shells (access to barbican tools)
    devShells.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.mkShell {
      packages = [
        barbican.packages.x86_64-linux.observability-stack-generator
      ];
    };
  };
}
```

---

## NixOS Infrastructure Modules

Barbican provides 14 NixOS modules implementing NIST 800-53 controls at the infrastructure level. These can be used with NixOS, MicroVMs, or any system using the Nix module system.

### Security Profiles

Pre-configured module combinations for common deployment scenarios:

| Profile | Use Case | Modules Enabled |
|---------|----------|-----------------|
| `minimal` | Development, testing | secureUsers, kernelHardening (basic) |
| `standard` | Staging, internal prod | + hardenedSSH, timeSync, resourceLimits |
| `hardened` | Production, FedRAMP | All modules with strict defaults |

```nix
# Use a profile
{ imports = [ barbican.nixosModules.hardened ]; }

# Or import individual modules
{ imports = [
    barbican.nixosModules.secureUsers
    barbican.nixosModules.hardenedSSH
    barbican.nixosModules.kernelHardening
  ];
}
```

### Available Modules

#### Core Security

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `secureUsers` | No empty passwords, SSH-only auth, login banners | AC-2, IA-5 |
| `hardenedSSH` | Strong ciphers, fail2ban, key-only auth, MaxAuthTries | AC-17, SC-8 |
| `kernelHardening` | Sysctl hardening, ASLR, kptr_restrict, audit | SC-3, SI-16 |
| `resourceLimits` | Cgroups, ulimits, core dump prevention | SC-5, SI-17 |
| `systemdHardening` | Service sandboxing (PrivateTmp, NoNewPrivileges, etc.) | SC-39, CM-7 |

#### Network Security

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `hardenedNginx` | NIST SP 800-52B ciphers, TLS 1.2+, mTLS, rate limiting | SC-8, SC-8(1), IA-3, SC-5 |
| `vmFirewall` | Network segmentation, egress filtering, drop logging | SC-7, AC-4 |

#### Data Protection

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `securePostgres` | scram-sha-256, SSL/TLS, audit logging, restricted listen | SC-8, SC-28, AU-12 |
| `databaseBackup` | Encrypted automated backups with GPG | CP-9, SC-28 |
| `secretsManagement` | sops-nix integration for secrets | SC-12, SC-28 |
| `vaultPki` | HashiCorp Vault PKI for mTLS certificates | SC-12, SC-17, IA-5(2) |

#### Monitoring & Detection

| Module | Description | NIST Controls |
|--------|-------------|---------------|
| `intrusionDetection` | AIDE file integrity, auditd rules | SI-4, AU-2 |
| `observabilityAuth` | Loki/Prometheus/Grafana authentication | AC-2, AU-9 |
| `timeSync` | Chrony NTP with secure servers (Cloudflare, NIST) | AU-8 |

### Hardened Nginx Reverse Proxy

The `hardenedNginx` module provides a production-ready reverse proxy with:

- **TLS 1.2+ only** with NIST SP 800-52B cipher suites
- **mTLS support** (disabled, optional, or required modes)
- **Rate limiting** per-IP with separate limits for auth endpoints
- **Security headers** (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- **Structured JSON logging** with security fields
- **Systemd hardening** (sandboxed, least privilege)

```nix
barbican.nginx = {
  enable = true;
  serverName = "api.example.com";
  fedRampHigh = true;  # Stricter cipher suites

  tls = {
    certPath = "/var/lib/acme/api.example.com/cert.pem";
    keyPath = "/var/lib/acme/api.example.com/key.pem";
    ocspStapling = true;
  };

  mtls = {
    mode = "required";  # "disabled", "optional", or "required"
    caCertPath = "/etc/ssl/ca-chain.pem";
  };

  rateLimit = {
    enable = true;
    requestsPerSecond = 10;
    authRequestsPerSecond = 3;  # Stricter for /login, /auth
    burst = 20;
  };

  upstream = {
    address = "127.0.0.1";
    port = 3000;
  };
};
```

### Vault PKI Integration

The `vaultPki` module integrates HashiCorp Vault for automated certificate management:

```nix
barbican.vaultPki = {
  enable = true;
  vaultAddr = "https://vault.internal:8200";

  # Automatic certificate renewal
  autoRenew = {
    enable = true;
    serverCert = {
      role = "server";
      commonName = "api.example.com";
      outputDir = "/var/lib/certs/server";
    };
  };
};
```

**CLI Tools** (available in `nix develop` or via `nix run`):

```bash
# Start Vault dev server with PKI configured
nix run .#vault-dev

# Issue certificates
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=barbican-dev

nix run .#vault-cert-server -- myserver.local
nix run .#vault-cert-client -- worker-1
nix run .#vault-cert-postgres
nix run .#vault-ca-chain
```

### Module Configuration Examples

**Firewall with Egress Filtering:**

```nix
barbican.vmFirewall = {
  enable = true;
  defaultPolicy = "drop";
  allowedInbound = [
    { port = 22; from = "10.0.0.0/8"; proto = "tcp"; }
    { port = 443; from = "any"; proto = "tcp"; }
  ];
  allowedOutbound = [
    { port = 443; to = "any"; proto = "tcp"; }  # HTTPS only
  ];
  enableEgressFiltering = true;
  allowDNS = true;
  logDropped = true;
};
```

**Intrusion Detection:**

```nix
barbican.intrusionDetection = {
  enable = true;
  enableAIDE = true;
  enableAuditd = true;
  enableProcessAccounting = true;
  auditRules = [
    "-a always,exit -F arch=b64 -S execve -k exec"
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/shadow -p wa -k identity"
  ];
};
```

**Secure PostgreSQL:**

```nix
barbican.securePostgres = {
  enable = true;
  requireSSL = true;
  passwordEncryption = "scram-sha-256";
  listenAddresses = "127.0.0.1";  # Local only
  enableAuditLog = true;
  maxConnections = 100;
};
```

---

## Library Helpers

Barbican exports Nix library functions for common security patterns:

### Network Zones

```nix
let
  zones = barbican.lib.networkZones.mkZones {
    dmz = { subnet = "10.0.10.0/24"; vlan = 10; };
    backend = { subnet = "10.0.20.0/24"; vlan = 20; };
    monitoring = { subnet = "10.0.30.0/24"; vlan = 30; };
  };
in {
  networking.vlans = zones.vlans;
  networking.firewall.extraCommands = zones.firewallRules;
}
```

### PKI Scripts

```nix
environment.systemPackages = [
  (barbican.lib.pki.mkCAScript { org = "MyOrg"; })
  (barbican.lib.pki.mkServerCertScript { ca = "/etc/ssl/ca"; })
];
```

### Systemd Hardening Presets

```nix
systemd.services.myapp = barbican.lib.systemdHardening.webService // {
  description = "My Application";
  serviceConfig.ExecStart = "${myapp}/bin/myapp";
};
# Applies: PrivateTmp, ProtectSystem=strict, NoNewPrivileges, etc.
```

---

## Observability Stack Generator

Generate FedRAMP-compliant observability infrastructure with Docker Compose:

```bash
# Interactive setup
nix run .#observability-init

# Or direct generation
nix run .#observability-stack -- \
  --app-name my-app \
  --app-port 3000 \
  --output ./observability \
  --profile fedramp-moderate
```

### Generated Files (21 total)

| Directory | Files | Purpose |
|-----------|-------|---------|
| `loki/` | `loki-config.yml`, `tenant-limits.yml` | Multi-tenant log aggregation |
| `prometheus/` | `prometheus.yml`, `web.yml`, `rules/security-alerts.yml` | Metrics with TLS, 15+ alerts |
| `grafana/` | `grafana.ini`, datasources, dashboards | OIDC SSO, security dashboard |
| `alertmanager/` | `alertmanager.yml`, `web.yml` | Alert routing with TLS |
| `scripts/` | `gen-certs.sh`, `backup-audit-logs.sh`, `health-check.sh` | Operations |
| `docs/` | `FEDRAMP_CONTROLS.md`, `SSO_SETUP.md`, `OPERATIONS.md` | Compliance docs |
| Root | `docker-compose.yml`, `.env.example` | Container deployment |

### Compliance Profiles

| Profile | Log Retention | mTLS | MFA | Container Security |
|---------|---------------|------|-----|-------------------|
| `fedramp-low` | 30 days | No | No | Basic |
| `fedramp-moderate` | 90 days | No | Yes | Read-only FS |
| `fedramp-high` | 365 days | Yes | Yes | Read-only + seccomp |
| `soc2` | 90 days | No | Yes | Read-only FS |

**FedRAMP Controls Implemented (20):** AU-2, AU-3, AU-4, AU-5, AU-6, AU-9, AU-11, AU-12, SC-8, SC-13, SC-28, IA-2, IA-2(1), AC-2, AC-3, AC-6, CP-9, IR-4, IR-5, SI-4

---

## Nix Apps

All apps can be run with `nix run .#<app-name>`:

### Security Audit

```bash
nix run .#audit  # Run all NixOS VM security tests with report
```

### Vault PKI

```bash
nix run .#vault-dev            # Start Vault dev server with PKI
nix run .#vault-cert-server    # Issue server certificate
nix run .#vault-cert-client    # Issue mTLS client certificate
nix run .#vault-cert-postgres  # Issue PostgreSQL certificate
nix run .#vault-ca-chain       # Export CA chain
```

### Observability

```bash
nix run .#observability-init   # Interactive stack setup
nix run .#observability-stack  # Generate with CLI args
```

### Individual Test Runners

```bash
nix run .#test-secure-users
nix run .#test-hardened-ssh
nix run .#test-kernel-hardening
nix run .#test-secure-postgres
nix run .#test-time-sync
nix run .#test-intrusion-detection
nix run .#test-vm-firewall
nix run .#test-resource-limits
nix run .#test-vault-pki
```

---

## Security Audit & Testing

### Flake Checks

Run all security validations with a single command:

```bash
nix flake check        # Run all checks (CI-friendly)
nix run .#audit        # Run VM tests with audit report
```

### Check Categories

| Check | Type | What It Validates |
|-------|------|-------------------|
| `flake-lock-check` | Static | All flake inputs have content-addressed hashes |
| `cargo-audit` | Static | No known vulnerabilities in Rust dependencies |
| `cargo-lock-check` | Static | Cargo.lock exists and is valid |
| `secure-users` | VM Test | No empty passwords, SSH-only auth |
| `hardened-ssh` | VM Test | Strong ciphers, fail2ban, key-only auth |
| `hardened-nginx` | VM Test | TLS 1.2+, mTLS, rate limiting, headers |
| `kernel-hardening` | VM Test | ASLR, kptr_restrict, sysctl hardening |
| `secure-postgres` | VM Test | scram-sha-256, SSL, restricted listen |
| `time-sync` | VM Test | Chrony NTP with secure servers |
| `intrusion-detection` | VM Test | Auditd rules, AIDE file integrity |
| `vm-firewall` | VM Test | Egress filtering, drop logging |
| `resource-limits` | VM Test | Core dumps blocked, ulimits |
| `vault-pki` | VM Test | PKI setup, certificate issuance |

### Running Individual Tests

```bash
# Build and run specific VM test
nix build .#checks.x86_64-linux.hardened-nginx -L

# Or use the app runners
nix run .#test-hardened-nginx
```

The combined test suite generates a JSON audit report with compliance rate.

## Documentation

- [SECURITY.md](./SECURITY.md) - Security controls and audit procedures
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Architecture and development guide
- [.claudedocs/SECURITY_CONTROL_REGISTRY.md](./.claudedocs/SECURITY_CONTROL_REGISTRY.md) - Full NIST 800-53 control registry
- [.claudedocs/NIST_800_53_CROSSWALK.md](./.claudedocs/NIST_800_53_CROSSWALK.md) - Auditor-friendly control-to-code crosswalk
- [.claudedocs/NIST_800_53_IMPLEMENTATION_GUIDE.md](./.claudedocs/NIST_800_53_IMPLEMENTATION_GUIDE.md) - Implementation guide with examples
- [.claudedocs/OAUTH_INTEGRATION.md](./.claudedocs/OAUTH_INTEGRATION.md) - OAuth/OIDC integration guide
- [API docs](https://docs.rs/barbican) - Full API reference

## License

Licensed under either of Apache License 2.0 or MIT license at your option.
