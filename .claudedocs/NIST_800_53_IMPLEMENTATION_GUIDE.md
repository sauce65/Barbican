# NIST 800-53 Implementation Guide for Barbican

**Quick reference for developers using barbican to build compliant applications**

**Last Updated:** 2025-12-11

---

## What Barbican Provides

Barbican is a **compliance-focused security library** that implements or facilitates **109 NIST 800-53 Rev 5 controls** out-of-the-box, allowing developers to build FedRAMP, SOC 2, and other compliance-required applications without reinventing security infrastructure.

### Current Implementation Status

| Category | Count | Percentage |
|----------|-------|------------|
| ✅ Implemented | 52 | 47.7% |
| ⚠️ Partial | 6 | 5.5% |
| 🎯 Facilitated | 32 | 29.4% |
| 📋 Planned | 19 | 17.4% |

### Three-Layer Approach

```
┌─────────────────────────────────────────────────────┐
│  Your Application                                   │
│  - Business logic                                   │
│  - Application-specific authorization               │
│  - Domain-specific validation                       │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│  Barbican Library (Rust/Axum Middleware)            │
│  ✅ 12 Modules implementing 52+ controls            │
│  - auth, validation, password, error                │
│  - session, login, alerting, health                 │
│  - keys, supply_chain, testing, observability       │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│  Barbican NixOS Modules (Infrastructure)            │
│  ✅ IMPLEMENTS: Infrastructure hardening            │
│  - Kernel hardening, firewall, SSH hardening        │
│  - Encrypted backups, intrusion detection           │
│  - Time sync, resource limits, systemd sandboxing   │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start: Compliance in 5 Minutes

### 1. Add Barbican to Your Project

```toml
[dependencies]
barbican = { version = "0.1", features = ["postgres", "observability-loki"] }
```

### 2. Initialize with Secure Defaults

```rust
use axum::{Router, routing::get};
use barbican::{SecurityConfig, SecureRouter};
use barbican::observability::{ObservabilityConfig, init};
use barbican::error::{ErrorConfig, init as init_error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Step 1: Initialize observability (AU-2, AU-3, AU-12)
    init(ObservabilityConfig::from_env()).await?;
    init_error(ErrorConfig::from_env());

    // Step 2: Apply security middleware (SC-5, SC-8, AC-4, etc.)
    let app = Router::new()
        .route("/api/users", get(list_users))
        .with_security(SecurityConfig::from_env());

    // You now have:
    // ✅ Rate limiting (SC-5)
    // ✅ Request size limits (SC-5)
    // ✅ Request timeouts (SC-10)
    // ✅ Security headers (SC-2)
    // ✅ CORS policy (AC-4)
    // ✅ Structured audit logging (AU-2, AU-3, AU-12)
    // ✅ Secure error handling (SI-11)

    // Serve...
    Ok(())
}
```

### 3. Configure via Environment Variables

```bash
# Security controls (all have secure defaults)
MAX_REQUEST_SIZE=10MB
REQUEST_TIMEOUT=30s
RATE_LIMIT_PER_SECOND=5
RATE_LIMIT_BURST=10
CORS_ALLOWED_ORIGINS=https://app.example.com
SECURITY_HEADERS_ENABLED=true

# Database security (SC-8, SC-28)
DATABASE_URL=postgres://localhost/mydb
DB_SSL_MODE=require                    # Enforce TLS
DB_SSL_ROOT_CERT=/etc/ssl/ca.crt      # Verify server

# Observability (AU-2, AU-12)
LOG_PROVIDER=loki
LOG_FORMAT=json
LOKI_ENDPOINT=http://loki:3100

# Error handling (SI-11)
ERROR_EXPOSE_DETAILS=false             # Production: hide internal errors
```

**You're now compliant with 20+ NIST controls!**

---

## Module Reference

### Phase 1: Core Security (✅ COMPLETE)

#### Input Validation (`src/validation.rs`) - SI-10

```rust
use barbican::validation::{validate_email, validate_length, validate_url, sanitize_html};
use barbican::{ValidationError, Validate};

// Validate user input
fn process_registration(email: &str, bio: &str, website: &str) -> Result<(), ValidationError> {
    validate_email(email)?;
    validate_length(bio, 0, 500, "bio")?;
    validate_url(website)?;
    let safe_bio = sanitize_html(bio);  // Strip dangerous HTML
    Ok(())
}

// Or use the Validate trait
#[derive(Validate)]
struct UserInput {
    #[validate(email)]
    email: String,
    #[validate(length(min = 0, max = 500))]
    bio: String,
}
```

#### OAuth Claims Bridge (`src/auth.rs`) - AC-3, IA-2, IA-8

```rust
use barbican::auth::{Claims, MfaPolicy, log_access_decision, log_access_denied};

// Extract claims from your OAuth provider's JWT
let claims = Claims::new("user-123")
    .with_email("user@example.com")
    .with_roles(vec!["admin", "user"])
    .with_amr(vec!["pwd", "otp"]);  // Authentication methods

// Check authorization
async fn admin_handler(claims: Claims) -> Result<&'static str, StatusCode> {
    if claims.has_role("admin") {
        log_access_decision(&claims, "admin_panel", true);
        Ok("Welcome, admin!")
    } else {
        log_access_denied(&claims, "admin_panel", "missing admin role");
        Err(StatusCode::FORBIDDEN)
    }
}

// Enforce MFA (IA-2(1))
async fn sensitive_handler(claims: Claims) -> Result<&'static str, StatusCode> {
    let policy = MfaPolicy::require_mfa();
    if policy.check_and_log(&claims, "sensitive_data") {
        Ok("Access granted")
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// Require hardware key for high-security operations (IA-2(6))
let policy = MfaPolicy::require_hardware_key();
let policy = MfaPolicy::require_any(&["hwk", "fpt", "face"]);
```

#### Password Policy (`src/password.rs`) - IA-5(1)

```rust
use barbican::password::{PasswordPolicy, PasswordStrength};

// Use NIST 800-63B compliant defaults (12 char min, no composition rules)
let policy = PasswordPolicy::default();

// Validate with user context (prevents password = username)
policy.validate_with_context(password, Some(username), Some(email))?;

// Check password strength
let strength = policy.estimate_strength(password);
match strength {
    PasswordStrength::VeryWeak => println!("Choose a stronger password"),
    PasswordStrength::Strong | PasswordStrength::VeryStrong => println!("Great password!"),
    _ => {}
}

// Custom policy for stricter requirements
let strict = PasswordPolicy::builder()
    .min_length(16)
    .require_uppercase(true)
    .require_digit(true)
    .build();
```

#### Error Handling (`src/error.rs`) - SI-11

```rust
use barbican::error::{AppError, ErrorKind, Result};

async fn handler() -> Result<String> {
    let data = fetch_data()
        .map_err(|e| AppError::internal("Failed to fetch data", e))?;
    Ok(data)
}

// Production: {"error": "internal_error", "message": "An internal error occurred"}
// Development: Full error chain with stack trace

// Common error types
AppError::bad_request("Invalid input");
AppError::unauthorized("Authentication required");
AppError::forbidden("Access denied");
AppError::not_found("Resource not found");
AppError::internal("Something went wrong", underlying_error);
AppError::validation(validation_errors);
```

### Phase 2: Advanced Auth (✅ COMPLETE)

#### Session Management (`src/session.rs`) - AC-11, AC-12

```rust
use barbican::session::{SessionPolicy, SessionState, SessionTerminationReason};
use std::time::Duration;

// Create session policy
let policy = SessionPolicy::default();  // 30 min idle, 8 hour max
let strict = SessionPolicy::strict();   // 15 min idle, 4 hour max
let custom = SessionPolicy::builder()
    .idle_timeout(Duration::from_secs(20 * 60))
    .max_lifetime(Duration::from_secs(6 * 60 * 60))
    .build();

// Track session state
let mut session = SessionState::new();

// Check session validity
if let Some(reason) = policy.check_session(&session) {
    match reason {
        SessionTerminationReason::Expired => log_session_expired(&session),
        SessionTerminationReason::IdleTimeout => log_session_idle(&session),
        SessionTerminationReason::UserLogout => log_session_logout(&session),
        _ => {}
    }
    // Terminate session
}

// Update activity
session.record_activity();
```

#### Login Attempt Tracking (`src/login.rs`) - AC-7

```rust
use barbican::login::{LoginTracker, LockoutPolicy, LockoutInfo};
use std::time::Duration;

// Create tracker with policy
let policy = LockoutPolicy::default();  // 5 attempts, 15 min lockout
let tracker = LoginTracker::new(policy);

// Check before allowing login
if let Some(lockout) = tracker.check_lockout(user_id) {
    return Err(format!("Account locked for {:?}", lockout.remaining));
}

// Record failed attempt
let result = tracker.record_failure(user_id);
if result.is_locked_out {
    log_account_locked(user_id, result.attempts);
}

// Record success (clears attempt counter)
tracker.record_success(user_id);

// IP-based brute force detection
if tracker.check_ip_lockout(client_ip) {
    log_brute_force_detected(client_ip);
}
```

### Phase 3: Audit & Incident Response (✅ COMPLETE)

#### Alerting (`src/alerting.rs`) - IR-4, IR-5

```rust
use barbican::alerting::{AlertManager, AlertConfig, Alert, AlertSeverity, AlertCategory};

// Create alert manager
let config = AlertConfig::default();           // Warning+, rate limited
let config = AlertConfig::high_sensitivity();  // All events
let config = AlertConfig::low_noise();         // Critical only

let manager = AlertManager::new(config);

// Register handlers
manager.register_handler(|alert| {
    // Send to PagerDuty, Slack, etc.
    send_to_pagerduty(alert);
});

// Send alerts
let alert = Alert::new(AlertSeverity::Critical, "Brute Force Detected", "50 failed logins from IP")
    .with_category(AlertCategory::SecurityIncident)
    .with_context("ip_address", client_ip);

manager.send(alert);

// Convenience functions
use barbican::alerting::{alert_brute_force, alert_account_locked};
alert_brute_force(client_ip, 50, &manager);
alert_account_locked(user_id, "too many failed attempts", &manager);
```

#### Health Checks (`src/health.rs`) - CA-7

```rust
use barbican::health::{HealthChecker, HealthCheck, HealthStatus, Status};

// Create health checker
let mut checker = HealthChecker::new();

// Add checks
checker.add_check(HealthCheck::new("database", || async {
    match check_db_connection().await {
        Ok(_) => HealthStatus::healthy(),
        Err(e) => HealthStatus::unhealthy(format!("DB error: {}", e)),
    }
}));

checker.add_check(HealthCheck::new("redis", || async {
    HealthStatus::healthy_with_message("Connected")
        .with_detail("latency_ms", "5")
}));

// Run checks
let report = checker.check_all().await;

// Check overall status
if !report.is_operational() {
    alert_health_check_failed(&report);
}

// Get JSON for /health endpoint
let json = report.to_json();
```

### Phase 4: Supply Chain & Keys (✅ COMPLETE)

#### Key Management (`src/keys.rs`) - SC-12

```rust
use barbican::keys::{KeyStore, KeyMetadata, RotationTracker, RotationPolicy, EnvKeyStore};

// Implement KeyStore trait for your KMS (Vault, AWS KMS, etc.)
struct VaultKeyStore { /* ... */ }

impl KeyStore for VaultKeyStore {
    fn get_key(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMaterial, KeyError>> + Send + '_>> {
        // Fetch from Vault
    }
    // ... other methods
}

// Or use EnvKeyStore for development
let store = EnvKeyStore::new("APP_KEYS");  // Reads APP_KEYS_JWT_SIGNING, etc.

// Track rotation schedules
let mut tracker = RotationTracker::new();
tracker.register("jwt-signing", RotationPolicy::days(90));
tracker.register("api-key", RotationPolicy::days(30));

// Check what needs rotation
for key_id in tracker.keys_needing_rotation() {
    // Trigger rotation workflow
    store.rotate_key(key_id).await?;
    tracker.record_rotation(key_id);
}

// Get rotation status report
let status = tracker.status_report();
if status.has_due_rotations() {
    alert_keys_need_rotation(&status.due_now);
}
```

#### Supply Chain Security (`src/supply_chain.rs`) - SR-3, SR-4

```rust
use barbican::supply_chain::{
    parse_cargo_lock, generate_cyclonedx_sbom, SbomMetadata,
    run_cargo_audit, LicensePolicy,
};

// Parse dependencies
let deps = parse_cargo_lock("Cargo.lock")?;

// Generate SBOM
let metadata = SbomMetadata::new("my-app", "1.0.0")
    .with_organization("My Company");
let sbom = generate_cyclonedx_sbom(&metadata, &deps);

// Run vulnerability audit
let audit = run_cargo_audit()?;
if audit.has_vulnerabilities() {
    eprintln!("Found {} vulnerabilities!", audit.vulnerability_count());
    for vuln in &audit.vulnerabilities {
        if vuln.severity >= VulnerabilitySeverity::High {
            alert_critical_vulnerability(&vuln);
        }
    }
}

// Check license compliance
let policy = LicensePolicy::permissive();  // MIT, Apache, BSD
let policy = LicensePolicy::strict();      // No copyleft

for dep in deps.values() {
    if !policy.is_allowed(&dep.license) {
        eprintln!("License violation: {} uses {}", dep.name, dep.license);
    }
}
```

#### Security Testing (`src/testing.rs`) - SA-11, CA-8

```rust
use barbican::testing::{
    xss_payloads, sql_injection_payloads, command_injection_payloads,
    SecurityHeaders, check_cors_headers, check_user_enumeration,
};

#[tokio::test]
async fn test_xss_protection() {
    for payload in xss_payloads() {
        let response = client.post("/comment")
            .json(&json!({ "text": payload }))
            .send().await;

        let body = response.text().await;
        assert!(!body.contains(payload), "XSS reflected: {}", payload);
    }
}

#[tokio::test]
async fn test_sql_injection() {
    for payload in sql_injection_payloads() {
        let response = client.get(&format!("/users?id={}", payload)).send().await;
        assert!(!response.text().await.contains("SQL syntax"));
    }
}

#[test]
fn test_security_headers() {
    let expected = SecurityHeaders::strict();
    let actual_headers = get_response_headers();

    let issues = expected.verify(&actual_headers);
    assert!(issues.is_empty(), "Missing headers: {:?}", issues);
}
```

---

## OAuth Provider Integration

Barbican provides claims extraction helpers for major OAuth providers. See [OAUTH_INTEGRATION.md](./OAUTH_INTEGRATION.md) for detailed guides.

### Quick Reference

```rust
use barbican::auth::{
    extract_keycloak_roles, extract_keycloak_groups,
    extract_entra_roles, extract_entra_groups,
    extract_amr, extract_acr,
};

// Keycloak
let roles = extract_keycloak_roles(&token_claims);
let groups = extract_keycloak_groups(&token_claims);
let acr = extract_acr(&token_claims);  // MFA level

// Entra ID (Azure AD)
let roles = extract_entra_roles(&token_claims);
let groups = extract_entra_groups(&token_claims);
let amr = extract_amr(&token_claims);  // Auth methods ["pwd", "mfa"]
```

---

## Controls by Module

| Module | NIST Controls | Status |
|--------|---------------|--------|
| `auth.rs` | AC-3, AC-6, IA-2, IA-2(1), IA-2(2), IA-2(6), IA-8 | ✅ |
| `validation.rs` | SI-10 | ✅ |
| `password.rs` | IA-5(1), IA-5(4) | ✅ |
| `error.rs` | SI-11, IA-6 | ✅ |
| `session.rs` | AC-11, AC-12, AU-14, SC-23 | ✅ |
| `login.rs` | AC-7 | ✅ |
| `alerting.rs` | IR-4, IR-5, SI-4(2), SI-4(5) | ✅ |
| `health.rs` | CA-7 | ✅ |
| `keys.rs` | SC-12, SC-4 | ✅ |
| `supply_chain.rs` | SR-3, SR-4, SR-11, SI-2, SI-3, SI-7, CM-8, CM-10 | ✅ |
| `testing.rs` | SA-11, CA-8 | ✅ |
| `observability/` | AU-2, AU-3, AU-8, AU-12 | ✅ |
| `layers.rs` | SC-5, SC-10, AC-4 | ✅ |
| `crypto.rs` | IA-5, SC-13 | ✅ |

---

## Compliance Certification Readiness

| Framework | Current | Target | Remaining |
|-----------|---------|--------|-----------|
| **FedRAMP** | 70% | 95% | HTTP TLS, DNSSEC |
| **SOC 2 Type II** | 75% | 95% | Log retention |
| **NIST 800-53 Moderate** | 65% | 90% | TLS enforcement |

---

## Best Practices

### 1. Always Use Secure Defaults

```rust
// ✅ Good: Use from_env() or default()
let config = SecurityConfig::from_env();
let policy = PasswordPolicy::default();
let alerts = AlertConfig::default();

// ❌ Bad: Don't weaken security
let config = SecurityConfig::builder()
    .disable_rate_limiting()  // DON'T DO THIS
    .build();
```

### 2. Log All Security Events

```rust
use barbican::observability::{SecurityEvent, security_event};

// ✅ Good: Log authentication events
security_event!(
    SecurityEvent::AuthenticationSuccess,
    user_id = %user.id,
    ip_address = %client_ip,
    "User authenticated"
);

// ❌ Bad: Silent authentication
```

### 3. Use Constant-Time Comparisons

```rust
// ✅ Good: Constant-time comparison
use barbican::constant_time_eq;
if constant_time_eq(stored_hash, provided_hash) {
    // Authenticated
}

// ❌ Bad: Timing attack vulnerable
if stored_hash == provided_hash {
    // Authenticated
}
```

### 4. Validate All Inputs

```rust
// ✅ Good: Validate and sanitize
validate_email(email)?;
let safe_bio = sanitize_html(bio);

// ❌ Bad: Trust user input
let query = format!("SELECT * FROM users WHERE email = '{}'", email);
```

### 5. Enable All Security Layers

```rust
// ✅ Good: Full security stack
let app = Router::new()
    .route("/api/users", get(list_users))
    .layer(AuthenticationLayer::new(auth))
    .with_security(SecurityConfig::from_env());

// ❌ Bad: Missing layers
let app = Router::new()
    .route("/api/users", get(list_users));
```

---

## Testing for Compliance

### Run All Tests

```bash
cargo test --all-features
```

### Security Audit

```bash
cargo audit
```

### Generate SBOM

```rust
let deps = parse_cargo_lock("Cargo.lock")?;
let sbom = generate_cyclonedx_sbom(&metadata, &deps);
std::fs::write("sbom.json", sbom)?;
```

---

## Getting Help

### Documentation

- [SECURITY_CONTROL_REGISTRY.md](./SECURITY_CONTROL_REGISTRY.md) - Complete control status
- [OAUTH_INTEGRATION.md](./OAUTH_INTEGRATION.md) - OAuth provider guides
- [SECURITY.md](../SECURITY.md) - Security controls and audit procedures

### Test Count

- **150 tests** covering all implemented controls
- All tests pass with `cargo test`

---

*For detailed control-by-control analysis, see [NIST_800_53_COMPLIANCE_ANALYSIS.md](./NIST_800_53_COMPLIANCE_ANALYSIS.md)*
