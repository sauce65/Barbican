# NIST 800-53 Rev 5 Control Crosswalk

## Purpose

This document provides auditors with a direct mapping from NIST 800-53 controls to their
implementation locations in the Barbican codebase. Each entry includes:

- **Control ID**: NIST 800-53 control identifier
- **File:Line**: Exact source location (click to navigate in IDE)
- **Function/Struct**: Specific implementation artifact
- **Test**: Verification test name
- **Verification Steps**: How to verify the control is implemented

---

## Quick Navigation

| Family | Controls |
|--------|----------|
| [Access Control (AC)](#access-control-ac) | AC-3, AC-4, AC-6, AC-7, AC-11, AC-12 |
| [Audit (AU)](#audit-and-accountability-au) | AU-2, AU-3, AU-8, AU-12, AU-14, AU-16 |
| [Assessment (CA)](#assessment-authorization-monitoring-ca) | CA-7, CA-8 |
| [Configuration (CM)](#configuration-management-cm) | CM-6, CM-8, CM-10 |
| [Identification (IA)](#identification-and-authentication-ia) | IA-2, IA-5, IA-6, IA-8 |
| [Incident Response (IR)](#incident-response-ir) | IR-4, IR-5 |
| [System Protection (SC)](#system-and-communications-protection-sc) | SC-5, SC-8, SC-10, SC-12, SC-13, SC-23 |
| [System Integrity (SI)](#system-and-information-integrity-si) | SI-2, SI-3, SI-4, SI-7, SI-10, SI-11 |
| [Supply Chain (SR)](#supply-chain-risk-management-sr) | SR-3, SR-4, SR-11 |

---

## Access Control (AC)

### AC-3: Access Enforcement

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:150-220` |
| **Function** | `Claims::has_role()`, `Claims::has_scope()`, `Claims::has_group()` |
| **Test** | `cargo test test_claims_roles` |
| **Verification** | Check that role/scope checks gate access to protected resources |

```rust
// src/auth.rs:183-195
pub fn has_role(&self, role: &str) -> bool {
    self.roles.iter().any(|r| r == role)
}

pub fn has_scope(&self, scope: &str) -> bool {
    self.scopes.iter().any(|s| s == scope)
}
```

### AC-4: Information Flow Enforcement

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/layers.rs:115-145` |
| **Function** | `build_cors_layer()` |
| **Config** | `src/config.rs:52-56` (`cors_origins`) |
| **Test** | `cargo test test_validator_security_layers_cors_permissive` |
| **Verification** | Verify CORS policy restricts cross-origin requests to allowlist |

```rust
// src/layers.rs:124-145
fn build_cors_layer(config: &SecurityConfig) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
        .max_age(std::time::Duration::from_secs(3600));

    if config.cors_is_restrictive() {
        base  // Same-origin only
    } else if config.cors_is_permissive() {
        base.allow_origin(Any)  // Development only!
    } else {
        base.allow_origin(origins).allow_credentials(true)
    }
}
```

### AC-6: Least Privilege

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:183-210` |
| **Function** | `Claims::has_role()`, `Claims::has_scope()` |
| **Test** | `cargo test test_has_role` |
| **Verification** | Verify minimum necessary roles/scopes are checked before access |

### AC-7: Unsuccessful Logon Attempts

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/login.rs:1-350` |
| **Struct** | `LoginTracker`, `LockoutPolicy` |
| **Test** | `cargo test test_lockout` |
| **Verification** | Verify account lockout after N failed attempts |

```rust
// src/login.rs:55-75
pub struct LockoutPolicy {
    pub max_attempts: u32,           // Default: 3
    pub lockout_duration: Duration,  // Default: 30 minutes
    pub attempt_window: Duration,    // Default: 15 minutes
}
```

### AC-11: Session Lock (Idle Timeout)

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:47-80` |
| **Function** | `SessionPolicy::is_idle_timeout_exceeded()` |
| **Config** | `src/compliance/profile.rs:191-200` (`idle_timeout()`) |
| **Test** | `cargo test test_idle_timeout` |
| **Verification** | Verify sessions expire after inactivity period |

```rust
// src/session.rs:128-135
pub fn is_idle_timeout_exceeded(&self, session: &SessionState) -> bool {
    let idle_duration = Instant::now().duration_since(session.last_activity);
    idle_duration > self.idle_timeout
}
```

### AC-12: Session Termination

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:47-120` |
| **Function** | `SessionPolicy::is_absolute_timeout_exceeded()` |
| **Config** | `src/compliance/profile.rs:180-189` (`session_timeout()`) |
| **Test** | `cargo test test_session_termination` |
| **Verification** | Verify sessions terminate after absolute timeout |

```rust
// src/session.rs:120-127
pub fn is_absolute_timeout_exceeded(&self, session: &SessionState) -> bool {
    let session_age = Instant::now().duration_since(session.created_at);
    session_age > self.absolute_timeout
}
```

---

## Audit and Accountability (AU)

### AU-2: Audit Events

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/observability/events.rs:32-91` |
| **Struct** | `SecurityEvent` enum (25+ events) |
| **HTTP Middleware** | `src/audit.rs:65-107` |
| **Test** | `cargo test test_event_categories` |
| **Verification** | Verify all security-relevant events are captured |

```rust
// src/observability/events.rs:37-91
pub enum SecurityEvent {
    AuthenticationSuccess,
    AuthenticationFailure,
    Logout,
    SessionCreated,
    SessionDestroyed,
    AccessGranted,
    AccessDenied,
    UserRegistered,
    UserModified,
    // ... 16 more events
}
```

### AU-3: Content of Audit Records

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/observability/events.rs:220-293` |
| **Macro** | `security_event!` |
| **HTTP Audit** | `src/audit.rs:109-191` |
| **Record Struct** | `src/audit.rs:259-282` (`AuditRecord`) |
| **Test** | `cargo test test_event_severity` |
| **Verification** | Verify records contain: who, what, when, where, outcome |

Required AU-3 fields captured:
- **Who**: `user_id` field in `audit_middleware`
- **What**: `security_event` type + `path`
- **When**: Automatic timestamp via `tracing`
- **Where**: `client_ip`, `path`
- **Outcome**: `status` code, `AuditOutcome` enum

```rust
// src/audit.rs:259-282
pub struct AuditRecord {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub source_ip: String,
    pub details: Option<String>,
}
```

### AU-8: Time Stamps

| Aspect | Location |
|--------|----------|
| **Implementation** | Automatic via `tracing` crate |
| **Format** | ISO 8601 / RFC 3339 |
| **Test** | All event logs include timestamps |
| **Verification** | Check any log output for timestamp field |

### AU-12: Audit Record Generation

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/observability/events.rs:249-293` |
| **Macro** | `security_event!` |
| **HTTP Middleware** | `src/audit.rs:65-107` (`audit_middleware`) |
| **Test** | `cargo test test_audit_outcome_display` |
| **Verification** | Verify events are generated at runtime |

```rust
// Usage example
security_event!(
    SecurityEvent::AuthenticationFailure,
    user_id = %email,
    ip_address = %client_ip,
    "Authentication failed"
);
```

### AU-14: Session Audit

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:180-220` |
| **Events** | `SessionCreated`, `SessionDestroyed` |
| **Test** | `cargo test test_session_state_creation` |
| **Verification** | Verify session lifecycle events are logged |

### AU-16: Cross-Organizational Audit

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/audit.rs:193-212` |
| **Function** | `extract_or_generate_correlation_id()` |
| **Headers** | `X-Correlation-ID`, `X-Request-ID` |
| **Test** | `cargo test test_generate_request_id` |
| **Verification** | Verify correlation IDs propagate across service boundaries |

```rust
// src/audit.rs:193-202
fn extract_or_generate_correlation_id(request: &Request<Body>) -> String {
    request
        .headers()
        .get("x-correlation-id")
        .or_else(|| request.headers().get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(generate_request_id)
}
```

---

## Assessment, Authorization, Monitoring (CA)

### CA-7: Continuous Monitoring

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/health.rs:1-350` |
| **Struct** | `HealthChecker`, `HealthCheck`, `HealthReport` |
| **Test** | `cargo test test_health_checker_all_healthy` |
| **Verification** | Verify health checks run continuously and report status |

### CA-8: Penetration Testing

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/testing.rs:1-450` |
| **Functions** | `xss_payloads()`, `sql_injection_payloads()`, `command_injection_payloads()` |
| **Test** | `cargo test test_xss_payloads_not_empty` |
| **Verification** | Use provided payloads to test application endpoints |

---

## Configuration Management (CM)

### CM-6: Configuration Settings

| Aspect | Location |
|--------|----------|
| **Secure Defaults** | `src/config.rs:65-77` (`Default` impl) |
| **Security Headers** | `src/layers.rs:75-113` |
| **Compliance Validation** | `src/compliance/validation.rs:493-571` |
| **Test** | `cargo test test_validator_security_layers_headers_disabled` |
| **Verification** | Verify secure defaults are applied |

Security headers implemented:
- `Strict-Transport-Security` (HSTS): 1 year, includeSubDomains
- `X-Content-Type-Options`: nosniff
- `X-Frame-Options`: DENY
- `Content-Security-Policy`: default-src 'none'
- `Cache-Control`: no-store, no-cache, must-revalidate, private
- `X-XSS-Protection`: 0 (disabled, CSP preferred)

```rust
// src/config.rs:65-77
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_request_size: 1024 * 1024,      // 1MB
            request_timeout: Duration::from_secs(30),
            rate_limit_per_second: 5,
            rate_limit_burst: 10,
            rate_limit_enabled: true,
            cors_origins: Vec::new(),           // Restrictive
            security_headers_enabled: true,
            tracing_enabled: true,
        }
    }
}
```

### CM-8: System Component Inventory

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:200-280` |
| **Function** | `generate_cyclonedx_sbom()` |
| **Test** | `cargo test test_generate_sbom` |
| **Verification** | Generate SBOM and verify all dependencies listed |

### CM-10: Software Usage Restrictions

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:100-180` |
| **Struct** | `LicensePolicy` |
| **Test** | `cargo test test_license_policy_strict` |
| **Verification** | Verify license compliance checking |

---

## Identification and Authentication (IA)

### IA-2: Identification and Authentication

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:1-400` |
| **Struct** | `Claims` |
| **MFA Policy** | `src/auth.rs:420-600` (`MfaPolicy`) |
| **Test** | `cargo test test_claims_*` |
| **Verification** | Verify JWT claims extraction and validation |

### IA-2(1): MFA for Privileged Accounts

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:449-600` |
| **Struct** | `MfaPolicy` |
| **Function** | `MfaPolicy::is_satisfied()` |
| **Test** | `cargo test test_mfa_policy_require_mfa` |
| **Verification** | Verify MFA required for privileged operations |

```rust
// src/auth.rs:500-520
pub fn is_satisfied(&self, claims: &Claims) -> bool {
    match self {
        MfaPolicy::None => true,
        MfaPolicy::RequireAny => claims.has_mfa(),
        MfaPolicy::RequireHardware => claims.has_hardware_mfa(),
        MfaPolicy::RequireAcrLevel(min) => claims.acr_level() >= *min,
    }
}
```

### IA-5(1): Password-Based Authentication

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/password.rs:1-400` |
| **Struct** | `PasswordPolicy` |
| **Config** | `src/compliance/profile.rs:154-166` (`min_password_length()`) |
| **Test** | `cargo test test_length_validation` |
| **Verification** | Verify password policy meets NIST 800-63B |

```rust
// src/password.rs:45-65
pub struct PasswordPolicy {
    pub min_length: usize,           // Default: 12 (NIST 800-63B)
    pub max_length: usize,           // Default: 128
    pub check_common: bool,          // Default: true
    pub check_context: bool,         // Default: true (username/email in password)
    pub blocked_passwords: Vec<String>,
}
```

### IA-6: Authentication Feedback

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/error.rs:1-300` |
| **Struct** | `AppError` |
| **Config** | `ErrorConfig::production_mode()` |
| **Test** | `cargo test test_error_display` |
| **Verification** | Verify error messages don't leak sensitive info |

### IA-8: Non-Organizational Users

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:250-400` |
| **Functions** | Provider-specific claim extraction |
| **Test** | `cargo test test_keycloak_role_extraction` |
| **Verification** | Verify OAuth/OIDC claims from external IdPs |

---

## Incident Response (IR)

### IR-4: Incident Handling

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/alerting.rs:1-550` |
| **Struct** | `AlertManager`, `Alert` |
| **Test** | `cargo test test_alert_manager_basic` |
| **Verification** | Verify alerts trigger on security events |

### IR-5: Incident Monitoring

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/alerting.rs:400-550` |
| **Function** | `AlertManager::register_handler()` |
| **Test** | `cargo test test_alert_handler` |
| **Verification** | Verify real-time alert handlers receive events |

---

## System and Communications Protection (SC)

### SC-5: Denial of Service Protection

| Aspect | Location |
|--------|----------|
| **Rate Limiting** | `src/layers.rs:67-73` |
| **Body Size Limit** | `src/layers.rs:63-65` |
| **Request Timeout** | `src/layers.rs:56-61` |
| **Config** | `src/config.rs:36-50` |
| **Test** | `cargo test test_validator_security_layers_rate_limit_disabled` |
| **Verification** | Verify rate limits and size limits are enforced |

```rust
// src/layers.rs:56-73
// SC-5: Denial of Service Protection - Request timeout
router = router.layer(TimeoutLayer::with_status_code(
    StatusCode::REQUEST_TIMEOUT,
    config.request_timeout,
));

// SC-5: Body size limit
router = router.layer(RequestBodyLimitLayer::new(config.max_request_size));

// SC-5: Rate limiting
if config.rate_limit_enabled {
    let rate_limit_config = GovernorConfigBuilder::default()
        .per_second(config.rate_limit_per_second)
        .burst_size(config.rate_limit_burst)
        .finish();
    router = router.layer(GovernorLayer::new(rate_limit_config));
}
```

### SC-8: Transmission Confidentiality

| Aspect | Location |
|--------|----------|
| **HSTS Header** | `src/layers.rs:80-82` |
| **Database TLS** | `src/database.rs:100-150` |
| **Config** | `src/compliance/profile.rs:108-113` (`requires_tls()`) |
| **Test** | SSL mode tests |
| **Verification** | Verify HTTPS enforcement and TLS configuration |

```rust
// src/layers.rs:80-82
.layer(SetResponseHeaderLayer::overriding(
    header::STRICT_TRANSPORT_SECURITY,
    HeaderValue::from_static("max-age=31536000; includeSubDomains"),
))
```

### SC-10: Network Disconnect

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:47-80` |
| **Function** | `SessionPolicy::is_idle_timeout_exceeded()` |
| **Test** | `cargo test test_session_termination` |
| **Verification** | Verify sessions terminate after inactivity |

### SC-12: Cryptographic Key Management

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/keys.rs:1-450` |
| **Trait** | `KeyStore` |
| **Struct** | `RotationTracker`, `RotationPolicy` |
| **Config** | `src/compliance/profile.rs:130-140` (`key_rotation_interval()`) |
| **Test** | `cargo test test_rotation_tracker_*` |
| **Verification** | Verify key rotation policy enforcement |

### SC-13: Cryptographic Protection

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/crypto.rs:1-100` |
| **Function** | `constant_time_eq()`, `constant_time_str_eq()` |
| **Test** | `cargo test test_constant_time_eq_*` |
| **Verification** | Verify constant-time comparison prevents timing attacks |

### SC-23: Session Authenticity

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:30-150` |
| **Struct** | `SessionState` |
| **Test** | `cargo test test_session_state_creation` |
| **Verification** | Verify session state integrity tracking |

---

## System and Information Integrity (SI)

### SI-2: Flaw Remediation

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:300-400` |
| **Function** | `run_cargo_audit()` |
| **Test** | Audit tests |
| **Verification** | Run `cargo audit` and verify no vulnerabilities |

### SI-3: Malicious Code Protection

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:300-400` |
| **Function** | Vulnerability scanning |
| **Test** | Audit tests |
| **Verification** | Verify dependencies scanned for vulnerabilities |

### SI-4: System Monitoring

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/alerting.rs:1-550` |
| **Struct** | `AlertManager` |
| **Test** | `cargo test test_alert_*` |
| **Verification** | Verify real-time monitoring of security events |

### SI-7: Software Integrity

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:50-100` |
| **Function** | `parse_cargo_lock()` (checksum verification) |
| **Test** | `cargo test test_parse_cargo_lock` |
| **Verification** | Verify dependency checksums match |

### SI-10: Information Input Validation

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/validation.rs:1-687` |
| **Functions** | `validate_email()`, `validate_length()`, `sanitize_html()`, etc. |
| **Test** | `cargo test test_validate_*` |
| **Verification** | Verify all user input is validated |

```rust
// Example validators in src/validation.rs
pub fn validate_email(value: &str) -> Result<(), ValidationError>;
pub fn validate_length(value: &str, min: usize, max: usize, field: &str) -> Result<(), ValidationError>;
pub fn validate_url(value: &str, allowed_schemes: &[&str]) -> Result<(), ValidationError>;
pub fn sanitize_html(input: &str) -> String;
pub fn contains_dangerous_patterns(input: &str) -> bool;
```

### SI-11: Error Handling

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/error.rs:1-300` |
| **Struct** | `AppError`, `ErrorConfig` |
| **Test** | `cargo test test_error_*` |
| **Verification** | Verify errors don't leak sensitive information |

---

## Supply Chain Risk Management (SR)

### SR-3: Supply Chain Controls

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:200-280` |
| **Function** | `generate_cyclonedx_sbom()` |
| **Test** | `cargo test test_generate_sbom` |
| **Verification** | Generate and review SBOM |

### SR-4: Provenance

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:50-100` |
| **Function** | `parse_cargo_lock()` |
| **Struct** | `Dependency` (includes source, checksum) |
| **Test** | `cargo test test_parse_cargo_lock` |
| **Verification** | Verify dependency sources are tracked |

### SR-11: Component Authenticity

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs:50-100` |
| **Function** | Checksum verification in `parse_cargo_lock()` |
| **Test** | Checksum tests |
| **Verification** | Verify checksums match for all dependencies |

---

## Compliance Validation

Barbican includes a compliance validation framework that can verify control implementation at runtime:

```rust
// src/compliance/validation.rs
use barbican::compliance::{ComplianceConfig, ComplianceValidator, ComplianceProfile};
use barbican::SecurityConfig;

let compliance = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
let security = SecurityConfig::default();

let mut validator = ComplianceValidator::new(&compliance);
validator.validate_security_layers(&security);  // SC-5, CM-6, AC-4, AU-2
validator.validate_tls(true);                    // SC-8
validator.validate_mfa(true, false);             // IA-2(1)
validator.validate_session_timeout(             // AC-11, AC-12
    Duration::from_secs(15 * 60),
    Duration::from_secs(10 * 60),
);

let report = validator.finish();
assert!(report.is_compliant());
```

Run compliance validation tests:
```bash
cargo test compliance::validation
```

---

## Verification Checklist

For each control, auditors should:

1. **Review Code**: Navigate to the specified file:line location
2. **Run Tests**: Execute the specified test with `cargo test <test_name>`
3. **Check Config**: Verify configuration matches compliance requirements
4. **Review Logs**: Verify audit events are generated appropriately

### Quick Test Commands

```bash
# Run all security-related tests
cargo test

# Run specific control family tests
cargo test test_claims      # AC-3, AC-6
cargo test test_lockout     # AC-7
cargo test test_session     # AC-11, AC-12, SC-10
cargo test test_event       # AU-2, AU-3
cargo test test_audit       # AU-12, AU-16
cargo test test_mfa         # IA-2(1)
cargo test test_password    # IA-5(1)
cargo test test_validate    # SI-10
cargo test test_error       # SI-11
cargo test compliance       # All controls validation
```

---

*Document generated: 2025-12-17*
*Barbican version: 0.1.0*
*NIST SP 800-53 Revision: 5*
