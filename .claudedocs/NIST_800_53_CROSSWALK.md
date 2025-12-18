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
| [Access Control (AC)](#access-control-ac) | AC-2, AC-3, AC-4, AC-6, AC-7, AC-11, AC-12 |
| [Audit (AU)](#audit-and-accountability-au) | AU-2, AU-3, AU-8, AU-12, AU-14, AU-16 |
| [Assessment (CA)](#assessment-authorization-monitoring-ca) | CA-7, CA-8 |
| [Configuration (CM)](#configuration-management-cm) | CM-6, CM-8, CM-10 |
| [Identification (IA)](#identification-and-authentication-ia) | IA-2, IA-5, IA-6, IA-8 |
| [Incident Response (IR)](#incident-response-ir) | IR-4, IR-5 |
| [System Protection (SC)](#system-and-communications-protection-sc) | SC-5, SC-8, SC-8(1), SC-10, SC-12, SC-13, SC-23 |
| [System Integrity (SI)](#system-and-information-integrity-si) | SI-2, SI-3, SI-4, SI-7, SI-10, SI-11 |
| [Supply Chain (SR)](#supply-chain-risk-management-sr) | SR-3, SR-4, SR-11 |

---

## Access Control (AC)

### AC-2: Account Management

| Aspect | Location |
|--------|----------|
| **Status** | FACILITATED |
| **Implementation** | `src/observability/events.rs:37-92` |
| **Events** | `SecurityEvent::UserRegistered`, `UserModified`, `UserDeleted`, `AccountLocked`, `AccountUnlocked` |
| **Test** | `cargo test test_event_categories` |
| **Verification** | Verify account lifecycle events are logged for audit trail |

Barbican provides security event hooks for account management. Your application implements
the account logic; Barbican logs the events for compliance.

```rust
// src/observability/events.rs:57-77
pub enum SecurityEvent {
    // ...
    /// New user registered
    UserRegistered,
    /// User account modified
    UserModified,
    /// User account deleted
    UserDeleted,
    // ...
    /// Account locked due to security
    AccountLocked,
    /// Account unlocked
    AccountUnlocked,
    // ...
}
```

### AC-3: Access Enforcement

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:87-184` |
| **Struct** | `Claims` |
| **Functions** | `Claims::has_role()`, `Claims::has_scope()`, `Claims::in_group()` |
| **Test** | `cargo test test_claims_roles` |
| **Verification** | Check that role/scope checks gate access to protected resources |

```rust
// src/auth.rs:161-183
pub fn has_role(&self, role: &str) -> bool {
    self.roles.contains(role)
}

pub fn has_any_role(&self, roles: &[&str]) -> bool {
    roles.iter().any(|r| self.roles.contains(*r))
}

pub fn in_group(&self, group: &str) -> bool {
    self.groups.contains(group)
}

pub fn has_scope(&self, scope: &str) -> bool {
    self.scopes.contains(scope)
}
```

### AC-4: Information Flow Enforcement

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/layers.rs:132-153` |
| **Function** | `build_cors_layer()` |
| **Config** | `src/config.rs` (`cors_origins`) |
| **Test** | `cargo test test_validator_security_layers_cors_permissive` |
| **Verification** | Verify CORS policy restricts cross-origin requests to allowlist |

```rust
// src/layers.rs:132-153
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
        // Explicit allowlist
        let origins: Vec<HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|s| HeaderValue::from_str(s).ok())
            .collect();
        base.allow_origin(origins).allow_credentials(true)
    }
}
```

### AC-6: Least Privilege

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:161-184` |
| **Functions** | `Claims::has_role()`, `Claims::has_scope()`, `Claims::has_all_roles()` |
| **Test** | `cargo test test_claims_roles` |
| **Verification** | Verify minimum necessary roles/scopes are checked before access |

### AC-7: Unsuccessful Logon Attempts

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/login.rs:1-632` |
| **Structs** | `LoginTracker`, `LockoutPolicy`, `AttemptRecord` |
| **Test** | `cargo test test_lockout` |
| **Verification** | Verify account lockout after N failed attempts |

```rust
// src/login.rs:64-96
pub struct LockoutPolicy {
    /// Number of failed attempts before lockout
    pub max_attempts: u32,

    /// Time window for counting attempts
    pub attempt_window: Duration,

    /// Duration of lockout after max attempts reached
    pub lockout_duration: Duration,

    /// Whether to use progressive lockout (longer each time)
    pub progressive_lockout: bool,

    /// Maximum lockout duration for progressive lockout
    pub max_lockout_duration: Duration,

    /// Multiplier for progressive lockout
    pub lockout_multiplier: f64,

    /// Whether to track by IP in addition to username
    pub track_by_ip: bool,

    /// Maximum failed attempts per IP (for brute force protection)
    pub max_ip_attempts: u32,

    /// IP lockout duration
    pub ip_lockout_duration: Duration,
}
```

### AC-11: Session Lock (Idle Timeout)

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:42-167` |
| **Struct** | `SessionPolicy` |
| **Function** | `SessionPolicy::should_terminate()` |
| **Config** | `src/compliance/profile.rs` (`session_idle_timeout`) |
| **Test** | `cargo test test_default_policy` |
| **Verification** | Verify sessions expire after inactivity period |

```rust
// src/session.rs:143-167
pub fn should_terminate(&self, state: &SessionState) -> SessionTerminationReason {
    let now = Instant::now();

    // Check max lifetime (AC-12)
    if let Some(created) = state.created_at {
        if now.duration_since(created) > self.max_lifetime {
            return SessionTerminationReason::MaxLifetimeExceeded;
        }
    }

    // Check idle timeout (AC-11)
    if let Some(last_activity) = state.last_activity {
        if now.duration_since(last_activity) > self.idle_timeout {
            return SessionTerminationReason::IdleTimeout;
        }
    }

    // Check extension limit
    if self.allow_extension && state.extension_count > self.max_extensions {
        return SessionTerminationReason::MaxExtensionsExceeded;
    }

    SessionTerminationReason::None
}
```

### AC-12: Session Termination

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:42-167` |
| **Struct** | `SessionPolicy` |
| **Function** | `SessionPolicy::should_terminate()` |
| **Config** | `src/compliance/profile.rs` (`session_max_lifetime`) |
| **Test** | `cargo test test_session_termination` |
| **Verification** | Verify sessions terminate after absolute timeout |

The `should_terminate()` function (shown above under AC-11) handles both idle timeout (AC-11)
and absolute session lifetime (AC-12) in a single check.

---

## Audit and Accountability (AU)

### AU-2: Audit Events

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/observability/events.rs:37-92` |
| **Struct** | `SecurityEvent` enum (22 events) |
| **HTTP Middleware** | `src/audit.rs:65-107` |
| **Test** | `cargo test test_event_categories` |
| **Verification** | Verify all security-relevant events are captured |

```rust
// src/observability/events.rs:37-92
pub enum SecurityEvent {
    // Authentication events
    AuthenticationSuccess,
    AuthenticationFailure,
    Logout,
    SessionCreated,
    SessionDestroyed,

    // Authorization events
    AccessGranted,
    AccessDenied,

    // User management events
    UserRegistered,
    UserModified,
    UserDeleted,
    PasswordChanged,
    PasswordResetRequested,

    // Security events
    RateLimitExceeded,
    BruteForceDetected,
    AccountLocked,
    AccountUnlocked,
    SuspiciousActivity,

    // System events
    SystemStartup,
    SystemShutdown,
    ConfigurationChanged,
    DatabaseConnected,
    DatabaseDisconnected,
}
```

### AU-3: Content of Audit Records

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/observability/events.rs:250-293` |
| **Macro** | `security_event!` |
| **HTTP Audit** | `src/audit.rs:109-191` |
| **Record Struct** | `src/audit.rs:262-282` (`AuditRecord`) |
| **Test** | `cargo test test_event_severity` |
| **Verification** | Verify records contain: who, what, when, where, outcome |

Required AU-3 fields captured:
- **Who**: `user_id` field in `audit_middleware`
- **What**: `security_event` type + `path`
- **When**: Automatic timestamp via `tracing`
- **Where**: `client_ip`, `path`
- **Outcome**: `status` code, `AuditOutcome` enum

```rust
// src/audit.rs:262-282
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
| **Implementation** | `src/observability/events.rs:250-293` |
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
| **Implementation** | `src/session.rs:468-524` |
| **Functions** | `log_session_created()`, `log_session_terminated()`, `log_session_extended()` |
| **Events** | `SessionCreated`, `SessionDestroyed` |
| **Test** | `cargo test test_session_state_creation` |
| **Verification** | Verify session lifecycle events are logged |

### AU-16: Cross-Organizational Audit

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/audit.rs:194-212` |
| **Function** | `extract_or_generate_correlation_id()` |
| **Headers** | `X-Correlation-ID`, `X-Request-ID` |
| **Test** | `cargo test test_generate_request_id` |
| **Verification** | Verify correlation IDs propagate across service boundaries |

```rust
// src/audit.rs:194-202
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
| **Implementation** | `src/health.rs` |
| **Structs** | `HealthChecker`, `HealthCheck`, `HealthReport` |
| **Test** | `cargo test test_health_checker_all_healthy` |
| **Verification** | Verify health checks run continuously and report status |

### CA-8: Penetration Testing

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/testing.rs` |
| **Functions** | `xss_payloads()`, `sql_injection_payloads()`, `command_injection_payloads()` |
| **Test** | `cargo test test_xss_payloads_not_empty` |
| **Verification** | Use provided payloads to test application endpoints |

---

## Configuration Management (CM)

### CM-6: Configuration Settings

| Aspect | Location |
|--------|----------|
| **Secure Defaults** | `src/config.rs` (`Default` impl) |
| **Security Headers** | `src/layers.rs:78-113` |
| **Compliance Validation** | `src/compliance/validation.rs` |
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
// src/layers.rs:84-87
.layer(SetResponseHeaderLayer::overriding(
    header::STRICT_TRANSPORT_SECURITY,
    HeaderValue::from_static("max-age=31536000; includeSubDomains"),
))
```

### CM-8: System Component Inventory

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Function** | `generate_cyclonedx_sbom()` |
| **Test** | `cargo test test_generate_sbom` |
| **Verification** | Generate SBOM and verify all dependencies listed |

### CM-10: Software Usage Restrictions

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Struct** | `LicensePolicy` |
| **Test** | `cargo test test_license_policy_strict` |
| **Verification** | Verify license compliance checking |

---

## Identification and Authentication (IA)

### IA-2: Identification and Authentication

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:87-310` |
| **Struct** | `Claims` |
| **MFA Policy** | `src/auth.rs:466-656` (`MfaPolicy`) |
| **Test** | `cargo test test_claims_*` |
| **Verification** | Verify JWT claims extraction and validation |

### IA-2(1): MFA for Privileged Accounts

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:466-656` |
| **Struct** | `MfaPolicy` |
| **Functions** | `MfaPolicy::is_satisfied()`, `Claims::mfa_satisfied()` |
| **Test** | `cargo test test_mfa_policy_require_mfa` |
| **Verification** | Verify MFA required for privileged operations |

```rust
// src/auth.rs:571-614
pub fn is_satisfied(&self, claims: &Claims) -> bool {
    // Check hardware requirement
    if self.require_hardware && !claims.used_hardware_auth() {
        return false;
    }

    // Check specific method requirements
    if !self.required_methods.is_empty() {
        let has_required = self
            .required_methods
            .iter()
            .any(|m| claims.amr.contains(m));
        if !has_required {
            return false;
        }
    }

    // Check general MFA requirement
    if self.require_any_mfa && !claims.mfa_satisfied() {
        return false;
    }

    // Check ACR level
    if let Some(ref min_acr) = self.min_acr_level {
        // ... ACR level checking
    }

    true
}
```

### IA-5(1): Password-Based Authentication

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/password.rs:57-292` |
| **Struct** | `PasswordPolicy` |
| **Config** | `src/compliance/profile.rs` (`password_min_length`) |
| **Test** | `cargo test test_length_validation` |
| **Verification** | Verify password policy meets NIST 800-63B |

```rust
// src/password.rs:57-86
pub struct PasswordPolicy {
    /// Minimum password length (NIST minimum: 8, recommended: 12+)
    pub min_length: usize,

    /// Maximum password length (NIST: at least 64)
    pub max_length: usize,

    /// Check against common password list
    pub check_common_passwords: bool,

    /// Check against Have I Been Pwned breach database
    pub check_breach_database: bool,

    /// Disallow passwords containing the username
    pub disallow_username_in_password: bool,

    /// Disallow passwords containing the email
    pub disallow_email_in_password: bool,

    /// Custom blocked passwords (application-specific)
    pub blocked_passwords: HashSet<String>,

    /// Require password to not be entirely numeric
    pub disallow_all_numeric: bool,
}
```

### IA-6: Authentication Feedback

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/error.rs` |
| **Struct** | `AppError` |
| **Config** | `ErrorConfig::production_mode()` |
| **Test** | `cargo test test_error_display` |
| **Verification** | Verify error messages don't leak sensitive info |

### IA-8: Non-Organizational Users

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/auth.rs:316-436` |
| **Functions** | `extract_keycloak_roles()`, `extract_entra_roles()`, `extract_amr()` |
| **Test** | `cargo test test_keycloak_role_extraction` |
| **Verification** | Verify OAuth/OIDC claims from external IdPs |

---

## Incident Response (IR)

### IR-4: Incident Handling

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/alerting.rs` |
| **Structs** | `AlertManager`, `Alert` |
| **Test** | `cargo test test_alert_manager_basic` |
| **Verification** | Verify alerts trigger on security events |

### IR-5: Incident Monitoring

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/alerting.rs` |
| **Function** | `AlertManager::register_handler()` |
| **Test** | `cargo test test_alert_handler` |
| **Verification** | Verify real-time alert handlers receive events |

---

## System and Communications Protection (SC)

### SC-5: Denial of Service Protection

| Aspect | Location |
|--------|----------|
| **Rate Limiting** | `src/layers.rs:69-76` |
| **Body Size Limit** | `src/layers.rs:65` |
| **Request Timeout** | `src/layers.rs:58-61` |
| **Config** | `src/config.rs` |
| **Test** | `cargo test test_validator_security_layers_rate_limit_disabled` |
| **Verification** | Verify rate limits and size limits are enforced |

```rust
// src/layers.rs:56-76
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
        .finish()
        .expect("Invalid rate limiter configuration");
    router = router.layer(GovernorLayer::new(rate_limit_config));
}
```

### SC-8: Transmission Confidentiality

| Aspect | Location |
|--------|----------|
| **HTTP TLS Enforcement** | `src/tls.rs:1-420` |
| **TLS Middleware** | `src/tls.rs:280-340` (`tls_enforcement_middleware`) |
| **TLS Mode Enum** | `src/tls.rs:52-98` (`TlsMode`) |
| **TLS Detection** | `src/tls.rs:145-210` (`detect_tls`) |
| **HSTS Header** | `src/layers.rs:87-90` |
| **Database TLS** | `src/database.rs:214-247` (`SslMode`) |
| **Config** | `src/config.rs:66-68` (`tls_mode`), `src/compliance/profile.rs` (`requires_tls()`) |
| **Compliance Validation** | `src/compliance/validation.rs:360-383` (`validate_http_tls`) |
| **Test** | `cargo test tls`, `cargo test test_validator_http_tls_*` |
| **Verification** | Verify HTTPS enforcement rejects HTTP requests |

The TLS module provides four enforcement modes:

```rust
// src/tls.rs:52-70
pub enum TlsMode {
    /// No TLS enforcement (development only)
    Disabled,

    /// Log warnings but allow HTTP traffic
    Opportunistic,

    /// Require HTTPS, reject HTTP requests (production default)
    #[default]
    Required,

    /// Strict mode: Required + TLS version validation
    Strict,
}
```

TLS detection checks proxy headers in priority order:

```rust
// src/tls.rs:145-210
pub fn detect_tls(request: &Request<Body>) -> TlsInfo {
    // 1. X-Forwarded-Proto (standard)
    // 2. X-Forwarded-Ssl (legacy)
    // 3. CF-Visitor (Cloudflare)
    // 4. URI scheme (direct TLS)
}
```

The middleware rejects non-HTTPS requests with 421 Misdirected Request:

```rust
// src/tls.rs:280-340
pub async fn tls_enforcement_middleware(
    request: Request,
    next: Next,
    mode: TlsMode,
) -> Response {
    // Disabled mode - pass through
    if mode == TlsMode::Disabled {
        return next.run(request).await;
    }

    let tls_info = detect_tls(&request);

    if !tls_info.is_https {
        match mode {
            TlsMode::Opportunistic => { /* log warning, allow */ }
            TlsMode::Required | TlsMode::Strict => {
                return tls_required_response(); // 421
            }
            _ => {}
        }
    }
    // ...
}
```

Configuration via environment or builder:

```rust
// Environment variable
// TLS_MODE=required (default), disabled, opportunistic, strict

// Builder pattern
let config = SecurityConfig::builder()
    .tls_mode(TlsMode::Strict)
    .build();

// Development helper (disables TLS enforcement)
let config = SecurityConfig::development();
```

### SC-8(1): Cryptographic Protection (TLS Version)

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/tls.rs:225-245` |
| **Function** | `is_tls_version_acceptable()` |
| **Mode** | `TlsMode::Strict` |
| **Test** | `cargo test test_tls_version_acceptable` |
| **Verification** | Verify TLS 1.2+ required, TLS 1.0/1.1 rejected |

Strict mode validates TLS version from proxy headers:

```rust
// src/tls.rs:225-245
pub fn is_tls_version_acceptable(version: &str) -> bool {
    let version_lower = version.to_lowercase();

    // Accept TLS 1.2 and 1.3
    if version_lower.contains("1.3") || version_lower.contains("1.2") {
        return true;
    }

    // Reject TLS 1.0 and 1.1
    if version_lower.contains("1.0") || version_lower.contains("1.1") {
        return false;
    }

    true // Unknown - permissive
}
```

Headers checked for TLS version:
- `X-SSL-Protocol` (common proxy header)
- `CF-SSL-Protocol` (Cloudflare)

### SC-10: Network Disconnect

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:143-167` |
| **Function** | `SessionPolicy::should_terminate()` |
| **Test** | `cargo test test_session_termination` |
| **Verification** | Verify sessions terminate after inactivity |

The `should_terminate()` function handles session termination for both idle timeout
and network disconnect scenarios. See AC-11 for implementation details.

### SC-12: Cryptographic Key Management

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/keys.rs` |
| **Trait** | `KeyStore` |
| **Structs** | `RotationTracker`, `RotationPolicy` |
| **Config** | `src/compliance/profile.rs` (`key_rotation_interval`) |
| **Test** | `cargo test test_rotation_tracker_*` |
| **Verification** | Verify key rotation policy enforcement |

### SC-13: Cryptographic Protection

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/crypto.rs:37-49` |
| **Functions** | `constant_time_eq()`, `constant_time_str_eq()` |
| **Test** | `cargo test test_constant_time_eq_*` |
| **Verification** | Verify constant-time comparison prevents timing attacks |

```rust
// src/crypto.rs:37-41
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // subtle::ConstantTimeEq returns a Choice, which we convert to bool
    // This comparison takes constant time regardless of input values
    a.ct_eq(b).into()
}
```

### SC-23: Session Authenticity

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/session.rs:270-392` |
| **Struct** | `SessionState` |
| **Test** | `cargo test test_session_state_creation` |
| **Verification** | Verify session state integrity tracking |

```rust
// src/session.rs:270-307
pub struct SessionState {
    pub session_id: String,
    pub user_id: String,
    pub created_at: Option<Instant>,
    pub created_at_unix: Option<i64>,
    pub last_activity: Option<Instant>,
    pub last_activity_unix: Option<i64>,
    pub last_authentication: Option<Instant>,
    pub last_authentication_unix: Option<i64>,
    pub extension_count: u32,
    pub is_active: bool,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}
```

---

## System and Information Integrity (SI)

### SI-2: Flaw Remediation

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Function** | `run_cargo_audit()` |
| **Test** | Audit tests |
| **Verification** | Run `cargo audit` and verify no vulnerabilities |

### SI-3: Malicious Code Protection

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Function** | Vulnerability scanning |
| **Test** | Audit tests |
| **Verification** | Verify dependencies scanned for vulnerabilities |

### SI-4: System Monitoring

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/alerting.rs` |
| **Struct** | `AlertManager` |
| **Test** | `cargo test test_alert_*` |
| **Verification** | Verify real-time monitoring of security events |

### SI-7: Software Integrity

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Function** | `parse_cargo_lock()` (checksum verification) |
| **Test** | `cargo test test_parse_cargo_lock` |
| **Verification** | Verify dependency checksums match |

### SI-10: Information Input Validation

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/validation.rs` |
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
| **Implementation** | `src/error.rs` |
| **Struct** | `AppError`, `ErrorConfig` |
| **Test** | `cargo test test_error_*` |
| **Verification** | Verify errors don't leak sensitive information |

---

## Supply Chain Risk Management (SR)

### SR-3: Supply Chain Controls

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Function** | `generate_cyclonedx_sbom()` |
| **Test** | `cargo test test_generate_sbom` |
| **Verification** | Generate and review SBOM |

### SR-4: Provenance

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Function** | `parse_cargo_lock()` |
| **Struct** | `Dependency` (includes source, checksum) |
| **Test** | `cargo test test_parse_cargo_lock` |
| **Verification** | Verify dependency sources are tracked |

### SR-11: Component Authenticity

| Aspect | Location |
|--------|----------|
| **Implementation** | `src/supply_chain.rs` |
| **Function** | Checksum verification in `parse_cargo_lock()` |
| **Test** | Checksum tests |
| **Verification** | Verify checksums match for all dependencies |

---

## Compliance Validation

Barbican includes a compliance validation framework that can verify control implementation at runtime:

```rust
// src/compliance/validation.rs
use barbican::compliance::{ComplianceConfig, ComplianceValidator, ComplianceProfile};
use barbican::{SecurityConfig, TlsMode};

let compliance = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
let security = SecurityConfig::default();

let mut validator = ComplianceValidator::new(&compliance);
validator.validate_security_layers(&security);  // SC-5, CM-6, AC-4, AU-2
validator.validate_http_tls(security.tls_mode); // SC-8 (HTTP TLS enforcement)
validator.validate_tls(true);                    // SC-8 (Database TLS)
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
cargo test tls              # SC-8, SC-8(1) - TLS enforcement
cargo test test_validate    # SI-10
cargo test test_error       # SI-11
cargo test compliance       # All controls validation
```

---

*Document generated: 2025-12-17*
*Barbican version: 0.1.0*
*NIST SP 800-53 Revision: 5*
