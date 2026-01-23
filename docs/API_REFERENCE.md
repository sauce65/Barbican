# Barbican API Reference

Complete reference for all public Barbican types and functions.

## Quick Import

```rust
use barbican::prelude::*;
```

This imports all commonly used types. For specific imports, see individual module documentation below.

---

## Table of Contents

- [Router Extensions](#router-extensions)
- [Password Validation](#password-validation)
- [Login Tracking](#login-tracking)
- [Session Management](#session-management)
- [Input Validation](#input-validation)
- [Authentication](#authentication)
- [Error Handling](#error-handling)
- [Audit Logging](#audit-logging)
- [Encryption](#encryption)
- [Key Management](#key-management)
- [Health Checks](#health-checks)
- [Alerting](#alerting)
- [Database](#database)
- [TLS](#tls)
- [Compliance Profiles](#compliance-profiles)

---

## Router Extensions

### `SecureRouter` trait

Extension methods for `axum::Router`.

```rust
use barbican::prelude::*;

let app = Router::new()
    .route("/", get(handler))
    .with_security_headers()
    .with_rate_limiting(100, 10)
    .with_request_timeout(Duration::from_secs(30))
    .with_body_limit(1024 * 1024);
```

#### Methods

| Method | Description |
|--------|-------------|
| `with_security_headers()` | Add HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) |
| `with_rate_limiting(rps, burst)` | Add rate limiting with requests per second and burst capacity |
| `with_request_timeout(duration)` | Add request timeout |
| `with_body_limit(bytes)` | Limit request body size |
| `with_security(config)` | Apply full security configuration |

#### Security Headers Added

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | `default-src 'self'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

---

## Password Validation

### `PasswordPolicy`

Validates passwords against NIST 800-63B and DISA STIG requirements.

```rust
use barbican::password::{PasswordPolicy, PasswordError, PasswordStrength};
```

#### Constructors

```rust
// Profile-based (recommended)
let policy = PasswordPolicy::fedramp_low();      // 8 char min
let policy = PasswordPolicy::fedramp_moderate(); // 15 char min
let policy = PasswordPolicy::fedramp_high();     // 15 char min

// Custom
let policy = PasswordPolicy::builder()
    .min_length(12)
    .max_length(128)
    .require_mixed_case(true)
    .require_digit(true)
    .require_special(true)
    .check_common_passwords(true)
    .build();
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `validate` | `(&self, password: &str, username: Option<&str>, email: Option<&str>) -> Result<PasswordStrength, PasswordError>` | Validate password, returns strength level |
| `min_length` | `(&self) -> usize` | Get minimum length requirement |
| `check_strength` | `(&self, password: &str) -> PasswordStrength` | Get password strength without full validation |

#### `PasswordStrength` enum

```rust
pub enum PasswordStrength {
    VeryWeak,   // Fails basic requirements
    Weak,       // Meets minimum, low entropy
    Fair,       // Acceptable
    Strong,     // Good entropy
    VeryStrong, // Excellent entropy
}
```

#### `PasswordError` enum

```rust
pub enum PasswordError {
    TooShort { min: usize, actual: usize },
    TooLong { max: usize, actual: usize },
    MissingUppercase,
    MissingLowercase,
    MissingDigit,
    MissingSpecial,
    ContainsUsername,
    ContainsEmail,
    CommonPassword,
    Breached { count: u64 },  // With 'hibp' feature
}
```

#### Example

```rust
let policy = PasswordPolicy::fedramp_moderate();

match policy.validate("MyP@ssw0rd123456", Some("john"), Some("john@example.com")) {
    Ok(PasswordStrength::Strong) => println!("Password accepted"),
    Ok(strength) => println!("Password accepted but {:?}", strength),
    Err(PasswordError::TooShort { min, actual }) => {
        println!("Password must be at least {} characters (got {})", min, actual);
    }
    Err(e) => println!("Password rejected: {:?}", e),
}
```

---

## Login Tracking

### `LoginTracker`

Tracks failed login attempts and enforces account lockout.

```rust
use barbican::login::{LoginTracker, LockoutPolicy, AttemptResult, LockoutInfo};
```

#### Constructors

```rust
let tracker = LoginTracker::new(LockoutPolicy::fedramp_moderate());

// Or with custom policy
let policy = LockoutPolicy::builder()
    .max_attempts(5)
    .lockout_duration(Duration::from_secs(900)) // 15 minutes
    .build();
let tracker = LoginTracker::new(policy);
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `check_lockout` | `(&self, identifier: &str) -> Option<LockoutInfo>` | Check if account is locked |
| `record_failure` | `(&self, identifier: &str) -> AttemptResult` | Record failed attempt |
| `record_success` | `(&self, identifier: &str)` | Clear attempts on success |
| `clear` | `(&self, identifier: &str)` | Manually clear lockout |

#### `AttemptResult` enum

```rust
pub enum AttemptResult {
    /// Account is now locked
    Locked(LockoutInfo),
    /// Failed but not yet locked, returns remaining attempts
    Warning(u32),
    /// Failed, no warning threshold reached
    Failed,
}
```

#### `LockoutInfo` struct

```rust
impl LockoutInfo {
    pub fn locked_until(&self) -> SystemTime;
    pub fn remaining_seconds(&self) -> u64;
    pub fn attempts(&self) -> u32;
}
```

#### Example

```rust
let tracker = LoginTracker::new(LockoutPolicy::fedramp_moderate());

// Check before authentication
if let Some(info) = tracker.check_lockout("user@example.com") {
    return Err(format!("Account locked for {} seconds", info.remaining_seconds()));
}

// After failed authentication
match tracker.record_failure("user@example.com") {
    AttemptResult::Locked(info) => {
        Err(format!("Account locked for {} seconds", info.remaining_seconds()))
    }
    AttemptResult::Warning(remaining) => {
        Err(format!("Invalid credentials. {} attempts remaining", remaining))
    }
    AttemptResult::Failed => {
        Err("Invalid credentials".into())
    }
}

// After successful authentication
tracker.record_success("user@example.com");
```

### `LockoutPolicy`

Configures lockout behavior.

```rust
// Profile-based
let policy = LockoutPolicy::fedramp_low();      // 3 attempts, 30 min
let policy = LockoutPolicy::fedramp_moderate(); // 3 attempts, 30 min
let policy = LockoutPolicy::fedramp_high();     // 3 attempts, 3 hours

// Custom
let policy = LockoutPolicy::builder()
    .max_attempts(5)
    .lockout_duration(Duration::from_secs(900))
    .warning_threshold(2) // Warn after 2 failures
    .build();
```

---

## Session Management

### `SessionPolicy`

Defines session timeout rules.

```rust
use barbican::session::{SessionPolicy, SessionState, SessionTerminationReason};
```

#### Constructors

```rust
// Profile-based
let policy = SessionPolicy::fedramp_low();      // 15m idle, 30m max
let policy = SessionPolicy::fedramp_moderate(); // 15m idle, 15m max
let policy = SessionPolicy::fedramp_high();     // 10m idle, 10m max

// Custom
let policy = SessionPolicy::builder()
    .idle_timeout(Duration::from_secs(600))  // 10 minutes
    .max_lifetime(Duration::from_secs(3600)) // 1 hour
    .build();
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `is_valid` | `(&self, session: &SessionState) -> bool` | Check if session is valid |
| `check` | `(&self, session: &SessionState) -> Result<(), SessionTerminationReason>` | Check with detailed reason |
| `idle_timeout` | `(&self) -> Duration` | Get idle timeout |
| `max_lifetime` | `(&self) -> Duration` | Get max lifetime |

### `SessionState`

Tracks individual session state.

```rust
let session = SessionState::new("user_123");

// On user activity
session.touch(); // Reset idle timer

// Check validity
if policy.is_valid(&session) {
    // Session is valid
}

// Get session info
let id = session.id();           // Unique session ID
let user = session.user_id();    // User identifier
let created = session.created_at();
let last_active = session.last_activity();
```

### `SessionTerminationReason` enum

```rust
pub enum SessionTerminationReason {
    IdleTimeout { idle_for: Duration, limit: Duration },
    MaxLifetimeExceeded { lifetime: Duration, limit: Duration },
    Invalidated, // Explicitly terminated
}
```

---

## Input Validation

### Validated Extractors

Drop-in replacements for Axum extractors that validate input.

```rust
use barbican::validation::{ValidatedJson, ValidatedQuery, ValidatedPath, Validate, ValidationError};
```

#### `ValidatedJson<T>`

```rust
#[derive(Deserialize)]
struct CreateUser {
    email: String,
    name: String,
}

impl Validate for CreateUser {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_email(&self.email)?;
        validate_length(&self.name, 1, 100, "name")?;
        Ok(())
    }
}

async fn handler(ValidatedJson(input): ValidatedJson<CreateUser>) -> impl IntoResponse {
    // input is guaranteed to be valid
}
```

#### `ValidatedQuery<T>`

```rust
#[derive(Deserialize)]
struct SearchParams {
    q: String,
    page: Option<u32>,
}

impl Validate for SearchParams {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_length(&self.q, 1, 100, "query")?;
        if let Some(page) = self.page {
            if page == 0 {
                return Err(ValidationError::new("page", "must be >= 1"));
            }
        }
        Ok(())
    }
}

async fn search(ValidatedQuery(params): ValidatedQuery<SearchParams>) -> impl IntoResponse {
    // params.q is validated
}
```

#### `ValidatedPath<T>`

```rust
#[derive(Deserialize)]
struct UserPath {
    id: i64,
}

impl Validate for UserPath {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.id <= 0 {
            return Err(ValidationError::new("id", "must be positive"));
        }
        Ok(())
    }
}

async fn get_user(ValidatedPath(path): ValidatedPath<UserPath>) -> impl IntoResponse {
    // path.id is validated
}
```

### Validation Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `validate_email` | `(email: &str) -> Result<(), ValidationError>` | Validate email format |
| `validate_length` | `(s: &str, min: usize, max: usize, field: &str) -> Result<(), ValidationError>` | Validate string length |
| `validate_required` | `(value: Option<&T>, field: &str) -> Result<&T, ValidationError>` | Ensure value is present |
| `sanitize_html` | `(input: &str) -> String` | Remove HTML tags and encode entities |

### `ValidationError`

```rust
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(field: &str, message: &str) -> Self;
}

// Response format (400 Bad Request):
// {"error": "Validation failed", "field": "email", "message": "invalid email format"}
```

---

## Authentication

### `Claims`

JWT claims for authenticated requests.

```rust
use barbican::auth::{Claims, MfaPolicy};
```

```rust
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub mfa_verified: bool,
    pub exp: u64,           // Expiration timestamp
    pub iat: u64,           // Issued at
}

impl Claims {
    pub fn has_role(&self, role: &str) -> bool;
    pub fn is_expired(&self) -> bool;
}
```

### `MfaPolicy`

MFA enforcement configuration.

```rust
// Require MFA for all users
let policy = MfaPolicy::require_mfa();

// Require MFA only for privileged operations
let policy = MfaPolicy::privileged_only();

// No MFA requirement
let policy = MfaPolicy::none();

// Check MFA status
if policy.requires_mfa(&claims) && !claims.mfa_verified {
    return Err(AppError::mfa_required());
}
```

### Auth Logging Functions

```rust
use barbican::auth::{log_access_decision, log_access_denied, log_mfa_success, log_mfa_required};

// Log access control decisions
log_access_decision(&claims, "resource_name", true);
log_access_denied(&claims, "resource_name", "insufficient permissions");
log_mfa_success(&claims);
log_mfa_required(&claims, "sensitive_operation");
```

---

## Error Handling

### `AppError`

Secure error type that hides internal details in production.

```rust
use barbican::error::{AppError, ErrorConfig, ErrorKind};
```

#### Constructors

```rust
// Common errors
AppError::not_found("User not found")
AppError::validation("Invalid email format")
AppError::auth_failed("Invalid credentials")
AppError::forbidden("Access denied")
AppError::locked_out(remaining_seconds)
AppError::mfa_required()
AppError::internal("An error occurred")
AppError::rate_limited(retry_after_seconds)

// From other errors
AppError::from_db_error(sqlx_error)
AppError::from_io_error(io_error)
```

#### `ErrorKind` enum

```rust
pub enum ErrorKind {
    NotFound,
    Validation,
    Authentication,
    Authorization,
    RateLimited,
    LockedOut,
    MfaRequired,
    Internal,
    BadRequest,
    Conflict,
}
```

#### `ErrorConfig`

```rust
// Development - shows full details
let config = ErrorConfig::development();

// Production - hides internal details
let config = ErrorConfig::production();

// Custom
let config = ErrorConfig::builder()
    .show_internal_errors(false)
    .include_request_id(true)
    .log_internal_errors(true)
    .build();
```

#### Response Format

```json
// Development
{
  "error": "Database connection failed: timeout",
  "kind": "internal",
  "details": "..stack trace..",
  "request_id": "abc123"
}

// Production
{
  "error": "An internal error occurred",
  "kind": "internal",
  "request_id": "abc123"
}
```

---

## Audit Logging

### Middleware

```rust
use barbican::audit::audit_middleware;

let app = Router::new()
    .route("/", get(handler))
    .layer(audit_middleware());
```

Automatically logs:
- Request method, path, query
- Response status code
- Duration
- Client IP
- User ID (if authenticated)

### `AuditRecord`

```rust
use barbican::audit::{AuditRecord, AuditOutcome};

let record = AuditRecord::builder()
    .event_type("user.created")
    .actor("user_123")
    .resource("users/456")
    .outcome(AuditOutcome::Success)
    .details(json!({"email": "user@example.com"}))
    .build();

record.log(); // Emit as structured log
```

### `AuditOutcome` enum

```rust
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
    Error,
}
```

---

## Encryption

### `FieldEncryptor`

AES-256-GCM encryption for sensitive fields.

```rust
use barbican::encryption::{FieldEncryptor, EncryptedField, EncryptionConfig};

let config = EncryptionConfig::from_env(); // Reads ENCRYPTION_KEY
let encryptor = FieldEncryptor::new(config);

// Encrypt
let encrypted: EncryptedField = encryptor.encrypt("sensitive data")?;
let json = serde_json::to_string(&encrypted)?; // Safe to store

// Decrypt
let decrypted: String = encryptor.decrypt(&encrypted)?;
```

### `EncryptedField`

Serializable encrypted data with nonce.

```rust
#[derive(Serialize, Deserialize)]
pub struct EncryptedField {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    version: u8, // Key version for rotation
}
```

---

## Key Management

### `KeyStore` trait

```rust
use barbican::keys::{KeyStore, KeyMetadata, KeyMaterial, EnvKeyStore};

// Environment-based key store
let store = EnvKeyStore::new();

// Get current encryption key
let key = store.get_key("encryption")?;

// List all keys
let keys: Vec<KeyMetadata> = store.list_keys()?;
```

### `RotationPolicy`

```rust
use barbican::keys::{RotationPolicy, RotationTracker};

let policy = RotationPolicy::builder()
    .max_age(Duration::from_secs(90 * 24 * 60 * 60)) // 90 days
    .build();

let tracker = RotationTracker::new(policy);
if tracker.needs_rotation(&key_metadata) {
    // Key should be rotated
}
```

---

## Health Checks

### `HealthChecker`

```rust
use barbican::health::{HealthChecker, HealthCheck, HealthStatus, health_routes};

let checker = HealthChecker::new()
    .add_check("database", db_health_check)
    .add_check("redis", redis_health_check);

// Add routes
let app = Router::new()
    .merge(health_routes(checker));
// Adds: GET /health, GET /health/live, GET /health/ready
```

### Custom Health Check

```rust
async fn db_health_check() -> HealthCheck {
    match pool.acquire().await {
        Ok(_) => HealthCheck::healthy("database"),
        Err(e) => HealthCheck::unhealthy("database", &e.to_string()),
    }
}
```

### `HealthStatus` enum

```rust
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}
```

---

## Alerting

### `AlertManager`

```rust
use barbican::alerting::{AlertManager, AlertConfig, Alert, AlertSeverity, AlertCategory};

let config = AlertConfig::builder()
    .webhook_url("https://hooks.slack.com/...")
    .build();
let manager = AlertManager::new(config);

// Send alert
manager.send(Alert {
    severity: AlertSeverity::High,
    category: AlertCategory::Security,
    title: "Multiple failed login attempts",
    message: "User john@example.com locked out after 3 failed attempts",
    metadata: json!({"user": "john@example.com", "ip": "1.2.3.4"}),
}).await?;
```

### `AlertSeverity` enum

```rust
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}
```

### `AlertCategory` enum

```rust
pub enum AlertCategory {
    Security,
    Performance,
    Availability,
    Compliance,
}
```

---

## Database

*Requires `postgres` feature*

### `DatabaseConfig`

```rust
use barbican::database::{DatabaseConfig, SslMode, create_pool};

let config = DatabaseConfig::builder("postgresql://user:pass@localhost/db")
    .ssl_mode(SslMode::VerifyFull)
    .max_connections(20)
    .min_connections(5)
    .acquire_timeout(Duration::from_secs(30))
    .build();

let pool = create_pool(config).await?;
```

### `SslMode` enum

```rust
pub enum SslMode {
    Disable,    // No SSL
    Prefer,     // SSL if available
    Require,    // Require SSL
    VerifyCA,   // Verify server certificate
    VerifyFull, // Verify server cert and hostname
}
```

---

## TLS

### `TlsMode` enum

```rust
use barbican::tls::{TlsMode, TlsInfo, MtlsMode, detect_tls, tls_enforcement_middleware};

pub enum TlsMode {
    Disabled,  // No TLS requirement
    Preferred, // Allow non-TLS in development
    Required,  // Require TLS
    Strict,    // Require TLS + verify client cert (mTLS)
}
```

### TLS Detection

```rust
// Detect TLS from request headers (set by reverse proxy)
let tls_info: Option<TlsInfo> = detect_tls(&request);

if let Some(info) = tls_info {
    println!("TLS version: {}", info.version);
    println!("Cipher: {}", info.cipher);
    if let Some(client_cert) = info.client_cert {
        println!("Client: {}", client_cert.subject);
    }
}
```

### TLS Enforcement Middleware

```rust
let app = Router::new()
    .route("/", get(handler))
    .layer(tls_enforcement_middleware(TlsMode::Required));
// Returns 403 if request is not over TLS
```

---

## Compliance Profiles

### `ComplianceProfile` enum

```rust
use barbican::compliance::{ComplianceProfile, ComplianceConfig};

pub enum ComplianceProfile {
    Development,    // No security requirements
    FedRampLow,     // FedRAMP Low baseline
    FedRampModerate,// FedRAMP Moderate baseline
    FedRampHigh,    // FedRAMP High baseline
}

impl ComplianceProfile {
    pub fn name(&self) -> &'static str;
    pub fn session_policy(&self) -> SessionPolicy;
    pub fn lockout_policy(&self) -> LockoutPolicy;
    pub fn password_policy(&self) -> PasswordPolicy;
}
```

### Environment Detection

```rust
// Read from BARBICAN_COMPLIANCE_PROFILE env var
let profile = ComplianceProfile::from_env();

// Or parse from string
let profile: ComplianceProfile = "fedramp-moderate".parse()?;
```

---

## Feature Flags

| Feature | Description |
|---------|-------------|
| `postgres` | SQLx PostgreSQL support |
| `hibp` | Have I Been Pwned password checking |
| `fips` | FIPS 140-3 cryptography via AWS-LC |
| `observability-stdout` | JSON logging to stdout (default) |
| `observability-loki` | Push logs to Grafana Loki |
| `observability-otlp` | OpenTelemetry Protocol export |
| `metrics-prometheus` | Prometheus metrics endpoint |
| `compliance-artifacts` | Generate audit evidence files |
| `stig` | STIG/ComplianceAsCode integration |
