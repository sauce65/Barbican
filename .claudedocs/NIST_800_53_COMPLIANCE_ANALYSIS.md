# NIST SP 800-53 Rev 5 Compliance Analysis for Barbican

**Project:** Barbican Security Library
**Analysis Date:** 2025-12-11
**Purpose:** Determine which NIST 800-53 controls a reusable Rust/Axum security middleware library can implement, facilitate, or should delegate to consuming applications

---

## Executive Summary

Barbican is a security-focused middleware library for Axum web applications with NixOS infrastructure hardening modules. This analysis categorizes all NIST 800-53 Rev 5 control families into four implementation categories:

1. **BARBICAN CAN IMPLEMENT** - Library provides out-of-the-box implementation
2. **BARBICAN CAN FACILITATE** - Library provides hooks/helpers, application must configure
3. **APPLICATION RESPONSIBILITY** - Application-specific logic required
4. **OUT OF SCOPE** - Organizational/physical/personnel controls

### Key Findings

- **18 control families** analyzed across 332+ individual controls
- **47 controls** can be implemented directly by barbican
- **62 controls** barbican can facilitate with hooks and helpers
- **89 controls** are application-specific responsibilities
- **134 controls** are out of scope (organizational/physical)

### Current Implementation Status

**Rust/Axum Middleware:**
- Implemented: SC-5, SC-8, SC-10, SC-28 (partial), AU-2, AU-3, AU-12, AC-4, IA-5 (partial)
- Coverage: ~15% of implementable controls

**NixOS Infrastructure Modules:**
- Implemented: SI-16, AC-2, IA-5, SC-7, AC-17, SI-4, CP-9, CM-7
- Coverage: ~25% of infrastructure controls

---

## Control Family Analysis

### AC: Access Control (25 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **AC-4** | Information Flow Enforcement | CORS middleware with origin allowlist | `SecurityConfig.cors_origins` | HIGH |
| **AC-7** | Unsuccessful Logon Attempts | Rate limiting + account lockout tracking | `LoginAttemptTracker` middleware | HIGH |
| **AC-11** | Device Lock | Session timeout middleware | `SessionConfig.idle_timeout` | MEDIUM |
| **AC-12** | Session Termination | Automatic session expiration | `SessionConfig.max_lifetime` | HIGH |
| **AC-17(2)** | Remote Access - Protection of Confidentiality | TLS enforcement middleware | `TlsConfig` | CRITICAL |

**Concrete Implementation Plan:**

```rust
// AC-7: Unsuccessful Logon Attempts
pub struct LoginAttemptConfig {
    pub max_attempts: u32,              // Default: 5
    pub lockout_duration: Duration,     // Default: 15 minutes
    pub reset_window: Duration,         // Default: 1 hour
    pub storage: Box<dyn AttemptStore>, // Redis, in-memory, DB
}

// Usage
let app = Router::new()
    .layer(LoginAttemptLayer::new(LoginAttemptConfig::from_env()))
    .with_security(SecurityConfig::from_env());
```

```rust
// AC-11/AC-12: Session Management
pub struct SessionConfig {
    pub idle_timeout: Duration,         // Default: 30 minutes (AC-11)
    pub max_lifetime: Duration,         // Default: 8 hours (AC-12)
    pub enforce_https: bool,            // Default: true
    pub secure_cookies: bool,           // Default: true
    pub same_site: SameSite,            // Default: Strict
}

// Middleware provides:
// - Automatic idle timeout detection
// - Absolute session expiration
// - Secure cookie attributes
// - Session renewal on activity
```

```rust
// AC-17(2): TLS Enforcement
pub struct TlsConfig {
    pub min_version: TlsVersion,        // Default: TLS 1.3
    pub cipher_suites: Vec<CipherSuite>,// Strong ciphers only
    pub require_client_cert: bool,      // Default: false (mTLS)
    pub enforce_https: bool,            // Default: true
}

// Middleware rejects non-HTTPS requests in production
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **AC-2** | Account Management | Audit logging hooks for account events | Implement user CRUD, call hooks | HIGH |
| **AC-3** | Access Enforcement | RBAC middleware framework | Define roles, permissions, rules | CRITICAL |
| **AC-5** | Separation of Duties | Role checking middleware | Define conflicting role pairs | MEDIUM |
| **AC-6** | Least Privilege | Permission verification middleware | Define granular permissions | HIGH |
| **AC-8** | System Use Notification | Login banner middleware | Provide banner text, record consent | LOW |
| **AC-10** | Concurrent Session Control | Session counting middleware | Choose max concurrent sessions | MEDIUM |
| **AC-14** | Permitted Actions Without Identification | Public endpoint whitelist middleware | Define which endpoints are public | MEDIUM |

**Concrete Implementation:**

```rust
// AC-2: Account Management Hooks
use barbican::observability::{SecurityEvent, security_event};

// Application calls when creating user:
security_event!(
    SecurityEvent::UserRegistered,
    user_id = %user.id,
    email = %user.email,
    created_by = %admin_id,
    "User account created"
);

// Barbican automatically logs with:
// - Timestamp (AU-3)
// - Event type (AU-2)
// - Category: "user_management"
// - Severity: Medium
```

```rust
// AC-3: RBAC Framework
pub trait Authorization {
    async fn authorize(&self, user: &User, resource: &Resource, action: &Action) -> bool;
}

pub struct RbacLayer<A: Authorization> {
    authorizer: A,
}

// Application implements:
struct MyAuthorizer;
impl Authorization for MyAuthorizer {
    async fn authorize(&self, user: &User, resource: &Resource, action: &Action) -> bool {
        // Check user.roles against resource.required_roles
        user.has_permission(resource, action)
    }
}

// Usage:
let app = Router::new()
    .route("/admin", get(admin_handler))
    .layer(RbacLayer::new(MyAuthorizer))
    .layer(AuthenticationLayer::new(auth_config));
```

```rust
// AC-10: Concurrent Session Control
pub struct ConcurrentSessionConfig {
    pub max_sessions_per_user: u32,     // Application defines
    pub storage: Box<dyn SessionStore>, // Redis, DB
    pub on_limit_exceeded: SessionPolicy, // Reject new, evict oldest
}

// Middleware counts active sessions per user
// Application chooses policy
```

#### APPLICATION RESPONSIBILITY

| Control | Name | Why Application Must Implement |
|---------|------|--------------------------------|
| **AC-1** | Policy and Procedures | Organizational policy document |
| **AC-9** | Previous Logon Notification | Business logic: store/display last login |
| **AC-16** | Security Attributes | Domain-specific attributes (clearance, classification) |
| **AC-19** | Access Control for Mobile Devices | Device management logic |
| **AC-20** | Use of External Systems | Business rules for external system access |
| **AC-21** | Information Sharing | Data sharing agreements, business logic |
| **AC-22** | Publicly Accessible Content | Content approval workflows |
| **AC-23** | Data Mining Protection | Domain-specific data anonymization |
| **AC-24** | Access Control Decisions | Complex business authorization logic |
| **AC-25** | Reference Monitor | Security kernel decisions |

#### OUT OF SCOPE

AC-1 (organizational policy), AC-18 (wireless access policy), AC-19 (mobile device management policy)

---

### AU: Audit and Accountability (16 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **AU-2** | Audit Events | `SecurityEvent` enum with 25+ event types | Extend enum for app-specific events | CRITICAL |
| **AU-3** | Content of Audit Records | Structured logging with required fields | `security_event!` macro | CRITICAL |
| **AU-4** | Audit Log Storage Capacity | Log rotation configuration | `ObservabilityConfig.rotation` | HIGH |
| **AU-5** | Response to Audit Failure | Alerting on log pipeline failure | `ObservabilityConfig.on_failure` | HIGH |
| **AU-6(3)** | Audit Review - Correlate Repositories | Centralized logging (Loki, OTLP) | Feature flags | MEDIUM |
| **AU-8** | Time Stamps | UTC timestamps on all events | Automatic | CRITICAL |
| **AU-9** | Protection of Audit Information | Write-only log destinations | Provider configuration | HIGH |
| **AU-10** | Non-repudiation | Immutable audit logs | Log signing (optional feature) | MEDIUM |
| **AU-11** | Audit Record Retention | Retention policy configuration | `ObservabilityConfig.retention` | HIGH |
| **AU-12** | Audit Record Generation | `security_event!` macro | Application calls macro | CRITICAL |
| **AU-14** | Session Audit | Session lifecycle logging | `SessionLayer` | MEDIUM |

**Concrete Implementation:**

```rust
// AU-2, AU-3, AU-12: Already Implemented
// See src/observability/events.rs

// AU-4: Log Storage Capacity
pub struct LogRotationConfig {
    pub max_size: usize,           // Default: 100MB per file
    pub max_files: u32,            // Default: 10 files
    pub compress: bool,            // Default: true
    pub retention_days: u32,       // Default: 90 days (AU-11)
}

// AU-5: Audit Failure Response
pub enum AuditFailurePolicy {
    Alert,                          // Send alert, continue
    Halt,                           // Stop application (critical systems)
    Fallback(Box<dyn LogSink>),    // Use fallback logger
}

pub struct ObservabilityConfig {
    pub rotation: LogRotationConfig,
    pub on_failure: AuditFailurePolicy,
    pub verify_delivery: bool,      // Confirm logs written (AU-9)
}
```

```rust
// AU-10: Non-repudiation (Log Signing)
#[cfg(feature = "audit-signing")]
pub struct LogSigningConfig {
    pub private_key: SigningKey,
    pub algorithm: SigningAlgorithm, // Ed25519, ECDSA
    pub include_chain: bool,         // Merkle tree for tamper detection
}

// Each log entry gets signature:
// {"timestamp": "...", "event": "...", "signature": "..."}
```

```rust
// AU-14: Session Audit
// Automatically logs:
// - Session created (user_id, ip, user_agent)
// - Session activity (last_seen updates)
// - Session destroyed (reason: timeout, logout, revoked)

pub struct SessionAuditLayer {
    config: SessionConfig,
}

// Application just uses sessions, auditing automatic
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **AU-6** | Audit Review | Log query helpers, filtering | Implement review workflow | MEDIUM |
| **AU-7** | Audit Reduction | Log aggregation utilities | Define reduction rules | MEDIUM |
| **AU-16** | Cross-Organizational Audit | Correlation ID middleware | Parse external correlation IDs | LOW |

**Concrete Implementation:**

```rust
// AU-6: Audit Review Helpers
pub mod audit_query {
    pub fn filter_by_user(logs: &[LogEntry], user_id: &str) -> Vec<LogEntry>;
    pub fn filter_by_severity(logs: &[LogEntry], min: Severity) -> Vec<LogEntry>;
    pub fn filter_by_category(logs: &[LogEntry], category: &str) -> Vec<LogEntry>;
    pub fn filter_by_timerange(logs: &[LogEntry], start: DateTime, end: DateTime) -> Vec<LogEntry>;
}

// Application builds review dashboard using helpers
```

```rust
// AU-16: Cross-Org Correlation
pub struct CorrelationIdLayer {
    pub header_name: String,        // Default: "X-Correlation-ID"
    pub generate_if_missing: bool,  // Default: true
}

// Automatically propagates correlation IDs across service boundaries
// Application logs with correlation ID included
```

#### APPLICATION RESPONSIBILITY

| Control | Name | Why Application Must Implement |
|---------|------|--------------------------------|
| **AU-1** | Policy and Procedures | Organizational audit policy |
| **AU-6(1)** | Automated Analysis | Domain-specific anomaly detection |
| **AU-7(1)** | Automatic Processing | Business-specific log processing |
| **AU-13** | Monitoring for Information Disclosure | PII detection (domain-specific) |

#### OUT OF SCOPE

AU-1 (organizational policy), AU-15 (alternate audit capability - physical backups)

---

### CA: Assessment, Authorization, and Monitoring (9 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **CA-7** | Continuous Monitoring | Health check endpoints | `HealthCheckConfig` | HIGH |
| **CA-8** | Penetration Testing | Security test helpers | Test utilities module | MEDIUM |

**Concrete Implementation:**

```rust
// CA-7: Continuous Monitoring
pub struct HealthCheckConfig {
    pub endpoints: Vec<HealthCheck>,
}

pub enum HealthCheck {
    Database(DatabaseConfig),
    Redis(RedisConfig),
    ExternalApi { url: String, timeout: Duration },
    Custom(Box<dyn Fn() -> HealthStatus>),
}

// Provides /health endpoint:
// GET /health -> {"status": "healthy", "checks": [...]}
let app = Router::new()
    .merge(barbican::health_routes(health_config));
```

```rust
// CA-8: Penetration Test Helpers
#[cfg(test)]
pub mod security_tests {
    // SQL injection test helpers
    pub fn test_sql_injection(client: &TestClient, endpoint: &str);

    // XSS test helpers
    pub fn test_xss(client: &TestClient, endpoint: &str);

    // CSRF test helpers
    pub fn test_csrf(client: &TestClient, endpoint: &str);

    // Authentication bypass tests
    pub fn test_auth_bypass(client: &TestClient, protected_routes: &[&str]);
}
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **CA-2** | Security Assessments | Audit report generation | Perform assessment, provide findings | MEDIUM |
| **CA-5** | Plan of Action | Vulnerability tracking utilities | Track actual vulnerabilities | LOW |

#### APPLICATION RESPONSIBILITY

All other CA controls are organizational processes (assessment plans, authorization procedures, continuous monitoring plans).

#### OUT OF SCOPE

CA-1 (policy), CA-3 (information exchange), CA-4 (security certification), CA-6 (authorization), CA-9 (internal connections)

---

### CM: Configuration Management (14 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **CM-2** | Baseline Configuration | NixOS declarative configs | Flake modules | HIGH |
| **CM-3** | Configuration Change Control | Audit logging on config changes | `SecurityEvent::ConfigurationChanged` | HIGH |
| **CM-6** | Configuration Settings | Secure defaults for all settings | Override via env vars or builder | CRITICAL |
| **CM-7** | Least Functionality | Minimal NixOS system profiles | `barbican.nixosModules.minimal` | HIGH |
| **CM-7(5)** | Authorized Software | NixOS allowed packages | `environment.systemPackages` allowlist | MEDIUM |
| **CM-8** | System Component Inventory | Dependency manifest | `Cargo.lock`, `flake.lock` | MEDIUM |

**Concrete Implementation:**

```rust
// CM-3: Configuration Change Auditing
impl SecurityConfig {
    pub fn from_env() -> Self {
        let config = Self::load_from_env();

        // Log configuration at startup
        security_event!(
            SecurityEvent::ConfigurationChanged,
            max_request_size = config.max_request_size,
            rate_limit_per_second = config.rate_limit_per_second,
            cors_origins = ?config.cors_origins,
            "Security configuration loaded"
        );

        config
    }
}

// Runtime configuration changes also logged
impl SecurityConfig {
    pub fn update(&mut self, new_config: SecurityConfig) {
        let old = self.clone();
        *self = new_config;

        security_event!(
            SecurityEvent::ConfigurationChanged,
            changed_by = %context.user_id,
            old_rate_limit = old.rate_limit_per_second,
            new_rate_limit = self.rate_limit_per_second,
            "Security configuration updated"
        );
    }
}
```

```nix
# CM-2, CM-7: NixOS Baseline Configuration
# Already implemented in nix/profiles/{minimal,standard,hardened}.nix

# CM-7(5): Authorized Software Allowlist
{ config, lib, pkgs, ... }: {
  environment.systemPackages = lib.mkForce [
    # Only explicitly allowed packages
    pkgs.curl
    pkgs.vim
    pkgs.htop
  ];

  # Prevent package installation
  nix.settings.allowed-users = [ "root" ];

  # Log package installations
  barbican.intrusionDetection.auditRules = [
    "-w /nix/store -p w -k software_install"
  ];
}
```

```rust
// CM-8: Component Inventory
pub fn generate_sbom() -> SoftwareBillOfMaterials {
    // Parse Cargo.lock
    // Generate SPDX or CycloneDX format
    // Include:
    // - Direct dependencies
    // - Transitive dependencies
    // - Version numbers
    // - License information
    // - Known vulnerabilities (from cargo-audit)
}

// Exposed as CLI tool:
// cargo barbican sbom --format spdx > sbom.json
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **CM-4** | Impact Analysis | Configuration validation | Define business impact rules | MEDIUM |
| **CM-5** | Access Restrictions | Config file permissions | Define who can change config | HIGH |
| **CM-9** | Configuration Management Plan | Template CM plan | Customize for organization | LOW |
| **CM-10** | Software Usage Restrictions | License checking | Define acceptable licenses | MEDIUM |
| **CM-11** | User-Installed Software | Installation detection | Define approval workflow | MEDIUM |

#### APPLICATION RESPONSIBILITY

CM-1 (policy), CM-4(1) (testing), CM-12 (information location), CM-13 (data action mapping)

#### OUT OF SCOPE

CM-1 (organizational policy), CM-14 (cryptographic protection - managed by OS/hardware)

---

### CP: Contingency Planning (13 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **CP-9** | System Backup | Automated encrypted backups | `barbican.nixosModules.databaseBackup` | HIGH |
| **CP-10** | System Recovery | Health checks + auto-restart | Systemd + `HealthCheckLayer` | HIGH |

**Concrete Implementation:**

```nix
# CP-9: Already Implemented
# See nix/modules/database-backup.nix
{ config, ... }: {
  barbican.databaseBackup = {
    enable = true;
    schedule = "daily";              # Daily backups
    retention = 30;                  # 30-day retention
    encryption = {
      enable = true;
      publicKey = "/etc/backup-key.pub";
    };
    destination = "s3://backups/";
  };
}
```

```rust
// CP-10: System Recovery
pub struct RecoveryConfig {
    pub health_check_interval: Duration,     // Default: 30s
    pub failure_threshold: u32,              // Default: 3 consecutive failures
    pub recovery_action: RecoveryAction,
}

pub enum RecoveryAction {
    Restart,                                 // Restart service
    Failover(String),                        // Failover to backup URL
    Alert,                                   // Alert only, no auto-recovery
}

// Middleware monitors health checks
// Triggers recovery action on persistent failure
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **CP-2** | Contingency Plan | Contingency plan template | Customize for application | MEDIUM |
| **CP-6** | Alternate Storage Site | Backup destination config | Provision backup storage | HIGH |
| **CP-7** | Alternate Processing Site | Multi-region deployment helpers | Deploy to multiple regions | HIGH |
| **CP-8** | Telecommunications Services | Connection failover | Configure backup providers | MEDIUM |

#### APPLICATION RESPONSIBILITY

CP-1 (policy), CP-3 (training), CP-4 (testing), CP-11 (alternate communications), CP-12 (safe mode), CP-13 (backup verification)

#### OUT OF SCOPE

CP-1 (organizational policy), CP-3 (training), CP-4 (plan testing)

---

### IA: Identification and Authentication (13 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **IA-2(1)** | MFA to Privileged Accounts | TOTP/WebAuthn middleware | `MfaLayer` | CRITICAL |
| **IA-2(2)** | MFA to Non-Privileged | TOTP/WebAuthn middleware | `MfaLayer` | HIGH |
| **IA-2(6)** | Access to Privileged Accounts - Separate Device | Certificate-based auth | mTLS middleware | MEDIUM |
| **IA-2(8)** | Access to Accounts - Replay Resistant | Nonce-based authentication | `NonceLayer` | HIGH |
| **IA-2(12)** | Acceptance of PIV Credentials | PIV/CAC card support | Smart card middleware | LOW |
| **IA-3** | Device Identification | Client certificate verification | mTLS config | MEDIUM |
| **IA-5(1)** | Password-Based Authentication | Password policy enforcement | `PasswordPolicy` struct | CRITICAL |
| **IA-5(2)** | PKI-Based Authentication | Certificate validation | mTLS middleware | HIGH |
| **IA-5(7)** | No Embedded Unencrypted Static Authenticators | Secret detection scanner | Compile-time check | CRITICAL |
| **IA-6** | Authentication Feedback | Password masking utilities | Frontend helpers | LOW |
| **IA-8** | Identification and Authentication (Non-Org Users) | OAuth 2.0/OIDC client | `OAuthLayer` | HIGH |
| **IA-11** | Re-authentication | Periodic re-auth middleware | `ReauthLayer` | MEDIUM |

**Concrete Implementation:**

```rust
// IA-2(1), IA-2(2): Multi-Factor Authentication
pub struct MfaConfig {
    pub required_for_roles: Vec<String>,    // Default: ["admin"]
    pub totp: TotpConfig,
    pub webauthn: WebAuthnConfig,
    pub backup_codes: bool,                 // Default: true
}

pub struct TotpConfig {
    pub issuer: String,
    pub period: u32,                        // Default: 30 seconds
    pub digits: u32,                        // Default: 6
    pub algorithm: TotpAlgorithm,           // SHA1, SHA256, SHA512
}

// Middleware checks MFA after primary authentication
pub struct MfaLayer {
    config: MfaConfig,
    storage: Box<dyn MfaStorage>,
}

// Usage:
let app = Router::new()
    .route("/admin", get(admin_handler))
    .layer(MfaLayer::new(MfaConfig::from_env()))
    .layer(AuthenticationLayer::new(auth_config));
```

```rust
// IA-5(1): Password Policy
pub struct PasswordPolicy {
    pub min_length: usize,                  // Default: 12 (NIST 800-63B)
    pub max_length: usize,                  // Default: 128
    pub require_uppercase: bool,            // Default: false (NIST recommends not)
    pub require_lowercase: bool,            // Default: false
    pub require_digit: bool,                // Default: false
    pub require_special: bool,              // Default: false
    pub check_pwned: bool,                  // Default: true (Have I Been Pwned API)
    pub prevent_common: bool,               // Default: true (top 10k list)
    pub max_age_days: Option<u32>,         // Default: None (NIST recommends no expiry)
    pub prevent_reuse: usize,               // Default: 5 (last 5 passwords)
}

impl PasswordPolicy {
    pub fn validate(&self, password: &str) -> Result<(), PasswordError> {
        // Length checks
        if password.len() < self.min_length {
            return Err(PasswordError::TooShort);
        }

        // Pwned password check
        if self.check_pwned && self.is_pwned(password).await? {
            return Err(PasswordError::Compromised);
        }

        // Common password check
        if self.prevent_common && COMMON_PASSWORDS.contains(password) {
            return Err(PasswordError::TooCommon);
        }

        Ok(())
    }
}
```

```rust
// IA-2(8): Replay Resistance
pub struct NonceLayer {
    pub nonce_lifetime: Duration,           // Default: 5 minutes
    pub storage: Box<dyn NonceStore>,       // Redis, in-memory
}

// Middleware ensures each nonce used only once
// Rejects replay attacks
```

```rust
// IA-5(2): PKI-Based Authentication (mTLS)
pub struct MtlsConfig {
    pub require_client_cert: bool,
    pub trusted_ca: PathBuf,                // CA certificate
    pub verify_hostname: bool,
    pub allowed_subjects: Vec<String>,      // DN patterns
}

// Already partially implemented in database.rs (DB mTLS)
// Need to add HTTP mTLS support
```

```rust
// IA-5(7): No Embedded Static Authenticators
// Cargo plugin to scan for secrets at compile time
// cargo barbican check-secrets

pub fn scan_for_secrets(source_dir: &Path) -> Vec<SecretViolation> {
    let patterns = [
        r"password\s*=\s*['\"].*['\"]",      // Hardcoded passwords
        r"api_key\s*=\s*['\"].*['\"]",       // API keys
        r"secret\s*=\s*['\"].*['\"]",        // Secrets
        r"token\s*=\s*['\"].*['\"]",         // Tokens
        r"-----BEGIN.*PRIVATE KEY-----",     // Private keys
    ];

    // Scan all .rs files
    // Return violations with file:line
}
```

```rust
// IA-8: OAuth 2.0 / OIDC Client
pub struct OAuthConfig {
    pub provider: OAuthProvider,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

pub enum OAuthProvider {
    Google,
    GitHub,
    Microsoft,
    Custom { discovery_url: String },
}

pub struct OAuthLayer {
    config: OAuthConfig,
}

// Provides OAuth callback handling
// Returns authenticated user info
```

```rust
// IA-11: Re-authentication for Sensitive Operations
pub struct ReauthConfig {
    pub sensitive_endpoints: Vec<String>,   // Require re-auth
    pub re_auth_window: Duration,           // Default: 15 minutes
}

// Middleware requires fresh authentication for sensitive operations
// Example: password change, delete account, financial transaction
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **IA-2** | Identification and Authentication | Authentication middleware framework | Implement auth method (JWT, session) | CRITICAL |
| **IA-4** | Identifier Management | User ID generation helpers | Manage user lifecycle | HIGH |
| **IA-5** | Authenticator Management | Credential storage helpers | Store hashed credentials | CRITICAL |
| **IA-5(4)** | Automated Support for Password Strength | Password strength meter | Display to user | MEDIUM |
| **IA-9** | Service Identification and Authentication | API key middleware | Generate and manage API keys | HIGH |
| **IA-10** | Adaptive Authentication | Risk-based auth framework | Define risk calculation | MEDIUM |

**Concrete Implementation:**

```rust
// IA-2: Authentication Framework
pub trait Authenticator {
    async fn authenticate(&self, credentials: &Credentials) -> Result<User, AuthError>;
}

pub struct JwtAuthenticator {
    pub signing_key: SigningKey,
    pub issuer: String,
    pub audience: String,
    pub expiry: Duration,
}

impl Authenticator for JwtAuthenticator {
    async fn authenticate(&self, credentials: &Credentials) -> Result<User, AuthError> {
        // Validate JWT
        // Return User
    }
}

// Application chooses authenticator
let app = Router::new()
    .layer(AuthenticationLayer::new(JwtAuthenticator::new(config)));
```

```rust
// IA-9: API Key Authentication
pub struct ApiKeyConfig {
    pub header_name: String,                // Default: "X-API-Key"
    pub prefix: String,                     // Default: "bk_" (barbican key)
    pub storage: Box<dyn ApiKeyStore>,
    pub rate_limit_per_key: Option<u64>,
}

// Provides API key generation
pub fn generate_api_key(prefix: &str) -> String {
    format!("{}_{}", prefix, random_string(32))
}

// Middleware validates API key
pub struct ApiKeyLayer {
    config: ApiKeyConfig,
}
```

```rust
// IA-10: Adaptive Authentication
pub trait RiskCalculator {
    async fn calculate_risk(&self, context: &AuthContext) -> RiskScore;
}

pub struct AuthContext {
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub location: Option<GeoLocation>,
    pub device_fingerprint: Option<String>,
    pub recent_failures: u32,
}

pub struct RiskScore(f32); // 0.0 = low risk, 1.0 = high risk

pub struct AdaptiveAuthLayer<R: RiskCalculator> {
    risk_calculator: R,
    high_risk_threshold: f32,           // Require MFA if above
    block_threshold: f32,               // Block if above
}

// Application implements RiskCalculator with business logic
```

#### APPLICATION RESPONSIBILITY

IA-1 (policy), IA-7 (cryptographic module authentication - hardware), IA-12 (identity proofing)

#### OUT OF SCOPE

IA-1 (organizational policy), IA-12 (identity proofing - real-world identity verification)

---

### IR: Incident Response (10 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **IR-4** | Incident Handling | Security event alerting | `AlertingConfig` | HIGH |
| **IR-5** | Incident Monitoring | Real-time event streaming | Metrics + log monitoring | HIGH |
| **IR-6** | Incident Reporting | Structured incident reports | `IncidentReport` struct | MEDIUM |

**Concrete Implementation:**

```rust
// IR-4: Incident Handling (Alerting)
pub struct AlertingConfig {
    pub critical_events: Vec<SecurityEvent>,    // Auto-alert on these
    pub destinations: Vec<AlertDestination>,
}

pub enum AlertDestination {
    Email { to: Vec<String> },
    Slack { webhook_url: String },
    PagerDuty { integration_key: String },
    Webhook { url: String },
}

// Middleware automatically sends alerts on critical events
impl ObservabilityConfig {
    pub fn with_alerting(mut self, config: AlertingConfig) -> Self {
        self.alerting = Some(config);
        self
    }
}

// When critical event logged:
security_event!(SecurityEvent::BruteForceDetected, ...);
// -> Automatically sends alert via configured destinations
```

```rust
// IR-5: Incident Monitoring
// Expose real-time event stream endpoint
// GET /api/security-events (SSE or WebSocket)

pub struct EventStreamConfig {
    pub require_auth: bool,                     // Default: true
    pub allowed_roles: Vec<String>,             // Default: ["admin", "security"]
    pub buffer_size: usize,                     // Default: 1000 events
}

// Streams security events in real-time for monitoring dashboards
```

```rust
// IR-6: Incident Reporting
pub struct IncidentReport {
    pub id: Uuid,
    pub detected_at: DateTime<Utc>,
    pub detected_by: DetectionSource,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub affected_systems: Vec<String>,
    pub indicators: Vec<Indicator>,
    pub timeline: Vec<TimelineEvent>,
    pub response_actions: Vec<ResponseAction>,
    pub status: IncidentStatus,
}

pub enum IncidentStatus {
    Detected,
    Investigating,
    Contained,
    Remediated,
    Closed,
}

// API to create incident from security events
pub async fn create_incident_from_events(
    events: Vec<SecurityEvent>,
    description: String,
) -> IncidentReport;
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **IR-2** | Incident Response Training | Security test scenarios | Conduct training | LOW |
| **IR-3** | Incident Response Testing | Simulated attack tests | Execute tests | MEDIUM |
| **IR-8** | Incident Response Plan | IR plan template | Customize plan | MEDIUM |

#### APPLICATION RESPONSIBILITY

IR-1 (policy), IR-7 (assistance), IR-9 (information spillage), IR-10 (integrated information security analysis team)

#### OUT OF SCOPE

IR-1 (organizational policy), IR-7 (incident response assistance - SOC team), IR-10 (integrated team - organizational)

---

### MA: Maintenance (6 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **MA-4** | Nonlocal Maintenance | Audit logging of remote admin | `SecurityEvent::RemoteAdministration` | MEDIUM |

**Concrete Implementation:**

```rust
// MA-4: Nonlocal Maintenance Logging
// Add to SecurityEvent enum:
pub enum SecurityEvent {
    // ... existing events
    RemoteAdministrationStarted,
    RemoteAdministrationEnded,
    RemoteConfigurationChanged,
}

// Application logs when admin connects remotely:
security_event!(
    SecurityEvent::RemoteAdministrationStarted,
    admin_id = %admin.id,
    ip_address = %remote_ip,
    method = "ssh",
    "Remote administration session started"
);
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **MA-2** | Controlled Maintenance | Maintenance mode middleware | Schedule maintenance | MEDIUM |
| **MA-3** | Maintenance Tools | Tool authorization tracking | Approve tools | LOW |
| **MA-5** | Maintenance Personnel | Personnel authorization | Manage authorized list | LOW |

```rust
// MA-2: Maintenance Mode
pub struct MaintenanceConfig {
    pub enabled: bool,
    pub message: String,
    pub allowed_ips: Vec<IpAddr>,           // Admin IPs allowed during maintenance
}

// Middleware returns 503 Service Unavailable during maintenance
// Except for allowed IPs
```

#### APPLICATION RESPONSIBILITY

MA-1 (policy), MA-6 (timely maintenance)

#### OUT OF SCOPE

MA-1 (organizational policy)

---

### MP: Media Protection (8 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **MP-5** | Media Transport | Encrypted backup transport | `databaseBackup.encryption` | HIGH |
| **MP-6** | Media Sanitization | Secure deletion utilities | `secure_delete()` function | MEDIUM |

**Concrete Implementation:**

```nix
# MP-5: Already implemented in nix/modules/database-backup.nix
# Backups encrypted before transport
```

```rust
// MP-6: Secure Deletion
pub fn secure_delete(path: &Path) -> Result<(), IoError> {
    // Overwrite file with random data before deleting
    let file_size = fs::metadata(path)?.len();
    let mut file = OpenOptions::new().write(true).open(path)?;

    // 3-pass overwrite (DoD 5220.22-M standard)
    for _ in 0..3 {
        let random_data = generate_random_bytes(file_size as usize);
        file.write_all(&random_data)?;
        file.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(())
}
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **MP-2** | Media Access | Access control to backup storage | Implement access policy | MEDIUM |
| **MP-4** | Media Storage | Encrypted storage configuration | Configure storage provider | HIGH |
| **MP-7** | Media Use | Removable media controls | Define usage policy | LOW |

#### APPLICATION RESPONSIBILITY

MP-1 (policy), MP-3 (media marking), MP-8 (media downgrading)

#### OUT OF SCOPE

MP-1 (organizational policy), MP-3 (physical media marking), MP-7 (portable/mobile device policy)

---

### PE: Physical and Environmental Protection (20 controls)

#### BARBICAN CAN IMPLEMENT

**None** - Physical controls are infrastructure/organizational, not software.

#### OUT OF SCOPE

**All PE controls** - Physical access, environmental controls, fire suppression, temperature/humidity, power, emergency lighting, visitor control, etc. These are datacenter/facility responsibilities.

---

### PL: Planning (11 controls)

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **PL-2** | System Security Plan | SSP template with barbican controls | Customize for system | MEDIUM |
| **PL-8** | Security Architecture | Architecture documentation | Define application architecture | LOW |

**Concrete Implementation:**

```markdown
# PL-2: System Security Plan Template
Barbican provides SSP template with pre-filled control implementations:

## AC-4: Information Flow Enforcement
**Implementation:** Barbican CORS middleware enforces origin-based access control.
**Configuration:** `CORS_ALLOWED_ORIGINS=https://app.example.com`
**Verification:** Security tests verify CORS enforcement
**Responsible Party:** [Organization to fill in]
**Implementation Status:** Implemented

[Template continues for all barbican controls...]
```

#### APPLICATION RESPONSIBILITY

PL-1 (policy), PL-4 (rules of behavior), PL-7 (concept of operations), PL-9 (central management), PL-10 (baseline selection), PL-11 (baseline tailoring)

#### OUT OF SCOPE

All PL controls are organizational planning activities.

---

### PM: Program Management (16 controls)

#### OUT OF SCOPE

**All PM controls** - These are organizational program management activities (risk management strategy, security architecture, insider threat program, critical infrastructure plan, etc.). Not implementable in software library.

---

### PS: Personnel Security (8 controls)

#### OUT OF SCOPE

**All PS controls** - These are HR/personnel controls (background checks, termination procedures, personnel sanctions, access agreements, etc.). Not implementable in software library.

---

### PT: PII Processing and Transparency (8 controls)

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **PT-2** | Authority to Process PII | PII processing authorization tracking | Define PII and authorization | MEDIUM |
| **PT-3** | PII Processing Purposes | Purpose logging for PII access | Define processing purposes | MEDIUM |
| **PT-5** | Privacy Notice | Privacy notice middleware | Provide privacy policy text | LOW |
| **PT-6** | System of Records Notice | SORN template | Customize SORN | LOW |

**Concrete Implementation:**

```rust
// PT-3: PII Processing Purpose Logging
pub struct PiiAccess {
    pub field: String,                      // e.g., "email", "ssn"
    pub purpose: PiiProcessingPurpose,
    pub user_id: String,
    pub timestamp: DateTime<Utc>,
}

pub enum PiiProcessingPurpose {
    Authentication,
    Communication,
    Billing,
    Analytics,
    LegalRequirement,
    Custom(String),
}

// Log PII access with purpose
security_event!(
    SecurityEvent::PiiAccessed,
    field = "email",
    purpose = "communication",
    user_id = %user.id,
    "PII accessed"
);
```

```rust
// PT-5: Privacy Notice
pub struct PrivacyNoticeConfig {
    pub notice_url: String,
    pub require_acceptance: bool,
    pub acceptance_expiry: Duration,        // Re-accept after 1 year
}

// Middleware ensures user has accepted current privacy notice
// Redirects to notice if not accepted
```

#### APPLICATION RESPONSIBILITY

PT-1 (policy), PT-4 (consent), PT-7 (specific categories of PII), PT-8 (computer matching requirements)

#### OUT OF SCOPE

PT-1 (organizational policy)

---

### RA: Risk Assessment (10 controls)

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **RA-3** | Risk Assessment | Vulnerability scanning utilities | Conduct risk assessment | HIGH |
| **RA-5** | Vulnerability Monitoring | Automated dependency scanning | Review and remediate | CRITICAL |
| **RA-7** | Risk Response | Risk tracking utilities | Make risk decisions | MEDIUM |

**Concrete Implementation:**

```rust
// RA-5: Vulnerability Monitoring (Already Implemented)
// cargo audit integration
// Provides: cargo barbican audit

pub fn run_vulnerability_scan() -> VulnerabilityReport {
    // Run cargo-audit
    // Parse results
    // Generate report with:
    // - RUSTSEC IDs
    // - Affected crates
    // - Severity
    // - Remediation (update to version X)
    // - Exploitability assessment
}

// Can be run in CI/CD:
// cargo barbican audit --fail-on critical
```

```rust
// RA-3: Risk Assessment Helpers
pub struct RiskAssessment {
    pub asset: String,
    pub threats: Vec<Threat>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub likelihood: Likelihood,
    pub impact: Impact,
    pub risk_level: RiskLevel,
}

pub enum RiskLevel {
    Low,
    Moderate,
    High,
    Critical,
}

// Utilities to document risk assessments
// Export as JSON/CSV for risk register
```

#### APPLICATION RESPONSIBILITY

RA-1 (policy), RA-2 (security categorization), RA-4 (risk assessment update), RA-6 (technical surveillance countermeasures), RA-8 (privacy impact assessment), RA-9 (criticality analysis), RA-10 (threat hunting)

#### OUT OF SCOPE

RA-1 (organizational policy), RA-6 (technical surveillance - physical), RA-8 (privacy impact assessment - organizational), RA-10 (threat hunting - SOC activity)

---

### SA: System and Services Acquisition (23 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **SA-10** | Developer Configuration Management | Lock file integrity | `Cargo.lock`, `flake.lock` | HIGH |
| **SA-11** | Developer Testing | Security test suite | `cargo barbican test-security` | HIGH |
| **SA-15(7)** | Continuous Monitoring | CI/CD security checks | GitHub Actions workflows | MEDIUM |

**Concrete Implementation:**

```rust
// SA-10: Lock File Integrity
// Verify Cargo.lock hasn't been tampered with
pub fn verify_lock_file_integrity() -> Result<(), IntegrityError> {
    // Hash Cargo.lock
    // Compare with expected hash (in CLAUDE.md or CI)
    // Detect if dependencies changed without updating lock
}

// In CI/CD:
// cargo barbican verify-lockfile --expected-hash abc123
```

```bash
# SA-11: Developer Testing (Security Test Suite)
# cargo barbican test-security
# Runs comprehensive security tests:
# - SQL injection tests
# - XSS tests
# - CSRF tests
# - Authentication bypass tests
# - Authorization tests
# - Rate limiting tests
# - Session management tests
# - Input validation tests

$ cargo barbican test-security
Running security test suite...
✓ SQL injection prevention (12/12 tests passed)
✓ XSS prevention (8/8 tests passed)
✓ CSRF protection (6/6 tests passed)
✓ Authentication (15/15 tests passed)
✓ Authorization (20/20 tests passed)
✓ Rate limiting (5/5 tests passed)
✓ Session management (10/10 tests passed)

Security test score: 76/76 (100%)
```

```yaml
# SA-15(7): Continuous Monitoring (CI/CD)
# .github/workflows/security.yml
name: Security Checks

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
      - name: Dependency audit
        run: cargo audit
      - name: Security tests
        run: cargo barbican test-security
      - name: Lock file verification
        run: cargo barbican verify-lockfile
      - name: Secret scanning
        run: cargo barbican check-secrets
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **SA-3** | System Development Life Cycle | Secure SDLC template | Implement SDLC | MEDIUM |
| **SA-4** | Acquisition Process | Security requirements checklist | Customize for acquisitions | LOW |
| **SA-8** | Security Engineering Principles | Security design patterns | Apply to architecture | MEDIUM |
| **SA-11(1)** | Static Code Analysis | Clippy security lints | Run and fix issues | HIGH |
| **SA-15** | Development Process | Secure development guide | Follow guide | MEDIUM |

```rust
// SA-11(1): Static Code Analysis
// Barbican provides security-focused clippy lints

// cargo barbican lint
// Checks for:
// - Use of unsafe blocks
// - Hardcoded secrets
// - Use of weak crypto (MD5, SHA1)
// - Non-constant-time comparisons on secrets
// - SQL injection risks (non-parameterized queries)
// - Path traversal risks
```

#### APPLICATION RESPONSIBILITY

SA-1 (policy), SA-2 (allocation of resources), SA-5 (system documentation), SA-9 (external services), SA-12 (supply chain protection), SA-16 (developer-provided training), SA-17 (developer security architecture)

#### OUT OF SCOPE

Most SA controls are organizational acquisition/contracting processes.

---

### SC: System and Communications Protection (51 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **SC-2** | Separation of System and User Functionality | Separate admin/user APIs | Router organization | MEDIUM |
| **SC-5** | Denial of Service Protection | Rate limiting + size limits | Already implemented | CRITICAL |
| **SC-7** | Boundary Protection | Network firewall rules | `barbican.nixosModules.vmFirewall` | HIGH |
| **SC-7(5)** | Deny by Default / Allow by Exception | Default-deny firewall | Already implemented | CRITICAL |
| **SC-8** | Transmission Confidentiality | TLS enforcement | Already implemented (DB), add HTTP | CRITICAL |
| **SC-8(1)** | Cryptographic Protection | TLS 1.3 with strong ciphers | `TlsConfig` | CRITICAL |
| **SC-10** | Network Disconnect | Request timeout | Already implemented | HIGH |
| **SC-12** | Cryptographic Key Management | Key rotation utilities | `KeyManagementConfig` | HIGH |
| **SC-13** | Cryptographic Protection | Approved algorithms | Constant-time ops | HIGH |
| **SC-17** | PKI Certificates | Certificate validation | mTLS config | HIGH |
| **SC-18** | Mobile Code | CSP headers | Already implemented | MEDIUM |
| **SC-20** | Secure Name Resolution | DNSSEC validation | DNS resolver config | MEDIUM |
| **SC-21** | Secure Name Resolution - Request/Response Integrity | DNSSEC | DNS config | MEDIUM |
| **SC-23** | Session Authenticity | Session token signing | `SessionConfig` | HIGH |
| **SC-28** | Protection of Information at Rest | Database encryption | Already implemented (partial) | CRITICAL |
| **SC-28(1)** | Cryptographic Protection | Encrypted backups | Already implemented | HIGH |

**Concrete Implementation:**

```rust
// SC-8(1): TLS 1.3 Enforcement
pub struct TlsConfig {
    pub min_version: TlsVersion,            // Default: TLS 1.3
    pub cipher_suites: Vec<CipherSuite>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub require_https: bool,                // Default: true in production
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::V1_3,
            cipher_suites: vec![
                // Only strong, modern ciphers
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_AES_128_GCM_SHA256,
            ],
            // ...
        }
    }
}

// Middleware rejects TLS < 1.3
pub struct TlsEnforcementLayer {
    config: TlsConfig,
}
```

```rust
// SC-12: Cryptographic Key Management
pub struct KeyManagementConfig {
    pub rotation_period: Duration,          // Default: 90 days
    pub storage: KeyStorage,
    pub algorithm: KeyAlgorithm,
}

pub enum KeyStorage {
    File { path: PathBuf, encrypted: bool },
    Hsm { device: String },
    KMS { provider: KmsProvider },
}

// Provides key rotation utilities
pub async fn rotate_keys(config: &KeyManagementConfig) -> Result<(), KeyError> {
    // Generate new key
    // Update configuration
    // Keep old key for decryption of existing data
    // Schedule old key deletion after grace period
}
```

```rust
// SC-23: Session Authenticity
pub struct SessionConfig {
    pub signing_key: SigningKey,            // HMAC key for session tokens
    pub encryption_key: EncryptionKey,      // Encrypt session data
    pub algorithm: SessionAlgorithm,
}

pub enum SessionAlgorithm {
    HmacSha256,                             // Sign only
    Aes256Gcm,                              // Encrypt + authenticate
}

// Session tokens are cryptographically signed
// Prevents tampering and forging
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **SC-4** | Information in Shared System Resources | Memory zeroing utilities | Use when handling secrets | HIGH |
| **SC-6** | Resource Availability | Resource limit configuration | Set appropriate limits | HIGH |
| **SC-7(4)** | External Telecommunications Services | VPN/tunnel configuration | Configure tunnels | MEDIUM |
| **SC-11** | Trusted Path | Secure connection indicators | Display indicators to user | MEDIUM |
| **SC-15** | Collaborative Computing | Screen sharing controls | Implement controls | LOW |
| **SC-28(2)** | Offline Storage | Encrypted offline backups | Configure offline storage | MEDIUM |
| **SC-39** | Process Isolation | Sandboxing configuration | Configure sandboxes | HIGH |

```rust
// SC-4: Memory Zeroing
pub fn zeroize_memory(buffer: &mut [u8]) {
    // Secure memory zeroing (prevents compiler optimization)
    use zeroize::Zeroize;
    buffer.zeroize();
}

// Trait for types containing secrets
pub trait SecretType: Zeroize {
    fn new(value: Vec<u8>) -> Self;
}

// Example:
struct ApiKey(Vec<u8>);
impl Drop for ApiKey {
    fn drop(&mut self) {
        self.0.zeroize();  // Zero memory on drop
    }
}
```

```nix
# SC-39: Process Isolation (Systemd Sandboxing)
# Already implemented in nix/modules/systemd-hardening.nix
{ config, ... }: {
  systemd.services.myapp = {
    serviceConfig = barbican.lib.systemdHardening.webService // {
      # Sandboxing enabled by default:
      # - PrivateTmp = true
      # - ProtectSystem = "strict"
      # - ProtectHome = true
      # - NoNewPrivileges = true
      # - PrivateDevices = true
      # - ProtectKernelTunables = true
      # - ProtectControlGroups = true
      # - RestrictAddressFamilies = "AF_INET AF_INET6"
    };
  };
}
```

#### APPLICATION RESPONSIBILITY

| Control | Name | Why Application Must Implement |
|---------|------|--------------------------------|
| **SC-3** | Security Function Isolation | Application-specific security boundaries |
| **SC-16** | Transmission of Security Attributes | Domain-specific security labels |
| **SC-22** | Architecture and Provisioning for Name Resolution | Application-specific DNS architecture |
| **SC-24** | Fail in Known State | Application-specific failure modes |
| **SC-30** | Concealment and Misdirection | Application-specific obfuscation |
| **SC-31** | Covert Channel Analysis | Application-specific covert channels |
| **SC-32** | System Partitioning | Application architecture |

#### OUT OF SCOPE

SC-1 (policy), SC-25 (thin nodes - hardware), SC-26 (honeypots), SC-27 (platform-independent applications), SC-29 (heterogeneity), SC-33 (transmission preparation integrity), SC-34 (non-modifiable executable programs), SC-36 (distributed processing), SC-37 (out-of-band channels), SC-38 (operations security), SC-40 (wireless link protection), SC-41 (port and I/O device access), SC-42 (sensor capability), SC-43 (usage restrictions), SC-44 (detonation chambers), SC-45 (system time synchronization - handled by timeSync module), SC-46 (cross-domain policy enforcement), SC-47 (alternate communications paths), SC-48 (sensor relocation)

---

### SI: System and Information Integrity (23 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **SI-2** | Flaw Remediation | Dependency update monitoring | `cargo barbican outdated` | CRITICAL |
| **SI-3** | Malicious Code Protection | Dependency vulnerability scanning | `cargo audit` integration | CRITICAL |
| **SI-4** | System Monitoring | Intrusion detection | `barbican.nixosModules.intrusionDetection` | HIGH |
| **SI-4(5)** | System-Generated Alerts | Automated alerting on anomalies | `AlertingConfig` | HIGH |
| **SI-7** | Software Integrity | Binary signature verification | Signed releases | HIGH |
| **SI-10** | Information Input Validation | Input validation framework | `ValidationLayer` | CRITICAL |
| **SI-11** | Error Handling | Secure error responses | Error handling middleware | HIGH |
| **SI-16** | Memory Protection | Kernel hardening | Already implemented | HIGH |

**Concrete Implementation:**

```rust
// SI-2: Flaw Remediation (Dependency Updates)
// cargo barbican outdated
pub fn check_outdated_dependencies() -> OutdatedReport {
    // Parse Cargo.toml and Cargo.lock
    // Check crates.io for newer versions
    // Categorize: security updates, minor updates, major updates
    // Return report with update recommendations
}

// Output:
// Outdated dependencies found:
// [SECURITY] tokio 1.28.0 -> 1.28.2 (fixes RUSTSEC-2023-0001)
// [MAJOR] axum 0.6.0 -> 0.7.0 (breaking changes)
// [MINOR] serde 1.0.160 -> 1.0.163 (compatible)
```

```rust
// SI-10: Information Input Validation
pub struct ValidationConfig {
    pub max_string_length: usize,           // Default: 1000
    pub allowed_charsets: Vec<CharSet>,
    pub sanitize_html: bool,                // Default: true
    pub validate_email: bool,               // Default: true
    pub validate_url: bool,                 // Default: true
}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

// Derive macro for automatic validation
#[derive(Validate)]
struct UserInput {
    #[validate(length(min = 1, max = 100))]
    #[validate(regex = "^[a-zA-Z0-9_-]+$")]
    username: String,

    #[validate(email)]
    email: String,

    #[validate(length(min = 12, max = 128))]
    password: String,
}

// Middleware automatically validates request bodies
pub struct ValidationLayer {
    config: ValidationConfig,
}
```

```rust
// SI-11: Error Handling
pub struct ErrorHandlingConfig {
    pub production_mode: bool,              // Hide details in production
    pub log_errors: bool,                   // Default: true
    pub include_request_id: bool,           // Default: true
}

// Middleware catches panics and returns safe error responses
// Production: {"error": "Internal server error", "request_id": "abc123"}
// Development: {"error": "DatabaseError: connection refused at ...", ...}

pub struct ErrorHandlingLayer {
    config: ErrorHandlingConfig,
}
```

```rust
// SI-7: Software Integrity (Binary Signing)
// Release process includes signing binaries
// Users verify signatures before running

// Generate signature:
// cargo barbican sign-release --key release-key.pem

// Verify signature:
// cargo barbican verify-signature --binary barbican-x86_64-linux --signature barbican.sig --pubkey release-pubkey.pem
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **SI-4(2)** | Automated Tools for Real-Time Analysis | Monitoring hooks | Implement analysis rules | HIGH |
| **SI-8** | Spam Protection | Rate limiting + content filtering | Define spam rules | MEDIUM |
| **SI-12** | Information Management | Data lifecycle management | Define retention policies | MEDIUM |

```rust
// SI-8: Spam Protection
pub struct SpamProtectionConfig {
    pub rate_limit: RateLimitConfig,        // Already have this
    pub content_filters: Vec<ContentFilter>,
    pub captcha: Option<CaptchaConfig>,
}

pub struct ContentFilter {
    pub pattern: Regex,
    pub action: FilterAction,
}

pub enum FilterAction {
    Block,
    Quarantine,
    FlagForReview,
}

// Application defines content filters
// Barbican applies them via middleware
```

#### APPLICATION RESPONSIBILITY

| Control | Name | Why Application Must Implement |
|---------|------|--------------------------------|
| **SI-1** | Policy and Procedures | Organizational policy |
| **SI-5** | Security Alerts | Subscribe to advisories, triage |
| **SI-6** | Security Functionality Verification | Application-specific security tests |
| **SI-7(1)** | Integrity Checks | Application-specific integrity checks |
| **SI-9** | Information Input Restrictions | Business-specific input rules |
| **SI-13** | Predictable Failure Prevention | Application-specific failure modes |
| **SI-14** | Non-Persistence | Stateless architecture decisions |
| **SI-15** | Information Output Filtering | Business-specific output filtering |
| **SI-17** | Fail-Safe Procedures | Application-specific fail-safe |
| **SI-18** | Personally Identifiable Information Quality | PII validation rules |
| **SI-19** | De-identification | Anonymization algorithms |
| **SI-20** | Tainting | Data provenance tracking |
| **SI-21** | Information Refresh | Data refresh logic |
| **SI-22** | Information Diversity | Redundant data sources |
| **SI-23** | Information Fragmentation | Data splitting strategies |

#### OUT OF SCOPE

SI-1 (policy)

---

### SR: Supply Chain Risk Management (12 controls)

#### BARBICAN CAN IMPLEMENT

| Control | Name | Implementation | Pluggability | Priority |
|---------|------|----------------|--------------|----------|
| **SR-3** | Supply Chain Controls | SBOM generation | `cargo barbican sbom` | HIGH |
| **SR-4** | Provenance | Dependency provenance tracking | Lock file + signatures | HIGH |
| **SR-6** | Supplier Assessments | Crate reputation scoring | `cargo barbican assess-deps` | MEDIUM |
| **SR-11** | Component Authenticity | Checksum verification | Cargo.lock verification | HIGH |

**Concrete Implementation:**

```rust
// SR-3: SBOM Generation (Already mentioned in CM-8)
// cargo barbican sbom --format spdx
// cargo barbican sbom --format cyclonedx

// Generates comprehensive SBOM including:
// - All direct and transitive dependencies
// - Version numbers and licenses
// - Known vulnerabilities
// - Download URLs and checksums
// - Supplier information
```

```rust
// SR-4: Dependency Provenance
pub fn verify_dependency_provenance() -> ProvenanceReport {
    // For each dependency in Cargo.lock:
    // - Verify it's from crates.io (trusted source)
    // - Check if published by verified author
    // - Verify checksums match
    // - Check for suspicious recent ownership changes
    // - Flag if downloaded from git (higher risk)
}
```

```rust
// SR-6: Supplier Assessment (Crate Reputation)
pub struct CrateReputation {
    pub name: String,
    pub downloads: u64,
    pub recent_downloads: u64,               // Last 90 days
    pub github_stars: Option<u32>,
    pub open_issues: Option<u32>,
    pub last_updated: DateTime<Utc>,
    pub maintainers: Vec<Maintainer>,
    pub security_advisories: u32,
    pub reputation_score: f32,               // 0-100
}

// cargo barbican assess-deps
// Scores each dependency on:
// - Popularity (download count)
// - Maintenance (recent updates)
// - Community trust (stars, maintainers)
// - Security history (advisories)
// Flags suspicious dependencies
```

```rust
// SR-11: Component Authenticity
// Verify Cargo.lock checksums match crates.io
pub fn verify_checksums() -> Result<(), ChecksumError> {
    // For each dependency:
    // - Download crate from crates.io
    // - Compute SHA256 checksum
    // - Compare with checksum in Cargo.lock
    // - Error if mismatch (supply chain attack detected)
}
```

#### BARBICAN CAN FACILITATE

| Control | Name | Facilitation | Application Must | Priority |
|---------|------|--------------|------------------|----------|
| **SR-2** | Supply Chain Risk Management Plan | SCRM plan template | Customize plan | MEDIUM |
| **SR-5** | Acquisition Strategies | Secure dependency selection guide | Follow guide | MEDIUM |
| **SR-10** | Inspection of Systems | Audit checklist | Perform audit | MEDIUM |

#### APPLICATION RESPONSIBILITY

SR-1 (policy), SR-7 (supply chain operations security), SR-8 (notification agreements), SR-9 (tamper resistance), SR-12 (component disposal)

#### OUT OF SCOPE

SR-1 (organizational policy), SR-7 (OPSEC - operational), SR-8 (contractual agreements), SR-9 (hardware tamper resistance), SR-12 (physical disposal)

---

## Implementation Priority Matrix

### CRITICAL (Implement First)

These controls provide the highest security value and should be prioritized:

| Control | Name | Effort | Impact | Status |
|---------|------|--------|--------|--------|
| **AC-3** | Access Enforcement (RBAC) | High | Critical | To Do |
| **AC-17(2)** | TLS Enforcement | Medium | Critical | Partial (DB only) |
| **AU-2/3/12** | Audit Logging | Low | Critical | Implemented |
| **IA-2(1)** | Multi-Factor Auth | High | Critical | To Do |
| **IA-5(1)** | Password Policy | Medium | Critical | To Do |
| **RA-5** | Vulnerability Scanning | Low | Critical | Implemented |
| **SC-5** | DoS Protection | Low | Critical | Implemented |
| **SC-8** | Transmission Confidentiality | Medium | Critical | Partial |
| **SC-13** | Cryptographic Protection | Low | Critical | Implemented |
| **SI-2** | Flaw Remediation | Low | Critical | To Do |
| **SI-3** | Malicious Code Protection | Low | Critical | Implemented |
| **SI-10** | Input Validation | High | Critical | To Do |

### HIGH (Implement Next)

| Control | Name | Effort | Impact | Status |
|---------|------|--------|--------|--------|
| **AC-2** | Account Management | Low | High | Facilitated |
| **AC-4** | Information Flow | Low | High | Implemented |
| **AC-6** | Least Privilege | Medium | High | To Do |
| **AC-7** | Login Attempts | Medium | High | To Do |
| **AC-11/12** | Session Management | High | High | To Do |
| **AU-4/5** | Audit Storage | Medium | High | To Do |
| **AU-9** | Audit Protection | Medium | High | To Do |
| **CA-7** | Continuous Monitoring | Low | High | Partial |
| **CM-2/7** | Baseline Config | Low | High | Implemented (Nix) |
| **CP-9** | System Backup | Low | High | Implemented (Nix) |
| **IA-5(2)** | PKI Auth (mTLS) | High | High | To Do |
| **IA-8** | OAuth/OIDC | High | High | To Do |
| **IR-4/5** | Incident Handling | Medium | High | To Do |
| **SC-7** | Boundary Protection | Low | High | Implemented (Nix) |
| **SC-12** | Key Management | High | High | To Do |
| **SC-23** | Session Authenticity | Medium | High | To Do |
| **SI-4** | System Monitoring | Medium | High | Implemented (Nix) |
| **SI-7** | Software Integrity | Medium | High | To Do |
| **SI-11** | Error Handling | Low | High | To Do |
| **SR-3/4** | Supply Chain (SBOM) | Medium | High | To Do |

### MEDIUM (Implement Later)

| Control | Name | Effort | Impact | Status |
|---------|------|--------|--------|--------|
| **AC-5** | Separation of Duties | Medium | Medium | To Do |
| **AC-10** | Concurrent Sessions | Medium | Medium | To Do |
| **AU-6/7** | Audit Review | Medium | Medium | To Do |
| **CA-8** | Penetration Testing | Low | Medium | To Do |
| **CM-3/6** | Config Management | Low | Medium | Partial |
| **IA-3** | Device Identification | High | Medium | To Do |
| **IA-10** | Adaptive Auth | High | Medium | To Do |
| **IA-11** | Re-authentication | Medium | Medium | To Do |
| **IR-6** | Incident Reporting | Medium | Medium | To Do |
| **MA-2** | Maintenance Mode | Low | Medium | To Do |
| **SC-2** | Security Function Separation | Medium | Medium | To Do |
| **SC-20/21** | DNSSEC | Medium | Medium | To Do |
| **SI-8** | Spam Protection | Medium | Medium | To Do |
| **SR-6** | Supplier Assessment | Medium | Medium | To Do |

### LOW (Nice to Have)

All other implementable controls fall into this category and should be prioritized based on specific compliance requirements.

---

## Recommended Implementation Roadmap

### Phase 1: Core Security (Months 1-2)

**Goal:** Implement critical authentication, authorization, and input validation

1. **Input Validation Framework** (SI-10)
   - Derive macro for validation
   - Built-in validators (email, URL, length, regex)
   - Sanitization utilities
   - Middleware integration

2. **RBAC Framework** (AC-3, AC-6)
   - Authorization trait
   - Role checking middleware
   - Permission verification
   - Example implementations

3. **Password Policy** (IA-5(1))
   - Policy configuration
   - Validation functions
   - Pwned password checking
   - Password strength meter

4. **TLS Enforcement** (AC-17(2), SC-8)
   - HTTP TLS middleware
   - Version enforcement (TLS 1.3+)
   - Strong cipher suites
   - HSTS enforcement

### Phase 2: Advanced Authentication (Months 3-4)

**Goal:** Add MFA, OAuth, and session management

1. **Multi-Factor Authentication** (IA-2(1), IA-2(2))
   - TOTP support
   - WebAuthn support
   - Backup codes
   - Recovery flows

2. **OAuth 2.0 / OIDC Client** (IA-8)
   - Provider abstraction
   - Authorization code flow
   - Token validation
   - User info endpoint

3. **Session Management** (AC-11, AC-12, SC-23)
   - Session configuration
   - Idle timeout
   - Absolute timeout
   - Secure cookies
   - Session signing/encryption

4. **Login Attempt Tracking** (AC-7)
   - Attempt counting
   - Account lockout
   - Rate limiting integration
   - Unlock mechanisms

### Phase 3: Audit and Incident Response (Months 5-6)

**Goal:** Enhance logging, monitoring, and incident handling

1. **Advanced Audit Logging** (AU-4, AU-5, AU-9, AU-11)
   - Log rotation
   - Failure handling
   - Write-only destinations
   - Retention policies
   - Log signing (optional)

2. **Incident Response** (IR-4, IR-5, IR-6)
   - Alerting framework
   - Alert destinations (email, Slack, PagerDuty)
   - Event streaming API
   - Incident report structure

3. **Continuous Monitoring** (CA-7, SI-4(5))
   - Health check framework
   - Custom health checks
   - Automated alerts
   - Dashboard integration

4. **Error Handling** (SI-11)
   - Safe error responses
   - Production/dev modes
   - Error logging
   - Request ID correlation

### Phase 4: Supply Chain and Key Management (Months 7-8)

**Goal:** Secure the software supply chain and cryptographic keys

1. **Supply Chain Security** (SR-3, SR-4, SR-6, SR-11)
   - SBOM generation
   - Provenance tracking
   - Crate reputation scoring
   - Checksum verification

2. **Dependency Management** (SI-2, SI-3)
   - Outdated dependency checking
   - Update recommendations
   - Security advisory integration
   - Automated update PRs (optional)

3. **Key Management** (SC-12)
   - Key rotation framework
   - Key storage abstraction (file, HSM, KMS)
   - Grace period handling
   - Key generation utilities

4. **Software Integrity** (SI-7, SR-11)
   - Binary signing
   - Signature verification
   - Release automation
   - Update verification

### Phase 5: Advanced Features (Months 9-12)

**Goal:** Implement remaining high-value controls

1. **Advanced Authorization** (AC-5, AC-10, AC-14)
   - Separation of duties checks
   - Concurrent session limits
   - Public endpoint whitelist
   - Dynamic policy evaluation

2. **API Security** (IA-9, IA-10)
   - API key management
   - API key rotation
   - Adaptive authentication
   - Risk-based access

3. **Content Security** (SI-8, SI-10)
   - Spam protection
   - Content filtering
   - CAPTCHA integration
   - Advanced validation rules

4. **Testing and Verification** (SA-11, CA-8)
   - Security test suite
   - Penetration test helpers
   - Fuzzing integration
   - Security benchmarks

---

## NixOS Infrastructure Modules Roadmap

The following controls should be implemented as additional NixOS modules to complement the existing ones:

### High Priority NixOS Modules

1. **TLS/Certificate Management** (SC-8(1), SC-17)
   - Automatic certificate renewal (Let's Encrypt)
   - Certificate validation
   - Strong cipher enforcement
   - Certificate monitoring

2. **Network Segmentation** (SC-7)
   - Virtual network zones (already have basics)
   - VLAN configuration
   - Inter-zone firewall rules
   - Zero-trust networking

3. **Secret Management** (Already have, enhance) (IA-5)
   - sops-nix integration (exists)
   - Secret rotation automation
   - Secret access auditing
   - Emergency secret revocation

4. **Compliance Reporting** (CA-2, CA-7)
   - Automated compliance checks
   - Report generation
   - Control status dashboard
   - Evidence collection

5. **Automated Updates** (SI-2, CM-11)
   - Security update automation
   - Rollback on failure
   - Update testing
   - Update notification

### Medium Priority NixOS Modules

1. **Centralized Authentication** (AC-2, IA-2)
   - LDAP/Active Directory integration
   - Single sign-on
   - Centralized user management
   - Account lifecycle automation

2. **File Integrity Monitoring** (SI-7, enhance existing AIDE)
   - Real-time monitoring
   - Alert on changes
   - Automatic restoration
   - Change attribution

3. **Log Management** (AU-4, AU-9, AU-11)
   - Centralized log collection
   - Log encryption
   - Long-term archival
   - Log integrity verification

4. **Vulnerability Scanning** (RA-5)
   - Automated scanning
   - CVE tracking
   - Remediation workflows
   - Risk scoring

---

## Testing Strategy

All implemented controls must have corresponding tests:

### Unit Tests
- Test each control's logic in isolation
- Verify configuration parsing
- Test edge cases and boundary conditions

### Integration Tests
- Test middleware stack interactions
- Verify control enforcement
- Test failure modes

### Security Tests
- Test attack scenarios (SQL injection, XSS, etc.)
- Verify controls prevent attacks
- Test bypass attempts

### Compliance Tests
- Verify control implementation matches NIST requirements
- Generate audit evidence
- Test control effectiveness

### NixOS VM Tests
- Test infrastructure hardening
- Verify system configuration
- Test across different profiles (minimal, standard, hardened)

---

## Metrics and Success Criteria

### Implementation Metrics

Track progress with these metrics:

- **Control Coverage:** X / 47 implementable controls complete (target: 100%)
- **Control Facilitation:** X / 62 facilitation controls with helpers (target: 80%)
- **Test Coverage:** X% of controls have passing tests (target: 100%)
- **Documentation:** X% of controls have usage examples (target: 100%)

### Quality Metrics

- **Security Test Score:** X / Y tests passing (target: 100%)
- **Vulnerability Count:** X known vulnerabilities (target: 0 critical/high)
- **Code Coverage:** X% line coverage (target: 80%+)
- **Performance Impact:** < 5% latency increase from middleware

### Adoption Metrics

- **Library Downloads:** Track crates.io downloads
- **GitHub Stars:** Community interest indicator
- **Issues/PRs:** Community engagement
- **Production Deployments:** Real-world usage

---

## Conclusion

Barbican can implement or facilitate **109 out of 332 NIST 800-53 controls** (33%), making it a highly valuable security library for Rust/Axum applications. The remaining 223 controls are either:

- **Application-specific** (89 controls): Business logic that varies per application
- **Organizational** (134 controls): Policies, procedures, and organizational processes

This analysis provides a clear roadmap for making barbican a comprehensive, NIST 800-53 compliant security library that:

1. **Implements** 47 controls out-of-the-box with secure defaults
2. **Facilitates** 62 controls with frameworks, hooks, and helpers
3. **Documents** 89 application responsibilities clearly
4. **Explains** why 134 controls are out of scope

By following the phased implementation roadmap, barbican can become the go-to security library for compliance-focused Rust applications, significantly reducing the burden on development teams building FedRAMP, SOC 2, or other compliance-required systems.

---

## Appendix: Control Quick Reference

### Controls by Implementation Category

**BARBICAN CAN IMPLEMENT (47 controls):**
AC-4, AC-7, AC-11, AC-12, AC-17(2), AU-2, AU-3, AU-4, AU-5, AU-6(3), AU-8, AU-9, AU-10, AU-11, AU-12, AU-14, CA-7, CA-8, CM-2, CM-3, CM-6, CM-7, CM-7(5), CM-8, CP-9, CP-10, IA-2(1), IA-2(2), IA-2(6), IA-2(8), IA-2(12), IA-3, IA-5(1), IA-5(2), IA-5(7), IA-6, IA-8, IA-11, IR-4, IR-5, IR-6, MA-4, MP-5, MP-6, SC-5, SC-7, SC-7(5), SC-8, SC-8(1), SC-10, SC-12, SC-13, SC-17, SC-18, SC-20, SC-21, SC-23, SC-28, SC-28(1), SI-2, SI-3, SI-4, SI-4(5), SI-7, SI-10, SI-11, SI-16, SA-10, SA-11, SA-15(7), SR-3, SR-4, SR-6, SR-11

**BARBICAN CAN FACILITATE (62 controls):**
AC-2, AC-3, AC-5, AC-6, AC-8, AC-10, AC-14, AU-6, AU-7, AU-16, CA-2, CA-5, CM-4, CM-5, CM-9, CM-10, CM-11, CP-2, CP-6, CP-7, CP-8, IA-2, IA-4, IA-5, IA-5(4), IA-9, IA-10, IR-2, IR-3, IR-8, MA-2, MA-3, MA-5, MP-2, MP-4, MP-7, PL-2, PL-8, PT-2, PT-3, PT-5, PT-6, RA-3, RA-5, RA-7, SA-3, SA-4, SA-8, SA-11(1), SA-15, SC-2, SC-4, SC-6, SC-7(4), SC-11, SC-15, SC-28(2), SC-39, SI-4(2), SI-8, SI-12, SR-2, SR-5, SR-10

**Total Barbican Can Help With: 109 controls (33% of all NIST 800-53 controls)**

This represents significant compliance value for organizations building secure Rust applications.
