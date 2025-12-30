# Barbican Compliance Audit Guide

A step-by-step guide for auditors assessing NIST SP 800-53 Rev 5 compliance of systems built with Barbican.

## Table of Contents

1. [Overview](#overview)
2. [Audit Preparation](#audit-preparation)
3. [Control Family Audits](#control-family-audits)
4. [Evidence Collection](#evidence-collection)
5. [Compliance Artifacts](#compliance-artifacts)
6. [Control Matrices](#control-matrices)

---

## Overview

### What is Barbican?

Barbican is a security infrastructure library that implements NIST SP 800-53 Rev 5 controls for Rust/Axum web applications deployed on NixOS. It provides:

- **56+ directly implemented controls** in Rust code
- **20+ infrastructure controls** via NixOS modules
- **Automated evidence generation** for audit verification
- **Profile-based configuration** for FedRAMP Low/Moderate/High

### Compliance Scope

| Profile | Control Count | Use Case |
|---------|---------------|----------|
| FedRAMP Low | ~125 controls | Limited adverse effect systems |
| FedRAMP Moderate | ~325 controls | Serious adverse effect systems |
| FedRAMP High | ~421 controls | Severe/catastrophic adverse effect systems |

### Audit Approach

For each control, this guide provides:
1. **Control requirement** - What the control mandates
2. **Barbican implementation** - How Barbican addresses it
3. **Evidence location** - Where to find audit evidence
4. **Verification steps** - How to verify compliance

---

## Audit Preparation

### Prerequisites

1. Access to the application source code repository
2. Access to the NixOS configuration (flake.nix, nix/generated/)
3. Access to production logs (or log aggregation system)
4. Access to the `barbican.toml` configuration file

### Key Files to Review

| File | Purpose |
|------|---------|
| `barbican.toml` | Security configuration (single source of truth) |
| `src/generated/barbican_config.rs` | Generated Rust configuration |
| `nix/generated/barbican.nix` | Generated NixOS module configuration |
| `flake.nix` | NixOS deployment definition |
| `Cargo.toml` | Dependency manifest |
| `Cargo.lock` | Locked dependency versions |

### Generating Compliance Artifacts

```bash
# Enable artifact generation
cargo build --features compliance-artifacts

# Run compliance tests (generates artifacts in compliance-artifacts/)
cargo test --features compliance-artifacts compliance_

# View generated artifacts
ls -la compliance-artifacts/
```

---

## Control Family Audits

### Access Control (AC)

#### AC-2: Account Management

**Requirement:** Manage system accounts including identifying, creating, enabling, modifying, disabling, and removing accounts.

**Implementation:**
- `src/auth.rs`: OAuth/OIDC JWT claims validation
- User lifecycle managed by identity provider (IdP)
- JWT claims include user identity and roles

**Evidence:**
```bash
# Verify JWT validation is enforced
grep -n "Claims" src/auth.rs
grep -n "validate" src/auth.rs

# Check configuration
grep -A5 "\[auth\]" barbican.toml
```

**Verification:**
1. Review `barbican.toml` for `[auth]` configuration
2. Verify JWT issuer and audience are configured
3. Confirm OAuth/OIDC provider manages user lifecycle

---

#### AC-4: Information Flow Enforcement

**Requirement:** Enforce approved authorizations for controlling information flow within the system and between systems.

**Implementation:**
- `src/layers.rs`: CORS policy controls cross-origin data flow
- Configured allowed origins in `barbican.toml`

**Evidence:**
```bash
# View CORS configuration
grep -A10 "\[cors\]" barbican.toml

# Verify CORS middleware
grep -n "cors" src/layers.rs
```

**Verification:**
1. Confirm `allowed_origins` matches approved domains
2. Verify `allow_credentials` is `false` unless required
3. Check that `allowed_methods` is restricted to necessary HTTP methods

---

#### AC-6: Least Privilege

**Requirement:** Employ least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Implementation:**
- `nix/modules/systemd-hardening.nix`: Systemd service hardening
  - `CapabilityBoundingSet` - Restricts Linux capabilities
  - `PrivateUsers` - User namespace isolation
  - `NoNewPrivileges` - Prevents privilege escalation

**Evidence:**
```bash
# View systemd hardening
cat nix/modules/systemd-hardening.nix

# In production, verify service configuration
systemctl show <service-name> | grep -E "(Capability|Private|NoNew)"
```

**Verification:**
1. Confirm `CapabilityBoundingSet` is minimized
2. Verify `NoNewPrivileges=true`
3. Check `ProtectSystem=strict`

---

#### AC-7: Unsuccessful Logon Attempts

**Requirement:** Limit unsuccessful logon attempts and take action after reaching the limit.

**Implementation:**
- `src/login.rs`: `LoginTracker` with `LockoutPolicy`
- Profile-based limits:
  - FedRAMP Low: 5 attempts, 15 min lockout
  - FedRAMP Moderate/High: 3 attempts, 30 min lockout

**Evidence:**
```bash
# View login protection implementation
grep -n "LockoutPolicy" src/login.rs
grep -n "max_attempts" src/login.rs

# View configuration
grep -A5 "\[login\]" barbican.toml
```

**Verification:**
1. Confirm `max_attempts` matches profile requirements
2. Verify `lockout_duration_minutes` is appropriate
3. Check that login endpoints are protected

---

#### AC-11: Session Lock

**Requirement:** Lock a session after a period of inactivity.

**Implementation:**
- `src/session.rs`: `SessionPolicy` with idle timeout
- Profile-based timeouts:
  - FedRAMP Low: 15 min idle
  - FedRAMP Moderate: 10 min idle
  - FedRAMP High: 5 min idle

**Evidence:**
```bash
# View session implementation
grep -n "idle_timeout" src/session.rs
grep -n "SessionPolicy" src/session.rs

# View configuration
grep -A5 "\[session\]" barbican.toml
```

**Verification:**
1. Confirm idle timeout matches profile requirement
2. Verify session state tracks last activity
3. Check enforcement middleware is applied to routes

---

#### AC-12: Session Termination

**Requirement:** Automatically terminate a session after defined conditions.

**Implementation:**
- `src/session.rs`: Absolute session timeout
- Profile-based timeouts:
  - FedRAMP Low: 30 min session
  - FedRAMP Moderate: 15 min session
  - FedRAMP High: 10 min session

**Evidence:**
```bash
# View session termination
grep -n "session_timeout" src/session.rs
grep -n "is_expired" src/session.rs
```

**Verification:**
1. Confirm absolute timeout matches profile requirement
2. Verify session termination forces re-authentication

---

### Audit and Accountability (AU)

#### AU-2: Audit Events

**Requirement:** Identify events that require auditing.

**Implementation:**
- `src/audit/mod.rs`: Automatic event classification
- Events captured:
  - Authentication failures (401)
  - Access denials (403)
  - Rate limit violations (429)
  - Server errors (5xx)
  - All successful/failed requests

**Evidence:**
```bash
# View audit event types
grep -n "AuditEvent" src/audit/mod.rs
grep -n "SecurityEvent" src/audit/mod.rs
```

**Verification:**
1. Confirm all security events are logged
2. Verify audit middleware is applied globally
3. Check logs contain required event types

---

#### AU-3: Content of Audit Records

**Requirement:** Audit records must contain sufficient information to establish what happened, when, where, source, and outcome.

**Implementation:**
- `src/audit/mod.rs`: Structured audit records
- Fields captured:
  - Timestamp (when)
  - Client IP (where/source)
  - User ID (who)
  - Method + Path (what)
  - Status code (outcome)
  - Correlation ID (traceability)

**Evidence:**
```bash
# View audit record structure
grep -n "struct AuditRecord" src/audit/mod.rs

# Sample log output
cat /var/log/app/*.log | jq '.timestamp, .client_ip, .user_id, .path, .status'
```

**Verification:**
1. Confirm all required fields are present
2. Verify timestamps are in UTC
3. Check correlation IDs link related events

---

#### AU-9: Protection of Audit Information

**Requirement:** Protect audit information from unauthorized access, modification, and deletion.

**Implementation:**
- `src/audit/integrity.rs`: HMAC chain integrity
- `nix/modules/secure-postgres.nix`: Log file permissions (0600)
- Optional syslog forwarding for centralized collection

**Evidence:**
```bash
# View integrity implementation
grep -n "AuditChain" src/audit/integrity.rs
grep -n "verify" src/audit/integrity.rs

# Check log permissions on production
ls -la /var/log/postgresql/
```

**Verification:**
1. Confirm HMAC signing is enabled for critical logs
2. Verify log file permissions are 0600
3. Check log forwarding to tamper-evident storage

---

#### AU-11: Audit Record Retention

**Requirement:** Retain audit records for a defined period.

**Implementation:**
- `src/compliance/profile.rs`: Profile-based retention
  - FedRAMP Low: 30 days
  - FedRAMP Moderate: 90 days
  - FedRAMP High: 365 days

**Evidence:**
```bash
# View retention configuration
grep -n "retention" src/compliance/profile.rs
grep "log_retention" barbican.toml
```

**Verification:**
1. Confirm retention period matches profile
2. Verify log rotation preserves required history
3. Check backup includes audit logs

---

### Identification and Authentication (IA)

#### IA-2: Identification and Authentication

**Requirement:** Uniquely identify and authenticate organizational users.

**Implementation:**
- `src/auth.rs`: JWT claims validation
- OAuth 2.0 / OIDC token verification
- Issuer and audience validation

**Evidence:**
```bash
# View authentication implementation
grep -n "validate_token" src/auth.rs
grep -n "issuer" src/auth.rs
```

**Verification:**
1. Confirm JWT signature verification
2. Verify issuer matches authorized IdP
3. Check audience claim validation

---

#### IA-2(1): Multi-Factor Authentication

**Requirement:** Implement MFA for privileged and non-privileged accounts.

**Implementation:**
- `src/auth.rs`: MFA policy enforcement
- Validates `amr` (Authentication Methods References) claim
- Profile requirements:
  - FedRAMP Low: MFA for privileged only
  - FedRAMP Moderate/High: MFA for all users

**Evidence:**
```bash
# View MFA implementation
grep -n "MfaPolicy" src/auth.rs
grep -n "mfa_verified" src/auth.rs
grep -n "amr" src/auth.rs
```

**Verification:**
1. Confirm `amr` claim is checked for MFA
2. Verify policy matches profile requirement
3. Check sensitive operations require MFA

---

#### IA-5: Authenticator Management

**Requirement:** Manage system authenticators.

**Implementation:**
- `src/password.rs`: NIST 800-63B password validation
- Password requirements by profile:
  - FedRAMP Low: 8 char minimum
  - FedRAMP Moderate: 12 char minimum
  - FedRAMP High: 14 char minimum

**Evidence:**
```bash
# View password policy
grep -n "PasswordPolicy" src/password.rs
grep -n "min_length" src/password.rs
```

**Verification:**
1. Confirm minimum length matches profile
2. Verify no arbitrary complexity rules (per NIST 800-63B)
3. Check breach database checking (if Moderate+)

---

#### IA-5(2): PKI-Based Authentication

**Requirement:** Implement PKI-based authentication for appropriate use cases.

**Implementation:**
- `nix/modules/secure-postgres.nix`: Client certificate auth
- `src/tls.rs`: mTLS enforcement (FedRAMP High)

**Evidence:**
```bash
# View PostgreSQL client cert config
grep -n "enableClientCert" nix/modules/secure-postgres.nix
grep -n "clientcert=verify-full" nix/modules/secure-postgres.nix

# View mTLS implementation
grep -n "mTLS" src/tls.rs
```

**Verification:**
1. Confirm client certificates required for database
2. Verify mTLS for service-to-service (High profile)
3. Check certificate validation settings

---

### System and Communications Protection (SC)

#### SC-5: Denial of Service Protection

**Requirement:** Protect against DoS attacks.

**Implementation:**
- `src/layers.rs`: Rate limiting via tower-governor
- Request timeouts and body size limits

**Evidence:**
```bash
# View rate limiting
grep -n "rate_limit" src/layers.rs
grep -n "with_rate_limiting" src/layers.rs

# View configuration
grep -A5 "\[rate_limit\]" barbican.toml
```

**Verification:**
1. Confirm rate limits are configured
2. Verify request timeout is set
3. Check body size limit is appropriate

---

#### SC-7: Boundary Protection

**Requirement:** Monitor and control communications at system boundaries.

**Implementation:**
- `nix/modules/vm-firewall.nix`: iptables rules
- Default DROP policy
- Explicit allow rules only

**Evidence:**
```bash
# View firewall configuration
cat nix/modules/vm-firewall.nix
grep -A20 "\[firewall\]" barbican.toml

# On production, verify rules
iptables -L -n -v
```

**Verification:**
1. Confirm default DROP policy
2. Verify only required ports are open
3. Check egress filtering (FedRAMP High)

---

#### SC-8: Transmission Confidentiality

**Requirement:** Protect the confidentiality of transmitted information.

**Implementation:**
- `src/tls.rs`: TLS enforcement middleware
- `nix/modules/secure-postgres.nix`: SSL required

**Evidence:**
```bash
# View TLS enforcement
grep -n "TlsMode" src/tls.rs
grep -n "require_ssl" barbican.toml
```

**Verification:**
1. Confirm TLS required for all connections
2. Verify TLS 1.2+ minimum
3. Check cipher suites exclude weak algorithms

---

#### SC-12: Cryptographic Key Establishment

**Requirement:** Establish and manage cryptographic keys.

**Implementation:**
- `src/keys.rs`: KeyStore trait for KMS integration
- Key rotation tracking
- Support for Vault, AWS KMS, Azure Key Vault

**Evidence:**
```bash
# View key management
grep -n "KeyStore" src/keys.rs
grep -n "RotationTracker" src/keys.rs
```

**Verification:**
1. Confirm key rotation schedule
2. Verify key lifecycle management
3. Check HSM/KMS integration if required

---

#### SC-13: Cryptographic Protection

**Requirement:** Use FIPS-validated cryptography when required.

**Implementation:**
- `src/encryption.rs`: Optional FIPS 140-3 mode
- Uses AWS-LC (Certificate #4631)
- AES-256-GCM encryption

**Evidence:**
```bash
# Check FIPS feature
grep 'fips' Cargo.toml
grep -n "fips" src/encryption.rs
```

**Verification:**
1. Confirm FIPS feature enabled (if required)
2. Verify AWS-LC is the crypto provider
3. Check only FIPS-approved algorithms used

---

#### SC-28: Protection of Information at Rest

**Requirement:** Protect the confidentiality of information at rest.

**Implementation:**
- `src/encryption.rs`: AES-256-GCM field-level encryption
- `nix/modules/database-backup.nix`: Encrypted backups

**Evidence:**
```bash
# View encryption implementation
grep -n "FieldEncryptor" src/encryption.rs
grep -n "AES-256-GCM" src/encryption.rs

# View backup encryption
grep -n "encryption" nix/modules/database-backup.nix
```

**Verification:**
1. Confirm sensitive fields are encrypted
2. Verify encryption keys are managed properly
3. Check backups are encrypted

---

### System and Information Integrity (SI)

#### SI-4: System Monitoring

**Requirement:** Monitor the system to detect attacks and unauthorized activities.

**Implementation:**
- `nix/modules/intrusion-detection.nix`: AIDE + auditd
- File integrity monitoring
- System call auditing

**Evidence:**
```bash
# View intrusion detection
cat nix/modules/intrusion-detection.nix

# On production
aide --check
ausearch -m avc,user_auth
```

**Verification:**
1. Confirm AIDE is configured for critical files
2. Verify auditd rules cover security events
3. Check alert integration for anomalies

---

#### SI-10: Information Input Validation

**Requirement:** Check the validity of information inputs.

**Implementation:**
- `src/validation.rs`: Input validation framework
- XSS, SQLi prevention
- Axum extractors for automatic validation

**Evidence:**
```bash
# View validation implementation
grep -n "Validate" src/validation.rs
grep -n "sanitize" src/validation.rs
grep -n "dangerous_pattern" src/validation.rs
```

**Verification:**
1. Confirm input validation on all endpoints
2. Verify sanitization of user input
3. Check dangerous pattern detection

---

### Supply Chain Risk Management (SR)

#### SR-3: Supply Chain Controls

**Requirement:** Implement supply chain controls.

**Implementation:**
- `src/supply_chain.rs`: cargo audit integration
- Vulnerability scanning of dependencies

**Evidence:**
```bash
# Run vulnerability scan
cargo audit

# View implementation
grep -n "DependencyAudit" src/supply_chain.rs
```

**Verification:**
1. Confirm no high/critical vulnerabilities
2. Verify audit is run in CI/CD
3. Check remediation process exists

---

#### SR-4: Provenance

**Requirement:** Document and verify the provenance of components.

**Implementation:**
- `src/supply_chain.rs`: SBOM generation (CycloneDX)
- Package URLs (purl) for traceability

**Evidence:**
```bash
# Generate SBOM
cargo run --example generate_sbom > sbom.json

# View implementation
grep -n "generate_cyclonedx_sbom" src/supply_chain.rs
```

**Verification:**
1. Confirm SBOM includes all dependencies
2. Verify purl format for each component
3. Check SBOM is updated with releases

---

## Evidence Collection

### Automated Evidence Generation

With the `compliance-artifacts` feature enabled:

```bash
# Run all compliance tests
cargo test --features compliance-artifacts

# View generated artifacts
ls -la compliance-artifacts/
```

Each artifact includes:
- Test name and timestamp
- Control ID(s) addressed
- Test methodology
- Expected vs actual results
- Pass/fail determination

### Log Evidence

```bash
# Export audit logs
journalctl -u myapp.service --since "7 days ago" -o json > audit_logs.json

# Export PostgreSQL logs
cat /var/log/postgresql/*.log > postgres_audit.log

# Export firewall logs
journalctl -k | grep -E "iptables|DROP|REJECT" > firewall.log
```

### Configuration Evidence

```bash
# Export all configuration
tar czf config_evidence.tar.gz \
    barbican.toml \
    Cargo.toml \
    Cargo.lock \
    flake.nix \
    flake.lock \
    nix/generated/ \
    src/generated/
```

---

## Compliance Artifacts

### Artifact Directory Structure

```
compliance-artifacts/
├── AC-7_login_lockout_test.json      # Login attempt testing
├── AC-11_session_idle_test.json      # Idle timeout testing
├── AU-2_audit_events_test.json       # Audit event verification
├── IA-5_password_policy_test.json    # Password validation testing
├── SC-5_rate_limit_test.json         # DoS protection testing
├── SC-8_tls_enforcement_test.json    # TLS verification
├── SI-10_input_validation_test.json  # Input validation testing
└── ...
```

### Artifact Format

```json
{
  "test_name": "AC-7 Login Lockout",
  "timestamp": "2025-12-30T12:00:00Z",
  "controls": ["AC-7"],
  "methodology": "Attempted 5 failed logins, verified lockout after 3rd attempt",
  "expected": "Account locked after 3 failed attempts",
  "actual": "Account locked after 3 failed attempts",
  "evidence": {
    "attempt_1": { "status": 401, "locked": false },
    "attempt_2": { "status": 401, "locked": false },
    "attempt_3": { "status": 401, "locked": true }
  },
  "result": "PASS"
}
```

---

## Control Matrices

### FedRAMP Moderate Control Matrix

| Control | Implementation | Status | Evidence |
|---------|----------------|--------|----------|
| AC-2 | auth.rs JWT validation | Implemented | Code review |
| AC-4 | layers.rs CORS | Implemented | barbican.toml |
| AC-6 | systemd-hardening.nix | Implemented | NixOS config |
| AC-7 | login.rs | Implemented | Test artifacts |
| AC-11 | session.rs | Implemented | Test artifacts |
| AC-12 | session.rs | Implemented | Test artifacts |
| AU-2 | audit/mod.rs | Implemented | Log samples |
| AU-3 | audit/mod.rs | Implemented | Log samples |
| AU-9 | audit/integrity.rs | Implemented | Code review |
| AU-11 | profile.rs | Implemented | barbican.toml |
| AU-12 | audit/mod.rs | Implemented | Log samples |
| IA-2 | auth.rs | Implemented | Code review |
| IA-2(1) | auth.rs MFA | Implemented | Code review |
| IA-5 | password.rs | Implemented | Test artifacts |
| IA-5(1) | password.rs | Implemented | Test artifacts |
| IA-5(2) | secure-postgres.nix | Implemented | NixOS config |
| SC-5 | layers.rs | Implemented | Test artifacts |
| SC-7 | vm-firewall.nix | Implemented | iptables -L |
| SC-8 | tls.rs + secure-postgres.nix | Implemented | SSL scan |
| SC-12 | keys.rs | Implemented | Code review |
| SC-13 | encryption.rs (fips feature) | Optional | Cargo.toml |
| SC-28 | encryption.rs | Implemented | Code review |
| SI-4 | intrusion-detection.nix | Implemented | AIDE report |
| SI-7 | intrusion-detection.nix | Implemented | AIDE report |
| SI-10 | validation.rs | Implemented | Test artifacts |
| SI-11 | error.rs | Implemented | Code review |
| SR-3 | supply_chain.rs | Implemented | cargo audit |
| SR-4 | supply_chain.rs | Implemented | SBOM |

### Control Inheritance

Some controls are inherited from external systems:

| Control | Inherited From |
|---------|----------------|
| AC-2 | Identity Provider (IdP) |
| PE-* | Cloud/Data Center Provider |
| PS-* | Organization HR Policies |
| CP-2/CP-3 | Organization Contingency Plans |
| IR-1/IR-2 | Organization Incident Response |

---

## Appendix: Quick Reference Commands

### Code Analysis

```bash
# Find all control implementations
grep -rn "NIST\|800-53\|FedRAMP" src/

# List all security modules
ls -la src/*.rs nix/modules/*.nix

# Check feature flags
grep "\[features\]" -A 20 Cargo.toml
```

### Configuration Verification

```bash
# Validate barbican.toml
barbican validate

# Show effective configuration
barbican show-config

# Diff generated vs source
diff src/generated/barbican_config.rs <(barbican generate rust --stdout)
```

### Security Testing

```bash
# Run security tests
cargo test security_

# Run compliance tests
cargo test --features compliance-artifacts compliance_

# Run fuzzing tests
cargo test fuzz_
```
