# Barbican Compliance Audit Guide

A step-by-step guide for auditors assessing NIST SP 800-53 Rev 5 compliance of systems built with Barbican.

## Table of Contents

1. [Overview](#overview)
2. [Audit Workflow](#audit-workflow)
3. [Phase 1: Preparation](#phase-1-preparation)
4. [Phase 2: Automated Testing](#phase-2-automated-testing)
5. [Phase 3: Configuration Verification](#phase-3-configuration-verification)
6. [Phase 4: Control Family Audits](#phase-4-control-family-audits)
7. [Phase 5: Production Runtime Verification](#phase-5-production-runtime-verification)
8. [Phase 6: Evidence Collection](#phase-6-evidence-collection)
9. [Phase 7: Report Generation](#phase-7-report-generation)
10. [Control Reference](#control-reference)
11. [Appendix](#appendix)

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

### Profile Requirements Quick Reference

| Control | FedRAMP Low | FedRAMP Moderate | FedRAMP High |
|---------|-------------|------------------|--------------|
| AC-7: Max login attempts | 5 | 3 | 3 |
| AC-7: Lockout duration | 15 min | 30 min | 30 min |
| AC-11: Idle timeout | 15 min | 10 min | 5 min |
| AC-12: Session max | 30 min | 15 min | 10 min |
| AU-11: Log retention | 30 days | 90 days | 365 days |
| IA-2(1): MFA required | Privileged only | All users | All users |
| IA-5: Password min length | 8 chars | 12 chars | 14 chars |
| SC-7: Egress filtering | Optional | Recommended | Required |
| SC-8: mTLS | Optional | Optional | Required |
| SC-13: FIPS crypto | Optional | Recommended | Required |

---

## Audit Workflow

Complete these phases in order for a thorough compliance audit:

```
Phase 1: Preparation
    │
    ├── Gather prerequisites
    ├── Identify target profile
    └── Clone/access repository
          │
          ▼
Phase 2: Automated Testing
    │
    ├── Build application
    ├── Run control tests
    ├── Generate compliance artifacts
    └── Run vulnerability scan
          │
          ▼
Phase 3: Configuration Verification
    │
    ├── Verify barbican.toml settings
    ├── Verify generated Rust config
    ├── Verify generated NixOS config
    └── Check config consistency
          │
          ▼
Phase 4: Control Family Audits
    │
    ├── Access Control (AC)
    ├── Audit & Accountability (AU)
    ├── Identification & Authentication (IA)
    ├── System & Communications Protection (SC)
    ├── System & Information Integrity (SI)
    └── Supply Chain Risk Management (SR)
          │
          ▼
Phase 5: Production Runtime Verification
    │
    ├── Verify FIPS cryptography active
    ├── Test mTLS connections
    ├── Verify firewall/egress filtering
    ├── Test session timeouts
    ├── Verify audit logging active
    └── Check intrusion detection running
          │
          ▼
Phase 6: Evidence Collection
    │
    ├── Export compliance artifacts
    ├── Export configuration files
    ├── Collect production logs
    └── Capture runtime state
          │
          ▼
Phase 7: Report Generation
    │
    ├── Complete control matrix
    ├── Document findings
    ├── Note gaps/recommendations
    └── Sign and date report
```

---

## Phase 1: Preparation

### Prerequisites Checklist

- [ ] Access to application source code repository
- [ ] Access to NixOS configuration (`flake.nix`, `nix/generated/`)
- [ ] Access to production logs (or log aggregation system)
- [ ] Access to `barbican.toml` configuration file
- [ ] Rust toolchain installed (`rustup`, `cargo`)
- [ ] `cargo-audit` installed (`cargo install cargo-audit`)

### Key Files to Review

| File | Purpose | Required |
|------|---------|----------|
| `barbican.toml` | Security configuration (single source of truth) | Yes |
| `src/generated/barbican_config.rs` | Generated Rust configuration | Yes |
| `nix/generated/barbican.nix` | Generated NixOS module configuration | Yes |
| `flake.nix` | NixOS deployment definition | Yes |
| `Cargo.toml` | Dependency manifest | Yes |
| `Cargo.lock` | Locked dependency versions | Yes |
| `secrets/*.age` | Encrypted secrets (verify existence only) | If applicable |

### Identify Target Profile

```bash
# Check the profile in barbican.toml
grep -E "^profile\s*=" barbican.toml

# Expected output examples:
# profile = "fedramp-low"
# profile = "fedramp-moderate"
# profile = "fedramp-high"
```

Record the profile for use in subsequent phases:
- **Target Profile:** ___________________
- **Date:** ___________________
- **Auditor:** ___________________

---

## Phase 2: Automated Testing

Complete ALL steps in this phase before proceeding.

### Step 2.1: Build the Application

```bash
# Build with all features to verify compilation
cargo build --features "postgres,compliance-artifacts"

# Expected: "Finished" with no errors (warnings are acceptable)
```

**Checklist:**
- [ ] Build completed successfully
- [ ] No compilation errors

### Step 2.2: Run Control Validation Tests

```bash
# Run control validation tests
cargo test --features compliance-artifacts control_test

# Expected: All tests pass
```

These tests validate that control implementations exist and function correctly.

**Important:** This step validates the control code but does NOT write artifacts to disk.

**Checklist:**
- [ ] All control tests passed
- [ ] Note any failures: ___________________

### Step 2.3: Generate Fresh Compliance Artifacts

**Important:** You must generate fresh artifacts for each audit session. Do not rely on
artifacts from previous runs.

```bash
# Create artifacts directory if needed
mkdir -p compliance-artifacts

# Generate fresh compliance report using the provided example
cargo run --features compliance-artifacts --example generate_compliance_report -- --profile high

# Alternative: Generate via Rust code
# use barbican::compliance::control_tests::generate_compliance_report;
# let report = generate_compliance_report();
# report.write_to_file(Path::new("./compliance-artifacts"))?;
```

**Checklist:**
- [ ] New artifact file created (check timestamp matches current time)
- [ ] Artifacts directory contains JSON files

### Step 2.4: Verify Artifact Freshness and Review

```bash
# Verify the artifact was generated during THIS audit session
ls -la compliance-artifacts/*.json

# Check the generated_at timestamp inside the report
cat compliance-artifacts/compliance_report_*.json | jq '.generated_at'

# Review the summary
cat compliance-artifacts/compliance_report_*.json | jq '.summary'
```

**CRITICAL:** If the artifact timestamp predates this audit session, return to Step 2.3
and regenerate. Stale artifacts are not valid audit evidence.

**Expected output structure:**
```json
{
  "total_controls": 29,
  "passed": 29,
  "failed": 0,
  "skipped": 0,
  "pass_rate": 100.0,
  "by_family": { ... }
}
```

**Checklist:**
- [ ] Artifact timestamp matches current audit session
- [ ] Pass rate is 100% (or document failures)
- [ ] All control families represented (AC, AU, CM, IA, SC, SI)

### Step 2.5: Run Vulnerability Scan (SR-3)

```bash
# Run cargo audit for dependency vulnerabilities
cargo audit

# Expected: No high/critical vulnerabilities
# Warnings for unmaintained packages are acceptable but should be noted
```

**Checklist:**
- [ ] No critical vulnerabilities
- [ ] No high vulnerabilities
- [ ] Warnings noted: ___________________

---

## Phase 3: Configuration Verification

### Step 3.1: Verify barbican.toml Profile Settings

```bash
# Display full configuration
cat barbican.toml
```

**Verify these settings match profile requirements:**

| Setting | Expected Value | Actual Value | Match? |
|---------|----------------|--------------|--------|
| `profile` | (target profile) | | [ ] |
| `[session]` idle timeout | (see quick ref) | | [ ] |
| `[session]` max lifetime | (see quick ref) | | [ ] |
| `[auth]` mfa_required | (see quick ref) | | [ ] |
| `[observability]` retention_days | (see quick ref) | | [ ] |

### Step 3.2: Verify Generated Rust Configuration

```bash
# View generated config
cat src/generated/barbican_config.rs

# Verify key constants match barbican.toml
grep -E "(IDLE_TIMEOUT|SESSION_TIMEOUT|MAX_LOGIN|MFA_REQUIRED|MIN_PASSWORD|RETENTION)" \
  src/generated/barbican_config.rs
```

**Cross-reference with profile requirements:**

| Constant | Expected | Actual | Match? |
|----------|----------|--------|--------|
| `IDLE_TIMEOUT_SECS` | | | [ ] |
| `SESSION_TIMEOUT_SECS` | | | [ ] |
| `MAX_LOGIN_ATTEMPTS` | | | [ ] |
| `LOCKOUT_DURATION_SECS` | | | [ ] |
| `MFA_REQUIRED` | | | [ ] |
| `MIN_PASSWORD_LENGTH` | | | [ ] |
| `MIN_RETENTION_DAYS` | | | [ ] |

### Step 3.3: Verify Generated NixOS Configuration

```bash
# View generated NixOS config
cat nix/generated/barbican.nix

# Check key security settings
grep -E "(enableSSL|enableClientCert|enableEgressFiltering|enableAuditLog|defaultPolicy)" \
  nix/generated/barbican.nix
```

**Verify NixOS modules are configured:**

| Module | Setting | Expected | Actual | Match? |
|--------|---------|----------|--------|--------|
| securePostgres | enableSSL | true | | [ ] |
| securePostgres | enableClientCert | (profile-dependent) | | [ ] |
| securePostgres | enableAuditLog | true | | [ ] |
| vmFirewall | defaultPolicy | "drop" | | [ ] |
| vmFirewall | enableEgressFiltering | (profile-dependent) | | [ ] |
| kernelHardening | enable | true | | [ ] |
| intrusionDetection | enableAIDE | true | | [ ] |
| intrusionDetection | enableAuditd | true | | [ ] |

### Step 3.4: Verify Configuration Consistency

```bash
# Regenerate configs and compare (if CLI available)
barbican generate rust --stdout > /tmp/rust_new.rs
diff src/generated/barbican_config.rs /tmp/rust_new.rs

barbican generate nix --stdout > /tmp/nix_new.nix
diff nix/generated/barbican.nix /tmp/nix_new.nix

# Expected: No differences (configs are in sync)
```

**Checklist:**
- [ ] Generated configs match source-of-truth (barbican.toml)
- [ ] No manual modifications to generated files

---

## Phase 4: Control Family Audits

For each control, verify:
1. **Implementation exists** in the specified source file
2. **Configuration matches** profile requirements
3. **Artifact passed** in compliance report

### Access Control (AC)

#### AC-7: Unsuccessful Logon Attempts

**Requirement:** Limit failed login attempts and enforce lockout.

| Profile | Max Attempts | Lockout Duration |
|---------|--------------|------------------|
| Low | 5 | 15 min |
| Moderate | 3 | 30 min |
| High | 3 | 30 min |

**Verification:**
```bash
# Check implementation
grep -n "LockoutPolicy" src/login.rs | head -5

# Check generated config
grep -E "(MAX_LOGIN_ATTEMPTS|LOCKOUT_DURATION)" src/generated/barbican_config.rs

# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "AC-7")'
```

**Checklist:**
- [ ] `MAX_LOGIN_ATTEMPTS` matches profile requirement
- [ ] `LOCKOUT_DURATION_SECS` matches profile requirement
- [ ] AC-7 artifact shows `passed: true`

---

#### AC-11: Session Lock (Idle Timeout)

**Requirement:** Lock session after period of inactivity.

| Profile | Idle Timeout |
|---------|--------------|
| Low | 15 min (900s) |
| Moderate | 10 min (600s) |
| High | 5 min (300s) |

**Verification:**
```bash
# Check implementation
grep -n "idle_timeout" src/session.rs | head -5

# Check generated config
grep "IDLE_TIMEOUT_SECS" src/generated/barbican_config.rs

# Check artifact (AC-11 may be in session timeout test)
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "AC-11")'
```

**Checklist:**
- [ ] `IDLE_TIMEOUT_SECS` matches profile requirement
- [ ] Session policy enforces idle timeout

---

#### AC-12: Session Termination

**Requirement:** Terminate session after maximum lifetime.

| Profile | Max Session |
|---------|-------------|
| Low | 30 min (1800s) |
| Moderate | 15 min (900s) |
| High | 10 min (600s) |

**Verification:**
```bash
# Check generated config
grep "SESSION_TIMEOUT_SECS" src/generated/barbican_config.rs
```

**Checklist:**
- [ ] `SESSION_TIMEOUT_SECS` matches profile requirement

---

### Audit and Accountability (AU)

#### AU-2/AU-3: Audit Events and Content

**Requirement:** Log security events with required fields.

**Verification:**
```bash
# Check implementation
grep -n "AuditEvent\|SecurityEvent" src/audit/mod.rs | head -10

# Check NixOS audit logging
grep -E "(enableAuditLog|enablePgaudit)" nix/generated/barbican.nix

# Check artifacts
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id | startswith("AU-"))'
```

**Checklist:**
- [ ] `enableAuditLog = true` in NixOS config
- [ ] `enablePgaudit = true` for database auditing
- [ ] AU-2 artifact passed
- [ ] AU-3 artifact passed

---

#### AU-9: Protection of Audit Information

**Requirement:** Protect logs from tampering.

**Verification:**
```bash
# Check integrity implementation
grep -n "AuditChain\|HMAC" src/audit/integrity.rs | head -5

# Check log file permissions
grep "logFileMode" nix/generated/barbican.nix
```

**Checklist:**
- [ ] HMAC chain integrity available
- [ ] `logFileMode = "0600"` (owner read/write only)
- [ ] AU-9 artifact passed (if present)

---

#### AU-11: Audit Record Retention

**Requirement:** Retain logs for required period.

| Profile | Retention |
|---------|-----------|
| Low | 30 days |
| Moderate | 90 days |
| High | 365 days |

**Verification:**
```bash
# Check configuration
grep "retention" barbican.toml
grep "MIN_RETENTION_DAYS" src/generated/barbican_config.rs
```

**Checklist:**
- [ ] `retention_days` matches profile requirement

---

### Identification and Authentication (IA)

#### IA-2(1): Multi-Factor Authentication

**Requirement:** Enforce MFA.

| Profile | MFA Requirement |
|---------|-----------------|
| Low | Privileged only |
| Moderate | All users |
| High | All users |

**Verification:**
```bash
# Check implementation
grep -n "MfaPolicy" src/auth.rs | head -5

# Check generated config
grep "MFA_REQUIRED" src/generated/barbican_config.rs

# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "IA-2")'
```

**Checklist:**
- [ ] `MFA_REQUIRED` matches profile requirement
- [ ] IA-2 artifact passed

---

#### IA-5: Authenticator Management (Password Policy)

**Requirement:** Enforce password requirements per NIST 800-63B.

| Profile | Min Length |
|---------|------------|
| Low | 8 chars |
| Moderate | 12 chars |
| High | 14 chars |

**Verification:**
```bash
# Check implementation
grep -n "PasswordPolicy\|min_length" src/password.rs | head -10

# Check generated config
grep "MIN_PASSWORD_LENGTH" src/generated/barbican_config.rs

# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id | startswith("IA-5"))'
```

**Checklist:**
- [ ] `MIN_PASSWORD_LENGTH` matches profile requirement
- [ ] IA-5 artifact passed
- [ ] IA-5(1) artifact passed

---

#### IA-5(2): PKI-Based Authentication

**Requirement:** Use client certificates where appropriate.

**Verification:**
```bash
# Check NixOS config
grep "enableClientCert" nix/generated/barbican.nix
```

**Checklist:**
- [ ] `enableClientCert = true` for FedRAMP High
- [ ] mTLS configured for service-to-service (if High)

---

### System and Communications Protection (SC)

#### SC-5: Denial of Service Protection

**Requirement:** Rate limiting and resource controls.

**Verification:**
```bash
# Check implementation
grep -n "rate_limit\|with_rate_limiting" src/layers.rs | head -5

# Check NixOS resource limits
grep -A5 "resourceLimits" nix/generated/barbican.nix

# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "SC-5")'
```

**Checklist:**
- [ ] Rate limiting configured
- [ ] Resource limits enabled
- [ ] SC-5 artifact passed

---

#### SC-7: Boundary Protection

**Requirement:** Firewall with default deny.

**Verification:**
```bash
# Check NixOS firewall
grep -A10 "vmFirewall" nix/generated/barbican.nix
```

**Checklist:**
- [ ] `defaultPolicy = "drop"`
- [ ] `enableEgressFiltering = true` (for High)
- [ ] `logDropped = true`

---

#### SC-8: Transmission Confidentiality

**Requirement:** TLS for all connections.

**Verification:**
```bash
# Check TLS mode
grep "TlsMode\|enableSSL" src/generated/barbican_config.rs nix/generated/barbican.nix

# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "SC-8")'
```

**Checklist:**
- [ ] `TlsMode::Strict` configured
- [ ] `enableSSL = true` for PostgreSQL
- [ ] SC-8 artifact passed

---

#### SC-13: Cryptographic Protection

**Requirement:** FIPS-validated cryptography (when required).

**Verification:**
```bash
# Check FIPS feature in Cargo.toml
grep -A5 "\[features\]" Cargo.toml | grep fips

# Check if built with FIPS (for High)
# The build should include --features fips for FedRAMP High
```

**Checklist:**
- [ ] FIPS feature available
- [ ] FIPS enabled for FedRAMP High builds
- [ ] SC-13 artifact passed

---

#### SC-28: Protection of Information at Rest

**Requirement:** Encryption at rest.

**Verification:**
```bash
# Check encryption implementation
grep -n "FieldEncryptor\|AES" src/encryption.rs | head -5

# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "SC-28")'
```

**Checklist:**
- [ ] Field-level encryption available
- [ ] SC-28 artifact passed

---

### System and Information Integrity (SI)

#### SI-4/SI-7: System Monitoring and Integrity

**Requirement:** Intrusion detection and file integrity monitoring.

**Verification:**
```bash
# Check NixOS intrusion detection
grep -A5 "intrusionDetection" nix/generated/barbican.nix
```

**Checklist:**
- [ ] `enableAIDE = true`
- [ ] `enableAuditd = true`

---

#### SI-10: Information Input Validation

**Requirement:** Validate all inputs.

**Verification:**
```bash
# Check implementation
grep -n "Validate\|sanitize" src/validation.rs | head -10

# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "SI-10")'
```

**Checklist:**
- [ ] Input validation framework exists
- [ ] XSS/SQLi prevention
- [ ] SI-10 artifact passed

---

#### SI-11: Error Handling

**Requirement:** Secure error handling (no information leakage).

**Verification:**
```bash
# Check artifact
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.control_id == "SI-11")'
```

**Checklist:**
- [ ] Production errors hide details
- [ ] SI-11 artifact passed

---

### Supply Chain Risk Management (SR)

#### SR-3: Supply Chain Controls

**Requirement:** Vulnerability scanning.

**Verification:**
```bash
# Run cargo audit (already done in Phase 2)
cargo audit
```

**Checklist:**
- [ ] No critical/high vulnerabilities
- [ ] Unmaintained packages documented

---

#### SR-4: Provenance

**Requirement:** Software Bill of Materials (SBOM).

**Verification:**
```bash
# Check SBOM capability
grep -n "cyclonedx\|sbom" src/supply_chain.rs | head -5

# Verify Cargo.lock exists
ls -la Cargo.lock
```

**Checklist:**
- [ ] SBOM generation available
- [ ] Cargo.lock committed

---

## Phase 5: Production Runtime Verification

This phase verifies that security controls are active on the **running production system**.
Skip this phase only for development/staging audits; it is **mandatory for FedRAMP authorization**.

### Prerequisites

- [ ] SSH access to production system (or console access)
- [ ] Application deployed via NixOS with barbican modules
- [ ] Application binary built with production features (`--features fips` for FedRAMP High)
- [ ] TLS certificates provisioned
- [ ] Database running with client certificates (for FedRAMP High)

### Step 5.1: Verify Build Configuration

```bash
# On the production system, verify the binary was built with FIPS support
# Check for AWS-LC FIPS symbols
nm /run/current-system/sw/bin/<app-name> 2>/dev/null | grep -i fips || \
  ldd /run/current-system/sw/bin/<app-name> | grep -i aws-lc

# Check the NixOS system configuration
nixos-option barbican.securePostgres.enable
nixos-option barbican.vmFirewall.enable
nixos-option barbican.kernelHardening.enable
```

**For FedRAMP High, verify FIPS feature was enabled at build time:**
```bash
# The binary should link against aws-lc-fips, not standard crypto
ldd /run/current-system/sw/bin/<app-name> | grep -E "(aws-lc|crypto)"
```

**Checklist:**
- [ ] Binary contains FIPS crypto symbols (FedRAMP High)
- [ ] All barbican NixOS modules enabled
- [ ] Build matches `barbican.toml` profile

### Step 5.2: Verify Services Running

```bash
# Check application service status
systemctl status <app-name>.service

# Check PostgreSQL with pgaudit
systemctl status postgresql.service
sudo -u postgres psql -c "SHOW shared_preload_libraries;" | grep pgaudit

# Check intrusion detection services
systemctl status aide-check.timer
systemctl status auditd.service

# Check all barbican-related services
systemctl list-units --type=service | grep -E "(postgres|aide|audit|<app-name>)"
```

**Checklist:**
- [ ] Application service running
- [ ] PostgreSQL running with pgaudit loaded
- [ ] AIDE timer active
- [ ] auditd service running

### Step 5.3: Verify TLS/mTLS Configuration (SC-8)

```bash
# Test TLS connection to the application
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates

# Verify TLS version (must be 1.2 or 1.3)
openssl s_client -connect <host>:443 -tls1_2 </dev/null 2>&1 | grep -i "protocol"

# For FedRAMP High: Test mTLS with client certificate
openssl s_client -connect <host>:443 \
  -cert /path/to/client.crt \
  -key /path/to/client.key \
  -CAfile /path/to/ca.crt \
  </dev/null 2>&1 | grep -E "(Verify return|SSL-Session)"

# Test that connections WITHOUT client cert are rejected (mTLS enforcement)
openssl s_client -connect <host>:443 </dev/null 2>&1 | grep -i "error\|alert"
```

**Checklist:**
- [ ] TLS 1.2 or 1.3 in use
- [ ] Valid certificate chain
- [ ] mTLS enforced (FedRAMP High) - connections without client cert rejected
- [ ] Certificate not expired

### Step 5.4: Verify Firewall and Egress Filtering (SC-7)

```bash
# View current firewall rules
sudo iptables -L -n -v

# Verify default DROP policy
sudo iptables -L INPUT -n | head -1
sudo iptables -L OUTPUT -n | head -1

# Check egress filtering is active (FedRAMP High)
sudo iptables -L OUTPUT -n -v | grep -E "(DROP|REJECT)"

# Test egress filtering - this should FAIL on a properly configured system
curl -s --connect-timeout 5 http://example.com && echo "FAIL: Egress not filtered" || echo "PASS: Egress filtered"

# Verify only allowed ports are open
sudo ss -tlnp | grep LISTEN
```

**Checklist:**
- [ ] Default INPUT policy is DROP
- [ ] Default OUTPUT policy is DROP (FedRAMP High)
- [ ] Only expected ports listening
- [ ] Egress filtering blocks unauthorized outbound (FedRAMP High)
- [ ] Dropped packets are logged

### Step 5.5: Verify Session Controls (AC-11, AC-12)

```bash
# Test idle timeout by creating a session and waiting
# This requires an authenticated session - adjust for your auth mechanism

# Example: Create session, wait for idle timeout, verify session invalid
TOKEN=$(curl -s -X POST https://<host>/auth/login -d '{"user":"test","pass":"test"}' | jq -r '.token')
echo "Session created, waiting for idle timeout (5 min for FedRAMP High)..."
sleep 310  # 5 min + 10 sec buffer

# Attempt to use the session - should fail
curl -s -H "Authorization: Bearer $TOKEN" https://<host>/api/protected
# Expected: 401 Unauthorized

# Test max session lifetime similarly (10 min for FedRAMP High)
```

**Checklist:**
- [ ] Idle timeout enforced (5 min for High, 10 min for Moderate)
- [ ] Max session lifetime enforced (10 min for High, 15 min for Moderate)
- [ ] Session invalidated after timeout

### Step 5.6: Verify Login Lockout (AC-7)

```bash
# Test account lockout after failed attempts
# WARNING: This will lock the test account

for i in {1..4}; do
  echo "Attempt $i:"
  curl -s -X POST https://<host>/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"wrongpassword"}' | jq '.error'
done

# After 3 failures (FedRAMP Moderate/High), account should be locked
# Verify the lockout duration (30 min for Moderate/High)

# Check audit logs for lockout event
sudo journalctl -u <app-name> --since "5 minutes ago" | grep -i "lockout\|locked"
```

**Checklist:**
- [ ] Account locked after 3 failed attempts (Moderate/High) or 5 (Low)
- [ ] Lockout event logged
- [ ] Lockout duration correct (30 min for Moderate/High)

### Step 5.7: Verify Audit Logging (AU-2, AU-3, AU-9)

```bash
# Check application audit logs are being generated
sudo journalctl -u <app-name> --since "1 hour ago" -o json | head -5 | jq '.MESSAGE'

# Verify PostgreSQL audit logs (pgaudit)
sudo cat /var/log/postgresql/postgresql-*.log | grep -i "AUDIT" | tail -10

# Check auditd is capturing system events
sudo ausearch -ts recent -m USER_AUTH,USER_LOGIN | head -20

# Verify log file permissions (AU-9)
ls -la /var/log/postgresql/
ls -la /var/log/audit/

# Check audit log integrity (if HMAC chain is used)
# This requires application-specific verification
```

**Checklist:**
- [ ] Application audit logs being generated
- [ ] PostgreSQL pgaudit logs present
- [ ] auditd capturing authentication events
- [ ] Log files have restrictive permissions (0600)
- [ ] Logs contain required fields (timestamp, user, action, outcome)

### Step 5.8: Verify Intrusion Detection (SI-4, SI-7)

```bash
# Check AIDE database exists and is current
sudo ls -la /var/lib/aide/aide.db

# Run AIDE check (may take several minutes)
sudo aide --check 2>&1 | head -50

# Verify auditd rules are loaded
sudo auditctl -l | head -20

# Check for recent auditd alerts
sudo ausearch -ts today -m ANOM_PROMISCUOUS,ANOM_ABEND -i 2>/dev/null | head -10
```

**Checklist:**
- [ ] AIDE database initialized
- [ ] AIDE check runs without unexpected changes
- [ ] auditd rules loaded
- [ ] No anomalous events detected (or documented if present)

### Step 5.9: Verify Resource Limits (SC-5, SC-6)

```bash
# Check systemd resource limits on the application
systemctl show <app-name> | grep -E "(MemoryMax|CPUQuota|LimitNOFILE|LimitNPROC)"

# Verify cgroup limits are enforced
cat /sys/fs/cgroup/system.slice/<app-name>.service/memory.max
cat /sys/fs/cgroup/system.slice/<app-name>.service/cpu.max

# Check rate limiting is active (application level)
# Attempt rapid requests - should be rate limited
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" https://<host>/api/endpoint
done | sort | uniq -c
# Should see 429 (Too Many Requests) responses
```

**Checklist:**
- [ ] Memory limits configured
- [ ] CPU quota configured
- [ ] Rate limiting active (429 responses under load)
- [ ] Core dumps disabled

### Step 5.10: Verify Cryptographic Protection (SC-13, SC-28)

```bash
# For FedRAMP High: Verify FIPS mode is active
# This checks if the crypto library is running in FIPS mode

# If using AWS-LC:
# The application should log FIPS mode status at startup
sudo journalctl -u <app-name> | grep -i "fips"

# Verify database encryption at rest
sudo -u postgres psql -c "SHOW ssl;"  # Should be 'on'
sudo -u postgres psql -c "SELECT pg_read_file('/var/lib/postgresql/*/server.crt', 0, 100);" 2>/dev/null && \
  echo "Certificate accessible"

# Check disk encryption (if applicable)
lsblk -o NAME,FSTYPE,MOUNTPOINT,ENCRYPTED
```

**Checklist:**
- [ ] FIPS mode active (FedRAMP High) - verified in application logs
- [ ] PostgreSQL SSL enabled
- [ ] Field-level encryption active (if applicable)
- [ ] Disk encryption enabled (if required by deployment)

### Step 5.11: Kernel Hardening Verification (SI-16)

```bash
# Verify kernel hardening sysctls
sysctl kernel.kptr_restrict          # Should be 1 or 2
sysctl kernel.dmesg_restrict         # Should be 1
sysctl kernel.perf_event_paranoid    # Should be 2 or 3
sysctl net.ipv4.conf.all.rp_filter   # Should be 1
sysctl net.ipv4.tcp_syncookies       # Should be 1

# Check ASLR is enabled
cat /proc/sys/kernel/randomize_va_space  # Should be 2

# Verify no unnecessary kernel modules
lsmod | wc -l  # Document count for baseline
```

**Checklist:**
- [ ] Kernel pointer restriction enabled
- [ ] dmesg restricted
- [ ] ASLR fully enabled (value: 2)
- [ ] SYN cookies enabled
- [ ] Reverse path filtering enabled

---

## Phase 6: Evidence Collection

### Step 6.1: Export Compliance Artifacts

```bash
# Create evidence directory
mkdir -p audit-evidence/$(date +%Y-%m-%d)

# Copy compliance artifacts
cp -r compliance-artifacts/ audit-evidence/$(date +%Y-%m-%d)/

# Copy cargo audit results
cargo audit --json > audit-evidence/$(date +%Y-%m-%d)/cargo-audit.json
```

### Step 6.2: Export Configuration Evidence

```bash
# Create configuration archive
tar czf audit-evidence/$(date +%Y-%m-%d)/config-evidence.tar.gz \
    barbican.toml \
    Cargo.toml \
    Cargo.lock \
    flake.nix \
    flake.lock \
    src/generated/ \
    nix/generated/
```

### Step 6.3: Collect Production Runtime Evidence

Run these commands on the production system to collect evidence from Phase 5 verification:

```bash
# Create evidence directory on production system
mkdir -p /tmp/audit-evidence

# === Service Status ===
systemctl status <app-name>.service > /tmp/audit-evidence/service_status.txt
systemctl status postgresql.service >> /tmp/audit-evidence/service_status.txt
systemctl status auditd.service >> /tmp/audit-evidence/service_status.txt

# === Application Audit Logs ===
journalctl -u <app-name>.service --since "7 days ago" -o json > /tmp/audit-evidence/app_audit_logs.json

# === PostgreSQL Audit Logs (pgaudit) ===
cp /var/log/postgresql/*.log /tmp/audit-evidence/ 2>/dev/null || \
  sudo -u postgres psql -c "SELECT * FROM pg_catalog.pg_stat_activity;" > /tmp/audit-evidence/pg_activity.txt

# === Firewall Configuration ===
sudo iptables -L -n -v > /tmp/audit-evidence/firewall_rules.txt
sudo iptables-save > /tmp/audit-evidence/firewall_rules_full.txt

# === AIDE Integrity Report ===
sudo aide --check > /tmp/audit-evidence/aide_report.txt 2>&1

# === Kernel Hardening State ===
sysctl -a 2>/dev/null | grep -E "^(kernel\.|net\.ipv4\.)" > /tmp/audit-evidence/sysctl_settings.txt

# === Systemd Hardening ===
systemctl show <app-name> | grep -E "(Capability|Private|NoNew|Protect|Memory|CPU)" > /tmp/audit-evidence/systemd_hardening.txt

# === TLS Certificate Info ===
openssl s_client -connect localhost:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text > /tmp/audit-evidence/tls_certificate.txt

# === auditd Rules and Recent Events ===
sudo auditctl -l > /tmp/audit-evidence/auditd_rules.txt
sudo ausearch -ts recent -m USER_AUTH,USER_LOGIN > /tmp/audit-evidence/auditd_auth_events.txt 2>&1

# === FIPS Mode Verification (FedRAMP High) ===
journalctl -u <app-name> | grep -i fips > /tmp/audit-evidence/fips_verification.txt
ldd /run/current-system/sw/bin/<app-name> > /tmp/audit-evidence/binary_libraries.txt

# === Resource Limits ===
cat /sys/fs/cgroup/system.slice/<app-name>.service/memory.max > /tmp/audit-evidence/cgroup_memory.txt 2>/dev/null
cat /sys/fs/cgroup/system.slice/<app-name>.service/cpu.max > /tmp/audit-evidence/cgroup_cpu.txt 2>/dev/null

# === Create Archive ===
tar czf /tmp/production-evidence.tar.gz -C /tmp audit-evidence/
echo "Evidence collected: /tmp/production-evidence.tar.gz"
```

**Transfer evidence to audit workstation:**
```bash
scp production-host:/tmp/production-evidence.tar.gz audit-evidence/$(date +%Y-%m-%d)/
```

### Step 6.4: Evidence Manifest

Create `audit-evidence/$(date +%Y-%m-%d)/MANIFEST.md`:

```markdown
# Audit Evidence Manifest

**Date:** YYYY-MM-DD
**Auditor:** Name
**Target Profile:** FedRAMP [Low/Moderate/High]
**Application:** [name from barbican.toml]
**Production Host:** [hostname]

## Code/Configuration Evidence

| File | Description | Hash (SHA256) |
|------|-------------|---------------|
| compliance-artifacts/*.json | Automated control test results | |
| cargo-audit.json | Dependency vulnerability scan | |
| config-evidence.tar.gz | barbican.toml, generated configs | |

## Production Runtime Evidence

| File | Description | Hash (SHA256) |
|------|-------------|---------------|
| service_status.txt | systemd service states | |
| app_audit_logs.json | Application audit events | |
| firewall_rules.txt | iptables configuration | |
| aide_report.txt | File integrity verification | |
| sysctl_settings.txt | Kernel hardening parameters | |
| systemd_hardening.txt | Process isolation settings | |
| tls_certificate.txt | TLS certificate details | |
| auditd_rules.txt | System audit rules | |
| auditd_auth_events.txt | Authentication audit events | |
| fips_verification.txt | FIPS mode confirmation (High only) | |
| binary_libraries.txt | Linked crypto libraries | |
| cgroup_memory.txt | Memory limit configuration | |
| cgroup_cpu.txt | CPU quota configuration | |

## Verification Summary

- [ ] All Phase 5 production verification steps completed
- [ ] Evidence files integrity verified (SHA256 hashes recorded)
- [ ] Evidence transferred securely from production
```

---

## Phase 7: Report Generation

### Audit Summary Template

```markdown
# Barbican Compliance Audit Report

## Executive Summary

**Application:** [name]
**Version:** [version]
**Profile:** FedRAMP [Low/Moderate/High]
**Audit Date:** YYYY-MM-DD
**Auditor:** [name]

### Overall Status: [PASS / PASS WITH FINDINGS / FAIL]

| Category | Controls Tested | Passed | Failed |
|----------|-----------------|--------|--------|
| Access Control (AC) | | | |
| Audit & Accountability (AU) | | | |
| Identification & Auth (IA) | | | |
| System & Comms Protection (SC) | | | |
| System & Info Integrity (SI) | | | |
| Supply Chain (SR) | | | |
| **TOTAL** | | | |

## Automated Test Results

- Compliance artifact pass rate: [X]%
- Cargo audit: [X] critical, [X] high, [X] warnings

## Configuration Verification

- [ ] barbican.toml matches profile requirements
- [ ] Generated Rust config matches barbican.toml
- [ ] Generated NixOS config matches barbican.toml

## Production Runtime Verification

**Production Host:** [hostname]
**Verification Date:** YYYY-MM-DD

### Build Verification
- [ ] Binary built with correct features (fips for High)
- [ ] All barbican NixOS modules enabled

### Service Status
- [ ] Application service running
- [ ] PostgreSQL with pgaudit running
- [ ] AIDE timer active
- [ ] auditd service running

### Network Security
- [ ] TLS 1.2+ verified
- [ ] mTLS enforced (High only)
- [ ] Firewall default DROP policy
- [ ] Egress filtering active (High only)

### Runtime Controls
- [ ] Session idle timeout verified
- [ ] Login lockout verified
- [ ] Rate limiting active
- [ ] Audit logs being generated

### System Hardening
- [ ] Kernel hardening sysctls applied
- [ ] ASLR enabled
- [ ] Resource limits enforced
- [ ] FIPS mode active (High only)

## Findings

### Critical Findings
(None / List findings)

### Recommendations
(List any recommendations)

## Evidence

Evidence collected and archived in: `audit-evidence/YYYY-MM-DD/`

## Signatures

Auditor: _______________________ Date: _________
Reviewer: ______________________ Date: _________
```

---

## Control Reference

### Complete Control Matrix

| Control | Description | Implementation | Artifact Test |
|---------|-------------|----------------|---------------|
| AC-4 | Information Flow | layers.rs (CORS) | Yes |
| AC-7 | Unsuccessful Logon | login.rs | Yes |
| AC-11 | Session Lock | session.rs | Yes |
| AC-12 | Session Termination | session.rs | Yes |
| AU-2 | Audit Events | audit/mod.rs | Yes |
| AU-3 | Audit Content | audit/mod.rs | Yes |
| AU-8 | Time Stamps | audit/mod.rs | Yes |
| AU-9 | Audit Protection | audit/integrity.rs | Yes |
| AU-12 | Audit Generation | audit/mod.rs | Yes |
| AU-14 | Session Audit | audit/mod.rs | Yes |
| AU-16 | Cross-Org Audit | audit/mod.rs | Yes |
| CM-6 | Config Settings | config.rs | Yes |
| IA-2 | Identification | auth.rs | Yes |
| IA-3 | Device Identification | auth.rs | Yes |
| IA-5 | Authenticator Mgmt | password.rs | Yes |
| IA-5(1) | Password Policy | password.rs | Yes |
| IA-5(7) | Secret Detection | secrets.rs | Yes |
| IA-6 | Auth Feedback | auth.rs | Yes |
| SC-5 | DoS Protection | layers.rs | Yes |
| SC-8 | Transmission Security | tls.rs | Yes |
| SC-10 | Network Disconnect | session.rs | Yes |
| SC-12 | Key Management | keys.rs | Yes |
| SC-13 | Cryptographic Protection | encryption.rs | Yes |
| SC-23 | Session Authenticity | session.rs | Yes |
| SC-28 | Data at Rest | encryption.rs | Yes |
| SI-10 | Input Validation | validation.rs | Yes |
| SI-11 | Error Handling | error.rs | Yes |

### Infrastructure Controls (NixOS)

| Control | Module | Description |
|---------|--------|-------------|
| AC-6 | systemd-hardening.nix | Least privilege |
| SC-7 | vm-firewall.nix | Boundary protection |
| SC-39 | systemd-hardening.nix | Process isolation |
| SI-4 | intrusion-detection.nix | System monitoring |
| SI-7 | intrusion-detection.nix | File integrity |
| SI-16 | kernel-hardening.nix | Memory protection |

### Inherited Controls

| Control | Inherited From |
|---------|----------------|
| AC-2 | Identity Provider (IdP) |
| PE-* | Cloud/Data Center Provider |
| PS-* | Organization HR Policies |
| CP-2/CP-3 | Organization Contingency Plans |
| IR-1/IR-2 | Organization Incident Response |

---

## Appendix

### Quick Reference Commands

```bash
# Full audit command sequence
cargo build --features "postgres,compliance-artifacts"
cargo test --features compliance-artifacts control_test
cargo run --features compliance-artifacts --example generate_compliance_report -- --profile high
cargo audit

# Verify artifact freshness (must match audit session time)
ls -la compliance-artifacts/*.json
cat compliance-artifacts/*.json | jq '.generated_at'

# View latest compliance report summary
cat compliance-artifacts/*.json | jq '.summary'

# Check all control artifacts passed
cat compliance-artifacts/*.json | jq '[.artifacts[].passed] | all'

# List failed controls (if any)
cat compliance-artifacts/*.json | jq '.artifacts[] | select(.passed == false) | .control_id'
```

### Troubleshooting

**Build fails:**
- Check Rust toolchain version (`rustc --version`)
- Verify all dependencies resolve (`cargo update`)

**Tests fail:**
- Review specific test output
- Check if profile requirements changed
- Verify generated configs are current

**Missing artifacts:**
- Ensure `--features compliance-artifacts` is used
- Check `compliance-artifacts/` directory exists
- Review test output for generation errors

### Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-30 | Initial workflow-based guide |
