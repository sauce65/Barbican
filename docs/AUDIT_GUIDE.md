# Barbican Compliance Audit Guide

A step-by-step guide for auditors assessing NIST SP 800-53 Rev 5 compliance of systems built with Barbican.

## Table of Contents

1. [Overview](#overview)
2. [Audit Workflow](#audit-workflow)
3. [Phase 1: Preparation](#phase-1-preparation)
4. [Phase 2: Automated Testing](#phase-2-automated-testing)
5. [Phase 3: Configuration Verification](#phase-3-configuration-verification)
6. [Phase 4: Control Family Audits](#phase-4-control-family-audits)
7. [Phase 5: Evidence Collection](#phase-5-evidence-collection)
8. [Phase 6: Report Generation](#phase-6-report-generation)
9. [Control Reference](#control-reference)
10. [Appendix](#appendix)

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
Phase 5: Evidence Collection
    │
    ├── Export compliance artifacts
    ├── Export configuration files
    ├── Collect log samples
    └── Document production verification
          │
          ▼
Phase 6: Report Generation
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

### Step 2.2: Run Control Tests

```bash
# Run ALL control tests to generate artifacts
cargo test --features compliance-artifacts control_test

# Expected: All tests pass
```

**Checklist:**
- [ ] All control tests passed
- [ ] Note any failures: ___________________

### Step 2.3: Generate Compliance Report

```bash
# Run full compliance test suite
cargo test --features compliance-artifacts compliance_

# View generated artifacts
ls -la compliance-artifacts/
```

**Checklist:**
- [ ] Compliance report generated
- [ ] Artifacts directory contains JSON files

### Step 2.4: Review Compliance Artifact

```bash
# Find the most recent compliance report
ls -t compliance-artifacts/*.json | head -1

# Review the report (replace with actual filename)
cat compliance-artifacts/compliance_report_*.json | jq '.summary'
```

**Expected output structure:**
```json
{
  "total_controls": 13,
  "passed": 13,
  "failed": 0,
  "skipped": 0,
  "pass_rate": 100.0,
  "by_family": { ... }
}
```

**Checklist:**
- [ ] Pass rate is 100% (or document failures)
- [ ] All control families represented
- [ ] Report timestamp is current

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

## Phase 5: Evidence Collection

### Step 5.1: Export Compliance Artifacts

```bash
# Create evidence directory
mkdir -p audit-evidence/$(date +%Y-%m-%d)

# Copy compliance artifacts
cp -r compliance-artifacts/ audit-evidence/$(date +%Y-%m-%d)/

# Copy cargo audit results
cargo audit --json > audit-evidence/$(date +%Y-%m-%d)/cargo-audit.json
```

### Step 5.2: Export Configuration Evidence

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

### Step 5.3: Collect Production Evidence (if applicable)

```bash
# Export audit logs (on production system)
journalctl -u <service-name>.service --since "7 days ago" -o json > audit_logs.json

# Export PostgreSQL logs
cat /var/log/postgresql/*.log > postgres_audit.log

# Export firewall state
iptables -L -n -v > firewall_rules.txt

# Export AIDE report
aide --check > aide_report.txt

# Collect systemd hardening evidence
systemctl show <service-name> | grep -E "(Capability|Private|NoNew|Protect)" > systemd_hardening.txt
```

### Step 5.4: Evidence Manifest

Create `audit-evidence/$(date +%Y-%m-%d)/MANIFEST.md`:

```markdown
# Audit Evidence Manifest

**Date:** YYYY-MM-DD
**Auditor:** Name
**Target Profile:** FedRAMP [Low/Moderate/High]
**Application:** [name from barbican.toml]

## Artifacts Collected

| File | Description | Hash (SHA256) |
|------|-------------|---------------|
| compliance-artifacts/*.json | Automated test results | |
| cargo-audit.json | Dependency vulnerability scan | |
| config-evidence.tar.gz | Configuration files | |
| audit_logs.json | Application audit logs | |
| firewall_rules.txt | Firewall configuration | |
| aide_report.txt | File integrity report | |
```

---

## Phase 6: Report Generation

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
cargo test --features compliance-artifacts compliance_
cargo audit

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
