# Barbican Compliance Audit Guide

A step-by-step guide for auditors assessing NIST SP 800-53 Rev 5 compliance of systems built with Barbican.

## Table of Contents

1. [Overview](#overview)
2. [Audit Workflow](#audit-workflow)
3. [Phase 1: Preparation](#phase-1-preparation)
4. [Phase 1b: Deploy Audit Target (If Needed)](#phase-1b-deploy-audit-target-if-needed)
5. [Phase 2: Automated Testing](#phase-2-automated-testing)
6. [Phase 3: Configuration Verification](#phase-3-configuration-verification)
7. [Phase 4: Control Family Audits](#phase-4-control-family-audits)
8. [Phase 5: Production Runtime Verification](#phase-5-production-runtime-verification)
9. [Phase 5a: Penetration Testing](#phase-5a-penetration-testing)
10. [Phase 5b: Database Security Audit](#phase-5b-database-security-audit)
11. [Phase 6: Evidence Collection](#phase-6-evidence-collection)
12. [Phase 7: Report Generation](#phase-7-report-generation)
13. [Control Reference](#control-reference)
14. [STIG Traceability Matrix](#stig-traceability-matrix)
15. [Independent Verification Tools](#independent-verification-tools)
16. [Appendix A: DPE-Specific Audit Procedures](#appendix-a-dpe-specific-audit-procedures)
17. [Appendix B: CI/CD Integration](#appendix-b-cicd-integration)

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

Values derived from NIST 800-53 Rev 5 and DISA STIGs. STIG references enable direct traceability to DoD security requirements.

| Control | STIG Reference | FedRAMP Low | FedRAMP Moderate | FedRAMP High |
|---------|----------------|-------------|------------------|--------------|
| AC-7: Max login attempts | UBTU-22-411045 | 3 | 3 | 3 |
| AC-7: Lockout duration | UBTU-22-411050 | 30 min | 30 min | 3 hours |
| AC-10: Concurrent sessions | APSC-DV-000200 | 5 | 3 | 1 |
| AC-11: Idle timeout | UBTU-22-412020 | 15 min | 15 min | 10 min |
| AC-12: Session max | APSC-DV-000180 | 30 min | 15 min | 10 min |
| AU-11: Log retention | UBTU-22-653045 | 30 days | 90 days | 365 days |
| IA-2(1): MFA required | UBTU-22-612010 | Privileged only | All users | All users |
| IA-5: Password min length | UBTU-22-611035 | 8 chars | 15 chars | 15 chars |
| SC-7: Egress filtering | UBTU-22-251010 | Optional | Recommended | Required |
| SC-8: TLS required | UBTU-22-255050 | Required | Required | Required |
| SC-8(1): mTLS | UBTU-22-612035 | Optional | Optional | Required |
| SC-13: FIPS crypto | FIPS 140-3 | Optional | Recommended | Required |
| SC-28: Encryption at rest | UBTU-22-231010 | Optional | Required | Required |

**STIG Sources:**
- Ubuntu 22.04 LTS STIG V2R3 (UBTU-22-*)
- Application Security STIG V5R3 (APSC-DV-*)
- PostgreSQL 15 STIG V2R6 (PGS15-00-*)

---

## Audit Workflow

Complete these phases in order for a thorough compliance audit:

```
Phase 1: Preparation
    │
    ├── Gather prerequisites
    ├── Identify target profile
    ├── Clone/access repository
    └── Check for existing production system
          │
          ├─► [YES: Production system exists]
          │         │
          │         └── Record system details, proceed to Phase 2
          │
          └─► [NO: No production system]
                    │
                    ▼
          Phase 1b: Deploy Audit Target
                    │
                    ├── Generate age keys for secrets
                    ├── Encrypt secrets with agenix
                    ├── Build NixOS VM from flake
                    ├── Start VM and verify boot
                    ├── Verify services running
                    └── Record VM access details
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
- [ ] Nix with flakes enabled (for VM tests and automated audit)

### Quick Start: Automated Audit

Barbican provides a built-in audit runner that executes all security checks:

```bash
# Run the full security audit (builds and runs NixOS VM tests)
nix run github:Sauce65/barbican#audit

# Or from a local clone
nix run .#audit
```

This will:
1. Build the NixOS VM security tests
2. Run all module tests (secure-postgres, kernel-hardening, etc.)
3. Generate an audit report with timestamps

For individual module testing:

```bash
nix run .#test-secure-postgres     # Test PostgreSQL hardening
nix run .#test-hardened-ssh        # Test SSH configuration
nix run .#test-kernel-hardening    # Test kernel hardening
nix run .#test-vm-firewall         # Test firewall rules
nix run .#test-intrusion-detection # Test AIDE/auditd
nix run .#test-vault-pki           # Test Vault PKI setup
nix run .#test-resource-limits     # Test resource limits
nix run .#test-time-sync           # Test NTP configuration
nix run .#test-secure-users        # Test user hardening
```

The automated tests complement manual verification in Phase 5.

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

### Check for Existing Production System

Determine whether a production system is already deployed and available for audit:

```bash
# If you have SSH access to a production host, verify it's running barbican
ssh <production-host> "systemctl list-units | grep -E '(postgres|aide|auditd)'"

# Or check if the NixOS VM can be accessed
ping <production-host>
```

**Decision Point:**

| Situation | Action |
|-----------|--------|
| Production system exists and is accessible | Record hostname/IP, proceed to Phase 2 |
| No production system available | Proceed to Phase 1b to deploy an audit target |
| Development/staging audit only | Skip Phase 1b, but note that Phase 5 will be limited |

Record your decision:
- **Production System Available:** [ ] Yes / [ ] No
- **Production Host:** ___________________
- **If No, deploying audit target:** [ ] Yes / [ ] Skipping (dev audit only)

---

## Phase 1b: Deploy Audit Target (If Needed)

If no production system exists, deploy a NixOS VM as the audit target. This ensures a complete
end-to-end audit including runtime verification (Phase 5).

**When to use this phase:**
- No existing production deployment to audit
- Need to verify the full infrastructure stack
- FedRAMP authorization audit (Phase 5 is mandatory)

**When to skip this phase:**
- Production system already exists and is accessible
- Development/staging-only audit (document this limitation in the report)

### Prerequisites for VM Deployment

- [ ] Nix installed with flakes enabled
- [ ] At least 4GB RAM available for VM
- [ ] QEMU/KVM available (`nix-shell -p qemu`)
- [ ] `age` installed for secret encryption (`nix-shell -p age`)
- [ ] `agenix` CLI available (`nix run github:ryantm/agenix`)

### Optional: Vault PKI for Certificates

If the audit target requires TLS certificates, use Barbican's Vault apps:

```bash
# Start a Vault dev server with PKI configured
nix run .#vault-dev

# In another terminal, issue certificates:
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=barbican-dev

nix run .#vault-cert-server -- localhost ./certs/server
nix run .#vault-cert-client -- audit-client ./certs/client
nix run .#vault-cert-postgres -- ./certs/postgres
nix run .#vault-ca-chain -- ./certs/ca
```

### Step 1b.1: Generate Age Keys for Secrets

Barbican examples use agenix for secret management. Generate keys for the audit VM:

```bash
# Navigate to the example directory
cd examples/fedramp-high  # or fedramp-moderate, fedramp-low

# Create a secrets directory if it doesn't exist
mkdir -p secrets

# Generate an age key for the VM (this simulates the VM's SSH host key)
age-keygen -o secrets/audit-vm-key.txt

# Extract the public key
AGE_PUBLIC_KEY=$(age-keygen -y secrets/audit-vm-key.txt)
echo "VM Public Key: $AGE_PUBLIC_KEY"
```

### Step 1b.2: Configure Secrets

Create the secrets configuration for agenix:

```bash
# Create secrets.nix with the VM's public key
cat > secrets/secrets.nix << 'EOF'
let
  # The audit VM's age public key (from step 1b.1)
  auditVM = "age1...";  # Replace with your $AGE_PUBLIC_KEY
in
{
  "db-password.age".publicKeys = [ auditVM ];
  "app-env.age".publicKeys = [ auditVM ];
}
EOF

# Edit secrets.nix to add your actual public key
# Replace "age1..." with the output from age-keygen -y
```

### Step 1b.3: Create and Encrypt Secrets

```bash
# Create the database password secret
echo "audit-db-password-$(date +%s)" | age -r "$AGE_PUBLIC_KEY" -o secrets/db-password.age

# Create the application environment file
cat << 'ENVEOF' | age -r "$AGE_PUBLIC_KEY" -o secrets/app-env.age
DATABASE_URL=postgresql://hello_fedramp_high:audit-db-password@localhost/hello_fedramp_high?sslmode=verify-full
ENVEOF

# Verify secrets were created
ls -la secrets/*.age
```

### Step 1b.4: Build the NixOS VM

```bash
# Build the VM (this may take several minutes on first run)
nix build .#nixosConfigurations.fedramp-high-vm.config.system.build.vm

# Verify the build succeeded
ls -la result/bin/run-*-vm
```

**Expected output:** A symlink to the VM runner script.

**Troubleshooting:**
- If build fails with secret errors, verify `secrets/*.age` files exist
- If build fails with missing module errors, ensure barbican flake input is correct
- Run `nix flake check` to diagnose configuration issues

### Step 1b.5: Start the VM

```bash
# Start the VM with port forwarding for SSH and the application
QEMU_NET_OPTS="hostfwd=tcp::2222-:22,hostfwd=tcp::3000-:3000" ./result/bin/run-*-vm

# The VM will boot and display a console
# Wait for the login prompt (indicates boot complete)
```

**Note:** The VM runs in the foreground. Open a new terminal for subsequent steps.

### Step 1b.6: Configure VM SSH Access

The default VM has a root user with password "changeme". Set up SSH access:

```bash
# In a new terminal, wait for SSH to be available
for i in {1..30}; do
  ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no -p 2222 root@localhost echo "SSH ready" && break
  echo "Waiting for SSH... ($i/30)"
  sleep 2
done

# Copy your SSH key for passwordless access (optional but recommended)
ssh-copy-id -p 2222 root@localhost
```

### Step 1b.7: Inject Age Key into VM

The VM needs the age private key to decrypt secrets at runtime:

```bash
# Copy the age key to the VM (simulating SSH host key derivation)
scp -P 2222 secrets/audit-vm-key.txt root@localhost:/etc/ssh/audit-age-key

# On the VM, set up the age identity
ssh -p 2222 root@localhost << 'VMEOF'
mkdir -p /etc/ssh
cp /etc/ssh/audit-age-key /etc/ssh/ssh_host_ed25519_key.age
chmod 600 /etc/ssh/ssh_host_ed25519_key.age
VMEOF
```

**Note:** In production, agenix uses the SSH host key. For audit VMs, we inject a key directly.

### Step 1b.8: Verify Services Running

```bash
# Check all barbican-related services
ssh -p 2222 root@localhost << 'VMEOF'
echo "=== Service Status ==="
systemctl status postgresql --no-pager || echo "PostgreSQL not running"
systemctl status auditd --no-pager || echo "auditd not running"
systemctl status aide-check.timer --no-pager || echo "AIDE timer not running"

echo ""
echo "=== Firewall Status ==="
iptables -L -n | head -20

echo ""
echo "=== Kernel Hardening ==="
sysctl kernel.kptr_restrict kernel.dmesg_restrict
VMEOF
```

**Expected:** PostgreSQL, auditd, and AIDE services should be running (or starting).

### Step 1b.9: Verify Application (If Applicable)

```bash
# Check if the application service is running
ssh -p 2222 root@localhost "systemctl status hello_fedramp_high --no-pager" || echo "App may need manual start"

# Test the application endpoint (via port forward)
curl -s http://localhost:3000/health || echo "App not responding yet"
curl -s http://localhost:3000/ | jq .
```

### Step 1b.10: Record Audit Target Details

Document the deployed audit target for use in subsequent phases:

- **Audit Target Type:** NixOS VM (deployed via Phase 1b)
- **SSH Access:** `ssh -p 2222 root@localhost`
- **Application URL:** `http://localhost:3000`
- **VM Build Date:** ___________________
- **Secrets Provisioned:** [ ] Yes

**Checklist:**
- [ ] VM boots successfully
- [ ] SSH access working
- [ ] PostgreSQL service running
- [ ] auditd service running
- [ ] Firewall rules active
- [ ] Application responding (if applicable)

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
| Low | 3 | 30 min |
| Moderate | 3 | 30 min |
| High | 3 | 3 hours |

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
| Moderate | 15 min (900s) |
| High | 10 min (600s) |

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

**Requirement:** Enforce password requirements per NIST 800-63B and DISA STIG.

| Profile | Min Length |
|---------|------------|
| Low | 8 chars |
| Moderate | 15 chars |
| High | 15 chars |

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
- [ ] Idle timeout enforced (10 min for High, 15 min for Moderate/Low)
- [ ] Max session lifetime enforced (10 min for High, 15 min for Moderate, 30 min for Low)
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
- [ ] Account locked after 3 failed attempts (all profiles)
- [ ] Lockout event logged
- [ ] Lockout duration correct (30 min for Low/Moderate, 3 hours for High)

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

## Phase 5a: Penetration Testing

This phase performs **active attack simulation** to verify controls actually prevent exploitation.
Configuration verification (Phase 5) confirms controls exist; penetration testing confirms they work.

**IMPORTANT:** Obtain written authorization before penetration testing. Document all test activities.

### Prerequisites

- [ ] Written authorization from system owner
- [ ] Test credentials (non-production or isolated environment preferred)
- [ ] Security testing tools installed (see [Independent Verification Tools](#independent-verification-tools))
- [ ] Network access to target system

### Step 5a.1: Input Validation Testing (SI-10)

**Objective:** Verify XSS, SQLi, and command injection are blocked.

```bash
# === XSS Testing ===
# Test reflected XSS in query parameters
curl -s "https://<host>/api/search?q=<script>alert(1)</script>" | grep -i "script"
# Expected: Script tags should be escaped or rejected (no raw <script> in response)

# Test stored XSS in JSON payloads
curl -s -X POST "https://<host>/api/resource" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "<img src=x onerror=alert(1)>", "description": "test"}' \
  | jq .
# Expected: 400 Bad Request with validation error, or HTML entities escaped

# Test XSS in headers
curl -s "https://<host>/api/resource" \
  -H "X-Custom-Header: <script>alert(1)</script>" \
  -H "Authorization: Bearer $TOKEN"
# Expected: Header should not be reflected in response body

# === SQL Injection Testing ===
# Test classic SQLi in query parameters
curl -s "https://<host>/api/users?id=1'%20OR%20'1'='1" \
  -H "Authorization: Bearer $TOKEN"
# Expected: 400 Bad Request or no data leakage

# Test SQLi in JSON body
curl -s -X POST "https://<host>/api/search" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "test'\'' OR 1=1--"}'
# Expected: 400 Bad Request with validation error

# Test UNION-based SQLi
curl -s "https://<host>/api/resource?sort=name%20UNION%20SELECT%20password%20FROM%20users--" \
  -H "Authorization: Bearer $TOKEN"
# Expected: 400 Bad Request or query rejected

# === Command Injection Testing ===
curl -s -X POST "https://<host>/api/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"filename": "test; cat /etc/passwd"}'
# Expected: 400 Bad Request, no command execution

curl -s -X POST "https://<host>/api/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"filename": "test$(whoami)"}'
# Expected: 400 Bad Request, no command execution
```

**Checklist:**
- [ ] XSS payloads rejected or escaped
- [ ] SQL injection payloads rejected
- [ ] Command injection payloads rejected
- [ ] No error messages reveal internal details

### Step 5a.2: Authentication Bypass Testing (IA-2, AC-3)

**Objective:** Verify authentication cannot be bypassed.

```bash
# === Missing Authentication ===
# Test protected endpoints without token
curl -s "https://<host>/api/protected/resource"
# Expected: 401 Unauthorized

curl -s "https://<host>/api/admin/users"
# Expected: 401 Unauthorized

# === Invalid Token Testing ===
# Test with malformed JWT
curl -s "https://<host>/api/protected/resource" \
  -H "Authorization: Bearer invalid.token.here"
# Expected: 401 Unauthorized

# Test with expired token (if you have one)
curl -s "https://<host>/api/protected/resource" \
  -H "Authorization: Bearer $EXPIRED_TOKEN"
# Expected: 401 Unauthorized

# Test JWT algorithm confusion (alg:none attack)
# Generate a token with alg:none
NONE_TOKEN=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0).$(echo -n '{"sub":"admin","role":"admin"}' | base64 -w0).
curl -s "https://<host>/api/protected/resource" \
  -H "Authorization: Bearer $NONE_TOKEN"
# Expected: 401 Unauthorized

# === Authorization Bypass (IDOR) ===
# Test accessing another user's resource
curl -s "https://<host>/api/users/OTHER_USER_ID/profile" \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN"
# Expected: 403 Forbidden or 404 Not Found

# Test privilege escalation
curl -s -X POST "https://<host>/api/admin/users" \
  -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
  -d '{"username": "hacker", "role": "admin"}'
# Expected: 403 Forbidden
```

**Checklist:**
- [ ] Unauthenticated requests rejected
- [ ] Invalid tokens rejected
- [ ] Algorithm confusion attacks blocked
- [ ] IDOR attempts blocked
- [ ] Privilege escalation prevented

### Step 5a.3: Session Security Testing (AC-11, AC-12)

**Objective:** Verify session controls are enforced.

```bash
# === Automated Session Timeout Test ===
# This script tests idle timeout without manual waiting

# Get a fresh session
TOKEN=$(curl -s -X POST "https://<host>/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"TestPassword123!"}' | jq -r '.access_token')

echo "Token obtained, testing session validity..."

# Verify token works
curl -s "https://<host>/api/protected" -H "Authorization: Bearer $TOKEN" | jq -r '.status'
# Expected: success

# For FedRAMP High (10 min idle), wait and test
# Note: In CI, use a pre-expired token from test fixtures instead
echo "To fully test idle timeout, wait for configured duration and retry"

# === Session Fixation Testing ===
# Verify session ID changes after login
PRE_LOGIN_COOKIE=$(curl -s -c - "https://<host>/login" | grep -i session)
POST_LOGIN_COOKIE=$(curl -s -c - -X POST "https://<host>/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"TestPassword123!"}' | grep -i session)

if [ "$PRE_LOGIN_COOKIE" != "$POST_LOGIN_COOKIE" ]; then
  echo "PASS: Session ID regenerated after login"
else
  echo "FAIL: Session fixation vulnerability - session ID not changed"
fi

# === Concurrent Session Testing (AC-10) ===
# Login from multiple "devices"
TOKEN1=$(curl -s -X POST "https://<host>/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device1" \
  -d '{"username":"testuser","password":"TestPassword123!"}' | jq -r '.access_token')

TOKEN2=$(curl -s -X POST "https://<host>/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device2" \
  -d '{"username":"testuser","password":"TestPassword123!"}' | jq -r '.access_token')

TOKEN3=$(curl -s -X POST "https://<host>/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device3" \
  -d '{"username":"testuser","password":"TestPassword123!"}' | jq -r '.access_token')

# For FedRAMP High (max 1 session), TOKEN1 should be invalidated
# For FedRAMP Moderate (max 3 sessions), all should work
curl -s "https://<host>/api/protected" -H "Authorization: Bearer $TOKEN1" | jq -r '.status'
# FedRAMP High Expected: 401 Unauthorized (session superseded)
# FedRAMP Moderate Expected: success
```

**Checklist:**
- [ ] Session timeout enforced (tested with expired token or wait)
- [ ] Session fixation prevented (ID changes on login)
- [ ] Concurrent session limits enforced per profile

### Step 5a.4: Rate Limiting and DoS Testing (SC-5)

**Objective:** Verify rate limiting prevents abuse.

```bash
# === Rapid Request Testing ===
# Send 100 requests rapidly and count responses
echo "Testing rate limiting with 100 rapid requests..."
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}\n" "https://<host>/api/public/endpoint"
done | sort | uniq -c

# Expected output should show 429 (Too Many Requests) after threshold:
#   75 200
#   25 429

# === Login Rate Limiting ===
echo "Testing login rate limiting..."
for i in {1..10}; do
  curl -s -X POST "https://<host>/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"ratelimit-test","password":"wrong"}' \
    -o /dev/null -w "%{http_code}\n"
done | sort | uniq -c

# Expected: 429 responses after 3-5 attempts (before lockout kicks in)

# === Large Payload Testing ===
# Test body size limits
dd if=/dev/zero bs=1M count=10 2>/dev/null | \
  curl -s -X POST "https://<host>/api/upload" \
    -H "Content-Type: application/octet-stream" \
    -H "Authorization: Bearer $TOKEN" \
    --data-binary @- \
    -o /dev/null -w "%{http_code}\n"
# Expected: 413 Payload Too Large

# === Slowloris-style Testing (connection exhaustion) ===
# Note: Use with caution, may trigger WAF alerts
timeout 30 slowhttptest -c 100 -H -g -o slowloris_report -i 10 -r 50 -t GET \
  -u "https://<host>/api/endpoint" 2>/dev/null || echo "slowhttptest not installed or blocked"
```

**Checklist:**
- [ ] Request rate limiting active (429 responses)
- [ ] Login rate limiting separate from general rate limiting
- [ ] Large payloads rejected
- [ ] Slow connection attacks mitigated

### Step 5a.5: Network Security Testing (SC-7, SC-8)

**Objective:** Verify network-level controls.

```bash
# === Port Scanning ===
# Verify only expected ports are open
nmap -sT -p- --min-rate 1000 <host> -oN nmap_full_scan.txt
# Expected: Only 22 (SSH), 443 (HTTPS), and application-specific ports

# Quick scan of common ports
nmap -sT -F <host>
# Document all open ports

# === TLS Configuration Testing ===
# Test TLS versions (should reject TLS 1.0, 1.1)
openssl s_client -connect <host>:443 -tls1 </dev/null 2>&1 | grep -i "handshake"
# Expected: Handshake failure (TLS 1.0 rejected)

openssl s_client -connect <host>:443 -tls1_1 </dev/null 2>&1 | grep -i "handshake"
# Expected: Handshake failure (TLS 1.1 rejected)

openssl s_client -connect <host>:443 -tls1_2 </dev/null 2>&1 | grep -i "protocol"
# Expected: TLSv1.2 (success)

# Test cipher suites
nmap --script ssl-enum-ciphers -p 443 <host>
# Expected: Only strong ciphers (AES-GCM, ChaCha20), no DES/RC4/MD5

# Use testssl.sh for comprehensive TLS audit
testssl.sh --severity HIGH <host>:443 > tls_audit_report.txt
# Expected: No HIGH or CRITICAL findings

# === Certificate Validation ===
openssl s_client -connect <host>:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer
# Verify: Not expired, correct subject, trusted issuer

# Test certificate chain
openssl s_client -connect <host>:443 -showcerts </dev/null 2>/dev/null | \
  grep -E "^(Certificate chain| [0-9]+ s:|   i:)"
# Expected: Complete chain to trusted root

# === Egress Testing (from within production system) ===
ssh <host> << 'EOF'
# Test if arbitrary outbound connections are blocked
timeout 5 curl -s http://example.com && echo "FAIL: Egress not filtered" || echo "PASS: Egress filtered"
timeout 5 curl -s https://ifconfig.me && echo "FAIL: Egress not filtered" || echo "PASS: Egress filtered"

# Test DNS exfiltration
timeout 5 nslookup test.example.com && echo "DNS allowed" || echo "DNS restricted"
EOF
```

**Checklist:**
- [ ] Only expected ports open (document all)
- [ ] TLS 1.0/1.1 rejected
- [ ] Only strong cipher suites enabled
- [ ] Certificate valid and chain complete
- [ ] Egress filtering active (FedRAMP High)

### Step 5a.6: Secrets and Sensitive Data Testing (IA-5(7))

**Objective:** Verify secrets are not exposed.

```bash
# === API Response Secrets Check ===
# Check error responses don't leak secrets
curl -s "https://<host>/api/nonexistent" | grep -iE "(password|secret|key|token|api_key)"
# Expected: No matches

# Check verbose errors don't expose internals
curl -s "https://<host>/api/cause-error" | grep -iE "(stack|trace|exception|sql|query)"
# Expected: No stack traces or SQL in production

# === Git History Scanning ===
# Scan for secrets in repository history
cd /path/to/repo
gitleaks detect --source . --report-path gitleaks_report.json
# Expected: No secrets detected

# Alternative: use trufflehog
trufflehog git file://. --json > trufflehog_report.json
# Expected: No high-confidence secrets

# === Environment Variable Check (on production system) ===
ssh <host> << 'EOF'
# Check if secrets are in environment (they shouldn't be visible)
env | grep -iE "(password|secret|api_key)" && \
  echo "WARNING: Secrets in environment" || \
  echo "PASS: No secrets in environment"

# Check systemd service doesn't expose secrets
systemctl show <app-name> | grep -i environment
EOF

# === Response Header Check ===
curl -s -I "https://<host>/api/endpoint" | grep -iE "(server|x-powered-by|x-aspnet)"
# Expected: No version information disclosed
```

**Checklist:**
- [ ] Error responses don't leak secrets
- [ ] No stack traces in production errors
- [ ] No secrets in git history
- [ ] Secrets not exposed via environment
- [ ] Server headers don't disclose versions

---

## Phase 5b: Database Security Audit

Comprehensive PostgreSQL security verification per STIG PGS15-00-*.

### Step 5b.1: Authentication Configuration (PGS15-00-000100)

```bash
# === pg_hba.conf Review ===
ssh <host> << 'EOF'
sudo cat /var/lib/postgresql/*/data/pg_hba.conf | grep -v "^#" | grep -v "^$"
EOF

# Expected configuration (FedRAMP Moderate/High):
# TYPE  DATABASE  USER      ADDRESS        METHOD
# local all       postgres                 peer
# host  all       all       127.0.0.1/32   scram-sha-256
# hostssl all     all       0.0.0.0/0      scram-sha-256 clientcert=verify-full

# FAIL conditions:
# - Any "trust" method
# - "md5" instead of "scram-sha-256"
# - "host" instead of "hostssl" for remote connections
# - Missing "clientcert=verify-full" for FedRAMP High

# === Password Authentication Verification ===
# Test that password authentication is required
ssh <host> << 'EOF'
# This should fail without password
PGPASSWORD='' psql -U testuser -h localhost -d postgres -c "SELECT 1;" 2>&1
# Expected: authentication failed

# Verify scram-sha-256 is enforced
sudo -u postgres psql -c "SHOW password_encryption;"
# Expected: scram-sha-256
EOF
```

**Checklist:**
- [ ] No "trust" authentication method
- [ ] scram-sha-256 password encryption
- [ ] hostssl required for remote connections
- [ ] Client certificates required (FedRAMP High)

### Step 5b.2: SSL/TLS Configuration (PGS15-00-000200)

```bash
ssh <host> << 'EOF'
# === SSL Configuration ===
sudo -u postgres psql << 'SQL'
SHOW ssl;
SHOW ssl_cert_file;
SHOW ssl_key_file;
SHOW ssl_ca_file;
SHOW ssl_min_protocol_version;
SHOW ssl_ciphers;
SQL
EOF

# Expected:
# ssl = on
# ssl_min_protocol_version = TLSv1.2
# ssl_ciphers = HIGH:!aNULL:!MD5 (or more restrictive)

# === Test SSL Connection ===
# Connect and verify SSL is used
ssh <host> << 'EOF'
psql "host=localhost dbname=postgres user=testuser sslmode=verify-full" \
  -c "SELECT ssl_is_used();"
EOF
# Expected: t (true)

# === Certificate Validation ===
ssh <host> << 'EOF'
# Check certificate expiration
sudo openssl x509 -in /var/lib/postgresql/*/data/server.crt -noout -dates
# Verify not expired and not expiring within 30 days
EOF
```

**Checklist:**
- [ ] SSL enabled
- [ ] TLS 1.2 minimum enforced
- [ ] Strong cipher suites only
- [ ] Server certificate valid
- [ ] CA certificate configured

### Step 5b.3: Audit Logging (PGS15-00-000300)

```bash
ssh <host> << 'EOF'
# === pgaudit Configuration ===
sudo -u postgres psql << 'SQL'
SHOW shared_preload_libraries;
-- Expected: includes 'pgaudit'

SHOW pgaudit.log;
-- Expected: 'all' or at minimum 'ddl,write,role'

SHOW pgaudit.log_catalog;
SHOW pgaudit.log_parameter;
SHOW pgaudit.log_statement_once;
SHOW log_destination;
SHOW log_directory;
SHOW log_filename;
SQL
EOF

# Expected:
# pgaudit.log = all (or ddl,write,role)
# pgaudit.log_parameter = on
# log_destination includes 'stderr' or 'syslog'

# === Verify Audit Logs Being Generated ===
ssh <host> << 'EOF'
# Check recent audit entries
sudo cat /var/log/postgresql/postgresql-*.log | grep -i "AUDIT" | tail -20

# Verify DDL is logged
sudo -u postgres psql -c "CREATE TABLE audit_test (id int);"
sudo -u postgres psql -c "DROP TABLE audit_test;"
sudo cat /var/log/postgresql/postgresql-*.log | grep -i "audit_test"
# Expected: CREATE TABLE and DROP TABLE audit entries
EOF

# === Log File Permissions ===
ssh <host> << 'EOF'
ls -la /var/log/postgresql/
# Expected: Owned by postgres, mode 0600 or 0640
EOF
```

**Checklist:**
- [ ] pgaudit extension loaded
- [ ] DDL, DML, and role changes logged
- [ ] Log parameters included
- [ ] Logs being written
- [ ] Log file permissions restrictive

### Step 5b.4: Role and Permission Audit (PGS15-00-000400)

```bash
ssh <host> << 'EOF'
sudo -u postgres psql << 'SQL'
-- List all roles and their attributes
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
FROM pg_roles
WHERE rolname NOT LIKE 'pg_%'
ORDER BY rolsuper DESC, rolname;

-- Check for excessive superuser accounts
SELECT count(*) as superuser_count FROM pg_roles WHERE rolsuper = true;
-- Expected: 1 (only postgres)

-- Check password expiration
SELECT rolname, rolvaliduntil FROM pg_roles WHERE rolpassword IS NOT NULL;
-- Expected: Expiration dates set for service accounts

-- Check for public schema permissions
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public';
-- Review for excessive permissions

-- Check for default privileges
SELECT * FROM pg_default_acl;
SQL
EOF
```

**Checklist:**
- [ ] Only one superuser account (postgres)
- [ ] Service accounts have minimal required permissions
- [ ] Password expiration configured
- [ ] Public schema permissions restricted
- [ ] No excessive default privileges

### Step 5b.5: Connection Security (PGS15-00-000500)

```bash
ssh <host> << 'EOF'
sudo -u postgres psql << 'SQL'
-- Connection limits
SHOW max_connections;
-- Document limit

-- Per-role connection limits
SELECT rolname, rolconnlimit FROM pg_roles WHERE rolconnlimit != -1;

-- Current connections
SELECT count(*), usename, state FROM pg_stat_activity GROUP BY usename, state;

-- Idle connection timeout
SHOW idle_in_transaction_session_timeout;
-- Expected: > 0 (not disabled)

SHOW statement_timeout;
-- Expected: > 0 (not disabled)
SQL
EOF

# === Test Connection Limits ===
# Attempt to exceed connection limit (adjust number based on max_connections)
# This is a stress test - use with caution
```

**Checklist:**
- [ ] max_connections appropriately limited
- [ ] Per-role connection limits set
- [ ] Idle transaction timeout configured
- [ ] Statement timeout configured

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

## STIG Traceability Matrix

This matrix maps Barbican controls to their authoritative STIG sources, enabling auditors to trace implementations back to DoD-approved security requirements.

### Ubuntu 22.04 STIG (V2R3)

| STIG Rule | Title | NIST Control | Barbican Implementation |
|-----------|-------|--------------|-------------------------|
| UBTU-22-411045 | Account lockout after 3 failed attempts | AC-7(a) | `login.rs:LockoutPolicy::max_attempts()` |
| UBTU-22-411050 | Lockout duration must be configured | AC-7(b) | `login.rs:LockoutPolicy::lockout_duration()` |
| UBTU-22-412020 | Session timeout after inactivity | AC-11, AC-12 | `session.rs:SessionPolicy::idle_timeout()` |
| UBTU-22-611035 | Minimum password length | IA-5(1)(a) | `password.rs:PasswordPolicy::min_length()` |
| UBTU-22-612010 | MFA for privileged accounts | IA-2(1) | `auth.rs:require_mfa` config option |
| UBTU-22-612035 | Certificate-based authentication | IA-2(12) | `tls.rs:require_client_cert()` |
| UBTU-22-231010 | Encryption at rest | SC-28 | `encryption.rs:FieldEncryption` |
| UBTU-22-255050 | TLS for data in transit | SC-8 | `tls.rs:TlsConfig`, `secure-postgres.nix` |
| UBTU-22-653045 | Audit log retention | AU-11 | `audit/mod.rs:retention_days` config |
| UBTU-22-671010 | Cryptographic key management | SC-12 | `keys.rs:KeyManager` |

### PostgreSQL 15 STIG (V2R6)

| STIG Rule | Title | NIST Control | Barbican Implementation |
|-----------|-------|--------------|-------------------------|
| PGS15-00-000100 | SSL/TLS required for connections | SC-8 | `secure-postgres.nix:enableSSL` |
| PGS15-00-000200 | Client certificate authentication | IA-5(2) | `secure-postgres.nix:enableClientCert` |
| PGS15-00-000300 | Audit logging enabled | AU-2, AU-3 | `secure-postgres.nix:pgaudit` |
| PGS15-00-000400 | SCRAM-SHA-256 authentication | IA-5(1) | `secure-postgres.nix:passwordEncryption` |
| PGS15-00-000500 | Connection limits enforced | SC-5 | `secure-postgres.nix:maxConnections` |
| PGS15-00-000600 | No trust authentication | IA-5 | `secure-postgres.nix:pg_hba.conf` |

### Application Security STIG (V5R3)

| STIG Rule | Title | NIST Control | Barbican Implementation |
|-----------|-------|--------------|-------------------------|
| APSC-DV-000160 | Input validation | SI-10 | `validation.rs:Validate trait` |
| APSC-DV-000170 | Output encoding | SI-10 | `validation.rs:html_escape()` |
| APSC-DV-000180 | Session timeout | AC-12 | `session.rs:SessionPolicy` |
| APSC-DV-000190 | MFA for web applications | IA-2(1) | `auth.rs:MfaRequirement` |
| APSC-DV-000200 | Concurrent session limits | AC-10 | `session.rs:max_concurrent_sessions` |
| APSC-DV-000210 | Account lockout | AC-7 | `login.rs:LockoutPolicy` |
| APSC-DV-000220 | Password complexity | IA-5(1) | `password.rs:PasswordPolicy` |
| APSC-DV-000230 | Secure cookie attributes | SC-8 | `session.rs:cookie_secure, cookie_http_only` |
| APSC-DV-000240 | HTTPS enforcement | SC-8(1) | `tls.rs:TlsEnforcement` |
| APSC-DV-000250 | Error message sanitization | SI-11 | `error.rs:SecureError` |

### Verification Commands

```bash
# Verify STIG mapping coverage
grep -r "UBTU-22\|PGS15\|APSC-DV" src/ nix/modules/ | wc -l

# List all STIG references in codebase
grep -roh "UBTU-22-[0-9]\+\|PGS15-00-[0-9]\+\|APSC-DV-[0-9]\+" src/ nix/modules/ | sort -u

# Cross-reference with ComplianceAsCode
# Download: https://github.com/ComplianceAsCode/content
# Verify rule IDs exist in official STIG content
```

---

## Independent Verification Tools

These external tools provide independent verification of security controls without relying on Barbican's own test output.

### Network Security Tools

#### Port Scanning (SC-7)

```bash
# Verify only expected ports are open
nmap -sT -sU -p- --min-rate=1000 TARGET_HOST

# Expected results for hardened system:
# - 22/tcp (SSH) - if remote access enabled
# - 443/tcp (HTTPS) - application port
# - 5432/tcp (PostgreSQL) - if exposed (should be internal only)

# Verify no unexpected services
nmap -sV -sC TARGET_HOST
```

#### TLS Configuration (SC-8)

```bash
# Comprehensive TLS audit
testssl.sh --severity HIGH TARGET_HOST:443

# Expected: No HIGH or CRITICAL findings
# Required checks:
# - TLS 1.2+ only
# - Strong cipher suites (AES-256-GCM, CHACHA20-POLY1305)
# - Valid certificate chain
# - HSTS header present

# Alternative: sslyze
sslyze --regular TARGET_HOST:443
```

### Web Application Security Tools

#### OWASP ZAP (SI-10, AC-3)

```bash
# Automated security scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://TARGET_HOST \
  -r zap-report.html

# Review for:
# - XSS vulnerabilities
# - SQL injection points
# - Missing security headers
# - Session management issues
```

#### Nikto Web Scanner

```bash
# Web server vulnerability scan
nikto -h https://TARGET_HOST -ssl

# Check for:
# - Dangerous HTTP methods enabled
# - Information disclosure
# - Default/backup files exposed
```

### Database Security Tools

#### pgAudit Verification

```bash
# Verify pgAudit is logging
sudo -u postgres psql -c "SHOW shared_preload_libraries;"
# Expected: 'pgaudit' in list

# Check audit log output
sudo journalctl -u postgresql | grep -i "AUDIT:"
```

#### pg_hba.conf Analyzer

```bash
# Dump and review authentication rules
sudo -u postgres cat /var/lib/postgresql/*/pg_hba.conf

# Verify:
# - No 'trust' entries
# - scram-sha-256 for password auth
# - cert for client certificate auth
# - hostssl for remote connections
```

### Secret Detection Tools

#### Gitleaks

```bash
# Scan repository for secrets
gitleaks detect --source . --report-format json --report-path gitleaks-report.json

# Expected: No findings or only false positives documented in .gitleaks.toml
```

#### TruffleHog

```bash
# Deep history scan
trufflehog git file://. --json > trufflehog-report.json

# Review all findings - even historical secrets require rotation
```

### Infrastructure Verification

#### Lynis Security Audit

```bash
# Comprehensive Linux security audit
lynis audit system --quick

# Review hardening index score
# FedRAMP High should target >80
```

#### OpenSCAP

```bash
# STIG compliance scan
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

### Verification Checklist

| Tool | Control Family | Expected Result |
|------|----------------|-----------------|
| nmap | SC-7 | Only documented ports open |
| testssl.sh | SC-8 | No HIGH/CRITICAL findings |
| OWASP ZAP | SI-10, AC-3 | No HIGH/CRITICAL alerts |
| gitleaks | IA-5(7) | No secrets detected |
| lynis | Multiple | Hardening index >70 (Low), >75 (Mod), >80 (High) |
| OpenSCAP | Multiple | STIG profile compliance >90% |

---

## Appendix A: DPE-Specific Audit Procedures

The Deployment Platform Engine (DPE) is the reference implementation of Barbican. These procedures supplement the main audit guide with DPE-specific verification steps.

### DPE Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     DPE Server (dpe-server)                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Auth API  │  │  Deploy API │  │   Cluster Manager   │ │
│  │  (Barbican) │  │  (Barbican) │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                           │                                 │
│  ┌────────────────────────┴────────────────────────────┐   │
│  │              Barbican Security Layer                 │   │
│  │  - Input Validation (SI-10)                          │   │
│  │  - Authentication (IA-2)                             │   │
│  │  - Session Management (AC-10, AC-11, AC-12)          │   │
│  │  - Rate Limiting (SC-5)                              │   │
│  │  - Audit Logging (AU-2, AU-3, AU-12)                 │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### DPE-Specific Control Verification

#### Step A.1: Verify Barbican Integration

```bash
# Check Barbican dependency version
cd /path/to/dpe
grep barbican Cargo.toml
# Expected: barbican with security features enabled

# Verify Barbican features
grep -A5 '\[dependencies.barbican\]' Cargo.toml
# Expected features: postgres, compliance-artifacts, stig
```

#### Step A.2: Verify Auth Handler Security

```bash
# Check login handler uses Barbican's LoginTracker
grep -n "LoginTracker\|LockoutPolicy" crates/dpe-server/src/server/api/auth/

# Verify password validation uses Barbican
grep -n "PasswordPolicy\|validate_password" crates/dpe-server/src/server/api/auth/

# Check ValidatedJson is used for input validation
grep -n "ValidatedJson" crates/dpe-server/src/server/api/
```

#### Step A.3: Test DPE Authentication Controls

```bash
# Test account lockout (AC-7)
DPE_URL="https://localhost:8080"

# Attempt 4 failed logins (should lock account after 3)
for i in {1..4}; do
  curl -s -X POST "$DPE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"test@example.com","password":"wrong"}' | jq .
done

# Verify lockout response on 4th attempt
# Expected: {"error":"account_locked","lockout_remaining_seconds":...}

# Test password validation (IA-5)
curl -s -X POST "$DPE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"short"}' | jq .
# Expected: {"error":"password_too_short",...}
```

#### Step A.4: Verify Input Validation

```bash
# Test XSS prevention in username field
curl -s -X POST "$DPE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"<script>alert(1)</script>","password":"test"}' | jq .
# Expected: Sanitized error, no script reflection

# Test SQL injection prevention
curl -s -X POST "$DPE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' OR '1'='1\",\"password\":\"test\"}" | jq .
# Expected: Invalid credentials error, not SQL error
```

#### Step A.5: Verify Session Management

```bash
# Login and get session token
TOKEN=$(curl -s -X POST "$DPE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"valid@example.com","password":"ValidPass123!"}' | jq -r .access_token)

# Test session timeout (wait for idle timeout)
# For FedRAMP Moderate: 15 minutes
sleep 901  # 15 min + 1 sec

curl -s -H "Authorization: Bearer $TOKEN" "$DPE_URL/api/profile" | jq .
# Expected: {"error":"session_expired"} or 401 Unauthorized

# Test concurrent session limit (AC-10)
# Login multiple times and verify oldest sessions are invalidated
```

#### Step A.6: Verify Rate Limiting

```bash
# Test rate limiting on login endpoint
for i in {1..150}; do
  curl -s -w "%{http_code}\n" -o /dev/null -X POST "$DPE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"test@example.com","password":"test"}'
done | sort | uniq -c
# Expected: Some 429 (Too Many Requests) responses after threshold
```

### DPE Audit Evidence Checklist

| Control | Verification Method | Evidence Location |
|---------|---------------------|-------------------|
| AC-7 | Login lockout test | Server logs, API responses |
| AC-10 | Concurrent session test | Session store inspection |
| AC-11 | Idle timeout test | Session expiry logs |
| IA-2 | Authentication flow test | Auth handler code review |
| IA-5(1) | Password policy test | Rejection of weak passwords |
| SI-10 | Input validation test | No XSS/SQLi exploitation |
| AU-2 | Audit log review | `/var/log/dpe/audit.log` |

---

## Appendix B: CI/CD Integration

Integrate security auditing into your CI/CD pipeline for continuous compliance verification.

### GitHub Actions Workflow

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly full audit

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-action@stable

      - name: Install Nix
        uses: cachix/install-nix-action@v25

      # Dependency Vulnerability Scan (SR-3)
      - name: Cargo Audit
        run: |
          cargo install cargo-audit
          cargo audit --deny warnings

      # Secret Detection (IA-5(7))
      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # SAST Analysis
      - name: Clippy Security Lints
        run: |
          cargo clippy -- \
            -D clippy::unwrap_used \
            -D clippy::expect_used \
            -D clippy::panic \
            -W clippy::pedantic

      # Compliance Artifact Generation
      - name: Generate Compliance Artifacts
        run: |
          cargo test --features compliance-artifacts control_test

      - name: Upload Compliance Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: compliance-artifacts
          path: compliance-artifacts/

      # NixOS Security Checks
      - name: Nix Flake Check
        run: nix flake check

  container-scan:
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4

      - name: Build Container
        run: docker build -t app:${{ github.sha }} .

      - name: Trivy Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:${{ github.sha }}'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

  weekly-full-audit:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4

      - name: Full STIG Compliance Scan
        run: |
          nix develop -c cargo test --features "compliance-artifacts,stig" -- --include-ignored

      - name: Generate Audit Report
        run: |
          cargo run --features compliance-artifacts --example generate_compliance_report -- \
            --profile high \
            --output compliance-report-$(date +%Y%m%d).json

      - name: Upload Audit Report
        uses: actions/upload-artifact@v4
        with:
          name: weekly-audit-report
          path: compliance-report-*.json
          retention-days: 365
```

### GitLab CI Configuration

```yaml
stages:
  - security
  - compliance
  - report

variables:
  CARGO_HOME: $CI_PROJECT_DIR/.cargo

cargo-audit:
  stage: security
  script:
    - cargo install cargo-audit
    - cargo audit --deny warnings
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

secret-scan:
  stage: security
  image: zricethezav/gitleaks:latest
  script:
    - gitleaks detect --source . --verbose
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

compliance-artifacts:
  stage: compliance
  script:
    - cargo test --features compliance-artifacts control_test
  artifacts:
    paths:
      - compliance-artifacts/
    expire_in: 1 year
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

weekly-audit:
  stage: report
  script:
    - cargo run --features compliance-artifacts --example generate_compliance_report -- --profile high
  artifacts:
    paths:
      - compliance-report-*.json
    expire_in: 1 year
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: local
    hooks:
      - id: cargo-audit
        name: cargo audit
        entry: cargo audit --deny warnings
        language: system
        pass_filenames: false
        files: Cargo\.(toml|lock)$

      - id: security-clippy
        name: security clippy
        entry: cargo clippy -- -D clippy::unwrap_used
        language: system
        pass_filenames: false
        types: [rust]
```

### Compliance Dashboard Integration

```bash
# Export compliance metrics to Prometheus
cat compliance-artifacts/compliance-report.json | jq -r '
  .artifacts[] |
  "barbican_control_status{control=\"\(.control_id)\",family=\"\(.family)\"} \(if .passed then 1 else 0 end)"
' > /var/lib/prometheus/textfile/barbican.prom

# Grafana dashboard query examples:
# - Compliance percentage: avg(barbican_control_status) * 100
# - Failed controls: count(barbican_control_status == 0)
# - Controls by family: sum by (family) (barbican_control_status)
```

### Audit Trail Requirements

For FedRAMP audits, maintain these CI/CD artifacts:

| Artifact | Retention | Purpose |
|----------|-----------|---------|
| `compliance-artifacts/*.json` | 1 year | Control test evidence |
| `cargo-audit-report.json` | 90 days | Vulnerability scan results |
| `gitleaks-report.json` | 90 days | Secret detection results |
| `container-scan-report.json` | 90 days | Container vulnerability scan |
| Pipeline logs | 1 year | Audit trail of all checks |

---

## Appendix C: Quick Reference

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
| 2.0 | 2026-01-23 | Major enhancement: Added penetration testing (Phase 5a), database security audit (Phase 5b), STIG traceability matrix, independent verification tools, DPE-specific procedures (Appendix A), CI/CD integration (Appendix B) |
| 1.1 | 2025-12-30 | Added Phase 1b for deploying audit targets when no production system exists |
| 1.0 | 2025-12-30 | Initial workflow-based guide |
