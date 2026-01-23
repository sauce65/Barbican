# STIG Traceability Matrix

This document provides formal traceability from Barbican's security implementations to official STIG rule IDs, enabling auditable compliance verification.

## Overview

Barbican implements controls from three primary STIGs:

| STIG | Version | Scope | Rule Count |
|------|---------|-------|------------|
| Ubuntu 22.04 LTS STIG | V2R3 | OS-level security controls | 15+ |
| PostgreSQL 15 STIG | V2R6 | Database security controls | 6 |
| Application Security STIG | V5R3 | Application-level controls | 12 |

## Ubuntu 22.04 STIG (V2R3)

### Account Management and Authentication

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| UBTU-22-411010 | Configure account lockout threshold | AC-7 | Medium | `nix/modules/secure-users.nix` |
| UBTU-22-411015 | Disable automatic logon | AC-2 | Medium | `nix/modules/secure-users.nix` |
| UBTU-22-411020 | Require unique user accounts | AC-2 | Medium | `nix/modules/secure-users.nix` |
| UBTU-22-411045 | Lock after 3 failed attempts | AC-7 | Medium | `src/login.rs:LockoutPolicy` |
| UBTU-22-411050 | Unlock after lockout duration | AC-7 | Medium | `src/login.rs:LockoutPolicy` |
| UBTU-22-412020 | Screen lock after 15 minutes | AC-11 | Medium | `src/session.rs:SessionPolicy` |
| UBTU-22-611035 | Minimum 15-char password length | IA-5(1) | Medium | `src/password.rs:PasswordPolicy` |
| UBTU-22-612010 | Require MFA for local access | IA-2 | High | `src/auth.rs:MfaPolicy` |
| UBTU-22-612020 | Display SSH warning banner | AC-8 | Medium | `nix/modules/secure-users.nix` |
| UBTU-22-612035 | PKI-based MFA | IA-2(6) | Medium | `src/tls.rs`, `src/auth.rs:MfaPolicy` |

### Encryption and Cryptography

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| UBTU-22-231010 | Encrypt partitions | SC-28 | High | `src/encryption.rs` |
| UBTU-22-255010 | SSH FIPS cryptography | AC-17(2), SC-8 | High | `nix/modules/hardened-ssh.nix` |
| UBTU-22-255015-040 | SSH strong algorithms | SC-8 | High | `nix/modules/hardened-ssh.nix` |
| UBTU-22-255050 | Encrypt transmitted data | SC-8 | High | `src/tls.rs` |
| UBTU-22-671010 | Cryptographic key management | SC-12 | Medium | `src/keys.rs` |

### Kernel and System Hardening

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| UBTU-22-213010 | Enable ASLR | SI-16 | Medium | `nix/modules/kernel-hardening.nix` |
| UBTU-22-213015 | Restrict kernel pointers | SI-16 | Medium | `nix/modules/kernel-hardening.nix` |
| UBTU-22-213020 | Restrict dmesg | SI-16 | Medium | `nix/modules/kernel-hardening.nix` |
| UBTU-22-213025 | TCP SYN cookies | SC-5 | Medium | `nix/modules/kernel-hardening.nix` |
| UBTU-22-213030 | Disable ICMP redirects | SC-7 | Medium | `nix/modules/kernel-hardening.nix` |
| UBTU-22-213035 | Disable source routing | SC-7 | Medium | `nix/modules/kernel-hardening.nix` |
| UBTU-22-213040 | Enable audit parameter | AU-2 | Medium | `nix/modules/kernel-hardening.nix` |

### Firewall and Network

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| UBTU-22-251010 | Default deny firewall | SC-7 | High | `nix/modules/vm-firewall.nix` |
| UBTU-22-251015 | Inbound filtering | SC-7 | High | `nix/modules/vm-firewall.nix` |
| UBTU-22-251020 | Outbound filtering | SC-7(5) | High | `nix/modules/vm-firewall.nix` |
| UBTU-22-251025 | Log dropped packets | AU-2 | Medium | `nix/modules/vm-firewall.nix` |
| UBTU-22-251030 | Allow essential services | CM-7 | Medium | `nix/modules/vm-firewall.nix` |

### Audit and Logging

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| UBTU-22-651010 | Audit privileged activities | AU-2, AU-12 | Medium | `nix/modules/intrusion-detection.nix` |
| UBTU-22-651015 | Audit executions | AU-2 | Medium | `nix/modules/intrusion-detection.nix` |
| UBTU-22-651020 | Audit file deletions | AU-2 | Medium | `nix/modules/intrusion-detection.nix` |
| UBTU-22-651025 | Auditd disk buffer | AU-5 | Medium | `nix/modules/intrusion-detection.nix` |
| UBTU-22-653045 | Audit record retention | AU-11 | Medium | `src/audit/mod.rs` |
| UBTU-22-654010 | Enable AIDE | SI-7 | Medium | `nix/modules/intrusion-detection.nix` |
| UBTU-22-654015 | Initialize AIDE DB | SI-7 | Medium | `nix/modules/intrusion-detection.nix` |
| UBTU-22-654020 | AIDE critical files | SI-7 | Medium | `nix/modules/intrusion-detection.nix` |

### Time Synchronization

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| UBTU-22-252010 | Time synchronization | AU-8 | Medium | `nix/modules/time-sync.nix` |
| UBTU-22-252015 | Multiple time sources | AU-8(1) | Medium | `nix/modules/time-sync.nix` |
| UBTU-22-252020 | NTP authentication | AU-8(1) | Medium | `nix/modules/time-sync.nix` |

### Process Isolation

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| UBTU-22-232010 | Restrict capabilities | AC-6 | Medium | `nix/modules/systemd-hardening.nix` |
| UBTU-22-232015 | NoNewPrivileges | AC-6 | Medium | `nix/modules/systemd-hardening.nix` |
| UBTU-22-232020 | ProtectSystem strict | AC-6 | Medium | `nix/modules/systemd-hardening.nix` |
| UBTU-22-232025 | Namespace isolation | SC-39 | Medium | `nix/modules/systemd-hardening.nix` |

---

## PostgreSQL 15 STIG (V2R6)

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| PGS15-00-000100 | Require SSL/TLS | SC-8 | High | `nix/modules/secure-postgres.nix:enableSSL` |
| PGS15-00-000200 | Client certificate auth | IA-5(2) | Medium | `nix/modules/secure-postgres.nix:enableClientCert` |
| PGS15-00-000300 | Enable pgaudit | AU-2, AU-3, AU-12 | Medium | `nix/modules/secure-postgres.nix:enablePgaudit` |
| PGS15-00-000400 | SCRAM-SHA-256 auth | IA-5 | Medium | `nix/modules/secure-postgres.nix` |
| PGS15-00-000500 | Protect log files | AU-9 | Medium | `nix/modules/secure-postgres.nix:logFileMode` |
| PGS15-00-000600 | Limit connections | SC-5 | Low | `nix/modules/secure-postgres.nix:maxConnections` |

---

## Application Security STIG (V5R3)

### Input Validation

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| APSC-DV-000160 | Validate all input | SI-10 | High | `src/validation.rs` |
| APSC-DV-000170 | Encode output | SI-10 | High | `src/validation.rs` |

### Session Management

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| APSC-DV-000180 | Session timeout | AC-11, AC-12 | Medium | `src/session.rs:SessionPolicy` |

### Authentication

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| APSC-DV-000190 | Implement MFA | IA-2 | High | `src/auth.rs:MfaPolicy` |
| APSC-DV-000200 | Hardware token auth | IA-2(6) | Medium | `src/auth.rs:MfaPolicy` |
| APSC-DV-000210 | Limit login attempts | AC-7 | Medium | `src/login.rs:LockoutPolicy` |
| APSC-DV-000220 | Password complexity | IA-5(1) | Medium | `src/password.rs:PasswordPolicy` |
| APSC-DV-000230 | Breach DB check | IA-5(1) | Medium | `src/password.rs:PasswordPolicy` |

### Access Control

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| APSC-DV-000240 | Enforce authorizations | AC-3 | High | `src/auth.rs:Claims` |

### Audit

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| APSC-DV-000250 | Log auth attempts | AU-2, AU-3 | Medium | `src/audit/mod.rs`, `src/login.rs` |

### Error Handling

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| APSC-DV-000260 | Safe error messages | SI-11 | Medium | `src/error.rs` |

### Cryptography

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| APSC-DV-000270 | FIPS cryptography | SC-13 | High | `src/encryption.rs`, `src/keys.rs` |

---

## CIS Nginx Benchmark

| Rule ID | Title | NIST | Barbican Implementation |
|---------|-------|------|-------------------------|
| CIS-NGINX-2.1 | TLS 1.2 or greater | SC-8 | `nix/modules/hardened-nginx.nix` |
| CIS-NGINX-2.2 | Approved cipher suites | SC-8 | `nix/modules/hardened-nginx.nix` |
| CIS-NGINX-2.3 | HSTS header | SC-8 | `nix/modules/hardened-nginx.nix` |
| CIS-NGINX-2.4 | Disable insecure protocols | SC-8 | `nix/modules/hardened-nginx.nix` |
| CIS-NGINX-2.5 | Client cert validation | IA-3 | `nix/modules/hardened-nginx.nix` |
| CIS-NGINX-3.1 | Rate limit connections | SC-5 | `nix/modules/hardened-nginx.nix` |
| CIS-NGINX-4.1 | Access/error logging | AU-2, AU-3 | `nix/modules/hardened-nginx.nix` |

---

## Anduril NixOS STIG (V1)

In addition to Ubuntu mappings, Barbican implements controls from the [Anduril NixOS STIG](https://www.stigviewer.com/stigs/anduril_nixos):

| Rule ID | Title | NIST | Severity | Barbican Implementation |
|---------|-------|------|----------|-------------------------|
| V-268078 | Enable built-in firewall | SC-7 | Medium | `nix/modules/vm-firewall.nix` |
| V-268080 | Enable audit daemon | AU-2 | High | `nix/modules/intrusion-detection.nix` |
| V-268081 | Lock after 3 failed attempts (15 min) | AC-7 | Medium | `nix/modules/secure-users.nix` |
| V-268134 | Enforce 15-character password minimum | IA-5(1) | High | `src/password.rs:PasswordPolicy` |
| V-268139 | Enable USBguard | CM-8 | Medium | `nix/modules/usb-protection.nix` |
| V-268173 | Configure AppArmor MAC | AC-3 | Medium | `nix/modules/mandatory-access-control.nix` |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total STIG Rules** | 54+ |
| **CAT I (High)** | 16 |
| **CAT II (Medium)** | 36 |
| **CAT III (Low)** | 2 |
| **Rust Modules** | 10 |
| **NixOS Modules** | 11 |

## Using STIG Mappings in Code

The `barbican::compliance::stig::mappings` module provides programmatic access:

```rust
use barbican::compliance::stig::mappings::{get_rule, rules_for_nist, StigCoverage};

// Look up specific rule
if let Some(rule) = get_rule("UBTU-22-411045") {
    println!("{}: {}", rule.id, rule.title);
    println!("NIST: {:?}", rule.nist_controls);
    println!("Impl: {}", rule.barbican_impl);
}

// Find all rules for a NIST control
let ac7_rules = rules_for_nist("AC-7");
for rule in ac7_rules {
    println!("{} ({})", rule.id, rule.severity);
}

// Coverage statistics
let coverage = StigCoverage::calculate();
println!("Total rules: {}", coverage.total);
println!("High severity: {}", coverage.high_severity);
```

## NixOS STIG Note

While Barbican maps NixOS modules to Ubuntu 22.04 STIG rules (because the underlying controls are OS-agnostic), there is also an [Anduril NixOS STIG](https://www.stigviewer.com/stigs/anduril_nixos) available for organizations requiring vendor-specific NixOS STIG compliance.

Barbican uses Ubuntu STIG mappings because:
1. The security controls (kernel parameters, SSH, firewall) are OS-agnostic
2. Ubuntu STIGs have broader industry adoption and tooling support
3. ComplianceAsCode provides extensive Ubuntu content for automation

## References

- [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) - Source of STIG definitions
- [DISA STIG Library](https://public.cyber.mil/stigs/) - Official STIG downloads
- [Anduril NixOS STIG](https://www.stigviewer.com/stigs/anduril_nixos) - NixOS-specific STIG
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security controls
