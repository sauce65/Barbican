# Barbican Security Compliance Documentation

This directory contains comprehensive NIST SP 800-53 Rev 5 compliance analysis and implementation guidance for the barbican security library.

## Documents

### [NIST_800_53_COMPLIANCE_ANALYSIS.md](./NIST_800_53_COMPLIANCE_ANALYSIS.md)
**Comprehensive analysis of all 18 NIST 800-53 control families**

- 47 controls barbican CAN IMPLEMENT out-of-the-box
- 62 controls barbican CAN FACILITATE with hooks/helpers
- 89 controls that are APPLICATION RESPONSIBILITY
- 134 controls that are OUT OF SCOPE (organizational/physical)
- Detailed implementation specifications for each control
- 5-phase implementation roadmap spanning 12 months
- Priority matrix (Critical, High, Medium, Low)

**Use this document to:**
- Understand what barbican provides vs what your application must implement
- Plan implementation priorities
- Design application architecture around barbican
- Communicate compliance capabilities to stakeholders

### [SECURITY_CONTROL_REGISTRY.md](./SECURITY_CONTROL_REGISTRY.md)
**Living registry tracking implementation status of all controls**

- Status tracking: Implemented, Partial, Planned, Facilitated
- Code locations and test artifacts for each control
- Gap analysis for incomplete controls
- Phase assignments and priorities
- Progress metrics and completion targets

**Use this document to:**
- Track implementation progress
- Identify gaps in current implementation
- Plan sprint work and feature development
- Generate compliance reports for auditors

### [NIST_800_53_IMPLEMENTATION_GUIDE.md](./NIST_800_53_IMPLEMENTATION_GUIDE.md)
**Practical quick-start guide for developers**

- 5-minute quick start to compliance
- Examples of using implemented controls
- Examples of facilitated controls (what you implement, what barbican provides)
- Best practices and common pitfalls
- Testing strategies
- NixOS infrastructure hardening guide

**Use this document to:**
- Get started using barbican
- Understand how to use each control
- Avoid common security mistakes
- Build compliant applications quickly

## Quick Reference

### Implementation Status

| Category | Count | Percentage |
|----------|-------|------------|
| Implemented | 56 | 50.9% |
| Partial | 5 | 4.5% |
| Planned | 17 | 15.5% |
| Facilitated | 32 | 29.1% |
| **Total Barbican Can Help** | **110** | **100%** |

### Remaining High Priority Controls

1. **IA-2(8)** - Nonce-based Replay Protection (HIGH)
2. **AC-5** - Role Conflict Checking (MEDIUM)
3. **AC-10** - Concurrent Session Control (MEDIUM)
4. **AU-11** - Audit Record Retention (HIGH)
5. **CP-10** - System Recovery Framework (HIGH)
6. **CM-3** - Runtime Config Change Auditing (HIGH)

### Controls Already Implemented (56 total)

**Authentication & Authorization:**
- **AC-3, AC-6** - Access Enforcement, Least Privilege (`src/auth.rs`)
- **AC-7** - Login Attempt Tracking (`src/login.rs`)
- **AC-11, AC-12** - Session Management (`src/session.rs`)
- **IA-2, IA-2(1), IA-2(2), IA-2(6), IA-8** - Authentication & MFA (`src/auth.rs`)
- **IA-3** - Device Identification via mTLS (`src/tls.rs`)
- **IA-5, IA-5(1), IA-5(2), IA-5(4), IA-5(7)** - Authenticator Management (`src/password.rs`, `src/secrets.rs`, `nix/modules/vault-pki.nix`)
- **IA-6** - Authentication Feedback (`src/error.rs`)

**Data Protection:**
- **SI-10** - Input Validation (`src/validation.rs`)
- **SI-11** - Secure Error Handling (`src/error.rs`)
- **SC-13** - Cryptographic Protection (`src/crypto.rs`)
- **SC-28** - Protection at Rest (`src/encryption.rs`)
- **SC-23** - Session Authenticity (`src/session.rs`)

**Operational Security:**
- **IR-4, IR-5** - Alerting (`src/alerting.rs`)
- **CA-7** - Health Checks (`src/health.rs`)
- **SC-12** - Key Management (`src/keys.rs`)
- **SR-3, SR-4** - Supply Chain Security (`src/supply_chain.rs`)
- **SA-11, CA-8** - Security Testing (`src/testing.rs`)

**Infrastructure (Rust):**
- **AC-4** - CORS Policy (`src/layers.rs`)
- **SC-5** - Rate Limiting & DoS Protection (`src/layers.rs`)
- **SC-8, SC-8(1)** - TLS/mTLS Enforcement (`src/tls.rs`, `src/database.rs`)
- **SC-10** - Network Disconnect (`src/layers.rs`)
- **AU-2, AU-3, AU-8, AU-9, AU-12, AU-14, AU-16** - Audit Logging & Protection (`src/audit/`, `src/observability/`)

**Infrastructure (NixOS):**
- **CM-2, CM-6, CM-7** - Configuration Management
- **CP-9** - Encrypted Backups (`nix/modules/database-backup.nix`)
- **SC-7, SC-7(5)** - Network Firewall (`nix/modules/vm-firewall.nix`)
- **SC-8, IA-3** - Hardened Nginx Reverse Proxy (`nix/modules/hardened-nginx.nix`)
- **SI-4, SI-16** - Intrusion Detection, Memory Protection (`nix/modules/intrusion-detection.nix`)

## Usage

### For Developers

1. Start with [NIST_800_53_IMPLEMENTATION_GUIDE.md](./NIST_800_53_IMPLEMENTATION_GUIDE.md)
2. Follow the quick start guide
3. Reference specific control examples as needed
4. Check [SECURITY_CONTROL_REGISTRY.md](./SECURITY_CONTROL_REGISTRY.md) for implementation status

### For Security Engineers

1. Review [NIST_800_53_COMPLIANCE_ANALYSIS.md](./NIST_800_53_COMPLIANCE_ANALYSIS.md)
2. Understand control categorization (implement/facilitate/app responsibility/out of scope)
3. Use [SECURITY_CONTROL_REGISTRY.md](./SECURITY_CONTROL_REGISTRY.md) to track progress
4. Generate compliance reports from registry status

### For Project Managers

1. Review implementation roadmap in [NIST_800_53_COMPLIANCE_ANALYSIS.md](./NIST_800_53_COMPLIANCE_ANALYSIS.md)
2. Track progress using [SECURITY_CONTROL_REGISTRY.md](./SECURITY_CONTROL_REGISTRY.md)
3. Use phase completion targets to plan sprints
4. Monitor compliance percentage metrics

### For Auditors

1. [SECURITY_CONTROL_REGISTRY.md](./SECURITY_CONTROL_REGISTRY.md) provides control status
2. Each implemented control has code location and test artifact
3. Gap analysis documents known deficiencies
4. Test results provide audit evidence

## Compliance Configuration (Single Source of Truth)

As of December 2025, barbican provides a unified compliance configuration module (`src/compliance/`) that serves as the **single source of truth** for all security settings across the application.

### Key Components

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and documentation |
| `profile.rs` | Compliance profile definitions (FedRAMP Low/Moderate/High, SOC 2) |
| `config.rs` | Unified `ComplianceConfig` struct with global singleton access |
| `validation.rs` | Compliance validation and reporting framework |

### Usage Pattern

```rust
// Initialize at application startup
use barbican::compliance::{ComplianceConfig, init, config};

init(ComplianceConfig::from_env());  // Reads COMPLIANCE_PROFILE env var

// Access globally anywhere
let compliance = config();

// Security modules derive settings from compliance config
let password_policy = PasswordPolicy::from_compliance(config());
let session_policy = SessionPolicy::from_compliance(config());
let lockout_policy = LockoutPolicy::from_compliance(config());
```

### Environment Variable

Set `COMPLIANCE_PROFILE` to: `fedramp-low`, `fedramp-moderate` (default), `fedramp-high`, `soc2`, or `custom`.

## Compliance Frameworks

Barbican is designed for compliance with:

- **NIST SP 800-53 Rev 5** - Federal security controls
- **FedRAMP** - Federal cloud security
- **SOC 2 Type II** - Trust service criteria
- **NIST SP 800-63B** - Digital identity guidelines

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- Architecture overview
- Development practices
- How to add new security controls
- Testing requirements

## Security

See [SECURITY.md](../SECURITY.md) for:
- Security control implementations
- Threat model
- Audit procedures
- Security contact

## Recent Updates

**2025-12-18: Phase 1 Artifact Tests Complete**
- 29 artifact-generating control tests implemented
- HMAC-SHA256 signed audit evidence generation
- Controls tested: AC-3, AC-4, AC-7, AC-11, AC-12, AU-2, AU-3, AU-8, AU-9, AU-12, AU-14, AU-16, CM-6, IA-2, IA-5, IA-5(1), IA-5(7), IA-6, SC-5, SC-8, SC-10, SC-12, SC-13, SC-23, SC-28, SI-10, SI-11
- FedRAMP Moderate readiness: 80% (up from 75%)
- Database SSL now defaults to VerifyFull (SC-8 compliance)
- Audit log integrity protection with tamper detection (AU-9)

**2025-12-15: Infrastructure Additions**
- `hardened-nginx` module: NIST SP 800-52B compliant reverse proxy
- `vault-pki` module: Automated PKI for mTLS certificates
- TLS/mTLS enforcement middleware (`src/tls.rs`)
- Secret detection scanner (`src/secrets.rs`) for IA-5(7)

This documentation is maintained by the security-auditor-agent and updated as controls are implemented, tested, and verified.

Last updated: 2025-12-18
