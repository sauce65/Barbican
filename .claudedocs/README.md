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
| Implemented | 52 | 47.7% |
| Partial | 6 | 5.5% |
| Planned | 19 | 17.4% |
| Facilitated | 32 | 29.4% |
| **Total Barbican Can Help** | **109** | **100%** |

### Remaining High Priority Controls

1. **SC-8/SC-8(1)** - HTTP TLS Enforcement (CRITICAL)
2. **IA-5(7)** - Secret Detection Scanner (CRITICAL)
3. **SC-17** - Certificate Validation Utilities (HIGH)
4. **SA-15(7)** - CI/CD Security Workflow (MEDIUM)
5. **AC-5** - Role Conflict Checking (MEDIUM)
6. **AC-10** - Concurrent Session Control (MEDIUM)
7. **IA-2(8)** - Nonce-based Replay Protection (HIGH)

### Controls Already Implemented (52 total)

**Authentication & Authorization:**
- **AC-3, AC-6** - Access Enforcement, Least Privilege (`src/auth.rs`)
- **AC-7** - Login Attempt Tracking (`src/login.rs`)
- **AC-11, AC-12** - Session Management (`src/session.rs`)
- **IA-2, IA-2(1), IA-2(2), IA-2(6), IA-8** - Authentication & MFA (`src/auth.rs`)
- **IA-5(1), IA-5(4)** - Password Policy (`src/password.rs`)

**Data Protection:**
- **SI-10** - Input Validation (`src/validation.rs`)
- **SI-11, IA-6** - Secure Error Handling (`src/error.rs`)
- **SC-13** - Cryptographic Protection (`src/crypto.rs`)

**Operational Security:**
- **IR-4, IR-5, SI-4(2), SI-4(5)** - Alerting (`src/alerting.rs`)
- **CA-7** - Health Checks (`src/health.rs`)
- **SC-12** - Key Management (`src/keys.rs`)
- **SR-3, SR-4, SR-11, SI-2, SI-3, SI-7, CM-8, CM-10** - Supply Chain (`src/supply_chain.rs`)
- **SA-11, CA-8** - Security Testing (`src/testing.rs`)

**Infrastructure (Rust):**
- **AC-4** - CORS Policy (`src/layers.rs`)
- **SC-5** - Rate Limiting & DoS Protection (`src/layers.rs`)
- **SC-10** - Request Timeout (`src/layers.rs`)
- **AU-2, AU-3, AU-8, AU-12** - Audit Logging (`src/observability/`)

**Infrastructure (NixOS):**
- **CM-2, CM-6, CM-7** - Configuration Management
- **CP-9** - Encrypted Backups
- **SC-7, SC-7(5)** - Network Firewall
- **SI-4, SI-16** - Intrusion Detection, Memory Protection

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

## Updates

This documentation is maintained by the security-auditor-agent and updated as controls are implemented, tested, and verified.

Last updated: 2025-12-17
