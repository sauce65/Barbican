# Barbican Auditor Guide

## What Is Barbican?

Barbican is a Rust library that implements NIST 800-53 Rev 5 security controls for web applications. When developers build applications with Barbican, they get 52+ controls "out of the box" with configuration derived from compliance profiles (FedRAMP Low/Moderate/High, SOC 2).

**Think of it as:** A pre-built security control library. Instead of each development team implementing AC-7 (Unsuccessful Logon Attempts) from scratch, they import Barbican and get a tested, documented implementation.

## Why Should Auditors Care?

Barbican produces **machine-verifiable compliance artifacts**. Rather than reviewing screenshots or interviewing developers, you can:

1. Run automated tests that generate JSON evidence
2. Verify control implementations against source code
3. Check that the same tests pass in production environments

The library is designed to make your job easier by providing traceable evidence from control requirement → source code → test → artifact.

## What Controls Does Barbican Implement?

| Family | Controls | Examples |
|--------|----------|----------|
| Access Control (AC) | AC-3, AC-4, AC-6, AC-7, AC-11, AC-12 | Role-based access, account lockout, session timeout |
| Audit (AU) | AU-2, AU-3, AU-8, AU-12, AU-14, AU-16 | Security event logging, audit records, timestamps |
| Config Mgmt (CM) | CM-6, CM-8, CM-10 | Secure defaults, SBOM generation, license compliance |
| Identification (IA) | IA-2, IA-5(1), IA-5(7) | MFA enforcement, password policy, secret detection |
| System Protection (SC) | SC-5, SC-8, SC-10, SC-12, SC-13 | Rate limiting, TLS, session disconnect, key management |
| System Integrity (SI) | SI-10, SI-11 | Input validation, secure error handling |

**Full registry:** `.claudedocs/SECURITY_CONTROL_REGISTRY.md`

## How to Audit Barbican

### Step 1: Generate Compliance Artifacts

Run the compliance test suite:

```bash
# Run compliance tests
cargo test --features compliance-artifacts

# Generate unsigned report (development)
cargo run --example generate_compliance_report --features compliance-artifacts

# Generate signed report (production - recommended)
COMPLIANCE_SIGNING_KEY=your-secret-key cargo run --example generate_compliance_report \
  --features compliance-artifacts -- --sign --key-id production-key-2025
```

This produces a JSON report in `./compliance-artifacts/` containing:
- Control ID and name (e.g., "AC-7", "Unsuccessful Logon Attempts")
- Test name and description
- Source code location (file, line numbers)
- Test inputs and expected outputs
- Observed results
- Pass/fail status with evidence

### Step 2: Review the Artifact

Each control test produces evidence like this (abbreviated):

```json
{
  "control_id": "AC-7",
  "control_name": "Unsuccessful Logon Attempts",
  "test_name": "lockout_after_max_attempts",
  "code_location": {
    "file": "src/login.rs",
    "line_start": 55,
    "line_end": 120
  },
  "inputs": {
    "max_attempts": 3,
    "lockout_duration_secs": 1800
  },
  "expected": {
    "locked_after_3_attempts": true
  },
  "observed": {
    "locked_after_3_attempts": true
  },
  "passed": true,
  "evidence": [
    {
      "evidence_type": "assertion",
      "description": "Account locks after 3 failed attempts",
      "content": { "passed": true, "details": {...} }
    }
  ]
}
```

### Step 3: Verify Source Code (If Needed)

The `code_location` field tells you exactly where to look. For AC-7:

```bash
# View the implementation
sed -n '55,120p' src/login.rs
```

You'll see the `LoginTracker` struct with lockout logic. The tests exercise this code and produce the evidence in the artifact.

### Step 4: Verify Report Integrity

Reports can be HMAC-SHA256 signed for integrity verification. Generate signed reports with:

```bash
COMPLIANCE_SIGNING_KEY=your-secret-key cargo run --example generate_compliance_report \
  --features compliance-artifacts -- --sign --key-id production-key-2025
```

The signature field in the report:

```json
{
  "signature": {
    "algorithm": "HMAC-SHA256",
    "key_id": "production-key-2025",
    "value": "qVmoawroyu0b7FM0Rs28OTgD1FHc816tAGq+g5cN3Wo=",
    "signed_at": "2025-12-23T17:33:43.289191918Z"
  }
}
```

**To verify manually:**
1. Load the report JSON
2. Remove the `signature` field entirely
3. Serialize the remaining JSON (compact, no whitespace)
4. Compute HMAC-SHA256 over the JSON bytes using the signing key
5. Base64-encode the result and compare with `signature.value`

**To verify programmatically (Rust):**
```rust
use barbican::compliance::ComplianceTestReport;

let report: ComplianceTestReport = serde_json::from_str(&json)?;
let key = std::env::var("COMPLIANCE_SIGNING_KEY")?.into_bytes();

if report.verify(&key)? {
    println!("Report is authentic and unmodified");
} else {
    println!("WARNING: Report may have been tampered with!");
}
```

The verification uses constant-time comparison to prevent timing attacks.

## Key Documentation Files

| File | Purpose |
|------|---------|
| `SECURITY.md` | Control matrix, threat model, compliance mappings |
| `.claudedocs/SECURITY_CONTROL_REGISTRY.md` | Living registry of all 52+ controls with status |
| `.claudedocs/NIST_800_53_CROSSWALK.md` | Detailed NIST → Barbican mapping |
| `src/compliance/` | Compliance configuration and artifact generation |

## Compliance Profile Configuration

Applications set `COMPLIANCE_PROFILE` to derive security settings:

| Setting | FedRAMP Low | FedRAMP Moderate | FedRAMP High | SOC 2 |
|---------|-------------|------------------|--------------|-------|
| Session Timeout | 30 min | 15 min | 10 min | 15 min |
| MFA Required | No | Yes | Yes | Yes |
| Password Minimum | 8 chars | 12 chars | 14 chars | 12 chars |
| Max Login Attempts | 5 | 3 | 3 | 3 |
| Key Rotation | 90 days | 90 days | 30 days | 90 days |

All security modules call `from_compliance()` to derive their settings from the profile. This ensures consistency—you don't audit 15 different timeout configurations, you audit one profile setting that propagates everywhere.

## What Barbican Does NOT Do

Barbican is a library, not a complete system. It cannot implement controls that require:

- **Infrastructure:** Network segmentation, physical security, backup systems
- **Human processes:** Security training, incident response procedures
- **Identity providers:** Barbican validates JWT claims from your IdP (Keycloak, Entra ID, Auth0), but doesn't manage users
- **Key storage:** Barbican provides rotation tracking and KMS integration traits, but actual keys live in Vault/AWS KMS/HSM

The registry marks these as "FACILITATED" (provides hooks) or "OUT OF SCOPE."

## Auditing Workflow Summary

1. **Request the compliance artifact** from the application team
2. **Verify the signature** against the organization's signing key
3. **Review pass/fail status** for each control
4. **For failed or partial controls:** Check `failure_reason` and `evidence`
5. **For sampling:** Use `code_location` to spot-check implementations
6. **Check the profile:** Confirm `COMPLIANCE_PROFILE` matches the system's authorization boundary

## Common Questions

**Q: How do I know these tests actually run in production?**

The artifact includes `generated_at` timestamp and `barbican_version`. Require that artifacts be generated from production builds as part of continuous compliance.

**Q: What if a control shows "FACILITATED"?**

The library provides hooks but can't fully implement the control. Example: AU-4 (Audit Log Storage Capacity) - Barbican logs events, but storage capacity is infrastructure. You'll audit that separately.

**Q: Can developers disable security controls?**

Some controls can be disabled via configuration (e.g., `SECURITY_HEADERS_ENABLED=false`). The artifact captures the actual configuration used during the test. If headers are disabled, the test will show that.

**Q: How do I verify the tests aren't faked?**

Multiple verification methods:

1. **Signature verification**: Signed reports include HMAC-SHA256 signatures. Verify the signature matches using the organization's signing key (see Step 4).

2. **Run the tests yourself**:
```bash
git clone <repo>
cargo test --features compliance-artifacts
```
The same tests that generate artifacts are the same tests that must pass for the build to succeed.

3. **Check CI/CD pipeline**: Request access to the build pipeline to confirm reports are generated from the same codebase that's deployed.

---

**Questions?** The development team should provide access to:
- Source repository
- CI/CD pipeline showing test runs
- Signed compliance artifacts
- Compliance profile configuration
