# FedRAMP High Remediation Implementation Plan
## Barbican Security Library - Critical Gap Resolution

**Created**: 2025-12-18
**Priority**: CRITICAL
**Timeline**: 3 weeks (Phase 1-2)
**Effort**: 22 person-days

---

## Overview

This document provides **detailed implementation steps** for closing the critical gaps blocking FedRAMP High authorization:

1. **SC-13**: FIPS 140-2/3 Validated Cryptography (5 days)
2. **IA-2(12)**: PIV Credential Support (9 days)
3. **IA-3/SC-8**: mTLS Enforcement (3 days)
4. **AU-10**: Non-Repudiation Signatures (5 days)

---

## Phase 1A: FIPS 140-2/3 Cryptography Migration (SC-13)

### Priority: CRITICAL ⛔ - BLOCKS ATO
### Effort: 5 days
### Owner: Senior Security Engineer

---

### Day 1: Library Selection and Planning

#### Morning: Evaluate FIPS-Validated Options

**Option 1: AWS-LC (RECOMMENDED)**
```toml
# Cargo.toml
[dependencies]
aws-lc-rs = { version = "1.10", features = ["fips"] }

# Benefits:
# - FIPS 140-3 validated (Certificate #4816)
# - Maintained by AWS
# - Drop-in replacement for ring
# - Performance optimized
# - Active development
```

**Option 2: BoringSSL**
```toml
[dependencies]
boring = { version = "4.0", features = ["fips"] }

# Benefits:
# - FIPS 140-2 validated
# - Used by Google
# - Requires build toolchain (more complex)
```

**Option 3: OpenSSL 3.0 FIPS**
```toml
[dependencies]
openssl = { version = "0.10", features = ["fips"] }

# Benefits:
# - Industry standard
# - FIPS 140-2 validated
# - Larger dependency footprint
```

**Decision**: Use AWS-LC for:
- Best Rust integration
- FIPS 140-3 (newer standard)
- Performance
- Simpler build process

#### Afternoon: Create Migration Plan

**Files to Modify**:
1. `/home/paul/code/barbican/src/crypto.rs` - Constant-time comparison
2. `/home/paul/code/barbican/src/audit/integrity.rs` - HMAC-SHA256
3. `/home/paul/code/barbican/src/encryption.rs` - AES-256-GCM
4. `/home/paul/code/barbican/Cargo.toml` - Dependencies

**Test Plan**:
- Unit tests for each crypto operation
- Integration tests for audit signing
- Encryption/decryption round-trip tests
- Performance benchmarks (ensure no regression)

---

### Day 2: Update Dependencies and Core Crypto

#### Task 1: Update Cargo.toml

```toml
# Before:
[dependencies]
subtle = "2.5"

# After:
[dependencies]
aws-lc-rs = { version = "1.10", features = ["fips"] }
```

#### Task 2: Add FIPS Mode Initialization

**File**: `/home/paul/code/barbican/src/lib.rs`

```rust
/// Initialize FIPS mode for FedRAMP High compliance (SC-13)
///
/// This function MUST be called at application startup before any
/// cryptographic operations. It ensures that only FIPS 140-3 validated
/// algorithms are used.
///
/// # Panics
///
/// Panics if FIPS mode cannot be enabled. This is intentional - FedRAMP
/// High deployments MUST use validated cryptography.
///
/// # Example
///
/// ```ignore
/// fn main() {
///     barbican::init_fips_mode();
///     // ... rest of application
/// }
/// ```
pub fn init_fips_mode() {
    if cfg!(feature = "fips") {
        aws_lc_rs::init_fips_mode()
            .expect("FIPS mode required for FedRAMP High - initialization failed");

        tracing::info!(
            "FIPS 140-3 mode enabled (AWS-LC Certificate #4816)",
        );
    } else {
        tracing::warn!(
            "FIPS mode not enabled - not suitable for FedRAMP High deployments"
        );
    }
}

/// Check if FIPS mode is currently active
pub fn is_fips_mode_enabled() -> bool {
    #[cfg(feature = "fips")]
    {
        aws_lc_rs::fips::is_enabled()
    }
    #[cfg(not(feature = "fips"))]
    {
        false
    }
}
```

#### Task 3: Update Constant-Time Comparison

**File**: `/home/paul/code/barbican/src/crypto.rs`

```rust
//! Cryptographic utilities for secure operations (SC-13)
//!
//! FIPS 140-3 Compliance: Uses AWS-LC validated cryptography
//! Certificate: #4816
//! Algorithms: HMAC-SHA256, AES-256-GCM

/// Performs constant-time comparison of two byte slices.
///
/// FIPS 140-3 Compliant: Uses AWS-LC validated constant-time comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use aws_lc_rs::constant_time;

    if a.len() != b.len() {
        return false;
    }

    constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Performs constant-time comparison of two strings.
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_str_eq("secret123", "secret123"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_str_eq("secret123", "secret456"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_fips_mode_available() {
        // Verify FIPS mode is available in this build
        #[cfg(feature = "fips")]
        assert!(crate::is_fips_mode_enabled());
    }
}
```

---

### Day 3: Update HMAC-SHA256 (Audit Integrity)

**File**: `/home/paul/code/barbican/src/audit/integrity.rs`

```rust
use aws_lc_rs::hmac;

/// Sign a message with HMAC-SHA256
///
/// FIPS 140-3 Compliant: Uses AWS-LC validated HMAC implementation
fn sign_hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, message);
    tag.as_ref().to_vec()
}

/// Verify HMAC-SHA256 signature
fn verify_hmac_sha256(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let verification_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&verification_key, message, signature).is_ok()
}

// Update SignedAuditRecord::sign() to use new functions
impl SignedAuditRecord {
    pub fn sign(config: &AuditIntegrityConfig, message: &str) -> Self {
        let message_bytes = message.as_bytes();
        let signature = sign_hmac_sha256(&config.signing_key, message_bytes);

        Self {
            message: message.to_string(),
            signature,
            algorithm: SignatureAlgorithm::HmacSha256,
            timestamp: SystemTime::now(),
            previous_hash: None,
        }
    }

    pub fn verify(&self, config: &AuditIntegrityConfig) -> bool {
        verify_hmac_sha256(
            &config.signing_key,
            self.message.as_bytes(),
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_hmac_sha256() {
        let key = b"test-key-for-hmac-validation-32b";
        let message = b"test message";

        let signature = sign_hmac_sha256(key, message);
        assert_eq!(signature.len(), 32); // SHA-256 = 32 bytes

        assert!(verify_hmac_sha256(key, message, &signature));
        assert!(!verify_hmac_sha256(key, b"different", &signature));
    }

    #[test]
    fn test_audit_record_fips_signing() {
        let config = AuditIntegrityConfig::new(b"test-signing-key-32-bytes-long!!");
        let record = SignedAuditRecord::sign(&config, "test audit event");

        assert!(record.verify(&config));
        assert_eq!(record.algorithm, SignatureAlgorithm::HmacSha256);
    }
}
```

---

### Day 4: Update AES-256-GCM (Field Encryption)

**File**: `/home/paul/code/barbican/src/encryption.rs`

```rust
use aws_lc_rs::aead;

/// Encrypt data using AES-256-GCM
///
/// FIPS 140-3 Compliant: Uses AWS-LC validated AES-GCM implementation
pub fn encrypt_aes_256_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| EncryptionError::InvalidKey)?;

    let sealing_key = aead::LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);

    let mut in_out = plaintext.to_vec();

    sealing_key
        .seal_in_place_append_tag(
            nonce,
            aead::Aad::from(associated_data),
            &mut in_out,
        )
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    Ok(in_out)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_aes_256_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| EncryptionError::InvalidKey)?;

    let opening_key = aead::LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);

    let mut in_out = ciphertext.to_vec();

    let plaintext = opening_key
        .open_in_place(
            nonce,
            aead::Aad::from(associated_data),
            &mut in_out,
        )
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_aes_gcm_round_trip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"sensitive data to encrypt";
        let aad = b"associated data";

        let ciphertext = encrypt_aes_256_gcm(&key, &nonce, plaintext, aad)
            .expect("encryption failed");

        let decrypted = decrypt_aes_256_gcm(&key, &nonce, &ciphertext, aad)
            .expect("decryption failed");

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
```

---

### Day 5: Integration Testing and Verification

#### Task 1: Full Test Suite

```bash
# Run all tests with FIPS feature enabled
cargo test --features fips

# Run compliance control tests
cargo test --features compliance-artifacts test_sc13_

# Verify FIPS mode is active
cargo run --example check_fips_mode
```

#### Task 2: Create FIPS Verification Example

**File**: `/home/paul/code/barbican/examples/check_fips_mode.rs`

```rust
use barbican::{init_fips_mode, is_fips_mode_enabled};

fn main() {
    println!("Barbican FIPS 140-3 Verification");
    println!("=================================\n");

    // Initialize FIPS mode
    init_fips_mode();

    // Check status
    if is_fips_mode_enabled() {
        println!("✓ FIPS 140-3 mode is ENABLED");
        println!("  Provider: AWS-LC");
        println!("  Certificate: #4816");
        println!("  Algorithms: HMAC-SHA256, AES-256-GCM");
        println!("\n✓ System is COMPLIANT with FedRAMP High SC-13\n");
    } else {
        println!("✗ FIPS mode is DISABLED");
        println!("  This build is NOT suitable for FedRAMP High\n");
        std::process::exit(1);
    }
}
```

#### Task 3: Update Documentation

**File**: `/home/paul/code/barbican/SECURITY.md`

Add section:

```markdown
## FIPS 140-3 Compliance (SC-13)

Barbican uses FIPS 140-3 validated cryptography via AWS-LC:

**Validation Certificate**: #4816
**Algorithms**:
- HMAC-SHA256 (audit log integrity)
- AES-256-GCM (field-level encryption)

### Enabling FIPS Mode

```rust
fn main() {
    barbican::init_fips_mode();
    // ... application code
}
```

### Build Configuration

```toml
[dependencies]
barbican = { version = "0.1", features = ["fips"] }
```
```

---

## Phase 1B: PIV Credential Support (IA-2(12))

### Priority: CRITICAL ⛔ - BLOCKS GOV DEPLOYMENTS
### Effort: 9 days
### Owner: Senior Security Engineer

---

### Day 1: Architecture Design

#### Design PIV Middleware

**New Module**: `/home/paul/code/barbican/src/piv.rs`

```rust
//! PIV/CAC Smart Card Authentication (IA-2(12))
//!
//! Implements support for Federal PIV (Personal Identity Verification) and
//! CAC (Common Access Card) credentials for government users.
//!
//! # NIST Standards
//!
//! - FIPS 201-3: Personal Identity Verification
//! - NIST SP 800-73-4: PIV Interfaces
//! - NIST SP 800-78-4: Cryptographic Algorithms
//!
//! # Features
//!
//! - X.509 client certificate extraction from mTLS
//! - PIV card authentication OID validation
//! - FASC-N (Federal Agency Smart Credential Number) parsing
//! - OCSP/CRL revocation checking
//! - Integration with OAuth IdP for user mapping

pub mod certificate;
pub mod fasca;
pub mod ocsp;
pub mod validation;

use std::collections::HashMap;

/// PIV authentication certificate OIDs
pub const PIV_CARD_AUTH_OID: &str = "2.16.840.1.101.3.6.8";
pub const PIV_AUTH_OID: &str = "2.16.840.1.101.3.6.7";

/// PIV certificate information extracted from mTLS connection
#[derive(Debug, Clone)]
pub struct PivCertificate {
    /// X.509 subject DN
    pub subject: String,

    /// Federal Agency Smart Credential Number
    pub fasc_n: Option<FascN>,

    /// Card UUID
    pub uuid: Option<String>,

    /// Certificate serial number
    pub serial: String,

    /// Issuer DN
    pub issuer: String,

    /// PIV certificate type
    pub cert_type: PivCertType,

    /// Raw DER-encoded certificate
    pub der: Vec<u8>,
}

/// PIV certificate type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivCertType {
    /// PIV authentication certificate
    Authentication,

    /// Card authentication certificate
    CardAuth,

    /// Digital signature certificate
    DigitalSignature,

    /// Key management certificate
    KeyManagement,
}

/// Federal Agency Smart Credential Number (FASC-N)
///
/// Structure defined in FIPS 201-3
#[derive(Debug, Clone)]
pub struct FascN {
    /// Agency code (4 digits)
    pub agency_code: String,

    /// System code (4 digits)
    pub system_code: String,

    /// Credential number (6 digits)
    pub credential_number: String,

    /// Credential series (1 digit)
    pub credential_series: String,

    /// Individual credential issue (1 digit)
    pub individual_credential_issue: String,

    /// Person identifier (10 digits)
    pub person_identifier: String,

    /// Organizational category (1 digit)
    pub organizational_category: String,

    /// Organizational identifier (4 digits)
    pub organizational_identifier: String,

    /// Person/Organization association category (1 digit)
    pub poa_category: String,
}

impl FascN {
    /// Parse FASC-N from BCD-encoded bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PivError> {
        // Implementation: BCD decoding per FIPS 201-3
        todo!("Parse FASC-N from BCD encoding")
    }

    /// Get full FASC-N string
    pub fn to_string(&self) -> String {
        format!(
            "{}{}{}{}{}{}{}{}{}",
            self.agency_code,
            self.system_code,
            self.credential_number,
            self.credential_series,
            self.individual_credential_issue,
            self.person_identifier,
            self.organizational_category,
            self.organizational_identifier,
            self.poa_category,
        )
    }
}

/// PIV validation error
#[derive(Debug, Clone)]
pub enum PivError {
    /// Certificate parsing failed
    InvalidCertificate(String),

    /// Not a PIV certificate
    NotPivCertificate,

    /// FASC-N parsing failed
    InvalidFascN(String),

    /// Certificate revoked
    Revoked(String),

    /// OCSP/CRL check failed
    RevocationCheckFailed(String),

    /// Certificate expired
    Expired,

    /// Untrusted issuer
    UntrustedIssuer(String),
}

impl std::fmt::Display for PivError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCertificate(msg) => write!(f, "Invalid certificate: {}", msg),
            Self::NotPivCertificate => write!(f, "Not a PIV certificate"),
            Self::InvalidFascN(msg) => write!(f, "Invalid FASC-N: {}", msg),
            Self::Revoked(msg) => write!(f, "Certificate revoked: {}", msg),
            Self::RevocationCheckFailed(msg) => write!(f, "Revocation check failed: {}", msg),
            Self::Expired => write!(f, "Certificate expired"),
            Self::UntrustedIssuer(msg) => write!(f, "Untrusted issuer: {}", msg),
        }
    }
}

impl std::error::Error for PivError {}
```

---

### Day 2-3: X.509 Certificate Extraction

**File**: `/home/paul/code/barbican/src/piv/certificate.rs`

```rust
use x509_parser::prelude::*;
use x509_parser::extensions::*;

/// Extract PIV certificate from mTLS connection
///
/// This extracts the client certificate from the TLS connection and
/// parses it into a PivCertificate structure.
pub fn extract_from_request(request: &axum::extract::Request) -> Result<PivCertificate, PivError> {
    // Extract client cert from TLS connection extensions
    let der = extract_client_cert_der(request)?;

    // Parse X.509 certificate
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|e| PivError::InvalidCertificate(e.to_string()))?;

    // Extract subject DN
    let subject = cert.subject().to_string();

    // Extract issuer DN
    let issuer = cert.issuer().to_string();

    // Extract serial number
    let serial = cert.serial.to_string();

    // Determine PIV certificate type
    let cert_type = determine_piv_type(&cert)?;

    // Extract FASC-N if present
    let fasc_n = extract_fasc_n(&cert)?;

    // Extract UUID if present
    let uuid = extract_uuid(&cert)?;

    Ok(PivCertificate {
        subject,
        fasc_n,
        uuid,
        serial,
        issuer,
        cert_type,
        der: der.to_vec(),
    })
}

/// Determine PIV certificate type from OIDs
fn determine_piv_type(cert: &X509Certificate) -> Result<PivCertType, PivError> {
    // Check certificate policy OIDs
    for ext in cert.extensions() {
        if let ParsedExtension::CertificatePolicies(policies) = ext.parsed_extension() {
            for policy in policies.iter() {
                let oid = policy.policy_id.to_string();
                match oid.as_str() {
                    crate::piv::PIV_AUTH_OID => return Ok(PivCertType::Authentication),
                    crate::piv::PIV_CARD_AUTH_OID => return Ok(PivCertType::CardAuth),
                    _ => {}
                }
            }
        }
    }

    Err(PivError::NotPivCertificate)
}

/// Extract FASC-N from PIV certificate
fn extract_fasc_n(cert: &X509Certificate) -> Result<Option<FascN>, PivError> {
    // FASC-N is in Subject Alternative Name extension
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                // FASC-N is in otherName with specific OID
                // Implementation: Parse BCD-encoded FASC-N
            }
        }
    }

    Ok(None)
}
```

---

### Day 4-5: OCSP/CRL Revocation Checking

**File**: `/home/paul/code/barbican/src/piv/ocsp.rs`

```rust
//! OCSP (Online Certificate Status Protocol) validation
//!
//! Checks certificate revocation status via OCSP responders.
//! Falls back to CRL (Certificate Revocation List) if OCSP unavailable.

use reqwest::Client;
use std::time::Duration;

/// OCSP validation configuration
pub struct OcspConfig {
    /// HTTP client for OCSP requests
    client: Client,

    /// Timeout for OCSP requests
    timeout: Duration,

    /// Whether to fall back to CRL if OCSP fails
    crl_fallback: bool,

    /// Cache for validation results
    cache: OcspCache,
}

/// Check certificate revocation status
pub async fn check_revocation(
    cert_der: &[u8],
    issuer_der: &[u8],
    config: &OcspConfig,
) -> Result<RevocationStatus, PivError> {
    // 1. Try OCSP first
    match check_ocsp(cert_der, issuer_der, config).await {
        Ok(status) => return Ok(status),
        Err(e) if config.crl_fallback => {
            tracing::warn!("OCSP check failed, falling back to CRL: {}", e);
        }
        Err(e) => return Err(e),
    }

    // 2. Fall back to CRL
    check_crl(cert_der, issuer_der, config).await
}

/// Revocation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Certificate is valid (not revoked)
    Valid,

    /// Certificate is revoked
    Revoked,

    /// Revocation status unknown
    Unknown,
}
```

---

### Day 6-7: IdP Integration and User Mapping

**File**: `/home/paul/code/barbican/src/piv/validation.rs`

```rust
//! PIV validation middleware
//!
//! Middleware to extract and validate PIV certificates from mTLS connections.

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

/// PIV validation middleware
pub async fn piv_validation_middleware(
    request: Request,
    next: Next,
    config: PivConfig,
) -> Response {
    // 1. Extract PIV certificate from mTLS connection
    let piv_cert = match certificate::extract_from_request(&request) {
        Ok(cert) => cert,
        Err(PivError::NotPivCertificate) => {
            // Not a PIV certificate - allow other auth methods
            return next.run(request).await;
        }
        Err(e) => {
            log_piv_error(&request, &e);
            return error_response(StatusCode::UNAUTHORIZED, "Invalid PIV certificate");
        }
    };

    // 2. Validate PIV certificate
    if let Err(e) = validate_piv_certificate(&piv_cert, &config).await {
        log_piv_validation_failure(&request, &piv_cert, &e);
        return error_response(StatusCode::FORBIDDEN, "PIV validation failed");
    }

    // 3. Check revocation status (OCSP/CRL)
    match ocsp::check_revocation(&piv_cert.der, &issuer_der, &config.ocsp).await {
        Ok(RevocationStatus::Valid) => {},
        Ok(RevocationStatus::Revoked) => {
            log_piv_revoked(&request, &piv_cert);
            return error_response(StatusCode::FORBIDDEN, "Certificate revoked");
        }
        Ok(RevocationStatus::Unknown) => {
            if config.require_revocation_check {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "Cannot verify revocation");
            }
        }
        Err(e) => {
            log_ocsp_error(&request, &e);
            if config.require_revocation_check {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "Revocation check failed");
            }
        }
    }

    // 4. Map PIV to user identity
    let user_id = map_piv_to_user(&piv_cert, &config).await?;

    // 5. Add PIV info to request extensions
    request.extensions_mut().insert(PivIdentity {
        user_id,
        fasc_n: piv_cert.fasc_n,
        subject: piv_cert.subject,
        cert_type: piv_cert.cert_type,
    });

    log_piv_success(&request, &piv_cert);
    next.run(request).await
}

/// Map PIV certificate to user identity
///
/// This integrates with your OAuth IdP (Keycloak, Entra) to map the
/// PIV certificate subject to a user account.
async fn map_piv_to_user(
    piv_cert: &PivCertificate,
    config: &PivConfig,
) -> Result<String, PivError> {
    // Implementation depends on IdP:
    //
    // Keycloak:
    //   - Use X.509 authenticator
    //   - Map cert subject DN to username
    //   - Or use FASC-N for mapping
    //
    // Entra ID:
    //   - Configure certificate-based authentication
    //   - Map cert SAN to UPN
    //
    // This is a library, so we provide hooks for custom mapping
    (config.piv_mapper)(piv_cert).await
}
```

---

### Day 8: Testing with PIV Test Cards

#### Setup Test Environment

**Acquire Test Cards**:
- Download GSA PIV test cards: https://piv.idmanagement.gov/fpki/tools/fpkitestcards/
- Import test certificates into test environment
- Configure test IdP with PIV mappings

**Test Cases**:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_piv_cert_extraction() {
        let test_cert_der = include_bytes!("../../tests/fixtures/piv-test-card.der");
        // Parse and validate
    }

    #[tokio::test]
    async fn test_fasc_n_parsing() {
        let test_fasc_n = b"\x.."; // BCD-encoded FASC-N
        let fasc_n = FascN::from_bytes(test_fasc_n).unwrap();
        assert_eq!(fasc_n.agency_code, "3200");
    }

    #[tokio::test]
    async fn test_ocsp_validation() {
        // Test OCSP request/response
    }

    #[tokio::test]
    async fn test_piv_authentication_flow() {
        // End-to-end: mTLS -> PIV validation -> user mapping
    }
}
```

---

### Day 9: Documentation and Integration Guide

**File**: `/home/paul/code/barbican/docs/PIV_INTEGRATION_GUIDE.md`

```markdown
# PIV/CAC Smart Card Integration Guide

## Overview

This guide explains how to configure Barbican for PIV (Personal Identity
Verification) and CAC (Common Access Card) authentication to meet FedRAMP
High IA-2(12) requirements.

## Architecture

```
[PIV Card] --mTLS--> [Barbican PIV Middleware] --OCSP--> [OCSP Responder]
                              |
                              v
                      [IdP User Mapping]
                              |
                              v
                        [OAuth Claims]
```

## Configuration

### Step 1: Enable mTLS

```rust
use barbican::piv::PivConfig;
use barbican::tls::TlsMode;

let tls_mode = TlsMode::Strict; // Requires client certificates

// Configure PIV validation
let piv_config = PivConfig::new()
    .with_trusted_cas(vec![piv_root_ca_der])
    .with_ocsp_enabled(true)
    .with_crl_fallback(true)
    .with_user_mapper(Box::new(my_piv_mapper));
```

### Step 2: Configure IdP for PIV

**Keycloak**:
```yaml
# realm-config.json
{
  "authenticationFlows": [
    {
      "alias": "X.509 PIV",
      "authenticators": [
        {
          "authenticator": "auth-x509-client-username-form",
          "requirement": "REQUIRED"
        }
      ]
    }
  ]
}
```

**Entra ID**:
- Enable certificate-based authentication
- Map certificate SAN to user UPN
- Configure trusted CA certificates

### Step 3: Test with PIV Cards

Download GSA test cards and verify:
- Certificate extraction works
- FASC-N parsing succeeds
- OCSP validation completes
- User mapping succeeds

## Troubleshooting

Common issues:
- OCSP responder unreachable -> Enable CRL fallback
- Certificate not trusted -> Add CA to trust store
- User mapping fails -> Check IdP configuration
```

---

## Phase 2A: mTLS Enforcement (IA-3, SC-8)

### Priority: HIGH
### Effort: 3 days
### Owner: Software Engineer

### Implementation Steps

**Day 1-2**: Create mTLS enforcement middleware
**Day 3**: Integration testing with Vault PKI certificates

---

## Phase 2B: Non-Repudiation Signatures (AU-10)

### Priority: HIGH
### Effort: 5 days
### Owner: Senior Security Engineer

### Implementation Steps

**Day 1-2**: Add digital signature support to AuditIntegrityConfig
**Day 3**: Implement RSA-PSS or ECDSA signing with Vault PKI
**Day 4**: Add timestamp authority support (RFC 3161)
**Day 5**: Testing and verification

---

## Testing Strategy

### Unit Tests

Each component must have comprehensive unit tests:
- FIPS crypto operations
- PIV certificate parsing
- FASC-N parsing
- OCSP/CRL checking
- Signature verification

### Integration Tests

End-to-end scenarios:
- FIPS mode initialization
- PIV authentication flow
- mTLS service-to-service
- Audit record signing

### Compliance Tests

Verify controls:
- SC-13: FIPS cryptography validated
- IA-2(12): PIV authentication works
- IA-3: Client device authenticated
- AU-10: Digital signatures generated

---

## Success Criteria

### Phase 1A (FIPS) Complete When:
- [ ] All crypto uses AWS-LC FIPS module
- [ ] FIPS mode enforced at startup
- [ ] All tests pass with FIPS enabled
- [ ] Documentation updated

### Phase 1B (PIV) Complete When:
- [ ] PIV certificates extracted from mTLS
- [ ] FASC-N parsed correctly
- [ ] OCSP/CRL checking works
- [ ] IdP integration documented
- [ ] Tests pass with GSA test cards

### Phase 2A (mTLS) Complete When:
- [ ] Client certificates required for High profile
- [ ] Service identity validated
- [ ] Integration with Vault PKI complete

### Phase 2B (AU-10) Complete When:
- [ ] Digital signatures option available
- [ ] Vault PKI integration for signing keys
- [ ] Signature verification works
- [ ] Optional timestamp authority supported

---

## Risk Mitigation

### FIPS Migration Risks
- **Risk**: Breaking changes in crypto APIs
- **Mitigation**: Comprehensive test coverage, gradual rollout

### PIV Testing Risks
- **Risk**: Lack of real PIV cards for testing
- **Mitigation**: Use GSA test cards, simulation

### Timeline Risks
- **Risk**: Complexity underestimated
- **Mitigation**: Daily standup, early escalation

---

## Deliverables Checklist

- [ ] FIPS cryptography implemented (SC-13)
- [ ] PIV support implemented (IA-2(12))
- [ ] mTLS enforcement implemented (IA-3, SC-8)
- [ ] Digital signatures implemented (AU-10)
- [ ] All tests passing
- [ ] Documentation complete
- [ ] Deployment guide updated
- [ ] FedRAMP High compliance report updated

---

**Next Steps**: Begin Phase 1A (FIPS Migration) immediately
**Owner**: Assign to Senior Security Engineer
**Timeline**: 3 weeks to completion
**Budget**: $31,500 (22 person-days @ $1,500/day)
