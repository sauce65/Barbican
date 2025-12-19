//! Audit Log Integrity Protection (AU-9)
//!
//! Provides cryptographic protection for audit logs to prevent unauthorized
//! modification and enable tamper detection.
//!
//! # NIST 800-53 Controls
//!
//! - **AU-9**: Protection of Audit Information - HMAC signing and chain integrity
//! - **AU-9(3)**: Cryptographic Protection - HMAC-SHA256 signatures
//!
//! # Features
//!
//! - **HMAC-SHA256 Signing**: Each audit record is signed with a secret key
//! - **Chain Integrity**: Records include hash of previous record for tamper detection
//! - **Verification**: Validate individual records or entire audit chains
//! - **Compliance Integration**: Works with FedRAMP profile system
//!
//! # Example
//!
//! ```
//! use barbican::audit::integrity::{SignedAuditRecord, AuditChain, AuditIntegrityConfig};
//!
//! // Create configuration with signing key
//! let config = AuditIntegrityConfig::new(b"your-32-byte-secret-key-here!!");
//!
//! // Create an audit chain
//! let mut chain = AuditChain::new(config);
//!
//! // Append signed records
//! let record = chain.append(
//!     "auth.login",
//!     "user@example.com",
//!     "/api/login",
//!     "POST",
//!     "success",
//!     "192.168.1.1",
//!     None,
//! );
//!
//! // Verify chain integrity
//! assert!(chain.verify_integrity().is_ok());
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for audit log integrity protection
#[derive(Clone)]
pub struct AuditIntegrityConfig {
    /// HMAC signing key (should be at least 32 bytes)
    signing_key: Vec<u8>,
    /// Whether to include previous record hash in chain
    chain_records: bool,
    /// Algorithm identifier for the signature
    algorithm: SignatureAlgorithm,
}

impl std::fmt::Debug for AuditIntegrityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditIntegrityConfig")
            .field("signing_key", &"[REDACTED]")
            .field("chain_records", &self.chain_records)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// Signature algorithm for audit records
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// HMAC-SHA256 (NIST approved, FedRAMP compliant)
    HmacSha256,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::HmacSha256
    }
}

impl SignatureAlgorithm {
    /// Get the algorithm identifier string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HmacSha256 => "HMAC-SHA256",
        }
    }
}

impl AuditIntegrityConfig {
    /// Create a new configuration with the given signing key
    ///
    /// # Arguments
    ///
    /// * `signing_key` - Secret key for HMAC signing (recommended: 32+ bytes)
    ///
    /// # Security
    ///
    /// The signing key should be:
    /// - At least 32 bytes for HMAC-SHA256
    /// - Stored securely (e.g., in a secrets manager)
    /// - Rotated periodically per SC-12
    pub fn new(signing_key: &[u8]) -> Self {
        Self {
            signing_key: signing_key.to_vec(),
            chain_records: true,
            algorithm: SignatureAlgorithm::HmacSha256,
        }
    }

    /// Create configuration from compliance profile
    ///
    /// Applies profile-appropriate settings for audit protection.
    pub fn from_compliance(
        signing_key: &[u8],
        config: &crate::compliance::ComplianceConfig,
    ) -> Self {
        use crate::compliance::ComplianceProfile;

        // All FedRAMP profiles require chained records for integrity
        let chain_records = config.profile.is_fedramp()
            || matches!(config.profile, ComplianceProfile::Soc2);

        Self {
            signing_key: signing_key.to_vec(),
            chain_records,
            algorithm: SignatureAlgorithm::HmacSha256,
        }
    }

    /// Disable record chaining (not recommended for production)
    pub fn without_chaining(mut self) -> Self {
        self.chain_records = false;
        self
    }

    /// Check if the signing key meets minimum requirements
    pub fn validate_key(&self) -> Result<(), AuditIntegrityError> {
        if self.signing_key.len() < 32 {
            return Err(AuditIntegrityError::KeyTooShort {
                actual: self.signing_key.len(),
                minimum: 32,
            });
        }
        Ok(())
    }
}

/// A signed audit record with integrity protection
#[derive(Debug, Clone)]
pub struct SignedAuditRecord {
    /// Unique identifier for this record
    pub id: String,
    /// Sequence number in the audit chain
    pub sequence: u64,
    /// Timestamp (Unix epoch milliseconds)
    pub timestamp: u64,
    /// Event type/category
    pub event_type: String,
    /// Actor (user ID, system, etc.)
    pub actor: String,
    /// Resource accessed
    pub resource: String,
    /// Action performed
    pub action: String,
    /// Outcome of the action
    pub outcome: String,
    /// Source IP address
    pub source_ip: String,
    /// Additional context/details
    pub details: Option<String>,
    /// Hash of the previous record in the chain (None for first record)
    pub previous_hash: Option<String>,
    /// HMAC signature of this record
    pub signature: String,
    /// Algorithm used for signature
    pub algorithm: String,
}

impl SignedAuditRecord {
    /// Get the canonical representation of this record for signing
    ///
    /// The canonical form includes all fields except the signature itself,
    /// concatenated in a deterministic order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Include all fields in deterministic order
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(&self.sequence.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(self.event_type.as_bytes());
        data.extend_from_slice(self.actor.as_bytes());
        data.extend_from_slice(self.resource.as_bytes());
        data.extend_from_slice(self.action.as_bytes());
        data.extend_from_slice(self.outcome.as_bytes());
        data.extend_from_slice(self.source_ip.as_bytes());

        if let Some(ref details) = self.details {
            data.extend_from_slice(details.as_bytes());
        }

        if let Some(ref prev) = self.previous_hash {
            data.extend_from_slice(prev.as_bytes());
        }

        data
    }

    /// Compute the hash of this record (used for chaining)
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_bytes());
        hasher.update(self.signature.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify the signature of this record
    pub fn verify(&self, key: &[u8]) -> Result<bool, AuditIntegrityError> {
        let expected_signature = compute_hmac_sha256(key, &self.canonical_bytes());
        Ok(constant_time_eq(&self.signature, &expected_signature))
    }

    /// Convert to JSON for storage/transmission
    pub fn to_json(&self) -> Result<String, AuditIntegrityError> {
        serde_json::to_string(self).map_err(|e| AuditIntegrityError::Serialization(e.to_string()))
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self, AuditIntegrityError> {
        serde_json::from_str(json).map_err(|e| AuditIntegrityError::Serialization(e.to_string()))
    }
}

// Implement Serialize/Deserialize for SignedAuditRecord
impl serde::Serialize for SignedAuditRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SignedAuditRecord", 12)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("sequence", &self.sequence)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("event_type", &self.event_type)?;
        state.serialize_field("actor", &self.actor)?;
        state.serialize_field("resource", &self.resource)?;
        state.serialize_field("action", &self.action)?;
        state.serialize_field("outcome", &self.outcome)?;
        state.serialize_field("source_ip", &self.source_ip)?;
        state.serialize_field("details", &self.details)?;
        state.serialize_field("previous_hash", &self.previous_hash)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("algorithm", &self.algorithm)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for SignedAuditRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Helper {
            id: String,
            sequence: u64,
            timestamp: u64,
            event_type: String,
            actor: String,
            resource: String,
            action: String,
            outcome: String,
            source_ip: String,
            details: Option<String>,
            previous_hash: Option<String>,
            signature: String,
            algorithm: String,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(SignedAuditRecord {
            id: helper.id,
            sequence: helper.sequence,
            timestamp: helper.timestamp,
            event_type: helper.event_type,
            actor: helper.actor,
            resource: helper.resource,
            action: helper.action,
            outcome: helper.outcome,
            source_ip: helper.source_ip,
            details: helper.details,
            previous_hash: helper.previous_hash,
            signature: helper.signature,
            algorithm: helper.algorithm,
        })
    }
}

/// An append-only chain of signed audit records
#[derive(Debug)]
pub struct AuditChain {
    config: AuditIntegrityConfig,
    /// Records in the chain (pub(crate) for compliance testing)
    pub(crate) records: Vec<SignedAuditRecord>,
    last_hash: Option<String>,
    next_sequence: u64,
}

impl AuditChain {
    /// Create a new audit chain with the given configuration
    pub fn new(config: AuditIntegrityConfig) -> Self {
        Self {
            config,
            records: Vec::new(),
            last_hash: None,
            next_sequence: 1,
        }
    }

    /// Create an audit chain configured for a compliance profile
    pub fn from_compliance(
        signing_key: &[u8],
        config: &crate::compliance::ComplianceConfig,
    ) -> Self {
        Self::new(AuditIntegrityConfig::from_compliance(signing_key, config))
    }

    /// Append a new signed record to the chain
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        event_type: &str,
        actor: &str,
        resource: &str,
        action: &str,
        outcome: &str,
        source_ip: &str,
        details: Option<String>,
    ) -> SignedAuditRecord {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let id = format!("audit-{}-{:x}", self.next_sequence, timestamp);

        let previous_hash = if self.config.chain_records {
            self.last_hash.clone()
        } else {
            None
        };

        // Create unsigned record
        let mut record = SignedAuditRecord {
            id,
            sequence: self.next_sequence,
            timestamp,
            event_type: event_type.to_string(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            outcome: outcome.to_string(),
            source_ip: source_ip.to_string(),
            details,
            previous_hash,
            signature: String::new(),
            algorithm: self.config.algorithm.as_str().to_string(),
        };

        // Sign the record
        record.signature = compute_hmac_sha256(&self.config.signing_key, &record.canonical_bytes());

        // Update chain state
        self.last_hash = Some(record.compute_hash());
        self.next_sequence += 1;
        self.records.push(record.clone());

        record
    }

    /// Verify the integrity of the entire chain
    ///
    /// Checks:
    /// 1. Each record's signature is valid
    /// 2. Each record's previous_hash matches the hash of the previous record
    /// 3. Sequence numbers are contiguous
    pub fn verify_integrity(&self) -> Result<ChainVerificationResult, AuditIntegrityError> {
        let mut result = ChainVerificationResult {
            records_verified: 0,
            chain_intact: true,
            first_invalid_sequence: None,
            errors: Vec::new(),
        };

        let mut expected_prev_hash: Option<String> = None;

        for (index, record) in self.records.iter().enumerate() {
            // Verify sequence number
            let expected_sequence = (index + 1) as u64;
            if record.sequence != expected_sequence {
                result.chain_intact = false;
                result.first_invalid_sequence = Some(record.sequence);
                result.errors.push(format!(
                    "Sequence gap: expected {}, got {}",
                    expected_sequence, record.sequence
                ));
            }

            // Verify signature
            match record.verify(&self.config.signing_key) {
                Ok(true) => {}
                Ok(false) => {
                    result.chain_intact = false;
                    if result.first_invalid_sequence.is_none() {
                        result.first_invalid_sequence = Some(record.sequence);
                    }
                    result
                        .errors
                        .push(format!("Invalid signature for record {}", record.sequence));
                }
                Err(e) => {
                    result.chain_intact = false;
                    result.errors.push(format!(
                        "Verification error for record {}: {}",
                        record.sequence, e
                    ));
                }
            }

            // Verify chain link
            if self.config.chain_records {
                if record.previous_hash != expected_prev_hash {
                    result.chain_intact = false;
                    if result.first_invalid_sequence.is_none() {
                        result.first_invalid_sequence = Some(record.sequence);
                    }
                    result.errors.push(format!(
                        "Chain broken at record {}: hash mismatch",
                        record.sequence
                    ));
                }
                expected_prev_hash = Some(record.compute_hash());
            }

            result.records_verified += 1;
        }

        Ok(result)
    }

    /// Get all records in the chain
    pub fn records(&self) -> &[SignedAuditRecord] {
        &self.records
    }

    /// Get the number of records in the chain
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get the last record in the chain
    pub fn last(&self) -> Option<&SignedAuditRecord> {
        self.records.last()
    }

    /// Export the chain to JSON
    pub fn to_json(&self) -> Result<String, AuditIntegrityError> {
        let json_records: Vec<_> = self
            .records
            .iter()
            .map(|r| r.to_json())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(format!("[{}]", json_records.join(",")))
    }
}

/// Result of chain verification
#[derive(Debug)]
pub struct ChainVerificationResult {
    /// Number of records verified
    pub records_verified: usize,
    /// Whether the entire chain is intact
    pub chain_intact: bool,
    /// First sequence number where integrity was violated (if any)
    pub first_invalid_sequence: Option<u64>,
    /// Detailed error messages
    pub errors: Vec<String>,
}

impl ChainVerificationResult {
    /// Check if verification passed
    pub fn is_valid(&self) -> bool {
        self.chain_intact && self.errors.is_empty()
    }
}

/// Errors related to audit integrity
#[derive(Debug)]
pub enum AuditIntegrityError {
    /// Signing key is too short
    KeyTooShort { actual: usize, minimum: usize },
    /// Signature verification failed
    InvalidSignature,
    /// Chain integrity violated
    ChainBroken { sequence: u64, reason: String },
    /// Serialization error
    Serialization(String),
    /// Record not found
    RecordNotFound(u64),
}

impl std::fmt::Display for AuditIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyTooShort { actual, minimum } => {
                write!(
                    f,
                    "Signing key too short: {} bytes (minimum: {})",
                    actual, minimum
                )
            }
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::ChainBroken { sequence, reason } => {
                write!(f, "Chain broken at sequence {}: {}", sequence, reason)
            }
            Self::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            Self::RecordNotFound(seq) => write!(f, "Record not found: sequence {}", seq),
        }
    }
}

impl std::error::Error for AuditIntegrityError {}

/// Compute HMAC-SHA256 signature
fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Trait for write-only audit log destinations (AU-9 compliance)
///
/// Implementations should ensure:
/// - Records can only be appended, never modified or deleted
/// - Write access is separate from read access
/// - Failed writes are reported for AU-5 compliance
pub trait AuditLogDestination: Send + Sync {
    /// Append a signed record to the destination
    fn append(&self, record: &SignedAuditRecord) -> Result<(), AuditIntegrityError>;

    /// Flush any buffered records
    fn flush(&self) -> Result<(), AuditIntegrityError>;

    /// Get destination identifier for logging
    fn destination_id(&self) -> &str;
}

/// Verify a single record's signature without needing the full chain
pub fn verify_record(record: &SignedAuditRecord, key: &[u8]) -> Result<bool, AuditIntegrityError> {
    record.verify(key)
}

/// Verify the integrity of audit records from JSON
pub fn verify_records_from_json(
    json: &str,
    key: &[u8],
    expect_chained: bool,
) -> Result<ChainVerificationResult, AuditIntegrityError> {
    let records: Vec<SignedAuditRecord> =
        serde_json::from_str(json).map_err(|e| AuditIntegrityError::Serialization(e.to_string()))?;

    let config = AuditIntegrityConfig::new(key);
    let mut chain = AuditChain {
        config: if expect_chained {
            config
        } else {
            config.without_chaining()
        },
        records,
        last_hash: None,
        next_sequence: 1,
    };

    // Reconstruct chain state
    if let Some(last) = chain.records.last() {
        chain.last_hash = Some(last.compute_hash());
        chain.next_sequence = last.sequence + 1;
    }

    chain.verify_integrity()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        b"test-signing-key-for-audit-logs!".to_vec()
    }

    #[test]
    fn test_config_creation() {
        let config = AuditIntegrityConfig::new(&test_key());
        assert!(config.chain_records);
        assert_eq!(config.algorithm, SignatureAlgorithm::HmacSha256);
    }

    #[test]
    fn test_key_validation() {
        let short_key = b"short";
        let config = AuditIntegrityConfig::new(short_key);
        assert!(config.validate_key().is_err());

        let good_key = test_key();
        let config = AuditIntegrityConfig::new(&good_key);
        assert!(config.validate_key().is_ok());
    }

    #[test]
    fn test_signed_record_creation() {
        let config = AuditIntegrityConfig::new(&test_key());
        let mut chain = AuditChain::new(config);

        let record = chain.append(
            "auth.login",
            "user@example.com",
            "/api/login",
            "POST",
            "success",
            "192.168.1.1",
            None,
        );

        assert_eq!(record.sequence, 1);
        assert_eq!(record.event_type, "auth.login");
        assert!(!record.signature.is_empty());
        assert!(record.previous_hash.is_none()); // First record has no previous
    }

    #[test]
    fn test_record_signature_verification() {
        let config = AuditIntegrityConfig::new(&test_key());
        let mut chain = AuditChain::new(config);

        let record = chain.append(
            "auth.login",
            "user@example.com",
            "/api/login",
            "POST",
            "success",
            "192.168.1.1",
            None,
        );

        // Should verify with correct key
        assert!(record.verify(&test_key()).unwrap());

        // Should fail with wrong key
        let wrong_key = b"wrong-key-that-is-also-32-bytes!";
        assert!(!record.verify(wrong_key).unwrap());
    }

    #[test]
    fn test_chain_integrity() {
        let config = AuditIntegrityConfig::new(&test_key());
        let mut chain = AuditChain::new(config);

        // Add multiple records
        for i in 0..5 {
            chain.append(
                "test.event",
                &format!("user{}", i),
                "/api/test",
                "GET",
                "success",
                "127.0.0.1",
                Some(format!("Test record {}", i)),
            );
        }

        assert_eq!(chain.len(), 5);

        // Verify chain
        let result = chain.verify_integrity().unwrap();
        assert!(result.is_valid());
        assert_eq!(result.records_verified, 5);
    }

    #[test]
    fn test_chain_links() {
        let config = AuditIntegrityConfig::new(&test_key());
        let mut chain = AuditChain::new(config);

        let record1 = chain.append(
            "event1",
            "user",
            "/test",
            "GET",
            "success",
            "127.0.0.1",
            None,
        );
        let record2 = chain.append(
            "event2",
            "user",
            "/test",
            "GET",
            "success",
            "127.0.0.1",
            None,
        );

        // Second record should reference first record's hash
        assert!(record2.previous_hash.is_some());
        assert_eq!(record2.previous_hash.unwrap(), record1.compute_hash());
    }

    #[test]
    fn test_tamper_detection() {
        let config = AuditIntegrityConfig::new(&test_key());
        let mut chain = AuditChain::new(config);

        chain.append(
            "auth.login",
            "user@example.com",
            "/api/login",
            "POST",
            "success",
            "192.168.1.1",
            None,
        );

        // Tamper with the record
        chain.records[0].actor = "attacker@evil.com".to_string();

        // Verification should fail
        let result = chain.verify_integrity().unwrap();
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_json_roundtrip() {
        let config = AuditIntegrityConfig::new(&test_key());
        let mut chain = AuditChain::new(config);

        chain.append(
            "test.event",
            "user",
            "/test",
            "GET",
            "success",
            "127.0.0.1",
            Some("Test details".to_string()),
        );

        let json = chain.to_json().unwrap();
        let result = verify_records_from_json(&json, &test_key(), true).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_algorithm_properties() {
        let algo = SignatureAlgorithm::HmacSha256;
        assert_eq!(algo.as_str(), "HMAC-SHA256");
    }

    #[test]
    fn test_config_debug_redacts_key() {
        let config = AuditIntegrityConfig::new(&test_key());
        let debug_output = format!("{:?}", config);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("test-signing-key"));
    }

    #[test]
    fn test_without_chaining() {
        let config = AuditIntegrityConfig::new(&test_key()).without_chaining();
        let mut chain = AuditChain::new(config);

        let record1 = chain.append(
            "event1",
            "user",
            "/test",
            "GET",
            "success",
            "127.0.0.1",
            None,
        );
        let record2 = chain.append(
            "event2",
            "user",
            "/test",
            "GET",
            "success",
            "127.0.0.1",
            None,
        );

        // Without chaining, previous_hash should be None
        assert!(record1.previous_hash.is_none());
        assert!(record2.previous_hash.is_none());
    }

    #[test]
    fn test_error_display() {
        let err = AuditIntegrityError::KeyTooShort {
            actual: 16,
            minimum: 32,
        };
        assert!(err.to_string().contains("16"));
        assert!(err.to_string().contains("32"));

        let err = AuditIntegrityError::InvalidSignature;
        assert!(err.to_string().contains("Invalid signature"));
    }

    #[test]
    fn test_chain_verification_result() {
        let result = ChainVerificationResult {
            records_verified: 5,
            chain_intact: true,
            first_invalid_sequence: None,
            errors: Vec::new(),
        };
        assert!(result.is_valid());

        let result = ChainVerificationResult {
            records_verified: 5,
            chain_intact: false,
            first_invalid_sequence: Some(3),
            errors: vec!["Test error".to_string()],
        };
        assert!(!result.is_valid());
    }
}
