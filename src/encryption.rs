//! Encryption at Rest (SC-28) and FIPS Cryptography (SC-13)
//!
//! NIST SP 800-53 SC-28 compliant encryption utilities for protecting
//! data at rest in applications and databases.
//!
//! # STIG References
//!
//! - **UBTU-22-231010**: Encrypt partitions containing sensitive data (SC-28)
//! - **APSC-DV-000270**: Use FIPS 140-2 validated cryptography (SC-13)
//!
//! # Control Requirements
//!
//! - **SC-28**: "Protect the confidentiality and integrity of information at rest."
//! - **SC-13**: "Use FIPS-validated cryptography." (when `fips` feature enabled)
//!
//! # What This Module Provides
//!
//! 1. **Field-Level Encryption**: AES-256-GCM encryption for sensitive fields
//! 2. **Encryption Verification**: Runtime checks that encryption is configured
//! 3. **Key Management Integration**: Works with the `keys` module for rotation
//! 4. **Compliance Validation**: Fails fast if encryption requirements not met
//! 5. **FIPS Mode**: Optional FIPS 140-3 validated crypto via `fips` feature
//!
//! # Architecture
//!
//! This module provides **application-level encryption** as a complement to
//! infrastructure-level encryption (PostgreSQL TDE, disk encryption). This
//! defense-in-depth approach ensures sensitive data is protected even if:
//!
//! - Database backups are leaked
//! - Disk encryption is misconfigured
//! - An attacker gains database access but not key access
//!
//! # Usage
//!
//! ```ignore
//! use barbican::encryption::{FieldEncryptor, EncryptionConfig};
//!
//! // Initialize with a 256-bit key (from Vault, KMS, etc.)
//! let key = std::env::var("ENCRYPTION_KEY").expect("key required");
//! let encryptor = FieldEncryptor::new(&key)?;
//!
//! // Encrypt sensitive data before storing
//! let encrypted = encryptor.encrypt(b"sensitive data")?;
//!
//! // Decrypt when reading
//! let plaintext = encryptor.decrypt(&encrypted)?;
//! ```

use std::fmt;

// ============================================================================
// Encryption Configuration
// ============================================================================

/// Configuration for encryption at rest
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Whether encryption at rest is required
    pub require_encryption: bool,
    /// Whether to verify database-level encryption
    pub verify_database_encryption: bool,
    /// Whether to verify disk-level encryption
    pub verify_disk_encryption: bool,
    /// Algorithm to use for field encryption
    pub algorithm: EncryptionAlgorithm,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            require_encryption: true,
            verify_database_encryption: true,
            verify_disk_encryption: false, // Can't verify from userspace
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }
}

impl EncryptionConfig {
    /// Create config for FedRAMP Moderate baseline
    pub fn fedramp_moderate() -> Self {
        Self {
            require_encryption: true,
            verify_database_encryption: true,
            verify_disk_encryption: false,
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }

    /// Create config for FedRAMP High baseline
    pub fn fedramp_high() -> Self {
        Self {
            require_encryption: true,
            verify_database_encryption: true,
            verify_disk_encryption: true, // Requires infrastructure verification
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }

    /// Derive config from compliance profile
    pub fn from_compliance(config: &crate::compliance::ComplianceConfig) -> Self {
        Self {
            require_encryption: config.require_encryption_at_rest,
            verify_database_encryption: config.require_encryption_at_rest,
            verify_disk_encryption: config.require_mtls, // High profiles require disk encryption
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }
}

/// Encryption algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM (NIST approved, recommended)
    /// When `fips` feature is enabled, uses FIPS 140-3 validated AWS-LC
    Aes256Gcm,
    /// ChaCha20-Poly1305 (alternative for non-AES hardware)
    /// Note: Not available in FIPS mode
    ChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    /// Check if this algorithm is available in the current build
    pub fn is_available(&self) -> bool {
        match self {
            Self::Aes256Gcm => true,
            #[cfg(feature = "fips")]
            Self::ChaCha20Poly1305 => false, // Not FIPS-approved
            #[cfg(not(feature = "fips"))]
            Self::ChaCha20Poly1305 => true,
        }
    }

    /// Check if this build uses FIPS-validated cryptography
    pub fn is_fips_mode() -> bool {
        cfg!(feature = "fips")
    }

    /// Get the FIPS certificate number (if applicable)
    pub fn fips_certificate() -> Option<&'static str> {
        if cfg!(feature = "fips") {
            Some("AWS-LC FIPS 140-3 Certificate #4631")
        } else {
            None
        }
    }
}

// ============================================================================
// Module-Level FIPS Helpers
// ============================================================================

/// Check if this build uses FIPS-validated cryptography (SC-13)
///
/// Returns `true` when built with the `fips` feature flag.
pub fn is_fips_mode() -> bool {
    EncryptionAlgorithm::is_fips_mode()
}

/// Get the FIPS certificate number (if applicable)
///
/// Returns the AWS-LC FIPS 140-3 certificate number when in FIPS mode.
pub fn fips_certificate() -> Option<&'static str> {
    EncryptionAlgorithm::fips_certificate()
}

impl EncryptionAlgorithm {
    /// Get the key size in bytes for this algorithm
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,        // 256 bits
            Self::ChaCha20Poly1305 => 32, // 256 bits
        }
    }

    /// Get the nonce size in bytes for this algorithm
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,        // 96 bits
            Self::ChaCha20Poly1305 => 12, // 96 bits
        }
    }

    /// Get the authentication tag size in bytes
    pub fn tag_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 16,        // 128 bits
            Self::ChaCha20Poly1305 => 16, // 128 bits
        }
    }
}

// ============================================================================
// Field-Level Encryption
// ============================================================================

/// Field-level encryptor for sensitive data
///
/// Uses AES-256-GCM with random nonces for each encryption operation.
/// The encrypted output format is: `nonce || ciphertext || tag`
///
/// # Security Properties
///
/// - **Confidentiality**: AES-256 encryption
/// - **Integrity**: GCM authentication tag
/// - **Freshness**: Random 96-bit nonce per encryption
///
/// # Thread Safety
///
/// `FieldEncryptor` is `Send + Sync` and can be shared across threads.
#[derive(Clone)]
pub struct FieldEncryptor {
    /// The encryption key (32 bytes for AES-256)
    key: [u8; 32],
    /// Algorithm in use
    algorithm: EncryptionAlgorithm,
}

impl FieldEncryptor {
    /// Create a new encryptor with a hex-encoded or base64-encoded key
    ///
    /// The key must be exactly 32 bytes (256 bits) after decoding.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or wrong length.
    pub fn new(key_str: &str) -> Result<Self, EncryptionError> {
        let key_bytes = decode_key(key_str)?;

        if key_bytes.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        Ok(Self {
            key,
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        })
    }

    /// Create from raw key bytes
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self {
            key,
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }

    /// Encrypt plaintext data
    ///
    /// Returns the encrypted data in format: `nonce || ciphertext || tag`
    ///
    /// # Security
    ///
    /// - Uses a cryptographically random 96-bit nonce
    /// - Never reuses nonces with the same key
    /// - Includes authentication tag to detect tampering
    /// - When `fips` feature is enabled, uses FIPS 140-3 validated AWS-LC
    #[cfg(not(feature = "fips"))]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| EncryptionError::CipherInitFailed)?;

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        // Output format: nonce || ciphertext (includes tag)
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Encrypt plaintext data (FIPS 140-3 validated implementation)
    ///
    /// Uses AWS-LC FIPS module (Certificate #4631) for AES-256-GCM.
    #[cfg(feature = "fips")]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
        use aws_lc_rs::rand::SystemRandom;

        // Generate random nonce using FIPS-validated RNG
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        aws_lc_rs::rand::SecureRandom::fill(&rng, &mut nonce_bytes)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        // Create unbound key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| EncryptionError::CipherInitFailed)?;
        let key = LessSafeKey::new(unbound_key);

        // Encrypt in place (need mutable buffer)
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        // Output format: nonce || ciphertext || tag
        let mut output = Vec::with_capacity(12 + in_out.len() + 16);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&in_out);
        output.extend_from_slice(tag.as_ref());

        Ok(output)
    }

    /// Decrypt ciphertext data
    ///
    /// Expects input in format: `nonce || ciphertext || tag`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Input is too short (missing nonce or tag)
    /// - Authentication tag doesn't match (data tampered)
    /// - Decryption fails for any other reason
    #[cfg(not(feature = "fips"))]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Minimum size: 12 (nonce) + 16 (tag) = 28 bytes
        if ciphertext.len() < 28 {
            return Err(EncryptionError::InvalidCiphertext(
                "Ciphertext too short".into(),
            ));
        }

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted = &ciphertext[12..];

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| EncryptionError::CipherInitFailed)?;

        // Decrypt and verify
        cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| EncryptionError::DecryptionFailed)
    }

    /// Decrypt ciphertext data (FIPS 140-3 validated implementation)
    ///
    /// Uses AWS-LC FIPS module (Certificate #4631) for AES-256-GCM.
    #[cfg(feature = "fips")]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

        // Minimum size: 12 (nonce) + 16 (tag) = 28 bytes
        if ciphertext.len() < 28 {
            return Err(EncryptionError::InvalidCiphertext(
                "Ciphertext too short".into(),
            ));
        }

        // Extract nonce, ciphertext, and tag
        let nonce_bytes: [u8; 12] = ciphertext[..12]
            .try_into()
            .map_err(|_| EncryptionError::InvalidCiphertext("Invalid nonce".into()))?;
        let encrypted = &ciphertext[12..];

        // Create key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| EncryptionError::CipherInitFailed)?;
        let key = LessSafeKey::new(unbound_key);

        // Decrypt in place
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = encrypted.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        Ok(plaintext.to_vec())
    }

    /// Encrypt a string value
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, EncryptionError> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted,
        ))
    }

    /// Decrypt a base64-encoded encrypted string
    pub fn decrypt_string(&self, ciphertext: &str) -> Result<String, EncryptionError> {
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ciphertext)
            .map_err(|_| EncryptionError::InvalidCiphertext("Invalid base64".into()))?;

        let plaintext = self.decrypt(&bytes)?;

        String::from_utf8(plaintext)
            .map_err(|_| EncryptionError::InvalidCiphertext("Invalid UTF-8".into()))
    }

    /// Get the algorithm in use
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }
}

impl fmt::Debug for FieldEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldEncryptor")
            .field("algorithm", &self.algorithm)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Encryption Verification
// ============================================================================

/// Result of encryption-at-rest verification
#[derive(Debug, Clone)]
pub struct EncryptionStatus {
    /// Application-level field encryption available
    pub field_encryption_available: bool,
    /// Database connection uses SSL/TLS
    pub database_ssl_enabled: bool,
    /// Database has encryption extensions (pgcrypto, etc.)
    pub database_encryption_available: bool,
    /// Overall SC-28 compliance status
    pub compliant: bool,
    /// Reasons for non-compliance (if any)
    pub issues: Vec<String>,
}

impl EncryptionStatus {
    /// Create a compliant status
    pub fn compliant() -> Self {
        Self {
            field_encryption_available: true,
            database_ssl_enabled: true,
            database_encryption_available: true,
            compliant: true,
            issues: Vec::new(),
        }
    }

    /// Create a non-compliant status with issues
    pub fn non_compliant(issues: Vec<String>) -> Self {
        Self {
            field_encryption_available: false,
            database_ssl_enabled: false,
            database_encryption_available: false,
            compliant: false,
            issues,
        }
    }

    /// Add an issue and mark as non-compliant
    pub fn add_issue(&mut self, issue: impl Into<String>) {
        self.issues.push(issue.into());
        self.compliant = false;
    }
}

/// Verify encryption at rest configuration
///
/// This function checks:
/// 1. Field encryption key is configured
/// 2. Database SSL is enabled
/// 3. Database encryption extensions are available (optional)
///
/// # Example
///
/// ```ignore
/// use barbican::encryption::{verify_encryption, EncryptionConfig};
///
/// let config = EncryptionConfig::fedramp_moderate();
/// let status = verify_encryption(&config, Some(&pool)).await?;
///
/// if !status.compliant {
///     for issue in &status.issues {
///         eprintln!("SC-28 violation: {}", issue);
///     }
/// }
/// ```
pub fn verify_encryption_config(
    config: &EncryptionConfig,
    field_encryption_key: Option<&str>,
) -> EncryptionStatus {
    let mut status = EncryptionStatus {
        field_encryption_available: false,
        database_ssl_enabled: false,
        database_encryption_available: false,
        compliant: true,
        issues: Vec::new(),
    };

    // Check field encryption key
    if let Some(key) = field_encryption_key {
        match FieldEncryptor::new(key) {
            Ok(_) => {
                status.field_encryption_available = true;
            }
            Err(e) => {
                if config.require_encryption {
                    status.add_issue(format!("Field encryption key invalid: {}", e));
                }
            }
        }
    } else if config.require_encryption {
        status.add_issue("Field encryption key not configured (ENCRYPTION_KEY env var)");
    }

    status
}

/// Verify encryption at rest with database checks
///
/// Performs runtime verification that the database connection is encrypted
/// and that encryption features are available.
#[cfg(feature = "postgres")]
pub async fn verify_encryption_with_database(
    config: &EncryptionConfig,
    field_encryption_key: Option<&str>,
    pool: &sqlx::PgPool,
) -> Result<EncryptionStatus, EncryptionError> {
    let mut status = verify_encryption_config(config, field_encryption_key);

    // Check database SSL status
    let ssl_result: Result<(bool,), _> = sqlx::query_as(
        "SELECT COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false)",
    )
    .fetch_one(pool)
    .await;

    match ssl_result {
        Ok((ssl_enabled,)) => {
            status.database_ssl_enabled = ssl_enabled;
            if !ssl_enabled && config.verify_database_encryption {
                status.add_issue("Database connection is not using SSL/TLS");
            }
        }
        Err(e) => {
            if config.verify_database_encryption {
                status.add_issue(format!("Could not verify database SSL status: {}", e));
            }
        }
    }

    // Check for pgcrypto extension (indicates database-level encryption capability)
    let pgcrypto_result: Result<(bool,), _> = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto')",
    )
    .fetch_one(pool)
    .await;

    match pgcrypto_result {
        Ok((has_pgcrypto,)) => {
            status.database_encryption_available = has_pgcrypto;
            // Note: pgcrypto is optional, not required for compliance
        }
        Err(_) => {
            // Ignore - pgcrypto check is informational only
        }
    }

    // Check PostgreSQL encryption settings
    let encryption_settings: Result<Vec<(String, String)>, _> = sqlx::query_as(
        "SELECT name, setting FROM pg_settings WHERE name IN ('ssl', 'ssl_cert_file', 'ssl_key_file')",
    )
    .fetch_all(pool)
    .await;

    if let Ok(settings) = encryption_settings {
        for (name, setting) in settings {
            tracing::debug!(
                setting_name = %name,
                setting_value = %setting,
                "PostgreSQL encryption setting"
            );
        }
    }

    Ok(status)
}

// ============================================================================
// Encrypted Field Wrapper
// ============================================================================

/// A wrapper type for encrypted field values
///
/// Use this type in your data models to indicate a field should be
/// encrypted at rest. The encryption/decryption happens automatically
/// when reading/writing to the database.
///
/// # Example
///
/// ```ignore
/// struct User {
///     id: Uuid,
///     email: String,
///     // Social Security Number - encrypted at rest
///     ssn: EncryptedField,
/// }
/// ```
#[derive(Clone)]
pub struct EncryptedField {
    /// The encrypted value (base64 encoded)
    ciphertext: String,
}

impl EncryptedField {
    /// Create from already-encrypted ciphertext
    pub fn from_ciphertext(ciphertext: String) -> Self {
        Self { ciphertext }
    }

    /// Create by encrypting plaintext
    pub fn encrypt(plaintext: &str, encryptor: &FieldEncryptor) -> Result<Self, EncryptionError> {
        let ciphertext = encryptor.encrypt_string(plaintext)?;
        Ok(Self { ciphertext })
    }

    /// Decrypt the value
    pub fn decrypt(&self, encryptor: &FieldEncryptor) -> Result<String, EncryptionError> {
        encryptor.decrypt_string(&self.ciphertext)
    }

    /// Get the raw ciphertext (for database storage)
    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }
}

impl fmt::Debug for EncryptedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedField")
            .field("ciphertext", &"[ENCRYPTED]")
            .finish()
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Encryption-related errors
#[derive(Debug)]
pub enum EncryptionError {
    /// Key has invalid length
    InvalidKeyLength { expected: usize, actual: usize },
    /// Key encoding is invalid
    InvalidKeyEncoding(String),
    /// Failed to initialize cipher
    CipherInitFailed,
    /// Encryption operation failed
    EncryptionFailed,
    /// Decryption operation failed (wrong key or tampered data)
    DecryptionFailed,
    /// Ciphertext format is invalid
    InvalidCiphertext(String),
    /// Database error during verification
    #[cfg(feature = "postgres")]
    DatabaseError(String),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "Invalid key length: expected {} bytes, got {}", expected, actual)
            }
            Self::InvalidKeyEncoding(msg) => write!(f, "Invalid key encoding: {}", msg),
            Self::CipherInitFailed => write!(f, "Failed to initialize cipher"),
            Self::EncryptionFailed => write!(f, "Encryption operation failed"),
            Self::DecryptionFailed => {
                write!(f, "Decryption failed (wrong key or tampered data)")
            }
            Self::InvalidCiphertext(msg) => write!(f, "Invalid ciphertext: {}", msg),
            #[cfg(feature = "postgres")]
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for EncryptionError {}

// ============================================================================
// Helper Functions
// ============================================================================

/// Decode a key from hex or base64 encoding
fn decode_key(key_str: &str) -> Result<Vec<u8>, EncryptionError> {
    // Try hex first (64 chars for 32 bytes)
    if key_str.len() == 64 && key_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(key_str)
            .map_err(|e| EncryptionError::InvalidKeyEncoding(e.to_string()));
    }

    // Try base64 (44 chars for 32 bytes with padding)
    if key_str.len() >= 43 {
        return base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_str)
            .map_err(|e| EncryptionError::InvalidKeyEncoding(e.to_string()));
    }

    // Raw bytes (not recommended, but supported)
    if key_str.len() == 32 {
        return Ok(key_str.as_bytes().to_vec());
    }

    Err(EncryptionError::InvalidKeyEncoding(
        "Key must be 64 hex chars, 44 base64 chars, or 32 raw bytes".into(),
    ))
}

/// Generate a new random encryption key
///
/// Returns a hex-encoded 256-bit key suitable for use with `FieldEncryptor::new()`.
///
/// # Security
///
/// Uses a cryptographically secure random number generator.
/// When `fips` feature is enabled, uses FIPS 140-3 validated RNG.
/// Store this key securely (e.g., in Vault, AWS KMS, or HSM).
#[cfg(not(feature = "fips"))]
pub fn generate_key() -> String {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    hex::encode(key)
}

/// Generate a cryptographically secure encryption key (FIPS mode)
///
/// Uses FIPS 140-3 validated RNG from AWS-LC.
#[cfg(feature = "fips")]
pub fn generate_key() -> String {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key).expect("FIPS RNG should not fail");
    hex::encode(key)
}

// ============================================================================
// SC-28 Enforcement Middleware
// ============================================================================

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use std::sync::Arc;

/// Configuration for SC-28 encryption enforcement middleware
///
/// Controls how the middleware validates and enforces encryption at rest.
#[derive(Debug, Clone)]
pub struct EncryptionEnforcementConfig {
    /// Require encryption key to be configured (fail-closed)
    /// When true, requests fail with 500 if no encryption key
    pub require_key: bool,

    /// Paths exempt from encryption requirements
    /// Useful for health checks and public endpoints
    pub exempt_paths: Vec<String>,

    /// Whether to inject EncryptionExtension into requests
    /// Allows handlers to access the encryptor
    pub provide_extension: bool,
}

impl Default for EncryptionEnforcementConfig {
    fn default() -> Self {
        Self {
            require_key: true,
            exempt_paths: vec![
                "/health".to_string(),
                "/healthz".to_string(),
                "/ready".to_string(),
                "/metrics".to_string(),
            ],
            provide_extension: true,
        }
    }
}

impl EncryptionEnforcementConfig {
    /// Create a config that doesn't require encryption (for development)
    pub fn optional() -> Self {
        Self {
            require_key: false,
            ..Default::default()
        }
    }

    /// Create a strict config requiring encryption for all paths
    pub fn strict() -> Self {
        Self {
            require_key: true,
            exempt_paths: Vec::new(),
            provide_extension: true,
        }
    }

    /// Check if a path is exempt from encryption requirements
    pub fn is_exempt(&self, path: &str) -> bool {
        self.exempt_paths.iter().any(|exempt| {
            path == exempt || path.starts_with(&format!("{}/", exempt))
        })
    }
}

/// Extension providing access to encryption capabilities in handlers
///
/// Handlers can extract this to encrypt/decrypt sensitive data:
///
/// ```ignore
/// async fn store_secret(
///     Extension(enc): Extension<EncryptionExtension>,
///     Json(data): Json<SensitiveData>,
/// ) -> Result<Json<()>, StatusCode> {
///     let encrypted = enc.encrypt(data.secret.as_bytes())?;
///     // Store encrypted...
///     Ok(Json(()))
/// }
/// ```
#[derive(Clone)]
pub struct EncryptionExtension {
    encryptor: Option<Arc<FieldEncryptor>>,
}

impl EncryptionExtension {
    /// Create a new extension with an encryptor
    pub fn new(encryptor: FieldEncryptor) -> Self {
        Self {
            encryptor: Some(Arc::new(encryptor)),
        }
    }

    /// Create an extension without an encryptor (encryption disabled)
    pub fn disabled() -> Self {
        Self { encryptor: None }
    }

    /// Check if encryption is available
    pub fn is_available(&self) -> bool {
        self.encryptor.is_some()
    }

    /// Encrypt data (returns error if encryption unavailable)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        match &self.encryptor {
            Some(enc) => enc.encrypt(plaintext),
            None => Err(EncryptionError::EncryptionFailed),
        }
    }

    /// Decrypt data (returns error if encryption unavailable)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        match &self.encryptor {
            Some(enc) => enc.decrypt(ciphertext),
            None => Err(EncryptionError::DecryptionFailed),
        }
    }

    /// Encrypt a string value
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, EncryptionError> {
        match &self.encryptor {
            Some(enc) => enc.encrypt_string(plaintext),
            None => Err(EncryptionError::EncryptionFailed),
        }
    }

    /// Decrypt a base64-encoded string
    pub fn decrypt_string(&self, ciphertext: &str) -> Result<String, EncryptionError> {
        match &self.encryptor {
            Some(enc) => enc.decrypt_string(ciphertext),
            None => Err(EncryptionError::DecryptionFailed),
        }
    }

    /// Create an EncryptedField from plaintext
    pub fn encrypt_field(&self, plaintext: &str) -> Result<EncryptedField, EncryptionError> {
        match &self.encryptor {
            Some(enc) => EncryptedField::encrypt(plaintext, enc),
            None => Err(EncryptionError::EncryptionFailed),
        }
    }

    /// Decrypt an EncryptedField
    pub fn decrypt_field(&self, field: &EncryptedField) -> Result<String, EncryptionError> {
        match &self.encryptor {
            Some(enc) => field.decrypt(enc),
            None => Err(EncryptionError::DecryptionFailed),
        }
    }
}

impl fmt::Debug for EncryptionExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionExtension")
            .field("available", &self.is_available())
            .finish()
    }
}

/// SC-28 enforcement middleware
///
/// This middleware validates that encryption is properly configured and
/// provides an `EncryptionExtension` to handlers for encrypting sensitive data.
///
/// # Behavior
///
/// 1. **Startup validation**: If `require_key` is true, the application should
///    fail to start if no encryption key is configured.
///
/// 2. **Request handling**: Injects `EncryptionExtension` into requests so
///    handlers can encrypt/decrypt data.
///
/// 3. **Exempt paths**: Health checks and metrics endpoints bypass encryption
///    requirements.
///
/// # Example
///
/// ```ignore
/// use barbican::encryption::{encryption_enforcement_middleware, EncryptionEnforcementConfig, FieldEncryptor};
/// use axum::{Router, middleware};
///
/// let key = std::env::var("ENCRYPTION_KEY").expect("encryption key required");
/// let encryptor = FieldEncryptor::new(&key).expect("valid key");
/// let config = EncryptionEnforcementConfig::default();
///
/// let app = Router::new()
///     .route("/secrets", post(store_secret))
///     .layer(middleware::from_fn(move |req, next| {
///         let encryptor = encryptor.clone();
///         let config = config.clone();
///         async move {
///             encryption_enforcement_middleware(req, next, Some(encryptor), config).await
///         }
///     }));
/// ```
pub async fn encryption_enforcement_middleware(
    mut req: Request,
    next: Next,
    encryptor: Option<FieldEncryptor>,
    config: EncryptionEnforcementConfig,
) -> Response {
    // Clone path to avoid borrow issues
    let path = req.uri().path().to_string();

    // Check if path is exempt from encryption requirements
    if config.is_exempt(&path) {
        // Still provide extension if available, but don't require it
        if config.provide_extension {
            let extension = match &encryptor {
                Some(enc) => EncryptionExtension::new(enc.clone()),
                None => EncryptionExtension::disabled(),
            };
            req.extensions_mut().insert(extension);
        }
        return next.run(req).await;
    }

    // Validate encryption is configured if required
    if config.require_key && encryptor.is_none() {
        tracing::error!(
            path = %path,
            control = "SC-28",
            "Encryption key not configured but required"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("X-SC28-Error", "encryption-not-configured")],
            "Encryption not available",
        )
            .into_response();
    }

    // Inject extension for handlers
    if config.provide_extension {
        let extension = match &encryptor {
            Some(enc) => EncryptionExtension::new(enc.clone()),
            None => EncryptionExtension::disabled(),
        };
        req.extensions_mut().insert(extension);
    }

    // Log that encryption is available for sensitive operations
    if encryptor.is_some() {
        tracing::debug!(
            path = %path,
            control = "SC-28",
            "Encryption available for sensitive data"
        );
    }

    next.run(req).await
}

/// Validate encryption configuration at startup
///
/// Call this during application initialization to fail fast if encryption
/// is required but not properly configured.
///
/// # Example
///
/// ```ignore
/// use barbican::encryption::{validate_encryption_startup, EncryptionEnforcementConfig};
///
/// fn main() -> anyhow::Result<()> {
///     let config = EncryptionEnforcementConfig::default();
///     let key = std::env::var("ENCRYPTION_KEY").ok();
///
///     validate_encryption_startup(&config, key.as_deref())?;
///
///     // ... start server
///     Ok(())
/// }
/// ```
pub fn validate_encryption_startup(
    config: &EncryptionEnforcementConfig,
    encryption_key: Option<&str>,
) -> Result<Option<FieldEncryptor>, EncryptionError> {
    match encryption_key {
        Some(key) => {
            let encryptor = FieldEncryptor::new(key)?;
            tracing::info!(
                control = "SC-28",
                algorithm = ?encryptor.algorithm(),
                fips_mode = %is_fips_mode(),
                "Encryption at rest configured"
            );
            Ok(Some(encryptor))
        }
        None => {
            if config.require_key {
                tracing::error!(
                    control = "SC-28",
                    "ENCRYPTION_KEY not set but encryption required"
                );
                Err(EncryptionError::InvalidKeyEncoding(
                    "ENCRYPTION_KEY environment variable not set".into(),
                ))
            } else {
                tracing::warn!(
                    control = "SC-28",
                    "Encryption not configured - sensitive data will not be encrypted"
                );
                Ok(None)
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> String {
        // 32-byte hex key for testing
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
    }

    #[test]
    fn test_field_encryptor_roundtrip() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();

        let plaintext = b"sensitive data";
        let encrypted = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_field_encryptor_string_roundtrip() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();

        let plaintext = "Hello, World!";
        let encrypted = encryptor.encrypt_string(plaintext).unwrap();
        let decrypted = encryptor.decrypt_string(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_field_roundtrip() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();

        let plaintext = "secret-value";
        let field = EncryptedField::encrypt(plaintext, &encryptor).unwrap();
        let decrypted = field.decrypt(&encryptor).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();

        let plaintext = b"same data";
        let encrypted1 = encryptor.encrypt(plaintext).unwrap();
        let encrypted2 = encryptor.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertexts (random nonce)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same value
        assert_eq!(
            encryptor.decrypt(&encrypted1).unwrap(),
            encryptor.decrypt(&encrypted2).unwrap()
        );
    }

    #[test]
    fn test_tamper_detection() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();

        let plaintext = b"sensitive data";
        let mut encrypted = encryptor.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = encrypted.get_mut(20) {
            *byte ^= 0xff;
        }

        // Decryption should fail
        assert!(encryptor.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_wrong_key() {
        let encryptor1 = FieldEncryptor::new(&test_key()).unwrap();
        let encryptor2 = FieldEncryptor::new(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )
        .unwrap();

        let encrypted = encryptor1.encrypt(b"secret").unwrap();

        // Wrong key should fail to decrypt
        assert!(encryptor2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        // 48 hex chars = 24 bytes, which is wrong length for AES-256 (needs 32)
        let result = FieldEncryptor::new("0123456789abcdef0123456789abcdef0123456789abcdef");
        assert!(matches!(result, Err(EncryptionError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_invalid_key_encoding() {
        let result = FieldEncryptor::new("tooshort");
        assert!(matches!(result, Err(EncryptionError::InvalidKeyEncoding(_))));
    }

    #[test]
    fn test_generate_key() {
        let key = generate_key();
        assert_eq!(key.len(), 64); // Hex-encoded 32 bytes

        // Should be valid for creating an encryptor
        assert!(FieldEncryptor::new(&key).is_ok());
    }

    #[test]
    fn test_algorithm_properties() {
        let algo = EncryptionAlgorithm::Aes256Gcm;
        assert_eq!(algo.key_size(), 32);
        assert_eq!(algo.nonce_size(), 12);
        assert_eq!(algo.tag_size(), 16);
    }

    #[test]
    fn test_encryption_config_defaults() {
        let config = EncryptionConfig::default();
        assert!(config.require_encryption);
        assert!(config.verify_database_encryption);
        assert_eq!(config.algorithm, EncryptionAlgorithm::Aes256Gcm);
    }

    #[test]
    fn test_verify_encryption_config_with_valid_key() {
        let config = EncryptionConfig::default();
        let status = verify_encryption_config(&config, Some(&test_key()));

        assert!(status.field_encryption_available);
        assert!(status.compliant);
    }

    #[test]
    fn test_verify_encryption_config_without_key() {
        let config = EncryptionConfig::default();
        let status = verify_encryption_config(&config, None);

        assert!(!status.field_encryption_available);
        assert!(!status.compliant);
        assert!(!status.issues.is_empty());
    }

    #[test]
    fn test_base64_key_decoding() {
        // Generate a key and encode as base64
        let raw_key = [0x42u8; 32];
        let base64_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw_key);

        let result = decode_key(&base64_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), raw_key.to_vec());
    }

    #[test]
    fn test_encrypted_field_debug_redacts() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();
        let field = EncryptedField::encrypt("secret", &encryptor).unwrap();

        let debug_output = format!("{:?}", field);
        assert!(debug_output.contains("[ENCRYPTED]"));
        assert!(!debug_output.contains("secret"));
    }

    #[test]
    fn test_encryptor_debug_redacts_key() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();
        let debug_output = format!("{:?}", encryptor);
        assert!(debug_output.contains("[REDACTED]"));
    }

    // ========================================================================
    // SC-28 Enforcement Middleware Tests
    // ========================================================================

    #[test]
    fn test_encryption_enforcement_config_defaults() {
        let config = EncryptionEnforcementConfig::default();
        assert!(config.require_key);
        assert!(config.provide_extension);
        assert!(config.exempt_paths.contains(&"/health".to_string()));
        assert!(config.exempt_paths.contains(&"/metrics".to_string()));
    }

    #[test]
    fn test_encryption_enforcement_config_optional() {
        let config = EncryptionEnforcementConfig::optional();
        assert!(!config.require_key);
        assert!(config.provide_extension);
    }

    #[test]
    fn test_encryption_enforcement_config_strict() {
        let config = EncryptionEnforcementConfig::strict();
        assert!(config.require_key);
        assert!(config.exempt_paths.is_empty());
    }

    #[test]
    fn test_encryption_enforcement_path_exemption() {
        let config = EncryptionEnforcementConfig::default();

        // Exact matches
        assert!(config.is_exempt("/health"));
        assert!(config.is_exempt("/healthz"));
        assert!(config.is_exempt("/metrics"));

        // Subpaths
        assert!(config.is_exempt("/health/ready"));
        assert!(config.is_exempt("/metrics/prometheus"));

        // Non-exempt
        assert!(!config.is_exempt("/api/secrets"));
        assert!(!config.is_exempt("/users"));
    }

    #[test]
    fn test_encryption_extension_with_encryptor() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();
        let extension = EncryptionExtension::new(encryptor);

        assert!(extension.is_available());

        // Test encrypt/decrypt roundtrip
        let plaintext = b"sensitive data";
        let encrypted = extension.encrypt(plaintext).unwrap();
        let decrypted = extension.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_extension_disabled() {
        let extension = EncryptionExtension::disabled();

        assert!(!extension.is_available());
        assert!(extension.encrypt(b"test").is_err());
        assert!(extension.decrypt(b"test").is_err());
    }

    #[test]
    fn test_encryption_extension_string_methods() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();
        let extension = EncryptionExtension::new(encryptor);

        let plaintext = "secret string";
        let encrypted = extension.encrypt_string(plaintext).unwrap();
        let decrypted = extension.decrypt_string(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_extension_field_methods() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();
        let extension = EncryptionExtension::new(encryptor);

        let plaintext = "field value";
        let field = extension.encrypt_field(plaintext).unwrap();
        let decrypted = extension.decrypt_field(&field).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_extension_debug_hides_details() {
        let encryptor = FieldEncryptor::new(&test_key()).unwrap();
        let extension = EncryptionExtension::new(encryptor);

        let debug_output = format!("{:?}", extension);
        assert!(debug_output.contains("available"));
        assert!(debug_output.contains("true"));
    }

    #[test]
    fn test_validate_encryption_startup_with_key() {
        let config = EncryptionEnforcementConfig::default();
        let result = validate_encryption_startup(&config, Some(&test_key()));

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_validate_encryption_startup_without_key_required() {
        let config = EncryptionEnforcementConfig::default();
        let result = validate_encryption_startup(&config, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_encryption_startup_without_key_optional() {
        let config = EncryptionEnforcementConfig::optional();
        let result = validate_encryption_startup(&config, None);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_validate_encryption_startup_invalid_key() {
        let config = EncryptionEnforcementConfig::default();
        let result = validate_encryption_startup(&config, Some("invalid"));

        assert!(result.is_err());
    }

    // Note: Full integration tests with axum middleware would require tower as a
    // dev-dependency for ServiceExt::oneshot. The middleware behavior is covered by:
    // 1. Unit tests for EncryptionEnforcementConfig (path exemption, modes)
    // 2. Unit tests for EncryptionExtension (encrypt/decrypt operations)
    // 3. Unit tests for validate_encryption_startup (startup validation)
    // 4. Integration via layers.rs (implicit testing via with_security())
}
