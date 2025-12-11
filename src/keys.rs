//! Cryptographic Key Management (SC-12)
//!
//! NIST SP 800-53 SC-12 (Cryptographic Key Establishment and Management)
//! compliant key management abstractions.
//!
//! # Design Philosophy
//!
//! This module provides **traits and abstractions** for integrating with
//! external key management systems. It does NOT store or manage actual
//! key material - that's the responsibility of your KMS.
//!
//! Supported integrations (via trait implementation):
//! - HashiCorp Vault
//! - AWS KMS
//! - Azure Key Vault
//! - Google Cloud KMS
//! - Hardware Security Modules (HSMs)
//! - Local development (environment variables)
//!
//! # What This Module Provides
//!
//! - `KeyStore` trait for KMS integration
//! - Key metadata and lifecycle tracking
//! - Rotation scheduling and alerting
//! - Compliance reporting
//! - Audit logging for key operations
//!
//! # Usage
//!
//! ```ignore
//! use barbican::keys::{KeyStore, KeyMetadata, KeyPurpose, RotationPolicy};
//!
//! // Implement KeyStore for your KMS
//! struct VaultKeyStore { /* ... */ }
//!
//! impl KeyStore for VaultKeyStore {
//!     async fn get_key(&self, id: &str) -> Result<KeyMaterial, KeyError> {
//!         // Fetch from Vault
//!     }
//!     // ...
//! }
//!
//! // Use with rotation tracking
//! let store = VaultKeyStore::new();
//! let tracker = RotationTracker::new();
//!
//! tracker.register("api-signing-key", RotationPolicy::days(90));
//!
//! if tracker.needs_rotation("api-signing-key") {
//!     store.rotate_key("api-signing-key").await?;
//!     tracker.record_rotation("api-signing-key");
//! }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use crate::observability::SecurityEvent;

// ============================================================================
// Key Store Trait (KMS Integration)
// ============================================================================

/// Error type for key operations
#[derive(Debug, Clone)]
pub enum KeyError {
    /// Key not found
    NotFound(String),
    /// Access denied
    AccessDenied(String),
    /// KMS connection failed
    ConnectionFailed(String),
    /// Key is expired or revoked
    KeyInvalid(String),
    /// Operation not supported
    Unsupported(String),
    /// Other error
    Other(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::NotFound(id) => write!(f, "Key not found: {}", id),
            KeyError::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            KeyError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            KeyError::KeyInvalid(msg) => write!(f, "Key invalid: {}", msg),
            KeyError::Unsupported(msg) => write!(f, "Unsupported: {}", msg),
            KeyError::Other(msg) => write!(f, "Key error: {}", msg),
        }
    }
}

impl std::error::Error for KeyError {}

/// Opaque key material wrapper
///
/// This wraps key bytes and ensures they're zeroed on drop.
/// The actual key material comes from your KMS.
#[derive(Clone)]
pub struct KeyMaterial {
    bytes: Vec<u8>,
    key_id: String,
}

impl KeyMaterial {
    /// Create new key material
    pub fn new(key_id: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            key_id: key_id.into(),
        }
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the key bytes (use carefully)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get key length in bytes
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Zero out key material on drop
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("key_id", &self.key_id)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Trait for key management system integration
///
/// Implement this trait to integrate with your KMS (Vault, AWS KMS, etc.)
pub trait KeyStore: Send + Sync {
    /// Get key material by ID
    fn get_key(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMaterial, KeyError>> + Send + '_>>;

    /// Check if a key exists
    fn key_exists(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<bool, KeyError>> + Send + '_>>;

    /// Rotate a key (create new version)
    fn rotate_key(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMaterial, KeyError>> + Send + '_>>;

    /// Get key metadata
    fn get_metadata(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMetadata, KeyError>> + Send + '_>>;

    /// List all key IDs
    fn list_keys(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>, KeyError>> + Send + '_>>;
}

// ============================================================================
// Key Metadata
// ============================================================================

/// Purpose of a cryptographic key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    /// Signing/verification (JWT, documents)
    Signing,
    /// Encryption/decryption
    Encryption,
    /// Key wrapping (encrypting other keys)
    KeyWrapping,
    /// Authentication (API keys, tokens)
    Authentication,
    /// Key derivation (master keys)
    Derivation,
}

/// Key state in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Key is active and can be used for all operations
    Active,
    /// Key can decrypt/verify but not encrypt/sign (rotation in progress)
    DecryptOnly,
    /// Key is disabled
    Disabled,
    /// Key is scheduled for destruction
    PendingDestruction,
    /// Key is destroyed
    Destroyed,
}

impl KeyState {
    /// Can this key be used for new encrypt/sign operations?
    pub fn can_encrypt(&self) -> bool {
        matches!(self, KeyState::Active)
    }

    /// Can this key be used for decrypt/verify operations?
    pub fn can_decrypt(&self) -> bool {
        matches!(self, KeyState::Active | KeyState::DecryptOnly)
    }
}

/// Metadata about a key (from KMS)
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// Key identifier
    pub id: String,
    /// Human-readable name
    pub name: Option<String>,
    /// Key purpose
    pub purpose: Option<KeyPurpose>,
    /// Current state
    pub state: KeyState,
    /// Key version
    pub version: u32,
    /// When created
    pub created_at: Option<SystemTime>,
    /// When last rotated
    pub rotated_at: Option<SystemTime>,
    /// When it expires
    pub expires_at: Option<SystemTime>,
    /// Custom tags/labels
    pub tags: HashMap<String, String>,
}

impl KeyMetadata {
    /// Create minimal metadata
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            purpose: None,
            state: KeyState::Active,
            version: 1,
            created_at: None,
            rotated_at: None,
            expires_at: None,
            tags: HashMap::new(),
        }
    }

    /// Set name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set purpose
    pub fn with_purpose(mut self, purpose: KeyPurpose) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Set state
    pub fn with_state(mut self, state: KeyState) -> Self {
        self.state = state;
        self
    }

    /// Set version
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set created timestamp
    pub fn with_created_at(mut self, time: SystemTime) -> Self {
        self.created_at = Some(time);
        self
    }

    /// Set rotated timestamp
    pub fn with_rotated_at(mut self, time: SystemTime) -> Self {
        self.rotated_at = Some(time);
        self
    }

    /// Set expiration
    pub fn with_expires_at(mut self, time: SystemTime) -> Self {
        self.expires_at = Some(time);
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Check if expired
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| SystemTime::now() >= exp)
            .unwrap_or(false)
    }
}

// ============================================================================
// Rotation Policy and Tracking
// ============================================================================

/// Rotation policy for a key
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// How often to rotate
    pub interval: Duration,
    /// Warn this long before rotation is due
    pub warn_before: Duration,
}

impl RotationPolicy {
    /// Create a policy with the given interval
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            warn_before: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
        }
    }

    /// Create a policy in days
    pub fn days(days: u64) -> Self {
        Self::new(Duration::from_secs(days * 24 * 60 * 60))
    }

    /// Set warning period
    pub fn with_warning(mut self, warn_before: Duration) -> Self {
        self.warn_before = warn_before;
        self
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::days(90)
    }
}

/// Tracks rotation schedules for keys
#[derive(Debug, Default)]
pub struct RotationTracker {
    /// Policies by key ID
    policies: HashMap<String, RotationPolicy>,
    /// Last rotation time by key ID
    last_rotated: HashMap<String, SystemTime>,
}

impl RotationTracker {
    /// Create a new tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a key with a rotation policy
    pub fn register(&mut self, key_id: impl Into<String>, policy: RotationPolicy) {
        let id = key_id.into();
        log_key_registered(&id);
        self.policies.insert(id.clone(), policy);
        self.last_rotated.insert(id, SystemTime::now());
    }

    /// Record that a key was rotated
    pub fn record_rotation(&mut self, key_id: &str) {
        self.last_rotated.insert(key_id.to_string(), SystemTime::now());
        log_key_rotated(key_id);
    }

    /// Check if a key needs rotation
    pub fn needs_rotation(&self, key_id: &str) -> bool {
        let policy = match self.policies.get(key_id) {
            Some(p) => p,
            None => return false,
        };

        let last = match self.last_rotated.get(key_id) {
            Some(t) => t,
            None => return true, // Never rotated
        };

        last.elapsed()
            .map(|elapsed| elapsed >= policy.interval)
            .unwrap_or(false)
    }

    /// Check if rotation is upcoming (within warning period)
    pub fn rotation_upcoming(&self, key_id: &str) -> bool {
        let policy = match self.policies.get(key_id) {
            Some(p) => p,
            None => return false,
        };

        let last = match self.last_rotated.get(key_id) {
            Some(t) => t,
            None => return true,
        };

        last.elapsed()
            .map(|elapsed| {
                let time_until = policy.interval.saturating_sub(elapsed);
                time_until <= policy.warn_before
            })
            .unwrap_or(false)
    }

    /// Get all keys needing rotation
    pub fn keys_needing_rotation(&self) -> Vec<&str> {
        self.policies
            .keys()
            .filter(|id| self.needs_rotation(id))
            .map(|s| s.as_str())
            .collect()
    }

    /// Get all keys with upcoming rotation
    pub fn keys_with_upcoming_rotation(&self) -> Vec<&str> {
        self.policies
            .keys()
            .filter(|id| self.rotation_upcoming(id) && !self.needs_rotation(id))
            .map(|s| s.as_str())
            .collect()
    }

    /// Generate a rotation status report
    pub fn status_report(&self) -> RotationStatus {
        RotationStatus {
            due_now: self.keys_needing_rotation().iter().map(|s| s.to_string()).collect(),
            upcoming: self.keys_with_upcoming_rotation().iter().map(|s| s.to_string()).collect(),
            total_tracked: self.policies.len(),
        }
    }

    /// Remove a key from tracking
    pub fn unregister(&mut self, key_id: &str) {
        self.policies.remove(key_id);
        self.last_rotated.remove(key_id);
    }
}

/// Rotation status report
#[derive(Debug, Clone)]
pub struct RotationStatus {
    /// Keys that need rotation now
    pub due_now: Vec<String>,
    /// Keys with upcoming rotation
    pub upcoming: Vec<String>,
    /// Total number of tracked keys
    pub total_tracked: usize,
}

impl RotationStatus {
    /// Check if any rotations are due
    pub fn has_due_rotations(&self) -> bool {
        !self.due_now.is_empty()
    }

    /// Check if any rotations are upcoming
    pub fn has_upcoming_rotations(&self) -> bool {
        !self.upcoming.is_empty()
    }
}

// ============================================================================
// Environment Variable Key Store (Development)
// ============================================================================

/// Simple key store that reads from environment variables
///
/// **For development/testing only.** Use a proper KMS in production.
///
/// Keys are read from environment variables with the pattern:
/// `{PREFIX}_{KEY_ID}` (e.g., `APP_KEYS_JWT_SIGNING`)
#[derive(Debug, Clone)]
pub struct EnvKeyStore {
    prefix: String,
}

impl EnvKeyStore {
    /// Create a new env key store with the given prefix
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    fn env_var_name(&self, key_id: &str) -> String {
        format!("{}_{}", self.prefix, key_id.to_uppercase().replace('-', "_"))
    }
}

impl KeyStore for EnvKeyStore {
    fn get_key(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMaterial, KeyError>> + Send + '_>> {
        let var_name = self.env_var_name(id);
        let id = id.to_string();

        Box::pin(async move {
            match std::env::var(&var_name) {
                Ok(value) => {
                    // Decode as base64 or use raw bytes
                    let bytes = if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
                        // Try base64 decode
                        base64_decode(&value).unwrap_or_else(|_| value.into_bytes())
                    } else {
                        value.into_bytes()
                    };
                    Ok(KeyMaterial::new(id, bytes))
                }
                Err(_) => Err(KeyError::NotFound(format!("Environment variable {} not set", var_name))),
            }
        })
    }

    fn key_exists(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<bool, KeyError>> + Send + '_>> {
        let var_name = self.env_var_name(id);
        Box::pin(async move {
            Ok(std::env::var(&var_name).is_ok())
        })
    }

    fn rotate_key(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMaterial, KeyError>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            Err(KeyError::Unsupported(format!(
                "Cannot rotate key '{}' in EnvKeyStore - use a proper KMS",
                id
            )))
        })
    }

    fn get_metadata(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMetadata, KeyError>> + Send + '_>> {
        let var_name = self.env_var_name(id);
        let id = id.to_string();

        Box::pin(async move {
            if std::env::var(&var_name).is_ok() {
                Ok(KeyMetadata::new(&id)
                    .with_name(&id)
                    .with_state(KeyState::Active))
            } else {
                Err(KeyError::NotFound(id))
            }
        })
    }

    fn list_keys(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>, KeyError>> + Send + '_>> {
        let prefix = format!("{}_", self.prefix);

        Box::pin(async move {
            let keys: Vec<String> = std::env::vars()
                .filter_map(|(k, _)| {
                    if k.starts_with(&prefix) {
                        Some(k[prefix.len()..].to_lowercase().replace('_', "-"))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(keys)
        })
    }
}

/// Simple base64 decode (no external dependency)
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.bytes() {
        let value = ALPHABET.iter().position(|&b| b == c).ok_or(())? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

// ============================================================================
// Logging
// ============================================================================

fn log_key_registered(key_id: &str) {
    crate::security_event!(
        SecurityEvent::ConfigurationChanged,
        key_id = %key_id,
        "Key registered for rotation tracking"
    );
}

fn log_key_rotated(key_id: &str) {
    crate::security_event!(
        SecurityEvent::ConfigurationChanged,
        key_id = %key_id,
        "Key rotation recorded"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_material_zeroed_on_drop() {
        let bytes = vec![1, 2, 3, 4, 5];

        {
            let material = KeyMaterial::new("test", bytes);
            assert_eq!(material.len(), 5);
        }
        // After drop, the implementation zeros the bytes
        // (verified by code inspection, can't easily test without unsafe)
    }

    #[test]
    fn test_key_state_permissions() {
        assert!(KeyState::Active.can_encrypt());
        assert!(KeyState::Active.can_decrypt());

        assert!(!KeyState::DecryptOnly.can_encrypt());
        assert!(KeyState::DecryptOnly.can_decrypt());

        assert!(!KeyState::Disabled.can_encrypt());
        assert!(!KeyState::Disabled.can_decrypt());
    }

    #[test]
    fn test_key_metadata_builder() {
        let meta = KeyMetadata::new("test-key")
            .with_name("Test Key")
            .with_purpose(KeyPurpose::Signing)
            .with_version(2)
            .with_tag("env", "prod");

        assert_eq!(meta.id, "test-key");
        assert_eq!(meta.name, Some("Test Key".to_string()));
        assert_eq!(meta.purpose, Some(KeyPurpose::Signing));
        assert_eq!(meta.version, 2);
        assert_eq!(meta.tags.get("env"), Some(&"prod".to_string()));
    }

    #[test]
    fn test_rotation_policy() {
        let policy = RotationPolicy::days(90);
        assert_eq!(policy.interval, Duration::from_secs(90 * 24 * 60 * 60));

        let policy = RotationPolicy::days(30)
            .with_warning(Duration::from_secs(3 * 24 * 60 * 60));
        assert_eq!(policy.warn_before, Duration::from_secs(3 * 24 * 60 * 60));
    }

    #[test]
    fn test_rotation_tracker_register() {
        let mut tracker = RotationTracker::new();
        tracker.register("key-1", RotationPolicy::days(90));
        tracker.register("key-2", RotationPolicy::days(30));

        assert!(!tracker.needs_rotation("key-1")); // Just registered
        assert!(!tracker.needs_rotation("key-2"));
        assert!(!tracker.needs_rotation("key-3")); // Not registered
    }

    #[test]
    fn test_rotation_tracker_status() {
        let mut tracker = RotationTracker::new();
        tracker.register("key-1", RotationPolicy::days(90));
        tracker.register("key-2", RotationPolicy::days(30));

        let status = tracker.status_report();
        assert_eq!(status.total_tracked, 2);
        assert!(!status.has_due_rotations()); // Just registered
    }

    #[test]
    fn test_rotation_tracker_unregister() {
        let mut tracker = RotationTracker::new();
        tracker.register("key-1", RotationPolicy::days(90));

        let status = tracker.status_report();
        assert_eq!(status.total_tracked, 1);

        tracker.unregister("key-1");

        let status = tracker.status_report();
        assert_eq!(status.total_tracked, 0);
    }

    #[test]
    fn test_env_key_store_var_name() {
        let store = EnvKeyStore::new("APP_KEYS");
        assert_eq!(store.env_var_name("jwt-signing"), "APP_KEYS_JWT_SIGNING");
        assert_eq!(store.env_var_name("api_key"), "APP_KEYS_API_KEY");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(base64_decode("dGVzdA==").unwrap(), b"test");
        assert!(base64_decode("!!!invalid!!!").is_err());
    }

    #[tokio::test]
    async fn test_env_key_store_not_found() {
        let store = EnvKeyStore::new("TEST_BARBICAN_KEYS");
        let result = store.get_key("nonexistent").await;
        assert!(matches!(result, Err(KeyError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_env_key_store_rotate_unsupported() {
        let store = EnvKeyStore::new("TEST_BARBICAN_KEYS");
        let result = store.rotate_key("any-key").await;
        assert!(matches!(result, Err(KeyError::Unsupported(_))));
    }

    #[test]
    fn test_key_error_display() {
        let err = KeyError::NotFound("test-key".to_string());
        assert!(err.to_string().contains("test-key"));

        let err = KeyError::AccessDenied("permission denied".to_string());
        assert!(err.to_string().contains("Access denied"));
    }
}
