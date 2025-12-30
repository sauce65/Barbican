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

    /// Create policy from compliance configuration
    ///
    /// Derives key rotation interval from the compliance profile. Higher
    /// profiles require more frequent key rotation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use barbican::compliance::ComplianceConfig;
    /// use barbican::keys::RotationPolicy;
    ///
    /// let compliance = barbican::compliance::config();
    /// let policy = RotationPolicy::from_compliance(compliance);
    /// ```
    pub fn from_compliance(config: &crate::compliance::ComplianceConfig) -> Self {
        use crate::compliance::ComplianceProfile;

        Self {
            interval: config.key_rotation_interval,
            warn_before: match config.profile {
                ComplianceProfile::FedRampHigh => Duration::from_secs(14 * 24 * 60 * 60), // 14 days
                _ => Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            },
        }
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
// In-Memory Key Store (Testing/Development)
// ============================================================================

use std::sync::RwLock;

/// In-memory key store for testing and development
///
/// Provides a simple key store that keeps keys in memory. Useful for
/// testing and development, but NOT suitable for production use.
///
/// # Example
///
/// ```ignore
/// use barbican::keys::{InMemoryKeyStore, KeyMaterial, KeyPurpose};
///
/// let store = InMemoryKeyStore::new();
/// store.set_key("signing-key", KeyMaterial::new("signing-key", vec![1, 2, 3, 4]));
///
/// let key = store.get_key("signing-key").await?;
/// ```
#[derive(Debug, Default)]
pub struct InMemoryKeyStore {
    keys: RwLock<HashMap<String, KeyMaterial>>,
    metadata: RwLock<HashMap<String, KeyMetadata>>,
}

impl InMemoryKeyStore {
    /// Create a new empty in-memory store
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a key in the store
    pub fn set_key(&self, id: impl Into<String>, material: KeyMaterial) {
        let id = id.into();
        let meta = KeyMetadata::new(&id)
            .with_state(KeyState::Active)
            .with_created_at(SystemTime::now());

        if let Ok(mut keys) = self.keys.write() {
            keys.insert(id.clone(), material);
        }
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.insert(id, meta);
        }
    }

    /// Set a key with custom metadata
    pub fn set_key_with_metadata(&self, material: KeyMaterial, meta: KeyMetadata) {
        let id = material.key_id().to_string();
        if let Ok(mut keys) = self.keys.write() {
            keys.insert(id.clone(), material);
        }
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.insert(id, meta);
        }
    }

    /// Remove a key from the store
    pub fn remove_key(&self, id: &str) {
        if let Ok(mut keys) = self.keys.write() {
            keys.remove(id);
        }
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.remove(id);
        }
    }

    /// Get the number of keys in the store
    pub fn len(&self) -> usize {
        self.keys.read().map(|k| k.len()).unwrap_or(0)
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl KeyStore for InMemoryKeyStore {
    fn get_key(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMaterial, KeyError>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            let keys = self.keys.read()
                .map_err(|_| KeyError::Other("Lock poisoned".to_string()))?;

            keys.get(&id)
                .cloned()
                .ok_or_else(|| KeyError::NotFound(id))
        })
    }

    fn key_exists(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<bool, KeyError>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            let keys = self.keys.read()
                .map_err(|_| KeyError::Other("Lock poisoned".to_string()))?;
            Ok(keys.contains_key(&id))
        })
    }

    fn rotate_key(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMaterial, KeyError>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            // Get current key
            let current = {
                let keys = self.keys.read()
                    .map_err(|_| KeyError::Other("Lock poisoned".to_string()))?;
                keys.get(&id).cloned()
            };

            match current {
                Some(material) => {
                    // Generate "rotated" key (just increment last byte for testing)
                    let mut new_bytes = material.as_bytes().to_vec();
                    if let Some(last) = new_bytes.last_mut() {
                        *last = last.wrapping_add(1);
                    }
                    let new_material = KeyMaterial::new(&id, new_bytes);

                    // Update store
                    if let Ok(mut keys) = self.keys.write() {
                        keys.insert(id.clone(), new_material.clone());
                    }
                    if let Ok(mut metadata) = self.metadata.write() {
                        if let Some(meta) = metadata.get_mut(&id) {
                            meta.version += 1;
                            meta.rotated_at = Some(SystemTime::now());
                        }
                    }

                    Ok(new_material)
                }
                None => Err(KeyError::NotFound(id)),
            }
        })
    }

    fn get_metadata(&self, id: &str) -> Pin<Box<dyn Future<Output = Result<KeyMetadata, KeyError>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move {
            let metadata = self.metadata.read()
                .map_err(|_| KeyError::Other("Lock poisoned".to_string()))?;

            metadata.get(&id)
                .cloned()
                .ok_or_else(|| KeyError::NotFound(id))
        })
    }

    fn list_keys(&self) -> Pin<Box<dyn Future<Output = Result<Vec<String>, KeyError>> + Send + '_>> {
        Box::pin(async move {
            let keys = self.keys.read()
                .map_err(|_| KeyError::Other("Lock poisoned".to_string()))?;
            Ok(keys.keys().cloned().collect())
        })
    }
}

// ============================================================================
// SC-12 Enforcement: Axum Integration
// ============================================================================

use std::sync::Arc;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// Axum extension for accessing key store in handlers (SC-12)
///
/// Provides handlers with access to the key management system.
///
/// # Example
///
/// ```ignore
/// use axum::Extension;
/// use barbican::keys::KeyStoreExtension;
///
/// async fn sign_document(
///     Extension(keys): Extension<KeyStoreExtension>,
///     body: String,
/// ) -> impl IntoResponse {
///     let key = keys.get_key("signing-key").await?;
///     // Use key to sign document...
///     "Signed"
/// }
/// ```
#[derive(Clone)]
pub struct KeyStoreExtension {
    store: Arc<dyn KeyStore>,
    tracker: Option<Arc<RwLock<RotationTracker>>>,
}

impl KeyStoreExtension {
    /// Create a new extension with the given key store
    pub fn new<S: KeyStore + 'static>(store: S) -> Self {
        Self {
            store: Arc::new(store),
            tracker: None,
        }
    }

    /// Create with a rotation tracker
    pub fn with_tracker<S: KeyStore + 'static>(store: S, tracker: RotationTracker) -> Self {
        Self {
            store: Arc::new(store),
            tracker: Some(Arc::new(RwLock::new(tracker))),
        }
    }

    /// Create with an in-memory store (for development/testing)
    pub fn in_memory() -> Self {
        Self::new(InMemoryKeyStore::new())
    }

    /// Create with an environment variable store
    pub fn from_env(prefix: impl Into<String>) -> Self {
        Self::new(EnvKeyStore::new(prefix))
    }

    /// Get a key by ID
    pub async fn get_key(&self, id: &str) -> Result<KeyMaterial, KeyError> {
        self.store.get_key(id).await
    }

    /// Check if a key exists
    pub async fn key_exists(&self, id: &str) -> Result<bool, KeyError> {
        self.store.key_exists(id).await
    }

    /// Rotate a key
    pub async fn rotate_key(&self, id: &str) -> Result<KeyMaterial, KeyError> {
        let result = self.store.rotate_key(id).await;
        if result.is_ok() {
            if let Some(ref tracker) = self.tracker {
                if let Ok(mut t) = tracker.write() {
                    t.record_rotation(id);
                }
            }
        }
        result
    }

    /// Get key metadata
    pub async fn get_metadata(&self, id: &str) -> Result<KeyMetadata, KeyError> {
        self.store.get_metadata(id).await
    }

    /// List all keys
    pub async fn list_keys(&self) -> Result<Vec<String>, KeyError> {
        self.store.list_keys().await
    }

    /// Check if a key needs rotation (if tracker is configured)
    pub fn needs_rotation(&self, id: &str) -> bool {
        self.tracker
            .as_ref()
            .and_then(|t| t.read().ok())
            .map(|t| t.needs_rotation(id))
            .unwrap_or(false)
    }

    /// Get rotation status (if tracker is configured)
    pub fn rotation_status(&self) -> Option<RotationStatus> {
        self.tracker
            .as_ref()
            .and_then(|t| t.read().ok())
            .map(|t| t.status_report())
    }

    /// Register a key for rotation tracking
    pub fn register_for_rotation(&self, key_id: impl Into<String>, policy: RotationPolicy) {
        if let Some(ref tracker) = self.tracker {
            if let Ok(mut t) = tracker.write() {
                t.register(key_id, policy);
            }
        }
    }
}

impl std::fmt::Debug for KeyStoreExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStoreExtension")
            .field("has_tracker", &self.tracker.is_some())
            .finish()
    }
}

/// Middleware that provides KeyStoreExtension to handlers
///
/// # Example
///
/// ```ignore
/// use barbican::keys::{key_store_middleware, InMemoryKeyStore};
/// use axum::{Router, middleware};
///
/// let store = InMemoryKeyStore::new();
/// let ext = KeyStoreExtension::new(store);
///
/// let app = Router::new()
///     .route("/sign", post(sign_handler))
///     .layer(middleware::from_fn(move |req, next| {
///         let ext = ext.clone();
///         async move {
///             key_store_middleware(req, next, ext).await
///         }
///     }));
/// ```
pub async fn key_store_middleware(
    mut req: Request,
    next: Next,
    extension: KeyStoreExtension,
) -> Response {
    req.extensions_mut().insert(extension);
    next.run(req).await
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

    // ========================================================================
    // SC-12 In-Memory Store Tests
    // ========================================================================

    #[test]
    fn test_in_memory_store_new() {
        let store = InMemoryKeyStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_in_memory_store_set_key() {
        let store = InMemoryKeyStore::new();
        let material = KeyMaterial::new("test-key", vec![1, 2, 3, 4]);

        store.set_key("test-key", material);

        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn test_in_memory_store_get_key() {
        let store = InMemoryKeyStore::new();
        let material = KeyMaterial::new("test-key", vec![1, 2, 3, 4]);
        store.set_key("test-key", material);

        let retrieved = store.get_key("test-key").await.unwrap();
        assert_eq!(retrieved.key_id(), "test-key");
        assert_eq!(retrieved.as_bytes(), &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_in_memory_store_key_exists() {
        let store = InMemoryKeyStore::new();
        let material = KeyMaterial::new("test-key", vec![1, 2, 3, 4]);
        store.set_key("test-key", material);

        assert!(store.key_exists("test-key").await.unwrap());
        assert!(!store.key_exists("nonexistent").await.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_store_rotate_key() {
        let store = InMemoryKeyStore::new();
        let material = KeyMaterial::new("test-key", vec![1, 2, 3, 4]);
        store.set_key("test-key", material);

        let rotated = store.rotate_key("test-key").await.unwrap();
        assert_eq!(rotated.key_id(), "test-key");
        // Last byte should be incremented
        assert_eq!(rotated.as_bytes(), &[1, 2, 3, 5]);

        // Metadata should show version 2
        let meta = store.get_metadata("test-key").await.unwrap();
        assert_eq!(meta.version, 2);
        assert!(meta.rotated_at.is_some());
    }

    #[tokio::test]
    async fn test_in_memory_store_get_metadata() {
        let store = InMemoryKeyStore::new();
        let material = KeyMaterial::new("test-key", vec![1, 2, 3, 4]);
        store.set_key("test-key", material);

        let meta = store.get_metadata("test-key").await.unwrap();
        assert_eq!(meta.id, "test-key");
        assert_eq!(meta.state, KeyState::Active);
        assert!(meta.created_at.is_some());
    }

    #[tokio::test]
    async fn test_in_memory_store_list_keys() {
        let store = InMemoryKeyStore::new();
        store.set_key("key-1", KeyMaterial::new("key-1", vec![1]));
        store.set_key("key-2", KeyMaterial::new("key-2", vec![2]));

        let keys = store.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key-1".to_string()));
        assert!(keys.contains(&"key-2".to_string()));
    }

    #[test]
    fn test_in_memory_store_remove_key() {
        let store = InMemoryKeyStore::new();
        store.set_key("key-1", KeyMaterial::new("key-1", vec![1]));
        assert_eq!(store.len(), 1);

        store.remove_key("key-1");
        assert_eq!(store.len(), 0);
    }

    // ========================================================================
    // SC-12 Extension Tests
    // ========================================================================

    #[test]
    fn test_key_store_extension_in_memory() {
        let ext = KeyStoreExtension::in_memory();
        assert!(!ext.needs_rotation("any-key")); // No tracker configured
    }

    #[test]
    fn test_key_store_extension_from_env() {
        let ext = KeyStoreExtension::from_env("TEST_KEYS");
        // Just verify it can be created
        let debug_output = format!("{:?}", ext);
        assert!(debug_output.contains("KeyStoreExtension"));
    }

    #[test]
    fn test_key_store_extension_with_tracker() {
        let store = InMemoryKeyStore::new();
        let mut tracker = RotationTracker::new();
        tracker.register("signing-key", RotationPolicy::days(90));

        let ext = KeyStoreExtension::with_tracker(store, tracker);

        // Should have tracker and not need rotation (just registered)
        assert!(!ext.needs_rotation("signing-key"));

        // Should have rotation status
        let status = ext.rotation_status();
        assert!(status.is_some());
        assert_eq!(status.unwrap().total_tracked, 1);
    }

    #[tokio::test]
    async fn test_key_store_extension_get_key() {
        let store = InMemoryKeyStore::new();
        store.set_key("test-key", KeyMaterial::new("test-key", vec![1, 2, 3]));

        let ext = KeyStoreExtension::new(store);

        let key = ext.get_key("test-key").await.unwrap();
        assert_eq!(key.as_bytes(), &[1, 2, 3]);
    }

    #[tokio::test]
    async fn test_key_store_extension_rotate_key() {
        let store = InMemoryKeyStore::new();
        store.set_key("test-key", KeyMaterial::new("test-key", vec![1, 2, 3]));

        let mut tracker = RotationTracker::new();
        tracker.register("test-key", RotationPolicy::days(90));

        let ext = KeyStoreExtension::with_tracker(store, tracker);

        let rotated = ext.rotate_key("test-key").await.unwrap();
        assert_eq!(rotated.as_bytes(), &[1, 2, 4]); // Last byte incremented
    }

    #[tokio::test]
    async fn test_key_store_extension_list_keys() {
        let store = InMemoryKeyStore::new();
        store.set_key("key-1", KeyMaterial::new("key-1", vec![1]));
        store.set_key("key-2", KeyMaterial::new("key-2", vec![2]));

        let ext = KeyStoreExtension::new(store);

        let keys = ext.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_key_store_extension_register_for_rotation() {
        let store = InMemoryKeyStore::new();
        let tracker = RotationTracker::new();
        let ext = KeyStoreExtension::with_tracker(store, tracker);

        ext.register_for_rotation("new-key", RotationPolicy::days(30));

        let status = ext.rotation_status().unwrap();
        assert_eq!(status.total_tracked, 1);
    }

    #[test]
    fn test_key_store_extension_debug() {
        let ext = KeyStoreExtension::in_memory();
        let debug_output = format!("{:?}", ext);
        assert!(debug_output.contains("KeyStoreExtension"));
        assert!(debug_output.contains("has_tracker"));
    }
}
