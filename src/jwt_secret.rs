//! JWT Secret Validation and Generation
//!
//! Provides environment-aware and compliance-aware validation of JWT secrets
//! to ensure they meet security requirements for signing tokens.
//!
//! # NIST 800-53 Controls
//!
//! - **IA-5**: Authenticator Management - Ensures JWT secrets meet minimum strength requirements
//! - **SC-12**: Cryptographic Key Establishment - Validates key material quality
//!
//! # Features
//!
//! - Environment-based secret length requirements
//! - Compliance profile-based validation (FedRAMP Low/Moderate/High)
//! - Weak pattern detection
//! - Shannon entropy calculation
//! - Character diversity requirements for production
//! - Secure secret generation
//!
//! # Example
//!
//! ```
//! use barbican::jwt_secret::{JwtSecretValidator, JwtSecretPolicy};
//!
//! // Validate a secret for production
//! let policy = JwtSecretPolicy::for_environment("production");
//! match policy.validate("my-secret-key") {
//!     Ok(()) => println!("Secret is valid"),
//!     Err(e) => println!("Secret validation failed: {}", e),
//! }
//!
//! // Generate a secure secret
//! let secret = JwtSecretValidator::generate_secure_secret(64);
//! ```

use std::collections::HashMap;
use std::fmt;

use crate::compliance::ComplianceProfile;

/// Error type for JWT secret validation failures.
#[derive(Debug, Clone, PartialEq)]
pub enum JwtSecretError {
    /// Secret is too short for the required environment/profile
    TooShort {
        actual: usize,
        minimum: usize,
        context: String,
    },
    /// Secret contains a weak/common pattern
    WeakPattern { pattern: String },
    /// Secret has insufficient entropy
    LowEntropy {
        actual: f64,
        minimum: f64,
        context: String,
    },
    /// Secret lacks required character diversity
    InsufficientDiversity { missing: Vec<String> },
}

impl fmt::Display for JwtSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort {
                actual,
                minimum,
                context,
            } => {
                write!(
                    f,
                    "Secret length ({} chars) is below minimum ({} chars) for {}",
                    actual, minimum, context
                )
            }
            Self::WeakPattern { pattern } => {
                write!(f, "Secret contains weak pattern: '{}'", pattern)
            }
            Self::LowEntropy {
                actual,
                minimum,
                context,
            } => {
                write!(
                    f,
                    "Secret entropy ({:.1} bits) is below minimum ({:.1} bits) for {}",
                    actual, minimum, context
                )
            }
            Self::InsufficientDiversity { missing } => {
                write!(
                    f,
                    "Secret must contain: {}",
                    missing.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for JwtSecretError {}

/// Result type for JWT secret validation.
pub type JwtSecretResult<T> = Result<T, JwtSecretError>;

/// Policy for JWT secret validation.
///
/// Defines the requirements for a valid JWT secret based on environment
/// or compliance profile.
#[derive(Debug, Clone)]
pub struct JwtSecretPolicy {
    /// Minimum secret length in characters
    pub min_length: usize,
    /// Minimum Shannon entropy in bits
    pub min_entropy: f64,
    /// Whether to require character diversity (upper, lower, digit, special)
    pub require_diversity: bool,
    /// Whether to check for weak patterns
    pub check_weak_patterns: bool,
    /// Context string for error messages
    pub context: String,
}

impl Default for JwtSecretPolicy {
    fn default() -> Self {
        Self::for_environment("development")
    }
}

impl JwtSecretPolicy {
    /// Create a policy for a specific environment.
    ///
    /// # Environments
    ///
    /// - `production`: 64 char min, 128-bit entropy, diversity required
    /// - `staging`: 48 char min, 96-bit entropy, diversity required
    /// - `testing`: 32 char min, 64-bit entropy
    /// - `development` (default): 32 char min, 32-bit entropy
    pub fn for_environment(environment: &str) -> Self {
        match environment.to_lowercase().as_str() {
            "production" | "prod" => Self {
                min_length: 64,
                min_entropy: 128.0,
                require_diversity: true,
                check_weak_patterns: true,
                context: "production environment".to_string(),
            },
            "staging" | "stage" => Self {
                min_length: 48,
                min_entropy: 96.0,
                require_diversity: true,
                check_weak_patterns: true,
                context: "staging environment".to_string(),
            },
            "testing" | "test" => Self {
                min_length: 32,
                min_entropy: 64.0,
                require_diversity: false,
                check_weak_patterns: true,
                context: "testing environment".to_string(),
            },
            _ => Self {
                min_length: 32,
                min_entropy: 32.0,
                require_diversity: false,
                check_weak_patterns: true,
                context: "development environment".to_string(),
            },
        }
    }

    /// Create a policy based on compliance profile.
    ///
    /// # Profiles
    ///
    /// - `FedRampHigh`: Most stringent (64 char, 128-bit entropy, diversity)
    /// - `FedRampModerate`/`Soc2`: Standard (48 char, 96-bit entropy, diversity)
    /// - `FedRampLow`: Basic (32 char, 64-bit entropy)
    /// - `Custom`: Relaxed (32 char, 32-bit entropy)
    pub fn for_compliance(profile: ComplianceProfile) -> Self {
        match profile {
            ComplianceProfile::FedRampHigh => Self {
                min_length: 64,
                min_entropy: 128.0,
                require_diversity: true,
                check_weak_patterns: true,
                context: format!("{} compliance", profile.name()),
            },
            ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => Self {
                min_length: 48,
                min_entropy: 96.0,
                require_diversity: true,
                check_weak_patterns: true,
                context: format!("{} compliance", profile.name()),
            },
            ComplianceProfile::FedRampLow => Self {
                min_length: 32,
                min_entropy: 64.0,
                require_diversity: false,
                check_weak_patterns: true,
                context: format!("{} compliance", profile.name()),
            },
            ComplianceProfile::Custom => Self {
                min_length: 32,
                min_entropy: 32.0,
                require_diversity: false,
                check_weak_patterns: true,
                context: "custom profile".to_string(),
            },
        }
    }

    /// Validate a secret against this policy.
    pub fn validate(&self, secret: &str) -> JwtSecretResult<()> {
        // Check minimum length
        if secret.len() < self.min_length {
            return Err(JwtSecretError::TooShort {
                actual: secret.len(),
                minimum: self.min_length,
                context: self.context.clone(),
            });
        }

        // Check for weak patterns
        if self.check_weak_patterns {
            if let Some(pattern) = Self::find_weak_pattern(secret) {
                return Err(JwtSecretError::WeakPattern {
                    pattern: pattern.to_string(),
                });
            }
        }

        // Check entropy
        let entropy = JwtSecretValidator::calculate_entropy(secret);
        if entropy < self.min_entropy {
            return Err(JwtSecretError::LowEntropy {
                actual: entropy,
                minimum: self.min_entropy,
                context: self.context.clone(),
            });
        }

        // Check character diversity
        if self.require_diversity {
            let missing = Self::check_diversity(secret);
            if !missing.is_empty() {
                return Err(JwtSecretError::InsufficientDiversity { missing });
            }
        }

        Ok(())
    }

    /// Check for weak patterns in the secret.
    fn find_weak_pattern(secret: &str) -> Option<&'static str> {
        const WEAK_PATTERNS: &[&str] = &[
            "secret", "password", "admin", "123456", "qwerty", "default",
            "example", "test", "demo", "sample", "temp", "changeme",
            "letmein", "welcome", "monkey", "dragon", "master",
        ];

        let secret_lower = secret.to_lowercase();
        for pattern in WEAK_PATTERNS {
            if secret_lower.contains(pattern) {
                return Some(pattern);
            }
        }
        None
    }

    /// Check character diversity and return missing categories.
    fn check_diversity(secret: &str) -> Vec<String> {
        let mut missing = Vec::new();

        if !secret.chars().any(|c| c.is_uppercase()) {
            missing.push("uppercase letters".to_string());
        }
        if !secret.chars().any(|c| c.is_lowercase()) {
            missing.push("lowercase letters".to_string());
        }
        if !secret.chars().any(|c| c.is_ascii_digit()) {
            missing.push("digits".to_string());
        }
        if !secret.chars().any(|c| !c.is_alphanumeric() && !c.is_whitespace()) {
            missing.push("special characters".to_string());
        }

        missing
    }
}

/// JWT secret validation utilities.
///
/// Provides static methods for validating and generating JWT secrets.
pub struct JwtSecretValidator;

impl JwtSecretValidator {
    /// Validate a JWT secret for a specific environment.
    ///
    /// This is a convenience method that creates a policy and validates.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret to validate
    /// * `environment` - Environment name (production, staging, testing, development)
    ///
    /// # Example
    ///
    /// ```
    /// use barbican::jwt_secret::JwtSecretValidator;
    ///
    /// let result = JwtSecretValidator::validate_for_environment(
    ///     "my-super-secret-key-that-is-very-long-and-complex!@#$",
    ///     "development"
    /// );
    /// ```
    pub fn validate_for_environment(secret: &str, environment: &str) -> JwtSecretResult<()> {
        let policy = JwtSecretPolicy::for_environment(environment);
        policy.validate(secret)
    }

    /// Validate a JWT secret for a compliance profile.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret to validate
    /// * `profile` - The compliance profile to validate against
    ///
    /// # Example
    ///
    /// ```
    /// use barbican::jwt_secret::JwtSecretValidator;
    /// use barbican::compliance::ComplianceProfile;
    ///
    /// let result = JwtSecretValidator::validate_for_compliance(
    ///     "my-super-secret-key",
    ///     ComplianceProfile::FedRampModerate
    /// );
    /// ```
    pub fn validate_for_compliance(
        secret: &str,
        profile: ComplianceProfile,
    ) -> JwtSecretResult<()> {
        let policy = JwtSecretPolicy::for_compliance(profile);
        policy.validate(secret)
    }

    /// Calculate Shannon entropy of a string in bits.
    ///
    /// Higher entropy indicates more randomness/unpredictability.
    ///
    /// # Example
    ///
    /// ```
    /// use barbican::jwt_secret::JwtSecretValidator;
    ///
    /// let entropy = JwtSecretValidator::calculate_entropy("aaaaaa");
    /// assert!(entropy < 10.0); // Low entropy (repeated chars)
    ///
    /// let entropy = JwtSecretValidator::calculate_entropy("aB3$xY9!");
    /// assert!(entropy > 20.0); // Higher entropy (diverse chars)
    /// ```
    pub fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts: HashMap<char, usize> = HashMap::new();
        let total = s.len() as f64;

        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let mut entropy = 0.0;
        for count in char_counts.values() {
            let probability = *count as f64 / total;
            entropy -= probability * probability.log2();
        }

        // Return total entropy (entropy per char * length)
        entropy * total
    }

    /// Generate a cryptographically secure random secret.
    ///
    /// Generates a secret using a secure random number generator with
    /// characters from: A-Z, a-z, 0-9, and special characters.
    ///
    /// # Arguments
    ///
    /// * `length` - The desired length of the secret
    ///
    /// # Example
    ///
    /// ```
    /// use barbican::jwt_secret::JwtSecretValidator;
    ///
    /// let secret = JwtSecretValidator::generate_secure_secret(64);
    /// assert_eq!(secret.len(), 64);
    /// ```
    pub fn generate_secure_secret(length: usize) -> String {
        use rand::Rng;

        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`";

        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate a secret that meets the requirements for a specific environment.
    ///
    /// Generates a secret and validates it meets the environment's requirements.
    /// Will retry up to 10 times if the generated secret doesn't meet entropy
    /// requirements (highly unlikely with proper length).
    ///
    /// # Arguments
    ///
    /// * `environment` - Target environment (production, staging, etc.)
    ///
    /// # Returns
    ///
    /// A secret that passes validation for the specified environment.
    pub fn generate_for_environment(environment: &str) -> String {
        let policy = JwtSecretPolicy::for_environment(environment);

        // Use appropriate length for the environment
        let length = policy.min_length.max(64);

        for _ in 0..10 {
            let secret = Self::generate_secure_secret(length);
            if policy.validate(&secret).is_ok() {
                return secret;
            }
        }

        // Fallback: generate a longer secret that will definitely pass
        Self::generate_secure_secret(length + 32)
    }

    /// Generate a secret that meets compliance profile requirements.
    ///
    /// # Arguments
    ///
    /// * `profile` - Target compliance profile
    ///
    /// # Returns
    ///
    /// A secret that passes validation for the specified compliance profile.
    pub fn generate_for_compliance(profile: ComplianceProfile) -> String {
        let policy = JwtSecretPolicy::for_compliance(profile);
        let length = policy.min_length.max(64);

        for _ in 0..10 {
            let secret = Self::generate_secure_secret(length);
            if policy.validate(&secret).is_ok() {
                return secret;
            }
        }

        Self::generate_secure_secret(length + 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_for_environment() {
        let prod = JwtSecretPolicy::for_environment("production");
        assert_eq!(prod.min_length, 64);
        assert!(prod.require_diversity);

        let dev = JwtSecretPolicy::for_environment("development");
        assert_eq!(dev.min_length, 32);
        assert!(!dev.require_diversity);
    }

    #[test]
    fn test_policy_for_compliance() {
        let high = JwtSecretPolicy::for_compliance(ComplianceProfile::FedRampHigh);
        assert_eq!(high.min_length, 64);
        assert_eq!(high.min_entropy, 128.0);

        let low = JwtSecretPolicy::for_compliance(ComplianceProfile::FedRampLow);
        assert_eq!(low.min_length, 32);
        assert!(!low.require_diversity);
    }

    #[test]
    fn test_validate_too_short() {
        let policy = JwtSecretPolicy::for_environment("production");
        let result = policy.validate("short");

        assert!(matches!(result, Err(JwtSecretError::TooShort { .. })));
    }

    #[test]
    fn test_validate_weak_pattern() {
        let policy = JwtSecretPolicy::for_environment("development");
        // Long enough but contains "password"
        let result = policy.validate("this-is-a-password-that-is-long-enough");

        assert!(matches!(result, Err(JwtSecretError::WeakPattern { .. })));
    }

    #[test]
    fn test_validate_low_entropy() {
        let policy = JwtSecretPolicy::for_environment("production");
        // Long enough but low entropy (repeated chars)
        let result = policy.validate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        assert!(matches!(result, Err(JwtSecretError::LowEntropy { .. })));
    }

    #[test]
    fn test_validate_insufficient_diversity() {
        let mut policy = JwtSecretPolicy::for_environment("production");
        policy.min_entropy = 10.0; // Lower entropy requirement for this test

        // Has length and entropy but only lowercase
        let result = policy.validate("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl");

        assert!(matches!(result, Err(JwtSecretError::InsufficientDiversity { .. })));
    }

    #[test]
    fn test_calculate_entropy() {
        // Low entropy (all same character)
        let low = JwtSecretValidator::calculate_entropy("aaaaaaaaaa");
        assert!(low < 1.0);

        // Higher entropy (diverse characters)
        let high = JwtSecretValidator::calculate_entropy("aB3$xY9!pQ");
        assert!(high > 30.0);

        // Empty string
        let empty = JwtSecretValidator::calculate_entropy("");
        assert_eq!(empty, 0.0);
    }

    #[test]
    fn test_generate_secure_secret() {
        let secret = JwtSecretValidator::generate_secure_secret(64);
        assert_eq!(secret.len(), 64);

        // Should have reasonable entropy
        let entropy = JwtSecretValidator::calculate_entropy(&secret);
        assert!(entropy > 100.0);
    }

    #[test]
    fn test_generate_for_environment() {
        let secret = JwtSecretValidator::generate_for_environment("production");

        // Should pass production validation
        let policy = JwtSecretPolicy::for_environment("production");
        assert!(policy.validate(&secret).is_ok());
    }

    #[test]
    fn test_generate_for_compliance() {
        let secret = JwtSecretValidator::generate_for_compliance(ComplianceProfile::FedRampHigh);

        // Should pass FedRAMP High validation
        let policy = JwtSecretPolicy::for_compliance(ComplianceProfile::FedRampHigh);
        assert!(policy.validate(&secret).is_ok());
    }

    #[test]
    fn test_valid_secret_passes() {
        let secret = JwtSecretValidator::generate_secure_secret(64);

        // Should pass development validation
        let result = JwtSecretValidator::validate_for_environment(&secret, "development");
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_display() {
        let err = JwtSecretError::TooShort {
            actual: 10,
            minimum: 64,
            context: "production".to_string(),
        };
        assert!(err.to_string().contains("10"));
        assert!(err.to_string().contains("64"));

        let err = JwtSecretError::WeakPattern {
            pattern: "password".to_string(),
        };
        assert!(err.to_string().contains("password"));
    }
}
