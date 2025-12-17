//! Password Policy Enforcement (IA-5(1))
//!
//! NIST SP 800-53 IA-5(1) and NIST SP 800-63B compliant password policy
//! for applications that implement local authentication.
//!
//! # When to Use This Module
//!
//! Use this module when your application:
//! - Implements local username/password authentication
//! - Needs to validate passwords during registration or change
//! - Requires compliance with NIST password guidelines
//!
//! # When NOT to Use This Module
//!
//! Skip this module when:
//! - Using OAuth/OIDC exclusively (password policy is the IdP's responsibility)
//! - Using passwordless authentication (WebAuthn, passkeys)
//!
//! # NIST 800-63B Guidelines
//!
//! Modern password guidance from NIST 800-63B:
//! - Minimum 8 characters (we default to 12 for higher security)
//! - Maximum at least 64 characters (we default to 128)
//! - No composition rules (uppercase, special chars) - they reduce security
//! - No periodic expiration - only change on compromise
//! - Check against breach databases (Have I Been Pwned)
//! - Check against common password lists
//!
//! # Usage
//!
//! ```ignore
//! use barbican::password::{PasswordPolicy, PasswordError};
//!
//! let policy = PasswordPolicy::default(); // NIST-compliant defaults
//!
//! // Validate a password
//! match policy.validate("user-chosen-password") {
//!     Ok(()) => println!("Password is valid"),
//!     Err(e) => println!("Password rejected: {}", e),
//! }
//!
//! // Custom policy
//! let strict_policy = PasswordPolicy::builder()
//!     .min_length(16)
//!     .check_common_passwords(true)
//!     .check_breach_database(true)
//!     .build();
//! ```

use std::collections::HashSet;
use std::fmt;

// ============================================================================
// Password Policy Configuration
// ============================================================================

/// Password policy configuration (IA-5(1))
///
/// Implements NIST SP 800-63B guidelines for memorized secrets.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum password length (NIST minimum: 8, recommended: 12+)
    pub min_length: usize,

    /// Maximum password length (NIST: at least 64)
    pub max_length: usize,

    /// Check against common password list
    pub check_common_passwords: bool,

    /// Check against Have I Been Pwned breach database
    /// Note: Requires async and network access
    pub check_breach_database: bool,

    /// Disallow passwords containing the username
    pub disallow_username_in_password: bool,

    /// Disallow passwords containing the email
    pub disallow_email_in_password: bool,

    /// Custom blocked passwords (application-specific)
    pub blocked_passwords: HashSet<String>,

    /// Require password to not be entirely numeric
    pub disallow_all_numeric: bool,
}

impl Default for PasswordPolicy {
    /// Create a NIST 800-63B compliant default policy
    fn default() -> Self {
        Self {
            min_length: 12,                    // Higher than NIST minimum for security
            max_length: 128,                   // Support long passphrases
            check_common_passwords: true,      // Block common passwords
            check_breach_database: false,      // Requires async, opt-in
            disallow_username_in_password: true,
            disallow_email_in_password: true,
            blocked_passwords: HashSet::new(),
            disallow_all_numeric: true,        // PIN-like passwords are weak
        }
    }
}

impl PasswordPolicy {
    /// Create a new builder for custom policy configuration
    pub fn builder() -> PasswordPolicyBuilder {
        PasswordPolicyBuilder::default()
    }

    /// Create a minimal policy (for testing only)
    pub fn minimal() -> Self {
        Self {
            min_length: 1,
            max_length: 128,
            check_common_passwords: false,
            check_breach_database: false,
            disallow_username_in_password: false,
            disallow_email_in_password: false,
            blocked_passwords: HashSet::new(),
            disallow_all_numeric: false,
        }
    }

    /// Create policy from compliance configuration
    ///
    /// Derives password requirements from the compliance profile. Higher
    /// profiles require longer passwords and breach database checking.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use barbican::compliance::ComplianceConfig;
    /// use barbican::password::PasswordPolicy;
    ///
    /// let compliance = barbican::compliance::config();
    /// let policy = PasswordPolicy::from_compliance(compliance);
    /// ```
    pub fn from_compliance(config: &crate::compliance::ComplianceConfig) -> Self {
        use crate::compliance::ComplianceProfile;

        let is_low = matches!(config.profile, ComplianceProfile::FedRampLow);

        Self {
            min_length: config.password_min_length,
            max_length: 128,
            check_common_passwords: !is_low,
            check_breach_database: config.password_check_breach_db,
            disallow_username_in_password: true,
            disallow_email_in_password: true,
            blocked_passwords: HashSet::new(),
            disallow_all_numeric: true,
        }
    }

    /// Validate a password against the policy
    pub fn validate(&self, password: &str) -> Result<(), PasswordError> {
        self.validate_with_context(password, None, None)
    }

    /// Validate a password with user context (username, email)
    pub fn validate_with_context(
        &self,
        password: &str,
        username: Option<&str>,
        email: Option<&str>,
    ) -> Result<(), PasswordError> {
        // Length checks
        if password.len() < self.min_length {
            return Err(PasswordError::TooShort {
                min: self.min_length,
                actual: password.len(),
            });
        }

        if password.len() > self.max_length {
            return Err(PasswordError::TooLong {
                max: self.max_length,
                actual: password.len(),
            });
        }

        // All-numeric check
        if self.disallow_all_numeric && password.chars().all(|c| c.is_ascii_digit()) {
            return Err(PasswordError::AllNumeric);
        }

        // Username in password check
        if self.disallow_username_in_password {
            if let Some(username) = username {
                if !username.is_empty() && password.to_lowercase().contains(&username.to_lowercase()) {
                    return Err(PasswordError::ContainsUsername);
                }
            }
        }

        // Email in password check
        if self.disallow_email_in_password {
            if let Some(email) = email {
                // Check local part of email (before @)
                if let Some(local) = email.split('@').next() {
                    if !local.is_empty() && local.len() > 2 && password.to_lowercase().contains(&local.to_lowercase()) {
                        return Err(PasswordError::ContainsEmail);
                    }
                }
            }
        }

        // Custom blocked passwords
        if self.blocked_passwords.contains(&password.to_lowercase()) {
            return Err(PasswordError::Blocked);
        }

        // Common password check
        if self.check_common_passwords && is_common_password(password) {
            return Err(PasswordError::TooCommon);
        }

        Ok(())
    }

    /// Check password against Have I Been Pwned (async)
    ///
    /// This uses the k-anonymity API to check if a password has been
    /// exposed in a data breach without sending the full password.
    ///
    /// # Privacy
    ///
    /// Only the first 5 characters of the SHA-1 hash are sent to the API.
    /// The full hash is never transmitted.
    #[cfg(feature = "hibp")]
    pub async fn check_hibp(&self, password: &str) -> Result<bool, PasswordError> {
        use sha1::{Sha1, Digest};

        // Hash the password
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = format!("{:X}", hasher.finalize());

        // Split into prefix (sent to API) and suffix (checked locally)
        let prefix = &hash[..5];
        let suffix = &hash[5..];

        // Query the API
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let response = reqwest::get(&url)
            .await
            .map_err(|e| PasswordError::HibpError(e.to_string()))?
            .text()
            .await
            .map_err(|e| PasswordError::HibpError(e.to_string()))?;

        // Check if our suffix appears in the response
        for line in response.lines() {
            if let Some((hash_suffix, _count)) = line.split_once(':') {
                if hash_suffix.eq_ignore_ascii_case(suffix) {
                    return Ok(true); // Password found in breach
                }
            }
        }

        Ok(false) // Password not found in breaches
    }

    /// Estimate password strength (informational, not for validation)
    pub fn estimate_strength(&self, password: &str) -> PasswordStrength {
        let len = password.len();
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        let char_types = [has_lower, has_upper, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();

        // Simple entropy-based estimation
        if len < 8 {
            PasswordStrength::VeryWeak
        } else if len < 12 && char_types < 2 {
            PasswordStrength::Weak
        } else if len < 12 {
            PasswordStrength::Fair
        } else if len < 16 || char_types < 3 {
            PasswordStrength::Good
        } else if len >= 16 && char_types >= 3 {
            PasswordStrength::Strong
        } else {
            PasswordStrength::Good
        }
    }
}

/// Builder for PasswordPolicy
#[derive(Debug, Clone, Default)]
pub struct PasswordPolicyBuilder {
    policy: PasswordPolicy,
}

impl PasswordPolicyBuilder {
    /// Set minimum password length
    pub fn min_length(mut self, len: usize) -> Self {
        self.policy.min_length = len;
        self
    }

    /// Set maximum password length
    pub fn max_length(mut self, len: usize) -> Self {
        self.policy.max_length = len;
        self
    }

    /// Enable/disable common password checking
    pub fn check_common_passwords(mut self, check: bool) -> Self {
        self.policy.check_common_passwords = check;
        self
    }

    /// Enable/disable Have I Been Pwned checking
    pub fn check_breach_database(mut self, check: bool) -> Self {
        self.policy.check_breach_database = check;
        self
    }

    /// Enable/disable username-in-password check
    pub fn disallow_username_in_password(mut self, disallow: bool) -> Self {
        self.policy.disallow_username_in_password = disallow;
        self
    }

    /// Enable/disable email-in-password check
    pub fn disallow_email_in_password(mut self, disallow: bool) -> Self {
        self.policy.disallow_email_in_password = disallow;
        self
    }

    /// Add custom blocked passwords
    pub fn block_passwords(mut self, passwords: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.policy.blocked_passwords.extend(
            passwords.into_iter().map(|p| p.into().to_lowercase())
        );
        self
    }

    /// Enable/disable all-numeric password check
    pub fn disallow_all_numeric(mut self, disallow: bool) -> Self {
        self.policy.disallow_all_numeric = disallow;
        self
    }

    /// Build the policy
    pub fn build(self) -> PasswordPolicy {
        self.policy
    }
}

// ============================================================================
// Password Errors
// ============================================================================

/// Password validation errors (IA-5(1))
#[derive(Debug, Clone)]
pub enum PasswordError {
    /// Password is too short
    TooShort { min: usize, actual: usize },
    /// Password is too long
    TooLong { max: usize, actual: usize },
    /// Password is too common
    TooCommon,
    /// Password found in breach database
    Breached,
    /// Password contains username
    ContainsUsername,
    /// Password contains email
    ContainsEmail,
    /// Password is blocked by policy
    Blocked,
    /// Password is all numeric (PIN-like)
    AllNumeric,
    /// Error checking HIBP API
    #[cfg(feature = "hibp")]
    HibpError(String),
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "Password must be at least {} characters (got {})", min, actual)
            }
            Self::TooLong { max, actual } => {
                write!(f, "Password must be at most {} characters (got {})", max, actual)
            }
            Self::TooCommon => write!(f, "Password is too common"),
            Self::Breached => write!(f, "Password has been exposed in a data breach"),
            Self::ContainsUsername => write!(f, "Password cannot contain your username"),
            Self::ContainsEmail => write!(f, "Password cannot contain your email"),
            Self::Blocked => write!(f, "This password is not allowed"),
            Self::AllNumeric => write!(f, "Password cannot be all numbers"),
            #[cfg(feature = "hibp")]
            Self::HibpError(e) => write!(f, "Error checking breach database: {}", e),
        }
    }
}

impl std::error::Error for PasswordError {}

// ============================================================================
// Password Strength (Informational)
// ============================================================================

/// Password strength estimation (informational only)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PasswordStrength {
    /// Very weak - easily guessable
    VeryWeak,
    /// Weak - could be cracked quickly
    Weak,
    /// Fair - acceptable but not ideal
    Fair,
    /// Good - reasonably strong
    Good,
    /// Strong - very difficult to crack
    Strong,
}

impl fmt::Display for PasswordStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VeryWeak => write!(f, "very_weak"),
            Self::Weak => write!(f, "weak"),
            Self::Fair => write!(f, "fair"),
            Self::Good => write!(f, "good"),
            Self::Strong => write!(f, "strong"),
        }
    }
}

// ============================================================================
// Common Password List
// ============================================================================

/// Check if a password is in the common password list or based on common patterns
fn is_common_password(password: &str) -> bool {
    let lower = password.to_lowercase();

    // Direct match
    if COMMON_PASSWORDS.contains(&lower.as_str()) {
        return true;
    }

    // Check if password is a common base with numbers appended
    // e.g., "password123456" should match "password"
    for common in COMMON_PASSWORDS {
        // Only check bases of 4+ characters to avoid false positives
        if common.len() >= 4 && lower.starts_with(common) {
            // Check if the rest is just digits
            let suffix = &lower[common.len()..];
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }

    false
}

/// Top 200 most common passwords (from SecLists)
///
/// This is a subset - for production, consider loading a larger list.
static COMMON_PASSWORDS: &[&str] = &[
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "mobilemail", "mom",
    "monitor", "monitoring", "montana", "moon", "moscow",
    "password1", "password123", "password12", "passw0rd", "admin",
    "admin123", "root", "toor", "pass123", "pass1234",
    "qwerty123", "qwerty1", "welcome", "welcome1", "welcome123",
    "login", "guest", "changeme", "letmein1", "test",
    "test123", "testing", "default", "changethis", "secret",
    // Application/service specific
    "administrator", "postgres", "mysql", "oracle", "redis",
    "mongodb", "elastic", "kafka", "rabbit", "docker",
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_length, 12);
        assert_eq!(policy.max_length, 128);
        assert!(policy.check_common_passwords);
    }

    #[test]
    fn test_length_validation() {
        let policy = PasswordPolicy::default();

        // Too short
        assert!(matches!(
            policy.validate("short"),
            Err(PasswordError::TooShort { .. })
        ));

        // Valid length
        assert!(policy.validate("thisisavalidpassword").is_ok());

        // At minimum
        assert!(policy.validate("exactlytwelv").is_ok());
    }

    #[test]
    fn test_common_password_rejection() {
        let policy = PasswordPolicy::default();

        // Common password with numbers appended (meets min length)
        assert!(matches!(
            policy.validate("password12345"),
            Err(PasswordError::TooCommon)
        ));

        assert!(matches!(
            policy.validate("qwerty123456"),
            Err(PasswordError::TooCommon)
        ));

        // Case insensitive
        assert!(matches!(
            policy.validate("PASSWORD12345"),
            Err(PasswordError::TooCommon)
        ));
    }

    #[test]
    fn test_username_in_password() {
        let policy = PasswordPolicy::default();

        assert!(matches!(
            policy.validate_with_context("johndoe12345", Some("johndoe"), None),
            Err(PasswordError::ContainsUsername)
        ));

        // Case insensitive
        assert!(matches!(
            policy.validate_with_context("JOHNDOE12345", Some("johndoe"), None),
            Err(PasswordError::ContainsUsername)
        ));

        // Without username, should pass
        assert!(policy.validate("johndoe12345").is_ok());
    }

    #[test]
    fn test_email_in_password() {
        let policy = PasswordPolicy::default();

        assert!(matches!(
            policy.validate_with_context("johnsmith1234", None, Some("johnsmith@example.com")),
            Err(PasswordError::ContainsEmail)
        ));
    }

    #[test]
    fn test_all_numeric() {
        let policy = PasswordPolicy::default();

        assert!(matches!(
            policy.validate("123456789012"),
            Err(PasswordError::AllNumeric)
        ));

        // Mixed is fine
        assert!(policy.validate("123456789012a").is_ok());
    }

    #[test]
    fn test_custom_blocked() {
        let policy = PasswordPolicy::builder()
            .min_length(8)
            .block_passwords(vec!["companyname123", "internalpassword"])
            .build();

        assert!(matches!(
            policy.validate("companyname123"),
            Err(PasswordError::Blocked)
        ));

        assert!(matches!(
            policy.validate("COMPANYNAME123"), // Case insensitive
            Err(PasswordError::Blocked)
        ));
    }

    #[test]
    fn test_strength_estimation() {
        let policy = PasswordPolicy::default();

        assert_eq!(policy.estimate_strength("short"), PasswordStrength::VeryWeak);
        // longerpassword has only lowercase, 14 chars -> Good (len >= 12)
        assert_eq!(policy.estimate_strength("longerpassword"), PasswordStrength::Good);
        // LongerPassword1 has upper + lower + digit, 15 chars -> Good
        assert_eq!(policy.estimate_strength("LongerPassword1"), PasswordStrength::Good);
        // VeryL0ng&C0mplexP@ss! has 4 char types, 21 chars -> Strong
        assert_eq!(policy.estimate_strength("VeryL0ng&C0mplexP@ss!"), PasswordStrength::Strong);
    }

    #[test]
    fn test_minimal_policy() {
        let policy = PasswordPolicy::minimal();

        // Should accept anything
        assert!(policy.validate("a").is_ok());
        assert!(policy.validate("password").is_ok());
        assert!(policy.validate("123456").is_ok());
    }

    #[test]
    fn test_builder() {
        let policy = PasswordPolicy::builder()
            .min_length(16)
            .max_length(64)
            .check_common_passwords(false)
            .disallow_all_numeric(false)
            .build();

        assert_eq!(policy.min_length, 16);
        assert_eq!(policy.max_length, 64);
        assert!(!policy.check_common_passwords);
        assert!(!policy.disallow_all_numeric);
    }
}
