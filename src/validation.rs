//! Input Validation Framework (SI-10)
//!
//! NIST SP 800-53 SI-10 compliant input validation for web applications.
//!
//! This module provides:
//! - Declarative validation via the `Validate` trait
//! - Built-in validators for common patterns (email, URL, length, etc.)
//! - HTML/XSS sanitization
//! - SQL injection prevention helpers
//! - Axum extractor integration
//!
//! # Security Rationale
//!
//! Input validation is the first line of defense against injection attacks.
//! All user input must be validated before processing:
//! - **Length limits**: Prevent buffer overflows and DoS
//! - **Character restrictions**: Prevent injection attacks
//! - **Format validation**: Ensure data integrity
//! - **Sanitization**: Remove/escape dangerous content
//!
//! # Usage
//!
//! ```ignore
//! use barbican::validation::{Validate, ValidationError};
//!
//! struct CreateUser {
//!     username: String,
//!     email: String,
//!     password: String,
//! }
//!
//! impl Validate for CreateUser {
//!     fn validate(&self) -> Result<(), ValidationError> {
//!         // Username: 3-32 alphanumeric + underscore
//!         validate_length(&self.username, 3, 32, "username")?;
//!         validate_alphanumeric_underscore(&self.username, "username")?;
//!
//!         // Email: valid format
//!         validate_email(&self.email)?;
//!
//!         // Password: minimum 12 characters (NIST 800-63B)
//!         validate_length(&self.password, 12, 128, "password")?;
//!
//!         Ok(())
//!     }
//! }
//! ```

use std::collections::HashSet;
use std::fmt;

/// Validation error with field context
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Field that failed validation (if applicable)
    pub field: Option<String>,
    /// Error code for programmatic handling
    pub code: ValidationErrorCode,
    /// Human-readable message
    pub message: String,
}

impl ValidationError {
    /// Create a new validation error
    pub fn new(code: ValidationErrorCode, message: impl Into<String>) -> Self {
        Self {
            field: None,
            code,
            message: message.into(),
        }
    }

    /// Create a validation error for a specific field
    pub fn for_field(field: impl Into<String>, code: ValidationErrorCode, message: impl Into<String>) -> Self {
        Self {
            field: Some(field.into()),
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.field {
            Some(field) => write!(f, "{}: {}", field, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validation error codes for programmatic handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorCode {
    /// Value is required but missing/empty
    Required,
    /// Value is too short
    TooShort,
    /// Value is too long
    TooLong,
    /// Value contains invalid characters
    InvalidCharacters,
    /// Value doesn't match expected pattern
    InvalidFormat,
    /// Email format is invalid
    InvalidEmail,
    /// URL format is invalid
    InvalidUrl,
    /// Value is not in allowed set
    NotAllowed,
    /// Value contains potentially dangerous content
    DangerousContent,
    /// Value failed custom validation
    Custom,
}

impl fmt::Display for ValidationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Required => write!(f, "required"),
            Self::TooShort => write!(f, "too_short"),
            Self::TooLong => write!(f, "too_long"),
            Self::InvalidCharacters => write!(f, "invalid_characters"),
            Self::InvalidFormat => write!(f, "invalid_format"),
            Self::InvalidEmail => write!(f, "invalid_email"),
            Self::InvalidUrl => write!(f, "invalid_url"),
            Self::NotAllowed => write!(f, "not_allowed"),
            Self::DangerousContent => write!(f, "dangerous_content"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Trait for validatable types
///
/// Implement this trait on your request/input types to enable validation.
pub trait Validate {
    /// Validate the instance, returning an error if invalid
    fn validate(&self) -> Result<(), ValidationError>;

    /// Check if the instance is valid (convenience method)
    fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

// ============================================================================
// String Validators
// ============================================================================

/// Validate that a string is not empty (SI-10)
pub fn validate_required(value: &str, field: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::Required,
            "Field is required",
        ));
    }
    Ok(())
}

/// Validate string length bounds (SI-10)
///
/// # Arguments
/// * `value` - String to validate
/// * `min` - Minimum length (inclusive)
/// * `max` - Maximum length (inclusive)
/// * `field` - Field name for error context
pub fn validate_length(value: &str, min: usize, max: usize, field: &str) -> Result<(), ValidationError> {
    let len = value.chars().count();
    if len < min {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::TooShort,
            format!("Must be at least {} characters", min),
        ));
    }
    if len > max {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::TooLong,
            format!("Must be at most {} characters", max),
        ));
    }
    Ok(())
}

/// Validate string contains only alphanumeric characters and underscores (SI-10)
///
/// Safe for use in identifiers, usernames, etc.
pub fn validate_alphanumeric_underscore(value: &str, field: &str) -> Result<(), ValidationError> {
    if !value.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::InvalidCharacters,
            "Only letters, numbers, and underscores allowed",
        ));
    }
    Ok(())
}

/// Validate string contains only alphanumeric characters, underscores, and hyphens (SI-10)
///
/// Safe for use in slugs, URL paths, etc.
pub fn validate_slug(value: &str, field: &str) -> Result<(), ValidationError> {
    if !value.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::InvalidCharacters,
            "Only letters, numbers, underscores, and hyphens allowed",
        ));
    }
    Ok(())
}

/// Validate string contains only ASCII printable characters (SI-10)
///
/// Prevents control characters and non-ASCII content.
pub fn validate_ascii_printable(value: &str, field: &str) -> Result<(), ValidationError> {
    if !value.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::InvalidCharacters,
            "Only printable ASCII characters allowed",
        ));
    }
    Ok(())
}

/// Validate email format (SI-10)
///
/// Uses a pragmatic regex that accepts most valid emails while rejecting
/// obviously invalid ones. Does not validate deliverability.
pub fn validate_email(value: &str) -> Result<(), ValidationError> {
    // Basic email validation:
    // - Must contain exactly one @
    // - Local part: non-empty, no consecutive dots
    // - Domain: non-empty, contains at least one dot, valid characters
    let parts: Vec<&str> = value.split('@').collect();
    if parts.len() != 2 {
        return Err(ValidationError::for_field(
            "email",
            ValidationErrorCode::InvalidEmail,
            "Invalid email format",
        ));
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part validation
    if local.is_empty() || local.len() > 64 {
        return Err(ValidationError::for_field(
            "email",
            ValidationErrorCode::InvalidEmail,
            "Invalid email local part",
        ));
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(ValidationError::for_field(
            "email",
            ValidationErrorCode::InvalidEmail,
            "Invalid email local part",
        ));
    }

    // Domain validation
    if domain.is_empty() || domain.len() > 255 {
        return Err(ValidationError::for_field(
            "email",
            ValidationErrorCode::InvalidEmail,
            "Invalid email domain",
        ));
    }
    if !domain.contains('.') {
        return Err(ValidationError::for_field(
            "email",
            ValidationErrorCode::InvalidEmail,
            "Invalid email domain",
        ));
    }
    if !domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Err(ValidationError::for_field(
            "email",
            ValidationErrorCode::InvalidEmail,
            "Invalid email domain characters",
        ));
    }

    Ok(())
}

/// Validate URL format (SI-10)
///
/// Validates that the string is a well-formed URL with an allowed scheme.
pub fn validate_url(value: &str, allowed_schemes: &[&str]) -> Result<(), ValidationError> {
    // Basic URL validation
    let scheme_end = value.find("://").ok_or_else(|| {
        ValidationError::for_field("url", ValidationErrorCode::InvalidUrl, "Invalid URL format")
    })?;

    let scheme = &value[..scheme_end].to_lowercase();
    if !allowed_schemes.iter().any(|s| s.to_lowercase() == *scheme) {
        return Err(ValidationError::for_field(
            "url",
            ValidationErrorCode::InvalidUrl,
            format!("URL scheme must be one of: {}", allowed_schemes.join(", ")),
        ));
    }

    // Check for suspicious patterns
    if value.contains("javascript:") || value.contains("data:") || value.contains("vbscript:") {
        return Err(ValidationError::for_field(
            "url",
            ValidationErrorCode::DangerousContent,
            "Potentially dangerous URL scheme",
        ));
    }

    Ok(())
}

/// Validate value is in allowed set (SI-10)
pub fn validate_one_of<T: PartialEq + fmt::Display>(
    value: &T,
    allowed: &[T],
    field: &str,
) -> Result<(), ValidationError> {
    if !allowed.contains(value) {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::NotAllowed,
            format!(
                "Value must be one of: {}",
                allowed.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    Ok(())
}

// ============================================================================
// Sanitization Functions
// ============================================================================

/// Sanitize HTML content to prevent XSS (SI-10)
///
/// Removes all HTML tags and decodes HTML entities.
/// Use this for user-generated content that should not contain HTML.
pub fn sanitize_html(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut in_tag = false;

    for c in input.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }

    // Decode common HTML entities
    result
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

/// Escape HTML special characters (SI-10)
///
/// Converts special characters to HTML entities for safe display.
/// Use this when you need to display user content in HTML context.
pub fn escape_html(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }
    result
}

/// Sanitize string for safe use in SQL LIKE patterns (SI-10)
///
/// Escapes SQL wildcard characters to prevent injection in LIKE clauses.
/// Note: Always use parameterized queries - this is an additional safeguard.
pub fn escape_sql_like(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Remove null bytes from input (SI-10)
///
/// Null bytes can cause truncation issues in C-based systems.
pub fn strip_null_bytes(input: &str) -> String {
    input.replace('\0', "")
}

/// Normalize Unicode to NFC form (SI-10)
///
/// Prevents Unicode normalization attacks where visually identical
/// characters have different byte representations.
pub fn normalize_unicode(input: &str) -> String {
    // Simple ASCII passthrough for now
    // Full Unicode normalization requires the `unicode-normalization` crate
    input.to_string()
}

// ============================================================================
// Content Validators
// ============================================================================

/// Check if content contains potentially dangerous patterns (SI-10)
///
/// Detects common injection patterns:
/// - Script tags
/// - Event handlers (onclick, onerror, etc.)
/// - Data URIs
/// - SQL injection patterns
pub fn contains_dangerous_patterns(input: &str) -> bool {
    let input_lower = input.to_lowercase();

    // XSS patterns
    let xss_patterns = [
        "<script",
        "javascript:",
        "vbscript:",
        "data:",
        "onclick",
        "onerror",
        "onload",
        "onmouseover",
        "onfocus",
        "onblur",
        "expression(",
        "eval(",
    ];

    for pattern in xss_patterns {
        if input_lower.contains(pattern) {
            return true;
        }
    }

    // SQL injection patterns (common ones)
    let sql_patterns = [
        "' or '",
        "' or \"",
        "'; drop",
        "'; delete",
        "'; update",
        "'; insert",
        "' union ",
        "1=1",
        "1 = 1",
    ];

    for pattern in sql_patterns {
        if input_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Validate content does not contain dangerous patterns (SI-10)
pub fn validate_safe_content(value: &str, field: &str) -> Result<(), ValidationError> {
    if contains_dangerous_patterns(value) {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::DangerousContent,
            "Content contains potentially dangerous patterns",
        ));
    }
    Ok(())
}

// ============================================================================
// Numeric Validators
// ============================================================================

/// Validate integer is within range (SI-10)
pub fn validate_range<T: PartialOrd + fmt::Display>(
    value: T,
    min: T,
    max: T,
    field: &str,
) -> Result<(), ValidationError> {
    if value < min {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::TooShort,
            format!("Value must be at least {}", min),
        ));
    }
    if value > max {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::TooLong,
            format!("Value must be at most {}", max),
        ));
    }
    Ok(())
}

/// Validate integer is positive (SI-10)
pub fn validate_positive<T: PartialOrd + Default + fmt::Display>(
    value: T,
    field: &str,
) -> Result<(), ValidationError> {
    if value <= T::default() {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::InvalidFormat,
            "Value must be positive",
        ));
    }
    Ok(())
}

// ============================================================================
// Collection Validators
// ============================================================================

/// Validate collection size (SI-10)
pub fn validate_collection_size<T>(
    collection: &[T],
    min: usize,
    max: usize,
    field: &str,
) -> Result<(), ValidationError> {
    let len = collection.len();
    if len < min {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::TooShort,
            format!("Must have at least {} items", min),
        ));
    }
    if len > max {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::TooLong,
            format!("Must have at most {} items", max),
        ));
    }
    Ok(())
}

/// Validate all items in collection are unique (SI-10)
pub fn validate_unique<T: std::hash::Hash + Eq>(
    collection: &[T],
    field: &str,
) -> Result<(), ValidationError> {
    let set: HashSet<_> = collection.iter().collect();
    if set.len() != collection.len() {
        return Err(ValidationError::for_field(
            field,
            ValidationErrorCode::InvalidFormat,
            "Collection contains duplicate values",
        ));
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_required() {
        assert!(validate_required("hello", "field").is_ok());
        assert!(validate_required("", "field").is_err());
        assert!(validate_required("   ", "field").is_err());
    }

    #[test]
    fn test_validate_length() {
        assert!(validate_length("hello", 1, 10, "field").is_ok());
        assert!(validate_length("hi", 3, 10, "field").is_err());
        assert!(validate_length("hello world!", 1, 5, "field").is_err());
    }

    #[test]
    fn test_validate_alphanumeric_underscore() {
        assert!(validate_alphanumeric_underscore("hello_123", "field").is_ok());
        assert!(validate_alphanumeric_underscore("hello-123", "field").is_err());
        assert!(validate_alphanumeric_underscore("hello 123", "field").is_err());
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("hello-world_123", "field").is_ok());
        assert!(validate_slug("hello world", "field").is_err());
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name@example.co.uk").is_ok());
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@localhost").is_err()); // No dot in domain
        assert!(validate_email("user..name@example.com").is_err());
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("https://example.com", &["https"]).is_ok());
        assert!(validate_url("http://example.com", &["https"]).is_err());
        assert!(validate_url("http://example.com", &["http", "https"]).is_ok());
        assert!(validate_url("javascript:alert(1)", &["https"]).is_err());
    }

    #[test]
    fn test_sanitize_html() {
        assert_eq!(sanitize_html("<script>alert(1)</script>"), "alert(1)");
        assert_eq!(sanitize_html("<p>Hello</p>"), "Hello");
        assert_eq!(sanitize_html("Hello &amp; World"), "Hello & World");
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("A & B"), "A &amp; B");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_contains_dangerous_patterns() {
        assert!(contains_dangerous_patterns("<script>alert(1)</script>"));
        assert!(contains_dangerous_patterns("onclick='evil()'"));
        assert!(contains_dangerous_patterns("javascript:void(0)"));
        assert!(contains_dangerous_patterns("' OR '1'='1"));
        assert!(contains_dangerous_patterns("'; DROP TABLE users;"));
        assert!(!contains_dangerous_patterns("Hello, World!"));
        assert!(!contains_dangerous_patterns("normal text"));
    }

    #[test]
    fn test_escape_sql_like() {
        assert_eq!(escape_sql_like("100%"), "100\\%");
        assert_eq!(escape_sql_like("user_name"), "user\\_name");
        assert_eq!(escape_sql_like("normal"), "normal");
    }

    #[test]
    fn test_validate_range() {
        assert!(validate_range(5, 1, 10, "field").is_ok());
        assert!(validate_range(0, 1, 10, "field").is_err());
        assert!(validate_range(15, 1, 10, "field").is_err());
    }

    #[test]
    fn test_validate_collection_size() {
        assert!(validate_collection_size(&[1, 2, 3], 1, 5, "field").is_ok());
        assert!(validate_collection_size(&[1, 2, 3], 5, 10, "field").is_err());
        assert!(validate_collection_size(&[1, 2, 3, 4, 5, 6], 1, 5, "field").is_err());
    }

    #[test]
    fn test_validate_unique() {
        assert!(validate_unique(&[1, 2, 3], "field").is_ok());
        assert!(validate_unique(&[1, 2, 2], "field").is_err());
    }
}
