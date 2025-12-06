//! Cryptographic utilities for secure operations
//!
//! This module provides security-hardened utilities for common cryptographic operations.
//!
//! ## Security Patterns
//!
//! - **Constant-Time Comparison**: Prevents timing attacks on secret comparisons

use subtle::ConstantTimeEq;

/// Performs constant-time comparison of two byte slices.
///
/// ## Security Rationale
///
/// Standard string comparison (`==`) in most languages uses early-exit optimization:
/// it returns `false` as soon as it finds a mismatching byte. This creates a timing
/// side-channel where an attacker can measure response times to progressively
/// discover secret values one byte at a time.
///
/// ## Implementation
///
/// We use the `subtle` crate which provides cryptographic constant-time operations.
/// The comparison takes the same amount of time regardless of where (or if) the
/// inputs differ.
///
/// ## Usage
///
/// ```rust
/// use barbican::constant_time_eq;
///
/// let stored_hash = b"abc123...";
/// let provided_hash = b"abc123...";
/// if constant_time_eq(stored_hash, provided_hash) {
///     // Secrets match
/// }
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // subtle::ConstantTimeEq returns a Choice, which we convert to bool
    // This comparison takes constant time regardless of input values
    a.ct_eq(b).into()
}

/// Performs constant-time comparison of two strings.
///
/// Convenience wrapper around `constant_time_eq` for string comparisons.
/// See `constant_time_eq` for security rationale.
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
    fn test_empty_strings() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_str_eq("", ""));
    }
}
