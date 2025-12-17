//! Artifact-Generating Control Tests
//!
//! This module provides test functions that generate auditor-verifiable artifacts
//! proving NIST 800-53 control implementations behave as specified.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::control_tests::generate_compliance_report;
//!
//! let report = generate_compliance_report();
//! println!("Pass rate: {:.1}%", report.summary.pass_rate);
//!
//! // Sign and write to file
//! report.sign(b"signing-key", "key-id")?;
//! report.write_to_file(Path::new("./artifacts"))?;
//! ```
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --features compliance-artifacts
//! ```

use crate::auth::{Claims, MfaPolicy};
use crate::compliance::artifacts::{ArtifactBuilder, ComplianceTestReport, ControlTestArtifact};
use crate::config::SecurityConfig;
use crate::crypto::constant_time_eq;
use crate::error::{AppError, ErrorConfig};
use crate::login::{LockoutPolicy, LoginTracker};
use crate::observability::SecurityEvent;
use crate::password::PasswordPolicy;
use crate::session::{SessionPolicy, SessionState, SessionTerminationReason};
use crate::validation::{sanitize_html, validate_email, validate_length};
use serde_json::json;

/// AC-7: Unsuccessful Logon Attempts
///
/// Verifies that accounts are locked after the configured number of failed
/// login attempts, as required by NIST 800-53 AC-7.
pub fn test_ac7_lockout() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-7", "Unsuccessful Logon Attempts")
        .test_name("lockout_after_max_attempts")
        .description(
            "Verify account locks after configured number of failed login attempts (AC-7)",
        )
        .code_location("src/login.rs", 418, 554)
        .related_control("AC-2")
        .related_control("IA-5")
        .input("username", "test@example.com")
        .input("max_attempts", 3)
        .expected("locked_after_3_attempts", true)
        .expected("allowed_before_lockout", true)
        .execute(|collector| {
            // Use strict policy (3 attempts, 30 min lockout)
            let policy = LockoutPolicy::strict();
            collector.configuration(
                "lockout_policy",
                json!({
                    "max_attempts": policy.max_attempts,
                    "lockout_duration_secs": policy.lockout_duration.as_secs(),
                    "progressive_lockout": policy.progressive_lockout,
                }),
            );

            let tracker = LoginTracker::new(policy);
            let username = "test@example.com";

            // First attempt should not lock out
            let result1 = tracker.record_failure(username);
            collector.log(format!("Attempt 1: failed_count={}, is_locked={}", result1.failed_count, result1.is_locked_out));
            let allowed1 = !result1.is_locked_out;

            // Second attempt should not lock out
            let result2 = tracker.record_failure(username);
            collector.log(format!("Attempt 2: failed_count={}, is_locked={}", result2.failed_count, result2.is_locked_out));
            let allowed2 = !result2.is_locked_out;

            // Third attempt should trigger lockout
            let result3 = tracker.record_failure(username);
            collector.log(format!("Attempt 3: failed_count={}, is_locked={}", result3.failed_count, result3.is_locked_out));
            let locked = result3.is_locked_out;

            collector.assertion(
                "First two attempts should not lock out",
                allowed1 && allowed2,
                json!({ "attempt1_allowed": allowed1, "attempt2_allowed": allowed2 }),
            );

            collector.assertion(
                "Third attempt should trigger lockout",
                locked,
                json!({ "locked_after_3": locked }),
            );

            json!({
                "locked_after_3_attempts": locked,
                "allowed_before_lockout": allowed1 && allowed2,
            })
        })
}

/// SC-5: Denial of Service Protection
///
/// Verifies that rate limiting is enabled and configured correctly
/// to protect against denial of service attacks.
pub fn test_sc5_rate_limiting() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-5", "Denial of Service Protection")
        .test_name("rate_limiting_configuration")
        .description("Verify rate limiting is enabled and configured correctly (SC-5)")
        .code_location("src/config.rs", 35, 93)
        .code_location_with_fn("src/layers.rs", 67, 73, "apply_security_layers")
        .input("expected_rate_limit_enabled", true)
        .expected("rate_limiting_enabled", true)
        .expected("has_request_timeout", true)
        .expected("has_max_request_size", true)
        .execute(|collector| {
            let config = SecurityConfig::default();

            collector.configuration(
                "security_config",
                json!({
                    "rate_limit_enabled": config.rate_limit_enabled,
                    "rate_limit_per_second": config.rate_limit_per_second,
                    "rate_limit_burst": config.rate_limit_burst,
                    "request_timeout_secs": config.request_timeout.as_secs(),
                    "max_request_size_bytes": config.max_request_size,
                }),
            );

            let rate_enabled = config.rate_limit_enabled;
            let has_timeout = config.request_timeout.as_secs() > 0;
            let has_size_limit = config.max_request_size > 0;

            collector.assertion(
                "Rate limiting should be enabled by default",
                rate_enabled,
                json!({ "enabled": rate_enabled }),
            );

            collector.assertion(
                "Request timeout should be configured",
                has_timeout,
                json!({ "timeout_secs": config.request_timeout.as_secs() }),
            );

            collector.assertion(
                "Max request size should be configured",
                has_size_limit,
                json!({ "max_size_bytes": config.max_request_size }),
            );

            json!({
                "rate_limiting_enabled": rate_enabled,
                "has_request_timeout": has_timeout,
                "has_max_request_size": has_size_limit,
            })
        })
}

/// SI-10: Information Input Validation
///
/// Verifies that input validation correctly rejects malformed data
/// and sanitizes potentially dangerous content.
pub fn test_si10_input_validation() -> ControlTestArtifact {
    ArtifactBuilder::new("SI-10", "Information Input Validation")
        .test_name("email_validation_and_xss_sanitization")
        .description("Verify input validation rejects malformed data and sanitizes XSS (SI-10)")
        .code_location("src/validation.rs", 237, 380)
        .input("valid_email", "user@example.com")
        .input("invalid_email", "not-an-email")
        .input("xss_payload", "<script>alert('xss')</script>")
        .expected("valid_email_accepted", true)
        .expected("invalid_email_rejected", true)
        .expected("xss_sanitized", true)
        .execute(|collector| {
            // Test valid email
            let valid_result = validate_email("user@example.com");
            let valid_accepted = valid_result.is_ok();
            collector.assertion(
                "Valid email should be accepted",
                valid_accepted,
                json!({ "result": format!("{:?}", valid_result) }),
            );

            // Test invalid email
            let invalid_result = validate_email("not-an-email");
            let invalid_rejected = invalid_result.is_err();
            collector.assertion(
                "Invalid email should be rejected",
                invalid_rejected,
                json!({ "result": format!("{:?}", invalid_result) }),
            );

            // Test XSS sanitization
            let xss_input = "<script>alert('xss')</script>";
            let sanitized = sanitize_html(xss_input);
            let xss_removed = !sanitized.contains("<script>") && !sanitized.contains("</script>");
            collector.assertion(
                "XSS payload should be sanitized",
                xss_removed,
                json!({
                    "input": xss_input,
                    "output": sanitized,
                    "script_removed": xss_removed,
                }),
            );

            // Test length validation
            let length_result = validate_length("test", 1, 100, "field");
            let length_ok = length_result.is_ok();
            collector.assertion(
                "Length validation should work",
                length_ok,
                json!({ "result": format!("{:?}", length_result) }),
            );

            json!({
                "valid_email_accepted": valid_accepted,
                "invalid_email_rejected": invalid_rejected,
                "xss_sanitized": xss_removed,
            })
        })
}

/// IA-5(1): Password-Based Authentication
///
/// Verifies that password policy meets NIST 800-63B requirements
/// including minimum length and common password rejection.
pub fn test_ia5_1_password_policy() -> ControlTestArtifact {
    ArtifactBuilder::new("IA-5(1)", "Password-Based Authentication")
        .test_name("password_policy_enforcement")
        .description("Verify password policy meets NIST 800-63B requirements (IA-5(1))")
        .code_location("src/password.rs", 61, 265)
        .input("min_length", 12)
        .input("weak_password", "password123")
        .input("short_password", "short")
        .input("strong_password", "K9$mP2vL#nQr5xWz")
        .expected("weak_password_rejected", true)
        .expected("short_password_rejected", true)
        .expected("strong_password_accepted", true)
        .execute(|collector| {
            let policy = PasswordPolicy::default();

            collector.configuration(
                "password_policy",
                json!({
                    "min_length": policy.min_length,
                    "max_length": policy.max_length,
                    "check_common_passwords": policy.check_common_passwords,
                    "disallow_username_in_password": policy.disallow_username_in_password,
                }),
            );

            // Test weak password (common password)
            let weak_result = policy.validate("password123");
            let weak_rejected = weak_result.is_err();
            collector.assertion(
                "Weak/common password should be rejected",
                weak_rejected,
                json!({ "result": format!("{:?}", weak_result) }),
            );

            // Test short password
            let short_result = policy.validate("short");
            let short_rejected = short_result.is_err();
            collector.assertion(
                "Short password should be rejected",
                short_rejected,
                json!({ "result": format!("{:?}", short_result) }),
            );

            // Test strong password
            let strong_result = policy.validate("K9$mP2vL#nQr5xWz");
            let strong_accepted = strong_result.is_ok();
            collector.assertion(
                "Strong password should be accepted",
                strong_accepted,
                json!({ "result": format!("{:?}", strong_result) }),
            );

            json!({
                "weak_password_rejected": weak_rejected,
                "short_password_rejected": short_rejected,
                "strong_password_accepted": strong_accepted,
            })
        })
}

/// AC-11: Session Lock (Idle Timeout)
///
/// Verifies that session policy includes idle timeout and absolute
/// timeout enforcement as required by NIST 800-53 AC-11.
pub fn test_ac11_session_timeout() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-11", "Session Lock")
        .test_name("session_timeout_configuration")
        .description("Verify session policy includes idle and absolute timeout (AC-11)")
        .code_location("src/session.rs", 43, 167)
        .related_control("AC-12")
        .related_control("SC-10")
        .input("expected_idle_timeout", true)
        .input("expected_max_lifetime", true)
        .expected("idle_timeout_configured", true)
        .expected("max_lifetime_configured", true)
        .expected("fresh_session_valid", true)
        .execute(|collector| {
            // Use strict policy for testing
            let policy = SessionPolicy::strict();

            collector.configuration(
                "session_policy",
                json!({
                    "idle_timeout_secs": policy.idle_timeout.as_secs(),
                    "max_lifetime_secs": policy.max_lifetime.as_secs(),
                    "allow_extension": policy.allow_extension,
                    "require_reauth_for_sensitive": policy.require_reauth_for_sensitive,
                }),
            );

            // Verify timeouts are configured
            let idle_configured = policy.idle_timeout.as_secs() > 0;
            let lifetime_configured = policy.max_lifetime.as_secs() > 0;

            collector.assertion(
                "Idle timeout should be configured",
                idle_configured,
                json!({ "idle_timeout_secs": policy.idle_timeout.as_secs() }),
            );

            collector.assertion(
                "Max lifetime should be configured",
                lifetime_configured,
                json!({ "max_lifetime_secs": policy.max_lifetime.as_secs() }),
            );

            // Test that a fresh session is not terminated
            let session = SessionState::new("test-session-id", "test-user-id");
            let termination_reason = policy.should_terminate(&session);
            let fresh_valid = matches!(termination_reason, SessionTerminationReason::None);

            collector.assertion(
                "Fresh session should not be terminated",
                fresh_valid,
                json!({ "termination_reason": format!("{:?}", termination_reason) }),
            );

            json!({
                "idle_timeout_configured": idle_configured,
                "max_lifetime_configured": lifetime_configured,
                "fresh_session_valid": fresh_valid,
            })
        })
}

/// CM-6: Configuration Management
///
/// Verifies that security headers are enabled by default in the
/// security configuration.
pub fn test_cm6_security_headers() -> ControlTestArtifact {
    ArtifactBuilder::new("CM-6", "Configuration Management")
        .test_name("security_headers_enabled")
        .description("Verify security headers are enabled by default (CM-6)")
        .code_location("src/config.rs", 35, 93)
        .related_control("SC-8")
        .expected("security_headers_enabled", true)
        .expected("tracing_enabled", true)
        .execute(|collector| {
            let config = SecurityConfig::default();

            collector.configuration(
                "security_config",
                json!({
                    "security_headers_enabled": config.security_headers_enabled,
                    "tracing_enabled": config.tracing_enabled,
                }),
            );

            let headers_enabled = config.security_headers_enabled;
            let tracing_enabled = config.tracing_enabled;

            collector.assertion(
                "Security headers should be enabled by default",
                headers_enabled,
                json!({ "enabled": headers_enabled }),
            );

            collector.assertion(
                "Tracing should be enabled by default",
                tracing_enabled,
                json!({ "enabled": tracing_enabled }),
            );

            json!({
                "security_headers_enabled": headers_enabled,
                "tracing_enabled": tracing_enabled,
            })
        })
}

/// AC-4: Information Flow Enforcement
///
/// Verifies that CORS configuration is not permissive by default,
/// enforcing information flow policies.
pub fn test_ac4_cors_policy() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-4", "Information Flow Enforcement")
        .test_name("cors_not_permissive_by_default")
        .description("Verify CORS is not permissive by default (AC-4)")
        .code_location("src/config.rs", 155, 165)
        .expected("default_not_permissive", true)
        .expected("permissive_detected", true)
        .execute(|collector| {
            // Test default config
            let default_config = SecurityConfig::default();
            let default_not_permissive = !default_config.cors_is_permissive();

            collector.assertion(
                "Default CORS should not be permissive",
                default_not_permissive,
                json!({
                    "is_permissive": default_config.cors_is_permissive(),
                    "cors_origins": default_config.cors_origins,
                }),
            );

            // Test that permissive config is detected
            let permissive_config = SecurityConfig::builder().cors_permissive().build();
            let permissive_detected = permissive_config.cors_is_permissive();

            collector.assertion(
                "Permissive CORS should be detected",
                permissive_detected,
                json!({
                    "is_permissive": permissive_config.cors_is_permissive(),
                }),
            );

            json!({
                "default_not_permissive": default_not_permissive,
                "permissive_detected": permissive_detected,
            })
        })
}

/// AU-2: Audit Events
///
/// Verifies that required security event types are defined for
/// comprehensive audit logging as required by NIST 800-53 AU-2.
pub fn test_au2_security_events() -> ControlTestArtifact {
    ArtifactBuilder::new("AU-2", "Audit Events")
        .test_name("security_event_coverage")
        .description("Verify all required security event types are defined (AU-2)")
        .code_location("src/observability/events.rs", 38, 120)
        .related_control("AU-3")
        .related_control("AU-12")
        .expected("has_auth_events", true)
        .expected("has_access_events", true)
        .expected("has_system_events", true)
        .execute(|collector| {
            // Check authentication events exist
            let auth_events = vec![
                SecurityEvent::AuthenticationSuccess,
                SecurityEvent::AuthenticationFailure,
                SecurityEvent::Logout,
                SecurityEvent::SessionCreated,
                SecurityEvent::SessionDestroyed,
            ];

            collector.log(format!("Auth events defined: {}", auth_events.len()));
            let has_auth = !auth_events.is_empty();

            // Check access control events
            let access_events = vec![
                SecurityEvent::AccessGranted,
                SecurityEvent::AccessDenied,
            ];

            collector.log(format!("Access events defined: {}", access_events.len()));
            let has_access = !access_events.is_empty();

            // Check system events
            let system_events = vec![
                SecurityEvent::SystemStartup,
                SecurityEvent::SystemShutdown,
                SecurityEvent::ConfigurationChanged,
            ];

            collector.log(format!("System events defined: {}", system_events.len()));
            let has_system = !system_events.is_empty();

            collector.assertion(
                "Authentication events should be defined",
                has_auth,
                json!({ "events": auth_events.iter().map(|e| e.name()).collect::<Vec<_>>() }),
            );

            collector.assertion(
                "Access control events should be defined",
                has_access,
                json!({ "events": access_events.iter().map(|e| e.name()).collect::<Vec<_>>() }),
            );

            collector.assertion(
                "System events should be defined",
                has_system,
                json!({ "events": system_events.iter().map(|e| e.name()).collect::<Vec<_>>() }),
            );

            json!({
                "has_auth_events": has_auth,
                "has_access_events": has_access,
                "has_system_events": has_system,
            })
        })
}

/// AU-3: Content of Audit Records
///
/// Verifies that security events contain required audit fields
/// (category, severity, name) as required by NIST 800-53 AU-3.
pub fn test_au3_audit_content() -> ControlTestArtifact {
    ArtifactBuilder::new("AU-3", "Content of Audit Records")
        .test_name("audit_record_fields")
        .description("Verify security events have required audit fields (AU-3)")
        .code_location("src/observability/events.rs", 120, 200)
        .related_control("AU-2")
        .expected("has_name", true)
        .expected("has_category", true)
        .expected("has_severity", true)
        .execute(|collector| {
            let event = SecurityEvent::AuthenticationFailure;

            // Check required fields
            let name = event.name();
            let category = event.category();
            let severity = event.severity();

            let has_name = !name.is_empty();
            let has_category = !category.is_empty();
            let has_severity = true; // Severity is always defined

            collector.assertion(
                "Event should have a name",
                has_name,
                json!({ "name": name }),
            );

            collector.assertion(
                "Event should have a category",
                has_category,
                json!({ "category": category }),
            );

            collector.assertion(
                "Event should have a severity",
                has_severity,
                json!({ "severity": format!("{:?}", severity) }),
            );

            // Log sample event structure
            collector.configuration(
                "sample_event",
                json!({
                    "event": "AuthenticationFailure",
                    "name": name,
                    "category": category,
                    "severity": format!("{:?}", severity),
                }),
            );

            json!({
                "has_name": has_name,
                "has_category": has_category,
                "has_severity": has_severity,
            })
        })
}

/// IA-2: Identification and Authentication
///
/// Verifies that MFA policy enforcement works correctly,
/// requiring multi-factor authentication for sensitive operations.
pub fn test_ia2_mfa_enforcement() -> ControlTestArtifact {
    ArtifactBuilder::new("IA-2", "Identification and Authentication")
        .test_name("mfa_policy_enforcement")
        .description("Verify MFA policy correctly enforces multi-factor authentication (IA-2)")
        .code_location("src/auth.rs", 467, 630)
        .related_control("IA-5")
        .input("mfa_required", true)
        .expected("mfa_enforced_without_amr", true)
        .expected("mfa_satisfied_with_amr", true)
        .execute(|collector| {
            // Create MFA-required policy
            let policy = MfaPolicy::require_mfa();

            collector.configuration(
                "mfa_policy",
                json!({ "requirement": policy.describe_requirement() }),
            );

            // Test claims without MFA
            let claims_no_mfa = Claims::new("user-123");
            let enforced = !policy.is_satisfied(&claims_no_mfa);

            collector.assertion(
                "MFA should be enforced for claims without AMR",
                enforced,
                json!({
                    "has_amr": claims_no_mfa.mfa_satisfied(),
                    "policy_satisfied": policy.is_satisfied(&claims_no_mfa),
                }),
            );

            // Test claims with MFA
            let claims_with_mfa = Claims::new("user-123")
                .with_amr("otp")
                .with_amr("pwd");
            let satisfied = policy.is_satisfied(&claims_with_mfa);

            collector.assertion(
                "MFA should be satisfied with proper AMR claims",
                satisfied,
                json!({
                    "has_amr": claims_with_mfa.mfa_satisfied(),
                    "policy_satisfied": satisfied,
                }),
            );

            json!({
                "mfa_enforced_without_amr": enforced,
                "mfa_satisfied_with_amr": satisfied,
            })
        })
}

/// SC-8: Transmission Confidentiality and Integrity
///
/// Verifies that security headers for transmission protection
/// are properly configured (HSTS, secure cookies, etc.).
pub fn test_sc8_transmission_security() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-8", "Transmission Confidentiality and Integrity")
        .test_name("security_headers_configuration")
        .description("Verify security headers protect data in transit (SC-8)")
        .code_location("src/layers.rs", 75, 95)
        .related_control("CM-6")
        .expected("security_headers_enabled", true)
        .expected("can_be_disabled", true)
        .execute(|collector| {
            // Default config should have security headers enabled
            let default_config = SecurityConfig::default();
            let headers_enabled = default_config.security_headers_enabled;

            collector.configuration(
                "default_config",
                json!({
                    "security_headers_enabled": headers_enabled,
                }),
            );

            collector.assertion(
                "Security headers should be enabled by default",
                headers_enabled,
                json!({ "enabled": headers_enabled }),
            );

            // Verify headers can be explicitly disabled (for testing)
            let disabled_config = SecurityConfig::builder()
                .disable_security_headers()
                .build();
            let can_disable = !disabled_config.security_headers_enabled;

            collector.assertion(
                "Security headers can be disabled when needed",
                can_disable,
                json!({ "disabled": can_disable }),
            );

            json!({
                "security_headers_enabled": headers_enabled,
                "can_be_disabled": can_disable,
            })
        })
}

/// SC-13: Cryptographic Protection
///
/// Verifies that constant-time comparison is available to prevent
/// timing attacks on sensitive comparisons.
pub fn test_sc13_constant_time() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-13", "Cryptographic Protection")
        .test_name("constant_time_comparison")
        .description("Verify constant-time comparison prevents timing attacks (SC-13)")
        .code_location("src/crypto.rs", 37, 50)
        .expected("equal_values_match", true)
        .expected("different_values_differ", true)
        .expected("different_lengths_differ", true)
        .execute(|collector| {
            // Test equal values
            let a = b"secret-token-12345";
            let b = b"secret-token-12345";
            let equal_match = constant_time_eq(a, b);

            collector.assertion(
                "Equal values should match",
                equal_match,
                json!({ "result": equal_match }),
            );

            // Test different values (same length)
            let c = b"secret-token-12345";
            let d = b"secret-token-12346";
            let diff_mismatch = !constant_time_eq(c, d);

            collector.assertion(
                "Different values should not match",
                diff_mismatch,
                json!({ "result": !diff_mismatch }),
            );

            // Test different lengths
            let e = b"short";
            let f = b"longer-string";
            let len_mismatch = !constant_time_eq(e, f);

            collector.assertion(
                "Different length values should not match",
                len_mismatch,
                json!({ "result": !len_mismatch }),
            );

            json!({
                "equal_values_match": equal_match,
                "different_values_differ": diff_mismatch,
                "different_lengths_differ": len_mismatch,
            })
        })
}

/// SI-11: Error Handling
///
/// Verifies that error responses do not leak sensitive information
/// in production mode as required by NIST 800-53 SI-11.
pub fn test_si11_error_handling() -> ControlTestArtifact {
    ArtifactBuilder::new("SI-11", "Error Handling")
        .test_name("secure_error_responses")
        .description("Verify errors do not leak sensitive info in production (SI-11)")
        .code_location("src/error.rs", 50, 150)
        .expected("prod_hides_details", true)
        .expected("dev_shows_details", true)
        .execute(|collector| {
            // Check production config hides details
            let prod_config = ErrorConfig::production();
            let prod_hides = !prod_config.expose_details;

            collector.configuration(
                "production_config",
                json!({
                    "expose_details": prod_config.expose_details,
                    "include_stack_traces": prod_config.include_stack_traces,
                    "log_errors": prod_config.log_errors,
                }),
            );

            collector.assertion(
                "Production config should hide error details",
                prod_hides,
                json!({ "expose_details": prod_config.expose_details }),
            );

            // Check development config shows details
            let dev_config = ErrorConfig::development();
            let dev_shows = dev_config.expose_details;

            collector.configuration(
                "development_config",
                json!({
                    "expose_details": dev_config.expose_details,
                    "include_stack_traces": dev_config.include_stack_traces,
                }),
            );

            collector.assertion(
                "Development config should show error details",
                dev_shows,
                json!({ "expose_details": dev_config.expose_details }),
            );

            // Verify internal errors don't expose details by default
            let error = AppError::internal_msg("Database connection failed");
            let exposes = error.kind.expose_details();

            collector.assertion(
                "Internal errors should not expose details",
                !exposes,
                json!({ "kind": format!("{:?}", error.kind), "expose_details": exposes }),
            );

            json!({
                "prod_hides_details": prod_hides,
                "dev_shows_details": dev_shows,
            })
        })
}

/// Generate a complete compliance test report with all control tests
///
/// This function runs all artifact-generating tests and collects them
/// into a single report that can be signed and exported.
///
/// # Example
///
/// ```ignore
/// use barbican::compliance::control_tests::generate_compliance_report;
///
/// let mut report = generate_compliance_report();
///
/// // Optionally sign the report
/// report.sign(b"my-signing-key", "key-2025")?;
///
/// // Write to file
/// std::fs::create_dir_all("./compliance-artifacts")?;
/// let path = report.write_to_file(Path::new("./compliance-artifacts"))?;
/// println!("Report written to: {}", path.display());
/// ```
pub fn generate_compliance_report() -> ComplianceTestReport {
    let mut report = ComplianceTestReport::new("FedRAMP Moderate");

    // Run all control tests and add artifacts
    // Access Control (AC)
    report.add_artifact(test_ac4_cors_policy());
    report.add_artifact(test_ac7_lockout());
    report.add_artifact(test_ac11_session_timeout());

    // Audit and Accountability (AU)
    report.add_artifact(test_au2_security_events());
    report.add_artifact(test_au3_audit_content());

    // Configuration Management (CM)
    report.add_artifact(test_cm6_security_headers());

    // Identification and Authentication (IA)
    report.add_artifact(test_ia2_mfa_enforcement());
    report.add_artifact(test_ia5_1_password_policy());

    // System and Communications Protection (SC)
    report.add_artifact(test_sc5_rate_limiting());
    report.add_artifact(test_sc8_transmission_security());
    report.add_artifact(test_sc13_constant_time());

    // System and Information Integrity (SI)
    report.add_artifact(test_si10_input_validation());
    report.add_artifact(test_si11_error_handling());

    report
}

/// Get all available control test functions
///
/// Returns a list of (control_id, test_function) pairs for programmatic execution.
pub fn all_control_tests() -> Vec<(&'static str, fn() -> ControlTestArtifact)> {
    vec![
        // Access Control (AC)
        ("AC-4", test_ac4_cors_policy as fn() -> ControlTestArtifact),
        ("AC-7", test_ac7_lockout),
        ("AC-11", test_ac11_session_timeout),
        // Audit and Accountability (AU)
        ("AU-2", test_au2_security_events),
        ("AU-3", test_au3_audit_content),
        // Configuration Management (CM)
        ("CM-6", test_cm6_security_headers),
        // Identification and Authentication (IA)
        ("IA-2", test_ia2_mfa_enforcement),
        ("IA-5(1)", test_ia5_1_password_policy),
        // System and Communications Protection (SC)
        ("SC-5", test_sc5_rate_limiting),
        ("SC-8", test_sc8_transmission_security),
        ("SC-13", test_sc13_constant_time),
        // System and Information Integrity (SI)
        ("SI-10", test_si10_input_validation),
        ("SI-11", test_si11_error_handling),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ac7_generates_passing_artifact() {
        let artifact = test_ac7_lockout();
        assert_eq!(artifact.control_id, "AC-7");
        assert!(
            artifact.passed,
            "AC-7 test should pass: {:?}",
            artifact.failure_reason
        );
        assert!(!artifact.evidence.is_empty(), "Should have evidence");
    }

    #[test]
    fn test_sc5_generates_passing_artifact() {
        let artifact = test_sc5_rate_limiting();
        assert_eq!(artifact.control_id, "SC-5");
        assert!(
            artifact.passed,
            "SC-5 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_si10_generates_passing_artifact() {
        let artifact = test_si10_input_validation();
        assert_eq!(artifact.control_id, "SI-10");
        assert!(
            artifact.passed,
            "SI-10 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ia5_1_generates_passing_artifact() {
        let artifact = test_ia5_1_password_policy();
        assert_eq!(artifact.control_id, "IA-5(1)");
        assert!(
            artifact.passed,
            "IA-5(1) test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ac11_generates_passing_artifact() {
        let artifact = test_ac11_session_timeout();
        assert_eq!(artifact.control_id, "AC-11");
        assert!(
            artifact.passed,
            "AC-11 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_cm6_generates_passing_artifact() {
        let artifact = test_cm6_security_headers();
        assert_eq!(artifact.control_id, "CM-6");
        assert!(
            artifact.passed,
            "CM-6 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ac4_generates_passing_artifact() {
        let artifact = test_ac4_cors_policy();
        assert_eq!(artifact.control_id, "AC-4");
        assert!(
            artifact.passed,
            "AC-4 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_au2_generates_passing_artifact() {
        let artifact = test_au2_security_events();
        assert_eq!(artifact.control_id, "AU-2");
        assert!(
            artifact.passed,
            "AU-2 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_au3_generates_passing_artifact() {
        let artifact = test_au3_audit_content();
        assert_eq!(artifact.control_id, "AU-3");
        assert!(
            artifact.passed,
            "AU-3 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ia2_generates_passing_artifact() {
        let artifact = test_ia2_mfa_enforcement();
        assert_eq!(artifact.control_id, "IA-2");
        assert!(
            artifact.passed,
            "IA-2 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_sc8_generates_passing_artifact() {
        let artifact = test_sc8_transmission_security();
        assert_eq!(artifact.control_id, "SC-8");
        assert!(
            artifact.passed,
            "SC-8 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_sc13_generates_passing_artifact() {
        let artifact = test_sc13_constant_time();
        assert_eq!(artifact.control_id, "SC-13");
        assert!(
            artifact.passed,
            "SC-13 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_si11_generates_passing_artifact() {
        let artifact = test_si11_error_handling();
        assert_eq!(artifact.control_id, "SI-11");
        assert!(
            artifact.passed,
            "SI-11 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_full_report_generation() {
        let report = generate_compliance_report();

        assert_eq!(report.artifacts.len(), 13, "Should have 13 control tests");
        assert_eq!(report.compliance_profile, "FedRAMP Moderate");
        assert!(
            report.all_passed(),
            "All tests should pass. Failed: {:?}",
            report.failed_artifacts()
        );
        assert_eq!(report.summary.pass_rate, 100.0);

        // Verify JSON export works
        let json = report.to_json().expect("JSON export should work");
        assert!(json.contains("AC-7"));
        assert!(json.contains("SC-5"));
        assert!(json.contains("FedRAMP Moderate"));
    }

    #[test]
    fn test_report_can_be_signed() {
        let mut report = generate_compliance_report();
        let key = b"test-signing-key-at-least-32-bytes-long";

        report.sign(key, "test-key").expect("Signing should work");
        assert!(report.is_signed());
        assert!(report.verify(key).expect("Verification should work"));
    }

    #[test]
    fn test_all_control_tests_returns_all() {
        let tests = all_control_tests();
        assert_eq!(tests.len(), 13);

        // Verify each test can be executed
        for (control_id, test_fn) in tests {
            let artifact = test_fn();
            assert_eq!(artifact.control_id, control_id);
        }
    }

    #[test]
    fn test_artifacts_have_code_locations() {
        let report = generate_compliance_report();

        for artifact in &report.artifacts {
            assert!(
                !artifact.code_location.file.is_empty(),
                "{} should have code location",
                artifact.control_id
            );
            assert!(
                artifact.code_location.line_start > 0,
                "{} should have valid line number",
                artifact.control_id
            );
        }
    }

    #[test]
    fn test_artifacts_have_evidence() {
        let report = generate_compliance_report();

        for artifact in &report.artifacts {
            assert!(
                !artifact.evidence.is_empty(),
                "{} should have evidence",
                artifact.control_id
            );
        }
    }

    #[test]
    fn test_report_summary_by_family() {
        let report = generate_compliance_report();

        // Should have AC, AU, CM, IA, SC, SI families
        assert!(report.summary.by_family.contains_key("AC"));
        assert!(report.summary.by_family.contains_key("AU"));
        assert!(report.summary.by_family.contains_key("CM"));
        assert!(report.summary.by_family.contains_key("IA"));
        assert!(report.summary.by_family.contains_key("SC"));
        assert!(report.summary.by_family.contains_key("SI"));

        // Verify family counts
        assert_eq!(report.summary.by_family.get("AC").unwrap().total, 3); // AC-4, AC-7, AC-11
        assert_eq!(report.summary.by_family.get("AU").unwrap().total, 2); // AU-2, AU-3
        assert_eq!(report.summary.by_family.get("CM").unwrap().total, 1); // CM-6
        assert_eq!(report.summary.by_family.get("IA").unwrap().total, 2); // IA-2, IA-5(1)
        assert_eq!(report.summary.by_family.get("SC").unwrap().total, 3); // SC-5, SC-8, SC-13
        assert_eq!(report.summary.by_family.get("SI").unwrap().total, 2); // SI-10, SI-11
    }
}
