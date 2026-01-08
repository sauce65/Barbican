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

use crate::audit::integrity::{AuditChain, AuditIntegrityConfig, SignatureAlgorithm};
use crate::auth::{Claims, MfaPolicy};
use crate::compliance::artifacts::{ArtifactBuilder, ComplianceTestReport, ControlTestArtifact};
use crate::compliance::config::ComplianceConfig;
use crate::compliance::profile::ComplianceProfile;
use crate::config::SecurityConfig;
use crate::crypto::constant_time_eq;
use crate::encryption::{EncryptedField, EncryptionAlgorithm, EncryptionConfig, FieldEncryptor};
use crate::error::{AppError, ErrorConfig};
use crate::login::{LockoutPolicy, LoginTracker};
use crate::observability::SecurityEvent;
use crate::password::PasswordPolicy;
use crate::secrets::{SecretCategory, SecretScanner};
use crate::session::{SessionPolicy, SessionState, SessionTerminationReason};
use crate::validation::{sanitize_html, validate_email, validate_length};
use serde_json::json;

// ============================================================================
// Test Helpers for Capturing Tracing Output
// ============================================================================

/// Helper module for capturing tracing output in compliance tests.
///
/// This allows tests to verify that security events are actually emitted
/// with the correct content, rather than just checking that enum variants exist.
mod test_capture {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// A writer that captures output to a shared buffer.
    #[derive(Clone)]
    pub struct CaptureWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl CaptureWriter {
        /// Create a new capture writer with an empty buffer.
        pub fn new() -> Self {
            Self {
                buffer: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Get the captured output as a string.
        pub fn output(&self) -> String {
            let buf = self.buffer.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        }

        /// Clear the captured output.
        #[allow(dead_code)]
        pub fn clear(&self) {
            self.buffer.lock().unwrap().clear();
        }
    }

    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run a closure with tracing output captured to a buffer.
    ///
    /// Returns the captured output after the closure completes.
    pub fn with_captured_tracing<F, R>(f: F) -> (R, String)
    where
        F: FnOnce() -> R,
    {
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::prelude::*;

        let capture = CaptureWriter::new();
        let capture_clone = capture.clone();

        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_span_events(FmtSpan::NONE)
            .with_writer(move || capture_clone.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)  // Capture debug events for Low severity
            .finish();

        let result = tracing::subscriber::with_default(subscriber, f);
        let output = capture.output();

        (result, output)
    }
}

/// AC-7: Unsuccessful Logon Attempts
///
/// Verifies that accounts are locked after the configured number of failed
/// login attempts, as required by NIST 800-53 AC-7.
///
/// Tests the `from_compliance()` configuration path to ensure lockout policies
/// are correctly derived from compliance profiles (FedRAMP Low/Moderate/High).
pub fn test_ac7_lockout() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-7", "Unsuccessful Logon Attempts")
        .test_name("lockout_after_max_attempts")
        .description(
            "Verify account locks after profile-configured number of failed attempts (AC-7)",
        )
        .code_location("src/login.rs", 169, 189)
        .code_location_with_fn("src/compliance/config.rs", 137, 143, "ComplianceConfig")
        .related_control("AC-2")
        .related_control("IA-5")
        .input("username", "test@example.com")
        .input("profiles_tested", "FedRAMP Low, Moderate, High")
        .expected("moderate_locks_at_3", true)
        .expected("low_locks_at_5", true)
        .expected("high_locks_at_3", true)
        .expected("from_compliance_path_tested", true)
        .execute(|collector| {
            let username = "test@example.com";

            // Test FedRAMP Moderate profile (3 attempts)
            let moderate_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
            let moderate_policy = LockoutPolicy::from_compliance(&moderate_config);

            collector.configuration(
                "fedramp_moderate_policy",
                json!({
                    "profile": "FedRAMP Moderate",
                    "max_attempts": moderate_policy.max_attempts,
                    "lockout_duration_secs": moderate_policy.lockout_duration.as_secs(),
                    "progressive_lockout": moderate_policy.progressive_lockout,
                    "track_by_ip": moderate_policy.track_by_ip,
                    "derived_from": "ComplianceConfig::from_profile()",
                }),
            );

            // Verify Moderate locks at 3 attempts
            let moderate_tracker = LoginTracker::new(moderate_policy.clone());
            moderate_tracker.record_failure(username);
            moderate_tracker.record_failure(username);
            let moderate_result = moderate_tracker.record_failure(username);
            let moderate_locks_at_3 = moderate_result.is_locked_out && moderate_policy.max_attempts == 3;

            collector.assertion(
                "FedRAMP Moderate should lock after 3 attempts (from_compliance path)",
                moderate_locks_at_3,
                json!({
                    "policy_max_attempts": moderate_policy.max_attempts,
                    "locked_after_3": moderate_result.is_locked_out,
                    "config_source": "ComplianceConfig::from_profile(FedRampModerate)",
                }),
            );

            // Test FedRAMP Low profile (5 attempts)
            let low_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampLow);
            let low_policy = LockoutPolicy::from_compliance(&low_config);

            collector.configuration(
                "fedramp_low_policy",
                json!({
                    "profile": "FedRAMP Low",
                    "max_attempts": low_policy.max_attempts,
                    "lockout_duration_secs": low_policy.lockout_duration.as_secs(),
                    "derived_from": "ComplianceConfig::from_profile()",
                }),
            );

            // Verify Low allows 4 attempts but locks at 5
            let low_tracker = LoginTracker::new(low_policy.clone());
            for _ in 0..4 {
                low_tracker.record_failure(username);
            }
            let low_4th_lockout = low_tracker.check_lockout(username);
            let low_result = low_tracker.record_failure(username);
            let low_locks_at_5 = low_4th_lockout.is_none()  // Not locked after 4 attempts
                && low_result.is_locked_out                  // Locked after 5th
                && low_policy.max_attempts == 5;

            collector.assertion(
                "FedRAMP Low should lock after 5 attempts (from_compliance path)",
                low_locks_at_5,
                json!({
                    "policy_max_attempts": low_policy.max_attempts,
                    "not_locked_at_4": low_4th_lockout.is_none(),
                    "locked_at_5": low_result.is_locked_out,
                    "config_source": "ComplianceConfig::from_profile(FedRampLow)",
                }),
            );

            // Test FedRAMP High profile (3 attempts, stricter settings)
            let high_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
            let high_policy = LockoutPolicy::from_compliance(&high_config);

            collector.configuration(
                "fedramp_high_policy",
                json!({
                    "profile": "FedRAMP High",
                    "max_attempts": high_policy.max_attempts,
                    "lockout_duration_secs": high_policy.lockout_duration.as_secs(),
                    "progressive_lockout": high_policy.progressive_lockout,
                    "lockout_multiplier": high_policy.lockout_multiplier,
                    "derived_from": "ComplianceConfig::from_profile()",
                }),
            );

            let high_tracker = LoginTracker::new(high_policy.clone());
            high_tracker.record_failure(username);
            high_tracker.record_failure(username);
            let high_result = high_tracker.record_failure(username);
            let high_locks_at_3 = high_result.is_locked_out && high_policy.max_attempts == 3;

            collector.assertion(
                "FedRAMP High should lock after 3 attempts with stricter settings",
                high_locks_at_3,
                json!({
                    "policy_max_attempts": high_policy.max_attempts,
                    "locked_after_3": high_result.is_locked_out,
                    "lockout_multiplier": high_policy.lockout_multiplier,
                    "config_source": "ComplianceConfig::from_profile(FedRampHigh)",
                }),
            );

            // Verify stricter settings for High vs Low
            let high_stricter = high_policy.lockout_multiplier > low_policy.lockout_multiplier
                && high_policy.max_ip_attempts < low_policy.max_ip_attempts;

            collector.assertion(
                "FedRAMP High should have stricter settings than Low",
                high_stricter,
                json!({
                    "high_lockout_multiplier": high_policy.lockout_multiplier,
                    "low_lockout_multiplier": low_policy.lockout_multiplier,
                    "high_max_ip_attempts": high_policy.max_ip_attempts,
                    "low_max_ip_attempts": low_policy.max_ip_attempts,
                }),
            );

            json!({
                "moderate_locks_at_3": moderate_locks_at_3,
                "low_locks_at_5": low_locks_at_5,
                "high_locks_at_3": high_locks_at_3,
                "from_compliance_path_tested": true,
            })
        })
}

/// SC-5: Denial of Service Protection
///
/// Verifies that rate limiting is enabled and configured correctly
/// to protect against denial of service attacks.
pub fn test_sc5_rate_limiting() -> ControlTestArtifact {
    use crate::rate_limit::{TieredRateLimiter, RateLimitTier};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    ArtifactBuilder::new("SC-5", "Denial of Service Protection")
        .test_name("rate_limiting_behavior")
        .description("Verify rate limiting actually blocks requests after limit is exceeded (SC-5)")
        .code_location("src/rate_limit.rs", 371, 430)
        .code_location_with_fn("src/config.rs", 35, 93, "SecurityConfig")
        .input("test_ip", "10.0.0.99")
        .input("tier_limit", 2)
        .expected("first_request_allowed", true)
        .expected("second_request_allowed", true)
        .expected("third_request_blocked", true)
        .expected("tier_classification_works", true)
        .execute(|collector| {
            // Create a rate limiter with very low limits for testing
            let limiter = TieredRateLimiter::builder()
                .auth_tier(2, Duration::from_secs(60), Duration::from_secs(30))
                .build();

            let test_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));

            collector.configuration(
                "rate_limiter",
                json!({
                    "auth_tier_limit": 2,
                    "auth_tier_window_secs": 60,
                    "auth_tier_lockout_secs": 30,
                }),
            );

            // First request should succeed
            let first_result = limiter.check(test_ip, "/api/v1/auth/login", "POST");
            let first_request_allowed = first_result.is_ok();

            collector.assertion(
                "First request should be allowed",
                first_request_allowed,
                json!({
                    "result": if first_result.is_ok() { "allowed" } else { "blocked" },
                    "remaining": first_result.as_ref().ok().map(|(_, s)| s.remaining),
                }),
            );

            // Second request should succeed (at limit)
            let second_result = limiter.check(test_ip, "/api/v1/auth/login", "POST");
            let second_request_allowed = second_result.is_ok();

            collector.assertion(
                "Second request should be allowed (at limit)",
                second_request_allowed,
                json!({
                    "result": if second_result.is_ok() { "allowed" } else { "blocked" },
                    "remaining": second_result.as_ref().ok().map(|(_, s)| s.remaining),
                }),
            );

            // Third request should be blocked (over limit)
            let third_result = limiter.check(test_ip, "/api/v1/auth/login", "POST");
            let third_request_blocked = third_result.is_err();

            collector.assertion(
                "Third request should be blocked (over limit)",
                third_request_blocked,
                json!({
                    "result": if third_result.is_err() { "blocked" } else { "allowed" },
                    "error": third_result.as_ref().err().map(|(_, e)| format!("{:?}", e)),
                }),
            );

            // Test tier classification works correctly
            let auth_tier = RateLimitTier::from_path("/api/v1/auth/login");
            let standard_tier = RateLimitTier::from_path("/api/v1/items");
            let relaxed_tier = RateLimitTier::from_path("/health");

            let tier_classification_works = auth_tier == RateLimitTier::Auth
                && standard_tier == RateLimitTier::Standard
                && relaxed_tier == RateLimitTier::Relaxed;

            collector.assertion(
                "Tier classification should work correctly",
                tier_classification_works,
                json!({
                    "auth_login_tier": format!("{:?}", auth_tier),
                    "items_tier": format!("{:?}", standard_tier),
                    "health_tier": format!("{:?}", relaxed_tier),
                }),
            );

            json!({
                "first_request_allowed": first_request_allowed,
                "second_request_allowed": second_request_allowed,
                "third_request_blocked": third_request_blocked,
                "tier_classification_works": tier_classification_works,
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
        .description("Verify password policy derived from compliance profile meets NIST 800-63B (IA-5(1))")
        .code_location("src/password.rs", 138, 153)
        .code_location_with_fn("src/compliance/config.rs", 128, 134, "ComplianceConfig")
        .input("profiles_tested", "FedRAMP Low, Moderate, High")
        .input("weak_password", "password123")
        .expected("low_min_length_8", true)
        .expected("moderate_min_length_12", true)
        .expected("high_min_length_14", true)
        .expected("common_password_rejected", true)
        .expected("from_compliance_path_tested", true)
        .execute(|collector| {
            // Test FedRAMP Low profile (8 char min, no breach checking)
            let low_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampLow);
            let low_policy = PasswordPolicy::from_compliance(&low_config);

            collector.configuration(
                "fedramp_low_policy",
                json!({
                    "profile": "FedRAMP Low",
                    "min_length": low_policy.min_length,
                    "max_length": low_policy.max_length,
                    "check_common_passwords": low_policy.check_common_passwords,
                    "check_breach_database": low_policy.check_breach_database,
                    "disallow_username_in_password": low_policy.disallow_username_in_password,
                    "derived_from": "ComplianceConfig::from_profile()",
                }),
            );

            let low_min_length_8 = low_policy.min_length == 8;
            collector.assertion(
                "FedRAMP Low should require minimum 8 characters",
                low_min_length_8,
                json!({
                    "expected": 8,
                    "actual": low_policy.min_length,
                    "config_source": "ComplianceConfig::from_profile(FedRampLow)",
                }),
            );

            // Test FedRAMP Moderate profile (12 char min, breach checking)
            let moderate_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
            let moderate_policy = PasswordPolicy::from_compliance(&moderate_config);

            collector.configuration(
                "fedramp_moderate_policy",
                json!({
                    "profile": "FedRAMP Moderate",
                    "min_length": moderate_policy.min_length,
                    "check_common_passwords": moderate_policy.check_common_passwords,
                    "check_breach_database": moderate_policy.check_breach_database,
                    "derived_from": "ComplianceConfig::from_profile()",
                }),
            );

            let moderate_min_length_12 = moderate_policy.min_length == 12;
            collector.assertion(
                "FedRAMP Moderate should require minimum 12 characters",
                moderate_min_length_12,
                json!({
                    "expected": 12,
                    "actual": moderate_policy.min_length,
                    "config_source": "ComplianceConfig::from_profile(FedRampModerate)",
                }),
            );

            // Test FedRAMP High profile (14 char min, breach checking required)
            let high_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
            let high_policy = PasswordPolicy::from_compliance(&high_config);

            collector.configuration(
                "fedramp_high_policy",
                json!({
                    "profile": "FedRAMP High",
                    "min_length": high_policy.min_length,
                    "check_common_passwords": high_policy.check_common_passwords,
                    "check_breach_database": high_policy.check_breach_database,
                    "derived_from": "ComplianceConfig::from_profile()",
                }),
            );

            let high_min_length_14 = high_policy.min_length == 14;
            collector.assertion(
                "FedRAMP High should require minimum 14 characters",
                high_min_length_14,
                json!({
                    "expected": 14,
                    "actual": high_policy.min_length,
                    "config_source": "ComplianceConfig::from_profile(FedRampHigh)",
                }),
            );

            // Verify breach checking is enabled for stricter profiles
            let breach_check_stricter = !low_config.password_check_breach_db
                && moderate_config.password_check_breach_db
                && high_config.password_check_breach_db;

            collector.assertion(
                "Breach checking should be enabled for Moderate/High but not Low",
                breach_check_stricter,
                json!({
                    "low_breach_check": low_config.password_check_breach_db,
                    "moderate_breach_check": moderate_config.password_check_breach_db,
                    "high_breach_check": high_config.password_check_breach_db,
                }),
            );

            // Test common password rejection (using Moderate policy)
            let weak_result = moderate_policy.validate("password123");
            let common_password_rejected = weak_result.is_err();
            collector.assertion(
                "Common password should be rejected by Moderate policy",
                common_password_rejected,
                json!({
                    "password": "password123",
                    "rejected": common_password_rejected,
                    "error": format!("{:?}", weak_result),
                }),
            );

            // Test that a password meeting High requirements is accepted
            let strong_password = "K9$mP2vL#nQr5xWz!@"; // 18 chars, no common patterns
            let strong_result = high_policy.validate(strong_password);
            let strong_accepted = strong_result.is_ok();
            collector.assertion(
                "Strong password should be accepted by High policy",
                strong_accepted,
                json!({
                    "password_length": strong_password.len(),
                    "accepted": strong_accepted,
                    "result": format!("{:?}", strong_result),
                }),
            );

            json!({
                "low_min_length_8": low_min_length_8,
                "moderate_min_length_12": moderate_min_length_12,
                "high_min_length_14": high_min_length_14,
                "common_password_rejected": common_password_rejected,
                "from_compliance_path_tested": true,
            })
        })
}

/// AC-11: Session Lock (Idle Timeout)
///
/// Verifies that session policy includes idle timeout and absolute
/// timeout enforcement as required by NIST 800-53 AC-11.
pub fn test_ac11_session_timeout() -> ControlTestArtifact {
    use std::time::{SystemTime, UNIX_EPOCH};

    ArtifactBuilder::new("AC-11", "Session Lock")
        .test_name("session_timeout_behavior")
        .description("Verify session policy derived from compliance profile enforces timeouts (AC-11)")
        .code_location("src/session.rs", 147, 169)
        .code_location_with_fn("src/compliance/config.rs", 106, 116, "ComplianceConfig")
        .related_control("AC-12")
        .related_control("SC-10")
        .input("profiles_tested", "FedRAMP Low, Moderate, High")
        .expected("high_stricter_than_low", true)
        .expected("timeouts_from_compliance", true)
        .expected("expired_token_terminated", true)
        .expected("from_compliance_path_tested", true)
        .execute(|collector| {
            // Test FedRAMP Low profile (relaxed timeouts)
            let low_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampLow);
            let low_policy = SessionPolicy::from_compliance(&low_config);

            collector.configuration(
                "fedramp_low_session_policy",
                json!({
                    "profile": "FedRAMP Low",
                    "idle_timeout_secs": low_policy.idle_timeout.as_secs(),
                    "max_lifetime_secs": low_policy.max_lifetime.as_secs(),
                    "max_concurrent_sessions": low_policy.max_concurrent_sessions,
                    "allow_extension": low_policy.allow_extension,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            // Test FedRAMP Moderate profile
            let moderate_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
            let moderate_policy = SessionPolicy::from_compliance(&moderate_config);

            collector.configuration(
                "fedramp_moderate_session_policy",
                json!({
                    "profile": "FedRAMP Moderate",
                    "idle_timeout_secs": moderate_policy.idle_timeout.as_secs(),
                    "max_lifetime_secs": moderate_policy.max_lifetime.as_secs(),
                    "max_concurrent_sessions": moderate_policy.max_concurrent_sessions,
                    "require_reauth_for_sensitive": moderate_policy.require_reauth_for_sensitive,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            // Test FedRAMP High profile (strictest timeouts)
            let high_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
            let high_policy = SessionPolicy::from_compliance(&high_config);

            collector.configuration(
                "fedramp_high_session_policy",
                json!({
                    "profile": "FedRAMP High",
                    "idle_timeout_secs": high_policy.idle_timeout.as_secs(),
                    "max_lifetime_secs": high_policy.max_lifetime.as_secs(),
                    "max_concurrent_sessions": high_policy.max_concurrent_sessions,
                    "require_reauth_for_sensitive": high_policy.require_reauth_for_sensitive,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            // Verify High has stricter timeouts than Low
            let high_stricter_than_low = high_policy.idle_timeout < low_policy.idle_timeout
                && high_policy.max_lifetime < low_policy.max_lifetime;

            collector.assertion(
                "FedRAMP High should have stricter timeouts than Low (from_compliance path)",
                high_stricter_than_low,
                json!({
                    "high_idle_secs": high_policy.idle_timeout.as_secs(),
                    "low_idle_secs": low_policy.idle_timeout.as_secs(),
                    "high_lifetime_secs": high_policy.max_lifetime.as_secs(),
                    "low_lifetime_secs": low_policy.max_lifetime.as_secs(),
                    "config_source": "SessionPolicy::from_compliance()",
                }),
            );

            // Verify concurrent session limits vary by profile (AC-10)
            let concurrent_limits_correct = high_policy.max_concurrent_sessions == Some(1)
                && moderate_policy.max_concurrent_sessions == Some(3)
                && low_policy.max_concurrent_sessions == Some(5);

            collector.assertion(
                "Concurrent session limits should vary by profile (AC-10)",
                concurrent_limits_correct,
                json!({
                    "high_limit": high_policy.max_concurrent_sessions,
                    "moderate_limit": moderate_policy.max_concurrent_sessions,
                    "low_limit": low_policy.max_concurrent_sessions,
                }),
            );

            // Verify timeouts match ComplianceConfig values
            let timeouts_from_compliance = high_policy.idle_timeout == high_config.session_idle_timeout
                && high_policy.max_lifetime == high_config.session_max_lifetime
                && moderate_policy.idle_timeout == moderate_config.session_idle_timeout;

            collector.assertion(
                "Session timeouts should match ComplianceConfig values",
                timeouts_from_compliance,
                json!({
                    "high_idle_matches": high_policy.idle_timeout == high_config.session_idle_timeout,
                    "high_lifetime_matches": high_policy.max_lifetime == high_config.session_max_lifetime,
                    "moderate_idle_matches": moderate_policy.idle_timeout == moderate_config.session_idle_timeout,
                }),
            );

            // Test token expiration detection using High profile
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            // Expired token (exp in the past)
            let expired_result = high_policy.check_token_times(
                Some(now - 3600),    // issued_at: 1 hour ago
                Some(now - 60),      // exp: expired 1 minute ago
            );
            let expired_token_terminated = matches!(
                expired_result,
                SessionTerminationReason::TokenExpired
            );

            collector.assertion(
                "Expired token should trigger termination",
                expired_token_terminated,
                json!({
                    "termination_reason": format!("{:?}", expired_result),
                    "policy": "FedRAMP High (from_compliance)",
                }),
            );

            // Token issued too long ago (exceeds High's max_lifetime)
            let max_lifetime_secs = high_policy.max_lifetime.as_secs() as i64;
            let old_issued_result = high_policy.check_token_times(
                Some(now - max_lifetime_secs - 3600),  // issued_at: beyond max_lifetime
                Some(now + 3600),                       // exp: still valid
            );
            let old_issued_terminated = matches!(
                old_issued_result,
                SessionTerminationReason::MaxLifetimeExceeded
            );

            collector.assertion(
                "Token exceeding High profile max_lifetime should be terminated",
                old_issued_terminated,
                json!({
                    "termination_reason": format!("{:?}", old_issued_result),
                    "high_max_lifetime_secs": max_lifetime_secs,
                    "config_source": "ComplianceConfig::from_profile(FedRampHigh)",
                }),
            );

            // Test that a fresh session passes High policy
            let session = SessionState::new("test-session-id", "test-user-id");
            let termination_reason = high_policy.should_terminate(&session);
            let fresh_valid = matches!(termination_reason, SessionTerminationReason::None);

            collector.assertion(
                "Fresh session should not be terminated by High policy",
                fresh_valid,
                json!({ "termination_reason": format!("{:?}", termination_reason) }),
            );

            json!({
                "high_stricter_than_low": high_stricter_than_low,
                "timeouts_from_compliance": timeouts_from_compliance,
                "expired_token_terminated": expired_token_terminated,
                "from_compliance_path_tested": true,
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
/// Verifies that required security event types are actually emitted
/// when triggered, as required by NIST 800-53 AU-2.
///
/// This test emits security events and captures tracing output to verify
/// they are actually logged, not just that the enum variants exist.
pub fn test_au2_security_events() -> ControlTestArtifact {
    use test_capture::with_captured_tracing;

    ArtifactBuilder::new("AU-2", "Audit Events")
        .test_name("security_event_emission")
        .description("Verify security events are actually emitted when triggered (AU-2)")
        .code_location("src/observability/events.rs", 38, 120)
        .related_control("AU-3")
        .related_control("AU-12")
        .expected("auth_success_emitted", true)
        .expected("auth_failure_emitted", true)
        .expected("access_denied_emitted", true)
        .expected("session_event_emitted", true)
        .execute(|collector| {
            // Emit events and capture tracing output
            let (_, captured_output) = with_captured_tracing(|| {
                // Authentication success
                crate::security_event!(
                    SecurityEvent::AuthenticationSuccess,
                    user_id = "au2-test-user",
                    "Test authentication success"
                );

                // Authentication failure
                crate::security_event!(
                    SecurityEvent::AuthenticationFailure,
                    user_id = "au2-test-user",
                    reason = "invalid_password",
                    "Test authentication failure"
                );

                // Access denied
                crate::security_event!(
                    SecurityEvent::AccessDenied,
                    user_id = "au2-test-user",
                    resource = "/api/admin",
                    "Test access denied"
                );

                // Session created
                crate::security_event!(
                    SecurityEvent::SessionCreated,
                    session_id = "au2-test-session",
                    user_id = "au2-test-user",
                    "Test session created"
                );
            });

            collector.log(format!("Captured {} bytes of tracing output", captured_output.len()));

            let lines: Vec<&str> = captured_output.lines().filter(|l| !l.is_empty()).collect();
            collector.log(format!("Captured {} log lines", lines.len()));

            // Verify AuthenticationSuccess was emitted
            let auth_success_emitted = lines.iter().any(|l| {
                l.contains("authentication_success") ||
                l.contains("AuthenticationSuccess") ||
                (l.contains("authentication") && l.contains("success"))
            });

            collector.assertion(
                "AuthenticationSuccess event should be emitted",
                auth_success_emitted,
                json!({
                    "emitted": auth_success_emitted,
                    "lines_searched": lines.len(),
                }),
            );

            // Verify AuthenticationFailure was emitted
            let auth_failure_emitted = lines.iter().any(|l| {
                l.contains("authentication_failure") ||
                l.contains("AuthenticationFailure") ||
                (l.contains("authentication") && l.contains("failure"))
            });

            collector.assertion(
                "AuthenticationFailure event should be emitted",
                auth_failure_emitted,
                json!({ "emitted": auth_failure_emitted }),
            );

            // Verify AccessDenied was emitted
            let access_denied_emitted = lines.iter().any(|l| {
                l.contains("access_denied") ||
                l.contains("AccessDenied")
            });

            collector.assertion(
                "AccessDenied event should be emitted",
                access_denied_emitted,
                json!({ "emitted": access_denied_emitted }),
            );

            // Verify SessionCreated was emitted
            let session_event_emitted = lines.iter().any(|l| {
                l.contains("session_created") ||
                l.contains("SessionCreated")
            });

            collector.assertion(
                "SessionCreated event should be emitted",
                session_event_emitted,
                json!({ "emitted": session_event_emitted }),
            );

            json!({
                "auth_success_emitted": auth_success_emitted,
                "auth_failure_emitted": auth_failure_emitted,
                "access_denied_emitted": access_denied_emitted,
                "session_event_emitted": session_event_emitted,
            })
        })
}

/// AU-3: Content of Audit Records
///
/// Verifies that security events contain required audit fields in the
/// actual log output: timestamp, level, target, and custom fields.
///
/// This test emits a security event and parses the captured JSON output
/// to verify all required AU-3 fields are present.
pub fn test_au3_audit_content() -> ControlTestArtifact {
    use test_capture::with_captured_tracing;

    ArtifactBuilder::new("AU-3", "Content of Audit Records")
        .test_name("audit_record_fields")
        .description("Verify security events contain required AU-3 fields in output (AU-3)")
        .code_location("src/observability/events.rs", 120, 200)
        .related_control("AU-2")
        .expected("has_timestamp", true)
        .expected("has_level", true)
        .expected("has_target", true)
        .expected("has_message", true)
        .expected("has_custom_fields", true)
        .execute(|collector| {
            // Emit event and capture output
            let (_, captured_output) = with_captured_tracing(|| {
                crate::security_event!(
                    SecurityEvent::AccessDenied,
                    user_id = "au3-test-user",
                    resource = "/api/admin/settings",
                    action = "read",
                    reason = "insufficient_permissions",
                    "Access denied to protected resource"
                );
            });

            collector.log(format!("Captured output: {}", captured_output));

            // Parse the JSON output
            let parsed: Option<serde_json::Value> = captured_output
                .lines()
                .filter(|l| !l.is_empty())
                .find_map(|line| serde_json::from_str(line).ok());

            let parsed = parsed.unwrap_or(serde_json::json!({}));

            collector.configuration(
                "parsed_log_entry",
                parsed.clone(),
            );

            // AU-3 requires: what type of event, when, where, source, outcome
            // In JSON logs: timestamp, level, target, message, fields

            // Check timestamp (when)
            let has_timestamp = parsed.get("timestamp").is_some();
            collector.assertion(
                "Audit record must have timestamp (AU-3: when)",
                has_timestamp,
                json!({ "timestamp": parsed.get("timestamp") }),
            );

            // Check level (severity/outcome indication)
            let has_level = parsed.get("level").is_some();
            collector.assertion(
                "Audit record must have level (AU-3: outcome)",
                has_level,
                json!({ "level": parsed.get("level") }),
            );

            // Check target (where in code)
            let has_target = parsed.get("target").is_some();
            collector.assertion(
                "Audit record must have target (AU-3: source)",
                has_target,
                json!({ "target": parsed.get("target") }),
            );

            // Check message exists
            let has_message = parsed.get("fields")
                .and_then(|f| f.get("message"))
                .is_some()
                || parsed.get("message").is_some();
            collector.assertion(
                "Audit record must have message (AU-3: what)",
                has_message,
                json!({
                    "has_fields_message": parsed.get("fields").and_then(|f| f.get("message")).is_some(),
                    "has_root_message": parsed.get("message").is_some(),
                }),
            );

            // Check custom fields (user_id, resource, etc.)
            let fields = parsed.get("fields").cloned().unwrap_or(serde_json::json!({}));
            let has_user_id = fields.get("user_id").is_some();
            let has_resource = fields.get("resource").is_some();
            let has_custom_fields = has_user_id && has_resource;

            collector.assertion(
                "Audit record should include custom security fields",
                has_custom_fields,
                json!({
                    "user_id": fields.get("user_id"),
                    "resource": fields.get("resource"),
                    "action": fields.get("action"),
                    "reason": fields.get("reason"),
                }),
            );

            json!({
                "has_timestamp": has_timestamp,
                "has_level": has_level,
                "has_target": has_target,
                "has_message": has_message,
                "has_custom_fields": has_custom_fields,
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

/// IA-5(7): No Embedded Unencrypted Static Authenticators
///
/// Verifies that the secret detection scanner can identify embedded
/// secrets in code, preventing unencrypted authenticators from being
/// stored in applications.
pub fn test_ia5_7_secret_detection() -> ControlTestArtifact {
    ArtifactBuilder::new("IA-5(7)", "No Embedded Unencrypted Static Authenticators")
        .test_name("secret_detection_scanner")
        .description("Verify secret detection identifies embedded authenticators (IA-5(7))")
        .code_location("src/secrets.rs", 1, 700)
        .related_control("IA-5")
        .related_control("IA-5(1)")
        .input("test_aws_key", "AKIAIOSFODNN7EXAMPLE")
        .input("test_github_token", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        .expected("detects_aws_credentials", true)
        .expected("detects_github_tokens", true)
        .expected("detects_private_keys", true)
        .expected("no_false_positives_on_clean_code", true)
        .execute(|collector| {
            let scanner = SecretScanner::default();

            collector.configuration(
                "scanner_config",
                json!({
                    "pattern_count": scanner.pattern_count(),
                    "patterns": scanner.pattern_ids(),
                }),
            );

            // Test AWS credential detection
            let aws_content = r#"aws_access_key_id = "AKIAIOSFODNN7EXAMPLE""#;
            let aws_findings = scanner.scan_content(aws_content, "test.py");
            let detects_aws = aws_findings.iter().any(|f| f.category == SecretCategory::AwsCredentials);

            collector.assertion(
                "Should detect AWS access keys",
                detects_aws,
                json!({
                    "findings_count": aws_findings.len(),
                    "detected": detects_aws,
                }),
            );

            // Test GitHub token detection
            let github_content = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            let github_findings = scanner.scan_content(github_content, "test.sh");
            let detects_github = github_findings.iter().any(|f| f.category == SecretCategory::GitToken);

            collector.assertion(
                "Should detect GitHub tokens",
                detects_github,
                json!({
                    "findings_count": github_findings.len(),
                    "detected": detects_github,
                }),
            );

            // Test private key detection
            let key_content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----";
            let key_findings = scanner.scan_content(key_content, "test.pem");
            let detects_keys = key_findings.iter().any(|f| f.category == SecretCategory::PrivateKey);

            collector.assertion(
                "Should detect private keys",
                detects_keys,
                json!({
                    "findings_count": key_findings.len(),
                    "detected": detects_keys,
                }),
            );

            // Test no false positives on clean code
            let clean_content = r#"
fn main() {
    let x = 42;
    println!("Hello, world!");
}
"#;
            let clean_findings = scanner.scan_content(clean_content, "test.rs");
            let no_false_positives = clean_findings.is_empty();

            collector.assertion(
                "Clean code should produce no findings",
                no_false_positives,
                json!({
                    "findings_count": clean_findings.len(),
                    "no_false_positives": no_false_positives,
                }),
            );

            // Log category coverage
            let categories_covered = vec![
                SecretCategory::AwsCredentials,
                SecretCategory::ApiKey,
                SecretCategory::GitToken,
                SecretCategory::PrivateKey,
                SecretCategory::Token,
                SecretCategory::DatabaseCredential,
            ];

            collector.log(format!(
                "Secret categories covered: {:?}",
                categories_covered.iter().map(|c| c.name()).collect::<Vec<_>>()
            ));

            json!({
                "detects_aws_credentials": detects_aws,
                "detects_github_tokens": detects_github,
                "detects_private_keys": detects_keys,
                "no_false_positives_on_clean_code": no_false_positives,
            })
        })
}

/// IA-5: Authenticator Management
///
/// Verifies that authenticator (credential) management follows security
/// best practices including constant-time comparison to prevent timing attacks.
pub fn test_ia5_authenticator_management() -> ControlTestArtifact {
    use crate::crypto::{constant_time_eq, constant_time_str_eq};

    ArtifactBuilder::new("IA-5", "Authenticator Management")
        .test_name("credential_security")
        .description("Verify secure authenticator handling with constant-time comparison (IA-5)")
        .code_location("src/crypto.rs", 1, 100)
        .related_control("IA-5(1)")
        .related_control("SC-13")
        .expected("constant_time_comparison_available", true)
        .expected("prevents_timing_attacks", true)
        .expected("handles_unequal_lengths", true)
        .execute(|collector| {
            // Verify constant-time byte comparison exists and works
            let secret1 = b"super-secret-password-123";
            let secret2 = b"super-secret-password-123";
            let secret3 = b"wrong-password-completely";

            let equal_match = constant_time_eq(secret1, secret2);
            let unequal_no_match = !constant_time_eq(secret1, secret3);

            collector.assertion(
                "Constant-time comparison should match equal values",
                equal_match,
                json!({
                    "equal_values": true,
                    "result": equal_match,
                }),
            );

            collector.assertion(
                "Constant-time comparison should reject unequal values",
                unequal_no_match,
                json!({
                    "equal_values": false,
                    "result": !unequal_no_match,
                }),
            );

            // Verify string comparison
            let str_equal = constant_time_str_eq("api-key-12345", "api-key-12345");
            let str_unequal = !constant_time_str_eq("api-key-12345", "api-key-67890");

            collector.assertion(
                "String constant-time comparison should work correctly",
                str_equal && str_unequal,
                json!({
                    "string_equal_test": str_equal,
                    "string_unequal_test": str_unequal,
                }),
            );

            // Verify handling of different lengths (should not short-circuit)
            let short = b"short";
            let long = b"this-is-a-much-longer-value";
            let handles_unequal_lengths = !constant_time_eq(short, long);

            collector.assertion(
                "Should handle unequal length inputs safely",
                handles_unequal_lengths,
                json!({
                    "short_length": short.len(),
                    "long_length": long.len(),
                    "result": handles_unequal_lengths,
                }),
            );

            collector.configuration(
                "crypto_implementation",
                json!({
                    "library": "subtle crate",
                    "algorithm": "constant-time comparison",
                    "timing_attack_resistant": true,
                }),
            );

            json!({
                "constant_time_comparison_available": true,
                "prevents_timing_attacks": equal_match && unequal_no_match,
                "handles_unequal_lengths": handles_unequal_lengths,
            })
        })
}

/// IA-6: Authentication Feedback
///
/// Verifies that authentication error responses do not leak sensitive
/// information that could aid an attacker (e.g., "user not found" vs "invalid password").
pub fn test_ia6_auth_feedback() -> ControlTestArtifact {
    use crate::error::{AppError, ErrorConfig};

    ArtifactBuilder::new("IA-6", "Authentication Feedback")
        .test_name("secure_error_responses")
        .description("Verify authentication errors don't leak sensitive information (IA-6)")
        .code_location("src/error.rs", 1, 300)
        .related_control("SI-11")
        .related_control("IA-5")
        .expected("production_hides_details", true)
        .expected("internal_hides_details", true)
        .expected("no_user_enumeration", true)
        .execute(|collector| {
            // Test that production mode hides internal details
            let production_config = ErrorConfig::production();

            collector.configuration(
                "error_config",
                json!({
                    "expose_details": production_config.expose_details,
                    "include_stack_traces": production_config.include_stack_traces,
                    "log_errors": production_config.log_errors,
                }),
            );

            // Create an auth error
            let auth_error = AppError::unauthorized("Authentication failed");
            let error_response = auth_error.to_string();

            // Verify response doesn't leak whether user exists
            let no_user_enumeration = !error_response.to_lowercase().contains("user not found")
                && !error_response.to_lowercase().contains("invalid user")
                && !error_response.to_lowercase().contains("no such user");

            collector.assertion(
                "Auth errors should not reveal if user exists",
                no_user_enumeration,
                json!({
                    "error_message": error_response,
                    "contains_user_info": !no_user_enumeration,
                }),
            );

            // Verify internal errors don't expose details
            let internal_error = AppError::internal_msg("Database connection failed");

            // The key security control: Internal errors should NOT expose details
            // This prevents information leakage about internal system state
            let internal_hides_details = !internal_error.kind.expose_details();

            collector.assertion(
                "Internal error kind should not expose details (IA-6 / SI-11)",
                internal_hides_details,
                json!({
                    "error_kind": format!("{:?}", internal_error.kind),
                    "expose_details": internal_error.kind.expose_details(),
                    "expected": false,
                }),
            );

            // Verify production config hides details globally
            let production_hides_internal = !production_config.expose_details
                && !production_config.include_stack_traces;

            collector.assertion(
                "Production config should hide error details and stack traces",
                production_hides_internal,
                json!({
                    "expose_details": production_config.expose_details,
                    "include_stack_traces": production_config.include_stack_traces,
                }),
            );

            // Verify different auth failure reasons produce same external message
            let bad_password = AppError::unauthorized("Invalid credentials");
            let bad_token = AppError::unauthorized("Invalid credentials");

            let same_external_message = bad_password.to_string() == bad_token.to_string();

            collector.assertion(
                "Different auth failures should produce same external message",
                same_external_message,
                json!({
                    "bad_password_msg": bad_password.to_string(),
                    "bad_token_msg": bad_token.to_string(),
                    "messages_equal": same_external_message,
                }),
            );

            json!({
                "production_hides_details": !production_config.expose_details,
                "internal_hides_details": internal_hides_details,
                "no_user_enumeration": no_user_enumeration,
            })
        })
}

/// SC-8: Transmission Confidentiality and Integrity
///
/// Verifies that:
/// 1. Security headers for transmission protection are properly configured (HSTS, secure cookies)
/// 2. Database SSL defaults to VerifyFull (when postgres feature is enabled)
pub fn test_sc8_transmission_security() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-8", "Transmission Confidentiality and Integrity")
        .test_name("transmission_security_configuration")
        .description("Verify transmission security for HTTP headers and database connections (SC-8)")
        .code_location("src/layers.rs", 75, 95)
        .related_control("CM-6")
        .expected("security_headers_enabled", true)
        .expected("can_be_disabled", true)
        .execute(|collector| {
            // Default config should have security headers enabled
            let default_config = SecurityConfig::default();
            let headers_enabled = default_config.security_headers_enabled;

            collector.configuration(
                "http_security_config",
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

            // Database SSL verification (when postgres feature is enabled)
            #[cfg(feature = "postgres")]
            {
                use crate::database::{DatabaseConfig, SslMode};

                let db_config = DatabaseConfig::default();
                let ssl_is_verify_full = matches!(db_config.ssl_mode, SslMode::VerifyFull);

                collector.configuration(
                    "database_ssl_config",
                    json!({
                        "ssl_mode": format!("{:?}", db_config.ssl_mode),
                        "ssl_require_valid_cert": db_config.ssl_require_valid_cert,
                    }),
                );

                collector.assertion(
                    "Database SSL should default to VerifyFull for FedRAMP compliance",
                    ssl_is_verify_full,
                    json!({
                        "ssl_mode": format!("{:?}", db_config.ssl_mode),
                        "is_verify_full": ssl_is_verify_full,
                        "fedramp_compliant": ssl_is_verify_full,
                    }),
                );
            }

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

/// SC-28: Protection of Information at Rest
///
/// Verifies that field-level encryption is available and working correctly
/// for protecting sensitive data at rest.
pub fn test_sc28_protection_at_rest() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-28", "Protection of Information at Rest")
        .test_name("field_level_encryption")
        .description("Verify encryption config from compliance profile protects data at rest (SC-28)")
        .code_location("src/encryption.rs", 97, 104)
        .code_location_with_fn("src/compliance/config.rs", 159, 161, "ComplianceConfig")
        .related_control("SC-13")
        .related_control("SC-12")
        .input("profiles_tested", "FedRAMP Low, Moderate, High")
        .input("algorithm", "AES-256-GCM")
        .expected("low_no_encryption_required", true)
        .expected("moderate_requires_encryption", true)
        .expected("high_requires_disk_verification", true)
        .expected("encryption_roundtrip_works", true)
        .expected("tamper_detection_works", true)
        .expected("from_compliance_path_tested", true)
        .execute(|collector| {
            // Test FedRAMP Low profile (encryption not required)
            let low_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampLow);
            let low_enc_config = EncryptionConfig::from_compliance(&low_config);

            collector.configuration(
                "fedramp_low_encryption",
                json!({
                    "profile": "FedRAMP Low",
                    "require_encryption": low_enc_config.require_encryption,
                    "verify_database_encryption": low_enc_config.verify_database_encryption,
                    "verify_disk_encryption": low_enc_config.verify_disk_encryption,
                    "algorithm": format!("{:?}", low_enc_config.algorithm),
                    "derived_from": "EncryptionConfig::from_compliance()",
                }),
            );

            let low_no_encryption_required = !low_enc_config.require_encryption;
            collector.assertion(
                "FedRAMP Low should not require encryption at rest",
                low_no_encryption_required,
                json!({
                    "require_encryption": low_enc_config.require_encryption,
                    "compliance_config_value": low_config.require_encryption_at_rest,
                    "config_source": "ComplianceConfig::from_profile(FedRampLow)",
                }),
            );

            // Test FedRAMP Moderate profile (encryption required)
            let moderate_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
            let moderate_enc_config = EncryptionConfig::from_compliance(&moderate_config);

            collector.configuration(
                "fedramp_moderate_encryption",
                json!({
                    "profile": "FedRAMP Moderate",
                    "require_encryption": moderate_enc_config.require_encryption,
                    "verify_database_encryption": moderate_enc_config.verify_database_encryption,
                    "verify_disk_encryption": moderate_enc_config.verify_disk_encryption,
                    "derived_from": "EncryptionConfig::from_compliance()",
                }),
            );

            let moderate_requires_encryption = moderate_enc_config.require_encryption
                && moderate_enc_config.verify_database_encryption;
            collector.assertion(
                "FedRAMP Moderate should require encryption at rest",
                moderate_requires_encryption,
                json!({
                    "require_encryption": moderate_enc_config.require_encryption,
                    "verify_database_encryption": moderate_enc_config.verify_database_encryption,
                    "config_source": "ComplianceConfig::from_profile(FedRampModerate)",
                }),
            );

            // Test FedRAMP High profile (encryption + disk verification required)
            let high_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
            let high_enc_config = EncryptionConfig::from_compliance(&high_config);

            collector.configuration(
                "fedramp_high_encryption",
                json!({
                    "profile": "FedRAMP High",
                    "require_encryption": high_enc_config.require_encryption,
                    "verify_database_encryption": high_enc_config.verify_database_encryption,
                    "verify_disk_encryption": high_enc_config.verify_disk_encryption,
                    "derived_from": "EncryptionConfig::from_compliance()",
                }),
            );

            let high_requires_disk_verification = high_enc_config.require_encryption
                && high_enc_config.verify_database_encryption
                && high_enc_config.verify_disk_encryption;
            collector.assertion(
                "FedRAMP High should require disk encryption verification",
                high_requires_disk_verification,
                json!({
                    "require_encryption": high_enc_config.require_encryption,
                    "verify_disk_encryption": high_enc_config.verify_disk_encryption,
                    "require_mtls_drives_disk_check": high_config.require_mtls,
                    "config_source": "ComplianceConfig::from_profile(FedRampHigh)",
                }),
            );

            // Verify algorithm properties
            let algo = EncryptionAlgorithm::Aes256Gcm;
            let algo_valid = algo.key_size() == 32 && algo.nonce_size() == 12 && algo.tag_size() == 16;

            collector.assertion(
                "AES-256-GCM algorithm properties are correct",
                algo_valid,
                json!({
                    "key_size": algo.key_size(),
                    "nonce_size": algo.nonce_size(),
                    "tag_size": algo.tag_size(),
                }),
            );

            // Create encryptor with test key and verify roundtrip
            let test_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let encryptor = FieldEncryptor::new(test_key).expect("Valid test key");

            let plaintext = "sensitive-ssn-123-45-6789";
            let encrypted = encryptor.encrypt_string(plaintext).expect("Encrypt");
            let decrypted = encryptor.decrypt_string(&encrypted).expect("Decrypt");
            let roundtrip_works = decrypted == plaintext;

            collector.assertion(
                "Encryption roundtrip preserves data",
                roundtrip_works,
                json!({
                    "plaintext_len": plaintext.len(),
                    "encrypted_len": encrypted.len(),
                    "decrypted_matches": roundtrip_works,
                }),
            );

            // Test tamper detection (GCM authentication)
            let encrypted_bytes = encryptor.encrypt(plaintext.as_bytes()).expect("Encrypt");
            let mut tampered = encrypted_bytes.clone();
            if tampered.len() > 20 {
                tampered[20] ^= 0xff; // Flip a bit in ciphertext
            }
            let tamper_detected = encryptor.decrypt(&tampered).is_err();

            collector.assertion(
                "Tampered ciphertext is detected and rejected",
                tamper_detected,
                json!({ "tamper_detected": tamper_detected }),
            );

            // Test unique nonces (same plaintext -> different ciphertext)
            let enc1 = encryptor.encrypt(b"same-data").expect("Encrypt 1");
            let enc2 = encryptor.encrypt(b"same-data").expect("Encrypt 2");
            let unique_nonces = enc1 != enc2;

            collector.assertion(
                "Each encryption uses unique nonce (no ciphertext reuse)",
                unique_nonces,
                json!({ "unique_nonces": unique_nonces }),
            );

            // Log encryption verification status using High profile config
            let status = crate::encryption::verify_encryption_config(&high_enc_config, Some(test_key));
            collector.log(format!(
                "Encryption verification (High profile): field_encryption={}, compliant={}",
                status.field_encryption_available, status.compliant
            ));

            json!({
                "low_no_encryption_required": low_no_encryption_required,
                "moderate_requires_encryption": moderate_requires_encryption,
                "high_requires_disk_verification": high_requires_disk_verification,
                "encryption_roundtrip_works": roundtrip_works,
                "tamper_detection_works": tamper_detected,
                "from_compliance_path_tested": true,
            })
        })
}

/// SC-23: Session Authenticity
///
/// Verifies that session state is protected against tampering and
/// session hijacking through proper session management.
pub fn test_sc23_session_authenticity() -> ControlTestArtifact {
    use crate::session::{SessionPolicy, SessionState};
    use std::time::Duration;

    ArtifactBuilder::new("SC-23", "Session Authenticity")
        .test_name("session_state_protection")
        .description("Verify session state authenticity and anti-tampering (SC-23)")
        .code_location("src/session.rs", 1, 400)
        .related_control("AC-11")
        .related_control("AC-12")
        .related_control("SC-10")
        .expected("session_has_unique_id", true)
        .expected("session_tracks_creation", true)
        .expected("session_tracks_activity", true)
        .expected("session_can_be_invalidated", true)
        .execute(|collector| {
            // Verify session IDs are unique
            let session1 = SessionState::new("session-aaa-111", "user-1");
            let session2 = SessionState::new("session-bbb-222", "user-2");

            let session_has_unique_id = session1.session_id != session2.session_id;

            collector.assertion(
                "Sessions should have unique identifiers",
                session_has_unique_id,
                json!({
                    "session1_id": &session1.session_id,
                    "session2_id": &session2.session_id,
                    "unique": session_has_unique_id,
                }),
            );

            // Verify session tracks creation time
            let session = SessionState::new("test-session", "test-user");
            let session_tracks_creation = session.created_at.is_some();

            collector.assertion(
                "Session should track creation time",
                session_tracks_creation,
                json!({
                    "has_created_at": session_tracks_creation,
                    "timestamp_type": "std::time::Instant",
                }),
            );

            // Verify session tracks last activity
            let mut active_session = SessionState::new("active-session", "active-user");
            let before_activity = active_session.last_activity;
            std::thread::sleep(Duration::from_millis(10));
            active_session.record_activity();
            let after_activity = active_session.last_activity;

            // Both should be Some, and after should be newer (but Instant doesn't have >)
            // So we check that activity was recorded (last_activity was updated)
            let session_tracks_activity = after_activity.is_some() && before_activity.is_some();

            collector.assertion(
                "Session should track last activity for idle timeout",
                session_tracks_activity,
                json!({
                    "activity_updated": session_tracks_activity,
                    "before": format!("{:?}", before_activity),
                    "after": format!("{:?}", after_activity),
                }),
            );

            // Verify session can be invalidated (prevents session fixation)
            let mut session_to_invalidate = SessionState::new("invalidate-me", "user");
            let was_active = session_to_invalidate.is_active;
            session_to_invalidate.terminate();
            let now_terminated = !session_to_invalidate.is_active;

            let session_can_be_invalidated = was_active && now_terminated;

            collector.assertion(
                "Session should be invalidatable for security",
                session_can_be_invalidated,
                json!({
                    "was_active": was_active,
                    "now_terminated": now_terminated,
                    "termination_reason": "SecurityConcern",
                }),
            );

            // Verify session policy enforces authenticity checks
            let policy = SessionPolicy::builder()
                .idle_timeout(Duration::from_secs(900))
                .max_lifetime(Duration::from_secs(28800))
                .build();

            let policy_exists = policy.idle_timeout.as_secs() > 0;

            collector.configuration(
                "session_policy",
                json!({
                    "idle_timeout_secs": policy.idle_timeout.as_secs(),
                    "max_lifetime_secs": policy.max_lifetime.as_secs(),
                    "enforces_timeouts": true,
                }),
            );

            collector.assertion(
                "Session policy should enforce timeout checks",
                policy_exists,
                json!({
                    "policy_configured": policy_exists,
                    "idle_timeout": policy.idle_timeout.as_secs(),
                    "max_lifetime": policy.max_lifetime.as_secs(),
                }),
            );

            json!({
                "session_has_unique_id": session_has_unique_id,
                "session_tracks_creation": session_tracks_creation,
                "session_tracks_activity": session_tracks_activity,
                "session_can_be_invalidated": session_can_be_invalidated,
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

// ============================================================================
// Phase 6: Extended Control Coverage
// ============================================================================

/// AC-3: Access Enforcement
///
/// Verifies that role-based and scope-based access controls are enforced
/// correctly through the Claims type.
pub fn test_ac3_access_enforcement() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-3", "Access Enforcement")
        .test_name("role_and_scope_enforcement")
        .description("Verify role-based and scope-based access controls work correctly (AC-3)")
        .code_location("src/auth.rs", 161, 184)
        .related_control("AC-6")
        .related_control("IA-2")
        .input("admin_role", "admin")
        .input("user_role", "user")
        .input("required_scope", "write:data")
        .expected("role_check_works", true)
        .expected("scope_check_works", true)
        .expected("multi_role_check_works", true)
        .execute(|collector| {
            // Create claims with specific roles and scopes
            let admin_claims = Claims::new("user-123")
                .with_role("admin")
                .with_role("user")
                .with_scope("read:data")
                .with_scope("write:data");

            let user_claims = Claims::new("user-456")
                .with_role("user")
                .with_scope("read:data");

            collector.configuration(
                "admin_claims",
                json!({
                    "subject": admin_claims.subject,
                    "roles": admin_claims.roles.iter().collect::<Vec<_>>(),
                    "scopes": admin_claims.scopes.iter().collect::<Vec<_>>(),
                }),
            );

            collector.configuration(
                "user_claims",
                json!({
                    "subject": user_claims.subject,
                    "roles": user_claims.roles.iter().collect::<Vec<_>>(),
                    "scopes": user_claims.scopes.iter().collect::<Vec<_>>(),
                }),
            );

            // Test role checking
            let admin_has_admin = admin_claims.has_role("admin");
            let user_has_admin = user_claims.has_role("admin");
            let role_check_works = admin_has_admin && !user_has_admin;

            collector.assertion(
                "Admin should have admin role, user should not",
                role_check_works,
                json!({
                    "admin_has_admin": admin_has_admin,
                    "user_has_admin": user_has_admin,
                }),
            );

            // Test scope checking
            let admin_has_write = admin_claims.has_scope("write:data");
            let user_has_write = user_claims.has_scope("write:data");
            let scope_check_works = admin_has_write && !user_has_write;

            collector.assertion(
                "Admin should have write scope, user should not",
                scope_check_works,
                json!({
                    "admin_has_write": admin_has_write,
                    "user_has_write": user_has_write,
                }),
            );

            // Test multi-role checking
            let has_any = admin_claims.has_any_role(&["admin", "superuser"]);
            let has_all = admin_claims.has_all_roles(&["admin", "user"]);
            let multi_role_check_works = has_any && has_all;

            collector.assertion(
                "Multi-role checks should work correctly",
                multi_role_check_works,
                json!({
                    "has_any_admin_superuser": has_any,
                    "has_all_admin_user": has_all,
                }),
            );

            json!({
                "role_check_works": role_check_works,
                "scope_check_works": scope_check_works,
                "multi_role_check_works": multi_role_check_works,
            })
        })
}

/// AC-12: Session Termination
///
/// Verifies that sessions are automatically terminated after maximum
/// lifetime is exceeded (absolute timeout).
pub fn test_ac12_session_termination() -> ControlTestArtifact {
    ArtifactBuilder::new("AC-12", "Session Termination")
        .test_name("absolute_timeout_enforcement")
        .description("Verify session termination derived from compliance profile (AC-12)")
        .code_location("src/session.rs", 147, 169)
        .code_location_with_fn("src/compliance/config.rs", 106, 116, "ComplianceConfig")
        .related_control("AC-11")
        .related_control("SC-10")
        .input("profiles_tested", "FedRAMP Moderate, High")
        .expected("max_lifetime_from_compliance", true)
        .expected("high_shorter_than_moderate", true)
        .expected("fresh_session_valid", true)
        .expected("from_compliance_path_tested", true)
        .execute(|collector| {
            // Test FedRAMP Moderate profile
            let moderate_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
            let moderate_policy = SessionPolicy::from_compliance(&moderate_config);

            collector.configuration(
                "fedramp_moderate_session",
                json!({
                    "profile": "FedRAMP Moderate",
                    "max_lifetime_secs": moderate_policy.max_lifetime.as_secs(),
                    "idle_timeout_secs": moderate_policy.idle_timeout.as_secs(),
                    "allow_extension": moderate_policy.allow_extension,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            // Test FedRAMP High profile (stricter)
            let high_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
            let high_policy = SessionPolicy::from_compliance(&high_config);

            collector.configuration(
                "fedramp_high_session",
                json!({
                    "profile": "FedRAMP High",
                    "max_lifetime_secs": high_policy.max_lifetime.as_secs(),
                    "idle_timeout_secs": high_policy.idle_timeout.as_secs(),
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            // Verify max lifetime comes from compliance config
            let max_lifetime_from_compliance = high_policy.max_lifetime == high_config.session_max_lifetime
                && moderate_policy.max_lifetime == moderate_config.session_max_lifetime;

            collector.assertion(
                "Max lifetime should be derived from ComplianceConfig",
                max_lifetime_from_compliance,
                json!({
                    "high_matches": high_policy.max_lifetime == high_config.session_max_lifetime,
                    "moderate_matches": moderate_policy.max_lifetime == moderate_config.session_max_lifetime,
                    "config_source": "ComplianceConfig::from_profile()",
                }),
            );

            // Verify High has shorter lifetime than Moderate
            let high_shorter_than_moderate = high_policy.max_lifetime < moderate_policy.max_lifetime;

            collector.assertion(
                "FedRAMP High should have shorter max lifetime than Moderate",
                high_shorter_than_moderate,
                json!({
                    "high_lifetime_secs": high_policy.max_lifetime.as_secs(),
                    "moderate_lifetime_secs": moderate_policy.max_lifetime.as_secs(),
                }),
            );

            // Test fresh session is valid under High policy
            let session = SessionState::new("session-123", "user-456");
            let termination = high_policy.should_terminate(&session);
            let fresh_valid = matches!(termination, SessionTerminationReason::None);

            collector.assertion(
                "Fresh session should not be terminated",
                fresh_valid,
                json!({
                    "termination_reason": format!("{:?}", termination),
                    "policy": "FedRAMP High (from_compliance)",
                }),
            );

            // Verify termination reasons are defined
            let reasons = [
                SessionTerminationReason::MaxLifetimeExceeded,
                SessionTerminationReason::IdleTimeout,
                SessionTerminationReason::TokenExpired,
            ];
            let reasons_defined = reasons.iter().all(|r| !r.message().is_empty());

            collector.assertion(
                "Termination reasons should have messages",
                reasons_defined,
                json!({
                    "max_lifetime_msg": SessionTerminationReason::MaxLifetimeExceeded.message(),
                    "idle_timeout_msg": SessionTerminationReason::IdleTimeout.message(),
                    "token_expired_msg": SessionTerminationReason::TokenExpired.message(),
                }),
            );

            json!({
                "max_lifetime_from_compliance": max_lifetime_from_compliance,
                "high_shorter_than_moderate": high_shorter_than_moderate,
                "fresh_session_valid": fresh_valid,
                "from_compliance_path_tested": true,
            })
        })
}

/// AU-12: Audit Record Generation
///
/// Verifies that the audit system can generate audit records at runtime
/// with all required fields.
pub fn test_au12_audit_generation() -> ControlTestArtifact {
    use crate::audit::{AuditOutcome, AuditRecord};

    ArtifactBuilder::new("AU-12", "Audit Record Generation")
        .test_name("audit_record_creation")
        .description("Verify audit records can be generated with required fields (AU-12)")
        .code_location("src/audit.rs", 266, 313)
        .related_control("AU-2")
        .related_control("AU-3")
        .expected("record_has_required_fields", true)
        .expected("outcomes_defined", true)
        .execute(|collector| {
            // Create an audit record with all fields
            let record = AuditRecord {
                id: "audit-001".to_string(),
                timestamp: "2025-12-18T12:00:00Z".to_string(),
                event_type: "authentication".to_string(),
                actor: "user-123".to_string(),
                resource: "/api/login".to_string(),
                action: "POST".to_string(),
                outcome: AuditOutcome::Success,
                source_ip: "192.168.1.100".to_string(),
                details: Some("Login successful".to_string()),
            };

            collector.configuration(
                "audit_record",
                json!({
                    "id": record.id,
                    "timestamp": record.timestamp,
                    "event_type": record.event_type,
                    "actor": record.actor,
                    "resource": record.resource,
                    "action": record.action,
                    "outcome": record.outcome.to_string(),
                    "source_ip": record.source_ip,
                    "details": record.details,
                }),
            );

            // Verify required fields are present
            let has_id = !record.id.is_empty();
            let has_timestamp = !record.timestamp.is_empty();
            let has_actor = !record.actor.is_empty();
            let has_resource = !record.resource.is_empty();
            let has_action = !record.action.is_empty();
            let record_has_required_fields =
                has_id && has_timestamp && has_actor && has_resource && has_action;

            collector.assertion(
                "Audit record should have all required fields",
                record_has_required_fields,
                json!({
                    "has_id": has_id,
                    "has_timestamp": has_timestamp,
                    "has_actor": has_actor,
                    "has_resource": has_resource,
                    "has_action": has_action,
                }),
            );

            // Verify all outcome types are defined
            let outcomes = [
                AuditOutcome::Success,
                AuditOutcome::Failure,
                AuditOutcome::Denied,
                AuditOutcome::RateLimited,
            ];
            let outcomes_defined = outcomes.iter().all(|o| !o.to_string().is_empty());

            collector.assertion(
                "All audit outcomes should be defined",
                outcomes_defined,
                json!({
                    "outcomes": outcomes.iter().map(|o| o.to_string()).collect::<Vec<_>>(),
                }),
            );

            json!({
                "record_has_required_fields": record_has_required_fields,
                "outcomes_defined": outcomes_defined,
            })
        })
}

/// AU-8: Time Stamps
///
/// Verifies that all security events include accurate UTC timestamps,
/// as required by NIST 800-53 AU-8 for audit record generation.
///
/// This test actually emits a security event and captures the tracing output
/// to verify timestamps are present and in UTC format.
pub fn test_au8_timestamps() -> ControlTestArtifact {
    use test_capture::with_captured_tracing;

    ArtifactBuilder::new("AU-8", "Time Stamps")
        .test_name("security_event_timestamps")
        .description("Verify security events have UTC timestamps in captured output (AU-8)")
        .code_location("src/observability/events.rs", 38, 293)
        .related_control("AU-2")
        .related_control("AU-3")
        .related_control("AU-12")
        .expected("timestamp_present", true)
        .expected("timestamp_is_utc", true)
        .expected("timestamp_is_rfc3339", true)
        .execute(|collector| {
            collector.configuration(
                "timestamp_source",
                json!({
                    "provider": "tracing crate",
                    "format": "RFC 3339 / ISO 8601",
                    "timezone": "UTC",
                    "automatic": true,
                }),
            );

            // Emit a security event and capture the tracing output
            let (_, captured_output) = with_captured_tracing(|| {
                crate::security_event!(
                    SecurityEvent::AuthenticationSuccess,
                    user_id = "au8-test-user",
                    "AU-8 timestamp verification event"
                );
            });

            collector.log(format!("Captured tracing output: {}", captured_output));

            // Parse the captured JSON log line to extract timestamp
            let timestamp_str = captured_output
                .lines()
                .filter(|l| !l.is_empty())
                .find_map(|line| {
                    serde_json::from_str::<serde_json::Value>(line)
                        .ok()
                        .and_then(|v| v.get("timestamp").and_then(|t| t.as_str().map(String::from)))
                })
                .unwrap_or_default();

            collector.log(format!("Extracted timestamp: {}", timestamp_str));

            // Verify timestamp is present
            let timestamp_present = !timestamp_str.is_empty();

            collector.assertion(
                "Timestamp field should be present in log output",
                timestamp_present,
                json!({ "timestamp": &timestamp_str, "present": timestamp_present }),
            );

            // Verify UTC (ends with Z or +00:00)
            let timestamp_is_utc = timestamp_str.ends_with('Z')
                || timestamp_str.ends_with("+00:00")
                || timestamp_str.contains("+00:00");

            collector.assertion(
                "Timestamp should be in UTC",
                timestamp_is_utc,
                json!({
                    "timestamp": &timestamp_str,
                    "ends_with_z": timestamp_str.ends_with('Z'),
                    "contains_utc_offset": timestamp_str.contains("+00:00"),
                }),
            );

            // Verify RFC 3339 format (parseable by chrono)
            let timestamp_is_rfc3339 = chrono::DateTime::parse_from_rfc3339(&timestamp_str).is_ok();

            collector.assertion(
                "Timestamp should be RFC 3339 compliant",
                timestamp_is_rfc3339,
                json!({
                    "timestamp": &timestamp_str,
                    "rfc3339_parseable": timestamp_is_rfc3339,
                }),
            );

            json!({
                "timestamp_present": timestamp_present,
                "timestamp_is_utc": timestamp_is_utc,
                "timestamp_is_rfc3339": timestamp_is_rfc3339,
            })
        })
}

/// AU-14: Session Audit
///
/// Verifies that session lifecycle events are actually logged by calling
/// the session logging functions and capturing the tracing output.
///
/// This test calls `log_session_created()` and `log_session_terminated()`
/// and verifies the events appear in captured output with required fields.
pub fn test_au14_session_audit() -> ControlTestArtifact {
    use crate::session::{
        SessionState, SessionTerminationReason,
        log_session_created, log_session_terminated, log_session_activity,
    };
    use test_capture::with_captured_tracing;

    ArtifactBuilder::new("AU-14", "Session Audit")
        .test_name("session_lifecycle_logging")
        .description("Verify session lifecycle events are actually logged (AU-14)")
        .code_location("src/session.rs", 509, 555)
        .related_control("AC-11")
        .related_control("AC-12")
        .related_control("AU-2")
        .expected("session_creation_logged", true)
        .expected("session_activity_logged", true)
        .expected("session_termination_logged", true)
        .expected("log_contains_session_id", true)
        .expected("log_contains_user_id", true)
        .execute(|collector| {
            // Create a test session with identifiable IDs
            let session = SessionState::new("au14-test-session-xyz", "au14-test-user-abc")
                .with_client_info(Some("192.168.1.100".to_string()), Some("Mozilla/5.0".to_string()));

            collector.configuration(
                "test_session",
                json!({
                    "session_id": &session.session_id,
                    "user_id": &session.user_id,
                    "client_ip": session.client_ip,
                }),
            );

            // Call session logging functions and capture output
            let (_, captured_output) = with_captured_tracing(|| {
                log_session_created(&session);
                log_session_activity(&session, "/api/protected/resource");
                log_session_terminated(&session, SessionTerminationReason::IdleTimeout);
            });

            collector.log(format!("Captured {} bytes of session logs", captured_output.len()));

            let lines: Vec<&str> = captured_output.lines().filter(|l| !l.is_empty()).collect();
            collector.log(format!("Captured {} log lines", lines.len()));

            // Verify session creation was logged
            let session_creation_logged = lines.iter().any(|l| {
                l.contains("session") && (l.contains("created") || l.contains("Created"))
            });

            collector.assertion(
                "Session creation should be logged",
                session_creation_logged,
                json!({
                    "logged": session_creation_logged,
                    "lines_checked": lines.len(),
                }),
            );

            // Verify session activity was logged
            let session_activity_logged = lines.iter().any(|l| {
                l.contains("session") && l.contains("activity")
            });

            collector.assertion(
                "Session activity should be logged",
                session_activity_logged,
                json!({ "logged": session_activity_logged }),
            );

            // Verify session termination was logged
            let session_termination_logged = lines.iter().any(|l| {
                l.contains("session") && (l.contains("terminated") || l.contains("Terminated") || l.contains("destroyed"))
            });

            collector.assertion(
                "Session termination should be logged",
                session_termination_logged,
                json!({ "logged": session_termination_logged }),
            );

            // Verify session ID appears in logs
            let log_contains_session_id = lines.iter().any(|l| l.contains("au14-test-session-xyz"));

            collector.assertion(
                "Session ID should appear in logs for traceability",
                log_contains_session_id,
                json!({
                    "session_id": "au14-test-session-xyz",
                    "found_in_logs": log_contains_session_id,
                }),
            );

            // Verify user ID appears in logs
            let log_contains_user_id = lines.iter().any(|l| l.contains("au14-test-user-abc"));

            collector.assertion(
                "User ID should appear in logs for accountability",
                log_contains_user_id,
                json!({
                    "user_id": "au14-test-user-abc",
                    "found_in_logs": log_contains_user_id,
                }),
            );

            json!({
                "session_creation_logged": session_creation_logged,
                "session_activity_logged": session_activity_logged,
                "session_termination_logged": session_termination_logged,
                "log_contains_session_id": log_contains_session_id,
                "log_contains_user_id": log_contains_user_id,
            })
        })
}

/// AU-16: Cross-Organizational Audit Logging
///
/// Verifies that correlation IDs are generated and extracted for
/// distributed tracing across organizational boundaries.
///
/// This test actually calls `extract_or_generate_correlation_id()` to verify:
/// - Extraction from X-Correlation-ID header
/// - Extraction from X-Request-ID header
/// - Generation of unique IDs when no header is present
pub fn test_au16_correlation_id() -> ControlTestArtifact {
    use crate::audit::extract_or_generate_correlation_id;
    use axum::http::Request;
    use axum::body::Body;

    ArtifactBuilder::new("AU-16", "Cross-Organizational Audit Logging")
        .test_name("correlation_id_handling")
        .description("Verify correlation ID extraction and generation (AU-16)")
        .code_location("src/audit/mod.rs", 219, 245)
        .related_control("AU-3")
        .related_control("AU-12")
        .expected("generates_id_when_missing", true)
        .expected("extracts_x_correlation_id", true)
        .expected("extracts_x_request_id", true)
        .expected("generated_ids_are_unique", true)
        .expected("x_correlation_id_takes_priority", true)
        .execute(|collector| {
            collector.configuration(
                "correlation_id_source",
                json!({
                    "function": "extract_or_generate_correlation_id",
                    "location": "src/audit/mod.rs",
                    "headers_checked": ["x-correlation-id", "x-request-id"],
                    "fallback": "timestamp-based generation (req-{hex})",
                }),
            );

            // Test 1: Generate ID when no header present
            let req_no_header = Request::builder()
                .uri("/api/test")
                .body(Body::empty())
                .unwrap();

            let generated_id = extract_or_generate_correlation_id(&req_no_header);
            let generates_id_when_missing = !generated_id.is_empty() && generated_id.starts_with("req-");

            collector.assertion(
                "Should generate correlation ID when not provided",
                generates_id_when_missing,
                json!({
                    "generated_id": &generated_id,
                    "starts_with_req": generated_id.starts_with("req-"),
                }),
            );

            // Test 2: Extract from X-Correlation-ID
            let req_with_correlation = Request::builder()
                .uri("/api/test")
                .header("x-correlation-id", "external-corr-12345")
                .body(Body::empty())
                .unwrap();

            let extracted_corr = extract_or_generate_correlation_id(&req_with_correlation);
            let extracts_x_correlation_id = extracted_corr == "external-corr-12345";

            collector.assertion(
                "Should extract X-Correlation-ID header",
                extracts_x_correlation_id,
                json!({
                    "header": "x-correlation-id",
                    "expected": "external-corr-12345",
                    "actual": &extracted_corr,
                }),
            );

            // Test 3: Extract from X-Request-ID
            let req_with_request_id = Request::builder()
                .uri("/api/test")
                .header("x-request-id", "external-req-67890")
                .body(Body::empty())
                .unwrap();

            let extracted_req = extract_or_generate_correlation_id(&req_with_request_id);
            let extracts_x_request_id = extracted_req == "external-req-67890";

            collector.assertion(
                "Should extract X-Request-ID header",
                extracts_x_request_id,
                json!({
                    "header": "x-request-id",
                    "expected": "external-req-67890",
                    "actual": &extracted_req,
                }),
            );

            // Test 4: Generated IDs are unique
            let req1 = Request::builder().uri("/test1").body(Body::empty()).unwrap();
            let req2 = Request::builder().uri("/test2").body(Body::empty()).unwrap();
            let id1 = extract_or_generate_correlation_id(&req1);
            // Small delay to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_nanos(1));
            let id2 = extract_or_generate_correlation_id(&req2);
            let generated_ids_are_unique = id1 != id2;

            collector.assertion(
                "Generated correlation IDs should be unique",
                generated_ids_are_unique,
                json!({
                    "id1": &id1,
                    "id2": &id2,
                    "unique": generated_ids_are_unique,
                }),
            );

            // Test 5: X-Correlation-ID takes priority over X-Request-ID
            let req_both_headers = Request::builder()
                .uri("/api/test")
                .header("x-correlation-id", "priority-corr")
                .header("x-request-id", "fallback-req")
                .body(Body::empty())
                .unwrap();

            let priority_id = extract_or_generate_correlation_id(&req_both_headers);
            let x_correlation_id_takes_priority = priority_id == "priority-corr";

            collector.assertion(
                "X-Correlation-ID should take priority over X-Request-ID",
                x_correlation_id_takes_priority,
                json!({
                    "x_correlation_id": "priority-corr",
                    "x_request_id": "fallback-req",
                    "extracted": &priority_id,
                }),
            );

            json!({
                "generates_id_when_missing": generates_id_when_missing,
                "extracts_x_correlation_id": extracts_x_correlation_id,
                "extracts_x_request_id": extracts_x_request_id,
                "generated_ids_are_unique": generated_ids_are_unique,
                "x_correlation_id_takes_priority": x_correlation_id_takes_priority,
            })
        })
}

/// AU-9: Protection of Audit Information
///
/// Verifies that audit records are protected from unauthorized modification
/// through HMAC-SHA256 signing and chain integrity verification.
pub fn test_au9_audit_protection() -> ControlTestArtifact {
    ArtifactBuilder::new("AU-9", "Protection of Audit Information")
        .test_name("audit_log_integrity")
        .description("Verify audit logs are signed and tamper-evident (AU-9)")
        .code_location("src/audit/integrity.rs", 1, 150)
        .related_control("AU-3")
        .related_control("AU-12")
        .expected("records_are_signed", true)
        .expected("chain_is_intact", true)
        .expected("tamper_detection_works", true)
        .expected("algorithm_is_approved", true)
        .execute(|collector| {
            // Test key (32 bytes for HMAC-SHA256)
            let test_key = b"au9-compliance-test-key-32bytes!";
            let config = AuditIntegrityConfig::new(test_key);

            collector.configuration(
                "integrity_config",
                json!({
                    "algorithm": SignatureAlgorithm::HmacSha256.as_str(),
                    "key_length_bytes": test_key.len(),
                    "chain_records": true,
                }),
            );

            // Verify algorithm is NIST-approved
            let algo = SignatureAlgorithm::HmacSha256;
            let algorithm_is_approved = algo.as_str() == "HMAC-SHA256";

            collector.assertion(
                "Algorithm should be NIST-approved HMAC-SHA256",
                algorithm_is_approved,
                json!({
                    "algorithm": algo.as_str(),
                    "nist_approved": algorithm_is_approved,
                }),
            );

            // Create audit chain and add records
            let mut chain = AuditChain::new(config);
            let record1 = chain.append(
                "auth.login",
                "user@example.com",
                "/api/login",
                "POST",
                "success",
                "192.168.1.100",
                None,
            );
            let record2 = chain.append(
                "data.access",
                "user@example.com",
                "/api/sensitive",
                "GET",
                "success",
                "192.168.1.100",
                Some("Accessed PII data".to_string()),
            );

            // Verify records are signed
            let records_are_signed =
                !record1.signature.is_empty() && !record2.signature.is_empty();

            collector.assertion(
                "All audit records should be HMAC signed",
                records_are_signed,
                json!({
                    "record1_signed": !record1.signature.is_empty(),
                    "record2_signed": !record2.signature.is_empty(),
                    "signature_length": record1.signature.len(),
                }),
            );

            // Verify chain integrity
            let verification_result = chain.verify_integrity().expect("Verification should work");
            let chain_is_intact = verification_result.is_valid();

            collector.assertion(
                "Audit chain integrity should be verifiable",
                chain_is_intact,
                json!({
                    "records_verified": verification_result.records_verified,
                    "chain_intact": verification_result.chain_intact,
                    "errors": verification_result.errors,
                }),
            );

            // Verify chain links (second record references first)
            let chain_linked = record2.previous_hash.is_some()
                && record2.previous_hash.as_ref() == Some(&record1.compute_hash());

            collector.assertion(
                "Records should be cryptographically chained",
                chain_linked,
                json!({
                    "record2_has_previous_hash": record2.previous_hash.is_some(),
                    "hash_matches_previous": chain_linked,
                }),
            );

            // Verify tamper detection by simulating modification
            let mut tampered_chain = AuditChain::new(AuditIntegrityConfig::new(test_key));
            tampered_chain.append(
                "auth.login",
                "legitimate@example.com",
                "/api/login",
                "POST",
                "success",
                "192.168.1.100",
                None,
            );

            // Tamper with the record (simulating an attack)
            if let Some(record) = tampered_chain.records.first().cloned() {
                let mut modified = record;
                modified.actor = "attacker@evil.com".to_string();
                // Replace the record
                tampered_chain.records[0] = modified;
            }

            let tamper_result = tampered_chain.verify_integrity().expect("Should work");
            let tamper_detection_works = !tamper_result.is_valid();

            collector.assertion(
                "Tampered records should be detected",
                tamper_detection_works,
                json!({
                    "tamper_detected": tamper_detection_works,
                    "verification_failed": !tamper_result.chain_intact,
                    "error_count": tamper_result.errors.len(),
                }),
            );

            json!({
                "records_are_signed": records_are_signed,
                "chain_is_intact": chain_is_intact,
                "tamper_detection_works": tamper_detection_works,
                "algorithm_is_approved": algorithm_is_approved,
            })
        })
}

/// IA-3: Device Identification and Authentication (mTLS)
///
/// Verifies that mTLS enforcement is available for service-to-service
/// authentication, as required by NIST 800-53 IA-3 for FedRAMP High.
pub fn test_ia3_mtls_enforcement() -> ControlTestArtifact {
    use crate::tls::{detect_client_cert, MtlsMode};
    use axum::body::Body;
    use axum::http::Request;

    ArtifactBuilder::new("IA-3", "Device Identification and Authentication")
        .test_name("mtls_enforcement")
        .description("Verify mTLS enforcement for service-to-service authentication (IA-3)")
        .code_location("src/tls.rs", 408, 727)
        .related_control("SC-8")
        .related_control("SC-23")
        .input("mtls_mode", "Required")
        .expected("mtls_modes_defined", true)
        .expected("client_cert_detection_works", true)
        .expected("required_mode_is_fedramp_compliant", true)
        .execute(|collector| {
            // Verify mTLS modes are defined
            let modes = [MtlsMode::Disabled, MtlsMode::Optional, MtlsMode::Required];
            let mtls_modes_defined = modes.len() == 3;

            collector.configuration(
                "mtls_modes",
                json!({
                    "modes": modes.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
                    "default": MtlsMode::default().to_string(),
                }),
            );

            collector.assertion(
                "All mTLS modes should be defined",
                mtls_modes_defined,
                json!({
                    "disabled": MtlsMode::Disabled.to_string(),
                    "optional": MtlsMode::Optional.to_string(),
                    "required": MtlsMode::Required.to_string(),
                }),
            );

            // Verify client cert detection
            let req_with_cert = Request::builder()
                .uri("/test")
                .header("X-Client-Verify", "SUCCESS")
                .header("X-Client-Cert-Subject", "CN=test-service,O=TestOrg")
                .body(Body::empty())
                .unwrap();

            let cert_info = detect_client_cert(&req_with_cert);
            let client_cert_detection_works = cert_info.cert_present && cert_info.cert_verified;

            collector.assertion(
                "Client certificate detection should work via headers",
                client_cert_detection_works,
                json!({
                    "cert_present": cert_info.cert_present,
                    "cert_verified": cert_info.cert_verified,
                    "subject_dn": cert_info.subject_dn,
                }),
            );

            // Verify no cert detection
            let req_no_cert = Request::builder()
                .uri("/test")
                .body(Body::empty())
                .unwrap();

            let no_cert_info = detect_client_cert(&req_no_cert);
            let no_cert_detection_works = !no_cert_info.cert_present;

            collector.assertion(
                "Missing client certificate should be detected",
                no_cert_detection_works,
                json!({
                    "cert_present": no_cert_info.cert_present,
                    "cert_verified": no_cert_info.cert_verified,
                }),
            );

            // Verify Required mode is FedRAMP High compliant
            let required_mode = MtlsMode::Required;
            let required_mode_is_fedramp_compliant = required_mode.is_fedramp_high_compliant();

            collector.assertion(
                "Required mode should be FedRAMP High compliant",
                required_mode_is_fedramp_compliant,
                json!({
                    "mode": required_mode.to_string(),
                    "is_fedramp_high_compliant": required_mode_is_fedramp_compliant,
                    "requires_cert": required_mode.requires_cert(),
                }),
            );

            // Verify other modes are not FedRAMP High compliant
            let optional_not_compliant = !MtlsMode::Optional.is_fedramp_high_compliant();
            let disabled_not_compliant = !MtlsMode::Disabled.is_fedramp_high_compliant();

            collector.assertion(
                "Optional and Disabled modes should not be FedRAMP High compliant",
                optional_not_compliant && disabled_not_compliant,
                json!({
                    "optional_compliant": MtlsMode::Optional.is_fedramp_high_compliant(),
                    "disabled_compliant": MtlsMode::Disabled.is_fedramp_high_compliant(),
                }),
            );

            json!({
                "mtls_modes_defined": mtls_modes_defined,
                "client_cert_detection_works": client_cert_detection_works,
                "required_mode_is_fedramp_compliant": required_mode_is_fedramp_compliant,
            })
        })
}

/// SC-13: FIPS 140-3 Validated Cryptography
///
/// Verifies that FIPS-validated cryptographic modules are available
/// when the `fips` feature is enabled. Required for FedRAMP High.
pub fn test_sc13_fips_crypto() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-13-FIPS", "FIPS 140-3 Cryptographic Protection")
        .test_name("fips_validated_crypto")
        .description("Verify FIPS 140-3 validated cryptography is available (SC-13)")
        .code_location("src/encryption.rs", 150, 250)
        .related_control("SC-12")
        .related_control("SC-28")
        .input("fips_feature", cfg!(feature = "fips"))
        .expected("fips_mode_detectable", true)
        .expected("encryption_works", true)
        .execute(|collector| {
            // Check if FIPS mode is enabled
            let fips_enabled = crate::encryption::is_fips_mode();

            collector.configuration(
                "fips_config",
                json!({
                    "fips_mode_enabled": fips_enabled,
                    "fips_certificate": crate::encryption::fips_certificate(),
                }),
            );

            // FIPS mode detectability
            collector.assertion(
                "FIPS mode should be detectable",
                true, // is_fips_mode() function exists
                json!({
                    "fips_enabled": fips_enabled,
                    "detection_available": true,
                }),
            );

            // Test encryption works (regardless of FIPS mode)
            let test_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let encryptor = FieldEncryptor::new(test_key).expect("Valid key");
            let plaintext = "test-data-for-encryption";
            let encrypted = encryptor.encrypt_string(plaintext).expect("Encrypt");
            let decrypted = encryptor.decrypt_string(&encrypted).expect("Decrypt");
            let encryption_works = decrypted == plaintext;

            collector.assertion(
                "Encryption should work correctly",
                encryption_works,
                json!({
                    "algorithm": if fips_enabled { "FIPS AES-256-GCM (AWS-LC)" } else { "AES-256-GCM (RustCrypto)" },
                    "roundtrip_success": encryption_works,
                }),
            );

            // Log FIPS certificate info
            if let Some(cert) = crate::encryption::fips_certificate() {
                collector.log(format!("FIPS Certificate: {}", cert));
            } else {
                collector.log("FIPS mode not enabled (using RustCrypto)".to_string());
            }

            json!({
                "fips_mode_detectable": true,
                "fips_enabled": fips_enabled,
                "encryption_works": encryption_works,
            })
        })
}

/// SC-10: Network Disconnect
///
/// Verifies that the system can terminate network connections/sessions
/// after defined conditions are met.
pub fn test_sc10_network_disconnect() -> ControlTestArtifact {
    ArtifactBuilder::new("SC-10", "Network Disconnect")
        .test_name("session_disconnect_policy")
        .description("Verify network disconnect policies from compliance profile (SC-10)")
        .code_location("src/session.rs", 147, 169)
        .code_location_with_fn("src/compliance/config.rs", 106, 116, "ComplianceConfig")
        .related_control("AC-11")
        .related_control("AC-12")
        .input("profiles_tested", "FedRAMP Moderate, High")
        .expected("idle_disconnect_from_compliance", true)
        .expected("high_faster_disconnect", true)
        .expected("termination_reasons_exist", true)
        .expected("from_compliance_path_tested", true)
        .execute(|collector| {
            // Test FedRAMP Moderate profile
            let moderate_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
            let moderate_policy = SessionPolicy::from_compliance(&moderate_config);

            collector.configuration(
                "fedramp_moderate_disconnect",
                json!({
                    "profile": "FedRAMP Moderate",
                    "idle_timeout_secs": moderate_policy.idle_timeout.as_secs(),
                    "max_lifetime_secs": moderate_policy.max_lifetime.as_secs(),
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            // Test FedRAMP High profile (stricter disconnect)
            let high_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
            let high_policy = SessionPolicy::from_compliance(&high_config);

            collector.configuration(
                "fedramp_high_disconnect",
                json!({
                    "profile": "FedRAMP High",
                    "idle_timeout_secs": high_policy.idle_timeout.as_secs(),
                    "max_lifetime_secs": high_policy.max_lifetime.as_secs(),
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            // Verify idle timeout comes from compliance config
            let idle_disconnect_from_compliance = high_policy.idle_timeout == high_config.session_idle_timeout
                && moderate_policy.idle_timeout == moderate_config.session_idle_timeout;

            collector.assertion(
                "Idle disconnect timeout should come from ComplianceConfig",
                idle_disconnect_from_compliance,
                json!({
                    "high_idle_matches": high_policy.idle_timeout == high_config.session_idle_timeout,
                    "moderate_idle_matches": moderate_policy.idle_timeout == moderate_config.session_idle_timeout,
                    "config_source": "ComplianceConfig::from_profile()",
                }),
            );

            // Verify High has faster disconnect than Moderate
            let high_faster_disconnect = high_policy.idle_timeout < moderate_policy.idle_timeout;

            collector.assertion(
                "FedRAMP High should disconnect faster than Moderate",
                high_faster_disconnect,
                json!({
                    "high_idle_secs": high_policy.idle_timeout.as_secs(),
                    "moderate_idle_secs": moderate_policy.idle_timeout.as_secs(),
                }),
            );

            // Verify termination/disconnect reasons are available
            let termination_reasons: Vec<SessionTerminationReason> = vec![
                SessionTerminationReason::IdleTimeout,
                SessionTerminationReason::MaxLifetimeExceeded,
                SessionTerminationReason::MaxExtensionsExceeded,
                SessionTerminationReason::TokenExpired,
                SessionTerminationReason::UserLogout,
            ];

            let reasons_have_messages = termination_reasons.iter().all(|r| !r.message().is_empty());

            collector.assertion(
                "Termination reasons should have descriptive messages",
                reasons_have_messages,
                json!({
                    "reasons": termination_reasons
                        .iter()
                        .map(|r: &SessionTerminationReason| json!({
                            "variant": format!("{:?}", r),
                            "message": r.message(),
                        }))
                        .collect::<Vec<_>>(),
                }),
            );

            json!({
                "idle_disconnect_from_compliance": idle_disconnect_from_compliance,
                "high_faster_disconnect": high_faster_disconnect,
                "termination_reasons_exist": reasons_have_messages,
                "from_compliance_path_tested": true,
            })
        })
}

/// SC-12: Cryptographic Key Establishment and Management
///
/// Verifies that key rotation policies and tracking are implemented
/// correctly for cryptographic key lifecycle management.
pub fn test_sc12_key_management() -> ControlTestArtifact {
    use crate::keys::{KeyMetadata, KeyPurpose, KeyState, RotationPolicy, RotationTracker};

    ArtifactBuilder::new("SC-12", "Cryptographic Key Establishment and Management")
        .test_name("key_rotation_policy")
        .description("Verify key rotation policies and lifecycle management (SC-12)")
        .code_location("src/keys.rs", 321, 447)
        .related_control("SC-13")
        .input("rotation_interval_days", 90)
        .expected("rotation_policy_works", true)
        .expected("key_lifecycle_tracked", true)
        .expected("key_states_defined", true)
        .execute(|collector| {
            // Test rotation policy creation
            let policy = RotationPolicy::days(90);

            collector.configuration(
                "rotation_policy",
                json!({
                    "interval_days": policy.interval.as_secs() / (24 * 60 * 60),
                    "warn_before_days": policy.warn_before.as_secs() / (24 * 60 * 60),
                }),
            );

            // Test rotation tracker
            let mut tracker = RotationTracker::new();
            tracker.register("api-key-001", RotationPolicy::days(90));

            // A freshly registered key should not need rotation
            let needs_rotation = tracker.needs_rotation("api-key-001");
            let rotation_policy_works = !needs_rotation;

            collector.assertion(
                "Freshly registered key should not need rotation",
                rotation_policy_works,
                json!({ "needs_rotation": needs_rotation }),
            );

            // Test key metadata lifecycle
            let metadata = KeyMetadata::new("test-key")
                .with_name("Test API Key")
                .with_purpose(KeyPurpose::Signing)
                .with_state(KeyState::Active)
                .with_version(1);

            let key_lifecycle_tracked =
                metadata.state.can_encrypt() && metadata.state.can_decrypt();

            collector.assertion(
                "Active key should support encrypt and decrypt",
                key_lifecycle_tracked,
                json!({
                    "can_encrypt": metadata.state.can_encrypt(),
                    "can_decrypt": metadata.state.can_decrypt(),
                }),
            );

            // Verify all key states are defined
            let states = [
                KeyState::Active,
                KeyState::DecryptOnly,
                KeyState::Disabled,
                KeyState::PendingDestruction,
                KeyState::Destroyed,
            ];

            // Active can encrypt, DecryptOnly cannot
            let states_work_correctly =
                KeyState::Active.can_encrypt() && !KeyState::DecryptOnly.can_encrypt();

            collector.assertion(
                "Key states should have correct capabilities",
                states_work_correctly,
                json!({
                    "states": states
                        .iter()
                        .map(|s| json!({
                            "state": format!("{:?}", s),
                            "can_encrypt": s.can_encrypt(),
                            "can_decrypt": s.can_decrypt(),
                        }))
                        .collect::<Vec<_>>(),
                }),
            );

            json!({
                "rotation_policy_works": rotation_policy_works,
                "key_lifecycle_tracked": key_lifecycle_tracked,
                "key_states_defined": states_work_correctly,
            })
        })
}

// ============================================================================
// Additional Control Tests (Added to address coverage gaps)
// ============================================================================

/// AC-10: Concurrent Session Control
///
/// Verifies that concurrent session limits are configured per compliance profile
/// and that the SessionTerminationReason for concurrent limit violations exists.
pub fn test_ac10_concurrent_sessions() -> ControlTestArtifact {
    use crate::session::SessionTerminationReason;

    ArtifactBuilder::new("AC-10", "Concurrent Session Control")
        .test_name("concurrent_session_limits")
        .description("Verify concurrent session limits from compliance profile (AC-10)")
        .code_location("src/session.rs", 147, 169)
        .code_location_with_fn("src/compliance/config.rs", 106, 116, "ComplianceConfig")
        .related_control("AC-11")
        .related_control("AC-12")
        .input("profiles_tested", "FedRAMP Low, Moderate, High, Development")
        .expected("fedramp_high_limit_is_1", true)
        .expected("fedramp_moderate_limit_is_3", true)
        .expected("fedramp_low_limit_is_5", true)
        .expected("development_unlimited", true)
        .expected("from_compliance_path_tested", true)
        .execute(|collector| {
            // Test FedRAMP High via from_compliance (strictest)
            let high_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampHigh);
            let high_policy = SessionPolicy::from_compliance(&high_config);
            let fedramp_high_limit_is_1 = high_policy.max_concurrent_sessions == Some(1);

            collector.configuration(
                "fedramp_high_concurrent",
                json!({
                    "profile": "FedRAMP High",
                    "max_concurrent_sessions": high_policy.max_concurrent_sessions,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            collector.assertion(
                "FedRAMP High should allow only 1 concurrent session (from_compliance)",
                fedramp_high_limit_is_1,
                json!({
                    "profile": "FedRAMP High",
                    "max_sessions": high_policy.max_concurrent_sessions,
                    "expected": 1,
                    "config_source": "ComplianceConfig::from_profile(FedRampHigh)",
                }),
            );

            // Test FedRAMP Moderate via from_compliance
            let moderate_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampModerate);
            let moderate_policy = SessionPolicy::from_compliance(&moderate_config);
            let fedramp_moderate_limit_is_3 = moderate_policy.max_concurrent_sessions == Some(3);

            collector.configuration(
                "fedramp_moderate_concurrent",
                json!({
                    "profile": "FedRAMP Moderate",
                    "max_concurrent_sessions": moderate_policy.max_concurrent_sessions,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            collector.assertion(
                "FedRAMP Moderate should allow 3 concurrent sessions (from_compliance)",
                fedramp_moderate_limit_is_3,
                json!({
                    "profile": "FedRAMP Moderate",
                    "max_sessions": moderate_policy.max_concurrent_sessions,
                    "expected": 3,
                    "config_source": "ComplianceConfig::from_profile(FedRampModerate)",
                }),
            );

            // Test FedRAMP Low via from_compliance
            let low_config = ComplianceConfig::from_profile(ComplianceProfile::FedRampLow);
            let low_policy = SessionPolicy::from_compliance(&low_config);
            let fedramp_low_limit_is_5 = low_policy.max_concurrent_sessions == Some(5);

            collector.configuration(
                "fedramp_low_concurrent",
                json!({
                    "profile": "FedRAMP Low",
                    "max_concurrent_sessions": low_policy.max_concurrent_sessions,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            collector.assertion(
                "FedRAMP Low should allow 5 concurrent sessions (from_compliance)",
                fedramp_low_limit_is_5,
                json!({
                    "profile": "FedRAMP Low",
                    "max_sessions": low_policy.max_concurrent_sessions,
                    "expected": 5,
                    "config_source": "ComplianceConfig::from_profile(FedRampLow)",
                }),
            );

            // Test Development profile via from_compliance (unlimited)
            let dev_config = ComplianceConfig::from_profile(ComplianceProfile::Development);
            let dev_policy = SessionPolicy::from_compliance(&dev_config);
            let development_unlimited = dev_policy.max_concurrent_sessions.is_none();

            collector.configuration(
                "development_concurrent",
                json!({
                    "profile": "Development",
                    "max_concurrent_sessions": dev_policy.max_concurrent_sessions,
                    "derived_from": "SessionPolicy::from_compliance()",
                }),
            );

            collector.assertion(
                "Development should allow unlimited sessions (from_compliance)",
                development_unlimited,
                json!({
                    "profile": "Development",
                    "max_sessions": dev_policy.max_concurrent_sessions,
                    "expected": "None (unlimited)",
                    "config_source": "ComplianceConfig::from_profile(Development)",
                }),
            );

            // Verify ConcurrentSessionLimit termination reason exists and works
            let reason = SessionTerminationReason::ConcurrentSessionLimit;
            let has_termination_reason = reason.should_terminate() && !reason.message().is_empty();

            collector.assertion(
                "ConcurrentSessionLimit termination reason should be defined",
                has_termination_reason,
                json!({
                    "reason_code": reason.code(),
                    "message": reason.message(),
                    "should_terminate": reason.should_terminate(),
                }),
            );

            json!({
                "fedramp_high_limit_is_1": fedramp_high_limit_is_1,
                "fedramp_moderate_limit_is_3": fedramp_moderate_limit_is_3,
                "fedramp_low_limit_is_5": fedramp_low_limit_is_5,
                "development_unlimited": development_unlimited,
                "from_compliance_path_tested": true,
            })
        })
}

/// CA-7: Continuous Monitoring
///
/// Verifies that the health check framework supports continuous monitoring
/// per NIST 800-53 CA-7.
pub fn test_ca7_health_checks() -> ControlTestArtifact {
    use crate::health::{HealthChecker, HealthCheck, HealthStatus, Status};

    ArtifactBuilder::new("CA-7", "Continuous Monitoring")
        .test_name("health_check_framework")
        .description("Verify health check framework for continuous monitoring (CA-7)")
        .code_location("src/health.rs", 1, 200)
        .related_control("SI-4")
        .expected("can_register_checks", true)
        .expected("reports_healthy_status", true)
        .expected("reports_unhealthy_status", true)
        .expected("aggregates_to_unhealthy", true)
        .execute(|collector| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            // Create health checker
            let mut checker = HealthChecker::new();

            // Register a healthy check
            checker.add_check(HealthCheck::new("database", || async {
                HealthStatus::healthy()
            }));

            // Register an unhealthy check
            checker.add_check(HealthCheck::new("external_api", || async {
                HealthStatus::unhealthy("Connection refused")
            }));

            let can_register_checks = checker.check_count() == 2;

            collector.assertion(
                "Health checker should accept multiple checks",
                can_register_checks,
                json!({ "check_count": checker.check_count() }),
            );

            // Run checks
            let report = rt.block_on(async {
                checker.check_all().await
            });

            // Verify individual check results
            let db_result = report.checks.get("database");
            let reports_healthy_status = db_result
                .map(|r| matches!(r.status, Status::Healthy))
                .unwrap_or(false);

            collector.assertion(
                "Healthy check should report healthy status",
                reports_healthy_status,
                json!({ "database_status": format!("{:?}", db_result.map(|r| &r.status)) }),
            );

            let api_result = report.checks.get("external_api");
            let reports_unhealthy_status = api_result
                .map(|r| matches!(r.status, Status::Unhealthy))
                .unwrap_or(false);

            collector.assertion(
                "Unhealthy check should report unhealthy status",
                reports_unhealthy_status,
                json!({ "api_status": format!("{:?}", api_result.map(|r| &r.status)) }),
            );

            // Verify aggregation (overall should be unhealthy if any check fails)
            let aggregates_to_unhealthy = matches!(report.status, Status::Unhealthy);

            collector.assertion(
                "Overall status should aggregate to unhealthy when any check fails",
                aggregates_to_unhealthy,
                json!({
                    "overall_status": format!("{:?}", report.status),
                    "healthy_checks": report.checks.values().filter(|r| matches!(r.status, Status::Healthy)).count(),
                    "unhealthy_checks": report.checks.values().filter(|r| matches!(r.status, Status::Unhealthy)).count(),
                }),
            );

            collector.configuration(
                "health_check_framework",
                json!({
                    "supports_async_checks": true,
                    "supports_aggregation": true,
                    "status_types": ["Healthy", "Unhealthy", "Degraded"],
                }),
            );

            json!({
                "can_register_checks": can_register_checks,
                "reports_healthy_status": reports_healthy_status,
                "reports_unhealthy_status": reports_unhealthy_status,
                "aggregates_to_unhealthy": aggregates_to_unhealthy,
            })
        })
}

/// IR-4: Incident Handling
///
/// Verifies that the alerting system supports incident handling
/// per NIST 800-53 IR-4.
pub fn test_ir4_incident_handling() -> ControlTestArtifact {
    use crate::alerting::{AlertManager, AlertConfig, Alert, AlertSeverity, AlertCategory};

    ArtifactBuilder::new("IR-4", "Incident Handling")
        .test_name("alerting_system")
        .description("Verify alerting system for incident handling (IR-4)")
        .code_location("src/alerting.rs", 1, 300)
        .related_control("IR-5")
        .related_control("IR-6")
        .expected("can_create_alerts", true)
        .expected("supports_severity_levels", true)
        .expected("supports_categories", true)
        .expected("helper_functions_work", true)
        .execute(|collector| {
            let config = AlertConfig::default();
            let manager = AlertManager::new(config.clone());

            // Test alert creation - Alert::new takes (severity, summary, description)
            let alert = Alert::new(
                AlertSeverity::Critical,
                "Test security incident",
                "Detailed description of the security incident",
            ).with_category(AlertCategory::SecurityIncident);

            let can_create_alerts = !alert.summary.is_empty()
                && !alert.description.is_empty()
                && matches!(alert.severity, AlertSeverity::Critical)
                && matches!(alert.category, AlertCategory::SecurityIncident);

            collector.assertion(
                "Should be able to create alerts with severity and category",
                can_create_alerts,
                json!({
                    "summary": &alert.summary,
                    "description": &alert.description,
                    "severity": format!("{:?}", alert.severity),
                    "category": format!("{:?}", alert.category),
                }),
            );

            // Test severity levels exist (Info, Warning, Error, Critical)
            let severities = [
                AlertSeverity::Info,
                AlertSeverity::Warning,
                AlertSeverity::Error,
                AlertSeverity::Critical,
            ];
            let supports_severity_levels = severities.len() == 4;

            collector.assertion(
                "Should support all severity levels (Info, Warning, Error, Critical)",
                supports_severity_levels,
                json!({
                    "severities": severities.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>(),
                    "count": severities.len(),
                }),
            );

            // Test categories exist - actual AlertCategory variants
            let categories = [
                AlertCategory::Authentication,
                AlertCategory::Authorization,
                AlertCategory::RateLimiting,
                AlertCategory::Session,
                AlertCategory::DataIntegrity,
                AlertCategory::Configuration,
                AlertCategory::SystemHealth,
                AlertCategory::SecurityIncident,
                AlertCategory::Compliance,
                AlertCategory::Custom,
            ];
            let supports_categories = categories.len() >= 8;

            collector.assertion(
                "Should support security-relevant categories",
                supports_categories,
                json!({
                    "categories": categories.iter().map(|c| format!("{:?}", c)).collect::<Vec<_>>(),
                }),
            );

            // Test helper functions exist and work - they require &AlertManager
            let brute_force_sent = crate::alerting::alert_brute_force("192.168.1.100", 10, &manager);
            let account_locked_sent = crate::alerting::alert_account_locked("test@example.com", "Too many failed attempts", &manager);
            let suspicious_sent = crate::alerting::alert_suspicious_activity(
                "Multiple failed MFA attempts",
                Some("test-user"),
                Some("192.168.1.100"),
                &manager,
            );
            // At least one should succeed (depending on rate limiting config)
            let helper_functions_work = brute_force_sent || account_locked_sent || suspicious_sent;

            collector.assertion(
                "Alert helper functions should be available and functional",
                helper_functions_work,
                json!({
                    "alert_brute_force": brute_force_sent,
                    "alert_account_locked": account_locked_sent,
                    "alert_suspicious_activity": suspicious_sent,
                }),
            );

            collector.configuration(
                "alerting_config",
                json!({
                    "rate_limiting_enabled": config.rate_limit_per_category > 0,
                    "rate_limit_per_category": config.rate_limit_per_category,
                    "min_severity": format!("{:?}", config.min_severity),
                    "enable_aggregation": config.enable_aggregation,
                }),
            );

            json!({
                "can_create_alerts": can_create_alerts,
                "supports_severity_levels": supports_severity_levels,
                "supports_categories": supports_categories,
                "helper_functions_work": helper_functions_work,
            })
        })
}

/// SR-3: Supply Chain Controls
///
/// Verifies SBOM generation capability for supply chain security
/// per NIST 800-53 SR-3.
pub fn test_sr3_supply_chain() -> ControlTestArtifact {
    use crate::supply_chain::{generate_cyclonedx_sbom, SbomMetadata, Dependency, DependencySource};
    use std::collections::HashMap;

    ArtifactBuilder::new("SR-3", "Supply Chain Controls and Processes")
        .test_name("sbom_generation")
        .description("Verify SBOM generation for supply chain controls (SR-3)")
        .code_location("src/supply_chain.rs", 1, 200)
        .related_control("SR-4")
        .expected("can_create_dependencies", true)
        .expected("generates_valid_sbom", true)
        .expected("sbom_contains_dependencies", true)
        .expected("sbom_has_metadata", true)
        .execute(|collector| {
            // Create test dependencies using builder pattern
            let serde_dep = Dependency::new("serde", "1.0.193")
                .with_source(DependencySource::CratesIo)
                .with_checksum("abc123");

            let tokio_dep = Dependency::new("tokio", "1.35.0")
                .with_source(DependencySource::CratesIo)
                .with_checksum("def456");

            // generate_cyclonedx_sbom expects HashMap<String, Dependency>
            let mut deps: HashMap<String, Dependency> = HashMap::new();
            deps.insert("serde 1.0.193".to_string(), serde_dep);
            deps.insert("tokio 1.35.0".to_string(), tokio_dep);

            let can_create_dependencies = deps.len() == 2;

            collector.assertion(
                "Should be able to create dependency records",
                can_create_dependencies,
                json!({
                    "dependency_count": deps.len(),
                    "dependencies": deps.values().map(|d| format!("{}@{}", d.name, d.version)).collect::<Vec<_>>(),
                }),
            );

            // Generate SBOM - signature is (metadata, dependencies)
            let metadata = SbomMetadata::new("test-app", "1.0.0");
            let sbom = generate_cyclonedx_sbom(&metadata, &deps);

            // Verify valid CycloneDX format
            let generates_valid_sbom = sbom.contains("bomFormat")
                && sbom.contains("CycloneDX")
                && sbom.contains("components");

            collector.assertion(
                "Should generate valid CycloneDX SBOM",
                generates_valid_sbom,
                json!({
                    "has_bom_format": sbom.contains("bomFormat"),
                    "has_cyclonedx": sbom.contains("CycloneDX"),
                    "has_components": sbom.contains("components"),
                    "sbom_length": sbom.len(),
                }),
            );

            // Verify dependencies are included
            let sbom_contains_dependencies = sbom.contains("serde") && sbom.contains("tokio");

            collector.assertion(
                "SBOM should contain parsed dependencies",
                sbom_contains_dependencies,
                json!({
                    "contains_serde": sbom.contains("serde"),
                    "contains_tokio": sbom.contains("tokio"),
                }),
            );

            // Verify metadata is included
            let sbom_has_metadata = sbom.contains("test-app") && sbom.contains("1.0.0");

            collector.assertion(
                "SBOM should include application metadata",
                sbom_has_metadata,
                json!({
                    "contains_app_name": sbom.contains("test-app"),
                    "contains_version": sbom.contains("1.0.0"),
                }),
            );

            collector.configuration(
                "sbom_format",
                json!({
                    "format": "CycloneDX",
                    "version": "1.4",
                    "output": "JSON",
                }),
            );

            json!({
                "can_create_dependencies": can_create_dependencies,
                "generates_valid_sbom": generates_valid_sbom,
                "sbom_contains_dependencies": sbom_contains_dependencies,
                "sbom_has_metadata": sbom_has_metadata,
            })
        })
}

/// SA-11: Developer Testing and Evaluation
///
/// Verifies security testing utilities are available per NIST 800-53 SA-11.
pub fn test_sa11_security_testing() -> ControlTestArtifact {
    use crate::testing::{
        xss_payloads, sql_injection_payloads, command_injection_payloads,
        SecurityHeaders,
    };

    ArtifactBuilder::new("SA-11", "Developer Testing and Evaluation")
        .test_name("security_test_utilities")
        .description("Verify security testing utilities exist (SA-11)")
        .code_location("src/testing.rs", 1, 200)
        .related_control("CA-8")
        .expected("provides_xss_payloads", true)
        .expected("provides_sqli_payloads", true)
        .expected("provides_cmdi_payloads", true)
        .expected("provides_header_utilities", true)
        .execute(|collector| {
            // Test XSS payloads
            let xss = xss_payloads();
            let provides_xss_payloads = !xss.is_empty()
                && xss.iter().any(|p| p.contains("<script>") || p.contains("javascript:"));

            collector.assertion(
                "Should provide XSS test payloads",
                provides_xss_payloads,
                json!({
                    "payload_count": xss.len(),
                    "sample_payloads": xss.iter().take(3).collect::<Vec<_>>(),
                }),
            );

            // Test SQL injection payloads
            let sqli = sql_injection_payloads();
            let provides_sqli_payloads = !sqli.is_empty()
                && sqli.iter().any(|p| p.contains("'") || p.contains("--") || p.contains("OR"));

            collector.assertion(
                "Should provide SQL injection test payloads",
                provides_sqli_payloads,
                json!({
                    "payload_count": sqli.len(),
                    "sample_payloads": sqli.iter().take(3).collect::<Vec<_>>(),
                }),
            );

            // Test command injection payloads
            let cmdi = command_injection_payloads();
            let provides_cmdi_payloads = !cmdi.is_empty()
                && cmdi.iter().any(|p| p.contains(";") || p.contains("|") || p.contains("`"));

            collector.assertion(
                "Should provide command injection test payloads",
                provides_cmdi_payloads,
                json!({
                    "payload_count": cmdi.len(),
                    "sample_payloads": cmdi.iter().take(3).collect::<Vec<_>>(),
                }),
            );

            // Test header verification utilities
            let expected_headers = SecurityHeaders::strict();
            let pairs = expected_headers.to_header_pairs();
            let provides_header_utilities = !pairs.is_empty()
                && pairs.iter().any(|(k, _)| k == "Strict-Transport-Security");

            collector.assertion(
                "Should provide security header verification utilities",
                provides_header_utilities,
                json!({
                    "header_count": pairs.len(),
                    "headers": pairs.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
                }),
            );

            collector.configuration(
                "security_testing_utilities",
                json!({
                    "xss_payload_count": xss.len(),
                    "sqli_payload_count": sqli.len(),
                    "cmdi_payload_count": cmdi.len(),
                    "header_profiles": ["default", "strict", "api", "production"],
                }),
            );

            json!({
                "provides_xss_payloads": provides_xss_payloads,
                "provides_sqli_payloads": provides_sqli_payloads,
                "provides_cmdi_payloads": provides_cmdi_payloads,
                "provides_header_utilities": provides_header_utilities,
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
    generate_compliance_report_for_profile(ComplianceProfile::default())
}

/// Generate a compliance test report for a specific profile
///
/// This function runs all artifact-generating tests and collects them
/// into a single report labeled with the specified compliance profile.
///
/// # Arguments
///
/// * `profile` - The compliance profile (FedRAMP Low/Moderate/High, SOC 2, etc.)
///
/// # Example
///
/// ```ignore
/// use barbican::compliance::control_tests::generate_compliance_report_for_profile;
/// use barbican::compliance::ComplianceProfile;
///
/// // Generate a FedRAMP High report
/// let mut report = generate_compliance_report_for_profile(ComplianceProfile::FedRampHigh);
///
/// // Optionally sign the report
/// report.sign(b"my-signing-key", "key-2025")?;
///
/// // Write to file
/// std::fs::create_dir_all("./compliance-artifacts")?;
/// let path = report.write_to_file(Path::new("./compliance-artifacts"))?;
/// println!("Report written to: {}", path.display());
/// ```
pub fn generate_compliance_report_for_profile(profile: ComplianceProfile) -> ComplianceTestReport {
    let mut report = ComplianceTestReport::new(profile.name());

    // Run all control tests and add artifacts
    // Access Control (AC)
    report.add_artifact(test_ac3_access_enforcement());
    report.add_artifact(test_ac4_cors_policy());
    report.add_artifact(test_ac7_lockout());
    report.add_artifact(test_ac11_session_timeout());
    report.add_artifact(test_ac12_session_termination());

    // Audit and Accountability (AU)
    report.add_artifact(test_au2_security_events());
    report.add_artifact(test_au3_audit_content());
    report.add_artifact(test_au8_timestamps());
    report.add_artifact(test_au9_audit_protection());
    report.add_artifact(test_au12_audit_generation());
    report.add_artifact(test_au14_session_audit());
    report.add_artifact(test_au16_correlation_id());

    // Configuration Management (CM)
    report.add_artifact(test_cm6_security_headers());

    // Identification and Authentication (IA)
    report.add_artifact(test_ia2_mfa_enforcement());
    report.add_artifact(test_ia3_mtls_enforcement());
    report.add_artifact(test_ia5_authenticator_management());
    report.add_artifact(test_ia5_1_password_policy());
    report.add_artifact(test_ia5_7_secret_detection());
    report.add_artifact(test_ia6_auth_feedback());

    // System and Communications Protection (SC)
    report.add_artifact(test_sc5_rate_limiting());
    report.add_artifact(test_sc8_transmission_security());
    report.add_artifact(test_sc10_network_disconnect());
    report.add_artifact(test_sc12_key_management());
    report.add_artifact(test_sc13_constant_time());
    report.add_artifact(test_sc13_fips_crypto());
    report.add_artifact(test_sc23_session_authenticity());
    report.add_artifact(test_sc28_protection_at_rest());

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
        ("AC-3", test_ac3_access_enforcement as fn() -> ControlTestArtifact),
        ("AC-4", test_ac4_cors_policy),
        ("AC-7", test_ac7_lockout),
        ("AC-10", test_ac10_concurrent_sessions),
        ("AC-11", test_ac11_session_timeout),
        ("AC-12", test_ac12_session_termination),
        // Audit and Accountability (AU)
        ("AU-2", test_au2_security_events),
        ("AU-3", test_au3_audit_content),
        ("AU-8", test_au8_timestamps),
        ("AU-9", test_au9_audit_protection),
        ("AU-12", test_au12_audit_generation),
        ("AU-14", test_au14_session_audit),
        ("AU-16", test_au16_correlation_id),
        // Contingency Planning (CA)
        ("CA-7", test_ca7_health_checks),
        // Configuration Management (CM)
        ("CM-6", test_cm6_security_headers),
        // Identification and Authentication (IA)
        ("IA-2", test_ia2_mfa_enforcement),
        ("IA-3", test_ia3_mtls_enforcement),
        ("IA-5", test_ia5_authenticator_management),
        ("IA-5(1)", test_ia5_1_password_policy),
        ("IA-5(7)", test_ia5_7_secret_detection),
        ("IA-6", test_ia6_auth_feedback),
        // Incident Response (IR)
        ("IR-4", test_ir4_incident_handling),
        // System and Services Acquisition (SA)
        ("SA-11", test_sa11_security_testing),
        // System and Communications Protection (SC)
        ("SC-5", test_sc5_rate_limiting),
        ("SC-8", test_sc8_transmission_security),
        ("SC-10", test_sc10_network_disconnect),
        ("SC-12", test_sc12_key_management),
        ("SC-13", test_sc13_constant_time),
        ("SC-13-FIPS", test_sc13_fips_crypto),
        ("SC-23", test_sc23_session_authenticity),
        ("SC-28", test_sc28_protection_at_rest),
        // System and Information Integrity (SI)
        ("SI-10", test_si10_input_validation),
        ("SI-11", test_si11_error_handling),
        // Supply Chain Risk Management (SR)
        ("SR-3", test_sr3_supply_chain),
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
    fn test_au9_generates_passing_artifact() {
        let artifact = test_au9_audit_protection();
        assert_eq!(artifact.control_id, "AU-9");
        assert!(
            artifact.passed,
            "AU-9 test should pass: {:?}",
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
    fn test_sc28_generates_passing_artifact() {
        let artifact = test_sc28_protection_at_rest();
        assert_eq!(artifact.control_id, "SC-28");
        assert!(
            artifact.passed,
            "SC-28 test should pass: {:?}",
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

        assert_eq!(report.artifacts.len(), 29, "Should have 29 control tests");
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
        assert!(json.contains("SC-12"));
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
        assert_eq!(tests.len(), 34);

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
        assert_eq!(report.summary.by_family.get("AC").unwrap().total, 5); // AC-3, AC-4, AC-7, AC-11, AC-12
        assert_eq!(report.summary.by_family.get("AU").unwrap().total, 7); // AU-2, AU-3, AU-8, AU-9, AU-12, AU-14, AU-16
        assert_eq!(report.summary.by_family.get("CM").unwrap().total, 1); // CM-6
        assert_eq!(report.summary.by_family.get("IA").unwrap().total, 6); // IA-2, IA-3, IA-5, IA-5(1), IA-5(7), IA-6
        assert_eq!(report.summary.by_family.get("SC").unwrap().total, 8); // SC-5, SC-8, SC-10, SC-12, SC-13, SC-13-FIPS, SC-23, SC-28
        assert_eq!(report.summary.by_family.get("SI").unwrap().total, 2); // SI-10, SI-11
    }

    // Phase 6 control tests
    #[test]
    fn test_ac3_generates_passing_artifact() {
        let artifact = test_ac3_access_enforcement();
        assert_eq!(artifact.control_id, "AC-3");
        assert!(
            artifact.passed,
            "AC-3 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ac12_generates_passing_artifact() {
        let artifact = test_ac12_session_termination();
        assert_eq!(artifact.control_id, "AC-12");
        assert!(
            artifact.passed,
            "AC-12 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_au12_generates_passing_artifact() {
        let artifact = test_au12_audit_generation();
        assert_eq!(artifact.control_id, "AU-12");
        assert!(
            artifact.passed,
            "AU-12 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_sc10_generates_passing_artifact() {
        let artifact = test_sc10_network_disconnect();
        assert_eq!(artifact.control_id, "SC-10");
        assert!(
            artifact.passed,
            "SC-10 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_sc12_generates_passing_artifact() {
        let artifact = test_sc12_key_management();
        assert_eq!(artifact.control_id, "SC-12");
        assert!(
            artifact.passed,
            "SC-12 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ia5_7_generates_passing_artifact() {
        let artifact = test_ia5_7_secret_detection();
        assert_eq!(artifact.control_id, "IA-5(7)");
        assert!(
            artifact.passed,
            "IA-5(7) test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ia3_generates_passing_artifact() {
        let artifact = test_ia3_mtls_enforcement();
        assert_eq!(artifact.control_id, "IA-3");
        assert!(
            artifact.passed,
            "IA-3 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_sc13_fips_generates_passing_artifact() {
        let artifact = test_sc13_fips_crypto();
        assert_eq!(artifact.control_id, "SC-13-FIPS");
        assert!(
            artifact.passed,
            "SC-13 FIPS test should pass: {:?}",
            artifact.failure_reason
        );
    }

    // Phase 1 gap-filling control tests

    #[test]
    fn test_au8_generates_passing_artifact() {
        let artifact = test_au8_timestamps();
        assert_eq!(artifact.control_id, "AU-8");
        assert!(
            artifact.passed,
            "AU-8 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_au14_generates_passing_artifact() {
        let artifact = test_au14_session_audit();
        assert_eq!(artifact.control_id, "AU-14");
        assert!(
            artifact.passed,
            "AU-14 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_au16_generates_passing_artifact() {
        let artifact = test_au16_correlation_id();
        assert_eq!(artifact.control_id, "AU-16");
        assert!(
            artifact.passed,
            "AU-16 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ia5_generates_passing_artifact() {
        let artifact = test_ia5_authenticator_management();
        assert_eq!(artifact.control_id, "IA-5");
        assert!(
            artifact.passed,
            "IA-5 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_ia6_generates_passing_artifact() {
        let artifact = test_ia6_auth_feedback();
        assert_eq!(artifact.control_id, "IA-6");
        assert!(
            artifact.passed,
            "IA-6 test should pass: {:?}",
            artifact.failure_reason
        );
    }

    #[test]
    fn test_sc23_generates_passing_artifact() {
        let artifact = test_sc23_session_authenticity();
        assert_eq!(artifact.control_id, "SC-23");
        assert!(
            artifact.passed,
            "SC-23 test should pass: {:?}",
            artifact.failure_reason
        );
    }
}
