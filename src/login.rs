//! Login Attempt Tracking (AC-7)
//!
//! NIST SP 800-53 AC-7 (Unsuccessful Logon Attempts) compliant login
//! attempt tracking and account lockout utilities.
//!
//! # Design Philosophy
//!
//! If using OAuth providers exclusively, login attempt tracking is handled
//! by the provider (Keycloak, Entra ID, etc.). This module is for applications
//! that implement local authentication alongside or instead of OAuth.
//!
//! This module provides:
//! - Login attempt tracking per user/IP
//! - Configurable lockout policies
//! - Automatic lockout and unlock
//! - Brute force detection
//! - Security event logging
//!
//! # Storage Note
//!
//! This module provides in-memory tracking suitable for single-instance deployments.
//! For distributed systems, implement the `LoginAttemptStore` trait with Redis,
//! PostgreSQL, or another shared storage backend.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::login::{LoginTracker, LockoutPolicy};
//! use std::time::Duration;
//!
//! // Create tracker with policy
//! let policy = LockoutPolicy::default(); // 5 failures, 15 min lockout
//! let tracker = LoginTracker::new(policy);
//!
//! // On login attempt
//! let identifier = "user@example.com"; // or IP address
//!
//! // Check if locked out BEFORE attempting auth
//! if let Some(lockout) = tracker.check_lockout(identifier) {
//!     return Err(format!("Account locked. Try again in {} seconds", lockout.remaining_secs()));
//! }
//!
//! // Attempt authentication...
//! if auth_success {
//!     tracker.record_success(identifier);
//! } else {
//!     let result = tracker.record_failure(identifier);
//!     if result.is_locked_out {
//!         // Account is now locked
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::observability::SecurityEvent;

// ============================================================================
// Lockout Policy (AC-7)
// ============================================================================

/// Lockout policy configuration (AC-7)
///
/// Defines rules for tracking failed login attempts and account lockout.
#[derive(Debug, Clone)]
pub struct LockoutPolicy {
    /// Number of failed attempts before lockout
    pub max_attempts: u32,

    /// Time window for counting attempts
    /// Attempts older than this are not counted
    pub attempt_window: Duration,

    /// Duration of lockout after max attempts reached
    pub lockout_duration: Duration,

    /// Whether to use progressive lockout (longer each time)
    pub progressive_lockout: bool,

    /// Maximum lockout duration for progressive lockout
    pub max_lockout_duration: Duration,

    /// Multiplier for progressive lockout
    pub lockout_multiplier: f64,

    /// Whether to track by IP in addition to username
    pub track_by_ip: bool,

    /// Maximum failed attempts per IP (for brute force protection)
    pub max_ip_attempts: u32,

    /// IP lockout duration
    pub ip_lockout_duration: Duration,
}

impl Default for LockoutPolicy {
    /// Default policy aligned with NIST recommendations
    ///
    /// - 5 failed attempts before lockout
    /// - 15 minute lockout duration
    /// - 30 minute attempt window
    fn default() -> Self {
        Self {
            max_attempts: 5,
            attempt_window: Duration::from_secs(30 * 60),        // 30 minutes
            lockout_duration: Duration::from_secs(15 * 60),      // 15 minutes
            progressive_lockout: true,
            max_lockout_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            lockout_multiplier: 2.0,
            track_by_ip: true,
            max_ip_attempts: 20,                                  // Higher threshold for IP
            ip_lockout_duration: Duration::from_secs(60 * 60),   // 1 hour
        }
    }
}

impl LockoutPolicy {
    /// Create a new builder
    pub fn builder() -> LockoutPolicyBuilder {
        LockoutPolicyBuilder::default()
    }

    /// Create a strict policy for high-security environments
    pub fn strict() -> Self {
        Self {
            max_attempts: 3,
            attempt_window: Duration::from_secs(60 * 60),        // 1 hour
            lockout_duration: Duration::from_secs(30 * 60),      // 30 minutes
            progressive_lockout: true,
            max_lockout_duration: Duration::from_secs(24 * 60 * 60),
            lockout_multiplier: 3.0,
            track_by_ip: true,
            max_ip_attempts: 10,
            ip_lockout_duration: Duration::from_secs(2 * 60 * 60), // 2 hours
        }
    }

    /// Create a relaxed policy for low-risk applications
    pub fn relaxed() -> Self {
        Self {
            max_attempts: 10,
            attempt_window: Duration::from_secs(15 * 60),        // 15 minutes
            lockout_duration: Duration::from_secs(5 * 60),       // 5 minutes
            progressive_lockout: false,
            max_lockout_duration: Duration::from_secs(60 * 60),
            lockout_multiplier: 1.0,
            track_by_ip: false,
            max_ip_attempts: 50,
            ip_lockout_duration: Duration::from_secs(30 * 60),
        }
    }

    /// Calculate lockout duration based on lockout count (for progressive lockout)
    pub fn calculate_lockout_duration(&self, lockout_count: u32) -> Duration {
        if !self.progressive_lockout || lockout_count == 0 {
            return self.lockout_duration;
        }

        let multiplier = self.lockout_multiplier.powi(lockout_count as i32 - 1);
        let duration_secs = (self.lockout_duration.as_secs_f64() * multiplier) as u64;

        Duration::from_secs(duration_secs.min(self.max_lockout_duration.as_secs()))
    }
}

/// Builder for LockoutPolicy
#[derive(Debug, Clone, Default)]
pub struct LockoutPolicyBuilder {
    policy: LockoutPolicy,
}

impl LockoutPolicyBuilder {
    /// Set maximum failed attempts before lockout
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.policy.max_attempts = attempts;
        self
    }

    /// Set the time window for counting attempts
    pub fn attempt_window(mut self, duration: Duration) -> Self {
        self.policy.attempt_window = duration;
        self
    }

    /// Set lockout duration
    pub fn lockout_duration(mut self, duration: Duration) -> Self {
        self.policy.lockout_duration = duration;
        self
    }

    /// Enable/disable progressive lockout
    pub fn progressive_lockout(mut self, enabled: bool) -> Self {
        self.policy.progressive_lockout = enabled;
        self
    }

    /// Set maximum lockout duration
    pub fn max_lockout_duration(mut self, duration: Duration) -> Self {
        self.policy.max_lockout_duration = duration;
        self
    }

    /// Set lockout multiplier for progressive lockout
    pub fn lockout_multiplier(mut self, multiplier: f64) -> Self {
        self.policy.lockout_multiplier = multiplier;
        self
    }

    /// Enable/disable IP tracking
    pub fn track_by_ip(mut self, enabled: bool) -> Self {
        self.policy.track_by_ip = enabled;
        self
    }

    /// Set maximum attempts per IP
    pub fn max_ip_attempts(mut self, attempts: u32) -> Self {
        self.policy.max_ip_attempts = attempts;
        self
    }

    /// Set IP lockout duration
    pub fn ip_lockout_duration(mut self, duration: Duration) -> Self {
        self.policy.ip_lockout_duration = duration;
        self
    }

    /// Build the policy
    pub fn build(self) -> LockoutPolicy {
        self.policy
    }
}

// ============================================================================
// Login Attempt Tracking
// ============================================================================

/// Tracks login attempts for a single identifier (user or IP)
#[derive(Debug, Clone)]
pub struct AttemptRecord {
    /// Recent failed attempt timestamps
    pub failed_attempts: Vec<Instant>,
    /// Number of times this identifier has been locked out
    pub lockout_count: u32,
    /// When the current lockout started (if locked out)
    pub lockout_started: Option<Instant>,
    /// Duration of current lockout
    pub lockout_duration: Duration,
    /// Last successful login
    pub last_success: Option<Instant>,
}

impl Default for AttemptRecord {
    fn default() -> Self {
        Self {
            failed_attempts: Vec::new(),
            lockout_count: 0,
            lockout_started: None,
            lockout_duration: Duration::ZERO,
            last_success: None,
        }
    }
}

impl AttemptRecord {
    /// Count recent failed attempts within the window
    pub fn recent_failures(&self, window: Duration) -> u32 {
        let cutoff = Instant::now() - window;
        self.failed_attempts
            .iter()
            .filter(|&&t| t > cutoff)
            .count() as u32
    }

    /// Check if currently locked out
    pub fn is_locked_out(&self) -> bool {
        if let Some(started) = self.lockout_started {
            Instant::now().duration_since(started) < self.lockout_duration
        } else {
            false
        }
    }

    /// Get remaining lockout time
    pub fn remaining_lockout(&self) -> Option<Duration> {
        if let Some(started) = self.lockout_started {
            let elapsed = Instant::now().duration_since(started);
            if elapsed < self.lockout_duration {
                Some(self.lockout_duration - elapsed)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Record a failed attempt
    pub fn record_failure(&mut self) {
        self.failed_attempts.push(Instant::now());
    }

    /// Record a successful login
    pub fn record_success(&mut self) {
        self.last_success = Some(Instant::now());
        self.failed_attempts.clear();
        // Keep lockout_count for progressive lockout tracking
    }

    /// Start lockout
    pub fn start_lockout(&mut self, duration: Duration) {
        self.lockout_started = Some(Instant::now());
        self.lockout_duration = duration;
        self.lockout_count += 1;
    }

    /// Manually unlock (admin action)
    pub fn unlock(&mut self) {
        self.lockout_started = None;
        self.failed_attempts.clear();
    }

    /// Clean up old attempts outside the window
    pub fn cleanup(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.failed_attempts.retain(|&t| t > cutoff);
    }
}

// ============================================================================
// Login Tracker (In-Memory Implementation)
// ============================================================================

/// Result of recording a login attempt
#[derive(Debug, Clone)]
pub struct AttemptResult {
    /// Number of recent failed attempts
    pub failed_count: u32,
    /// Number of remaining attempts before lockout
    pub remaining_attempts: u32,
    /// Whether the account is now locked out
    pub is_locked_out: bool,
    /// Lockout duration if locked out
    pub lockout_duration: Option<Duration>,
    /// Whether this triggered a brute force alert
    pub brute_force_detected: bool,
}

/// Lockout information returned when checking lockout status
#[derive(Debug, Clone)]
pub struct LockoutInfo {
    /// When the lockout started
    pub started: Instant,
    /// Total lockout duration
    pub duration: Duration,
    /// Number of times locked out
    pub lockout_count: u32,
}

impl LockoutInfo {
    /// Get remaining lockout time in seconds
    pub fn remaining_secs(&self) -> u64 {
        let elapsed = Instant::now().duration_since(self.started);
        if elapsed < self.duration {
            (self.duration - elapsed).as_secs()
        } else {
            0
        }
    }

    /// Check if lockout has expired
    pub fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.started) >= self.duration
    }
}

/// In-memory login attempt tracker (AC-7)
///
/// For distributed systems, implement the tracking with Redis or a database.
#[derive(Debug)]
pub struct LoginTracker {
    policy: LockoutPolicy,
    records: Arc<RwLock<HashMap<String, AttemptRecord>>>,
    ip_records: Arc<RwLock<HashMap<String, AttemptRecord>>>,
}

impl LoginTracker {
    /// Create a new login tracker with the given policy
    pub fn new(policy: LockoutPolicy) -> Self {
        Self {
            policy,
            records: Arc::new(RwLock::new(HashMap::new())),
            ip_records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a tracker with default policy
    pub fn with_default_policy() -> Self {
        Self::new(LockoutPolicy::default())
    }

    /// Check if an identifier is locked out
    ///
    /// Returns lockout info if locked out, None if not.
    pub fn check_lockout(&self, identifier: &str) -> Option<LockoutInfo> {
        let records = self.records.read().ok()?;
        let record = records.get(identifier)?;

        if record.is_locked_out() {
            Some(LockoutInfo {
                started: record.lockout_started?,
                duration: record.lockout_duration,
                lockout_count: record.lockout_count,
            })
        } else {
            None
        }
    }

    /// Check if an IP is locked out
    pub fn check_ip_lockout(&self, ip: &str) -> Option<LockoutInfo> {
        if !self.policy.track_by_ip {
            return None;
        }

        let records = self.ip_records.read().ok()?;
        let record = records.get(ip)?;

        if record.is_locked_out() {
            Some(LockoutInfo {
                started: record.lockout_started?,
                duration: record.lockout_duration,
                lockout_count: record.lockout_count,
            })
        } else {
            None
        }
    }

    /// Record a failed login attempt
    pub fn record_failure(&self, identifier: &str) -> AttemptResult {
        self.record_failure_with_ip(identifier, None)
    }

    /// Record a failed login attempt with IP tracking
    pub fn record_failure_with_ip(&self, identifier: &str, ip: Option<&str>) -> AttemptResult {
        let mut brute_force_detected = false;

        // Track by identifier (username/email)
        let (failed_count, remaining, is_locked, lockout_dur) = {
            let mut records = self.records.write().unwrap();
            let record = records.entry(identifier.to_string()).or_default();

            // Clean up old attempts
            record.cleanup(self.policy.attempt_window);

            // Record the failure
            record.record_failure();

            let failed_count = record.recent_failures(self.policy.attempt_window);
            let remaining = self.policy.max_attempts.saturating_sub(failed_count);

            // Check if we should lock out
            let (is_locked, lockout_dur) = if failed_count >= self.policy.max_attempts && !record.is_locked_out() {
                let duration = self.policy.calculate_lockout_duration(record.lockout_count + 1);
                record.start_lockout(duration);

                // Log lockout event
                log_account_locked(identifier, failed_count, duration);

                (true, Some(duration))
            } else {
                (record.is_locked_out(), record.remaining_lockout())
            };

            (failed_count, remaining, is_locked, lockout_dur)
        };

        // Track by IP if enabled
        if self.policy.track_by_ip {
            if let Some(ip) = ip {
                let mut ip_records = self.ip_records.write().unwrap();
                let ip_record = ip_records.entry(ip.to_string()).or_default();

                ip_record.cleanup(self.policy.attempt_window);
                ip_record.record_failure();

                let ip_failures = ip_record.recent_failures(self.policy.attempt_window);

                // Detect brute force (many attempts from same IP)
                if ip_failures >= self.policy.max_ip_attempts / 2 {
                    brute_force_detected = true;
                    log_brute_force_detected(ip, ip_failures);
                }

                // Lock out IP if threshold exceeded
                if ip_failures >= self.policy.max_ip_attempts && !ip_record.is_locked_out() {
                    ip_record.start_lockout(self.policy.ip_lockout_duration);
                    log_ip_locked(ip, ip_failures);
                }
            }
        }

        // Log the failed attempt
        log_login_failure(identifier, failed_count, remaining);

        AttemptResult {
            failed_count,
            remaining_attempts: remaining,
            is_locked_out: is_locked,
            lockout_duration: lockout_dur,
            brute_force_detected,
        }
    }

    /// Record a successful login
    pub fn record_success(&self, identifier: &str) {
        let mut records = self.records.write().unwrap();
        let record = records.entry(identifier.to_string()).or_default();
        record.record_success();

        log_login_success(identifier);
    }

    /// Record a successful login with IP
    pub fn record_success_with_ip(&self, identifier: &str, ip: Option<&str>) {
        self.record_success(identifier);

        // Clear IP record on successful auth
        if self.policy.track_by_ip {
            if let Some(ip) = ip {
                let mut ip_records = self.ip_records.write().unwrap();
                if let Some(record) = ip_records.get_mut(ip) {
                    record.record_success();
                }
            }
        }
    }

    /// Manually unlock an identifier (admin action)
    pub fn unlock(&self, identifier: &str) {
        let mut records = self.records.write().unwrap();
        if let Some(record) = records.get_mut(identifier) {
            record.unlock();
            log_account_unlocked(identifier);
        }
    }

    /// Manually unlock an IP (admin action)
    pub fn unlock_ip(&self, ip: &str) {
        let mut ip_records = self.ip_records.write().unwrap();
        if let Some(record) = ip_records.get_mut(ip) {
            record.unlock();
        }
    }

    /// Get attempt info for an identifier (for admin/debugging)
    pub fn get_attempt_info(&self, identifier: &str) -> Option<AttemptRecord> {
        let records = self.records.read().ok()?;
        records.get(identifier).cloned()
    }

    /// Clean up expired records (call periodically)
    pub fn cleanup(&self) {
        let window = self.policy.attempt_window;

        // Clean user records
        {
            let mut records = self.records.write().unwrap();
            records.retain(|_, record| {
                record.cleanup(window);
                !record.failed_attempts.is_empty() || record.is_locked_out()
            });
        }

        // Clean IP records
        {
            let mut ip_records = self.ip_records.write().unwrap();
            ip_records.retain(|_, record| {
                record.cleanup(window);
                !record.failed_attempts.is_empty() || record.is_locked_out()
            });
        }
    }
}

impl Clone for LoginTracker {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            records: Arc::clone(&self.records),
            ip_records: Arc::clone(&self.ip_records),
        }
    }
}

// ============================================================================
// Security Event Logging (AU-2, AU-3)
// ============================================================================

/// Log successful login
fn log_login_success(identifier: &str) {
    crate::security_event!(
        SecurityEvent::AuthenticationSuccess,
        identifier = %identifier,
        "Login successful"
    );
}

/// Log failed login attempt
fn log_login_failure(identifier: &str, failed_count: u32, remaining: u32) {
    crate::security_event!(
        SecurityEvent::AuthenticationFailure,
        identifier = %identifier,
        failed_count = failed_count,
        remaining_attempts = remaining,
        "Login failed"
    );
}

/// Log account lockout
fn log_account_locked(identifier: &str, failed_count: u32, duration: Duration) {
    crate::security_event!(
        SecurityEvent::AccountLocked,
        identifier = %identifier,
        failed_count = failed_count,
        lockout_duration_secs = duration.as_secs(),
        "Account locked due to failed login attempts"
    );
}

/// Log account unlock
fn log_account_unlocked(identifier: &str) {
    crate::security_event!(
        SecurityEvent::AccountUnlocked,
        identifier = %identifier,
        "Account unlocked"
    );
}

/// Log brute force detection
fn log_brute_force_detected(ip: &str, attempt_count: u32) {
    crate::security_event!(
        SecurityEvent::BruteForceDetected,
        ip_address = %ip,
        attempt_count = attempt_count,
        "Possible brute force attack detected"
    );
}

/// Log IP lockout
fn log_ip_locked(ip: &str, attempt_count: u32) {
    crate::security_event!(
        SecurityEvent::SuspiciousActivity,
        ip_address = %ip,
        attempt_count = attempt_count,
        "IP address locked due to excessive failed attempts"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = LockoutPolicy::default();
        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.lockout_duration, Duration::from_secs(15 * 60));
        assert!(policy.progressive_lockout);
    }

    #[test]
    fn test_strict_policy() {
        let policy = LockoutPolicy::strict();
        assert_eq!(policy.max_attempts, 3);
        assert!(policy.track_by_ip);
    }

    #[test]
    fn test_progressive_lockout_duration() {
        let policy = LockoutPolicy::default();

        // First lockout: base duration
        assert_eq!(
            policy.calculate_lockout_duration(1),
            Duration::from_secs(15 * 60)
        );

        // Second lockout: 2x
        assert_eq!(
            policy.calculate_lockout_duration(2),
            Duration::from_secs(30 * 60)
        );

        // Third lockout: 4x
        assert_eq!(
            policy.calculate_lockout_duration(3),
            Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn test_attempt_record() {
        let mut record = AttemptRecord::default();

        assert!(!record.is_locked_out());
        assert_eq!(record.recent_failures(Duration::from_secs(300)), 0);

        record.record_failure();
        record.record_failure();
        assert_eq!(record.recent_failures(Duration::from_secs(300)), 2);

        record.record_success();
        assert_eq!(record.recent_failures(Duration::from_secs(300)), 0);
    }

    #[test]
    fn test_lockout() {
        let mut record = AttemptRecord::default();

        record.start_lockout(Duration::from_secs(60));
        assert!(record.is_locked_out());
        assert!(record.remaining_lockout().is_some());

        record.unlock();
        assert!(!record.is_locked_out());
    }

    #[test]
    fn test_login_tracker_success() {
        let tracker = LoginTracker::with_default_policy();
        tracker.record_success("user@example.com");

        // Should not be locked out after success
        assert!(tracker.check_lockout("user@example.com").is_none());
    }

    #[test]
    fn test_login_tracker_failure() {
        let policy = LockoutPolicy::builder()
            .max_attempts(3)
            .lockout_duration(Duration::from_secs(60))
            .build();

        let tracker = LoginTracker::new(policy);

        // First failure
        let result = tracker.record_failure("user@example.com");
        assert_eq!(result.failed_count, 1);
        assert_eq!(result.remaining_attempts, 2);
        assert!(!result.is_locked_out);

        // Second failure
        let result = tracker.record_failure("user@example.com");
        assert_eq!(result.failed_count, 2);
        assert_eq!(result.remaining_attempts, 1);
        assert!(!result.is_locked_out);

        // Third failure - should lock out
        let result = tracker.record_failure("user@example.com");
        assert_eq!(result.failed_count, 3);
        assert_eq!(result.remaining_attempts, 0);
        assert!(result.is_locked_out);

        // Check lockout
        let lockout = tracker.check_lockout("user@example.com");
        assert!(lockout.is_some());
    }

    #[test]
    fn test_login_tracker_unlock() {
        let policy = LockoutPolicy::builder()
            .max_attempts(2)
            .lockout_duration(Duration::from_secs(60))
            .build();

        let tracker = LoginTracker::new(policy);

        // Lock the account
        tracker.record_failure("user@example.com");
        tracker.record_failure("user@example.com");
        assert!(tracker.check_lockout("user@example.com").is_some());

        // Unlock
        tracker.unlock("user@example.com");
        assert!(tracker.check_lockout("user@example.com").is_none());
    }

    #[test]
    fn test_ip_tracking() {
        let policy = LockoutPolicy::builder()
            .max_attempts(5)
            .track_by_ip(true)
            .max_ip_attempts(3)
            .ip_lockout_duration(Duration::from_secs(60))
            .build();

        let tracker = LoginTracker::new(policy);

        // Fail from same IP for different users
        tracker.record_failure_with_ip("user1@example.com", Some("192.168.1.1"));
        tracker.record_failure_with_ip("user2@example.com", Some("192.168.1.1"));
        tracker.record_failure_with_ip("user3@example.com", Some("192.168.1.1"));

        // IP should be locked out
        assert!(tracker.check_ip_lockout("192.168.1.1").is_some());
    }

    #[test]
    fn test_success_clears_failures() {
        let policy = LockoutPolicy::builder()
            .max_attempts(5)
            .build();

        let tracker = LoginTracker::new(policy);

        // Record some failures
        tracker.record_failure("user@example.com");
        tracker.record_failure("user@example.com");
        tracker.record_failure("user@example.com");

        // Success should clear failures
        tracker.record_success("user@example.com");

        // Should be back to 5 remaining attempts
        let result = tracker.record_failure("user@example.com");
        assert_eq!(result.failed_count, 1);
        assert_eq!(result.remaining_attempts, 4);
    }
}
