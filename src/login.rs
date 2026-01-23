//! Login Attempt Tracking (AC-7)
//!
//! NIST SP 800-53 AC-7 (Unsuccessful Logon Attempts) compliant login
//! attempt tracking and account lockout utilities.
//!
//! # STIG References
//!
//! - **UBTU-22-411045**: Lock account after 3 unsuccessful login attempts (AC-7)
//! - **UBTU-22-411050**: Automatically unlock accounts after lockout duration (AC-7)
//! - **APSC-DV-000210**: Limit failed login attempts (AC-7)
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

    /// Create policy from compliance configuration
    ///
    /// Derives lockout parameters from the compliance profile. Higher
    /// profiles have stricter lockout policies.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use barbican::compliance::ComplianceConfig;
    /// use barbican::login::LockoutPolicy;
    ///
    /// let compliance = barbican::compliance::config();
    /// let policy = LockoutPolicy::from_compliance(compliance);
    /// ```
    pub fn from_compliance(config: &crate::compliance::ComplianceConfig) -> Self {
        use crate::compliance::ComplianceProfile;

        let is_strict = !matches!(config.profile, ComplianceProfile::FedRampLow);

        Self {
            max_attempts: config.max_login_attempts,
            attempt_window: if is_strict {
                Duration::from_secs(60 * 60) // 1 hour for stricter profiles
            } else {
                Duration::from_secs(30 * 60) // 30 minutes for low
            },
            lockout_duration: config.lockout_duration,
            progressive_lockout: true,
            max_lockout_duration: Duration::from_secs(24 * 60 * 60),
            lockout_multiplier: if is_strict { 3.0 } else { 2.0 },
            track_by_ip: true,
            max_ip_attempts: if is_strict { 10 } else { 20 },
            ip_lockout_duration: config.lockout_duration * 2,
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
// Login Tracking Middleware (AC-7 Enforcement)
// ============================================================================

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// HTTP header for passing username to login tracking middleware
///
/// Set this header on auth requests to enable per-user lockout checking.
/// If not set, only IP-based tracking is used.
pub const LOGIN_IDENTIFIER_HEADER: &str = "X-Login-Identifier";

/// Configuration for login tracking middleware
#[derive(Debug, Clone)]
pub struct LoginTrackingConfig {
    /// URL path patterns that should be tracked (e.g., "/login", "/auth/token")
    pub auth_paths: Vec<String>,

    /// Whether to require the X-Login-Identifier header
    /// If false, falls back to IP-only tracking
    pub require_identifier: bool,

    /// Whether IP lockout should block requests (vs just logging)
    pub enforce_ip_lockout: bool,
}

impl Default for LoginTrackingConfig {
    fn default() -> Self {
        Self {
            auth_paths: vec![
                "/login".to_string(),
                "/auth/token".to_string(),
                "/oauth/token".to_string(),
            ],
            require_identifier: false,
            enforce_ip_lockout: true,
        }
    }
}

/// Middleware that enforces login attempt tracking (AC-7)
///
/// This middleware automatically:
/// 1. Checks lockout status before allowing authentication attempts
/// 2. Records success/failure based on response status code
/// 3. Returns 429 Too Many Requests when locked out
///
/// # Usage
///
/// ```ignore
/// use axum::{Router, routing::post, middleware};
/// use barbican::login::{LoginTracker, LockoutPolicy, login_tracking_middleware, LoginTrackingConfig};
///
/// let tracker = LoginTracker::with_default_policy();
/// let config = LoginTrackingConfig::default();
///
/// let app = Router::new()
///     .route("/login", post(login_handler))
///     .layer(middleware::from_fn(move |req, next| {
///         let tracker = tracker.clone();
///         let config = config.clone();
///         async move {
///             login_tracking_middleware(req, next, tracker, config).await
///         }
///     }));
/// ```
///
/// # Header-Based Identification
///
/// The middleware looks for the username in the `X-Login-Identifier` header.
/// Your authentication handler should set this header using
/// `LoginTrackerExtension::set_identifier()` or by having the client send it.
///
/// # Response-Based Recording
///
/// - 2xx responses are recorded as successful login
/// - 401/403 responses are recorded as failed attempts
/// - Other status codes are not recorded (e.g., 400 Bad Request)
pub async fn login_tracking_middleware(
    req: Request,
    next: Next,
    tracker: LoginTracker,
    config: LoginTrackingConfig,
) -> Response {
    let path = req.uri().path().to_string();

    // Check if this path should be tracked
    let should_track = config.auth_paths.iter().any(|p| path.starts_with(p));
    if !should_track {
        return next.run(req).await;
    }

    // Extract client IP for tracking
    let client_ip = extract_client_ip_from_request(&req);

    // Extract identifier from header (if present)
    let identifier = req
        .headers()
        .get(LOGIN_IDENTIFIER_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Check IP lockout first
    if config.enforce_ip_lockout {
        if let Some(ref ip) = client_ip {
            if let Some(lockout) = tracker.check_ip_lockout(ip) {
                let remaining = lockout.remaining_secs();
                return locked_out_response(None, Some(ip), remaining);
            }
        }
    }

    // Check user lockout if identifier provided
    if let Some(ref id) = identifier {
        if let Some(lockout) = tracker.check_lockout(id) {
            let remaining = lockout.remaining_secs();
            return locked_out_response(Some(id), client_ip.as_deref(), remaining);
        }
    }

    // Run the actual handler
    let response = next.run(req).await;
    let status = response.status();

    // Record the result based on status code
    match status.as_u16() {
        200..=299 => {
            // Success - record successful login
            if let Some(ref id) = identifier {
                tracker.record_success_with_ip(id, client_ip.as_deref());
            }
        }
        401 | 403 => {
            // Authentication failure - record failed attempt
            if let Some(ref id) = identifier {
                let result = tracker.record_failure_with_ip(id, client_ip.as_deref());
                if result.is_locked_out {
                    // Account is now locked - the response already went out,
                    // but we've recorded the lockout for next request
                    crate::security_event!(
                        SecurityEvent::AccountLocked,
                        identifier = %id,
                        client_ip = %client_ip.as_deref().unwrap_or("unknown"),
                        "Account locked after failed authentication"
                    );
                }
            } else if let Some(ref ip) = client_ip {
                // No identifier, track by IP only
                tracker.record_failure_with_ip("unknown", Some(ip));
            }
        }
        _ => {
            // Other status codes (400, 500, etc.) - don't record as auth failure
            // These are typically malformed requests, not auth attempts
        }
    }

    response
}

/// Generate a 429 Too Many Requests response for locked out accounts
fn locked_out_response(
    identifier: Option<&str>,
    ip: Option<&str>,
    remaining_secs: u64,
) -> Response {
    let reason = if identifier.is_some() {
        "Account temporarily locked due to too many failed login attempts"
    } else {
        "IP address temporarily blocked due to too many failed login attempts"
    };

    crate::security_event!(
        SecurityEvent::AuthenticationFailure,
        identifier = %identifier.unwrap_or("unknown"),
        client_ip = %ip.unwrap_or("unknown"),
        lockout_remaining_secs = remaining_secs,
        "Login attempt blocked - account/IP locked out"
    );

    let body = json!({
        "error": "too_many_attempts",
        "message": reason,
        "retry_after": remaining_secs
    });

    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, remaining_secs.to_string())],
        Json(body),
    )
        .into_response()
}

/// Extract client IP from request headers
///
/// Checks (in order): X-Forwarded-For, X-Real-IP, CF-Connecting-IP
fn extract_client_ip_from_request(req: &Request) -> Option<String> {
    // X-Forwarded-For (first IP in chain)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(first_ip) = s.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }
    }

    // X-Real-IP
    if let Some(xri) = req.headers().get("x-real-ip") {
        if let Ok(s) = xri.to_str() {
            return Some(s.trim().to_string());
        }
    }

    // CF-Connecting-IP (Cloudflare)
    if let Some(cf) = req.headers().get("cf-connecting-ip") {
        if let Ok(s) = cf.to_str() {
            return Some(s.trim().to_string());
        }
    }

    None
}

/// Extension for setting the login identifier from within a handler
///
/// Use this to set the username/email after parsing the request body,
/// so the middleware can record the correct identifier.
///
/// # Example
///
/// ```ignore
/// use axum::{Extension, Json};
/// use barbican::login::LoginTrackerExtension;
///
/// async fn login_handler(
///     Extension(tracker_ext): Extension<LoginTrackerExtension>,
///     Json(payload): Json<LoginRequest>,
/// ) -> impl IntoResponse {
///     // Set identifier for tracking
///     tracker_ext.set_identifier(&payload.username);
///
///     // ... perform authentication ...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LoginTrackerExtension {
    tracker: LoginTracker,
    identifier: Arc<RwLock<Option<String>>>,
}

impl LoginTrackerExtension {
    /// Create a new extension
    pub fn new(tracker: LoginTracker) -> Self {
        Self {
            tracker,
            identifier: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the identifier (username/email) for the current request
    pub fn set_identifier(&self, identifier: &str) {
        if let Ok(mut id) = self.identifier.write() {
            *id = Some(identifier.to_string());
        }
    }

    /// Get the current identifier
    pub fn get_identifier(&self) -> Option<String> {
        self.identifier.read().ok()?.clone()
    }

    /// Get the underlying tracker
    pub fn tracker(&self) -> &LoginTracker {
        &self.tracker
    }

    /// Check if the identifier is locked out
    pub fn check_lockout(&self) -> Option<LockoutInfo> {
        let id = self.get_identifier()?;
        self.tracker.check_lockout(&id)
    }

    /// Record a failed attempt for the current identifier
    pub fn record_failure(&self, ip: Option<&str>) -> Option<AttemptResult> {
        let id = self.get_identifier()?;
        Some(self.tracker.record_failure_with_ip(&id, ip))
    }

    /// Record a successful login for the current identifier
    pub fn record_success(&self, ip: Option<&str>) {
        if let Some(id) = self.get_identifier() {
            self.tracker.record_success_with_ip(&id, ip);
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

    #[test]
    fn test_login_tracking_config_default() {
        let config = LoginTrackingConfig::default();
        assert!(config.auth_paths.contains(&"/login".to_string()));
        assert!(config.auth_paths.contains(&"/auth/token".to_string()));
        assert!(config.auth_paths.contains(&"/oauth/token".to_string()));
        assert!(!config.require_identifier);
        assert!(config.enforce_ip_lockout);
    }

    #[test]
    fn test_login_tracker_extension() {
        let tracker = LoginTracker::with_default_policy();
        let ext = LoginTrackerExtension::new(tracker);

        // No identifier initially
        assert!(ext.get_identifier().is_none());

        // Set identifier
        ext.set_identifier("user@test.com");
        assert_eq!(ext.get_identifier(), Some("user@test.com".to_string()));

        // Should not be locked out initially
        assert!(ext.check_lockout().is_none());
    }

    #[test]
    fn test_middleware_config_path_matching() {
        let config = LoginTrackingConfig {
            auth_paths: vec!["/login".to_string(), "/api/auth".to_string()],
            require_identifier: false,
            enforce_ip_lockout: true,
        };

        // Test that paths are configurable
        assert!(config.auth_paths.iter().any(|p| "/login".starts_with(p)));
        assert!(config.auth_paths.iter().any(|p| "/api/auth/token".starts_with(p)));
        assert!(!config.auth_paths.iter().any(|p| "/other".starts_with(p)));
    }
}
