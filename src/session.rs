//! Session Management (AC-11, AC-12)
//!
//! NIST SP 800-53 AC-11 (Device Lock) and AC-12 (Session Termination) compliant
//! session management utilities.
//!
//! # Design Philosophy
//!
//! Your OAuth provider manages the primary session (SSO session). Barbican provides:
//! - Session timeout policy enforcement
//! - Activity tracking for idle timeout detection
//! - Session event logging for audit compliance
//! - Helpers for session termination decisions
//!
//! # Usage
//!
//! ```ignore
//! use barbican::session::{SessionPolicy, SessionState, SessionEvent};
//! use std::time::Duration;
//!
//! // Define session policy
//! let policy = SessionPolicy::builder()
//!     .max_lifetime(Duration::from_secs(8 * 60 * 60))  // 8 hours max
//!     .idle_timeout(Duration::from_secs(30 * 60))      // 30 min idle
//!     .build();
//!
//! // Check if session should be terminated
//! if policy.should_terminate(&session_state) {
//!     // Redirect to re-authenticate
//! }
//! ```

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::observability::SecurityEvent;

// ============================================================================
// Session Policy (AC-11, AC-12)
// ============================================================================

/// Session management policy (AC-11, AC-12)
///
/// Defines rules for session lifetime and idle timeout.
#[derive(Debug, Clone)]
pub struct SessionPolicy {
    /// Maximum session lifetime from creation (AC-12)
    /// After this duration, the session must be terminated regardless of activity.
    pub max_lifetime: Duration,

    /// Idle timeout duration (AC-11)
    /// Session is terminated after this duration of inactivity.
    pub idle_timeout: Duration,

    /// Whether to require re-authentication for sensitive operations
    pub require_reauth_for_sensitive: bool,

    /// Duration after which re-authentication is required for sensitive ops
    pub reauth_timeout: Duration,

    /// Whether to allow session extension on activity
    pub allow_extension: bool,

    /// Maximum number of times a session can be extended
    pub max_extensions: u32,
}

impl Default for SessionPolicy {
    /// Default policy aligned with common security requirements
    ///
    /// - 8 hour max lifetime (typical workday)
    /// - 30 minute idle timeout
    /// - Re-auth required for sensitive operations after 15 minutes
    fn default() -> Self {
        Self {
            max_lifetime: Duration::from_secs(8 * 60 * 60),      // 8 hours
            idle_timeout: Duration::from_secs(30 * 60),          // 30 minutes
            require_reauth_for_sensitive: true,
            reauth_timeout: Duration::from_secs(15 * 60),        // 15 minutes
            allow_extension: false,
            max_extensions: 0,
        }
    }
}

impl SessionPolicy {
    /// Create a new builder
    pub fn builder() -> SessionPolicyBuilder {
        SessionPolicyBuilder::default()
    }

    /// Create a strict policy for high-security environments
    pub fn strict() -> Self {
        Self {
            max_lifetime: Duration::from_secs(4 * 60 * 60),      // 4 hours
            idle_timeout: Duration::from_secs(15 * 60),          // 15 minutes
            require_reauth_for_sensitive: true,
            reauth_timeout: Duration::from_secs(5 * 60),         // 5 minutes
            allow_extension: false,
            max_extensions: 0,
        }
    }

    /// Create a relaxed policy for low-risk applications
    pub fn relaxed() -> Self {
        Self {
            max_lifetime: Duration::from_secs(24 * 60 * 60),     // 24 hours
            idle_timeout: Duration::from_secs(60 * 60),          // 1 hour
            require_reauth_for_sensitive: false,
            reauth_timeout: Duration::from_secs(60 * 60),        // 1 hour
            allow_extension: true,
            max_extensions: 3,
        }
    }

    /// Create policy from compliance configuration
    ///
    /// Derives session timeouts and re-authentication requirements from the
    /// compliance profile. Use this to ensure session management aligns with
    /// your compliance requirements.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use barbican::compliance::ComplianceConfig;
    /// use barbican::session::SessionPolicy;
    ///
    /// let compliance = barbican::compliance::config();
    /// let policy = SessionPolicy::from_compliance(compliance);
    /// ```
    pub fn from_compliance(config: &crate::compliance::ComplianceConfig) -> Self {
        use crate::compliance::ComplianceProfile;

        let is_low_security = matches!(config.profile, ComplianceProfile::FedRampLow);

        Self {
            max_lifetime: config.session_max_lifetime,
            idle_timeout: config.session_idle_timeout,
            require_reauth_for_sensitive: !is_low_security,
            reauth_timeout: config.reauth_timeout,
            allow_extension: is_low_security,
            max_extensions: if is_low_security { 3 } else { 0 },
        }
    }

    /// Check if a session should be terminated based on this policy
    pub fn should_terminate(&self, state: &SessionState) -> SessionTerminationReason {
        let now = Instant::now();

        // Check max lifetime
        if let Some(created) = state.created_at {
            if now.duration_since(created) > self.max_lifetime {
                return SessionTerminationReason::MaxLifetimeExceeded;
            }
        }

        // Check idle timeout
        if let Some(last_activity) = state.last_activity {
            if now.duration_since(last_activity) > self.idle_timeout {
                return SessionTerminationReason::IdleTimeout;
            }
        }

        // Check extension limit
        if self.allow_extension && state.extension_count > self.max_extensions {
            return SessionTerminationReason::MaxExtensionsExceeded;
        }

        SessionTerminationReason::None
    }

    /// Check if re-authentication is required for a sensitive operation
    pub fn requires_reauth(&self, state: &SessionState) -> bool {
        if !self.require_reauth_for_sensitive {
            return false;
        }

        if let Some(last_auth) = state.last_authentication {
            let now = Instant::now();
            now.duration_since(last_auth) > self.reauth_timeout
        } else {
            true // No auth recorded, require it
        }
    }

    /// Check session validity using Unix timestamps (for JWT exp/iat)
    pub fn check_token_times(
        &self,
        issued_at: Option<i64>,
        expires_at: Option<i64>,
    ) -> SessionTerminationReason {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Check expiration
        if let Some(exp) = expires_at {
            if now > exp {
                return SessionTerminationReason::TokenExpired;
            }
        }

        // Check max lifetime from issued_at
        if let Some(iat) = issued_at {
            let age = Duration::from_secs((now - iat).max(0) as u64);
            if age > self.max_lifetime {
                return SessionTerminationReason::MaxLifetimeExceeded;
            }
        }

        SessionTerminationReason::None
    }
}

/// Builder for SessionPolicy
#[derive(Debug, Clone, Default)]
pub struct SessionPolicyBuilder {
    policy: SessionPolicy,
}

impl SessionPolicyBuilder {
    /// Set maximum session lifetime (AC-12)
    pub fn max_lifetime(mut self, duration: Duration) -> Self {
        self.policy.max_lifetime = duration;
        self
    }

    /// Set idle timeout (AC-11)
    pub fn idle_timeout(mut self, duration: Duration) -> Self {
        self.policy.idle_timeout = duration;
        self
    }

    /// Enable/disable re-authentication requirement for sensitive operations
    pub fn require_reauth_for_sensitive(mut self, require: bool) -> Self {
        self.policy.require_reauth_for_sensitive = require;
        self
    }

    /// Set re-authentication timeout
    pub fn reauth_timeout(mut self, duration: Duration) -> Self {
        self.policy.reauth_timeout = duration;
        self
    }

    /// Allow session extension on activity
    pub fn allow_extension(mut self, allow: bool) -> Self {
        self.policy.allow_extension = allow;
        self
    }

    /// Set maximum number of session extensions
    pub fn max_extensions(mut self, count: u32) -> Self {
        self.policy.max_extensions = count;
        self
    }

    /// Build the policy
    pub fn build(self) -> SessionPolicy {
        self.policy
    }
}

// ============================================================================
// Session State
// ============================================================================

/// Tracks the state of a user session (AC-11, AC-12)
///
/// Use this to track session timing for policy enforcement.
/// Store this in your session storage (Redis, database, etc.).
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Session identifier
    pub session_id: String,

    /// User identifier
    pub user_id: String,

    /// When the session was created
    pub created_at: Option<Instant>,

    /// When the session was created (Unix timestamp for persistence)
    pub created_at_unix: Option<i64>,

    /// Last activity time
    pub last_activity: Option<Instant>,

    /// Last activity time (Unix timestamp for persistence)
    pub last_activity_unix: Option<i64>,

    /// Last authentication time (for re-auth checks)
    pub last_authentication: Option<Instant>,

    /// Last authentication time (Unix timestamp for persistence)
    pub last_authentication_unix: Option<i64>,

    /// Number of times the session has been extended
    pub extension_count: u32,

    /// Whether the session is currently active
    pub is_active: bool,

    /// IP address of the client (for audit logging)
    pub client_ip: Option<String>,

    /// User agent of the client (for audit logging)
    pub user_agent: Option<String>,
}

impl SessionState {
    /// Create a new session state
    pub fn new(session_id: impl Into<String>, user_id: impl Into<String>) -> Self {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            session_id: session_id.into(),
            user_id: user_id.into(),
            created_at: Some(now),
            created_at_unix: Some(now_unix),
            last_activity: Some(now),
            last_activity_unix: Some(now_unix),
            last_authentication: Some(now),
            last_authentication_unix: Some(now_unix),
            extension_count: 0,
            is_active: true,
            client_ip: None,
            user_agent: None,
        }
    }

    /// Record activity (updates last_activity time)
    pub fn record_activity(&mut self) {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        self.last_activity = Some(now);
        self.last_activity_unix = Some(now_unix);
    }

    /// Record re-authentication
    pub fn record_authentication(&mut self) {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        self.last_authentication = Some(now);
        self.last_authentication_unix = Some(now_unix);
        self.last_activity = Some(now);
        self.last_activity_unix = Some(now_unix);
    }

    /// Extend the session (if allowed by policy)
    pub fn extend(&mut self) {
        self.extension_count += 1;
        self.record_activity();
    }

    /// Mark the session as terminated
    pub fn terminate(&mut self) {
        self.is_active = false;
    }

    /// Set client information
    pub fn with_client_info(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.client_ip = ip;
        self.user_agent = user_agent;
        self
    }

    /// Calculate session age
    pub fn age(&self) -> Option<Duration> {
        self.created_at.map(|created| Instant::now().duration_since(created))
    }

    /// Calculate idle time
    pub fn idle_time(&self) -> Option<Duration> {
        self.last_activity.map(|last| Instant::now().duration_since(last))
    }

    /// Calculate time since last authentication
    pub fn time_since_auth(&self) -> Option<Duration> {
        self.last_authentication.map(|last| Instant::now().duration_since(last))
    }
}

// ============================================================================
// Session Termination
// ============================================================================

/// Reason for session termination (AC-11, AC-12)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTerminationReason {
    /// Session is still valid
    None,
    /// Maximum session lifetime exceeded (AC-12)
    MaxLifetimeExceeded,
    /// Session idle timeout (AC-11)
    IdleTimeout,
    /// Token has expired
    TokenExpired,
    /// Maximum extensions exceeded
    MaxExtensionsExceeded,
    /// User requested logout
    UserLogout,
    /// Administrative termination
    AdminTermination,
    /// Security concern (suspicious activity)
    SecurityConcern,
    /// Concurrent session limit exceeded
    ConcurrentSessionLimit,
}

impl SessionTerminationReason {
    /// Check if the session should be terminated
    pub fn should_terminate(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Get a user-friendly message for this reason
    pub fn message(&self) -> &'static str {
        match self {
            Self::None => "Session is valid",
            Self::MaxLifetimeExceeded => "Your session has expired. Please sign in again.",
            Self::IdleTimeout => "Your session timed out due to inactivity. Please sign in again.",
            Self::TokenExpired => "Your session has expired. Please sign in again.",
            Self::MaxExtensionsExceeded => "Your session can no longer be extended. Please sign in again.",
            Self::UserLogout => "You have been signed out.",
            Self::AdminTermination => "Your session was terminated by an administrator.",
            Self::SecurityConcern => "Your session was terminated for security reasons.",
            Self::ConcurrentSessionLimit => "You have been signed out because you signed in from another location.",
        }
    }

    /// Get the reason as a string code
    pub fn code(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MaxLifetimeExceeded => "max_lifetime_exceeded",
            Self::IdleTimeout => "idle_timeout",
            Self::TokenExpired => "token_expired",
            Self::MaxExtensionsExceeded => "max_extensions_exceeded",
            Self::UserLogout => "user_logout",
            Self::AdminTermination => "admin_termination",
            Self::SecurityConcern => "security_concern",
            Self::ConcurrentSessionLimit => "concurrent_session_limit",
        }
    }
}

impl std::fmt::Display for SessionTerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

// ============================================================================
// Session Event Logging (AU-2, AU-3)
// ============================================================================

/// Log session creation (AU-2, AU-3)
pub fn log_session_created(state: &SessionState) {
    crate::security_event!(
        SecurityEvent::SessionCreated,
        session_id = %state.session_id,
        user_id = %state.user_id,
        client_ip = %state.client_ip.as_deref().unwrap_or("unknown"),
        "Session created"
    );
}

/// Log session activity (for debugging/audit)
pub fn log_session_activity(state: &SessionState, resource: &str) {
    tracing::debug!(
        session_id = %state.session_id,
        user_id = %state.user_id,
        resource = %resource,
        idle_time_secs = ?state.idle_time().map(|d| d.as_secs()),
        "Session activity"
    );
}

/// Log session termination (AU-2, AU-3)
pub fn log_session_terminated(state: &SessionState, reason: SessionTerminationReason) {
    crate::security_event!(
        SecurityEvent::SessionDestroyed,
        session_id = %state.session_id,
        user_id = %state.user_id,
        reason = %reason.code(),
        session_age_secs = ?state.age().map(|d| d.as_secs()),
        client_ip = %state.client_ip.as_deref().unwrap_or("unknown"),
        "Session terminated"
    );
}

/// Log session extension
pub fn log_session_extended(state: &SessionState) {
    tracing::info!(
        session_id = %state.session_id,
        user_id = %state.user_id,
        extension_count = state.extension_count,
        "Session extended"
    );
}

/// Log re-authentication requirement
pub fn log_reauth_required(state: &SessionState, resource: &str) {
    crate::security_event!(
        SecurityEvent::AccessDenied,
        session_id = %state.session_id,
        user_id = %state.user_id,
        resource = %resource,
        reason = "reauth_required",
        time_since_auth_secs = ?state.time_since_auth().map(|d| d.as_secs()),
        "Re-authentication required for sensitive operation"
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
        let policy = SessionPolicy::default();
        assert_eq!(policy.max_lifetime, Duration::from_secs(8 * 60 * 60));
        assert_eq!(policy.idle_timeout, Duration::from_secs(30 * 60));
        assert!(policy.require_reauth_for_sensitive);
    }

    #[test]
    fn test_strict_policy() {
        let policy = SessionPolicy::strict();
        assert_eq!(policy.max_lifetime, Duration::from_secs(4 * 60 * 60));
        assert_eq!(policy.idle_timeout, Duration::from_secs(15 * 60));
    }

    #[test]
    fn test_relaxed_policy() {
        let policy = SessionPolicy::relaxed();
        assert_eq!(policy.max_lifetime, Duration::from_secs(24 * 60 * 60));
        assert!(policy.allow_extension);
    }

    #[test]
    fn test_session_state_creation() {
        let state = SessionState::new("sess-123", "user-456");
        assert_eq!(state.session_id, "sess-123");
        assert_eq!(state.user_id, "user-456");
        assert!(state.is_active);
        assert_eq!(state.extension_count, 0);
    }

    #[test]
    fn test_session_activity_recording() {
        let mut state = SessionState::new("sess-123", "user-456");
        let initial_activity = state.last_activity;

        // Small delay to ensure time difference
        std::thread::sleep(Duration::from_millis(10));

        state.record_activity();
        assert!(state.last_activity > initial_activity);
    }

    #[test]
    fn test_session_extension() {
        let mut state = SessionState::new("sess-123", "user-456");
        assert_eq!(state.extension_count, 0);

        state.extend();
        assert_eq!(state.extension_count, 1);

        state.extend();
        assert_eq!(state.extension_count, 2);
    }

    #[test]
    fn test_session_termination() {
        let mut state = SessionState::new("sess-123", "user-456");
        assert!(state.is_active);

        state.terminate();
        assert!(!state.is_active);
    }

    #[test]
    fn test_termination_reason_messages() {
        assert!(!SessionTerminationReason::None.should_terminate());
        assert!(SessionTerminationReason::IdleTimeout.should_terminate());
        assert!(SessionTerminationReason::MaxLifetimeExceeded.should_terminate());

        assert_eq!(SessionTerminationReason::IdleTimeout.code(), "idle_timeout");
        assert_eq!(SessionTerminationReason::MaxLifetimeExceeded.code(), "max_lifetime_exceeded");
    }

    #[test]
    fn test_token_time_check() {
        let policy = SessionPolicy::default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Valid token
        let result = policy.check_token_times(
            Some(now - 3600), // issued 1 hour ago
            Some(now + 3600), // expires in 1 hour
        );
        assert_eq!(result, SessionTerminationReason::None);

        // Expired token
        let result = policy.check_token_times(
            Some(now - 3600),
            Some(now - 60), // expired 1 minute ago
        );
        assert_eq!(result, SessionTerminationReason::TokenExpired);
    }

    #[test]
    fn test_policy_builder() {
        let policy = SessionPolicy::builder()
            .max_lifetime(Duration::from_secs(3600))
            .idle_timeout(Duration::from_secs(600))
            .require_reauth_for_sensitive(false)
            .allow_extension(true)
            .max_extensions(5)
            .build();

        assert_eq!(policy.max_lifetime, Duration::from_secs(3600));
        assert_eq!(policy.idle_timeout, Duration::from_secs(600));
        assert!(!policy.require_reauth_for_sensitive);
        assert!(policy.allow_extension);
        assert_eq!(policy.max_extensions, 5);
    }
}
