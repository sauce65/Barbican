//! Security Event Logging
//!
//! Provides structured logging for security-relevant events as required by
//! NIST SP 800-53 AU-2 (Audit Events), AU-3 (Content of Audit Records).
//!
//! # Usage
//!
//! ```ignore
//! use barbican::observability::{SecurityEvent, security_event};
//!
//! // Log a security event
//! security_event!(
//!     SecurityEvent::AuthenticationSuccess,
//!     user_id = %user.id,
//!     ip_address = %client_ip,
//!     "User authenticated successfully"
//! );
//!
//! // Log a security failure
//! security_event!(
//!     SecurityEvent::AuthenticationFailure,
//!     email = %email,
//!     ip_address = %client_ip,
//!     reason = "invalid_password",
//!     "Authentication failed"
//! );
//! ```

use std::fmt;

/// Security event categories for audit logging.
///
/// These categories align with NIST SP 800-53 AU-2 auditable events.
/// This enum contains generic security events that apply to any application.
/// Application-specific events (OAuth, etc.) should be defined in the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
    // Authentication events
    /// Successful user authentication
    AuthenticationSuccess,
    /// Failed authentication attempt
    AuthenticationFailure,
    /// User logout
    Logout,
    /// Session created
    SessionCreated,
    /// Session expired or invalidated
    SessionDestroyed,

    // Authorization events
    /// Access granted to resource
    AccessGranted,
    /// Access denied to resource
    AccessDenied,

    // User management events
    /// New user registered
    UserRegistered,
    /// User account modified
    UserModified,
    /// User account deleted
    UserDeleted,
    /// Password changed
    PasswordChanged,
    /// Password reset requested
    PasswordResetRequested,

    // Security events
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Brute force attempt detected
    BruteForceDetected,
    /// Account locked due to security
    AccountLocked,
    /// Account unlocked
    AccountUnlocked,
    /// Suspicious activity detected
    SuspiciousActivity,

    // System events
    /// Application started
    SystemStartup,
    /// Application shutdown
    SystemShutdown,
    /// Configuration changed
    ConfigurationChanged,
    /// Database connection established
    DatabaseConnected,
    /// Database connection lost
    DatabaseDisconnected,
}

impl SecurityEvent {
    /// Get the event category for filtering/grouping
    pub fn category(&self) -> &'static str {
        match self {
            Self::AuthenticationSuccess
            | Self::AuthenticationFailure
            | Self::Logout
            | Self::SessionCreated
            | Self::SessionDestroyed => "authentication",

            Self::AccessGranted
            | Self::AccessDenied => "authorization",

            Self::UserRegistered
            | Self::UserModified
            | Self::UserDeleted
            | Self::PasswordChanged
            | Self::PasswordResetRequested => "user_management",

            Self::RateLimitExceeded
            | Self::BruteForceDetected
            | Self::AccountLocked
            | Self::AccountUnlocked
            | Self::SuspiciousActivity => "security",

            Self::SystemStartup
            | Self::SystemShutdown
            | Self::ConfigurationChanged
            | Self::DatabaseConnected
            | Self::DatabaseDisconnected => "system",
        }
    }

    /// Get the severity level for the event
    pub fn severity(&self) -> Severity {
        match self {
            // Critical - immediate attention required
            Self::BruteForceDetected
            | Self::SuspiciousActivity
            | Self::DatabaseDisconnected => Severity::Critical,

            // High - security-relevant failures
            Self::AuthenticationFailure
            | Self::AccessDenied
            | Self::AccountLocked
            | Self::RateLimitExceeded => Severity::High,

            // Medium - important state changes
            Self::AuthenticationSuccess
            | Self::UserRegistered
            | Self::UserModified
            | Self::UserDeleted
            | Self::PasswordChanged
            | Self::PasswordResetRequested
            | Self::AccountUnlocked
            | Self::ConfigurationChanged => Severity::Medium,

            // Low - routine operations
            Self::AccessGranted
            | Self::Logout
            | Self::SessionCreated
            | Self::SessionDestroyed
            | Self::SystemStartup
            | Self::SystemShutdown
            | Self::DatabaseConnected => Severity::Low,
        }
    }

    /// Get the event name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Self::AuthenticationSuccess => "authentication_success",
            Self::AuthenticationFailure => "authentication_failure",
            Self::Logout => "logout",
            Self::SessionCreated => "session_created",
            Self::SessionDestroyed => "session_destroyed",
            Self::AccessGranted => "access_granted",
            Self::AccessDenied => "access_denied",
            Self::UserRegistered => "user_registered",
            Self::UserModified => "user_modified",
            Self::UserDeleted => "user_deleted",
            Self::PasswordChanged => "password_changed",
            Self::PasswordResetRequested => "password_reset_requested",
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::BruteForceDetected => "brute_force_detected",
            Self::AccountLocked => "account_locked",
            Self::AccountUnlocked => "account_unlocked",
            Self::SuspiciousActivity => "suspicious_activity",
            Self::SystemStartup => "system_startup",
            Self::SystemShutdown => "system_shutdown",
            Self::ConfigurationChanged => "configuration_changed",
            Self::DatabaseConnected => "database_connected",
            Self::DatabaseDisconnected => "database_disconnected",
        }
    }
}

impl fmt::Display for SecurityEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Routine operations
    Low,
    /// Important state changes
    Medium,
    /// Security-relevant failures
    High,
    /// Immediate attention required
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Log a security event with structured fields.
///
/// This macro provides consistent formatting for security-relevant events
/// as required by NIST SP 800-53 AU-3 (Content of Audit Records).
///
/// # Required Fields
///
/// The macro automatically includes:
/// - `security_event`: Event type name
/// - `category`: Event category
/// - `severity`: Event severity level
///
/// # Examples
///
/// ```ignore
/// security_event!(
///     SecurityEvent::AuthenticationSuccess,
///     user_id = %user.id,
///     ip_address = %client_ip,
///     "User authenticated"
/// );
///
/// security_event!(
///     SecurityEvent::RateLimitExceeded,
///     ip_address = %client_ip,
///     endpoint = "/api/login",
///     "Rate limit exceeded"
/// );
/// ```
#[macro_export]
macro_rules! security_event {
    ($event:expr, $($field:tt)*) => {{
        let event = $event;
        let severity = event.severity();
        let category = event.category();
        let event_name = event.name();

        match severity {
            $crate::observability::Severity::Critical => {
                ::tracing::error!(
                    security_event = event_name,
                    category = category,
                    severity = "critical",
                    $($field)*
                );
            }
            $crate::observability::Severity::High => {
                ::tracing::warn!(
                    security_event = event_name,
                    category = category,
                    severity = "high",
                    $($field)*
                );
            }
            $crate::observability::Severity::Medium => {
                ::tracing::info!(
                    security_event = event_name,
                    category = category,
                    severity = "medium",
                    $($field)*
                );
            }
            $crate::observability::Severity::Low => {
                ::tracing::debug!(
                    security_event = event_name,
                    category = category,
                    severity = "low",
                    $($field)*
                );
            }
        }
    }};
}

pub use security_event;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_categories() {
        assert_eq!(SecurityEvent::AuthenticationSuccess.category(), "authentication");
        assert_eq!(SecurityEvent::AccessDenied.category(), "authorization");
        assert_eq!(SecurityEvent::UserRegistered.category(), "user_management");
        assert_eq!(SecurityEvent::RateLimitExceeded.category(), "security");
        assert_eq!(SecurityEvent::SystemStartup.category(), "system");
    }

    #[test]
    fn test_event_severity() {
        assert_eq!(SecurityEvent::BruteForceDetected.severity(), Severity::Critical);
        assert_eq!(SecurityEvent::AuthenticationFailure.severity(), Severity::High);
        assert_eq!(SecurityEvent::UserRegistered.severity(), Severity::Medium);
        assert_eq!(SecurityEvent::SessionCreated.severity(), Severity::Low);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_event_name() {
        assert_eq!(SecurityEvent::AuthenticationSuccess.name(), "authentication_success");
        assert_eq!(SecurityEvent::BruteForceDetected.name(), "brute_force_detected");
    }
}
