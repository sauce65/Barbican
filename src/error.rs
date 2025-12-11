//! Secure Error Handling (SI-11)
//!
//! NIST SP 800-53 SI-11 compliant error handling that prevents
//! information leakage while maintaining debuggability.
//!
//! # Security Rationale
//!
//! Error messages can leak sensitive information:
//! - Stack traces reveal internal structure
//! - Database errors reveal schema details
//! - Path information reveals deployment structure
//! - Detailed errors help attackers probe vulnerabilities
//!
//! This module provides:
//! - Safe error responses for production (hide details)
//! - Detailed errors for development (full context)
//! - Automatic error logging with request correlation
//! - Structured error format for API responses
//!
//! # Usage
//!
//! ```ignore
//! use barbican::error::{AppError, ErrorConfig};
//! use axum::{Router, response::IntoResponse};
//!
//! async fn handler() -> Result<String, AppError> {
//!     // Internal errors are logged but not exposed
//!     let data = fetch_data()
//!         .map_err(|e| AppError::internal("Failed to fetch data", e))?;
//!     Ok(data)
//! }
//!
//! // In production: returns {"error": "Internal server error", "request_id": "..."}
//! // In development: returns full error details
//! ```

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::fmt;

// ============================================================================
// Error Configuration
// ============================================================================

/// Error handling configuration (SI-11)
#[derive(Debug, Clone)]
pub struct ErrorConfig {
    /// Whether to expose detailed error messages
    /// Should be `false` in production
    pub expose_details: bool,

    /// Whether to include stack traces in responses
    /// Should be `false` in production
    pub include_stack_traces: bool,

    /// Whether to log errors
    pub log_errors: bool,

    /// Whether to include request ID in error responses
    pub include_request_id: bool,

    /// Custom message for internal errors in production
    pub internal_error_message: String,

    /// Custom message for validation errors
    pub validation_error_message: String,
}

impl Default for ErrorConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl ErrorConfig {
    /// Production configuration (secure defaults)
    pub fn production() -> Self {
        Self {
            expose_details: false,
            include_stack_traces: false,
            log_errors: true,
            include_request_id: true,
            internal_error_message: "An internal error occurred".to_string(),
            validation_error_message: "Invalid request".to_string(),
        }
    }

    /// Development configuration (detailed errors)
    pub fn development() -> Self {
        Self {
            expose_details: true,
            include_stack_traces: true,
            log_errors: true,
            include_request_id: true,
            internal_error_message: "Internal server error".to_string(),
            validation_error_message: "Validation error".to_string(),
        }
    }

    /// Load from environment
    ///
    /// Uses `RUST_ENV` or `APP_ENV` to determine mode:
    /// - "production" or "prod" -> production config
    /// - anything else -> development config
    pub fn from_env() -> Self {
        let env = std::env::var("RUST_ENV")
            .or_else(|_| std::env::var("APP_ENV"))
            .unwrap_or_else(|_| "development".to_string());

        if env.to_lowercase() == "production" || env.to_lowercase() == "prod" {
            Self::production()
        } else {
            Self::development()
        }
    }
}

// Global configuration (set once at startup)
static ERROR_CONFIG: std::sync::OnceLock<ErrorConfig> = std::sync::OnceLock::new();

/// Initialize error handling configuration
///
/// Call this once at application startup:
/// ```ignore
/// barbican::error::init(ErrorConfig::from_env());
/// ```
pub fn init(config: ErrorConfig) {
    let _ = ERROR_CONFIG.set(config);
}

/// Get the current error configuration
pub fn config() -> &'static ErrorConfig {
    ERROR_CONFIG.get_or_init(ErrorConfig::default)
}

// ============================================================================
// Error Types
// ============================================================================

/// Application error type with secure handling (SI-11)
///
/// This error type:
/// - Logs internal details for debugging
/// - Returns safe messages to clients
/// - Includes request ID for correlation
/// - Maps to appropriate HTTP status codes
#[derive(Debug)]
pub struct AppError {
    /// Error kind determines HTTP status and handling
    pub kind: ErrorKind,
    /// User-facing message (safe to expose)
    pub message: String,
    /// Internal details (logged, not exposed in production)
    pub details: Option<String>,
    /// Original error (for logging)
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
    /// Request ID for correlation
    pub request_id: Option<String>,
}

/// Error categories with appropriate HTTP status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad request (400) - client error, safe to expose details
    BadRequest,
    /// Unauthorized (401) - authentication required
    Unauthorized,
    /// Forbidden (403) - authenticated but not authorized
    Forbidden,
    /// Not found (404) - resource doesn't exist
    NotFound,
    /// Conflict (409) - resource state conflict
    Conflict,
    /// Unprocessable entity (422) - validation error
    Validation,
    /// Too many requests (429) - rate limited
    RateLimited,
    /// Internal server error (500) - hide details
    Internal,
    /// Service unavailable (503) - temporary failure
    Unavailable,
}

impl ErrorKind {
    /// Get the HTTP status code for this error kind
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Validation => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Whether details can be safely exposed for this error kind
    pub fn expose_details(&self) -> bool {
        matches!(
            self,
            Self::BadRequest | Self::Validation | Self::NotFound | Self::Conflict
        )
    }
}

impl AppError {
    /// Create a new error
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            details: None,
            source: None,
            request_id: None,
        }
    }

    /// Create a bad request error (400)
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::BadRequest, message)
    }

    /// Create an unauthorized error (401)
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unauthorized, message)
    }

    /// Create a forbidden error (403)
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Forbidden, message)
    }

    /// Create a not found error (404)
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    /// Create a conflict error (409)
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Conflict, message)
    }

    /// Create a validation error (422)
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Validation, message)
    }

    /// Create a rate limited error (429)
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::RateLimited, message)
    }

    /// Create an internal error (500) with source
    ///
    /// The message is what users see; the source is logged but not exposed.
    pub fn internal(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind: ErrorKind::Internal,
            message: message.into(),
            details: Some(source.to_string()),
            source: Some(Box::new(source)),
            request_id: None,
        }
    }

    /// Create an internal error without a source
    pub fn internal_msg(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }

    /// Create a service unavailable error (503)
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unavailable, message)
    }

    /// Add internal details (logged but not exposed)
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Add request ID for correlation
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Log the error (called automatically by IntoResponse)
    fn log(&self) {
        let cfg = config();
        if !cfg.log_errors {
            return;
        }

        let request_id = self.request_id.as_deref().unwrap_or("unknown");
        let details = self.details.as_deref().unwrap_or("none");

        match self.kind {
            ErrorKind::Internal | ErrorKind::Unavailable => {
                tracing::error!(
                    error_kind = %self.kind,
                    message = %self.message,
                    details = %details,
                    request_id = %request_id,
                    "Internal error"
                );
            }
            ErrorKind::Unauthorized | ErrorKind::Forbidden => {
                tracing::warn!(
                    error_kind = %self.kind,
                    message = %self.message,
                    request_id = %request_id,
                    "Auth error"
                );
            }
            _ => {
                tracing::debug!(
                    error_kind = %self.kind,
                    message = %self.message,
                    request_id = %request_id,
                    "Client error"
                );
            }
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest => write!(f, "bad_request"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::NotFound => write!(f, "not_found"),
            Self::Conflict => write!(f, "conflict"),
            Self::Validation => write!(f, "validation_error"),
            Self::RateLimited => write!(f, "rate_limited"),
            Self::Internal => write!(f, "internal_error"),
            Self::Unavailable => write!(f, "service_unavailable"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

// ============================================================================
// Error Response
// ============================================================================

/// JSON error response format
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErrorResponse {
    /// Error type/code
    pub error: String,
    /// Human-readable message
    pub message: String,
    /// Request ID for support/debugging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Error details (only in development)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log the error
        self.log();

        let cfg = config();
        let status = self.kind.status_code();

        // Determine what to expose
        let (message, details) = if cfg.expose_details || self.kind.expose_details() {
            (self.message.clone(), self.details.clone())
        } else {
            // Use generic messages for sensitive errors
            let msg = match self.kind {
                ErrorKind::Internal => cfg.internal_error_message.clone(),
                ErrorKind::Unauthorized => "Authentication required".to_string(),
                ErrorKind::Forbidden => "Access denied".to_string(),
                _ => self.message.clone(),
            };
            (msg, None)
        };

        let response = ErrorResponse {
            error: self.kind.to_string(),
            message,
            request_id: if cfg.include_request_id {
                self.request_id
            } else {
                None
            },
            details: if cfg.expose_details { details } else { None },
        };

        (status, Json(response)).into_response()
    }
}

// ============================================================================
// Conversions from common error types
// ============================================================================

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::internal("IO error", err)
    }
}

impl From<crate::validation::ValidationError> for AppError {
    fn from(err: crate::validation::ValidationError) -> Self {
        AppError::validation(err.to_string())
    }
}

impl From<crate::password::PasswordError> for AppError {
    fn from(err: crate::password::PasswordError) -> Self {
        AppError::validation(err.to_string())
    }
}

#[cfg(feature = "postgres")]
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        // Don't expose database details
        AppError::internal("Database error", err)
    }
}

// ============================================================================
// Result type alias
// ============================================================================

/// Result type alias for handlers returning AppError
pub type Result<T> = std::result::Result<T, AppError>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_kind_status_codes() {
        assert_eq!(ErrorKind::BadRequest.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(ErrorKind::Unauthorized.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(ErrorKind::Forbidden.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(ErrorKind::NotFound.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(ErrorKind::Internal.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_kind_expose_details() {
        assert!(ErrorKind::BadRequest.expose_details());
        assert!(ErrorKind::Validation.expose_details());
        assert!(ErrorKind::NotFound.expose_details());
        assert!(!ErrorKind::Internal.expose_details());
        assert!(!ErrorKind::Unauthorized.expose_details());
    }

    #[test]
    fn test_error_builders() {
        let err = AppError::not_found("User not found");
        assert_eq!(err.kind, ErrorKind::NotFound);
        assert_eq!(err.message, "User not found");

        let err = AppError::validation("Invalid email")
            .with_details("Must contain @");
        assert_eq!(err.kind, ErrorKind::Validation);
        assert_eq!(err.details, Some("Must contain @".to_string()));
    }

    #[test]
    fn test_error_with_request_id() {
        let err = AppError::internal_msg("Something went wrong")
            .with_request_id("req-123");
        assert_eq!(err.request_id, Some("req-123".to_string()));
    }

    #[test]
    fn test_config_modes() {
        let prod = ErrorConfig::production();
        assert!(!prod.expose_details);
        assert!(!prod.include_stack_traces);

        let dev = ErrorConfig::development();
        assert!(dev.expose_details);
        assert!(dev.include_stack_traces);
    }

    #[test]
    fn test_error_display() {
        let err = AppError::not_found("User not found");
        assert_eq!(format!("{}", err), "not_found: User not found");
    }
}
