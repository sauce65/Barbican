//! Secure Error Handling (SI-11)
//!
//! Provides safe error responses that don't leak internal details.

use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use tracing::error;

/// Application error type with secure response handling
#[derive(Debug)]
pub struct AppError {
    /// Error kind for categorization
    pub kind: ErrorKind,
    /// Message safe to show to users
    pub message: String,
    /// Internal details (logged but not exposed)
    internal: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Validation,
    Authentication,
    Authorization,
    NotFound,
    Conflict,
    RateLimited,
    LockedOut,
    Internal,
}

impl AppError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Validation,
            message: message.into(),
            internal: None,
        }
    }

    pub fn auth_failed(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Authentication,
            message: message.into(),
            internal: None,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Authorization,
            message: message.into(),
            internal: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::NotFound,
            message: message.into(),
            internal: None,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Conflict,
            message: message.into(),
            internal: None,
        }
    }

    pub fn locked_out(seconds_remaining: u64) -> Self {
        Self {
            kind: ErrorKind::LockedOut,
            message: format!("Account locked. Try again in {} seconds.", seconds_remaining),
            internal: None,
        }
    }

    pub fn rate_limited() -> Self {
        Self {
            kind: ErrorKind::RateLimited,
            message: "Too many requests. Please slow down.".into(),
            internal: None,
        }
    }

    /// Create internal error - logs details but shows generic message
    pub fn internal(internal_details: impl Into<String>) -> Self {
        let details = internal_details.into();
        error!(error = %details, "Internal error occurred");
        Self {
            kind: ErrorKind::Internal,
            message: "An internal error occurred".into(),
            internal: Some(details),
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    kind: ErrorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self.kind {
            ErrorKind::Validation => StatusCode::BAD_REQUEST,
            ErrorKind::Authentication => StatusCode::UNAUTHORIZED,
            ErrorKind::Authorization => StatusCode::FORBIDDEN,
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorKind::LockedOut => StatusCode::FORBIDDEN,
            ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = ErrorResponse {
            error: self.message,
            kind: self.kind,
            field: None,
        };

        (status, Json(body)).into_response()
    }
}

// Convert validation errors
impl From<barbican::validation::ValidationError> for AppError {
    fn from(e: barbican::validation::ValidationError) -> Self {
        Self {
            kind: ErrorKind::Validation,
            message: format!("{}: {}", e.field, e.message),
            internal: None,
        }
    }
}

// Convert password errors
impl From<barbican::password::PasswordError> for AppError {
    fn from(e: barbican::password::PasswordError) -> Self {
        Self {
            kind: ErrorKind::Validation,
            message: format!("Password: {}", e),
            internal: None,
        }
    }
}
