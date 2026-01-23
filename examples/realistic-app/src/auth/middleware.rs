//! Authentication Middleware
//!
//! Validates JWT tokens and extracts user claims for protected routes.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    http::header::AUTHORIZATION,
};
use tracing::warn;

use crate::error::AppError;
use crate::AppState;
use super::jwt::{self, Claims};

/// Middleware that requires valid JWT authentication
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            &header[7..] // Skip "Bearer "
        }
        Some(_) => {
            warn!(event = "auth.invalid_header", "Invalid Authorization header format");
            return Err(AppError::auth_failed("Invalid Authorization header"));
        }
        None => {
            return Err(AppError::auth_failed("Authorization header required"));
        }
    };

    // Validate token
    let claims = jwt::validate_token(token, &state.config.jwt_secret)?;

    // Check session timeout (AC-11, AC-12)
    // In production, track last activity and check against session policy:
    // if !state.session_policy.is_valid(&session_state) {
    //     return Err(AppError::auth_failed("Session expired"));
    // }

    // Add claims to request extensions for use in handlers
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Extract claims from request extensions
///
/// Use in handlers after auth_middleware:
/// ```ignore
/// async fn handler(claims: Claims) -> impl IntoResponse {
///     format!("Hello, user {}", claims.user_id())
/// }
/// ```
impl<S> axum::extract::FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .ok_or_else(|| AppError::auth_failed("Not authenticated"))
    }
}
