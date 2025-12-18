//! Security-Aware Audit Middleware (AU-2, AU-3, AU-12)
//!
//! Provides HTTP request auditing that integrates with the security event
//! logging system to capture security-relevant events.
//!
//! # NIST 800-53 Controls
//!
//! - **AU-2**: Audit Events - Identifies security-relevant events
//! - **AU-3**: Content of Audit Records - Captures who, what, when, where, outcome
//! - **AU-12**: Audit Generation - Generates audit records at runtime
//!
//! # Usage
//!
//! ```ignore
//! use axum::{Router, middleware};
//! use barbican::audit::audit_middleware;
//!
//! let app = Router::new()
//!     .route("/api/data", get(handler))
//!     .layer(middleware::from_fn(audit_middleware));
//! ```
//!
//! # Security Events Captured
//!
//! The middleware automatically logs:
//! - Rate limit exceeded (429) → `SecurityEvent::RateLimitExceeded`
//! - Authentication failures (401) → `SecurityEvent::AuthenticationFailure`
//! - Authorization failures (403) → `SecurityEvent::AccessDenied`
//! - Server errors (5xx) → Logged at error level with correlation ID

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{error, info, warn};

use crate::observability::{SecurityEvent, Severity};

/// Security-aware audit middleware function
///
/// Use with `axum::middleware::from_fn`:
///
/// ```ignore
/// use axum::{Router, middleware};
/// use barbican::audit::audit_middleware;
///
/// let app = Router::new()
///     .route("/", get(handler))
///     .layer(middleware::from_fn(audit_middleware));
/// ```
///
/// # Captured Information (AU-3)
///
/// - Timestamp (automatic via tracing)
/// - Client IP (from X-Forwarded-For, X-Real-IP, or CF-Connecting-IP)
/// - Request method and path
/// - Response status code
/// - Request latency
/// - User identity (if Authorization header present)
/// - Correlation ID (from X-Correlation-ID or X-Request-ID headers)
pub async fn audit_middleware(request: Request, next: Next) -> Response {
    let correlation_id = extract_or_generate_correlation_id(&request);
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();

    // Extract client IP from headers
    let client_ip = extract_client_ip(&request);

    // Extract user identity if available
    let user_id = extract_user_id(&request);

    let start = Instant::now();

    // Create span for this request
    let span = tracing::info_span!(
        "http_request",
        correlation_id = %correlation_id,
        method = %method,
        path = %path,
        client_ip = %client_ip,
        user_id = %user_id.as_deref().unwrap_or("-"),
    );
    let _guard = span.enter();

    // Execute the request
    let response = next.run(request).await;

    let status = response.status();
    let latency = start.elapsed();

    // Log security events based on response status
    log_security_event(status, &path, &client_ip, user_id.as_deref(), latency);

    // Standard request completion log
    info!(
        status = %status.as_u16(),
        latency_ms = %latency.as_millis(),
        "Request completed"
    );

    response
}

/// Log security events based on response status code
fn log_security_event(
    status: StatusCode,
    path: &str,
    client_ip: &str,
    user_id: Option<&str>,
    latency: std::time::Duration,
) {
    let user_field = user_id.unwrap_or("-");

    match status {
        // Rate limit exceeded - potential DoS or brute force
        StatusCode::TOO_MANY_REQUESTS => {
            warn!(
                security_event = SecurityEvent::RateLimitExceeded.name(),
                category = SecurityEvent::RateLimitExceeded.category(),
                severity = %Severity::High,
                ip_address = %client_ip,
                path = %path,
                user_id = %user_field,
                "Rate limit exceeded"
            );
        }

        // Authentication failure
        StatusCode::UNAUTHORIZED => {
            warn!(
                security_event = SecurityEvent::AuthenticationFailure.name(),
                category = SecurityEvent::AuthenticationFailure.category(),
                severity = %Severity::High,
                ip_address = %client_ip,
                path = %path,
                user_id = %user_field,
                "Authentication failure"
            );
        }

        // Authorization failure
        StatusCode::FORBIDDEN => {
            warn!(
                security_event = SecurityEvent::AccessDenied.name(),
                category = SecurityEvent::AccessDenied.category(),
                severity = %Severity::High,
                ip_address = %client_ip,
                path = %path,
                user_id = %user_field,
                "Access denied"
            );
        }

        // Server errors - potential security issue
        status if status.is_server_error() => {
            error!(
                status = %status.as_u16(),
                ip_address = %client_ip,
                path = %path,
                user_id = %user_field,
                latency_ms = %latency.as_millis(),
                "Server error occurred"
            );
        }

        // Successful authentication endpoints
        StatusCode::OK | StatusCode::CREATED
            if path.contains("/login")
                || path.contains("/auth")
                || path.contains("/token") =>
        {
            info!(
                security_event = SecurityEvent::AuthenticationSuccess.name(),
                category = SecurityEvent::AuthenticationSuccess.category(),
                severity = %Severity::Medium,
                ip_address = %client_ip,
                path = %path,
                user_id = %user_field,
                "Authentication success"
            );
        }

        // All other responses - no special handling
        _ => {}
    }
}

/// Extract or generate a correlation ID for request tracing
fn extract_or_generate_correlation_id(request: &Request<Body>) -> String {
    request
        .headers()
        .get("x-correlation-id")
        .or_else(|| request.headers().get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(generate_request_id)
}

/// Generate a simple request ID without external dependencies
fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("req-{:x}", timestamp)
}

/// Extract client IP from request headers
///
/// Checks headers in priority order:
/// 1. `X-Forwarded-For` (standard, may contain chain - takes first)
/// 2. `X-Real-IP` (single IP from reverse proxy)
/// 3. `CF-Connecting-IP` (Cloudflare)
///
/// Returns "unknown" if no client IP can be determined.
pub fn extract_client_ip(request: &Request<Body>) -> String {
    let headers = request.headers();

    // X-Forwarded-For (may contain multiple IPs, take first)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // X-Real-IP (single IP from reverse proxy)
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip) = real_ip.to_str() {
            return ip.to_string();
        }
    }

    // CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers.get("cf-connecting-ip") {
        if let Ok(ip) = cf_ip.to_str() {
            return ip.to_string();
        }
    }

    "unknown".to_string()
}

/// Extract user ID from request if available
fn extract_user_id(request: &Request<Body>) -> Option<String> {
    // Check Authorization header for Bearer token
    if let Some(auth) = request.headers().get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                // In a real implementation, decode JWT and extract sub
                return Some("[authenticated]".to_string());
            }
        }
    }

    None
}

/// Audit record for compliance reporting
///
/// Contains all fields required by AU-3 (Content of Audit Records)
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// Unique identifier for this audit record
    pub id: String,
    /// When the event occurred (ISO 8601)
    pub timestamp: String,
    /// Type of event
    pub event_type: String,
    /// Who performed the action (user ID or system)
    pub actor: String,
    /// What resource was accessed
    pub resource: String,
    /// Action performed (GET, POST, etc.)
    pub action: String,
    /// Outcome (success, failure)
    pub outcome: AuditOutcome,
    /// Source IP address
    pub source_ip: String,
    /// Additional context
    pub details: Option<String>,
}

/// Outcome of an audited action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Action completed successfully
    Success,
    /// Action failed
    Failure,
    /// Action was denied (authorization)
    Denied,
    /// Action was rate limited
    RateLimited,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Denied => write!(f, "denied"),
            Self::RateLimited => write!(f, "rate_limited"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_outcome_display() {
        assert_eq!(AuditOutcome::Success.to_string(), "success");
        assert_eq!(AuditOutcome::Failure.to_string(), "failure");
        assert_eq!(AuditOutcome::Denied.to_string(), "denied");
        assert_eq!(AuditOutcome::RateLimited.to_string(), "rate_limited");
    }

    #[test]
    fn test_generate_request_id() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();
        assert!(id1.starts_with("req-"));
        assert!(id2.starts_with("req-"));
        // IDs should be different (due to nanosecond timestamp)
        // Note: In a very fast loop they might be the same, so we don't assert inequality
    }
}
