//! HTTP metrics middleware for Axum
//!
//! Automatic HTTP request instrumentation that records:
//! - `http_requests_total{method, path, status}` - Counter
//! - `http_request_duration_seconds{method, path}` - Histogram
//! - `http_requests_active` - Gauge

use super::registry::MetricsHandle;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::time::Instant;

/// Middleware that records HTTP request metrics.
///
/// This middleware should be applied after authentication but before
/// route handlers, so it captures the full request lifecycle.
///
/// # Metrics Recorded
///
/// - `http_requests_total{method, path, status}` - Counter incremented for each request
/// - `http_request_duration_seconds{method, path}` - Histogram of request durations
/// - `http_requests_active` - Gauge of currently processing requests
///
/// # Path Normalization
///
/// Path segments matching UUID patterns are normalized to `:id` to prevent
/// cardinality explosion. For example:
/// - `/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000` → `/api/v1/jobs/:id`
///
/// # Example
///
/// ```ignore
/// use axum::{Router, middleware};
/// use barbican::observability::metrics::{MetricRegistry, MetricsHandle, http_metrics_middleware};
/// use std::sync::Arc;
///
/// let metrics = Arc::new(MetricRegistry::builder()
///     .with_http_metrics()
///     .build());
///
/// let app = Router::new()
///     .route("/", get(handler))
///     .layer(middleware::from_fn(move |req, next| {
///         let handle = MetricsHandle::from(metrics.clone());
///         http_metrics_middleware(handle, req, next)
///     }));
/// ```
pub async fn http_metrics_middleware(
    metrics: MetricsHandle,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = normalize_path(request.uri().path());

    // Track active requests
    metrics.inc_active_requests();

    let start = Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();

    // Decrement active requests
    metrics.dec_active_requests();

    // Record request metrics
    let status = response.status().as_u16();
    metrics.record_http_request(&method, &path, status, duration.as_secs_f64());

    response
}

/// Normalize a request path for metrics labeling.
///
/// This prevents cardinality explosion from dynamic path segments like UUIDs.
///
/// # Normalization Rules
///
/// 1. UUID segments (8-4-4-4-12 hex) → `:id`
/// 2. Numeric segments → `:id`
/// 3. Empty trailing slash → removed
///
/// # Examples
///
/// ```
/// use barbican::observability::metrics::normalize_path;
///
/// assert_eq!(normalize_path("/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000"), "/api/v1/jobs/:id");
/// assert_eq!(normalize_path("/users/12345/profile"), "/users/:id/profile");
/// assert_eq!(normalize_path("/api/health/"), "/api/health");
/// ```
pub fn normalize_path(path: &str) -> String {
    // Remove trailing slash
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return "/".to_string();
    }

    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<&str> = segments
        .iter()
        .map(|seg| {
            if is_uuid(seg) || is_numeric(seg) {
                ":id"
            } else {
                *seg
            }
        })
        .collect();

    normalized.join("/")
}

/// Check if a string looks like a UUID (8-4-4-4-12 hex pattern).
fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }

    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }

    let expected_lengths = [8, 4, 4, 4, 12];
    for (part, expected_len) in parts.iter().zip(expected_lengths.iter()) {
        if part.len() != *expected_len {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }

    true
}

/// Check if a string is purely numeric.
fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// Handler for the `/metrics` endpoint that exports Prometheus format.
///
/// # Example
///
/// ```ignore
/// use axum::{Router, routing::get};
/// use barbican::observability::metrics::{MetricRegistry, metrics_handler};
/// use std::sync::Arc;
///
/// let metrics = Arc::new(MetricRegistry::builder().with_http_metrics().build());
///
/// let app = Router::new()
///     .route("/metrics", get({
///         let m = metrics.clone();
///         move || metrics_handler(m.clone())
///     }));
/// ```
pub async fn metrics_handler(
    metrics: std::sync::Arc<super::registry::MetricRegistry>,
) -> impl IntoResponse {
    use super::prometheus::PrometheusExport;

    let body = metrics.export_prometheus();
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_uuid() {
        assert_eq!(
            normalize_path("/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000"),
            "/api/v1/jobs/:id"
        );
        assert_eq!(
            normalize_path("/jobs/ABCDEF12-3456-7890-ABCD-EF1234567890/status"),
            "/jobs/:id/status"
        );
    }

    #[test]
    fn test_normalize_path_numeric() {
        assert_eq!(normalize_path("/users/12345/profile"), "/users/:id/profile");
        assert_eq!(normalize_path("/items/0/details"), "/items/:id/details");
    }

    #[test]
    fn test_normalize_path_trailing_slash() {
        assert_eq!(normalize_path("/api/health/"), "/api/health");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_no_change() {
        assert_eq!(normalize_path("/api/v1/health"), "/api/v1/health");
        assert_eq!(normalize_path("/api/users"), "/api/users");
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("ABCDEF12-3456-7890-ABCD-EF1234567890"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400-e29b-41d4-a716-44665544000")); // Too short
        assert!(!is_uuid("550e8400-e29b-41d4-a716-4466554400000")); // Too long
    }

    #[test]
    fn test_is_numeric() {
        assert!(is_numeric("12345"));
        assert!(is_numeric("0"));
        assert!(!is_numeric(""));
        assert!(!is_numeric("12a45"));
        assert!(!is_numeric("abc"));
    }
}
