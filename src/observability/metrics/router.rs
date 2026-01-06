//! ObservableRouter trait for Axum integration
//!
//! Extension trait that adds observability to any Axum router.

use super::middleware::{http_metrics_middleware, metrics_handler};
use super::registry::{MetricRegistry, MetricsHandle};
use axum::{
    middleware,
    routing::get,
    Router,
};
use std::sync::Arc;

/// Extension trait for adding observability to an Axum Router.
///
/// This trait provides a single method `with_observability` that:
/// 1. Adds HTTP metrics middleware to instrument all requests
/// 2. Adds a `/metrics` endpoint for Prometheus scraping
///
/// # Example
///
/// ```ignore
/// use axum::{Router, routing::get};
/// use barbican::observability::metrics::{MetricRegistry, ObservableRouter};
/// use std::sync::Arc;
///
/// async fn handler() -> &'static str { "Hello" }
///
/// let metrics = Arc::new(MetricRegistry::builder()
///     .app_name("my-app")
///     .with_http_metrics()
///     .counter("custom_events", &["type"], "Custom events")
///     .build());
///
/// let app = Router::new()
///     .route("/", get(handler))
///     .with_observability(metrics);
///
/// // Now the router has:
/// // - Automatic HTTP metrics on all routes
/// // - GET /metrics endpoint for Prometheus
/// ```
pub trait ObservableRouter {
    /// Add observability to this router.
    ///
    /// This adds:
    /// - HTTP metrics middleware (records requests, durations, active count)
    /// - `/metrics` endpoint for Prometheus scraping
    ///
    /// The metrics registry should have been created with `with_http_metrics()`
    /// to include the standard HTTP metrics.
    fn with_observability(self, metrics: Arc<MetricRegistry>) -> Self;

    /// Add observability with a custom metrics path.
    ///
    /// Same as `with_observability` but allows customizing the metrics endpoint path.
    fn with_observability_at(self, metrics: Arc<MetricRegistry>, metrics_path: &str) -> Self;
}

impl<S> ObservableRouter for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn with_observability(self, metrics: Arc<MetricRegistry>) -> Self {
        self.with_observability_at(metrics, "/metrics")
    }

    fn with_observability_at(self, metrics: Arc<MetricRegistry>, metrics_path: &str) -> Self {
        let metrics_for_middleware = metrics.clone();
        let metrics_for_handler = metrics.clone();

        self
            // Add /metrics endpoint
            .route(
                metrics_path,
                get(move || metrics_handler(metrics_for_handler.clone())),
            )
            // Add metrics middleware
            .layer(middleware::from_fn(move |req, next| {
                let handle = MetricsHandle::from(metrics_for_middleware.clone());
                http_metrics_middleware(handle, req, next)
            }))
    }
}

/// Create a metrics registry with standard HTTP metrics and optional custom metrics.
///
/// This is a convenience function for the common case of wanting HTTP metrics
/// plus some application-specific metrics.
///
/// # Example
///
/// ```ignore
/// use barbican::observability::metrics::create_metrics;
///
/// let metrics = create_metrics("my-app", |builder| {
///     builder
///         .counter("jobs_submitted", &["user_id"], "Jobs submitted")
///         .histogram("job_duration", &[], &[1.0, 5.0, 10.0], "Job duration")
/// });
/// ```
pub fn create_metrics<F>(app_name: &str, customize: F) -> Arc<MetricRegistry>
where
    F: FnOnce(super::registry::MetricRegistryBuilder) -> super::registry::MetricRegistryBuilder,
{
    let builder = MetricRegistry::builder()
        .app_name(app_name)
        .with_http_metrics();

    Arc::new(customize(builder).build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_observable_router() {
        let metrics = Arc::new(
            MetricRegistry::builder()
                .app_name("test")
                .with_http_metrics()
                .build(),
        );

        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .with_observability(metrics.clone());

        // Test /health works
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test /metrics exists
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_create_metrics() {
        let metrics = create_metrics("test-app", |b| {
            b.counter("custom_counter", &["label"], "Custom counter")
        });

        assert!(metrics.has_counter("http_requests_total"));
        assert!(metrics.has_counter("custom_counter"));
    }
}
