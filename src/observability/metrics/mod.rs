//! Application Metrics Infrastructure
//!
//! Provides a complete metrics solution for Axum applications:
//! - Define custom counters, histograms, and gauges
//! - Automatic HTTP request instrumentation
//! - Prometheus text format export
//! - `/metrics` endpoint for scraping
//!
//! # Quick Start
//!
//! ```ignore
//! use axum::{Router, routing::get};
//! use barbican::observability::metrics::{MetricRegistry, ObservableRouter};
//! use std::sync::Arc;
//!
//! // Define your metrics
//! let metrics = Arc::new(MetricRegistry::builder()
//!     .app_name("my-app")
//!     .with_http_metrics()  // Standard HTTP metrics
//!     .counter("jobs_total", &["status"], "Total jobs processed")
//!     .histogram("job_duration_seconds", &["type"], &[1.0, 5.0, 10.0], "Job duration")
//!     .build());
//!
//! // Build your router with observability
//! let app = Router::new()
//!     .route("/", get(handler))
//!     .with_observability(metrics.clone());
//!
//! // Now you have:
//! // - Automatic HTTP metrics on all routes
//! // - GET /metrics endpoint for Prometheus
//! // - Access to custom metrics via the registry
//! ```
//!
//! # Recording Custom Metrics
//!
//! ```ignore
//! // In your handlers or services:
//! metrics.counter("jobs_total").unwrap().inc("status=\"completed\"");
//! metrics.histogram("job_duration_seconds").unwrap().observe("type=\"csv\"", 2.5);
//! ```
//!
//! # Standard HTTP Metrics
//!
//! When you call `with_http_metrics()`, the following are automatically tracked:
//!
//! | Metric | Type | Labels | Description |
//! |--------|------|--------|-------------|
//! | `http_requests_total` | Counter | method, path, status | Total HTTP requests |
//! | `http_request_duration_seconds` | Histogram | method, path | Request duration |
//! | `http_requests_active` | Gauge | - | Currently processing requests |
//!
//! # Path Normalization
//!
//! Dynamic path segments (UUIDs, numeric IDs) are normalized to `:id` to prevent
//! cardinality explosion:
//! - `/api/jobs/550e8400-e29b-41d4-a716-446655440000` → `/api/jobs/:id`
//! - `/users/12345/profile` → `/users/:id/profile`

mod middleware;
mod prometheus;
mod registry;
mod router;
mod types;

// Core types
pub use registry::{MetricDef, MetricRegistry, MetricRegistryBuilder, MetricsHandle};
pub use types::{Gauge, Histogram, HistogramData, LabeledCounter};

// Bucket constants
pub use types::{DB_DURATION_BUCKETS, HTTP_DURATION_BUCKETS, JOB_DURATION_BUCKETS};

// Prometheus export
pub use prometheus::{export_prometheus, PrometheusExport};

// Middleware and router
pub use middleware::{http_metrics_middleware, metrics_handler, normalize_path};
pub use router::{create_metrics, ObservableRouter};
