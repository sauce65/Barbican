//! MetricRegistry - Application metrics registration and management
//!
//! Provides a builder pattern for applications to define their metrics,
//! and handles Prometheus export.

use super::types::{Gauge, Histogram, LabeledCounter, HTTP_DURATION_BUCKETS};
use std::collections::HashMap;
use std::sync::Arc;

/// Metric definition with metadata.
#[derive(Debug, Clone)]
pub struct MetricDef {
    /// Metric name (e.g., `http_requests_total`)
    pub name: String,
    /// Help text describing the metric
    pub help: String,
    /// Label names for this metric
    pub labels: Vec<String>,
}

/// Central registry for application metrics.
///
/// Applications define their metrics once at startup, then record values
/// throughout the application lifecycle. The registry handles thread-safe
/// storage and Prometheus export.
///
/// # Example
///
/// ```ignore
/// use barbican::observability::metrics::MetricRegistry;
///
/// let metrics = MetricRegistry::builder()
///     .app_name("my-app")
///     .counter("requests_total", &["method", "status"], "Total HTTP requests")
///     .histogram("request_duration_seconds", &["method"], &[0.1, 0.5, 1.0], "Request duration")
///     .with_http_metrics()
///     .build();
///
/// // Record metrics
/// metrics.counter("requests_total").unwrap().inc("method=\"GET\",status=\"200\"");
/// metrics.histogram("request_duration_seconds").unwrap().observe("method=\"GET\"", 0.123);
/// ```
#[derive(Debug)]
pub struct MetricRegistry {
    app_name: String,
    counters: HashMap<String, (MetricDef, LabeledCounter)>,
    histograms: HashMap<String, (MetricDef, Histogram)>,
    gauges: HashMap<String, (MetricDef, Gauge)>,
}

impl MetricRegistry {
    /// Create a new builder.
    pub fn builder() -> MetricRegistryBuilder {
        MetricRegistryBuilder::default()
    }

    /// Get the application name.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Get a counter by name.
    pub fn counter(&self, name: &str) -> Option<&LabeledCounter> {
        self.counters.get(name).map(|(_, c)| c)
    }

    /// Get a histogram by name.
    pub fn histogram(&self, name: &str) -> Option<&Histogram> {
        self.histograms.get(name).map(|(_, h)| h)
    }

    /// Get a gauge by name.
    pub fn gauge(&self, name: &str) -> Option<&Gauge> {
        self.gauges.get(name).map(|(_, g)| g)
    }

    /// Get counter definition and value.
    pub fn counter_with_def(&self, name: &str) -> Option<(&MetricDef, &LabeledCounter)> {
        self.counters.get(name).map(|(def, c)| (def, c))
    }

    /// Get histogram definition and value.
    pub fn histogram_with_def(&self, name: &str) -> Option<(&MetricDef, &Histogram)> {
        self.histograms.get(name).map(|(def, h)| (def, h))
    }

    /// Get gauge definition and value.
    pub fn gauge_with_def(&self, name: &str) -> Option<(&MetricDef, &Gauge)> {
        self.gauges.get(name).map(|(def, g)| (def, g))
    }

    /// Iterate over all counters.
    pub fn counters(&self) -> impl Iterator<Item = (&MetricDef, &LabeledCounter)> {
        self.counters.values().map(|(def, c)| (def, c))
    }

    /// Iterate over all histograms.
    pub fn histograms(&self) -> impl Iterator<Item = (&MetricDef, &Histogram)> {
        self.histograms.values().map(|(def, h)| (def, h))
    }

    /// Iterate over all gauges.
    pub fn gauges(&self) -> impl Iterator<Item = (&MetricDef, &Gauge)> {
        self.gauges.values().map(|(def, g)| (def, g))
    }

    /// Check if a counter exists.
    pub fn has_counter(&self, name: &str) -> bool {
        self.counters.contains_key(name)
    }

    /// Check if a histogram exists.
    pub fn has_histogram(&self, name: &str) -> bool {
        self.histograms.contains_key(name)
    }

    /// Check if a gauge exists.
    pub fn has_gauge(&self, name: &str) -> bool {
        self.gauges.contains_key(name)
    }
}

/// Builder for MetricRegistry.
#[derive(Default)]
pub struct MetricRegistryBuilder {
    app_name: Option<String>,
    counters: Vec<(String, Vec<String>, String)>,
    histograms: Vec<(String, Vec<String>, Vec<f64>, String)>,
    gauges: Vec<(String, Vec<String>, String)>,
    include_http_metrics: bool,
}

impl MetricRegistryBuilder {
    /// Set the application name (used as a prefix and label).
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }

    /// Add a counter metric.
    ///
    /// # Arguments
    ///
    /// * `name` - Metric name (e.g., `requests_total`)
    /// * `labels` - Label names (e.g., `["method", "status"]`)
    /// * `help` - Description of the metric
    pub fn counter(mut self, name: &str, labels: &[&str], help: &str) -> Self {
        self.counters.push((
            name.to_string(),
            labels.iter().map(|s| s.to_string()).collect(),
            help.to_string(),
        ));
        self
    }

    /// Add a histogram metric.
    ///
    /// # Arguments
    ///
    /// * `name` - Metric name (e.g., `request_duration_seconds`)
    /// * `labels` - Label names (e.g., `["method"]`)
    /// * `buckets` - Histogram bucket boundaries
    /// * `help` - Description of the metric
    pub fn histogram(mut self, name: &str, labels: &[&str], buckets: &[f64], help: &str) -> Self {
        self.histograms.push((
            name.to_string(),
            labels.iter().map(|s| s.to_string()).collect(),
            buckets.to_vec(),
            help.to_string(),
        ));
        self
    }

    /// Add a gauge metric.
    ///
    /// # Arguments
    ///
    /// * `name` - Metric name (e.g., `active_connections`)
    /// * `labels` - Label names (e.g., `["pool"]`)
    /// * `help` - Description of the metric
    pub fn gauge(mut self, name: &str, labels: &[&str], help: &str) -> Self {
        self.gauges.push((
            name.to_string(),
            labels.iter().map(|s| s.to_string()).collect(),
            help.to_string(),
        ));
        self
    }

    /// Include standard HTTP metrics.
    ///
    /// Adds:
    /// - `http_requests_total{method, path, status}` - Counter
    /// - `http_request_duration_seconds{method, path}` - Histogram
    /// - `http_requests_active` - Gauge
    pub fn with_http_metrics(mut self) -> Self {
        self.include_http_metrics = true;
        self
    }

    /// Build the MetricRegistry.
    pub fn build(self) -> MetricRegistry {
        let app_name = self.app_name.unwrap_or_else(|| "app".to_string());
        let mut counters = HashMap::new();
        let mut histograms = HashMap::new();
        let mut gauges = HashMap::new();

        // Add user-defined counters
        for (name, labels, help) in self.counters {
            let def = MetricDef {
                name: name.clone(),
                help,
                labels,
            };
            counters.insert(name, (def, LabeledCounter::new()));
        }

        // Add user-defined histograms
        for (name, labels, buckets, help) in self.histograms {
            let def = MetricDef {
                name: name.clone(),
                help,
                labels,
            };
            histograms.insert(name, (def, Histogram::new(&buckets)));
        }

        // Add user-defined gauges
        for (name, labels, help) in self.gauges {
            let def = MetricDef {
                name: name.clone(),
                help,
                labels,
            };
            gauges.insert(name, (def, Gauge::new()));
        }

        // Add standard HTTP metrics if requested
        if self.include_http_metrics {
            // HTTP requests counter
            let http_counter_def = MetricDef {
                name: "http_requests_total".to_string(),
                help: "Total number of HTTP requests".to_string(),
                labels: vec![
                    "method".to_string(),
                    "path".to_string(),
                    "status".to_string(),
                ],
            };
            counters.insert(
                "http_requests_total".to_string(),
                (http_counter_def, LabeledCounter::new()),
            );

            // HTTP request duration histogram
            let http_duration_def = MetricDef {
                name: "http_request_duration_seconds".to_string(),
                help: "HTTP request duration in seconds".to_string(),
                labels: vec!["method".to_string(), "path".to_string()],
            };
            histograms.insert(
                "http_request_duration_seconds".to_string(),
                (http_duration_def, Histogram::new(HTTP_DURATION_BUCKETS)),
            );

            // Active requests gauge
            let http_active_def = MetricDef {
                name: "http_requests_active".to_string(),
                help: "Number of currently active HTTP requests".to_string(),
                labels: vec![],
            };
            gauges.insert(
                "http_requests_active".to_string(),
                (http_active_def, Gauge::new()),
            );
        }

        MetricRegistry {
            app_name,
            counters,
            histograms,
            gauges,
        }
    }
}

/// Handle to a MetricRegistry for use in middleware and handlers.
///
/// This is a thin wrapper around `Arc<MetricRegistry>` that provides
/// convenient methods for recording common metrics.
#[derive(Clone, Debug)]
pub struct MetricsHandle {
    registry: Arc<MetricRegistry>,
}

impl MetricsHandle {
    /// Create a new handle from a registry.
    pub fn new(registry: Arc<MetricRegistry>) -> Self {
        Self { registry }
    }

    /// Get the underlying registry.
    pub fn registry(&self) -> &MetricRegistry {
        &self.registry
    }

    /// Record an HTTP request.
    ///
    /// This is a convenience method that updates:
    /// - `http_requests_total` counter
    /// - `http_request_duration_seconds` histogram
    pub fn record_http_request(&self, method: &str, path: &str, status: u16, duration_secs: f64) {
        let counter_labels = format!("method=\"{method}\",path=\"{path}\",status=\"{status}\"");
        let hist_labels = format!("method=\"{method}\",path=\"{path}\"");

        if let Some(counter) = self.registry.counter("http_requests_total") {
            counter.inc(&counter_labels);
        }
        if let Some(hist) = self.registry.histogram("http_request_duration_seconds") {
            hist.observe(&hist_labels, duration_secs);
        }
    }

    /// Increment active HTTP requests.
    pub fn inc_active_requests(&self) {
        if let Some(gauge) = self.registry.gauge("http_requests_active") {
            gauge.inc("");
        }
    }

    /// Decrement active HTTP requests.
    pub fn dec_active_requests(&self) {
        if let Some(gauge) = self.registry.gauge("http_requests_active") {
            gauge.dec("");
        }
    }

    /// Get a counter by name for custom recording.
    pub fn counter(&self, name: &str) -> Option<&LabeledCounter> {
        self.registry.counter(name)
    }

    /// Get a histogram by name for custom recording.
    pub fn histogram(&self, name: &str) -> Option<&Histogram> {
        self.registry.histogram(name)
    }

    /// Get a gauge by name for custom recording.
    pub fn gauge(&self, name: &str) -> Option<&Gauge> {
        self.registry.gauge(name)
    }
}

impl From<Arc<MetricRegistry>> for MetricsHandle {
    fn from(registry: Arc<MetricRegistry>) -> Self {
        Self::new(registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let registry = MetricRegistry::builder()
            .app_name("test-app")
            .counter("requests_total", &["method"], "Total requests")
            .histogram(
                "duration_seconds",
                &["method"],
                &[0.1, 0.5, 1.0],
                "Duration",
            )
            .gauge("active", &[], "Active count")
            .build();

        assert_eq!(registry.app_name(), "test-app");
        assert!(registry.has_counter("requests_total"));
        assert!(registry.has_histogram("duration_seconds"));
        assert!(registry.has_gauge("active"));
    }

    #[test]
    fn test_http_metrics() {
        let registry = MetricRegistry::builder()
            .app_name("test")
            .with_http_metrics()
            .build();

        assert!(registry.has_counter("http_requests_total"));
        assert!(registry.has_histogram("http_request_duration_seconds"));
        assert!(registry.has_gauge("http_requests_active"));
    }

    #[test]
    fn test_metrics_handle() {
        let registry = Arc::new(
            MetricRegistry::builder()
                .app_name("test")
                .with_http_metrics()
                .build(),
        );

        let handle = MetricsHandle::new(registry);

        handle.record_http_request("GET", "/api/health", 200, 0.05);

        let counter = handle.counter("http_requests_total").unwrap();
        assert_eq!(
            counter.get("method=\"GET\",path=\"/api/health\",status=\"200\""),
            1
        );
    }

    #[test]
    fn test_active_requests() {
        let registry = Arc::new(
            MetricRegistry::builder()
                .app_name("test")
                .with_http_metrics()
                .build(),
        );

        let handle = MetricsHandle::new(registry);

        handle.inc_active_requests();
        handle.inc_active_requests();
        assert_eq!(handle.gauge("http_requests_active").unwrap().get(""), 2);

        handle.dec_active_requests();
        assert_eq!(handle.gauge("http_requests_active").unwrap().get(""), 1);
    }
}
