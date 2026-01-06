//! Prometheus text format export
//!
//! Converts MetricRegistry data to Prometheus exposition format.

use super::registry::MetricRegistry;
use std::fmt::Write;

/// Export metrics in Prometheus text format.
///
/// This produces the standard Prometheus exposition format that can be
/// scraped by Prometheus or compatible collectors.
///
/// # Example Output
///
/// ```text
/// # HELP http_requests_total Total number of HTTP requests
/// # TYPE http_requests_total counter
/// http_requests_total{method="GET",path="/api",status="200"} 42
///
/// # HELP http_request_duration_seconds HTTP request duration in seconds
/// # TYPE http_request_duration_seconds histogram
/// http_request_duration_seconds_bucket{method="GET",path="/api",le="0.1"} 10
/// http_request_duration_seconds_bucket{method="GET",path="/api",le="0.5"} 35
/// http_request_duration_seconds_bucket{method="GET",path="/api",le="+Inf"} 42
/// http_request_duration_seconds_sum{method="GET",path="/api"} 12.345
/// http_request_duration_seconds_count{method="GET",path="/api"} 42
/// ```
pub fn export_prometheus(registry: &MetricRegistry) -> String {
    let mut output = String::with_capacity(4096);

    // Export counters
    for (def, counter) in registry.counters() {
        write_counter(&mut output, &def.name, &def.help, counter.get_all());
    }

    // Export gauges
    for (def, gauge) in registry.gauges() {
        write_gauge(&mut output, &def.name, &def.help, gauge.get_all());
    }

    // Export histograms
    for (def, histogram) in registry.histograms() {
        write_histogram(&mut output, &def.name, &def.help, histogram.get_all());
    }

    output
}

fn write_counter(output: &mut String, name: &str, help: &str, values: Vec<(String, u64)>) {
    if values.is_empty() {
        return;
    }

    writeln!(output, "# HELP {name} {help}").unwrap();
    writeln!(output, "# TYPE {name} counter").unwrap();

    for (labels, value) in values {
        if labels.is_empty() {
            writeln!(output, "{name} {value}").unwrap();
        } else {
            writeln!(output, "{name}{{{labels}}} {value}").unwrap();
        }
    }
    writeln!(output).unwrap();
}

fn write_gauge(output: &mut String, name: &str, help: &str, values: Vec<(String, i64)>) {
    if values.is_empty() {
        return;
    }

    writeln!(output, "# HELP {name} {help}").unwrap();
    writeln!(output, "# TYPE {name} gauge").unwrap();

    for (labels, value) in values {
        if labels.is_empty() {
            writeln!(output, "{name} {value}").unwrap();
        } else {
            writeln!(output, "{name}{{{labels}}} {value}").unwrap();
        }
    }
    writeln!(output).unwrap();
}

fn write_histogram(
    output: &mut String,
    name: &str,
    help: &str,
    data: Vec<super::types::HistogramData>,
) {
    if data.is_empty() {
        return;
    }

    writeln!(output, "# HELP {name} {help}").unwrap();
    writeln!(output, "# TYPE {name} histogram").unwrap();

    for hist_data in data {
        let labels = &hist_data.labels;

        // Write bucket lines
        for (i, &bucket) in hist_data.buckets.iter().enumerate() {
            let count = hist_data.counts[i];
            let le = format_le(bucket);

            if labels.is_empty() {
                writeln!(output, "{name}_bucket{{le=\"{le}\"}} {count}").unwrap();
            } else {
                writeln!(output, "{name}_bucket{{{labels},le=\"{le}\"}} {count}").unwrap();
            }
        }

        // Write +Inf bucket (total count)
        if labels.is_empty() {
            writeln!(output, "{name}_bucket{{le=\"+Inf\"}} {}", hist_data.count).unwrap();
        } else {
            writeln!(
                output,
                "{name}_bucket{{{labels},le=\"+Inf\"}} {}",
                hist_data.count
            )
            .unwrap();
        }

        // Write sum
        if labels.is_empty() {
            writeln!(output, "{name}_sum {}", hist_data.sum).unwrap();
        } else {
            writeln!(output, "{name}_sum{{{labels}}} {}", hist_data.sum).unwrap();
        }

        // Write count
        if labels.is_empty() {
            writeln!(output, "{name}_count {}", hist_data.count).unwrap();
        } else {
            writeln!(output, "{name}_count{{{labels}}} {}", hist_data.count).unwrap();
        }
    }
    writeln!(output).unwrap();
}

/// Format a bucket boundary for Prometheus.
fn format_le(value: f64) -> String {
    if value == f64::INFINITY {
        "+Inf".to_string()
    } else if value == value.floor() && value.abs() < 1e10 {
        // Integer-like values
        format!("{:.0}", value)
    } else {
        // Keep reasonable precision
        format!("{}", value)
    }
}

/// Extension trait for MetricRegistry to add prometheus export.
pub trait PrometheusExport {
    /// Export all metrics in Prometheus text format.
    fn export_prometheus(&self) -> String;
}

impl PrometheusExport for MetricRegistry {
    fn export_prometheus(&self) -> String {
        export_prometheus(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::metrics::registry::MetricRegistry;

    #[test]
    fn test_export_counter() {
        let registry = MetricRegistry::builder()
            .app_name("test")
            .counter("requests_total", &["method"], "Total requests")
            .build();

        registry.counter("requests_total").unwrap().inc("method=\"GET\"");
        registry.counter("requests_total").unwrap().inc("method=\"GET\"");
        registry.counter("requests_total").unwrap().inc("method=\"POST\"");

        let output = export_prometheus(&registry);

        assert!(output.contains("# HELP requests_total Total requests"));
        assert!(output.contains("# TYPE requests_total counter"));
        assert!(output.contains("requests_total{method=\"GET\"} 2"));
        assert!(output.contains("requests_total{method=\"POST\"} 1"));
    }

    #[test]
    fn test_export_gauge() {
        let registry = MetricRegistry::builder()
            .app_name("test")
            .gauge("active_connections", &[], "Active connections")
            .build();

        registry.gauge("active_connections").unwrap().set("", 42);

        let output = export_prometheus(&registry);

        assert!(output.contains("# HELP active_connections Active connections"));
        assert!(output.contains("# TYPE active_connections gauge"));
        assert!(output.contains("active_connections 42"));
    }

    #[test]
    fn test_export_histogram() {
        let registry = MetricRegistry::builder()
            .app_name("test")
            .histogram(
                "request_duration",
                &["method"],
                &[0.1, 0.5, 1.0],
                "Request duration",
            )
            .build();

        registry
            .histogram("request_duration")
            .unwrap()
            .observe("method=\"GET\"", 0.05);
        registry
            .histogram("request_duration")
            .unwrap()
            .observe("method=\"GET\"", 0.3);

        let output = export_prometheus(&registry);

        assert!(output.contains("# HELP request_duration Request duration"));
        assert!(output.contains("# TYPE request_duration histogram"));
        assert!(output.contains("request_duration_bucket{method=\"GET\",le=\"0.1\"} 1"));
        assert!(output.contains("request_duration_bucket{method=\"GET\",le=\"0.5\"} 2"));
        assert!(output.contains("request_duration_bucket{method=\"GET\",le=\"1\"} 2"));
        assert!(output.contains("request_duration_bucket{method=\"GET\",le=\"+Inf\"} 2"));
        assert!(output.contains("request_duration_count{method=\"GET\"} 2"));
    }

    #[test]
    fn test_format_le() {
        assert_eq!(format_le(0.1), "0.1");
        assert_eq!(format_le(1.0), "1");
        assert_eq!(format_le(10.0), "10");
        assert_eq!(format_le(0.005), "0.005");
        assert_eq!(format_le(f64::INFINITY), "+Inf");
    }

    #[test]
    fn test_export_trait() {
        use super::PrometheusExport;

        let registry = MetricRegistry::builder()
            .app_name("test")
            .counter("test_counter", &[], "Test")
            .build();

        registry.counter("test_counter").unwrap().inc("");

        let output = registry.export_prometheus();
        assert!(output.contains("test_counter 1"));
    }
}
