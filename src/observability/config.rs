//! Observability Configuration
//!
//! Defines configuration types for logging, tracing, and metrics providers.

use std::env;

/// Log output format
#[derive(Debug, Clone, Default)]
pub enum LogFormat {
    /// Human-readable format for development
    #[default]
    Pretty,
    /// JSON format for production/log aggregation
    Json,
    /// Compact single-line format
    Compact,
}

/// Log provider configuration
#[derive(Debug, Clone)]
pub enum LogProvider {
    /// Output to stdout (default)
    Stdout,

    /// Send logs to Loki
    #[cfg(feature = "observability-loki")]
    Loki {
        /// Loki push endpoint (e.g., "http://loki:3100")
        endpoint: String,
        /// Additional labels to attach to all logs
        labels: Vec<(String, String)>,
    },

    /// Send traces via OpenTelemetry Protocol
    #[cfg(feature = "observability-otlp")]
    Otlp {
        /// OTLP endpoint (e.g., "http://jaeger:4317")
        endpoint: String,
        /// Service name for traces
        service_name: String,
    },
}

impl Default for LogProvider {
    fn default() -> Self {
        Self::Stdout
    }
}

/// Metrics provider configuration
#[derive(Debug, Clone)]
pub enum MetricsProvider {
    /// Expose Prometheus metrics endpoint
    #[cfg(feature = "metrics-prometheus")]
    Prometheus {
        /// Listen address for metrics endpoint (e.g., "0.0.0.0:9090")
        listen: String,
    },
}

/// Complete observability configuration
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Log/trace provider
    pub log_provider: LogProvider,
    /// Log output format
    pub log_format: LogFormat,
    /// Log level filter (e.g., "info", "debug", "myapp=debug,tower_http=info")
    pub log_filter: String,
    /// Metrics provider (optional)
    pub metrics_provider: Option<MetricsProvider>,
    /// Enable request/response tracing
    pub enable_request_tracing: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_provider: LogProvider::default(),
            log_format: LogFormat::default(),
            log_filter: "info".to_string(),
            metrics_provider: None,
            enable_request_tracing: true,
        }
    }
}

impl ObservabilityConfig {
    /// Create configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `LOG_PROVIDER`: "stdout", "loki", or "otlp" (default: "stdout")
    /// - `LOG_FORMAT`: "pretty", "json", or "compact" (default: "pretty")
    /// - `RUST_LOG`: Log filter directive (default: "info")
    /// - `TRACING_ENABLED`: Enable request tracing (default: "true")
    ///
    /// For Loki (`LOG_PROVIDER=loki`):
    /// - `LOKI_ENDPOINT`: Loki push URL (required)
    /// - `LOKI_LABELS`: Comma-separated key=value pairs (optional)
    ///
    /// For OTLP (`LOG_PROVIDER=otlp`):
    /// - `OTLP_ENDPOINT`: OTLP collector URL (required)
    /// - `OTEL_SERVICE_NAME`: Service name (default: "app")
    ///
    /// For Prometheus metrics (`METRICS_PROVIDER=prometheus`):
    /// - `PROMETHEUS_LISTEN`: Listen address (default: "0.0.0.0:9090")
    pub fn from_env() -> Self {
        let log_provider = match env::var("LOG_PROVIDER").as_deref() {
            Ok("loki") => {
                #[cfg(feature = "observability-loki")]
                {
                    let endpoint = env::var("LOKI_ENDPOINT")
                        .unwrap_or_else(|_| "http://localhost:3100".to_string());
                    let labels = env::var("LOKI_LABELS")
                        .map(|s| parse_labels(&s))
                        .unwrap_or_default();
                    LogProvider::Loki { endpoint, labels }
                }
                #[cfg(not(feature = "observability-loki"))]
                {
                    eprintln!("Warning: Loki requested but observability-loki feature not enabled, falling back to stdout");
                    LogProvider::Stdout
                }
            }
            Ok("otlp") => {
                #[cfg(feature = "observability-otlp")]
                {
                    let endpoint = env::var("OTLP_ENDPOINT")
                        .unwrap_or_else(|_| "http://localhost:4317".to_string());
                    let service_name = env::var("OTEL_SERVICE_NAME")
                        .unwrap_or_else(|_| "app".to_string());
                    LogProvider::Otlp { endpoint, service_name }
                }
                #[cfg(not(feature = "observability-otlp"))]
                {
                    eprintln!("Warning: OTLP requested but observability-otlp feature not enabled, falling back to stdout");
                    LogProvider::Stdout
                }
            }
            _ => LogProvider::Stdout,
        };

        let log_format = match env::var("LOG_FORMAT").as_deref() {
            Ok("json") => LogFormat::Json,
            Ok("compact") => LogFormat::Compact,
            _ => LogFormat::Pretty,
        };

        let log_filter = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        let enable_request_tracing = env::var("TRACING_ENABLED")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        let metrics_provider = match env::var("METRICS_PROVIDER").as_deref() {
            Ok("prometheus") => {
                #[cfg(feature = "metrics-prometheus")]
                {
                    let listen = env::var("PROMETHEUS_LISTEN")
                        .unwrap_or_else(|_| "0.0.0.0:9090".to_string());
                    Some(MetricsProvider::Prometheus { listen })
                }
                #[cfg(not(feature = "metrics-prometheus"))]
                {
                    eprintln!("Warning: Prometheus requested but metrics-prometheus feature not enabled");
                    None
                }
            }
            _ => None,
        };

        Self {
            log_provider,
            log_format,
            log_filter,
            metrics_provider,
            enable_request_tracing,
        }
    }

    /// Create a new configuration builder
    pub fn builder() -> ObservabilityConfigBuilder {
        ObservabilityConfigBuilder::default()
    }
}

/// Builder for ObservabilityConfig
#[derive(Default)]
pub struct ObservabilityConfigBuilder {
    config: ObservabilityConfig,
}

impl ObservabilityConfigBuilder {
    /// Set the log provider
    pub fn log_provider(mut self, provider: LogProvider) -> Self {
        self.config.log_provider = provider;
        self
    }

    /// Set the log format
    pub fn log_format(mut self, format: LogFormat) -> Self {
        self.config.log_format = format;
        self
    }

    /// Set the log filter
    pub fn log_filter(mut self, filter: impl Into<String>) -> Self {
        self.config.log_filter = filter.into();
        self
    }

    /// Set the metrics provider
    pub fn metrics_provider(mut self, provider: MetricsProvider) -> Self {
        self.config.metrics_provider = Some(provider);
        self
    }

    /// Enable or disable request tracing
    pub fn enable_request_tracing(mut self, enable: bool) -> Self {
        self.config.enable_request_tracing = enable;
        self
    }

    /// Build the configuration
    pub fn build(self) -> ObservabilityConfig {
        self.config
    }
}

/// Parse comma-separated key=value labels
fn parse_labels(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(k), Some(v)) => Some((k.trim().to_string(), v.trim().to_string())),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_labels() {
        let labels = parse_labels("app=myapp,env=prod");
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], ("app".to_string(), "myapp".to_string()));
        assert_eq!(labels[1], ("env".to_string(), "prod".to_string()));
    }

    #[test]
    fn test_parse_labels_empty() {
        let labels = parse_labels("");
        assert!(labels.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = ObservabilityConfig::default();
        assert!(matches!(config.log_provider, LogProvider::Stdout));
        assert!(matches!(config.log_format, LogFormat::Pretty));
        assert_eq!(config.log_filter, "info");
        assert!(config.enable_request_tracing);
        assert!(config.metrics_provider.is_none());
    }

    #[test]
    fn test_builder() {
        let config = ObservabilityConfig::builder()
            .log_format(LogFormat::Json)
            .log_filter("debug")
            .enable_request_tracing(false)
            .build();

        assert!(matches!(config.log_format, LogFormat::Json));
        assert_eq!(config.log_filter, "debug");
        assert!(!config.enable_request_tracing);
    }
}
