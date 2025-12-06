//! Provider Implementations
//!
//! Initializes tracing and metrics based on configuration.

use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

use super::{ObservabilityConfig, ObservabilityError, LogFormat, LogProvider};

#[cfg(feature = "metrics-prometheus")]
use super::config::MetricsProvider;

/// Initialize the tracing subscriber based on configuration.
pub fn init_tracing(config: &ObservabilityConfig) -> Result<(), ObservabilityError> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_filter))
        .map_err(|e| ObservabilityError::Config(format!("Invalid log filter: {}", e)))?;

    match &config.log_provider {
        LogProvider::Stdout => init_stdout_tracing(config, filter),

        #[cfg(feature = "observability-loki")]
        LogProvider::Loki { endpoint, labels } => {
            init_loki_tracing(config, filter, endpoint, labels)
        }

        #[cfg(feature = "observability-otlp")]
        LogProvider::Otlp { endpoint, service_name } => {
            init_otlp_tracing(config, filter, endpoint, service_name)
        }
    }
}

/// Initialize stdout tracing (default provider)
fn init_stdout_tracing(
    config: &ObservabilityConfig,
    filter: EnvFilter,
) -> Result<(), ObservabilityError> {
    let subscriber = tracing_subscriber::registry().with(filter);

    match config.log_format {
        LogFormat::Pretty => {
            subscriber
                .with(
                    fmt::layer()
                        .pretty()
                        .with_target(true)
                        .with_thread_ids(false)
                        .with_file(true)
                        .with_line_number(true),
                )
                .try_init()
                .map_err(|e| ObservabilityError::Provider(format!("Failed to init tracing: {}", e)))?;
        }
        LogFormat::Json => {
            subscriber
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_file(true)
                        .with_line_number(true),
                )
                .try_init()
                .map_err(|e| ObservabilityError::Provider(format!("Failed to init tracing: {}", e)))?;
        }
        LogFormat::Compact => {
            subscriber
                .with(
                    fmt::layer()
                        .compact()
                        .with_target(true),
                )
                .try_init()
                .map_err(|e| ObservabilityError::Provider(format!("Failed to init tracing: {}", e)))?;
        }
    }

    Ok(())
}

/// Initialize Loki tracing provider
#[cfg(feature = "observability-loki")]
fn init_loki_tracing(
    config: &ObservabilityConfig,
    filter: EnvFilter,
    endpoint: &str,
    labels: &[(String, String)],
) -> Result<(), ObservabilityError> {
    use url::Url;

    let url = Url::parse(endpoint)
        .map_err(|e| ObservabilityError::Config(format!("Invalid Loki endpoint: {}", e)))?;

    // Build Loki layer with labels
    let mut builder = tracing_loki::builder()
        .label("service", "barbican")
        .map_err(|e| ObservabilityError::Provider(format!("Failed to set Loki label: {}", e)))?;

    for (key, value) in labels {
        builder = builder
            .label(key, value)
            .map_err(|e| ObservabilityError::Provider(format!("Failed to set Loki label: {}", e)))?;
    }

    let (loki_layer, task) = builder
        .build_url(url)
        .map_err(|e| ObservabilityError::Provider(format!("Failed to build Loki layer: {}", e)))?;

    // Spawn the Loki background task
    tokio::spawn(task);

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(loki_layer);

    // Also add stdout layer based on format for local visibility
    match config.log_format {
        LogFormat::Pretty => {
            subscriber
                .with(fmt::layer().pretty())
                .try_init()
                .map_err(|e| ObservabilityError::Provider(format!("Failed to init tracing: {}", e)))?;
        }
        LogFormat::Json => {
            subscriber
                .with(fmt::layer().json())
                .try_init()
                .map_err(|e| ObservabilityError::Provider(format!("Failed to init tracing: {}", e)))?;
        }
        LogFormat::Compact => {
            subscriber
                .with(fmt::layer().compact())
                .try_init()
                .map_err(|e| ObservabilityError::Provider(format!("Failed to init tracing: {}", e)))?;
        }
    }

    Ok(())
}

/// Initialize OpenTelemetry/OTLP tracing provider
#[cfg(feature = "observability-otlp")]
fn init_otlp_tracing(
    _config: &ObservabilityConfig,
    filter: EnvFilter,
    endpoint: &str,
    service_name: &str,
) -> Result<(), ObservabilityError> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{runtime, Resource};
    use opentelemetry::KeyValue;

    // Create OTLP exporter
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    // Create tracer provider
    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                .with_resource(Resource::new(vec![
                    KeyValue::new("service.name", service_name.to_string()),
                ])),
        )
        .install_batch(runtime::Tokio)
        .map_err(|e| ObservabilityError::Provider(format!("Failed to install OTLP tracer: {}", e)))?;

    let tracer = tracer_provider.tracer(service_name.to_string());

    // Create OpenTelemetry tracing layer
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(filter)
        .with(otel_layer)
        .with(fmt::layer().compact()) // Also log to stdout
        .try_init()
        .map_err(|e| ObservabilityError::Provider(format!("Failed to init tracing: {}", e)))?;

    Ok(())
}

/// Initialize metrics exporter based on configuration.
#[cfg(feature = "metrics-prometheus")]
pub fn init_metrics(config: &MetricsProvider) -> Result<(), ObservabilityError> {
    match config {
        MetricsProvider::Prometheus { listen } => {
            init_prometheus_metrics(listen)
        }
    }
}

/// Initialize Prometheus metrics exporter
#[cfg(feature = "metrics-prometheus")]
fn init_prometheus_metrics(listen: &str) -> Result<(), ObservabilityError> {
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::net::SocketAddr;

    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| ObservabilityError::Config(format!("Invalid Prometheus listen address: {}", e)))?;

    // Install the Prometheus recorder
    let builder = PrometheusBuilder::new();

    builder
        .with_http_listener(addr)
        .install()
        .map_err(|e| ObservabilityError::Metrics(format!("Failed to start Prometheus exporter: {}", e)))?;

    tracing::info!(listen = %addr, "Prometheus metrics server started");

    Ok(())
}

/// Placeholder for when metrics-prometheus feature is not enabled
#[cfg(not(feature = "metrics-prometheus"))]
pub fn init_metrics(_config: &super::config::MetricsProvider) -> Result<(), ObservabilityError> {
    Ok(())
}
