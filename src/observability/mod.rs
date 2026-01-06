//! Observability Infrastructure (AU-2, AU-3, AU-12)
//!
//! Provides pluggable logging, tracing, and metrics infrastructure.
//! The application code uses standard `tracing` macros and doesn't know
//! which provider is configured.
//!
//! # Modules
//!
//! - **Runtime configuration**: [`ObservabilityConfig`] for initializing logging/metrics at startup
//! - **[`stack`]**: Generate FedRAMP-compliant observability infrastructure (Loki, Prometheus, Grafana)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────┐
//! │   Application Code  │  ← Uses tracing::info!, metrics::counter!, etc.
//! │   (provider-agnostic)│
//! └──────────┬──────────┘
//!            │
//! ┌──────────▼──────────┐
//! │   Observability     │  ← This module
//! │   Abstraction       │
//! └──────────┬──────────┘
//!            │
//! ┌──────────▼──────────┐
//! │     Providers       │  ← Configured at startup
//! │  - Stdout (default) │
//! │  - Loki (logs)      │
//! │  - OTLP (traces)    │
//! │  - Prometheus (metrics)
//! └─────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use barbican::observability::{ObservabilityConfig, init};
//!
//! // From environment variables
//! let config = ObservabilityConfig::from_env();
//! init(config).await?;
//!
//! // Or programmatically
//! let config = ObservabilityConfig::builder()
//!     .log_provider(LogProvider::Loki { endpoint: "http://loki:3100".into() })
//!     .metrics_provider(MetricsProvider::Prometheus { listen: "0.0.0.0:9090".into() })
//!     .build();
//! init(config).await?;
//! ```
//!
//! # Stack Generation
//!
//! Use the [`stack`] submodule to generate complete FedRAMP-compliant observability infrastructure:
//!
//! ```ignore
//! use barbican::observability::stack::{ObservabilityStack, FedRampProfile};
//!
//! let stack = ObservabilityStack::builder()
//!     .app_name("my-app")
//!     .app_port(3443)
//!     .output_dir("./observability")
//!     .fedramp_profile(FedRampProfile::Moderate)
//!     .build()?;
//!
//! stack.generate()?;  // Generates 21 config files
//! ```
//!
//! # Compliance
//!
//! - NIST SP 800-53: AU-2 (Audit Events), AU-3 (Content of Audit Records), AU-12 (Audit Generation)
//! - SOC 2: CC7.2 (System Monitoring)
//! - FedRAMP: 20 controls via stack generator (AU-*, SC-8, SC-13, IA-2, AC-*, IR-*, SI-4)

mod config;
mod providers;
mod events;
pub mod metrics;
pub mod stack;

pub use config::{LogFormat, LogProvider, MetricsProvider, ObservabilityConfig, ObservabilityConfigBuilder};
pub use events::{SecurityEvent, Severity, security_event};

use tracing::info;

/// Initialize the observability stack.
///
/// This must be called once at application startup, before any logging occurs.
/// It configures:
/// - Tracing subscriber with the configured log provider
/// - Metrics exporter if configured
///
/// # Errors
///
/// Returns an error if:
/// - Loki endpoint is invalid
/// - OTLP connection fails
/// - Prometheus server fails to start
pub async fn init(config: ObservabilityConfig) -> Result<(), ObservabilityError> {
    providers::init_tracing(&config)?;

    #[cfg(feature = "metrics-prometheus")]
    if let Some(ref metrics_config) = config.metrics_provider {
        providers::init_metrics(metrics_config)?;
    }

    info!(
        log_provider = ?config.log_provider,
        log_format = ?config.log_format,
        "Observability initialized"
    );

    Ok(())
}

/// Observability initialization errors
#[derive(Debug)]
pub enum ObservabilityError {
    /// Invalid configuration
    Config(String),
    /// Provider initialization failed
    Provider(String),
    /// Metrics server failed
    Metrics(String),
}

impl std::fmt::Display for ObservabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "Observability config error: {}", msg),
            Self::Provider(msg) => write!(f, "Provider error: {}", msg),
            Self::Metrics(msg) => write!(f, "Metrics error: {}", msg),
        }
    }
}

impl std::error::Error for ObservabilityError {}
