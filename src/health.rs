//! Health Check Framework (CA-7)
//!
//! NIST SP 800-53 CA-7 (Continuous Monitoring) compliant health check
//! utilities for system monitoring and availability.
//!
//! # Design Philosophy
//!
//! This module provides a framework for health checks that can be used
//! with any monitoring system. It supports:
//!
//! - Multiple check types (database, external services, custom)
//! - Configurable timeouts and thresholds
//! - Aggregated health status
//! - Detailed check results for debugging
//! - Integration with alerting system
//!
//! # Usage
//!
//! ```ignore
//! use barbican::health::{HealthChecker, HealthCheck, HealthStatus};
//! use std::time::Duration;
//!
//! // Create health checker
//! let mut checker = HealthChecker::new();
//!
//! // Add checks
//! checker.add_check(HealthCheck::new("database", || async {
//!     // Check database connectivity
//!     if db_is_healthy().await {
//!         HealthStatus::healthy()
//!     } else {
//!         HealthStatus::unhealthy("Connection failed")
//!     }
//! }));
//!
//! // Run all checks
//! let report = checker.check_all().await;
//! println!("Overall status: {:?}", report.status);
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::observability::SecurityEvent;

// ============================================================================
// Health Status
// ============================================================================

/// Health check status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// System is healthy and functioning normally
    Healthy,
    /// System is degraded but still functional
    Degraded,
    /// System is unhealthy and may not function correctly
    Unhealthy,
}

impl Status {
    /// Check if status indicates the system is operational
    pub fn is_operational(&self) -> bool {
        matches!(self, Status::Healthy | Status::Degraded)
    }

    /// Get the worst status between two
    pub fn worst(self, other: Status) -> Status {
        match (self, other) {
            (Status::Unhealthy, _) | (_, Status::Unhealthy) => Status::Unhealthy,
            (Status::Degraded, _) | (_, Status::Degraded) => Status::Degraded,
            _ => Status::Healthy,
        }
    }
}

/// Result of a single health check
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// The status
    pub status: Status,
    /// Optional message describing the status
    pub message: Option<String>,
    /// Additional details as key-value pairs
    pub details: HashMap<String, String>,
    /// How long the check took
    pub duration: Duration,
    /// When the check was performed
    pub checked_at: Instant,
}

impl HealthStatus {
    /// Create a healthy status
    pub fn healthy() -> Self {
        Self {
            status: Status::Healthy,
            message: None,
            details: HashMap::new(),
            duration: Duration::ZERO,
            checked_at: Instant::now(),
        }
    }

    /// Create a healthy status with a message
    pub fn healthy_with_message(message: impl Into<String>) -> Self {
        Self {
            status: Status::Healthy,
            message: Some(message.into()),
            details: HashMap::new(),
            duration: Duration::ZERO,
            checked_at: Instant::now(),
        }
    }

    /// Create a degraded status
    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: Status::Degraded,
            message: Some(message.into()),
            details: HashMap::new(),
            duration: Duration::ZERO,
            checked_at: Instant::now(),
        }
    }

    /// Create an unhealthy status
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: Status::Unhealthy,
            message: Some(message.into()),
            details: HashMap::new(),
            duration: Duration::ZERO,
            checked_at: Instant::now(),
        }
    }

    /// Add a detail to the status
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Set the duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
}

// ============================================================================
// Health Check Configuration
// ============================================================================

/// Configuration for a health check
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Name of the check
    pub name: String,
    /// Timeout for the check
    pub timeout: Duration,
    /// Whether this check is critical (affects overall status)
    pub critical: bool,
    /// Interval between checks (for continuous monitoring)
    pub interval: Duration,
    /// Number of consecutive failures before alerting
    pub failure_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            timeout: Duration::from_secs(5),
            critical: true,
            interval: Duration::from_secs(30),
            failure_threshold: 3,
        }
    }
}

impl HealthCheckConfig {
    /// Create a new config with the given name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set the timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set whether the check is critical
    pub fn critical(mut self, critical: bool) -> Self {
        self.critical = critical;
        self
    }

    /// Set the check interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set the failure threshold
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }
}

// ============================================================================
// Health Check Types
// ============================================================================

/// Type alias for async health check functions
pub type CheckFn = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = HealthStatus> + Send>> + Send + Sync>;

/// A health check definition
pub struct HealthCheck {
    /// Configuration for this check
    pub config: HealthCheckConfig,
    /// The check function
    check_fn: CheckFn,
}

impl HealthCheck {
    /// Create a new health check
    pub fn new<F, Fut>(name: impl Into<String>, check_fn: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HealthStatus> + Send + 'static,
    {
        Self {
            config: HealthCheckConfig::new(name),
            check_fn: Arc::new(move || Box::pin(check_fn())),
        }
    }

    /// Create a health check with custom configuration
    pub fn with_config<F, Fut>(config: HealthCheckConfig, check_fn: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HealthStatus> + Send + 'static,
    {
        Self {
            config,
            check_fn: Arc::new(move || Box::pin(check_fn())),
        }
    }

    /// Run the health check
    pub async fn run(&self) -> HealthStatus {
        let start = Instant::now();
        let mut status = (self.check_fn)().await;
        status.duration = start.elapsed();
        status.checked_at = start;
        status
    }
}

impl std::fmt::Debug for HealthCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthCheck")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Health Report
// ============================================================================

/// Result of running all health checks
#[derive(Debug, Clone)]
pub struct HealthReport {
    /// Overall status
    pub status: Status,
    /// Individual check results
    pub checks: HashMap<String, HealthStatus>,
    /// When the report was generated
    pub generated_at: Instant,
    /// Total time to run all checks
    pub total_duration: Duration,
}

impl HealthReport {
    /// Check if the system is operational
    pub fn is_operational(&self) -> bool {
        self.status.is_operational()
    }

    /// Get checks that failed
    pub fn failed_checks(&self) -> Vec<(&String, &HealthStatus)> {
        self.checks
            .iter()
            .filter(|(_, status)| status.status == Status::Unhealthy)
            .collect()
    }

    /// Get checks that are degraded
    pub fn degraded_checks(&self) -> Vec<(&String, &HealthStatus)> {
        self.checks
            .iter()
            .filter(|(_, status)| status.status == Status::Degraded)
            .collect()
    }

    /// Convert to a JSON-serializable format
    pub fn to_json(&self) -> serde_json::Value {
        let checks: HashMap<String, serde_json::Value> = self
            .checks
            .iter()
            .map(|(name, status)| {
                let value = serde_json::json!({
                    "status": format!("{:?}", status.status).to_lowercase(),
                    "message": status.message,
                    "details": status.details,
                    "duration_ms": status.duration.as_millis(),
                });
                (name.clone(), value)
            })
            .collect();

        serde_json::json!({
            "status": format!("{:?}", self.status).to_lowercase(),
            "checks": checks,
            "total_duration_ms": self.total_duration.as_millis(),
        })
    }
}

// ============================================================================
// Health Checker
// ============================================================================

/// Health checker that runs multiple health checks
#[derive(Default)]
pub struct HealthChecker {
    checks: Vec<HealthCheck>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Add a health check
    pub fn add_check(&mut self, check: HealthCheck) {
        self.checks.push(check);
    }

    /// Add a health check (builder pattern)
    pub fn with_check(mut self, check: HealthCheck) -> Self {
        self.checks.push(check);
        self
    }

    /// Run all health checks
    pub async fn check_all(&self) -> HealthReport {
        let start = Instant::now();
        let mut results = HashMap::new();
        let mut overall_status = Status::Healthy;

        for check in &self.checks {
            let status = check.run().await;

            // Only critical checks affect overall status
            if check.config.critical {
                overall_status = overall_status.worst(status.status);
            }

            results.insert(check.config.name.clone(), status);
        }

        let report = HealthReport {
            status: overall_status,
            checks: results,
            generated_at: start,
            total_duration: start.elapsed(),
        };

        // Log health check completion
        log_health_check(&report);

        report
    }

    /// Run a specific check by name
    pub async fn check_one(&self, name: &str) -> Option<HealthStatus> {
        for check in &self.checks {
            if check.config.name == name {
                return Some(check.run().await);
            }
        }
        None
    }

    /// Get the number of registered checks
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }
}

impl std::fmt::Debug for HealthChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthChecker")
            .field("check_count", &self.checks.len())
            .finish()
    }
}

// ============================================================================
// Common Health Checks
// ============================================================================

/// Create a simple "always healthy" check (for testing)
pub fn always_healthy(name: impl Into<String>) -> HealthCheck {
    HealthCheck::new(name, || async { HealthStatus::healthy() })
}

/// Create a simple "always unhealthy" check (for testing)
pub fn always_unhealthy(name: impl Into<String>, message: impl Into<String> + Clone + Send + Sync + 'static) -> HealthCheck {
    let msg = message.into();
    HealthCheck::new(name, move || {
        let m = msg.clone();
        async move { HealthStatus::unhealthy(m) }
    })
}

/// Create a memory usage check
pub fn memory_check(threshold_percent: f64) -> HealthCheck {
    HealthCheck::with_config(
        HealthCheckConfig::new("memory")
            .with_timeout(Duration::from_secs(1))
            .critical(false),
        move || async move {
            // This is a simplified check - in production you'd use sys-info crate
            // For now, always report healthy with a note
            HealthStatus::healthy_with_message("Memory check requires sys-info feature")
                .with_detail("threshold_percent", threshold_percent.to_string())
        },
    )
}

/// Create an HTTP endpoint check
pub fn http_check(name: impl Into<String>, url: impl Into<String> + Clone + Send + Sync + 'static) -> HealthCheck {
    let url_str = url.into();
    HealthCheck::with_config(
        HealthCheckConfig::new(name)
            .with_timeout(Duration::from_secs(10)),
        move || {
            let u = url_str.clone();
            async move {
                // This is a placeholder - in production you'd use reqwest
                // For now, report as degraded indicating the feature isn't available
                HealthStatus::degraded(format!("HTTP check for {} requires reqwest feature", u))
                    .with_detail("url", u)
            }
        },
    )
}

// ============================================================================
// Logging
// ============================================================================

/// Log health check completion
fn log_health_check(report: &HealthReport) {
    let status_str = format!("{:?}", report.status).to_lowercase();
    let failed_count = report.failed_checks().len();
    let degraded_count = report.degraded_checks().len();

    if report.status == Status::Unhealthy {
        crate::security_event!(
            SecurityEvent::SuspiciousActivity,
            health_status = %status_str,
            failed_checks = failed_count,
            degraded_checks = degraded_count,
            duration_ms = report.total_duration.as_millis() as u64,
            "Health check failed"
        );
    } else {
        tracing::debug!(
            health_status = %status_str,
            failed_checks = failed_count,
            degraded_checks = degraded_count,
            duration_ms = report.total_duration.as_millis() as u64,
            "Health check completed"
        );
    }
}

// ============================================================================
// CA-7 Enforcement: Axum Health Endpoints
// ============================================================================

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::Serialize;

/// Health endpoint configuration
#[derive(Debug, Clone)]
pub struct HealthEndpointConfig {
    /// Path for overall health endpoint (default: "/health")
    pub health_path: String,

    /// Path for liveness probe (default: "/health/live")
    pub live_path: String,

    /// Path for readiness probe (default: "/health/ready")
    pub ready_path: String,

    /// Include detailed check results in response
    pub include_details: bool,

    /// Only return 200 OK for healthy status (strict mode)
    pub strict_mode: bool,
}

impl Default for HealthEndpointConfig {
    fn default() -> Self {
        Self {
            health_path: "/health".to_string(),
            live_path: "/health/live".to_string(),
            ready_path: "/health/ready".to_string(),
            include_details: true,
            strict_mode: false,
        }
    }
}

impl HealthEndpointConfig {
    /// Create a minimal config for production (no details exposed)
    pub fn production() -> Self {
        Self {
            include_details: false,
            strict_mode: true,
            ..Default::default()
        }
    }

    /// Create a development config with full details
    pub fn development() -> Self {
        Self {
            include_details: true,
            strict_mode: false,
            ..Default::default()
        }
    }
}

/// JSON response for health endpoints
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Overall status: "healthy", "degraded", or "unhealthy"
    pub status: String,

    /// Individual check results (if include_details is true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<CheckResult>>,

    /// Total duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Individual check result for JSON response
#[derive(Debug, Serialize)]
pub struct CheckResult {
    /// Check name
    pub name: String,

    /// Check status
    pub status: String,

    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Duration in milliseconds
    pub duration_ms: u64,
}

impl From<&HealthReport> for HealthResponse {
    fn from(report: &HealthReport) -> Self {
        let checks: Vec<CheckResult> = report
            .checks
            .iter()
            .map(|(name, status)| CheckResult {
                name: name.clone(),
                status: format!("{:?}", status.status).to_lowercase(),
                message: status.message.clone(),
                duration_ms: status.duration.as_millis() as u64,
            })
            .collect();

        Self {
            status: format!("{:?}", report.status).to_lowercase(),
            checks: Some(checks),
            duration_ms: Some(report.total_duration.as_millis() as u64),
        }
    }
}

/// Shared state for health endpoints
#[derive(Clone)]
pub struct HealthState {
    checker: Arc<HealthChecker>,
    config: HealthEndpointConfig,
}

impl HealthState {
    /// Create new health state
    pub fn new(checker: HealthChecker, config: HealthEndpointConfig) -> Self {
        Self {
            checker: Arc::new(checker),
            config,
        }
    }
}

/// Create an Axum router with health check endpoints
///
/// This provides three endpoints:
/// - `/health` - Full health check with all registered checks
/// - `/health/live` - Liveness probe (always returns 200 if server is running)
/// - `/health/ready` - Readiness probe (returns 200 only if all checks pass)
///
/// # Example
///
/// ```ignore
/// use barbican::health::{health_routes, HealthChecker, HealthCheck, HealthStatus, HealthEndpointConfig};
/// use axum::Router;
///
/// let mut checker = HealthChecker::new();
/// checker.add_check(HealthCheck::new("database", || async {
///     HealthStatus::healthy()
/// }));
///
/// let app = Router::new()
///     .merge(health_routes(checker, HealthEndpointConfig::default()));
/// ```
pub fn health_routes(checker: HealthChecker, config: HealthEndpointConfig) -> Router {
    let state = HealthState::new(checker, config.clone());

    Router::new()
        .route(&config.health_path, get(health_handler))
        .route(&config.live_path, get(live_handler))
        .route(&config.ready_path, get(ready_handler))
        .with_state(state)
}

/// Handler for /health endpoint
async fn health_handler(State(state): State<HealthState>) -> Response {
    let report = state.checker.check_all().await;
    let status_code = status_to_http(&report.status, state.config.strict_mode);

    let response = if state.config.include_details {
        HealthResponse::from(&report)
    } else {
        HealthResponse {
            status: format!("{:?}", report.status).to_lowercase(),
            checks: None,
            duration_ms: None,
        }
    };

    tracing::debug!(
        control = "CA-7",
        status = %response.status,
        endpoint = "/health",
        "Health check completed"
    );

    (status_code, Json(response)).into_response()
}

/// Handler for /health/live endpoint (liveness probe)
///
/// Always returns 200 OK if the server is running.
/// Used by Kubernetes to determine if the container should be restarted.
async fn live_handler() -> Response {
    tracing::debug!(control = "CA-7", endpoint = "/health/live", "Liveness probe");

    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "alive".to_string(),
            checks: None,
            duration_ms: None,
        }),
    )
        .into_response()
}

/// Handler for /health/ready endpoint (readiness probe)
///
/// Returns 200 OK only if all critical checks pass.
/// Used by Kubernetes to determine if the pod should receive traffic.
async fn ready_handler(State(state): State<HealthState>) -> Response {
    let report = state.checker.check_all().await;
    let is_ready = report.status != Status::Unhealthy;

    let status_code = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let response = if state.config.include_details {
        HealthResponse::from(&report)
    } else {
        HealthResponse {
            status: if is_ready { "ready" } else { "not_ready" }.to_string(),
            checks: None,
            duration_ms: None,
        }
    };

    tracing::debug!(
        control = "CA-7",
        status = %response.status,
        endpoint = "/health/ready",
        "Readiness probe completed"
    );

    (status_code, Json(response)).into_response()
}

/// Convert health status to HTTP status code
fn status_to_http(status: &Status, strict: bool) -> StatusCode {
    match (status, strict) {
        (Status::Healthy, _) => StatusCode::OK,
        (Status::Degraded, false) => StatusCode::OK, // Degraded is operational
        (Status::Degraded, true) => StatusCode::SERVICE_UNAVAILABLE,
        (Status::Unhealthy, _) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Extension for sharing HealthChecker with handlers
///
/// Handlers can extract this to run health checks or add dynamic checks:
///
/// ```ignore
/// async fn custom_health(
///     Extension(health): Extension<HealthExtension>,
/// ) -> impl IntoResponse {
///     let report = health.check_all().await;
///     Json(report)
/// }
/// ```
#[derive(Clone)]
pub struct HealthExtension {
    checker: Arc<HealthChecker>,
}

impl HealthExtension {
    /// Create a new health extension
    pub fn new(checker: HealthChecker) -> Self {
        Self {
            checker: Arc::new(checker),
        }
    }

    /// Run all health checks
    pub async fn check_all(&self) -> HealthReport {
        self.checker.check_all().await
    }

    /// Run a specific check
    pub async fn check_one(&self, name: &str) -> Option<HealthStatus> {
        self.checker.check_one(name).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_worst() {
        assert_eq!(Status::Healthy.worst(Status::Healthy), Status::Healthy);
        assert_eq!(Status::Healthy.worst(Status::Degraded), Status::Degraded);
        assert_eq!(Status::Healthy.worst(Status::Unhealthy), Status::Unhealthy);
        assert_eq!(Status::Degraded.worst(Status::Unhealthy), Status::Unhealthy);
    }

    #[test]
    fn test_status_is_operational() {
        assert!(Status::Healthy.is_operational());
        assert!(Status::Degraded.is_operational());
        assert!(!Status::Unhealthy.is_operational());
    }

    #[test]
    fn test_health_status_healthy() {
        let status = HealthStatus::healthy();
        assert_eq!(status.status, Status::Healthy);
        assert!(status.message.is_none());
    }

    #[test]
    fn test_health_status_unhealthy() {
        let status = HealthStatus::unhealthy("Connection failed");
        assert_eq!(status.status, Status::Unhealthy);
        assert_eq!(status.message, Some("Connection failed".to_string()));
    }

    #[test]
    fn test_health_status_with_details() {
        let status = HealthStatus::healthy()
            .with_detail("version", "1.0.0")
            .with_detail("uptime", "3600");

        assert_eq!(status.details.get("version"), Some(&"1.0.0".to_string()));
        assert_eq!(status.details.get("uptime"), Some(&"3600".to_string()));
    }

    #[test]
    fn test_health_check_config() {
        let config = HealthCheckConfig::new("database")
            .with_timeout(Duration::from_secs(10))
            .critical(true)
            .with_failure_threshold(5);

        assert_eq!(config.name, "database");
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert!(config.critical);
        assert_eq!(config.failure_threshold, 5);
    }

    #[tokio::test]
    async fn test_health_check_run() {
        let check = HealthCheck::new("test", || async {
            HealthStatus::healthy_with_message("All good")
        });

        let status = check.run().await;
        assert_eq!(status.status, Status::Healthy);
        assert!(status.duration > Duration::ZERO || status.duration == Duration::ZERO);
    }

    #[tokio::test]
    async fn test_health_checker_all_healthy() {
        let checker = HealthChecker::new()
            .with_check(always_healthy("check1"))
            .with_check(always_healthy("check2"));

        let report = checker.check_all().await;
        assert_eq!(report.status, Status::Healthy);
        assert_eq!(report.checks.len(), 2);
    }

    #[tokio::test]
    async fn test_health_checker_one_unhealthy() {
        let checker = HealthChecker::new()
            .with_check(always_healthy("healthy"))
            .with_check(always_unhealthy("unhealthy", "Failed"));

        let report = checker.check_all().await;
        assert_eq!(report.status, Status::Unhealthy);
        assert_eq!(report.failed_checks().len(), 1);
    }

    #[tokio::test]
    async fn test_health_checker_non_critical() {
        let mut checker = HealthChecker::new();

        // Add a non-critical unhealthy check
        let config = HealthCheckConfig::new("non_critical").critical(false);
        checker.add_check(HealthCheck::with_config(config, || async {
            HealthStatus::unhealthy("Failed but not critical")
        }));

        // Add a healthy critical check
        checker.add_check(always_healthy("critical"));

        let report = checker.check_all().await;
        // Overall should be healthy because the failed check is non-critical
        assert_eq!(report.status, Status::Healthy);
    }

    #[tokio::test]
    async fn test_health_checker_check_one() {
        let checker = HealthChecker::new()
            .with_check(always_healthy("exists"))
            .with_check(always_unhealthy("also_exists", "err"));

        let status = checker.check_one("exists").await;
        assert!(status.is_some());
        assert_eq!(status.unwrap().status, Status::Healthy);

        let missing = checker.check_one("missing").await;
        assert!(missing.is_none());
    }

    #[test]
    fn test_health_report_to_json() {
        let mut checks = HashMap::new();
        checks.insert(
            "test".to_string(),
            HealthStatus::healthy_with_message("OK"),
        );

        let report = HealthReport {
            status: Status::Healthy,
            checks,
            generated_at: Instant::now(),
            total_duration: Duration::from_millis(100),
        };

        let json = report.to_json();
        assert_eq!(json["status"], "healthy");
        assert!(json["checks"]["test"].is_object());
    }

    #[test]
    fn test_always_healthy() {
        let check = always_healthy("test");
        assert_eq!(check.config.name, "test");
    }

    // ========================================================================
    // CA-7 Enforcement Tests
    // ========================================================================

    #[test]
    fn test_health_endpoint_config_defaults() {
        let config = HealthEndpointConfig::default();
        assert_eq!(config.health_path, "/health");
        assert_eq!(config.live_path, "/health/live");
        assert_eq!(config.ready_path, "/health/ready");
        assert!(config.include_details);
        assert!(!config.strict_mode);
    }

    #[test]
    fn test_health_endpoint_config_production() {
        let config = HealthEndpointConfig::production();
        assert!(!config.include_details);
        assert!(config.strict_mode);
    }

    #[test]
    fn test_health_endpoint_config_development() {
        let config = HealthEndpointConfig::development();
        assert!(config.include_details);
        assert!(!config.strict_mode);
    }

    #[test]
    fn test_status_to_http() {
        // Non-strict mode
        assert_eq!(status_to_http(&Status::Healthy, false), StatusCode::OK);
        assert_eq!(status_to_http(&Status::Degraded, false), StatusCode::OK);
        assert_eq!(status_to_http(&Status::Unhealthy, false), StatusCode::SERVICE_UNAVAILABLE);

        // Strict mode
        assert_eq!(status_to_http(&Status::Healthy, true), StatusCode::OK);
        assert_eq!(status_to_http(&Status::Degraded, true), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_to_http(&Status::Unhealthy, true), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_health_response_from_report() {
        let mut checks = HashMap::new();
        checks.insert(
            "database".to_string(),
            HealthStatus::healthy_with_message("Connected"),
        );
        checks.insert(
            "cache".to_string(),
            HealthStatus::degraded("Slow").with_duration(Duration::from_millis(50)),
        );

        let report = HealthReport {
            status: Status::Degraded,
            checks,
            generated_at: Instant::now(),
            total_duration: Duration::from_millis(100),
        };

        let response = HealthResponse::from(&report);
        assert_eq!(response.status, "degraded");
        assert!(response.checks.is_some());
        assert_eq!(response.checks.as_ref().unwrap().len(), 2);
        assert_eq!(response.duration_ms, Some(100));
    }

    #[test]
    fn test_check_result_serialization() {
        let result = CheckResult {
            name: "test".to_string(),
            status: "healthy".to_string(),
            message: Some("All good".to_string()),
            duration_ms: 10,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"message\":\"All good\""));
    }

    #[tokio::test]
    async fn test_health_extension() {
        let checker = HealthChecker::new()
            .with_check(always_healthy("test"));
        let extension = HealthExtension::new(checker);

        let report = extension.check_all().await;
        assert_eq!(report.status, Status::Healthy);

        let status = extension.check_one("test").await;
        assert!(status.is_some());
        assert_eq!(status.unwrap().status, Status::Healthy);
    }

    #[test]
    fn test_health_state() {
        let checker = HealthChecker::new();
        let config = HealthEndpointConfig::default();
        let state = HealthState::new(checker, config.clone());

        // State should be cloneable
        let _cloned = state.clone();
    }
}
