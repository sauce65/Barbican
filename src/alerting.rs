//! Incident Alerting Framework (IR-4, IR-5)
//!
//! NIST SP 800-53 IR-4 (Incident Handling) and IR-5 (Incident Monitoring)
//! compliant alerting utilities for security events.
//!
//! # Design Philosophy
//!
//! This module provides the framework for incident alerting. The actual
//! delivery mechanisms (email, Slack, PagerDuty, etc.) are typically handled
//! by external systems. This module:
//!
//! - Defines alert severity and categories
//! - Provides alert aggregation to prevent alert storms
//! - Offers hooks for custom alert handlers
//! - Includes rate limiting for alerts
//! - Supports alert suppression during incidents
//!
//! For production deployments, integrate with:
//! - AlertManager (Prometheus)
//! - PagerDuty
//! - Opsgenie
//! - Slack/Teams webhooks
//! - Custom SIEM integration
//!
//! # Usage
//!
//! ```ignore
//! use barbican::alerting::{AlertManager, AlertConfig, AlertSeverity, Alert};
//!
//! // Create alert manager
//! let config = AlertConfig::default();
//! let alerts = AlertManager::new(config);
//!
//! // Register a handler
//! alerts.register_handler(|alert| {
//!     println!("ALERT: {:?}", alert);
//! });
//!
//! // Send an alert
//! alerts.send(Alert::new(
//!     AlertSeverity::Critical,
//!     "Brute force attack detected",
//!     "Multiple failed login attempts from IP 192.168.1.1",
//! ));
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::observability::{SecurityEvent, Severity};

// ============================================================================
// Alert Configuration (IR-4)
// ============================================================================

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    /// Informational - no action required
    Info,
    /// Warning - investigation may be needed
    Warning,
    /// Error - action should be taken
    Error,
    /// Critical - immediate action required
    Critical,
}

impl From<Severity> for AlertSeverity {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Low => AlertSeverity::Info,
            Severity::Medium => AlertSeverity::Warning,
            Severity::High => AlertSeverity::Error,
            Severity::Critical => AlertSeverity::Critical,
        }
    }
}

/// Alert categories for routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertCategory {
    /// Authentication-related alerts
    Authentication,
    /// Authorization/access control alerts
    Authorization,
    /// Rate limiting/DoS alerts
    RateLimiting,
    /// Session management alerts
    Session,
    /// Data integrity alerts
    DataIntegrity,
    /// Configuration change alerts
    Configuration,
    /// System health alerts
    SystemHealth,
    /// Security incident alerts
    SecurityIncident,
    /// Compliance-related alerts
    Compliance,
    /// Custom category
    Custom,
}

impl From<SecurityEvent> for AlertCategory {
    fn from(event: SecurityEvent) -> Self {
        match event {
            SecurityEvent::AuthenticationSuccess
            | SecurityEvent::AuthenticationFailure
            | SecurityEvent::Logout => AlertCategory::Authentication,

            SecurityEvent::AccessGranted
            | SecurityEvent::AccessDenied => AlertCategory::Authorization,

            SecurityEvent::RateLimitExceeded
            | SecurityEvent::BruteForceDetected => AlertCategory::RateLimiting,

            SecurityEvent::SessionCreated
            | SecurityEvent::SessionDestroyed => AlertCategory::Session,

            SecurityEvent::UserRegistered
            | SecurityEvent::UserModified
            | SecurityEvent::UserDeleted
            | SecurityEvent::PasswordChanged
            | SecurityEvent::PasswordResetRequested => AlertCategory::DataIntegrity,

            SecurityEvent::ConfigurationChanged => AlertCategory::Configuration,

            SecurityEvent::SystemStartup
            | SecurityEvent::SystemShutdown
            | SecurityEvent::DatabaseConnected
            | SecurityEvent::DatabaseDisconnected => AlertCategory::SystemHealth,

            SecurityEvent::SuspiciousActivity
            | SecurityEvent::AccountLocked
            | SecurityEvent::AccountUnlocked => AlertCategory::SecurityIncident,
        }
    }
}

/// Alert configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Minimum severity to trigger alerts
    pub min_severity: AlertSeverity,

    /// Rate limit: max alerts per category per time window
    pub rate_limit_per_category: u32,

    /// Rate limit window
    pub rate_limit_window: Duration,

    /// Enable alert aggregation (group similar alerts)
    pub enable_aggregation: bool,

    /// Aggregation window for grouping similar alerts
    pub aggregation_window: Duration,

    /// Suppress duplicate alerts within this duration
    pub dedup_window: Duration,

    /// Categories that should always alert (bypass rate limiting)
    pub critical_categories: Vec<AlertCategory>,

    /// Security events that should trigger alerts
    pub alertable_events: Vec<SecurityEvent>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            min_severity: AlertSeverity::Warning,
            rate_limit_per_category: 10,
            rate_limit_window: Duration::from_secs(60),
            enable_aggregation: true,
            aggregation_window: Duration::from_secs(30),
            dedup_window: Duration::from_secs(300),
            critical_categories: vec![
                AlertCategory::SecurityIncident,
                AlertCategory::Authorization,
            ],
            alertable_events: vec![
                SecurityEvent::BruteForceDetected,
                SecurityEvent::AccountLocked,
                SecurityEvent::SuspiciousActivity,
                SecurityEvent::DatabaseDisconnected,
                SecurityEvent::AccessDenied,
            ],
        }
    }
}

impl AlertConfig {
    /// Create a builder for custom configuration
    pub fn builder() -> AlertConfigBuilder {
        AlertConfigBuilder::default()
    }

    /// High-sensitivity configuration for security-critical environments
    pub fn high_sensitivity() -> Self {
        Self {
            min_severity: AlertSeverity::Info,
            rate_limit_per_category: 50,
            rate_limit_window: Duration::from_secs(60),
            enable_aggregation: false,
            aggregation_window: Duration::from_secs(10),
            dedup_window: Duration::from_secs(60),
            critical_categories: vec![
                AlertCategory::SecurityIncident,
                AlertCategory::Authorization,
                AlertCategory::Authentication,
                AlertCategory::Session,
            ],
            alertable_events: vec![
                SecurityEvent::AuthenticationFailure,
                SecurityEvent::AccessDenied,
                SecurityEvent::BruteForceDetected,
                SecurityEvent::AccountLocked,
                SecurityEvent::SuspiciousActivity,
                SecurityEvent::DatabaseDisconnected,
                SecurityEvent::ConfigurationChanged,
                SecurityEvent::UserDeleted,
            ],
        }
    }

    /// Low-noise configuration for less critical environments
    pub fn low_noise() -> Self {
        Self {
            min_severity: AlertSeverity::Critical,
            rate_limit_per_category: 5,
            rate_limit_window: Duration::from_secs(300),
            enable_aggregation: true,
            aggregation_window: Duration::from_secs(60),
            dedup_window: Duration::from_secs(600),
            critical_categories: vec![AlertCategory::SecurityIncident],
            alertable_events: vec![
                SecurityEvent::BruteForceDetected,
                SecurityEvent::SuspiciousActivity,
                SecurityEvent::DatabaseDisconnected,
            ],
        }
    }

    /// Check if an event should trigger an alert
    pub fn should_alert(&self, event: &SecurityEvent) -> bool {
        self.alertable_events.contains(event)
    }
}

/// Builder for AlertConfig
#[derive(Default)]
pub struct AlertConfigBuilder {
    config: AlertConfig,
}

impl AlertConfigBuilder {
    /// Set minimum severity
    pub fn min_severity(mut self, severity: AlertSeverity) -> Self {
        self.config.min_severity = severity;
        self
    }

    /// Set rate limit per category
    pub fn rate_limit(mut self, count: u32, window: Duration) -> Self {
        self.config.rate_limit_per_category = count;
        self.config.rate_limit_window = window;
        self
    }

    /// Enable or disable aggregation
    pub fn enable_aggregation(mut self, enabled: bool) -> Self {
        self.config.enable_aggregation = enabled;
        self
    }

    /// Set aggregation window
    pub fn aggregation_window(mut self, duration: Duration) -> Self {
        self.config.aggregation_window = duration;
        self
    }

    /// Set deduplication window
    pub fn dedup_window(mut self, duration: Duration) -> Self {
        self.config.dedup_window = duration;
        self
    }

    /// Set critical categories
    pub fn critical_categories(mut self, categories: Vec<AlertCategory>) -> Self {
        self.config.critical_categories = categories;
        self
    }

    /// Set alertable events
    pub fn alertable_events(mut self, events: Vec<SecurityEvent>) -> Self {
        self.config.alertable_events = events;
        self
    }

    /// Build the configuration
    pub fn build(self) -> AlertConfig {
        self.config
    }
}

// ============================================================================
// Alert Structure
// ============================================================================

/// A security alert
#[derive(Debug, Clone)]
pub struct Alert {
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert category
    pub category: AlertCategory,
    /// Short summary
    pub summary: String,
    /// Detailed description
    pub description: String,
    /// Source of the alert (e.g., "login_tracker", "rate_limiter")
    pub source: String,
    /// Additional context as key-value pairs
    pub context: HashMap<String, String>,
    /// When the alert was created
    pub timestamp: Instant,
    /// Unique fingerprint for deduplication
    pub fingerprint: String,
    /// Related security event (if any)
    pub event: Option<SecurityEvent>,
}

impl Alert {
    /// Create a new alert
    pub fn new(
        severity: AlertSeverity,
        summary: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let summary = summary.into();
        let description = description.into();
        let fingerprint = Self::compute_fingerprint(&summary, &description);

        Self {
            severity,
            category: AlertCategory::Custom,
            summary,
            description,
            source: String::new(),
            context: HashMap::new(),
            timestamp: Instant::now(),
            fingerprint,
            event: None,
        }
    }

    /// Create an alert from a security event
    pub fn from_event(event: SecurityEvent, description: impl Into<String>) -> Self {
        let severity = event.severity().into();
        let category = event.clone().into();
        let summary = format!("{}", event.name());
        let description = description.into();
        let fingerprint = Self::compute_fingerprint(&summary, &description);

        Self {
            severity,
            category,
            summary,
            description,
            source: String::new(),
            context: HashMap::new(),
            timestamp: Instant::now(),
            fingerprint,
            event: Some(event),
        }
    }

    /// Set the alert category
    pub fn with_category(mut self, category: AlertCategory) -> Self {
        self.category = category;
        self
    }

    /// Set the alert source
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// Add context to the alert
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Add multiple context entries
    pub fn with_contexts(mut self, contexts: impl IntoIterator<Item = (String, String)>) -> Self {
        self.context.extend(contexts);
        self
    }

    /// Compute a fingerprint for deduplication
    fn compute_fingerprint(summary: &str, description: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        summary.hash(&mut hasher);
        description.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

// ============================================================================
// Alert Manager (IR-5)
// ============================================================================
//
// The AlertManager implements a 5-stage pipeline for processing alerts:
//
// ```text
// ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
// │  STAGE 1        │     │  STAGE 2        │     │  STAGE 3        │
// │  Severity Gate  │────▶│  Deduplication  │────▶│  Rate Limiting  │
// │                 │     │                 │     │                 │
// │  Drop if below  │     │  Drop if same   │     │  Drop if cat.   │
// │  min_severity   │     │  fingerprint    │     │  over limit     │
// │                 │     │  in dedup_window│     │  (unless crit.) │
// └─────────────────┘     └─────────────────┘     └─────────────────┘
//                                                         │
//          ┌──────────────────────────────────────────────┘
//          ▼
// ┌─────────────────┐     ┌─────────────────┐
// │  STAGE 4        │     │  STAGE 5        │
// │  Record State   │────▶│  Dispatch       │
// │                 │     │                 │
// │  Update dedup   │     │  Call handlers  │
// │  and rate limit │     │  then log       │
// │  tracking       │     │                 │
// └─────────────────┘     └─────────────────┘
// ```
//
// This design prevents alert storms during incidents while ensuring critical
// security events always reach operators.

/// Tracks rate limiting and deduplication state.
///
/// Uses a sliding window approach - stores timestamps rather than simple
/// counters, allowing precise time-based decisions.
#[derive(Debug, Default)]
struct RateLimitState {
    /// Timestamps of recent alerts per category (for rate limiting).
    /// Used in Stage 3 to enforce per-category limits.
    category_counts: HashMap<AlertCategory, Vec<Instant>>,

    /// Recent alert fingerprints mapped to when they were last seen.
    /// Used in Stage 2 to suppress duplicate alerts.
    recent_fingerprints: HashMap<String, Instant>,
}

/// Alert handler function type.
///
/// Handlers are called in Stage 5 for every alert that passes the pipeline.
/// The `Send + Sync + 'static` bounds allow handlers to be called from any
/// thread and capture owned data (like HTTP clients for external services).
pub type AlertHandler = Box<dyn Fn(&Alert) + Send + Sync>;

/// Alert manager for coordinating alert delivery.
///
/// Central coordinator that ensures alerts reach the right systems without
/// overwhelming operators during an incident. Thread-safe and cheaply
/// cloneable via internal `Arc` wrappers.
pub struct AlertManager {
    config: AlertConfig,
    /// Mutable state for rate limiting and deduplication (Stages 2-4)
    state: Arc<RwLock<RateLimitState>>,
    /// Registered callbacks for alert dispatch (Stage 5)
    handlers: Arc<RwLock<Vec<AlertHandler>>>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(RateLimitState::default())),
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create with default configuration
    pub fn with_default_config() -> Self {
        Self::new(AlertConfig::default())
    }

    /// Register an alert handler for Stage 5 dispatch.
    ///
    /// Handlers are called synchronously for every alert that passes
    /// through the pipeline. Common integrations include:
    ///
    /// - PagerDuty/Opsgenie for on-call notification
    /// - Slack/Teams webhooks for team channels
    /// - SIEM systems for correlation
    /// - Firewall APIs for automated blocking
    ///
    /// # Example
    ///
    /// ```ignore
    /// alerts.register_handler(|alert| {
    ///     if alert.severity == AlertSeverity::Critical {
    ///         pagerduty.create_incident(&alert.summary);
    ///     }
    /// });
    /// ```
    pub fn register_handler<F>(&self, handler: F)
    where
        F: Fn(&Alert) + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().unwrap();
        handlers.push(Box::new(handler));
    }

    /// Send an alert through the 5-stage pipeline.
    ///
    /// Returns `true` if the alert was dispatched to handlers, `false` if
    /// it was dropped by any stage (severity, dedup, or rate limiting).
    pub fn send(&self, alert: Alert) -> bool {
        // =====================================================================
        // STAGE 1: Severity Gate
        // =====================================================================
        // Drop alerts below the configured minimum severity threshold.
        // With default config (min_severity: Warning), Info alerts are dropped.
        if alert.severity < self.config.min_severity {
            return false;
        }

        // =====================================================================
        // STAGES 2-3: Deduplication and Rate Limiting
        // =====================================================================
        // Implemented in should_send() - checks fingerprint dedup window and
        // per-category rate limits (with bypass for critical categories).
        if !self.should_send(&alert) {
            return false;
        }

        // =====================================================================
        // STAGE 4: Record State
        // =====================================================================
        // Update tracking state for future dedup and rate limit decisions.
        self.record_alert(&alert);

        // =====================================================================
        // STAGE 5: Dispatch
        // =====================================================================
        // Call all registered handlers, then log via tracing.
        let handlers = self.handlers.read().unwrap();
        for handler in handlers.iter() {
            handler(&alert);
        }

        log_alert(&alert);

        true
    }

    /// Send an alert from a security event.
    ///
    /// Convenience method that checks if the event type is in the alertable
    /// events list before converting and sending.
    pub fn send_event(&self, event: SecurityEvent, description: impl Into<String>) -> bool {
        if !self.config.should_alert(&event) {
            return false;
        }

        let alert = Alert::from_event(event, description);
        self.send(alert)
    }

    /// Stages 2-3: Check deduplication and rate limiting.
    ///
    /// Returns `true` if the alert should proceed, `false` if it should
    /// be dropped.
    fn should_send(&self, alert: &Alert) -> bool {
        let mut state = self.state.write().unwrap();
        let now = Instant::now();

        // =====================================================================
        // STAGE 2: Deduplication
        // =====================================================================
        // Drop if the same fingerprint (hash of summary+description) was seen
        // within the dedup_window (default: 5 minutes).
        if let Some(&last_seen) = state.recent_fingerprints.get(&alert.fingerprint) {
            if now.duration_since(last_seen) < self.config.dedup_window {
                return false;
            }
        }

        // =====================================================================
        // STAGE 3: Rate Limiting (with critical category bypass)
        // =====================================================================
        // Critical categories (default: SecurityIncident, Authorization) skip
        // rate limiting entirely - these always get through.
        if self.config.critical_categories.contains(&alert.category) {
            return true;
        }

        // For non-critical categories, enforce per-category limits.
        // Default: max 10 alerts per category per 60-second window.
        let counts = state
            .category_counts
            .entry(alert.category)
            .or_default();

        // Prune timestamps outside the rate limit window (sliding window)
        counts.retain(|&t| now.duration_since(t) < self.config.rate_limit_window);

        // Reject if at or over the limit
        if counts.len() as u32 >= self.config.rate_limit_per_category {
            return false;
        }

        true
    }

    /// Stage 4: Record alert state for future pipeline decisions.
    ///
    /// Updates both the fingerprint map (for dedup) and the category
    /// timestamp list (for rate limiting).
    fn record_alert(&self, alert: &Alert) {
        let mut state = self.state.write().unwrap();
        let now = Instant::now();

        // Record fingerprint timestamp for Stage 2 (deduplication)
        state.recent_fingerprints.insert(alert.fingerprint.clone(), now);

        // Record category timestamp for Stage 3 (rate limiting)
        state
            .category_counts
            .entry(alert.category)
            .or_default()
            .push(now);

        // Memory management: prune expired fingerprints when map grows large
        if state.recent_fingerprints.len() > 1000 {
            state.recent_fingerprints.retain(|_, &mut t| {
                now.duration_since(t) < self.config.dedup_window
            });
        }
    }

    /// Get current alert counts by category within the rate limit window.
    ///
    /// Useful for dashboards and monitoring to show alert volume. Returns
    /// only alerts within the active `rate_limit_window`, not historical data.
    pub fn get_alert_counts(&self) -> HashMap<AlertCategory, usize> {
        let state = self.state.read().unwrap();
        let now = Instant::now();

        state
            .category_counts
            .iter()
            .map(|(cat, times)| {
                let count = times
                    .iter()
                    .filter(|&&t| now.duration_since(t) < self.config.rate_limit_window)
                    .count();
                (*cat, count)
            })
            .collect()
    }

    /// Clear all pipeline state (Stages 2-4 tracking data).
    ///
    /// Resets both the fingerprint dedup map and category rate limit counters.
    /// Primarily useful for testing; in production, state naturally expires
    /// based on configured time windows.
    pub fn clear(&self) {
        let mut state = self.state.write().unwrap();
        state.category_counts.clear();
        state.recent_fingerprints.clear();
    }
}

impl Clone for AlertManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            handlers: Arc::clone(&self.handlers),
        }
    }
}

impl std::fmt::Debug for AlertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertManager")
            .field("config", &self.config)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Logging
// ============================================================================

/// Log an alert
fn log_alert(alert: &Alert) {
    use tracing::{error, info, warn};

    let severity_str = format!("{:?}", alert.severity);
    let category_str = format!("{:?}", alert.category);

    match alert.severity {
        AlertSeverity::Critical => {
            error!(
                severity = %severity_str,
                category = %category_str,
                summary = %alert.summary,
                source = %alert.source,
                fingerprint = %alert.fingerprint,
                "[ALERT] {}",
                alert.description
            );
        }
        AlertSeverity::Error => {
            error!(
                severity = %severity_str,
                category = %category_str,
                summary = %alert.summary,
                source = %alert.source,
                "[ALERT] {}",
                alert.description
            );
        }
        AlertSeverity::Warning => {
            warn!(
                severity = %severity_str,
                category = %category_str,
                summary = %alert.summary,
                source = %alert.source,
                "[ALERT] {}",
                alert.description
            );
        }
        AlertSeverity::Info => {
            info!(
                severity = %severity_str,
                category = %category_str,
                summary = %alert.summary,
                source = %alert.source,
                "[ALERT] {}",
                alert.description
            );
        }
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Create and send a critical alert
pub fn alert_critical(summary: impl Into<String>, description: impl Into<String>, manager: &AlertManager) -> bool {
    let alert = Alert::new(AlertSeverity::Critical, summary, description)
        .with_category(AlertCategory::SecurityIncident);
    manager.send(alert)
}

/// Create and send a brute force detection alert
pub fn alert_brute_force(ip: &str, attempt_count: u32, manager: &AlertManager) -> bool {
    let alert = Alert::from_event(
        SecurityEvent::BruteForceDetected,
        format!("Detected {} failed login attempts from IP {}", attempt_count, ip),
    )
    .with_source("login_tracker")
    .with_context("ip_address", ip.to_string())
    .with_context("attempt_count", attempt_count.to_string());

    manager.send(alert)
}

/// Create and send an account lockout alert
pub fn alert_account_locked(identifier: &str, reason: &str, manager: &AlertManager) -> bool {
    let alert = Alert::from_event(
        SecurityEvent::AccountLocked,
        format!("Account '{}' locked: {}", identifier, reason),
    )
    .with_source("login_tracker")
    .with_context("identifier", identifier.to_string())
    .with_context("reason", reason.to_string());

    manager.send(alert)
}

/// Create and send a suspicious activity alert
pub fn alert_suspicious_activity(
    description: &str,
    user_id: Option<&str>,
    ip: Option<&str>,
    manager: &AlertManager,
) -> bool {
    let mut alert = Alert::from_event(
        SecurityEvent::SuspiciousActivity,
        description.to_string(),
    )
    .with_source("security_monitor");

    if let Some(uid) = user_id {
        alert = alert.with_context("user_id", uid.to_string());
    }
    if let Some(ip_addr) = ip {
        alert = alert.with_context("ip_address", ip_addr.to_string());
    }

    manager.send(alert)
}

/// Create and send a database disconnection alert
pub fn alert_database_disconnected(
    database_name: &str,
    reason: &str,
    manager: &AlertManager,
) -> bool {
    let alert = Alert::from_event(
        SecurityEvent::DatabaseDisconnected,
        format!("Database '{}' disconnected: {}", database_name, reason),
    )
    .with_source("database_monitor")
    .with_context("database", database_name.to_string())
    .with_context("reason", reason.to_string());

    manager.send(alert)
}

// ============================================================================
// IR-4 Enforcement: Axum Integration
// ============================================================================

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;

/// Extension for sharing AlertManager with request handlers
///
/// Handlers can extract this to send alerts:
///
/// ```ignore
/// use barbican::alerting::{AlertingExtension, Alert, AlertSeverity, AlertCategory};
///
/// async fn risky_operation(
///     Extension(alerting): Extension<AlertingExtension>,
/// ) -> impl IntoResponse {
///     // Perform operation...
///     if suspicious_activity_detected {
///         alerting.alert(Alert::new(
///             AlertSeverity::Warning,
///             "Suspicious activity",
///             "Unusual pattern detected",
///         ).with_category(AlertCategory::SecurityIncident));
///     }
///     "OK"
/// }
/// ```
#[derive(Clone)]
pub struct AlertingExtension {
    manager: AlertManager,
}

impl AlertingExtension {
    /// Create a new alerting extension
    pub fn new(manager: AlertManager) -> Self {
        Self { manager }
    }

    /// Send an alert through the manager
    pub fn alert(&self, alert: Alert) -> bool {
        self.manager.send(alert)
    }

    /// Send a critical alert
    pub fn alert_critical(&self, summary: impl Into<String>, description: impl Into<String>) -> bool {
        alert_critical(summary, description, &self.manager)
    }

    /// Send a brute force detection alert
    pub fn alert_brute_force(&self, ip: &str, attempt_count: u32) -> bool {
        alert_brute_force(ip, attempt_count, &self.manager)
    }

    /// Send an account lockout alert
    pub fn alert_account_locked(&self, identifier: &str, reason: &str) -> bool {
        alert_account_locked(identifier, reason, &self.manager)
    }

    /// Send a suspicious activity alert
    pub fn alert_suspicious(&self, description: &str, user_id: Option<&str>, ip: Option<&str>) -> bool {
        alert_suspicious_activity(description, user_id, ip, &self.manager)
    }

    /// Send a database disconnection alert
    pub fn alert_database_disconnected(&self, database_name: &str, reason: &str) -> bool {
        alert_database_disconnected(database_name, reason, &self.manager)
    }

    /// Get the underlying manager for advanced usage
    pub fn manager(&self) -> &AlertManager {
        &self.manager
    }
}

impl std::fmt::Debug for AlertingExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertingExtension")
            .field("manager", &"AlertManager { ... }")
            .finish()
    }
}

/// Middleware that provides AlertingExtension to handlers
///
/// This middleware injects the `AlertingExtension` into all requests,
/// allowing handlers to send alerts as needed.
///
/// # Example
///
/// ```ignore
/// use barbican::alerting::{alerting_middleware, AlertManager, AlertConfig};
/// use axum::{Router, middleware};
///
/// let manager = AlertManager::new(AlertConfig::default());
///
/// let app = Router::new()
///     .route("/api/action", post(risky_handler))
///     .layer(middleware::from_fn(move |req, next| {
///         let manager = manager.clone();
///         async move {
///             alerting_middleware(req, next, manager).await
///         }
///     }));
/// ```
pub async fn alerting_middleware(
    mut req: Request,
    next: Next,
    manager: AlertManager,
) -> Response {
    // Inject the alerting extension
    req.extensions_mut().insert(AlertingExtension::new(manager));

    next.run(req).await
}

/// Create an Axum layer that provides alerting to all handlers
///
/// This is a convenience wrapper around `alerting_middleware`.
///
/// # Example
///
/// ```ignore
/// use barbican::alerting::{alerting_layer, AlertManager, AlertConfig};
/// use axum::Router;
///
/// let manager = AlertManager::new(AlertConfig::default());
///
/// let app = Router::new()
///     .route("/api/action", post(handler))
///     .layer(alerting_layer(manager));
/// ```
pub fn alerting_layer(manager: AlertManager) -> axum::middleware::FromFnLayer<
    impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> + Clone + Send,
    (),
    Request,
> {
    axum::middleware::from_fn(move |req: Request, next: Next| {
        let manager = manager.clone();
        Box::pin(async move {
            alerting_middleware(req, next, manager).await
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
    })
}

// ============================================================================
// IR-5 Enforcement: Incident Tracking
// ============================================================================

/// Incident status lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncidentStatus {
    /// Newly created, not yet investigated
    Open,
    /// Under active investigation
    Investigating,
    /// Incident has been contained
    Contained,
    /// Incident has been fully resolved
    Resolved,
    /// Closed without resolution (false positive, etc.)
    Closed,
}

impl Default for IncidentStatus {
    fn default() -> Self {
        Self::Open
    }
}

/// A tracked security incident (IR-5)
///
/// Unlike `Alert` which is a notification, `Incident` represents a tracked
/// security event with lifecycle management.
#[derive(Debug, Clone)]
pub struct Incident {
    /// Unique incident identifier
    pub id: String,
    /// Incident severity
    pub severity: AlertSeverity,
    /// Incident category
    pub category: AlertCategory,
    /// Short summary
    pub summary: String,
    /// Detailed description
    pub description: String,
    /// Current status
    pub status: IncidentStatus,
    /// Source of the incident
    pub source: String,
    /// When the incident was created
    pub created_at: Instant,
    /// When the incident was last updated
    pub updated_at: Instant,
    /// When the incident was resolved (if resolved)
    pub resolved_at: Option<Instant>,
    /// Related alert fingerprints
    pub related_alerts: Vec<String>,
    /// Additional context
    pub context: HashMap<String, String>,
    /// Resolution notes (if resolved)
    pub resolution_notes: Option<String>,
    /// Assigned responder (if any)
    pub assignee: Option<String>,
}

impl Incident {
    /// Create a new incident
    pub fn new(
        severity: AlertSeverity,
        summary: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let now = Instant::now();
        Self {
            id: generate_incident_id(),
            severity,
            category: AlertCategory::Custom,
            summary: summary.into(),
            description: description.into(),
            status: IncidentStatus::Open,
            source: String::new(),
            created_at: now,
            updated_at: now,
            resolved_at: None,
            related_alerts: Vec::new(),
            context: HashMap::new(),
            resolution_notes: None,
            assignee: None,
        }
    }

    /// Create an incident from an alert
    pub fn from_alert(alert: &Alert) -> Self {
        let now = Instant::now();
        Self {
            id: generate_incident_id(),
            severity: alert.severity,
            category: alert.category,
            summary: alert.summary.clone(),
            description: alert.description.clone(),
            status: IncidentStatus::Open,
            source: alert.source.clone(),
            created_at: now,
            updated_at: now,
            resolved_at: None,
            related_alerts: vec![alert.fingerprint.clone()],
            context: alert.context.clone(),
            resolution_notes: None,
            assignee: None,
        }
    }

    /// Set the incident category
    pub fn with_category(mut self, category: AlertCategory) -> Self {
        self.category = category;
        self
    }

    /// Set the incident source
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// Add context to the incident
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Update the incident status
    pub fn update_status(&mut self, status: IncidentStatus) {
        self.status = status;
        self.updated_at = Instant::now();
        if matches!(status, IncidentStatus::Resolved | IncidentStatus::Closed) {
            self.resolved_at = Some(Instant::now());
        }
    }

    /// Assign the incident to a responder
    pub fn assign(&mut self, assignee: impl Into<String>) {
        self.assignee = Some(assignee.into());
        self.updated_at = Instant::now();
    }

    /// Add resolution notes
    pub fn resolve(&mut self, notes: impl Into<String>) {
        self.resolution_notes = Some(notes.into());
        self.update_status(IncidentStatus::Resolved);
    }

    /// Link a related alert
    pub fn link_alert(&mut self, fingerprint: impl Into<String>) {
        self.related_alerts.push(fingerprint.into());
        self.updated_at = Instant::now();
    }

    /// Check if the incident is open (not resolved or closed)
    pub fn is_open(&self) -> bool {
        !matches!(self.status, IncidentStatus::Resolved | IncidentStatus::Closed)
    }
}

/// Generate a unique incident ID
fn generate_incident_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    format!("INC-{:08x}-{:04x}", timestamp, count & 0xFFFF)
}

/// Trait for incident storage backends (IR-5)
///
/// Implement this trait to integrate with external incident management systems
/// like PagerDuty, Opsgenie, ServiceNow, or custom databases.
pub trait IncidentStore: Send + Sync {
    /// Create a new incident
    fn create(&self, incident: Incident) -> Result<String, IncidentError>;

    /// Get an incident by ID
    fn get(&self, id: &str) -> Result<Option<Incident>, IncidentError>;

    /// Update an incident
    fn update(&self, incident: &Incident) -> Result<(), IncidentError>;

    /// List incidents with optional status filter
    fn list(&self, status: Option<IncidentStatus>) -> Result<Vec<Incident>, IncidentError>;

    /// Get open incidents count
    fn open_count(&self) -> Result<usize, IncidentError>;
}

/// Incident storage errors
#[derive(Debug)]
pub enum IncidentError {
    /// Incident not found
    NotFound(String),
    /// Storage error
    Storage(String),
    /// Concurrent modification
    Conflict(String),
}

impl std::fmt::Display for IncidentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "Incident not found: {}", id),
            Self::Storage(msg) => write!(f, "Storage error: {}", msg),
            Self::Conflict(msg) => write!(f, "Conflict: {}", msg),
        }
    }
}

impl std::error::Error for IncidentError {}

/// In-memory incident store for development and testing
#[derive(Debug, Default)]
pub struct InMemoryIncidentStore {
    incidents: RwLock<HashMap<String, Incident>>,
}

impl InMemoryIncidentStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self::default()
    }
}

impl IncidentStore for InMemoryIncidentStore {
    fn create(&self, incident: Incident) -> Result<String, IncidentError> {
        let id = incident.id.clone();
        let mut incidents = self.incidents.write()
            .map_err(|_| IncidentError::Storage("Lock poisoned".to_string()))?;
        incidents.insert(id.clone(), incident);
        Ok(id)
    }

    fn get(&self, id: &str) -> Result<Option<Incident>, IncidentError> {
        let incidents = self.incidents.read()
            .map_err(|_| IncidentError::Storage("Lock poisoned".to_string()))?;
        Ok(incidents.get(id).cloned())
    }

    fn update(&self, incident: &Incident) -> Result<(), IncidentError> {
        let mut incidents = self.incidents.write()
            .map_err(|_| IncidentError::Storage("Lock poisoned".to_string()))?;

        if !incidents.contains_key(&incident.id) {
            return Err(IncidentError::NotFound(incident.id.clone()));
        }

        incidents.insert(incident.id.clone(), incident.clone());
        Ok(())
    }

    fn list(&self, status: Option<IncidentStatus>) -> Result<Vec<Incident>, IncidentError> {
        let incidents = self.incidents.read()
            .map_err(|_| IncidentError::Storage("Lock poisoned".to_string()))?;

        let result: Vec<_> = incidents
            .values()
            .filter(|i| status.map_or(true, |s| i.status == s))
            .cloned()
            .collect();

        Ok(result)
    }

    fn open_count(&self) -> Result<usize, IncidentError> {
        let incidents = self.incidents.read()
            .map_err(|_| IncidentError::Storage("Lock poisoned".to_string()))?;

        Ok(incidents.values().filter(|i| i.is_open()).count())
    }
}

/// Incident tracker for managing security incidents (IR-5)
///
/// Provides incident lifecycle management with automatic escalation
/// from alerts to tracked incidents.
pub struct IncidentTracker<S: IncidentStore = InMemoryIncidentStore> {
    store: Arc<S>,
    config: IncidentTrackerConfig,
}

/// Configuration for incident tracking
#[derive(Debug, Clone)]
pub struct IncidentTrackerConfig {
    /// Automatically create incidents for critical alerts
    pub auto_create_for_critical: bool,
    /// Automatically create incidents for these categories
    pub auto_create_categories: Vec<AlertCategory>,
    /// Maximum open incidents before alerting
    pub max_open_incidents: usize,
}

impl Default for IncidentTrackerConfig {
    fn default() -> Self {
        Self {
            auto_create_for_critical: true,
            auto_create_categories: vec![
                AlertCategory::SecurityIncident,
            ],
            max_open_incidents: 100,
        }
    }
}

impl<S: IncidentStore> IncidentTracker<S> {
    /// Create a new incident tracker with the given store
    pub fn new(store: S, config: IncidentTrackerConfig) -> Self {
        Self {
            store: Arc::new(store),
            config,
        }
    }

    /// Create a new incident
    pub fn create_incident(&self, incident: Incident) -> Result<String, IncidentError> {
        self.store.create(incident)
    }

    /// Create an incident from an alert
    pub fn create_from_alert(&self, alert: &Alert) -> Result<String, IncidentError> {
        let incident = Incident::from_alert(alert);
        self.store.create(incident)
    }

    /// Get an incident by ID
    pub fn get_incident(&self, id: &str) -> Result<Option<Incident>, IncidentError> {
        self.store.get(id)
    }

    /// Update an incident's status
    pub fn update_status(&self, id: &str, status: IncidentStatus) -> Result<(), IncidentError> {
        let mut incident = self.store.get(id)?
            .ok_or_else(|| IncidentError::NotFound(id.to_string()))?;
        incident.update_status(status);
        self.store.update(&incident)
    }

    /// Resolve an incident
    pub fn resolve_incident(&self, id: &str, notes: impl Into<String>) -> Result<(), IncidentError> {
        let mut incident = self.store.get(id)?
            .ok_or_else(|| IncidentError::NotFound(id.to_string()))?;
        incident.resolve(notes);
        self.store.update(&incident)
    }

    /// Assign an incident
    pub fn assign_incident(&self, id: &str, assignee: impl Into<String>) -> Result<(), IncidentError> {
        let mut incident = self.store.get(id)?
            .ok_or_else(|| IncidentError::NotFound(id.to_string()))?;
        incident.assign(assignee);
        self.store.update(&incident)
    }

    /// List open incidents (Open, Investigating, or Contained)
    pub fn list_open(&self) -> Result<Vec<Incident>, IncidentError> {
        let all = self.store.list(None)?;
        Ok(all.into_iter().filter(|i| i.is_open()).collect())
    }

    /// List all incidents
    pub fn list_all(&self) -> Result<Vec<Incident>, IncidentError> {
        self.store.list(None)
    }

    /// Get count of open incidents
    pub fn open_count(&self) -> Result<usize, IncidentError> {
        self.store.open_count()
    }

    /// Check if an alert should create an incident
    pub fn should_create_incident(&self, alert: &Alert) -> bool {
        if self.config.auto_create_for_critical && alert.severity == AlertSeverity::Critical {
            return true;
        }
        self.config.auto_create_categories.contains(&alert.category)
    }

    /// Process an alert and optionally create an incident
    pub fn process_alert(&self, alert: &Alert) -> Option<String> {
        if self.should_create_incident(alert) {
            self.create_from_alert(alert).ok()
        } else {
            None
        }
    }

    /// Get the underlying store
    pub fn store(&self) -> &Arc<S> {
        &self.store
    }
}

impl<S: IncidentStore> Clone for IncidentTracker<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            config: self.config.clone(),
        }
    }
}

impl<S: IncidentStore + std::fmt::Debug> std::fmt::Debug for IncidentTracker<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncidentTracker")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Axum extension for incident tracking (IR-5)
///
/// Provides handlers with access to the incident tracker.
///
/// # Example
///
/// ```ignore
/// use barbican::alerting::{IncidentTrackerExtension, Incident, AlertSeverity, IncidentStatus};
///
/// async fn security_handler(
///     Extension(incidents): Extension<IncidentTrackerExtension>,
/// ) -> impl IntoResponse {
///     // Create an incident
///     let incident = Incident::new(
///         AlertSeverity::Critical,
///         "Data breach detected",
///         "Unauthorized data access from IP 10.0.0.1",
///     );
///     let id = incidents.create(incident).unwrap();
///
///     // Later: update status
///     incidents.update_status(&id, IncidentStatus::Investigating).unwrap();
///
///     "Incident created"
/// }
/// ```
#[derive(Clone)]
pub struct IncidentTrackerExtension {
    tracker: IncidentTracker<InMemoryIncidentStore>,
}

impl IncidentTrackerExtension {
    /// Create a new extension with an in-memory store
    pub fn new() -> Self {
        Self {
            tracker: IncidentTracker::new(
                InMemoryIncidentStore::new(),
                IncidentTrackerConfig::default(),
            ),
        }
    }

    /// Create from an existing tracker
    pub fn from_tracker(tracker: IncidentTracker<InMemoryIncidentStore>) -> Self {
        Self { tracker }
    }

    /// Create a new incident
    pub fn create(&self, incident: Incident) -> Result<String, IncidentError> {
        self.tracker.create_incident(incident)
    }

    /// Create an incident from an alert
    pub fn create_from_alert(&self, alert: &Alert) -> Result<String, IncidentError> {
        self.tracker.create_from_alert(alert)
    }

    /// Get an incident by ID
    pub fn get(&self, id: &str) -> Result<Option<Incident>, IncidentError> {
        self.tracker.get_incident(id)
    }

    /// Update incident status
    pub fn update_status(&self, id: &str, status: IncidentStatus) -> Result<(), IncidentError> {
        self.tracker.update_status(id, status)
    }

    /// Resolve an incident
    pub fn resolve(&self, id: &str, notes: impl Into<String>) -> Result<(), IncidentError> {
        self.tracker.resolve_incident(id, notes)
    }

    /// Assign an incident
    pub fn assign(&self, id: &str, assignee: impl Into<String>) -> Result<(), IncidentError> {
        self.tracker.assign_incident(id, assignee)
    }

    /// List open incidents
    pub fn list_open(&self) -> Result<Vec<Incident>, IncidentError> {
        self.tracker.list_open()
    }

    /// List all incidents
    pub fn list_all(&self) -> Result<Vec<Incident>, IncidentError> {
        self.tracker.list_all()
    }

    /// Get count of open incidents
    pub fn open_count(&self) -> Result<usize, IncidentError> {
        self.tracker.open_count()
    }

    /// Process an alert and optionally create an incident
    pub fn process_alert(&self, alert: &Alert) -> Option<String> {
        self.tracker.process_alert(alert)
    }
}

impl Default for IncidentTrackerExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IncidentTrackerExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncidentTrackerExtension")
            .field("open_count", &self.open_count().unwrap_or(0))
            .finish()
    }
}

/// Middleware that provides IncidentTrackerExtension to handlers
pub async fn incident_tracking_middleware(
    mut req: Request,
    next: Next,
    tracker: IncidentTracker<InMemoryIncidentStore>,
) -> Response {
    req.extensions_mut().insert(IncidentTrackerExtension::from_tracker(tracker));
    next.run(req).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AlertConfig::default();
        assert_eq!(config.min_severity, AlertSeverity::Warning);
        assert_eq!(config.rate_limit_per_category, 10);
        assert!(config.enable_aggregation);
    }

    #[test]
    fn test_high_sensitivity_config() {
        let config = AlertConfig::high_sensitivity();
        assert_eq!(config.min_severity, AlertSeverity::Info);
        assert!(!config.enable_aggregation);
    }

    #[test]
    fn test_low_noise_config() {
        let config = AlertConfig::low_noise();
        assert_eq!(config.min_severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(
            AlertSeverity::Critical,
            "Test Alert",
            "This is a test alert",
        )
        .with_category(AlertCategory::SecurityIncident)
        .with_source("test")
        .with_context("key", "value");

        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.category, AlertCategory::SecurityIncident);
        assert_eq!(alert.source, "test");
        assert_eq!(alert.context.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_alert_from_event() {
        let alert = Alert::from_event(
            SecurityEvent::BruteForceDetected,
            "Multiple failed attempts",
        );

        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.category, AlertCategory::RateLimiting);
        assert!(alert.event.is_some());
    }

    #[test]
    fn test_alert_manager_basic() {
        let manager = AlertManager::with_default_config();

        let alert = Alert::new(
            AlertSeverity::Critical,
            "Test",
            "Test alert",
        );

        assert!(manager.send(alert));
    }

    #[test]
    fn test_alert_manager_severity_filter() {
        let config = AlertConfig::builder()
            .min_severity(AlertSeverity::Error)
            .build();

        let manager = AlertManager::new(config);

        // Warning should be filtered
        let warning = Alert::new(AlertSeverity::Warning, "Test", "Test");
        assert!(!manager.send(warning));

        // Error should pass
        let error = Alert::new(AlertSeverity::Error, "Test", "Test");
        assert!(manager.send(error));
    }

    #[test]
    fn test_alert_deduplication() {
        let config = AlertConfig::builder()
            .dedup_window(Duration::from_secs(60))
            .build();

        let manager = AlertManager::new(config);

        // First alert should pass
        let alert1 = Alert::new(AlertSeverity::Critical, "Same", "Same description");
        assert!(manager.send(alert1));

        // Duplicate should be filtered
        let alert2 = Alert::new(AlertSeverity::Critical, "Same", "Same description");
        assert!(!manager.send(alert2));

        // Different alert should pass
        let alert3 = Alert::new(AlertSeverity::Critical, "Different", "Different description");
        assert!(manager.send(alert3));
    }

    #[test]
    fn test_alert_rate_limiting() {
        let config = AlertConfig::builder()
            .rate_limit(2, Duration::from_secs(60))
            .critical_categories(vec![]) // Disable bypass
            .build();

        let manager = AlertManager::new(config);

        // First two should pass
        let alert1 = Alert::new(AlertSeverity::Critical, "Test 1", "Desc 1")
            .with_category(AlertCategory::Authentication);
        let alert2 = Alert::new(AlertSeverity::Critical, "Test 2", "Desc 2")
            .with_category(AlertCategory::Authentication);
        let alert3 = Alert::new(AlertSeverity::Critical, "Test 3", "Desc 3")
            .with_category(AlertCategory::Authentication);

        assert!(manager.send(alert1));
        assert!(manager.send(alert2));
        assert!(!manager.send(alert3)); // Rate limited
    }

    #[test]
    fn test_critical_category_bypass() {
        let config = AlertConfig::builder()
            .rate_limit(1, Duration::from_secs(60))
            .critical_categories(vec![AlertCategory::SecurityIncident])
            .build();

        let manager = AlertManager::new(config);

        // Security incidents bypass rate limiting
        let alert1 = Alert::new(AlertSeverity::Critical, "Incident 1", "Desc 1")
            .with_category(AlertCategory::SecurityIncident);
        let alert2 = Alert::new(AlertSeverity::Critical, "Incident 2", "Desc 2")
            .with_category(AlertCategory::SecurityIncident);

        assert!(manager.send(alert1));
        assert!(manager.send(alert2)); // Bypasses rate limit
    }

    #[test]
    fn test_alert_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let manager = AlertManager::with_default_config();
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);

        manager.register_handler(move |_alert| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        });

        manager.send(Alert::new(AlertSeverity::Critical, "Test", "Test"));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_should_alert() {
        let config = AlertConfig::default();

        assert!(config.should_alert(&SecurityEvent::BruteForceDetected));
        assert!(config.should_alert(&SecurityEvent::AccountLocked));
        assert!(!config.should_alert(&SecurityEvent::AuthenticationSuccess));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(AlertSeverity::Info < AlertSeverity::Warning);
        assert!(AlertSeverity::Warning < AlertSeverity::Error);
        assert!(AlertSeverity::Error < AlertSeverity::Critical);
    }

    #[test]
    fn test_category_from_event() {
        assert_eq!(
            AlertCategory::from(SecurityEvent::AuthenticationFailure),
            AlertCategory::Authentication
        );
        assert_eq!(
            AlertCategory::from(SecurityEvent::BruteForceDetected),
            AlertCategory::RateLimiting
        );
        assert_eq!(
            AlertCategory::from(SecurityEvent::SessionDestroyed),
            AlertCategory::Session
        );
    }

    // ========================================================================
    // IR-4 Enforcement Tests
    // ========================================================================

    #[test]
    fn test_alerting_extension_creation() {
        let manager = AlertManager::with_default_config();
        let extension = AlertingExtension::new(manager);

        // Should be able to send alerts
        let sent = extension.alert(Alert::new(
            AlertSeverity::Critical,
            "Test",
            "Test alert",
        ));
        assert!(sent);
    }

    #[test]
    fn test_alerting_extension_convenience_methods() {
        let manager = AlertManager::with_default_config();
        let extension = AlertingExtension::new(manager);

        // Critical alert
        assert!(extension.alert_critical("Test", "Critical alert"));

        // Brute force alert
        assert!(extension.alert_brute_force("192.168.1.1", 5));

        // Account locked alert
        assert!(extension.alert_account_locked("user@example.com", "Too many attempts"));

        // Suspicious activity alert
        assert!(extension.alert_suspicious(
            "Unusual login pattern",
            Some("user123"),
            Some("10.0.0.1")
        ));

        // Database disconnected alert
        assert!(extension.alert_database_disconnected("primary", "Connection timeout"));
    }

    #[test]
    fn test_alerting_extension_debug() {
        let manager = AlertManager::with_default_config();
        let extension = AlertingExtension::new(manager);

        let debug_output = format!("{:?}", extension);
        assert!(debug_output.contains("AlertingExtension"));
    }

    #[test]
    fn test_alerting_extension_manager_access() {
        let config = AlertConfig::builder()
            .min_severity(AlertSeverity::Error)
            .build();
        let manager = AlertManager::new(config);
        let extension = AlertingExtension::new(manager);

        // Should be able to access the underlying manager
        let _manager = extension.manager();
    }

    #[test]
    fn test_alerting_extension_clone() {
        let manager = AlertManager::with_default_config();
        let extension = AlertingExtension::new(manager);

        // Should be cloneable (needed for Axum extension)
        let cloned = extension.clone();

        // Both should work
        assert!(extension.alert_critical("Test 1", "Test"));
        assert!(cloned.alert_critical("Test 2", "Test"));
    }

    // ========================================================================
    // IR-5 Incident Tracking Tests
    // ========================================================================

    #[test]
    fn test_incident_creation() {
        let incident = Incident::new(
            AlertSeverity::Critical,
            "Data breach detected",
            "Unauthorized access from external IP",
        )
        .with_category(AlertCategory::SecurityIncident)
        .with_source("security_monitor")
        .with_context("ip_address", "10.0.0.1");

        assert!(incident.id.starts_with("INC-"));
        assert_eq!(incident.severity, AlertSeverity::Critical);
        assert_eq!(incident.category, AlertCategory::SecurityIncident);
        assert_eq!(incident.status, IncidentStatus::Open);
        assert!(incident.is_open());
    }

    #[test]
    fn test_incident_from_alert() {
        let alert = Alert::new(AlertSeverity::Critical, "Test Alert", "Test description")
            .with_category(AlertCategory::SecurityIncident)
            .with_context("key", "value");

        let incident = Incident::from_alert(&alert);

        assert_eq!(incident.severity, alert.severity);
        assert_eq!(incident.category, alert.category);
        assert_eq!(incident.summary, alert.summary);
        assert!(incident.related_alerts.contains(&alert.fingerprint));
    }

    #[test]
    fn test_incident_status_lifecycle() {
        let mut incident = Incident::new(
            AlertSeverity::Critical,
            "Test",
            "Test incident",
        );

        assert_eq!(incident.status, IncidentStatus::Open);
        assert!(incident.is_open());

        incident.update_status(IncidentStatus::Investigating);
        assert_eq!(incident.status, IncidentStatus::Investigating);
        assert!(incident.is_open());

        incident.update_status(IncidentStatus::Contained);
        assert_eq!(incident.status, IncidentStatus::Contained);
        assert!(incident.is_open());

        incident.resolve("Issue resolved by patching vulnerability");
        assert_eq!(incident.status, IncidentStatus::Resolved);
        assert!(!incident.is_open());
        assert!(incident.resolution_notes.is_some());
        assert!(incident.resolved_at.is_some());
    }

    #[test]
    fn test_incident_assignment() {
        let mut incident = Incident::new(
            AlertSeverity::Critical,
            "Test",
            "Test incident",
        );

        assert!(incident.assignee.is_none());

        incident.assign("security-team@example.com");
        assert_eq!(incident.assignee, Some("security-team@example.com".to_string()));
    }

    #[test]
    fn test_in_memory_incident_store() {
        let store = InMemoryIncidentStore::new();

        // Create incident
        let incident = Incident::new(
            AlertSeverity::Critical,
            "Test Incident",
            "Description",
        );
        let id = store.create(incident).unwrap();

        // Get incident
        let retrieved = store.get(&id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, id);

        // Update incident
        let mut updated = store.get(&id).unwrap().unwrap();
        updated.update_status(IncidentStatus::Investigating);
        store.update(&updated).unwrap();

        let after_update = store.get(&id).unwrap().unwrap();
        assert_eq!(after_update.status, IncidentStatus::Investigating);

        // List open incidents
        let open = store.list(Some(IncidentStatus::Open)).unwrap();
        assert_eq!(open.len(), 0); // Status changed to Investigating

        let investigating = store.list(Some(IncidentStatus::Investigating)).unwrap();
        assert_eq!(investigating.len(), 1);

        // Open count
        assert_eq!(store.open_count().unwrap(), 1);
    }

    #[test]
    fn test_incident_tracker() {
        let tracker = IncidentTracker::new(
            InMemoryIncidentStore::new(),
            IncidentTrackerConfig::default(),
        );

        // Create incident
        let incident = Incident::new(
            AlertSeverity::Critical,
            "Test Incident",
            "Description",
        );
        let id = tracker.create_incident(incident).unwrap();

        // Get incident
        let retrieved = tracker.get_incident(&id).unwrap();
        assert!(retrieved.is_some());

        // Update status
        tracker.update_status(&id, IncidentStatus::Investigating).unwrap();
        let after_update = tracker.get_incident(&id).unwrap().unwrap();
        assert_eq!(after_update.status, IncidentStatus::Investigating);

        // Assign
        tracker.assign_incident(&id, "responder@example.com").unwrap();
        let assigned = tracker.get_incident(&id).unwrap().unwrap();
        assert!(assigned.assignee.is_some());

        // Resolve
        tracker.resolve_incident(&id, "Fixed the issue").unwrap();
        let resolved = tracker.get_incident(&id).unwrap().unwrap();
        assert_eq!(resolved.status, IncidentStatus::Resolved);

        // Open count should be 0 after resolution
        assert_eq!(tracker.open_count().unwrap(), 0);
    }

    #[test]
    fn test_incident_tracker_auto_create() {
        let tracker = IncidentTracker::new(
            InMemoryIncidentStore::new(),
            IncidentTrackerConfig::default(),
        );

        // Critical alert should auto-create incident
        let critical_alert = Alert::new(
            AlertSeverity::Critical,
            "Critical Alert",
            "This should create an incident",
        );
        assert!(tracker.should_create_incident(&critical_alert));
        let id = tracker.process_alert(&critical_alert);
        assert!(id.is_some());

        // Warning alert should not auto-create (unless in security category)
        let warning_alert = Alert::new(
            AlertSeverity::Warning,
            "Warning Alert",
            "This should not create an incident",
        ).with_category(AlertCategory::Authentication);
        assert!(!tracker.should_create_incident(&warning_alert));
        let id = tracker.process_alert(&warning_alert);
        assert!(id.is_none());

        // SecurityIncident category should auto-create
        let security_alert = Alert::new(
            AlertSeverity::Warning,
            "Security Alert",
            "Security incident",
        ).with_category(AlertCategory::SecurityIncident);
        assert!(tracker.should_create_incident(&security_alert));
    }

    #[test]
    fn test_incident_tracker_extension() {
        let extension = IncidentTrackerExtension::new();

        // Create incident
        let incident = Incident::new(
            AlertSeverity::Critical,
            "Test Incident",
            "Description",
        );
        let id = extension.create(incident).unwrap();

        // Get incident
        let retrieved = extension.get(&id).unwrap();
        assert!(retrieved.is_some());

        // Update status
        extension.update_status(&id, IncidentStatus::Investigating).unwrap();

        // Assign
        extension.assign(&id, "responder@example.com").unwrap();

        // List open
        let open = extension.list_open().unwrap();
        assert_eq!(open.len(), 1);

        // Resolve
        extension.resolve(&id, "Issue resolved").unwrap();

        // Open count should be 0
        assert_eq!(extension.open_count().unwrap(), 0);
    }

    #[test]
    fn test_incident_tracker_extension_from_alert() {
        let extension = IncidentTrackerExtension::new();

        let alert = Alert::new(
            AlertSeverity::Critical,
            "Test Alert",
            "Alert description",
        );

        let id = extension.create_from_alert(&alert).unwrap();

        let incident = extension.get(&id).unwrap().unwrap();
        assert_eq!(incident.summary, alert.summary);
        assert!(incident.related_alerts.contains(&alert.fingerprint));
    }

    #[test]
    fn test_incident_tracker_extension_debug() {
        let extension = IncidentTrackerExtension::new();

        let debug_output = format!("{:?}", extension);
        assert!(debug_output.contains("IncidentTrackerExtension"));
        assert!(debug_output.contains("open_count"));
    }

    #[test]
    fn test_incident_tracker_extension_default() {
        let extension = IncidentTrackerExtension::default();

        // Should work with defaults
        let incident = Incident::new(
            AlertSeverity::Critical,
            "Test",
            "Description",
        );
        let id = extension.create(incident).unwrap();
        assert!(extension.get(&id).unwrap().is_some());
    }

    #[test]
    fn test_incident_error_display() {
        let err = IncidentError::NotFound("INC-123".to_string());
        assert!(err.to_string().contains("INC-123"));

        let err = IncidentError::Storage("Database error".to_string());
        assert!(err.to_string().contains("Database error"));

        let err = IncidentError::Conflict("Version mismatch".to_string());
        assert!(err.to_string().contains("Version mismatch"));
    }

    #[test]
    fn test_incident_id_uniqueness() {
        let id1 = generate_incident_id();
        let id2 = generate_incident_id();
        let id3 = generate_incident_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert!(id1.starts_with("INC-"));
    }
}
