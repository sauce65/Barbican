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

/// Tracks rate limiting for alerts
#[derive(Debug, Default)]
struct RateLimitState {
    /// Count per category within the current window
    category_counts: HashMap<AlertCategory, Vec<Instant>>,
    /// Recent fingerprints for deduplication
    recent_fingerprints: HashMap<String, Instant>,
}

/// Alert handler function type
pub type AlertHandler = Box<dyn Fn(&Alert) + Send + Sync>;

/// Alert manager for coordinating alert delivery
pub struct AlertManager {
    config: AlertConfig,
    state: Arc<RwLock<RateLimitState>>,
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

    /// Register an alert handler
    pub fn register_handler<F>(&self, handler: F)
    where
        F: Fn(&Alert) + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().unwrap();
        handlers.push(Box::new(handler));
    }

    /// Send an alert
    ///
    /// Returns true if the alert was sent, false if it was rate-limited or deduplicated.
    pub fn send(&self, alert: Alert) -> bool {
        // Check severity threshold
        if alert.severity < self.config.min_severity {
            return false;
        }

        // Check rate limiting and deduplication
        if !self.should_send(&alert) {
            return false;
        }

        // Update state
        self.record_alert(&alert);

        // Dispatch to handlers
        let handlers = self.handlers.read().unwrap();
        for handler in handlers.iter() {
            handler(&alert);
        }

        // Log the alert
        log_alert(&alert);

        true
    }

    /// Send an alert from a security event
    pub fn send_event(&self, event: SecurityEvent, description: impl Into<String>) -> bool {
        if !self.config.should_alert(&event) {
            return false;
        }

        let alert = Alert::from_event(event, description);
        self.send(alert)
    }

    /// Check if an alert should be sent (rate limiting + dedup)
    fn should_send(&self, alert: &Alert) -> bool {
        let mut state = self.state.write().unwrap();
        let now = Instant::now();

        // Deduplication check
        if let Some(&last_seen) = state.recent_fingerprints.get(&alert.fingerprint) {
            if now.duration_since(last_seen) < self.config.dedup_window {
                return false;
            }
        }

        // Skip rate limiting for critical categories
        if self.config.critical_categories.contains(&alert.category) {
            return true;
        }

        // Rate limiting check
        let counts = state
            .category_counts
            .entry(alert.category)
            .or_default();

        // Clean up old entries
        counts.retain(|&t| now.duration_since(t) < self.config.rate_limit_window);

        // Check if under limit
        if counts.len() as u32 >= self.config.rate_limit_per_category {
            return false;
        }

        true
    }

    /// Record that an alert was sent
    fn record_alert(&self, alert: &Alert) {
        let mut state = self.state.write().unwrap();
        let now = Instant::now();

        // Record fingerprint for dedup
        state.recent_fingerprints.insert(alert.fingerprint.clone(), now);

        // Record category count
        state
            .category_counts
            .entry(alert.category)
            .or_default()
            .push(now);

        // Cleanup old fingerprints periodically
        if state.recent_fingerprints.len() > 1000 {
            state.recent_fingerprints.retain(|_, &mut t| {
                now.duration_since(t) < self.config.dedup_window
            });
        }
    }

    /// Get current alert counts by category
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

    /// Clear all state (for testing)
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
}
