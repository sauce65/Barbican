//! Security configuration for the infrastructure layer
//!
//! Provides a builder-pattern configuration for all security controls.

use std::time::Duration;
use crate::parse::{parse_duration, parse_size};
use crate::tls::TlsMode;

/// Security configuration for the API infrastructure layer.
///
/// Controls all NIST 800-53 compliant security features:
/// - SC-2: Security Headers (HSTS, CSP, X-Frame-Options, etc.)
/// - SC-3: Rate Limiting (requests per second, burst size)
/// - SC-4: Request Body Size Limits
/// - SC-5: Request Timeouts
/// - SC-6: CORS Policy
/// - SC-7: Structured Logging (TraceLayer)
/// - SC-8: TLS Enforcement (HTTPS required)
///
/// # Example
///
/// ```ignore
/// use barbican::SecurityConfig;
///
/// // Load from environment variables
/// let config = SecurityConfig::from_env();
///
/// // Or build programmatically
/// let config = SecurityConfig::builder()
///     .max_request_size(5 * 1024 * 1024) // 5MB
///     .request_timeout(Duration::from_secs(60))
///     .rate_limit(10, 20) // 10/sec, burst 20
///     .cors_origins(vec!["https://app.example.com"])
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Maximum request body size in bytes (SC-4)
    pub max_request_size: usize,

    /// Request timeout duration (SC-5)
    pub request_timeout: Duration,

    /// Rate limit: requests per second (SC-3)
    pub rate_limit_per_second: u64,

    /// Rate limit: burst size (SC-3)
    pub rate_limit_burst: u32,

    /// Enable rate limiting (SC-3)
    /// Set to false for testing only
    pub rate_limit_enabled: bool,

    /// CORS allowed origins (SC-6)
    /// Empty = restrictive (same-origin only)
    /// ["*"] = permissive (any origin - NOT for production)
    /// ["https://..."] = explicit allowlist
    pub cors_origins: Vec<String>,

    /// Enable security headers (SC-2)
    pub security_headers_enabled: bool,

    /// Enable request/response tracing (SC-7)
    pub tracing_enabled: bool,

    /// TLS enforcement mode (SC-8)
    /// Controls HTTPS requirement for incoming requests
    pub tls_mode: TlsMode,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_request_size: 1024 * 1024, // 1MB
            request_timeout: Duration::from_secs(30),
            rate_limit_per_second: 5,
            rate_limit_burst: 10,
            rate_limit_enabled: true,
            cors_origins: Vec::new(), // Restrictive by default
            security_headers_enabled: true,
            tracing_enabled: true,
            tls_mode: TlsMode::Required, // SC-8: HTTPS required by default
        }
    }
}

impl SecurityConfig {
    /// Create a development configuration with relaxed security.
    ///
    /// WARNING: Never use in production. Disables TLS enforcement
    /// and allows permissive CORS.
    pub fn development() -> Self {
        Self {
            max_request_size: 10 * 1024 * 1024, // 10MB
            request_timeout: Duration::from_secs(60),
            rate_limit_per_second: 100,
            rate_limit_burst: 200,
            rate_limit_enabled: false,
            cors_origins: vec!["*".to_string()],
            security_headers_enabled: false,
            tracing_enabled: true,
            tls_mode: TlsMode::Disabled, // Development only!
        }
    }
}

impl SecurityConfig {
    /// Create configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `MAX_REQUEST_SIZE`: e.g., "10MB", "1GB" (default: "1MB")
    /// - `REQUEST_TIMEOUT`: e.g., "30s", "5m" (default: "30s")
    /// - `RATE_LIMIT_PER_SECOND`: requests/sec (default: 5)
    /// - `RATE_LIMIT_BURST`: burst size (default: 10)
    /// - `RATE_LIMIT_ENABLED`: "true"/"false" (default: "true")
    /// - `CORS_ALLOWED_ORIGINS`: comma-separated, or "*" (default: empty/restrictive)
    /// - `SECURITY_HEADERS_ENABLED`: "true"/"false" (default: "true")
    /// - `TRACING_ENABLED`: "true"/"false" (default: "true")
    /// - `TLS_MODE`: "disabled", "opportunistic", "required", "strict" (default: "required")
    pub fn from_env() -> Self {
        let max_request_size = std::env::var("MAX_REQUEST_SIZE")
            .map(|s| parse_size(&s))
            .unwrap_or(1024 * 1024);

        let request_timeout = std::env::var("REQUEST_TIMEOUT")
            .map(|s| parse_duration(&s))
            .unwrap_or(Duration::from_secs(30));

        let rate_limit_per_second = std::env::var("RATE_LIMIT_PER_SECOND")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let rate_limit_burst = std::env::var("RATE_LIMIT_BURST")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let rate_limit_enabled = std::env::var("RATE_LIMIT_ENABLED")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        let cors_origins = std::env::var("CORS_ALLOWED_ORIGINS")
            .map(|s| {
                if s.is_empty() {
                    Vec::new()
                } else {
                    s.split(',')
                        .map(|o| o.trim().to_string())
                        .filter(|o| !o.is_empty())
                        .collect()
                }
            })
            .unwrap_or_default();

        let security_headers_enabled = std::env::var("SECURITY_HEADERS_ENABLED")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        let tracing_enabled = std::env::var("TRACING_ENABLED")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        let tls_mode = std::env::var("TLS_MODE")
            .ok()
            .and_then(|s| TlsMode::from_str_loose(&s))
            .unwrap_or(TlsMode::Required);

        Self {
            max_request_size,
            request_timeout,
            rate_limit_per_second,
            rate_limit_burst,
            rate_limit_enabled,
            cors_origins,
            security_headers_enabled,
            tracing_enabled,
            tls_mode,
        }
    }

    /// Create a new builder for programmatic configuration.
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }

    /// Check if CORS is in permissive mode (allows any origin).
    pub fn cors_is_permissive(&self) -> bool {
        self.cors_origins.len() == 1 && self.cors_origins[0] == "*"
    }

    /// Check if CORS is in restrictive mode (same-origin only).
    pub fn cors_is_restrictive(&self) -> bool {
        self.cors_origins.is_empty()
    }
}

/// Builder for SecurityConfig
#[derive(Debug, Clone, Default)]
pub struct SecurityConfigBuilder {
    config: SecurityConfig,
}

impl SecurityConfigBuilder {
    /// Set maximum request body size in bytes.
    pub fn max_request_size(mut self, size: usize) -> Self {
        self.config.max_request_size = size;
        self
    }

    /// Set request timeout duration.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Set rate limiting parameters.
    pub fn rate_limit(mut self, per_second: u64, burst: u32) -> Self {
        self.config.rate_limit_per_second = per_second;
        self.config.rate_limit_burst = burst;
        self
    }

    /// Set CORS allowed origins.
    pub fn cors_origins(mut self, origins: Vec<&str>) -> Self {
        self.config.cors_origins = origins.into_iter().map(String::from).collect();
        self
    }

    /// Allow any CORS origin (development only!).
    pub fn cors_permissive(mut self) -> Self {
        self.config.cors_origins = vec!["*".to_string()];
        self
    }

    /// Disable security headers.
    pub fn disable_security_headers(mut self) -> Self {
        self.config.security_headers_enabled = false;
        self
    }

    /// Disable request/response tracing.
    pub fn disable_tracing(mut self) -> Self {
        self.config.tracing_enabled = false;
        self
    }

    /// Disable rate limiting (for testing only!).
    pub fn disable_rate_limiting(mut self) -> Self {
        self.config.rate_limit_enabled = false;
        self
    }

    /// Set TLS enforcement mode (SC-8).
    pub fn tls_mode(mut self, mode: TlsMode) -> Self {
        self.config.tls_mode = mode;
        self
    }

    /// Disable TLS enforcement (development only!).
    pub fn disable_tls_enforcement(mut self) -> Self {
        self.config.tls_mode = TlsMode::Disabled;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> SecurityConfig {
        self.config
    }
}
