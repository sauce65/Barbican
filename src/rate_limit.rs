//! Tiered Rate Limiting for Axum Applications
//!
//! Provides NIST 800-53 SC-5 (Denial of Service Protection) compliant rate limiting
//! with support for different rate limit tiers based on endpoint sensitivity.
//!
//! # Compliance Controls
//!
//! - **SC-5**: Denial of Service Protection - Prevents resource exhaustion
//! - **AC-7**: Unsuccessful Login Attempts - Stricter limits on auth endpoints
//!
//! # Rate Limit Tiers
//!
//! | Tier | Default Limit | Lockout | Use Case |
//! |------|---------------|---------|----------|
//! | Auth | 10/min | 5 min | Login, token refresh, password reset |
//! | Sensitive | 30/min | 2 min | Admin operations, key management |
//! | Standard | 100/min | 1 min | Normal API operations |
//! | Relaxed | 1000/min | 10 sec | Health checks, public endpoints |
//!
//! # Example
//!
//! ```ignore
//! use axum::{Router, routing::post};
//! use barbican::rate_limit::{TieredRateLimiter, RateLimitTier, tiered_rate_limit_middleware};
//!
//! let limiter = TieredRateLimiter::default();
//!
//! let app = Router::new()
//!     .route("/api/v1/auth/login", post(login_handler))
//!     .route("/api/v1/users", post(create_user))
//!     .layer(axum::middleware::from_fn_with_state(
//!         limiter,
//!         tiered_rate_limit_middleware,
//!     ));
//! ```
//!
//! # Custom Tier Configuration
//!
//! ```ignore
//! use barbican::rate_limit::{TieredRateLimiter, RateLimitTierConfig};
//! use std::time::Duration;
//!
//! let limiter = TieredRateLimiter::builder()
//!     .auth_tier(5, Duration::from_secs(60), Duration::from_secs(600))  // 5/min, 10min lockout
//!     .standard_tier(50, Duration::from_secs(60), Duration::from_secs(120))
//!     .build();
//! ```

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

// ============================================================================
// Rate Limit Tier
// ============================================================================

/// Rate limit tier for different endpoint sensitivity levels.
///
/// Tiers are ordered from most restrictive (Auth) to least restrictive (Relaxed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitTier {
    /// Authentication endpoints - most restrictive (AC-7)
    /// Login, logout, token refresh, password reset, MFA
    Auth,

    /// Sensitive operations - restricted
    /// Admin endpoints, key management, user management
    Sensitive,

    /// Standard API operations - moderate limits
    /// Normal CRUD operations, data processing
    Standard,

    /// Relaxed endpoints - least restrictive
    /// Health checks, metrics, public read-only endpoints
    Relaxed,
}

impl RateLimitTier {
    /// Get the tier name for logging and metrics
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Sensitive => "sensitive",
            Self::Standard => "standard",
            Self::Relaxed => "relaxed",
        }
    }

    /// Default limits for this tier: (max_requests, window_duration)
    pub fn default_limits(&self) -> (usize, Duration) {
        match self {
            Self::Auth => (10, Duration::from_secs(60)),      // 10/min
            Self::Sensitive => (30, Duration::from_secs(60)), // 30/min
            Self::Standard => (100, Duration::from_secs(60)), // 100/min
            Self::Relaxed => (1000, Duration::from_secs(60)), // 1000/min
        }
    }

    /// Default lockout duration when rate limit is exceeded
    pub fn default_lockout(&self) -> Duration {
        match self {
            Self::Auth => Duration::from_secs(300),      // 5 min
            Self::Sensitive => Duration::from_secs(120), // 2 min
            Self::Standard => Duration::from_secs(60),   // 1 min
            Self::Relaxed => Duration::from_secs(10),    // 10 sec
        }
    }

    /// Determine tier from request path using common conventions
    ///
    /// Override this by implementing a custom `TierResolver`
    pub fn from_path(path: &str) -> Self {
        let path_lower = path.to_lowercase();

        // Auth tier: authentication-related endpoints
        if path_lower.contains("/auth/")
            || path_lower.contains("/login")
            || path_lower.contains("/logout")
            || path_lower.contains("/token")
            || path_lower.contains("/password")
            || path_lower.contains("/mfa")
            || path_lower.contains("/oauth")
            || path_lower.contains("/oidc")
        {
            return Self::Auth;
        }

        // Sensitive tier: admin and management endpoints
        if path_lower.contains("/admin")
            || path_lower.contains("/keys")
            || path_lower.contains("/users")
            || path_lower.contains("/roles")
            || path_lower.contains("/permissions")
            || path_lower.contains("/settings")
            || path_lower.contains("/config")
        {
            return Self::Sensitive;
        }

        // Relaxed tier: health and metrics
        if path_lower.contains("/health")
            || path_lower.contains("/metrics")
            || path_lower.contains("/ready")
            || path_lower.contains("/live")
            || path_lower.contains("/version")
            || path_lower.contains("/status")
        {
            return Self::Relaxed;
        }

        // Default to standard tier
        Self::Standard
    }
}

// ============================================================================
// Tier Configuration
// ============================================================================

/// Configuration for a single rate limit tier
#[derive(Debug, Clone)]
pub struct RateLimitTierConfig {
    /// Maximum requests allowed in the window
    pub max_requests: usize,
    /// Time window for counting requests
    pub window: Duration,
    /// Lockout duration when limit is exceeded
    pub lockout_duration: Duration,
}

impl RateLimitTierConfig {
    /// Create a new tier configuration
    pub fn new(max_requests: usize, window: Duration, lockout_duration: Duration) -> Self {
        Self {
            max_requests,
            window,
            lockout_duration,
        }
    }
}

// ============================================================================
// Rate Limiter Core
// ============================================================================

/// Internal rate limiter for a single tier
#[derive(Debug)]
struct TierRateLimiter {
    config: RateLimitTierConfig,
    /// Attempts by key: key -> list of attempt timestamps
    attempts: RwLock<HashMap<String, Vec<Instant>>>,
    /// Active lockouts: key -> lockout expiry time
    lockouts: RwLock<HashMap<String, Instant>>,
}

impl TierRateLimiter {
    fn new(config: RateLimitTierConfig) -> Self {
        Self {
            config,
            attempts: RwLock::new(HashMap::new()),
            lockouts: RwLock::new(HashMap::new()),
        }
    }

    /// Check if the request should be allowed
    fn check(&self, key: &str) -> Result<RateLimitStatus, RateLimitError> {
        let now = Instant::now();

        // Check for active lockout
        {
            let lockouts = self.lockouts.read().expect("lockouts lock poisoned");
            if let Some(&lockout_until) = lockouts.get(key) {
                if now < lockout_until {
                    let remaining = lockout_until.duration_since(now);
                    return Err(RateLimitError::LockedOut {
                        remaining_secs: remaining.as_secs(),
                    });
                }
            }
        }

        // Clean expired lockouts
        {
            let mut lockouts = self.lockouts.write().expect("lockouts lock poisoned");
            lockouts.retain(|_, &mut until| now < until);
        }

        // Check and update attempts
        let mut attempts = self.attempts.write().expect("attempts lock poisoned");
        let attempt_list = attempts.entry(key.to_string()).or_default();

        // Remove attempts outside the window
        attempt_list.retain(|&t| now.duration_since(t) < self.config.window);

        // Check if over limit
        if attempt_list.len() >= self.config.max_requests {
            // Add to lockout
            let lockout_until = now + self.config.lockout_duration;
            drop(attempts); // Release lock before acquiring lockouts lock

            let mut lockouts = self.lockouts.write().expect("lockouts lock poisoned");
            lockouts.insert(key.to_string(), lockout_until);

            return Err(RateLimitError::LimitExceeded {
                lockout_secs: self.config.lockout_duration.as_secs(),
            });
        }

        // Record this attempt
        attempt_list.push(now);
        let current = attempt_list.len();

        Ok(RateLimitStatus {
            remaining: self.config.max_requests - current,
            limit: self.config.max_requests,
            window_secs: self.config.window.as_secs(),
        })
    }

    /// Clear attempts for a key (e.g., after successful authentication)
    fn clear(&self, key: &str) {
        let mut attempts = self.attempts.write().expect("attempts lock poisoned");
        attempts.remove(key);

        let mut lockouts = self.lockouts.write().expect("lockouts lock poisoned");
        lockouts.remove(key);
    }
}

// ============================================================================
// Rate Limit Status and Errors
// ============================================================================

/// Current rate limit status for a request
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStatus {
    /// Remaining requests in the current window
    pub remaining: usize,
    /// Maximum requests allowed
    pub limit: usize,
    /// Window duration in seconds
    pub window_secs: u64,
}

/// Rate limit error
#[derive(Debug, Clone)]
pub enum RateLimitError {
    /// Rate limit exceeded, now in lockout
    LimitExceeded {
        /// Duration of lockout in seconds
        lockout_secs: u64,
    },
    /// Currently locked out from previous violation
    LockedOut {
        /// Remaining lockout time in seconds
        remaining_secs: u64,
    },
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded { lockout_secs } => {
                write!(f, "Rate limit exceeded. Locked out for {} seconds.", lockout_secs)
            }
            Self::LockedOut { remaining_secs } => {
                write!(f, "Currently locked out. {} seconds remaining.", remaining_secs)
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

// ============================================================================
// Tiered Rate Limiter
// ============================================================================

/// Trait for custom tier resolution from requests
pub trait TierResolver: Send + Sync {
    /// Determine the rate limit tier for a request path
    fn resolve(&self, path: &str, method: &str) -> RateLimitTier;
}

/// Default tier resolver using path-based heuristics
#[derive(Debug, Clone, Default)]
pub struct DefaultTierResolver;

impl TierResolver for DefaultTierResolver {
    fn resolve(&self, path: &str, _method: &str) -> RateLimitTier {
        RateLimitTier::from_path(path)
    }
}

/// Tiered rate limiter with per-tier configurations
///
/// Implements SC-5 (DoS Protection) and AC-7 (Unsuccessful Login Attempts)
#[derive(Clone)]
pub struct TieredRateLimiter {
    limiters: Arc<HashMap<RateLimitTier, Arc<TierRateLimiter>>>,
    resolver: Arc<dyn TierResolver>,
    /// Paths to skip rate limiting (e.g., health checks)
    skip_paths: Arc<Vec<String>>,
}

impl std::fmt::Debug for TieredRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TieredRateLimiter")
            .field("tiers", &self.limiters.keys().collect::<Vec<_>>())
            .field("skip_paths", &self.skip_paths)
            .finish()
    }
}

impl Default for TieredRateLimiter {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl TieredRateLimiter {
    /// Create a new builder for custom configuration
    pub fn builder() -> TieredRateLimiterBuilder {
        TieredRateLimiterBuilder::default()
    }

    /// Check rate limit for a request
    pub fn check(&self, ip: IpAddr, path: &str, method: &str) -> Result<(RateLimitTier, RateLimitStatus), (RateLimitTier, RateLimitError)> {
        // Check if path should be skipped
        for skip_path in self.skip_paths.iter() {
            if path.starts_with(skip_path) {
                return Ok((RateLimitTier::Relaxed, RateLimitStatus {
                    remaining: usize::MAX,
                    limit: usize::MAX,
                    window_secs: 0,
                }));
            }
        }

        let tier = self.resolver.resolve(path, method);
        let key = format!("{}:{}", ip, tier.as_str());

        let limiter = self.limiters.get(&tier)
            .expect("All tiers should be configured");

        match limiter.check(&key) {
            Ok(status) => Ok((tier, status)),
            Err(e) => Err((tier, e)),
        }
    }

    /// Clear rate limit attempts for a specific IP and tier
    ///
    /// Call this after successful authentication to reset the counter
    pub fn clear(&self, ip: IpAddr, tier: RateLimitTier) {
        let key = format!("{}:{}", ip, tier.as_str());
        if let Some(limiter) = self.limiters.get(&tier) {
            limiter.clear(&key);
        }
    }

    /// Clear all rate limit attempts for an IP across all tiers
    pub fn clear_all(&self, ip: IpAddr) {
        for (tier, limiter) in self.limiters.iter() {
            let key = format!("{}:{}", ip, tier.as_str());
            limiter.clear(&key);
        }
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for TieredRateLimiter
#[derive(Default)]
pub struct TieredRateLimiterBuilder {
    configs: HashMap<RateLimitTier, RateLimitTierConfig>,
    resolver: Option<Arc<dyn TierResolver>>,
    skip_paths: Vec<String>,
}

impl TieredRateLimiterBuilder {
    /// Configure the Auth tier (most restrictive - AC-7)
    pub fn auth_tier(mut self, max_requests: usize, window: Duration, lockout: Duration) -> Self {
        self.configs.insert(
            RateLimitTier::Auth,
            RateLimitTierConfig::new(max_requests, window, lockout),
        );
        self
    }

    /// Configure the Sensitive tier
    pub fn sensitive_tier(mut self, max_requests: usize, window: Duration, lockout: Duration) -> Self {
        self.configs.insert(
            RateLimitTier::Sensitive,
            RateLimitTierConfig::new(max_requests, window, lockout),
        );
        self
    }

    /// Configure the Standard tier
    pub fn standard_tier(mut self, max_requests: usize, window: Duration, lockout: Duration) -> Self {
        self.configs.insert(
            RateLimitTier::Standard,
            RateLimitTierConfig::new(max_requests, window, lockout),
        );
        self
    }

    /// Configure the Relaxed tier (least restrictive)
    pub fn relaxed_tier(mut self, max_requests: usize, window: Duration, lockout: Duration) -> Self {
        self.configs.insert(
            RateLimitTier::Relaxed,
            RateLimitTierConfig::new(max_requests, window, lockout),
        );
        self
    }

    /// Set a custom tier resolver
    pub fn resolver<R: TierResolver + 'static>(mut self, resolver: R) -> Self {
        self.resolver = Some(Arc::new(resolver));
        self
    }

    /// Add a path prefix to skip rate limiting
    pub fn skip_path(mut self, path: impl Into<String>) -> Self {
        self.skip_paths.push(path.into());
        self
    }

    /// Build the rate limiter
    pub fn build(self) -> TieredRateLimiter {
        let mut limiters = HashMap::new();

        // Add all tiers with defaults or custom configs
        for tier in [
            RateLimitTier::Auth,
            RateLimitTier::Sensitive,
            RateLimitTier::Standard,
            RateLimitTier::Relaxed,
        ] {
            let config = self.configs.get(&tier).cloned().unwrap_or_else(|| {
                let (max_requests, window) = tier.default_limits();
                RateLimitTierConfig::new(max_requests, window, tier.default_lockout())
            });
            limiters.insert(tier, Arc::new(TierRateLimiter::new(config)));
        }

        TieredRateLimiter {
            limiters: Arc::new(limiters),
            resolver: self.resolver.unwrap_or_else(|| Arc::new(DefaultTierResolver)),
            skip_paths: Arc::new(self.skip_paths),
        }
    }
}

// ============================================================================
// Axum Middleware
// ============================================================================

/// Rate limit response body
#[derive(Debug, Serialize)]
struct RateLimitErrorResponse {
    error: &'static str,
    message: String,
    tier: &'static str,
    retry_after_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_secs: Option<u64>,
}

/// Tiered rate limiting middleware for Axum
///
/// # Usage
///
/// ```ignore
/// use axum::Router;
/// use barbican::rate_limit::{TieredRateLimiter, tiered_rate_limit_middleware};
///
/// let limiter = TieredRateLimiter::default();
///
/// let app = Router::new()
///     .route("/api/v1/resource", get(handler))
///     .layer(axum::middleware::from_fn_with_state(
///         limiter,
///         tiered_rate_limit_middleware,
///     ));
/// ```
pub async fn tiered_rate_limit_middleware(
    State(limiter): State<TieredRateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().as_str();
    let ip = addr.ip();

    match limiter.check(ip, &path, method) {
        Ok((tier, status)) => {
            debug!(
                ip = %ip,
                path = %path,
                tier = tier.as_str(),
                remaining = status.remaining,
                limit = status.limit,
                "Rate limit check passed"
            );

            let mut response = next.run(request).await;

            // Add rate limit headers
            let headers = response.headers_mut();
            headers.insert(
                "X-RateLimit-Limit",
                status.limit.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-RateLimit-Remaining",
                status.remaining.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-RateLimit-Window",
                status.window_secs.to_string().parse().unwrap(),
            );

            response
        }
        Err((tier, error)) => {
            let (retry_after, message) = match &error {
                RateLimitError::LimitExceeded { lockout_secs } => {
                    warn!(
                        ip = %ip,
                        path = %path,
                        tier = tier.as_str(),
                        lockout_secs = lockout_secs,
                        "Rate limit exceeded - lockout initiated"
                    );
                    (*lockout_secs, format!("Rate limit exceeded. Try again in {} seconds.", lockout_secs))
                }
                RateLimitError::LockedOut { remaining_secs } => {
                    warn!(
                        ip = %ip,
                        path = %path,
                        tier = tier.as_str(),
                        remaining_secs = remaining_secs,
                        "Request rejected - currently locked out"
                    );
                    (*remaining_secs, format!("Too many requests. Try again in {} seconds.", remaining_secs))
                }
            };

            let (limit, window) = tier.default_limits();
            let error_response = RateLimitErrorResponse {
                error: "rate_limit_exceeded",
                message,
                tier: tier.as_str(),
                retry_after_secs: retry_after,
                limit: Some(limit),
                window_secs: Some(window.as_secs()),
            };

            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(error_response),
            ).into_response();

            response.headers_mut().insert(
                "Retry-After",
                retry_after.to_string().parse().unwrap(),
            );

            response
        }
    }
}

/// Variant middleware that extracts IP from X-Forwarded-For header
///
/// Use this when behind a reverse proxy
pub async fn tiered_rate_limit_middleware_with_proxy(
    State(limiter): State<TieredRateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request);
    let path = request.uri().path().to_string();
    let method = request.method().as_str();

    match limiter.check(ip, &path, method) {
        Ok((tier, status)) => {
            debug!(
                ip = %ip,
                path = %path,
                tier = tier.as_str(),
                remaining = status.remaining,
                "Rate limit check passed (proxy mode)"
            );

            let mut response = next.run(request).await;

            let headers = response.headers_mut();
            headers.insert(
                "X-RateLimit-Limit",
                status.limit.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-RateLimit-Remaining",
                status.remaining.to_string().parse().unwrap(),
            );

            response
        }
        Err((tier, error)) => {
            let retry_after = match &error {
                RateLimitError::LimitExceeded { lockout_secs } => *lockout_secs,
                RateLimitError::LockedOut { remaining_secs } => *remaining_secs,
            };

            warn!(
                ip = %ip,
                path = %path,
                tier = tier.as_str(),
                "Rate limit exceeded (proxy mode)"
            );

            let (limit, window) = tier.default_limits();
            let error_response = RateLimitErrorResponse {
                error: "rate_limit_exceeded",
                message: error.to_string(),
                tier: tier.as_str(),
                retry_after_secs: retry_after,
                limit: Some(limit),
                window_secs: Some(window.as_secs()),
            };

            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(error_response),
            ).into_response();

            response.headers_mut().insert(
                "Retry-After",
                retry_after.to_string().parse().unwrap(),
            );

            response
        }
    }
}

/// Extract client IP from request, checking proxy headers
fn extract_client_ip(request: &Request) -> IpAddr {
    // Check X-Forwarded-For header
    if let Some(xff) = request.headers().get("X-Forwarded-For") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first (leftmost) IP - the original client
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }

    // Check X-Real-IP header (nginx)
    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.trim().parse() {
                return ip;
            }
        }
    }

    // Fallback to loopback
    "127.0.0.1".parse().unwrap()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tier_from_path() {
        assert_eq!(RateLimitTier::from_path("/api/v1/auth/login"), RateLimitTier::Auth);
        assert_eq!(RateLimitTier::from_path("/api/v1/auth/token/refresh"), RateLimitTier::Auth);
        assert_eq!(RateLimitTier::from_path("/api/v1/oauth/callback"), RateLimitTier::Auth);
        assert_eq!(RateLimitTier::from_path("/api/v1/admin/users"), RateLimitTier::Sensitive);
        assert_eq!(RateLimitTier::from_path("/api/v1/users"), RateLimitTier::Sensitive);
        assert_eq!(RateLimitTier::from_path("/api/v1/keys/rotate"), RateLimitTier::Sensitive);
        assert_eq!(RateLimitTier::from_path("/health"), RateLimitTier::Relaxed);
        assert_eq!(RateLimitTier::from_path("/metrics"), RateLimitTier::Relaxed);
        assert_eq!(RateLimitTier::from_path("/api/v1/items"), RateLimitTier::Standard);
        assert_eq!(RateLimitTier::from_path("/api/v1/process"), RateLimitTier::Standard);
    }

    #[test]
    fn test_default_limiter() {
        let limiter = TieredRateLimiter::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First request should succeed
        let result = limiter.check(ip, "/api/v1/auth/login", "POST");
        assert!(result.is_ok());

        let (tier, status) = result.unwrap();
        assert_eq!(tier, RateLimitTier::Auth);
        assert_eq!(status.limit, 10);
        assert_eq!(status.remaining, 9);
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let limiter = TieredRateLimiter::builder()
            .auth_tier(2, Duration::from_secs(60), Duration::from_secs(30))
            .build();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // First two requests succeed
        assert!(limiter.check(ip, "/api/v1/auth/login", "POST").is_ok());
        assert!(limiter.check(ip, "/api/v1/auth/login", "POST").is_ok());

        // Third request should fail
        let result = limiter.check(ip, "/api/v1/auth/login", "POST");
        assert!(result.is_err());

        if let Err((tier, RateLimitError::LimitExceeded { lockout_secs })) = result {
            assert_eq!(tier, RateLimitTier::Auth);
            assert_eq!(lockout_secs, 30);
        } else {
            panic!("Expected LimitExceeded error");
        }
    }

    #[test]
    fn test_clear_on_success() {
        let limiter = TieredRateLimiter::builder()
            .auth_tier(2, Duration::from_secs(60), Duration::from_secs(30))
            .build();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Use up the limit
        assert!(limiter.check(ip, "/api/v1/auth/login", "POST").is_ok());
        assert!(limiter.check(ip, "/api/v1/auth/login", "POST").is_ok());

        // Clear after successful auth
        limiter.clear(ip, RateLimitTier::Auth);

        // Should be able to make requests again
        let result = limiter.check(ip, "/api/v1/auth/login", "POST");
        assert!(result.is_ok());
    }

    #[test]
    fn test_skip_paths() {
        let limiter = TieredRateLimiter::builder()
            .skip_path("/health")
            .skip_path("/metrics")
            .build();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        // Skipped paths should always succeed with max remaining
        for _ in 0..100 {
            let result = limiter.check(ip, "/health", "GET");
            assert!(result.is_ok());
            let (_, status) = result.unwrap();
            assert_eq!(status.remaining, usize::MAX);
        }
    }

    #[test]
    fn test_different_tiers_independent() {
        let limiter = TieredRateLimiter::builder()
            .auth_tier(2, Duration::from_secs(60), Duration::from_secs(30))
            .standard_tier(5, Duration::from_secs(60), Duration::from_secs(30))
            .build();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

        // Exhaust auth tier
        assert!(limiter.check(ip, "/api/v1/auth/login", "POST").is_ok());
        assert!(limiter.check(ip, "/api/v1/auth/login", "POST").is_ok());
        assert!(limiter.check(ip, "/api/v1/auth/login", "POST").is_err());

        // Standard tier should still work
        assert!(limiter.check(ip, "/api/v1/items", "GET").is_ok());
        assert!(limiter.check(ip, "/api/v1/items", "GET").is_ok());
    }
}
