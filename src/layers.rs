//! Security layer application for Axum routers
//!
//! Provides the `SecureRouter` trait that wraps any router with security layers.

use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::Router;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

use crate::config::SecurityConfig;

/// Extension trait for applying security layers to an Axum Router.
///
/// This trait provides a single method `with_security` that applies all
/// NIST 800-53 compliant security controls to any Axum router.
///
/// # Example
///
/// ```ignore
/// use axum::{Router, routing::get};
/// use barbican::{SecurityConfig, SecureRouter};
///
/// async fn handler() -> &'static str { "Hello" }
///
/// let config = SecurityConfig::from_env();
/// let app = Router::new()
///     .route("/", get(handler))
///     .with_security(config);
/// ```
pub trait SecureRouter {
    /// Apply all security layers based on the provided configuration.
    ///
    /// Layers are applied in the correct order for proper security:
    /// 1. TraceLayer (outermost - logs all requests)
    /// 2. CorsLayer (handles preflight)
    /// 3. Security Headers
    /// 4. Rate Limiting
    /// 5. Request Body Limit
    /// 6. Timeout (innermost)
    fn with_security(self, config: SecurityConfig) -> Self;
}

impl<S> SecureRouter for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn with_security(self, config: SecurityConfig) -> Self {
        let mut router = self;

        // SC-5: Request Timeout - NIST 800-53 SC-10
        router = router.layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.request_timeout,
        ));

        // SC-4: Request Body Size Limit - NIST 800-53 SC-5
        router = router.layer(RequestBodyLimitLayer::new(config.max_request_size));

        // SC-3: Rate Limiting - NIST 800-53 SC-5, FedRAMP SC-5
        if config.rate_limit_enabled {
            let rate_limit_config = GovernorConfigBuilder::default()
                .per_second(config.rate_limit_per_second)
                .burst_size(config.rate_limit_burst)
                .finish()
                .expect("Invalid rate limiter configuration");
            router = router.layer(GovernorLayer::new(rate_limit_config));
        }

        // SC-2: Security Headers - NIST 800-53 SC-28, SOC 2 CC6.1
        if config.security_headers_enabled {
            router = router
                // HSTS: Enforce HTTPS for 1 year, include subdomains
                .layer(SetResponseHeaderLayer::overriding(
                    header::STRICT_TRANSPORT_SECURITY,
                    HeaderValue::from_static("max-age=31536000; includeSubDomains"),
                ))
                // Prevent MIME type sniffing
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                // Prevent clickjacking
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                // Content Security Policy - restrictive default for API
                .layer(SetResponseHeaderLayer::overriding(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
                ))
                // Prevent caching of sensitive responses
                .layer(SetResponseHeaderLayer::overriding(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
                ))
                // Disable legacy XSS filter (CSP is preferred)
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_XSS_PROTECTION,
                    HeaderValue::from_static("0"),
                ));
        }

        // SC-6: CORS Policy - NIST 800-53 AC-4, SOC 2 CC6.6
        let cors_layer = build_cors_layer(&config);
        router = router.layer(cors_layer);

        // SC-7: Structured Logging - NIST 800-53 AU-2, AU-3, AU-12
        if config.tracing_enabled {
            router = router.layer(TraceLayer::new_for_http());
        }

        router
    }
}

/// Build CORS layer based on configuration
fn build_cors_layer(config: &SecurityConfig) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
        .max_age(std::time::Duration::from_secs(3600));

    if config.cors_is_restrictive() {
        // Same-origin only
        base
    } else if config.cors_is_permissive() {
        // Any origin (development only!)
        base.allow_origin(Any)
    } else {
        // Explicit allowlist
        let origins: Vec<HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|s| HeaderValue::from_str(s).ok())
            .collect();
        base.allow_origin(origins).allow_credentials(true)
    }
}
