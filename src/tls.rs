//! HTTP TLS Enforcement (SC-8, SC-8(1))
//!
//! Middleware to enforce HTTPS transport security at the application level.
//!
//! # NIST 800-53 Controls
//!
//! - **SC-8**: Transmission Confidentiality - Enforces encrypted transport
//! - **SC-8(1)**: Cryptographic Protection - Validates TLS version requirements
//!
//! # Design Philosophy
//!
//! In production, TLS termination typically happens at a reverse proxy (nginx,
//! Caddy, cloud load balancer). This middleware verifies that requests came
//! through HTTPS by checking proxy headers.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::tls::{TlsMode, tls_enforcement_middleware};
//! use axum::{Router, middleware};
//!
//! let app = Router::new()
//!     .route("/", get(handler))
//!     .layer(middleware::from_fn(move |req, next| {
//!         tls_enforcement_middleware(req, next, TlsMode::Required)
//!     }));
//! ```
//!
//! # Header Detection
//!
//! The middleware checks these headers (in order):
//! 1. `X-Forwarded-Proto` - Standard proxy header
//! 2. `X-Forwarded-Ssl` - Legacy header ("on" = HTTPS)
//! 3. `CF-Visitor` - Cloudflare header (`{"scheme":"https"}`)

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::audit::extract_client_ip;
use crate::observability::SecurityEvent;

// ============================================================================
// TLS Mode Configuration
// ============================================================================

/// TLS enforcement mode (SC-8)
///
/// Controls how strictly the middleware enforces HTTPS transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TlsMode {
    /// No TLS enforcement (development only)
    ///
    /// WARNING: Never use in production. Allows all HTTP traffic.
    Disabled,

    /// Log warnings but allow HTTP traffic
    ///
    /// Useful for gradual rollout or debugging. Logs a security event
    /// for each non-HTTPS request but does not block.
    Opportunistic,

    /// Require HTTPS, reject HTTP requests (production default)
    ///
    /// Returns 421 Misdirected Request for non-HTTPS traffic.
    #[default]
    Required,

    /// Strict mode: Required + TLS version validation
    ///
    /// In addition to requiring HTTPS, validates that the TLS version
    /// meets minimum requirements (TLS 1.2+) via headers if available.
    Strict,
}

impl TlsMode {
    /// Parse from string (case-insensitive)
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "disabled" | "off" | "none" | "false" | "0" => Some(Self::Disabled),
            "opportunistic" | "warn" | "log" => Some(Self::Opportunistic),
            "required" | "require" | "on" | "true" | "1" => Some(Self::Required),
            "strict" | "enforce" | "full" => Some(Self::Strict),
            _ => None,
        }
    }

    /// Check if this mode enforces TLS (rejects HTTP)
    pub fn enforces(&self) -> bool {
        matches!(self, Self::Required | Self::Strict)
    }

    /// Check if this mode is compliant with SC-8
    pub fn is_compliant(&self) -> bool {
        matches!(self, Self::Required | Self::Strict)
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Opportunistic => write!(f, "opportunistic"),
            Self::Required => write!(f, "required"),
            Self::Strict => write!(f, "strict"),
        }
    }
}

// ============================================================================
// TLS Detection Result
// ============================================================================

/// Result of TLS detection from request headers
#[derive(Debug, Clone)]
pub struct TlsInfo {
    /// Whether the request came over HTTPS
    pub is_https: bool,

    /// Detected TLS version (if available from headers)
    pub tls_version: Option<String>,

    /// Which header was used for detection
    pub detected_via: Option<String>,
}

impl TlsInfo {
    /// Create info indicating HTTPS was detected
    pub fn https(detected_via: impl Into<String>) -> Self {
        Self {
            is_https: true,
            tls_version: None,
            detected_via: Some(detected_via.into()),
        }
    }

    /// Create info indicating HTTP (no TLS)
    pub fn http() -> Self {
        Self {
            is_https: false,
            tls_version: None,
            detected_via: None,
        }
    }

    /// Set TLS version
    pub fn with_tls_version(mut self, version: impl Into<String>) -> Self {
        self.tls_version = Some(version.into());
        self
    }
}

// ============================================================================
// TLS Detection Logic
// ============================================================================

/// Detect if request came over HTTPS by checking proxy headers
///
/// Checks headers in this order:
/// 1. `X-Forwarded-Proto` - Standard, set by most proxies
/// 2. `X-Forwarded-Ssl` - Legacy, "on" means HTTPS
/// 3. `CF-Visitor` - Cloudflare, JSON with scheme field
///
/// Returns `TlsInfo` with detection result and source.
pub fn detect_tls(request: &Request<Body>) -> TlsInfo {
    let headers = request.headers();

    // 1. X-Forwarded-Proto (standard)
    if let Some(proto) = headers.get("x-forwarded-proto") {
        if let Ok(proto_str) = proto.to_str() {
            let is_https = proto_str.eq_ignore_ascii_case("https");
            return TlsInfo {
                is_https,
                tls_version: None,
                detected_via: Some("X-Forwarded-Proto".to_string()),
            };
        }
    }

    // 2. X-Forwarded-Ssl (legacy)
    if let Some(ssl) = headers.get("x-forwarded-ssl") {
        if let Ok(ssl_str) = ssl.to_str() {
            let is_https = ssl_str.eq_ignore_ascii_case("on");
            return TlsInfo {
                is_https,
                tls_version: None,
                detected_via: Some("X-Forwarded-Ssl".to_string()),
            };
        }
    }

    // 3. CF-Visitor (Cloudflare)
    if let Some(cf_visitor) = headers.get("cf-visitor") {
        if let Ok(cf_str) = cf_visitor.to_str() {
            // Parse JSON: {"scheme":"https"}
            if cf_str.contains("\"https\"") {
                return TlsInfo {
                    is_https: true,
                    tls_version: None,
                    detected_via: Some("CF-Visitor".to_string()),
                };
            } else if cf_str.contains("\"http\"") {
                return TlsInfo {
                    is_https: false,
                    tls_version: None,
                    detected_via: Some("CF-Visitor".to_string()),
                };
            }
        }
    }

    // 4. Check request URI scheme directly (for direct TLS connections)
    if let Some(scheme) = request.uri().scheme_str() {
        if scheme.eq_ignore_ascii_case("https") {
            return TlsInfo::https("URI scheme");
        }
    }

    // No TLS indicators found - assume HTTP
    TlsInfo::http()
}

/// Detect TLS version from headers (if available)
///
/// Some proxies/CDNs provide TLS version information:
/// - `X-SSL-Protocol` - Common proxy header
/// - `CF-SSL-Protocol` - Cloudflare (if configured)
pub fn detect_tls_version(request: &Request<Body>) -> Option<String> {
    let headers = request.headers();

    // X-SSL-Protocol
    if let Some(proto) = headers.get("x-ssl-protocol") {
        if let Ok(proto_str) = proto.to_str() {
            return Some(proto_str.to_string());
        }
    }

    // CF-SSL-Protocol (Cloudflare)
    if let Some(proto) = headers.get("cf-ssl-protocol") {
        if let Ok(proto_str) = proto.to_str() {
            return Some(proto_str.to_string());
        }
    }

    None
}

/// Check if TLS version meets minimum requirements
///
/// Requires TLS 1.2 or higher. TLS 1.0 and 1.1 are considered insecure.
pub fn is_tls_version_acceptable(version: &str) -> bool {
    let version_lower = version.to_lowercase();

    // Accept TLS 1.2 and 1.3
    if version_lower.contains("1.3") || version_lower.contains("1.2") {
        return true;
    }

    // Reject TLS 1.0 and 1.1
    if version_lower.contains("1.0") || version_lower.contains("1.1") {
        return false;
    }

    // Accept TLSv1.2, TLSv1.3 format
    if version_lower.starts_with("tlsv1.2") || version_lower.starts_with("tlsv1.3") {
        return true;
    }

    // Unknown version - be permissive but log
    true
}

// ============================================================================
// Middleware
// ============================================================================

/// TLS enforcement middleware function
///
/// Use with `axum::middleware::from_fn`:
///
/// ```ignore
/// use axum::{Router, middleware};
/// use barbican::tls::{TlsMode, tls_enforcement_middleware};
///
/// let mode = TlsMode::Required;
/// let app = Router::new()
///     .layer(middleware::from_fn(move |req, next| {
///         tls_enforcement_middleware(req, next, mode)
///     }));
/// ```
///
/// # Behavior by Mode
///
/// - `Disabled`: Pass through all requests
/// - `Opportunistic`: Log warning for HTTP, pass through
/// - `Required`: Return 421 for HTTP requests
/// - `Strict`: Return 421 for HTTP or weak TLS versions
pub async fn tls_enforcement_middleware(
    request: Request,
    next: Next,
    mode: TlsMode,
) -> Response {
    // Disabled mode - pass through
    if mode == TlsMode::Disabled {
        return next.run(request).await;
    }

    let tls_info = detect_tls(&request);
    let path = request.uri().path().to_string();
    let client_ip = extract_client_ip(&request);

    // Check HTTPS requirement
    if !tls_info.is_https {
        match mode {
            TlsMode::Disabled => {
                // Already handled above
            }
            TlsMode::Opportunistic => {
                // Log warning but allow
                log_tls_warning(&path, &client_ip, "HTTP request to HTTPS-preferred endpoint");
                return next.run(request).await;
            }
            TlsMode::Required | TlsMode::Strict => {
                // Reject HTTP
                log_tls_rejected(&path, &client_ip, "HTTPS required");
                return tls_required_response();
            }
        }
    }

    // Strict mode: also check TLS version
    if mode == TlsMode::Strict {
        if let Some(tls_version) = detect_tls_version(&request) {
            if !is_tls_version_acceptable(&tls_version) {
                log_tls_rejected(&path, &client_ip, &format!("TLS version {} not acceptable", tls_version));
                return tls_version_response(&tls_version);
            }
        }
    }

    // TLS requirements met - proceed
    next.run(request).await
}

/// Generate 421 Misdirected Request response for non-HTTPS
fn tls_required_response() -> Response {
    let body = r#"{"error":"tls_required","message":"HTTPS is required for this endpoint"}"#;

    Response::builder()
        .status(StatusCode::MISDIRECTED_REQUEST) // 421
        .header(header::CONTENT_TYPE, "application/json")
        .header("Upgrade", "TLS/1.2, TLS/1.3")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::MISDIRECTED_REQUEST.into_response())
}

/// Generate response for unacceptable TLS version
fn tls_version_response(version: &str) -> Response {
    let body = format!(
        r#"{{"error":"tls_version_rejected","message":"TLS version {} is not acceptable. Minimum TLS 1.2 required.","minimum_version":"TLS 1.2"}}"#,
        version
    );

    Response::builder()
        .status(StatusCode::MISDIRECTED_REQUEST) // 421
        .header(header::CONTENT_TYPE, "application/json")
        .header("Upgrade", "TLS/1.2, TLS/1.3")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::MISDIRECTED_REQUEST.into_response())
}

// ============================================================================
// Security Event Logging (AU-2, AU-3)
// ============================================================================

/// Log TLS warning (opportunistic mode)
fn log_tls_warning(path: &str, client_ip: &str, reason: &str) {
    tracing::warn!(
        security_event = SecurityEvent::SuspiciousActivity.name(),
        category = "security",
        severity = "medium",
        path = %path,
        client_ip = %client_ip,
        reason = %reason,
        "TLS warning: non-HTTPS request"
    );
}

/// Log TLS rejection
fn log_tls_rejected(path: &str, client_ip: &str, reason: &str) {
    crate::security_event!(
        SecurityEvent::AccessDenied,
        path = %path,
        client_ip = %client_ip,
        reason = %reason,
        control = "SC-8",
        "TLS enforcement: request rejected"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn make_request_with_header(header: &str, value: &str) -> Request<Body> {
        Request::builder()
            .uri("/test")
            .header(header, value)
            .body(Body::empty())
            .unwrap()
    }

    fn make_plain_request() -> Request<Body> {
        Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn test_tls_mode_from_str() {
        assert_eq!(TlsMode::from_str_loose("disabled"), Some(TlsMode::Disabled));
        assert_eq!(TlsMode::from_str_loose("off"), Some(TlsMode::Disabled));
        assert_eq!(TlsMode::from_str_loose("required"), Some(TlsMode::Required));
        assert_eq!(TlsMode::from_str_loose("STRICT"), Some(TlsMode::Strict));
        assert_eq!(TlsMode::from_str_loose("invalid"), None);
    }

    #[test]
    fn test_tls_mode_enforces() {
        assert!(!TlsMode::Disabled.enforces());
        assert!(!TlsMode::Opportunistic.enforces());
        assert!(TlsMode::Required.enforces());
        assert!(TlsMode::Strict.enforces());
    }

    #[test]
    fn test_tls_mode_compliant() {
        assert!(!TlsMode::Disabled.is_compliant());
        assert!(!TlsMode::Opportunistic.is_compliant());
        assert!(TlsMode::Required.is_compliant());
        assert!(TlsMode::Strict.is_compliant());
    }

    #[test]
    fn test_detect_tls_x_forwarded_proto_https() {
        let req = make_request_with_header("X-Forwarded-Proto", "https");
        let info = detect_tls(&req);
        assert!(info.is_https);
        assert_eq!(info.detected_via, Some("X-Forwarded-Proto".to_string()));
    }

    #[test]
    fn test_detect_tls_x_forwarded_proto_http() {
        let req = make_request_with_header("X-Forwarded-Proto", "http");
        let info = detect_tls(&req);
        assert!(!info.is_https);
        assert_eq!(info.detected_via, Some("X-Forwarded-Proto".to_string()));
    }

    #[test]
    fn test_detect_tls_x_forwarded_ssl() {
        let req = make_request_with_header("X-Forwarded-Ssl", "on");
        let info = detect_tls(&req);
        assert!(info.is_https);
        assert_eq!(info.detected_via, Some("X-Forwarded-Ssl".to_string()));
    }

    #[test]
    fn test_detect_tls_cf_visitor_https() {
        let req = make_request_with_header("CF-Visitor", r#"{"scheme":"https"}"#);
        let info = detect_tls(&req);
        assert!(info.is_https);
        assert_eq!(info.detected_via, Some("CF-Visitor".to_string()));
    }

    #[test]
    fn test_detect_tls_cf_visitor_http() {
        let req = make_request_with_header("CF-Visitor", r#"{"scheme":"http"}"#);
        let info = detect_tls(&req);
        assert!(!info.is_https);
    }

    #[test]
    fn test_detect_tls_no_headers() {
        let req = make_plain_request();
        let info = detect_tls(&req);
        assert!(!info.is_https);
        assert!(info.detected_via.is_none());
    }

    #[test]
    fn test_tls_version_acceptable() {
        assert!(is_tls_version_acceptable("TLSv1.3"));
        assert!(is_tls_version_acceptable("TLSv1.2"));
        assert!(is_tls_version_acceptable("TLS 1.3"));
        assert!(is_tls_version_acceptable("TLS 1.2"));
        assert!(!is_tls_version_acceptable("TLSv1.1"));
        assert!(!is_tls_version_acceptable("TLSv1.0"));
        assert!(!is_tls_version_acceptable("TLS 1.0"));
    }

    #[test]
    fn test_tls_mode_display() {
        assert_eq!(TlsMode::Disabled.to_string(), "disabled");
        assert_eq!(TlsMode::Required.to_string(), "required");
        assert_eq!(TlsMode::Strict.to_string(), "strict");
    }

    #[test]
    fn test_tls_mode_default() {
        assert_eq!(TlsMode::default(), TlsMode::Required);
    }
}
