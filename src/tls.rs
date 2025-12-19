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
// Mutual TLS (mTLS) Support (IA-3, SC-8 for FedRAMP High)
// ============================================================================

/// mTLS enforcement mode
///
/// Controls how strictly the middleware enforces client certificates.
/// FedRAMP High requires mTLS for all service-to-service communications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum MtlsMode {
    /// No client certificate required (default)
    #[default]
    Disabled,

    /// Client certificate optional (log if missing)
    Optional,

    /// Client certificate required (reject if missing/invalid)
    /// Required for FedRAMP High IA-3 compliance
    Required,
}

impl MtlsMode {
    /// Parse from string (case-insensitive)
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "disabled" | "off" | "none" | "false" | "0" => Some(Self::Disabled),
            "optional" | "verify" | "request" => Some(Self::Optional),
            "required" | "require" | "on" | "true" | "1" | "strict" => Some(Self::Required),
            _ => None,
        }
    }

    /// Check if this mode requires valid client certificates
    pub fn requires_cert(&self) -> bool {
        matches!(self, Self::Required)
    }

    /// Check if this mode is compliant with FedRAMP High IA-3
    pub fn is_fedramp_high_compliant(&self) -> bool {
        matches!(self, Self::Required)
    }
}

impl fmt::Display for MtlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Optional => write!(f, "optional"),
            Self::Required => write!(f, "required"),
        }
    }
}

/// Client certificate information from proxy headers
#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    /// Whether a client certificate was presented
    pub cert_present: bool,

    /// Whether the certificate was successfully verified
    pub cert_verified: bool,

    /// Client certificate subject DN (if available)
    pub subject_dn: Option<String>,

    /// Client certificate fingerprint (if available)
    pub fingerprint: Option<String>,

    /// Which header was used for detection
    pub detected_via: Option<String>,

    /// Verification status message from proxy
    pub verify_status: Option<String>,
}

impl ClientCertInfo {
    /// Create info for no client certificate
    pub fn none() -> Self {
        Self {
            cert_present: false,
            cert_verified: false,
            subject_dn: None,
            fingerprint: None,
            detected_via: None,
            verify_status: None,
        }
    }

    /// Create info for a verified certificate
    pub fn verified(subject_dn: String, detected_via: &str) -> Self {
        Self {
            cert_present: true,
            cert_verified: true,
            subject_dn: Some(subject_dn),
            fingerprint: None,
            detected_via: Some(detected_via.to_string()),
            verify_status: Some("SUCCESS".to_string()),
        }
    }

    /// Create info for a failed verification
    pub fn failed(status: &str, detected_via: &str) -> Self {
        Self {
            cert_present: true,
            cert_verified: false,
            subject_dn: None,
            fingerprint: None,
            detected_via: Some(detected_via.to_string()),
            verify_status: Some(status.to_string()),
        }
    }
}

/// Detect client certificate from proxy headers
///
/// Checks headers typically set by reverse proxies for mTLS:
/// - `X-Client-Verify` - nginx: "SUCCESS", "FAILED", "NONE"
/// - `X-SSL-Client-Verify` - Apache: "SUCCESS", "GENEROUS", etc.
/// - `X-Client-Cert-Subject` or `X-SSL-Client-S-DN` - Subject DN
/// - `X-Client-Cert-Fingerprint` - Certificate fingerprint
pub fn detect_client_cert(request: &Request<Body>) -> ClientCertInfo {
    let headers = request.headers();

    // Check nginx-style headers first
    if let Some(verify) = headers.get("x-client-verify") {
        if let Ok(verify_str) = verify.to_str() {
            let verified = verify_str.eq_ignore_ascii_case("SUCCESS");
            let cert_present = !verify_str.eq_ignore_ascii_case("NONE");

            if verified {
                // Get subject DN if available
                let subject_dn = headers
                    .get("x-client-cert-subject")
                    .or_else(|| headers.get("x-ssl-client-s-dn"))
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);

                let mut info = ClientCertInfo::verified(
                    subject_dn.unwrap_or_else(|| "[verified]".to_string()),
                    "X-Client-Verify",
                );

                // Add fingerprint if available
                info.fingerprint = headers
                    .get("x-client-cert-fingerprint")
                    .or_else(|| headers.get("x-ssl-client-fingerprint"))
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);

                return info;
            } else if cert_present {
                return ClientCertInfo::failed(verify_str, "X-Client-Verify");
            }
        }
    }

    // Check Apache-style headers
    if let Some(verify) = headers.get("x-ssl-client-verify") {
        if let Ok(verify_str) = verify.to_str() {
            let verified = verify_str.eq_ignore_ascii_case("SUCCESS")
                || verify_str.eq_ignore_ascii_case("GENEROUS");
            let cert_present = !verify_str.eq_ignore_ascii_case("NONE");

            if verified {
                let subject_dn = headers
                    .get("x-ssl-client-s-dn")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);

                return ClientCertInfo::verified(
                    subject_dn.unwrap_or_else(|| "[verified]".to_string()),
                    "X-SSL-Client-Verify",
                );
            } else if cert_present {
                return ClientCertInfo::failed(verify_str, "X-SSL-Client-Verify");
            }
        }
    }

    // Check if client cert header exists (some proxies just forward the cert)
    if headers.contains_key("x-client-cert") || headers.contains_key("x-ssl-client-cert") {
        // Certificate was presented but we can't verify it here
        // (verification should be done by the proxy)
        return ClientCertInfo {
            cert_present: true,
            cert_verified: false,
            subject_dn: None,
            fingerprint: None,
            detected_via: Some("X-Client-Cert (unverified)".to_string()),
            verify_status: Some("UNVERIFIED".to_string()),
        };
    }

    // No client certificate detected
    ClientCertInfo::none()
}

/// mTLS enforcement middleware
///
/// Enforces client certificate requirements based on the configured mode.
/// Use with `axum::middleware::from_fn`.
///
/// # Controls
///
/// - **IA-3**: Device Identification and Authentication
/// - **SC-8**: Transmission Confidentiality and Integrity (mTLS)
///
/// # Example
///
/// ```ignore
/// use barbican::tls::{MtlsMode, mtls_enforcement_middleware};
/// use axum::{Router, middleware};
///
/// let app = Router::new()
///     .route("/api/internal", get(handler))
///     .layer(middleware::from_fn(move |req, next| {
///         mtls_enforcement_middleware(req, next, MtlsMode::Required)
///     }));
/// ```
pub async fn mtls_enforcement_middleware(
    request: Request,
    next: Next,
    mode: MtlsMode,
) -> Response {
    // Disabled mode - pass through
    if matches!(mode, MtlsMode::Disabled) {
        return next.run(request).await;
    }

    let client_ip = extract_client_ip(&request);
    let path = request.uri().path().to_string();
    let cert_info = detect_client_cert(&request);

    match mode {
        MtlsMode::Disabled => next.run(request).await,

        MtlsMode::Optional => {
            if !cert_info.cert_present {
                tracing::debug!(
                    client_ip = %client_ip,
                    path = %path,
                    "mTLS: No client certificate (optional mode)"
                );
            } else if !cert_info.cert_verified {
                tracing::warn!(
                    security_event = "mtls_cert_invalid",
                    client_ip = %client_ip,
                    path = %path,
                    verify_status = ?cert_info.verify_status,
                    "mTLS: Client certificate not verified"
                );
            } else {
                tracing::debug!(
                    client_ip = %client_ip,
                    path = %path,
                    subject = ?cert_info.subject_dn,
                    "mTLS: Valid client certificate"
                );
            }
            next.run(request).await
        }

        MtlsMode::Required => {
            if !cert_info.cert_present {
                log_mtls_rejection(&client_ip, &path, "No client certificate presented");
                return (
                    StatusCode::FORBIDDEN,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"error":"client_certificate_required","message":"mTLS client certificate required (IA-3)"}"#,
                )
                    .into_response();
            }

            if !cert_info.cert_verified {
                log_mtls_rejection(
                    &client_ip,
                    &path,
                    &format!(
                        "Client certificate not verified: {:?}",
                        cert_info.verify_status
                    ),
                );
                return (
                    StatusCode::FORBIDDEN,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"error":"client_certificate_invalid","message":"Valid mTLS client certificate required"}"#,
                )
                    .into_response();
            }

            // Log successful mTLS authentication
            tracing::info!(
                security_event = "mtls_authenticated",
                category = "authentication",
                client_ip = %client_ip,
                path = %path,
                subject = ?cert_info.subject_dn,
                fingerprint = ?cert_info.fingerprint,
                control = "IA-3",
                "mTLS: Client authenticated via certificate"
            );

            next.run(request).await
        }
    }
}

/// Log mTLS enforcement rejection
fn log_mtls_rejection(client_ip: &str, path: &str, reason: &str) {
    tracing::warn!(
        security_event = SecurityEvent::AuthenticationFailure.name(),
        category = "authentication",
        severity = "high",
        client_ip = %client_ip,
        path = %path,
        reason = %reason,
        control = "IA-3",
        "mTLS enforcement: request rejected"
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

    // ========================================================================
    // mTLS Tests (IA-3, SC-8)
    // ========================================================================

    #[test]
    fn test_mtls_mode_from_str() {
        assert_eq!(MtlsMode::from_str_loose("disabled"), Some(MtlsMode::Disabled));
        assert_eq!(MtlsMode::from_str_loose("off"), Some(MtlsMode::Disabled));
        assert_eq!(MtlsMode::from_str_loose("optional"), Some(MtlsMode::Optional));
        assert_eq!(MtlsMode::from_str_loose("verify"), Some(MtlsMode::Optional));
        assert_eq!(MtlsMode::from_str_loose("required"), Some(MtlsMode::Required));
        assert_eq!(MtlsMode::from_str_loose("strict"), Some(MtlsMode::Required));
        assert_eq!(MtlsMode::from_str_loose("invalid"), None);
    }

    #[test]
    fn test_mtls_mode_requires_cert() {
        assert!(!MtlsMode::Disabled.requires_cert());
        assert!(!MtlsMode::Optional.requires_cert());
        assert!(MtlsMode::Required.requires_cert());
    }

    #[test]
    fn test_mtls_mode_fedramp_high_compliant() {
        assert!(!MtlsMode::Disabled.is_fedramp_high_compliant());
        assert!(!MtlsMode::Optional.is_fedramp_high_compliant());
        assert!(MtlsMode::Required.is_fedramp_high_compliant());
    }

    #[test]
    fn test_mtls_mode_display() {
        assert_eq!(MtlsMode::Disabled.to_string(), "disabled");
        assert_eq!(MtlsMode::Optional.to_string(), "optional");
        assert_eq!(MtlsMode::Required.to_string(), "required");
    }

    #[test]
    fn test_mtls_mode_default() {
        assert_eq!(MtlsMode::default(), MtlsMode::Disabled);
    }

    #[test]
    fn test_detect_client_cert_none() {
        let req = make_plain_request();
        let info = detect_client_cert(&req);
        assert!(!info.cert_present);
        assert!(!info.cert_verified);
        assert!(info.subject_dn.is_none());
    }

    #[test]
    fn test_detect_client_cert_nginx_success() {
        let req = Request::builder()
            .uri("/test")
            .header("X-Client-Verify", "SUCCESS")
            .header("X-Client-Cert-Subject", "CN=test-service,O=Acme")
            .body(Body::empty())
            .unwrap();
        let info = detect_client_cert(&req);
        assert!(info.cert_present);
        assert!(info.cert_verified);
        assert_eq!(info.subject_dn, Some("CN=test-service,O=Acme".to_string()));
        assert_eq!(info.detected_via, Some("X-Client-Verify".to_string()));
    }

    #[test]
    fn test_detect_client_cert_nginx_failed() {
        let req = Request::builder()
            .uri("/test")
            .header("X-Client-Verify", "FAILED:unable to verify")
            .body(Body::empty())
            .unwrap();
        let info = detect_client_cert(&req);
        assert!(info.cert_present);
        assert!(!info.cert_verified);
        assert_eq!(info.verify_status, Some("FAILED:unable to verify".to_string()));
    }

    #[test]
    fn test_detect_client_cert_nginx_none() {
        let req = make_request_with_header("X-Client-Verify", "NONE");
        let info = detect_client_cert(&req);
        assert!(!info.cert_present);
        assert!(!info.cert_verified);
    }

    #[test]
    fn test_detect_client_cert_apache_success() {
        let req = Request::builder()
            .uri("/test")
            .header("X-SSL-Client-Verify", "SUCCESS")
            .header("X-SSL-Client-S-DN", "CN=api-gateway,O=Corp")
            .body(Body::empty())
            .unwrap();
        let info = detect_client_cert(&req);
        assert!(info.cert_present);
        assert!(info.cert_verified);
        assert_eq!(info.subject_dn, Some("CN=api-gateway,O=Corp".to_string()));
        assert_eq!(info.detected_via, Some("X-SSL-Client-Verify".to_string()));
    }

    #[test]
    fn test_detect_client_cert_with_fingerprint() {
        let req = Request::builder()
            .uri("/test")
            .header("X-Client-Verify", "SUCCESS")
            .header("X-Client-Cert-Subject", "CN=service")
            .header("X-Client-Cert-Fingerprint", "SHA256:abc123")
            .body(Body::empty())
            .unwrap();
        let info = detect_client_cert(&req);
        assert!(info.cert_verified);
        assert_eq!(info.fingerprint, Some("SHA256:abc123".to_string()));
    }

    #[test]
    fn test_detect_client_cert_unverified() {
        let req = make_request_with_header("X-Client-Cert", "-----BEGIN CERT-----");
        let info = detect_client_cert(&req);
        assert!(info.cert_present);
        assert!(!info.cert_verified);
        assert_eq!(info.verify_status, Some("UNVERIFIED".to_string()));
    }

    #[test]
    fn test_client_cert_info_constructors() {
        let none = ClientCertInfo::none();
        assert!(!none.cert_present);
        assert!(!none.cert_verified);

        let verified = ClientCertInfo::verified("CN=test".to_string(), "X-Client-Verify");
        assert!(verified.cert_present);
        assert!(verified.cert_verified);
        assert_eq!(verified.subject_dn, Some("CN=test".to_string()));

        let failed = ClientCertInfo::failed("EXPIRED", "X-Client-Verify");
        assert!(failed.cert_present);
        assert!(!failed.cert_verified);
        assert_eq!(failed.verify_status, Some("EXPIRED".to_string()));
    }
}
