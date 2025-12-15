# Proposal: SSRF Protection Module for Barbican

**Status**: Draft
**Author**: Claude
**Date**: 2025-12-15
**Security Controls**: SC-7 (Boundary Protection), SI-10 (Input Validation)

## Executive Summary

Server-Side Request Forgery (SSRF) attacks increased 452% between 2023-2024, driven by AI-powered exploitation tools. While Portcullis currently has no outbound HTTP client (eliminating direct SSRF risk), future features like `jwks_uri` fetching and `sector_identifier_uri` validation will require SSRF protection.

This proposal outlines a comprehensive `barbican::ssrf` module implementing defense-in-depth against SSRF attacks, suitable for any Rust application making server-initiated HTTP requests.

## Motivation

### Current State

Portcullis stores but never fetches:
- `jwks_uri` - Client JWKS for `private_key_jwt` validation
- `sector_identifier_uri` - OIDC pairwise subject calculation

If these features are implemented, SSRF becomes a critical attack vector.

### Attack Scenarios

1. **Cloud Metadata Theft**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. **Internal Service Access**: `http://192.168.1.1/admin/`
3. **Port Scanning**: Enumerate internal services via timing/error differences
4. **Protocol Smuggling**: `gopher://redis:6379/_*1%0d%0a$8%0d%0aflushall`

## Proposed Design

### Module Structure

```
barbican/src/ssrf/
├── mod.rs           # Public API, SsrfFilter struct
├── config.rs        # SsrfConfig with sensible defaults
├── ip.rs            # IP validation, range checking, normalization
├── dns.rs           # DNS resolution with rebinding protection
├── url.rs           # URL parsing and validation
├── redirect.rs      # Redirect policy and validation
└── client.rs        # SSRF-safe HTTP client wrapper (optional)
```

### Core API

```rust
use barbican::ssrf::{SsrfFilter, SsrfConfig, SsrfError};

// Create filter with defaults (blocks private IPs, metadata endpoints)
let filter = SsrfFilter::new(SsrfConfig::default());

// Validate a URL before fetching
let validated = filter.validate_url("https://example.com/jwks.json").await?;

// validated.url - Original URL
// validated.resolved_ip - Pinned IP address (DNS rebinding protection)
// validated.socket_addr - Ready for direct connection

// Or use the safe client wrapper
let client = filter.client();
let response = client.get("https://example.com/jwks.json").await?;
```

### Configuration

```rust
pub struct SsrfConfig {
    // === IP Blocking ===
    /// Block RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
    pub block_private: bool,                    // default: true

    /// Block loopback (127/8, ::1)
    pub block_loopback: bool,                   // default: true

    /// Block link-local (169.254/16, fe80::/10)
    pub block_link_local: bool,                 // default: true

    /// Block cloud metadata endpoints (169.254.169.254, metadata.google.internal)
    pub block_cloud_metadata: bool,             // default: true

    /// Additional CIDR ranges to block
    pub blocked_ranges: Vec<IpNetwork>,         // default: []

    /// Explicit IP allowlist (bypasses all blocking)
    pub allowed_ips: Vec<IpAddr>,               // default: []

    // === Domain Filtering ===
    /// Domain allowlist (empty = allow all public domains)
    pub allowed_domains: Vec<String>,           // default: []

    /// Domain denylist
    pub blocked_domains: Vec<String>,           // default: []

    // === Protocol/Scheme ===
    /// Allowed URL schemes
    pub allowed_schemes: Vec<String>,           // default: ["https"]

    /// Allow HTTP for specific domains (e.g., localhost in dev)
    pub http_allowed_domains: Vec<String>,      // default: []

    // === DNS Rebinding Protection ===
    /// Enable DNS pinning (resolve once, connect to resolved IP)
    pub dns_pinning: bool,                      // default: true

    /// Validate ALL IPs if DNS returns multiple A records
    pub validate_all_dns_results: bool,         // default: true

    /// Custom DNS resolver (None = system resolver)
    pub dns_resolver: Option<SocketAddr>,       // default: None

    /// Minimum DNS cache TTL (prevents 0-TTL rebinding)
    pub min_dns_ttl: Duration,                  // default: 300s

    // === Redirect Policy ===
    /// Maximum redirects to follow (0 = disable redirects)
    pub max_redirects: u8,                      // default: 0

    /// Re-validate URL after each redirect
    pub validate_redirects: bool,               // default: true

    /// Allow scheme downgrade (https → http)
    pub allow_scheme_downgrade: bool,           // default: false

    // === Response Limits ===
    /// Maximum response body size
    pub max_response_size: usize,               // default: 1MB

    /// Request timeout
    pub timeout: Duration,                      // default: 10s

    /// Connect timeout (separate from total timeout)
    pub connect_timeout: Duration,              // default: 5s
}
```

### IP Validation

Must handle all encoding bypass attempts:

```rust
/// Blocked IP ranges with all encoding normalizations
pub struct IpValidator {
    blocked_networks: Vec<IpNetwork>,
}

impl IpValidator {
    /// Parse and normalize IP from any representation
    /// Handles: decimal, octal, hex, mixed, IPv4-mapped IPv6
    pub fn parse_and_normalize(input: &str) -> Result<IpAddr, IpParseError>;

    /// Check if IP is in any blocked range
    pub fn is_blocked(&self, ip: &IpAddr) -> bool;

    /// For IPv4-mapped IPv6, extract and validate the inner IPv4
    pub fn unwrap_ipv4_mapped(ip: &Ipv6Addr) -> Option<Ipv4Addr>;
}

// Test cases that MUST pass:
#[cfg(test)]
mod tests {
    // All of these must be detected as localhost:
    assert!(is_localhost("127.0.0.1"));
    assert!(is_localhost("127.1"));
    assert!(is_localhost("127.0.1.0"));
    assert!(is_localhost("2130706433"));           // Decimal
    assert!(is_localhost("0x7f000001"));           // Hex
    assert!(is_localhost("0177.0.0.1"));           // Octal
    assert!(is_localhost("0x7f.0.0.1"));           // Mixed
    assert!(is_localhost("::1"));                   // IPv6
    assert!(is_localhost("[::1]"));                 // Bracketed IPv6
    assert!(is_localhost("::ffff:127.0.0.1"));     // IPv4-mapped
    assert!(is_localhost("[::ffff:7f00:1]"));      // IPv4-mapped hex

    // Cloud metadata detection:
    assert!(is_cloud_metadata("169.254.169.254"));
    assert!(is_cloud_metadata("0xa9fea9fe"));      // Hex encoding
    assert!(is_cloud_metadata("[::ffff:169.254.169.254]"));
}
```

### DNS Rebinding Protection

```rust
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    config: SsrfConfig,
    cache: DnsCache,
}

impl DnsResolver {
    /// Resolve hostname and validate ALL returned IPs
    /// Returns error if ANY IP is in blocked ranges
    pub async fn resolve_and_validate(
        &self,
        hostname: &str,
    ) -> Result<ResolvedHost, SsrfError> {
        // 1. Check domain allowlist/denylist
        self.validate_domain(hostname)?;

        // 2. Resolve DNS
        let ips = self.resolver.lookup_ip(hostname).await?;

        // 3. Validate ALL returned IPs (multi-A-record attack protection)
        for ip in ips.iter() {
            if self.ip_validator.is_blocked(&ip) {
                return Err(SsrfError::BlockedIp {
                    hostname: hostname.to_string(),
                    ip,
                    reason: self.ip_validator.block_reason(&ip),
                });
            }
        }

        // 4. Return first valid IP for pinning
        Ok(ResolvedHost {
            hostname: hostname.to_string(),
            ip: ips.iter().next().unwrap(),
            all_ips: ips.iter().collect(),
            resolved_at: Instant::now(),
        })
    }
}

/// Resolved and validated host, ready for connection
pub struct ResolvedHost {
    pub hostname: String,
    pub ip: IpAddr,
    pub all_ips: Vec<IpAddr>,
    pub resolved_at: Instant,
}
```

### URL Validation

```rust
pub struct UrlValidator {
    config: SsrfConfig,
    ip_validator: IpValidator,
}

impl UrlValidator {
    /// Validate URL format without DNS resolution
    pub fn validate_format(&self, url: &str) -> Result<Url, SsrfError> {
        let parsed = Url::parse(url)?;

        // Scheme check
        if !self.config.allowed_schemes.contains(&parsed.scheme().to_string()) {
            return Err(SsrfError::BlockedScheme(parsed.scheme().to_string()));
        }

        // Check for URL parsing tricks
        self.check_url_smuggling(&parsed)?;

        // If host is an IP literal, validate immediately
        if let Some(host) = parsed.host() {
            if let Host::Ipv4(ip) = host {
                self.ip_validator.validate(IpAddr::V4(ip))?;
            } else if let Host::Ipv6(ip) = host {
                self.ip_validator.validate(IpAddr::V6(ip))?;
            }
        }

        Ok(parsed)
    }

    /// Detect URL parsing inconsistencies
    fn check_url_smuggling(&self, url: &Url) -> Result<(), SsrfError> {
        let raw = url.as_str();

        // Detect backslash confusion
        if raw.contains('\\') {
            return Err(SsrfError::SuspiciousUrl("backslash in URL".into()));
        }

        // Detect @ confusion (user:pass@host vs host\@other)
        if raw.matches('@').count() > 1 {
            return Err(SsrfError::SuspiciousUrl("multiple @ symbols".into()));
        }

        // Detect fragment in authority
        // ... additional checks based on Orange Tsai research

        Ok(())
    }
}
```

### Redirect Handling

```rust
pub struct RedirectPolicy {
    config: SsrfConfig,
    filter: SsrfFilter,
}

impl RedirectPolicy {
    /// Validate a redirect target before following
    pub async fn validate_redirect(
        &self,
        from: &Url,
        to: &str,
        redirect_count: u8,
    ) -> Result<ValidatedUrl, SsrfError> {
        // Check redirect count
        if redirect_count >= self.config.max_redirects {
            return Err(SsrfError::TooManyRedirects(redirect_count));
        }

        let to_url = Url::parse(to).or_else(|_| from.join(to))?;

        // Check scheme downgrade
        if from.scheme() == "https" && to_url.scheme() == "http" {
            if !self.config.allow_scheme_downgrade {
                return Err(SsrfError::SchemeDowngrade);
            }
        }

        // Full validation of redirect target
        self.filter.validate_url(to_url.as_str()).await
    }
}
```

### Safe HTTP Client Wrapper (Optional)

```rust
/// SSRF-safe HTTP client that enforces all protections
pub struct SafeClient {
    inner: reqwest::Client,
    filter: SsrfFilter,
}

impl SafeClient {
    pub async fn get(&self, url: &str) -> Result<Response, SsrfError> {
        // 1. Validate and resolve URL
        let validated = self.filter.validate_url(url).await?;

        // 2. Build request with pinned IP
        let request = self.inner
            .get(url)
            .timeout(self.filter.config.timeout)
            // Connect directly to resolved IP, preserving Host header
            .resolve(&validated.hostname, validated.socket_addr)
            .build()?;

        // 3. Execute with response size limit
        let response = self.inner.execute(request).await?;

        // 4. Validate response size
        if let Some(len) = response.content_length() {
            if len > self.filter.config.max_response_size as u64 {
                return Err(SsrfError::ResponseTooLarge(len));
            }
        }

        Ok(response)
    }
}
```

## Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
    #[error("URL blocked: IP {ip} is in blocked range ({reason})")]
    BlockedIp {
        hostname: String,
        ip: IpAddr,
        reason: String,
    },

    #[error("URL blocked: scheme '{0}' not allowed")]
    BlockedScheme(String),

    #[error("URL blocked: domain '{0}' not in allowlist")]
    DomainNotAllowed(String),

    #[error("URL blocked: domain '{0}' is in denylist")]
    DomainBlocked(String),

    #[error("DNS resolution failed for '{hostname}': {source}")]
    DnsError {
        hostname: String,
        source: trust_dns_resolver::error::ResolveError,
    },

    #[error("Too many redirects ({0})")]
    TooManyRedirects(u8),

    #[error("Scheme downgrade from HTTPS to HTTP not allowed")]
    SchemeDowngrade,

    #[error("Response too large: {0} bytes")]
    ResponseTooLarge(u64),

    #[error("Request timeout")]
    Timeout,

    #[error("Suspicious URL pattern: {0}")]
    SuspiciousUrl(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}
```

## Configuration Presets

```rust
impl SsrfConfig {
    /// Maximum security - allowlist only
    pub fn strict() -> Self {
        Self {
            allowed_schemes: vec!["https".into()],
            max_redirects: 0,
            dns_pinning: true,
            ..Default::default()
        }
    }

    /// Balanced security for webhook/callback scenarios
    pub fn webhooks() -> Self {
        Self {
            allowed_schemes: vec!["https".into()],
            max_redirects: 2,
            validate_redirects: true,
            dns_pinning: true,
            ..Default::default()
        }
    }

    /// Development mode (allows localhost HTTP)
    pub fn development() -> Self {
        Self {
            allowed_schemes: vec!["https".into(), "http".into()],
            http_allowed_domains: vec!["localhost".into(), "127.0.0.1".into()],
            block_loopback: false,
            ..Default::default()
        }
    }
}
```

## Environment Variables

```bash
# IP blocking
SSRF_BLOCK_PRIVATE=true
SSRF_BLOCK_LOOPBACK=true
SSRF_BLOCK_LINK_LOCAL=true
SSRF_BLOCK_CLOUD_METADATA=true
SSRF_BLOCKED_RANGES=                    # Comma-separated CIDRs

# Domain filtering
SSRF_ALLOWED_DOMAINS=                   # Comma-separated (empty = allow all)
SSRF_BLOCKED_DOMAINS=                   # Comma-separated

# Protocol
SSRF_ALLOWED_SCHEMES=https              # Comma-separated

# DNS
SSRF_DNS_PINNING=true
SSRF_MIN_DNS_TTL=300
SSRF_DNS_RESOLVER=                      # Custom resolver IP:port

# Redirects
SSRF_MAX_REDIRECTS=0
SSRF_VALIDATE_REDIRECTS=true
SSRF_ALLOW_SCHEME_DOWNGRADE=false

# Limits
SSRF_MAX_RESPONSE_SIZE=1048576          # 1MB
SSRF_TIMEOUT=10
SSRF_CONNECT_TIMEOUT=5
```

## Dependencies

```toml
[dependencies]
trust-dns-resolver = "0.23"    # DNS resolution
ipnetwork = "0.20"             # CIDR range checking
url = "2"                      # URL parsing
reqwest = { version = "0.11", optional = true }  # HTTP client wrapper
thiserror = "1.0"
tracing = "0.1"
tokio = { version = "1", features = ["time"] }
```

## Test Plan

### Unit Tests

1. **IP Normalization**: All encoding variants (decimal, octal, hex, mixed, IPv6)
2. **Range Blocking**: RFC 1918, loopback, link-local, metadata
3. **IPv4-mapped IPv6**: Properly unwrap and validate inner address
4. **URL Parsing**: Detect smuggling attempts (backslash, multi-@, etc.)
5. **Domain Validation**: Allowlist/denylist enforcement

### Integration Tests

1. **DNS Rebinding**: Mock DNS server returning different IPs
2. **Multi-A-Record**: Validate ALL returned IPs are checked
3. **Redirect Chains**: Verify redirect validation at each hop
4. **Timeout Handling**: Slow responses don't bypass limits

### Fuzz Testing

1. **IP Parser Fuzzing**: Random strings to IP parser
2. **URL Parser Fuzzing**: Malformed URLs with special characters

## Security Considerations

### Known Bypass Techniques to Address

| Bypass | Mitigation |
|--------|------------|
| Decimal IP encoding | Normalize before validation |
| Octal IP encoding | Normalize before validation |
| Hex IP encoding | Normalize before validation |
| IPv4-mapped IPv6 | Unwrap and validate inner IP |
| DNS rebinding | DNS pinning + validate all A records |
| HTTP redirects | Disable or re-validate each hop |
| URL parser confusion | Strict parsing, reject ambiguous URLs |
| Short DNS TTL | Enforce minimum TTL in cache |
| Gopher/file schemes | Allowlist schemes (HTTPS only) |

### CVE Reference

- **CVE-2021-29922**: Rust std library IP parser accepted leading zeros (octal)
- Ensure normalization handles this and any similar edge cases

## Implementation Phases

### Phase 1: Core Validation
- IP normalization and range checking
- URL format validation
- Basic configuration

### Phase 2: DNS Protection
- DNS resolution with pinning
- Multi-A-record validation
- TTL enforcement

### Phase 3: HTTP Client Integration
- Optional reqwest wrapper
- Redirect handling
- Response limits

### Phase 4: Monitoring
- Metrics for blocked requests
- Logging with tracing
- Alert integration

## Usage in Portcullis

```rust
// In jwks_uri fetching (future feature)
use barbican::ssrf::{SsrfFilter, SsrfConfig};

async fn fetch_client_jwks(jwks_uri: &str) -> Result<Jwks, Error> {
    let filter = SsrfFilter::new(SsrfConfig::strict());

    // Validate URL and get pinned IP
    let validated = filter.validate_url(jwks_uri).await
        .map_err(|e| Error::InvalidJwksUri(e.to_string()))?;

    // Fetch with SSRF protection
    let client = filter.client();
    let response = client.get(jwks_uri).await?;

    // Parse JWKS
    let jwks: Jwks = response.json().await?;
    Ok(jwks)
}
```

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [HackTricks URL Format Bypass](https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass.html)
- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md)
- [PortSwigger URL Validation Bypass Cheat Sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- [Orange Tsai: A New Era of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- [Palo Alto DNS Rebinding](https://www.paloaltonetworks.com/cyberpedia/what-is-dns-rebinding)

## Appendix: Blocked IP Ranges

```rust
const BLOCKED_RANGES: &[&str] = &[
    // RFC 1918 - Private
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",

    // Loopback
    "127.0.0.0/8",

    // Link-local
    "169.254.0.0/16",

    // "This" network
    "0.0.0.0/8",

    // Shared address space (RFC 6598)
    "100.64.0.0/10",

    // IETF protocol assignments
    "192.0.0.0/24",

    // Documentation (RFC 5737)
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",

    // Benchmarking (RFC 2544)
    "198.18.0.0/15",

    // Multicast
    "224.0.0.0/4",

    // Reserved
    "240.0.0.0/4",

    // Broadcast
    "255.255.255.255/32",

    // IPv6 equivalents
    "::1/128",           // Loopback
    "fc00::/7",          // Unique local
    "fe80::/10",         // Link-local
    "::ffff:0:0/96",     // IPv4-mapped (validate inner!)
    "64:ff9b::/96",      // IPv4/IPv6 translation
    "100::/64",          // Discard
    "2001:db8::/32",     // Documentation
    "ff00::/8",          // Multicast
];

// Cloud metadata endpoints (special handling)
const CLOUD_METADATA: &[&str] = &[
    "169.254.169.254",           // AWS, GCP, Azure
    "metadata.google.internal",   // GCP
    "metadata.goog",              // GCP alternative
];
```
