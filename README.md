# barbican

NIST 800-53 compliant security infrastructure for Axum applications. Provides reusable middleware and configuration for building production-ready web services with PostgreSQL.

## Quick Start

```rust
use axum::{Router, routing::get};
use barbican::{SecurityConfig, SecureRouter, DatabaseConfig, create_pool};
use barbican::observability::{ObservabilityConfig, init};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize observability
    init(ObservabilityConfig::from_env()).await?;

    // Create database pool
    let pool = create_pool(&DatabaseConfig::from_env()).await?;

    // Build app with security layers
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .with_state(pool)
        .with_security(SecurityConfig::from_env());

    // Serve with TLS...
    Ok(())
}
```

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `default` | Includes `observability-stdout` | Yes |
| `postgres` | PostgreSQL connection pooling with SSL | No |
| `observability-stdout` | Log to stdout (development) | Yes |
| `observability-loki` | Send logs to Grafana Loki | No |
| `observability-otlp` | OpenTelemetry Protocol tracing | No |
| `metrics-prometheus` | Prometheus metrics endpoint | No |

Enable features in `Cargo.toml`:

```toml
[dependencies]
barbican = { version = "0.1", features = ["postgres", "observability-loki", "metrics-prometheus"] }
```

## Security Controls

| Control | Name | Description | NIST 800-53 |
|---------|------|-------------|-------------|
| SC-2 | Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options | SC-28, CC6.1 |
| SC-3 | Rate Limiting | Token bucket per IP, configurable burst | SC-5 |
| SC-4 | Request Size Limits | Prevent DoS via large payloads | SC-5 |
| SC-5 | Request Timeouts | Configurable timeout with 408 response | SC-10 |
| SC-6 | CORS Policy | Origin allowlist or restrictive (same-origin) | AC-4, CC6.6 |
| SC-7 | Structured Logging | JSON audit logs with tracing | AU-2, AU-3, AU-12 |
| SC-8 | Database Security | SSL/TLS, pooling, health checks | SC-8, SC-28, IA-5 |
| SC-9 | Observability | Pluggable logging/metrics providers | AU-2, AU-12 |

## Environment Variables

### Security Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAX_REQUEST_SIZE` | size | `1MB` | Maximum request body size (e.g., "10MB", "1GB") |
| `REQUEST_TIMEOUT` | duration | `30s` | Request timeout (e.g., "30s", "5m") |
| `RATE_LIMIT_PER_SECOND` | int | `5` | Requests per second per IP |
| `RATE_LIMIT_BURST` | int | `10` | Burst capacity for rate limiter |
| `RATE_LIMIT_ENABLED` | bool | `true` | Enable rate limiting |
| `CORS_ALLOWED_ORIGINS` | csv | (empty) | Comma-separated origins or `*` (dev only) |
| `SECURITY_HEADERS_ENABLED` | bool | `true` | Enable security headers |
| `TRACING_ENABLED` | bool | `true` | Enable request tracing |

### Database Configuration (requires `postgres` feature)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | string | (required) | PostgreSQL connection URL |
| `DB_MAX_CONNECTIONS` | int | `10` | Maximum pool size |
| `DB_MIN_CONNECTIONS` | int | `1` | Minimum idle connections |
| `DB_ACQUIRE_TIMEOUT` | duration | `30s` | Connection acquire timeout |
| `DB_MAX_LIFETIME` | duration | `30m` | Maximum connection lifetime |
| `DB_IDLE_TIMEOUT` | duration | `10m` | Idle connection timeout |
| `DB_SSL_MODE` | string | `require` | `disable`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `DB_SSL_ROOT_CERT` | path | (none) | Path to CA certificate for SSL verification |
| `DB_STATEMENT_LOGGING` | bool | `false` | Enable SQL statement logging |
| `DB_AUTO_MIGRATE` | bool | `true` | Run migrations on startup |

### Observability Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `LOG_PROVIDER` | string | `stdout` | `stdout`, `loki`, or `otlp` |
| `LOG_FORMAT` | string | `pretty` | `pretty`, `json`, or `compact` |
| `RUST_LOG` | string | `info` | Log filter (e.g., `debug`, `myapp=debug,tower_http=info`) |
| `TRACING_ENABLED` | bool | `true` | Enable request/response tracing |

**For Loki** (`LOG_PROVIDER=loki`, requires `observability-loki` feature):
- `LOKI_ENDPOINT`: Loki push URL (e.g., `http://loki:3100`)
- `LOKI_LABELS`: Comma-separated `key=value` pairs (optional)

**For OTLP** (`LOG_PROVIDER=otlp`, requires `observability-otlp` feature):
- `OTLP_ENDPOINT`: OTLP collector URL (e.g., `http://jaeger:4317`)
- `OTEL_SERVICE_NAME`: Service name for traces (default: `app`)

**For Prometheus** (requires `metrics-prometheus` feature):
- `METRICS_PROVIDER`: Set to `prometheus` to enable
- `PROMETHEUS_LISTEN`: Listen address (default: `0.0.0.0:9090`)

## Programmatic Configuration

All configuration can be set via builder pattern:

```rust
use std::time::Duration;
use barbican::{SecurityConfig, DatabaseConfig, SslMode};

// Security config
let security = SecurityConfig::builder()
    .max_request_size(5 * 1024 * 1024) // 5MB
    .request_timeout(Duration::from_secs(60))
    .rate_limit(10, 20) // 10/sec, burst 20
    .cors_origins(vec!["https://app.example.com"])
    .build();

// Database config
let db = DatabaseConfig::builder("postgres://localhost/mydb")
    .max_connections(20)
    .ssl_mode(SslMode::VerifyFull)
    .with_statement_logging()
    .build();

// Observability config
use barbican::observability::{ObservabilityConfig, LogFormat, LogProvider};

let obs = ObservabilityConfig::builder()
    .log_format(LogFormat::Json)
    .log_filter("debug")
    .log_provider(LogProvider::Stdout)
    .build();
```

## Security Event Logging

Log security events with structured fields for compliance:

```rust
use barbican::observability::{SecurityEvent, security_event};

security_event!(
    SecurityEvent::AuthenticationSuccess,
    user_id = %user.id,
    ip_address = %client_ip,
    "User authenticated successfully"
);

security_event!(
    SecurityEvent::RateLimitExceeded,
    ip_address = %client_ip,
    endpoint = "/api/login",
    "Rate limit exceeded"
);
```

Available events: `AuthenticationSuccess`, `AuthenticationFailure`, `AccessDenied`, `UserRegistered`, `RateLimitExceeded`, `BruteForceDetected`, `AccountLocked`, and more. See `SecurityEvent` enum for full list.

## Cryptographic Utilities

```rust
use barbican::{constant_time_eq, constant_time_str_eq};

// Prevent timing attacks on secret comparisons
let stored_hash = b"abc123...";
let provided_hash = b"abc123...";
if constant_time_eq(stored_hash, provided_hash) {
    // Secrets match
}

// String variant
if constant_time_str_eq(&stored_token, &provided_token) {
    // Tokens match
}
```

## Compliance

This crate supports:
- **NIST SP 800-53 Rev 5**: SC-2, SC-3, SC-5, SC-8, SC-10, SC-28, AU-2, AU-3, AU-12, AC-4, IA-5
- **SOC 2 Type II**: CC6.1, CC6.6, CC6.7, CC7.2
- **FedRAMP**: SC-5, SC-8, SC-28

## Documentation

- [CONTRIBUTING.md](./CONTRIBUTING.md) - Architecture and development guide
- [SECURITY.md](./SECURITY.md) - Security controls and audit procedures
- [API docs](https://docs.rs/barbican) - Full API reference

## License

Licensed under either of Apache License 2.0 or MIT license at your option.
