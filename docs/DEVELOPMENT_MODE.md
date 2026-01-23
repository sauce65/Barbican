# Development Mode Guide

How to run Barbican-secured applications locally without the full security stack.

## Overview

Production security controls (mTLS, strict password policies, short sessions) can be frustrating during development. This guide shows how to safely relax controls for local development while maintaining them in production.

## Quick Start

Set the development profile:
```bash
export BARBICAN_PROFILE=development
cargo run
```

This relaxes:
- Password minimum length: 1 character
- Session timeout: 24 hours
- Rate limits: 10,000 req/sec
- TLS: Not required
- MFA: Not required

---

## Environment-Based Configuration

### Option 1: Use BARBICAN_PROFILE

```bash
# Development (relaxed)
BARBICAN_PROFILE=development cargo run

# Staging (moderate)
BARBICAN_PROFILE=fedramp-moderate cargo run

# Production (strict)
BARBICAN_PROFILE=fedramp-high cargo run
```

In your code:
```rust
let profile = ComplianceProfile::from_env(); // Reads BARBICAN_PROFILE

let state = AppState {
    password_policy: profile.password_policy(),
    lockout_policy: profile.lockout_policy(),
    session_policy: profile.session_policy(),
};
```

### Option 2: Compile-Time Detection

Use `cfg!(debug_assertions)` to detect debug vs release builds:

```rust
fn create_config() -> AppConfig {
    if cfg!(debug_assertions) {
        // Debug build - relaxed settings
        AppConfig {
            password_policy: PasswordPolicy::builder()
                .min_length(4)
                .build(),
            lockout_policy: LockoutPolicy::builder()
                .max_attempts(100)
                .lockout_duration(Duration::from_secs(1))
                .build(),
            session_policy: SessionPolicy::builder()
                .idle_timeout(Duration::from_secs(86400))
                .max_lifetime(Duration::from_secs(86400))
                .build(),
            tls_mode: TlsMode::Disabled,
        }
    } else {
        // Release build - production settings
        AppConfig {
            password_policy: PasswordPolicy::fedramp_moderate(),
            lockout_policy: LockoutPolicy::fedramp_moderate(),
            session_policy: SessionPolicy::fedramp_moderate(),
            tls_mode: TlsMode::Required,
        }
    }
}
```

### Option 3: Feature Flags

Define a `dev` feature in Cargo.toml:

```toml
[features]
default = []
dev = []  # Enable relaxed security for development
```

In code:
```rust
#[cfg(feature = "dev")]
const MIN_PASSWORD_LENGTH: usize = 4;

#[cfg(not(feature = "dev"))]
const MIN_PASSWORD_LENGTH: usize = 15;
```

Run with:
```bash
cargo run --features dev
```

---

## Relaxing Specific Controls

### Password Policy

```rust
// Development: allow simple passwords
let policy = PasswordPolicy::builder()
    .min_length(1)              // Any length
    .max_length(128)
    .require_mixed_case(false)  // No case requirements
    .require_digit(false)       // No digit required
    .require_special(false)     // No special char required
    .check_common_passwords(false) // Don't check common passwords
    .build();

// Or skip validation entirely for tests
if std::env::var("SKIP_PASSWORD_VALIDATION").is_ok() {
    return Ok(()); // Accept any password
}
```

### Login Lockout

```rust
// Development: effectively disable lockout
let policy = LockoutPolicy::builder()
    .max_attempts(10000)        // Very high threshold
    .lockout_duration(Duration::from_secs(1)) // 1 second lockout
    .build();
```

### Session Timeout

```rust
// Development: long sessions
let policy = SessionPolicy::builder()
    .idle_timeout(Duration::from_secs(86400))  // 24 hours
    .max_lifetime(Duration::from_secs(86400))  // 24 hours
    .build();
```

### Rate Limiting

```rust
// Development: high limits
let app = Router::new()
    .route("/", get(handler));

#[cfg(debug_assertions)]
let app = app.with_rate_limiting(10000, 1000); // Very permissive

#[cfg(not(debug_assertions))]
let app = app.with_rate_limiting(100, 10); // Production limits
```

Or disable entirely for tests:
```rust
#[cfg(test)]
let app = Router::new().route("/", get(handler)); // No rate limiting

#[cfg(not(test))]
let app = Router::new()
    .route("/", get(handler))
    .with_rate_limiting(100, 10);
```

### TLS Enforcement

```rust
// Skip TLS check in development
let tls_mode = match std::env::var("REQUIRE_TLS").as_deref() {
    Ok("false") | Err(_) if cfg!(debug_assertions) => TlsMode::Disabled,
    _ => TlsMode::Required,
};
```

### Security Headers

```rust
// Development: allow embedding in iframes (for dev tools)
#[cfg(debug_assertions)]
let app = app; // No security headers

#[cfg(not(debug_assertions))]
let app = app.with_security_headers();
```

---

## Local TLS Setup

If you need TLS locally (e.g., testing mTLS):

### Generate Self-Signed Certificates

```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/CN=Dev CA"

# Create server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=localhost"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

# Create client certificate (for mTLS)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
    -subj "/CN=dev-client"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt
```

### Use with curl

```bash
# Server TLS
curl --cacert ca.crt https://localhost:3000/

# mTLS
curl --cacert ca.crt --cert client.crt --key client.key https://localhost:3000/
```

### Use Local Reverse Proxy

Run nginx locally for TLS termination:

```nginx
# /etc/nginx/conf.d/dev.conf
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate /path/to/server.crt;
    ssl_certificate_key /path/to/server.key;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

---

## Testing Utilities

### Mock Authentication

```rust
#[cfg(test)]
mod test_utils {
    use super::*;

    pub fn mock_claims(user_id: &str) -> Claims {
        Claims {
            sub: user_id.to_string(),
            email: format!("{}@test.com", user_id),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn mock_token(user_id: &str, secret: &str) -> String {
        jwt::create_token(user_id, &format!("{}@test.com", user_id), secret, 3600)
            .unwrap()
    }

    pub async fn authenticated_request(
        app: Router,
        method: &str,
        path: &str,
        token: &str,
    ) -> Response {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        app.oneshot(request).await.unwrap()
    }
}
```

### Test Without Security Layers

```rust
#[cfg(test)]
fn test_app() -> Router {
    // Minimal app without security middleware
    Router::new()
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .with_state(test_state())
    // No rate limiting, security headers, etc.
}

#[cfg(not(test))]
fn production_app() -> Router {
    Router::new()
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .with_state(production_state())
        .layer(audit_middleware())
        .with_security_headers()
        .with_rate_limiting(100, 10)
}
```

### Skip Audit Logging in Tests

```rust
// Only log in non-test environments
if !cfg!(test) {
    info!(event = "user.created", user_id = %id, "User created");
}
```

---

## Environment Variables Reference

| Variable | Purpose | Development Value |
|----------|---------|-------------------|
| `BARBICAN_PROFILE` | Compliance profile | `development` |
| `JWT_SECRET` | Token signing | `dev-secret-at-least-32-characters-long` |
| `ENCRYPTION_KEY` | Field encryption | `base64-encoded-32-byte-key` |
| `DATABASE_URL` | Database connection | `postgresql://localhost/dev` |
| `RUST_LOG` | Log level | `debug` |
| `REQUIRE_TLS` | TLS enforcement | `false` |

### .env File

Create a `.env` file for development:

```bash
# .env (DO NOT commit to git)
BARBICAN_PROFILE=development
JWT_SECRET=development-jwt-secret-minimum-32-characters
ENCRYPTION_KEY=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
DATABASE_URL=postgresql://postgres:postgres@localhost/myapp_dev
RUST_LOG=debug,sqlx=warn
REQUIRE_TLS=false
```

Load with:
```rust
dotenv::dotenv().ok();
```

Or:
```bash
source .env && cargo run
```

---

## Docker Development Setup

```yaml
# docker-compose.yml
version: "3.8"

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - BARBICAN_PROFILE=development
      - JWT_SECRET=docker-dev-jwt-secret-minimum-32-chars
      - ENCRYPTION_KEY=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
      - DATABASE_URL=postgresql://postgres:postgres@db/app
      - RUST_LOG=debug
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

---

## Security Checklist Before Production

Before deploying to production, verify:

- [ ] `BARBICAN_PROFILE` is NOT `development`
- [ ] JWT_SECRET is unique and securely generated
- [ ] ENCRYPTION_KEY is unique and securely stored
- [ ] TLS is enabled and properly configured
- [ ] Rate limiting is active
- [ ] Security headers are enabled
- [ ] Password policy matches FedRAMP requirements
- [ ] Session timeouts are appropriate for profile
- [ ] Audit logging is enabled
- [ ] No debug/development code paths active

Run compliance tests:
```bash
BARBICAN_PROFILE=fedramp-moderate cargo test
```

---

## Common Patterns

### Profile-Aware Configuration

```rust
pub fn load_config() -> Config {
    let profile = ComplianceProfile::from_env();

    Config {
        password_policy: profile.password_policy(),
        session_policy: profile.session_policy(),
        lockout_policy: profile.lockout_policy(),

        // Profile-specific overrides
        rate_limit: match profile {
            ComplianceProfile::Development => (10000, 1000),
            ComplianceProfile::FedRampLow => (200, 20),
            ComplianceProfile::FedRampModerate => (100, 10),
            ComplianceProfile::FedRampHigh => (50, 5),
        },

        tls_mode: match profile {
            ComplianceProfile::Development => TlsMode::Disabled,
            ComplianceProfile::FedRampLow => TlsMode::Preferred,
            ComplianceProfile::FedRampModerate => TlsMode::Required,
            ComplianceProfile::FedRampHigh => TlsMode::Strict,
        },
    }
}
```

### Conditional Middleware

```rust
fn build_router(config: &Config) -> Router {
    let mut app = Router::new()
        .route("/", get(handler));

    // Always add audit logging (even in dev, for debugging)
    app = app.layer(audit_middleware());

    // Conditional security layers
    if config.profile != ComplianceProfile::Development {
        app = app
            .with_security_headers()
            .with_rate_limiting(config.rate_limit.0, config.rate_limit.1);
    }

    app
}
```
