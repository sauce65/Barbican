# Troubleshooting Guide

Common issues and solutions when using Barbican.

## Table of Contents

- [Build Issues](#build-issues)
- [Runtime Issues](#runtime-issues)
- [Authentication](#authentication)
- [Password Validation](#password-validation)
- [Rate Limiting](#rate-limiting)
- [TLS/mTLS](#tlsmtls)
- [Database](#database)
- [NixOS Deployment](#nixos-deployment)
- [Development Mode](#development-mode)

---

## Build Issues

### "feature `edition2024` is required"

**Error:**
```
error: feature `edition2024` is required
```

**Solution:** Update your Rust toolchain:
```bash
rustup update stable
# Or use nightly if needed
rustup default nightly
```

### "cannot find crate `barbican`"

**Error:**
```
error[E0463]: can't find crate for `barbican`
```

**Solutions:**

1. **Check Cargo.toml dependency:**
   ```toml
   [dependencies]
   barbican = { git = "https://github.com/Sauce65/barbican" }
   ```

2. **For examples in the barbican repo, use path:**
   ```toml
   barbican = { path = "../.." }
   ```

3. **Clear cargo cache and rebuild:**
   ```bash
   cargo clean
   cargo build
   ```

### "unresolved import `barbican::prelude`"

**Error:**
```
error[E0432]: unresolved import `barbican::prelude`
```

**Solution:** This usually means a feature is missing. Check you have the right features enabled:
```toml
barbican = { git = "...", features = ["postgres"] }
```

### SQLx compilation errors

**Error:**
```
error: `DATABASE_URL` must be set
```

**Solution:** SQLx checks queries at compile time. Either:

1. Set the environment variable:
   ```bash
   export DATABASE_URL="postgresql://localhost/mydb"
   cargo build
   ```

2. Or use offline mode with a prepared query cache:
   ```bash
   cargo sqlx prepare
   ```

---

## Runtime Issues

### "JWT_SECRET environment variable required"

**Error:**
```
Error: JWT_SECRET environment variable required
```

**Solution:** Set the required environment variables:
```bash
export JWT_SECRET="your-secret-key-at-least-32-chars-long"
export ENCRYPTION_KEY="base64-encoded-32-byte-key"
```

Generate a secure key:
```bash
# Generate JWT secret
openssl rand -base64 32

# Generate encryption key
openssl rand -base64 32
```

### "ENCRYPTION_KEY environment variable required"

**Solution:** Set a 32-byte base64-encoded key:
```bash
export ENCRYPTION_KEY=$(openssl rand -base64 32)
```

### App starts but returns 500 errors

**Diagnosis:**
1. Check logs for actual error:
   ```bash
   RUST_LOG=debug cargo run
   ```

2. Common causes:
   - Database not running
   - Invalid configuration
   - Missing environment variables

---

## Authentication

### "Invalid credentials" even with correct password

**Causes:**

1. **Account is locked out (AC-7):**
   ```
   Account locked. Try again in 1800 seconds.
   ```
   Wait for lockout to expire, or clear it programmatically.

2. **Password doesn't meet policy:**
   Check the password meets the profile requirements (15 chars for Moderate/High).

3. **Wrong profile in testing:**
   Development may use relaxed policies, production stricter ones.

### "Token expired" immediately after login

**Cause:** System clock skew or very short token lifetime.

**Solutions:**
1. Sync system time:
   ```bash
   sudo ntpdate pool.ntp.org
   ```

2. Check token lifetime configuration:
   ```rust
   // FedRAMP High: 10 minutes
   // FedRAMP Moderate: 15 minutes
   // FedRAMP Low: 30 minutes
   ```

### "Authorization header required"

**Cause:** Missing or malformed Authorization header.

**Solution:** Include the header correctly:
```bash
curl -H "Authorization: Bearer eyJ..." http://localhost:3000/api/endpoint
```

Note: It's `Bearer ` (with space), not `Bearer:`.

### Login always fails in tests

**Cause:** LoginTracker persists between tests.

**Solution:** Create a fresh tracker for each test:
```rust
#[tokio::test]
async fn test_login() {
    let tracker = LoginTracker::new(LockoutPolicy::fedramp_moderate());
    // Use this tracker
}
```

---

## Password Validation

### "Password: TooShort { min: 15, actual: 12 }"

**Cause:** Password doesn't meet profile requirements.

**FedRAMP password requirements:**
| Profile | Minimum Length |
|---------|----------------|
| Low | 8 |
| Moderate | 15 |
| High | 15 |

**Solution:** Use a longer password or adjust profile for development:
```rust
let policy = if cfg!(debug_assertions) {
    PasswordPolicy::builder().min_length(4).build()
} else {
    PasswordPolicy::fedramp_moderate()
};
```

### "Password: ContainsUsername"

**Cause:** Password includes the username.

**Solution:** Choose a password that doesn't contain your username or email.

### "Password: CommonPassword"

**Cause:** Password is in the common passwords list.

**Solution:** Use a unique password not in common password lists.

### "Password: Breached { count: 12345 }"

**Cause:** Password found in Have I Been Pwned database (with `hibp` feature).

**Solution:** Choose a password not found in data breaches.

---

## Rate Limiting

### "429 Too Many Requests"

**Cause:** Rate limit exceeded.

**Response headers:**
```
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1234567890
```

**Solutions:**

1. **Wait and retry:**
   ```bash
   sleep $(curl -sI ... | grep Retry-After | cut -d: -f2)
   ```

2. **Increase rate limit for development:**
   ```rust
   .with_rate_limiting(10000, 100) // Very high for dev
   ```

3. **Use separate rate limits per endpoint:**
   ```rust
   let login_routes = Router::new()
       .route("/login", post(login))
       .with_rate_limiting(10, 5); // Stricter for login

   let api_routes = Router::new()
       .route("/api/*", any(api_handler))
       .with_rate_limiting(100, 20);
   ```

### Rate limiting blocks legitimate users

**Cause:** Rate limit too aggressive or shared across users.

**Solution:** Implement per-user rate limiting:
```rust
// Use user ID or API key as rate limit key
// instead of IP address
```

---

## TLS/mTLS

### "TLS required" in development

**Cause:** TLS enforcement is on but you're testing over HTTP.

**Solutions:**

1. **Use HTTPS with self-signed cert:**
   ```bash
   # Generate self-signed cert
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

   # Run with TLS
   cargo run -- --cert cert.pem --key key.pem
   ```

2. **Disable TLS enforcement for development:**
   ```rust
   let tls_mode = if cfg!(debug_assertions) {
       TlsMode::Disabled
   } else {
       TlsMode::Required
   };
   ```

3. **Use a reverse proxy (nginx) with TLS termination.**

### "Client certificate required" (mTLS)

**Cause:** FedRAMP High requires mutual TLS.

**Solution:** Provide client certificate:
```bash
curl --cert client.crt --key client.key https://api.example.com/
```

Or disable mTLS for development (not recommended for production).

### Certificate validation fails

**Error:**
```
SSL certificate problem: unable to get local issuer certificate
```

**Solutions:**

1. **Add CA certificate:**
   ```bash
   curl --cacert ca.crt https://api.example.com/
   ```

2. **Skip verification (dev only!):**
   ```bash
   curl -k https://localhost:3000/  # NEVER in production
   ```

---

## Database

### "Connection refused" to PostgreSQL

**Solutions:**

1. **Check PostgreSQL is running:**
   ```bash
   systemctl status postgresql
   # or
   docker ps | grep postgres
   ```

2. **Check connection URL:**
   ```bash
   psql $DATABASE_URL
   ```

3. **Check pg_hba.conf allows your connection method.**

### "SSL required" but database doesn't support it

**Error:**
```
SSL connection is required
```

**Solutions:**

1. **Enable SSL on PostgreSQL:**
   ```
   # postgresql.conf
   ssl = on
   ssl_cert_file = '/path/to/server.crt'
   ssl_key_file = '/path/to/server.key'
   ```

2. **For development, use SslMode::Prefer:**
   ```rust
   let config = DatabaseConfig::builder(url)
       .ssl_mode(SslMode::Prefer) // Falls back to no SSL
       .build();
   ```

### pgaudit not loading

**Error:**
```
FATAL: could not access file "pgaudit": No such file or directory
```

**Solution:** Install pgaudit extension:
```bash
# Ubuntu/Debian
sudo apt install postgresql-15-pgaudit

# NixOS (via module)
barbican.securePostgres.enablePgaudit = true;
```

---

## NixOS Deployment

### "undefined variable 'barbican'"

**Cause:** Barbican flake not in inputs or not passed to module.

**Solution:** Check flake.nix:
```nix
{
  inputs = {
    barbican.url = "github:Sauce65/barbican";
  };

  outputs = { nixpkgs, barbican, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        barbican.nixosModules.all
        # ...
      ];
    };
  };
}
```

### "option barbican.securePostgres does not exist"

**Cause:** Barbican modules not imported.

**Solution:** Import the modules:
```nix
modules = [
  barbican.nixosModules.all  # Import all modules
  # or individual:
  barbican.nixosModules.securePostgres
];
```

### VM won't boot

**Common causes:**

1. **Missing secrets:** Check all required agenix secrets exist.

2. **Disk space:** Ensure enough disk allocated:
   ```nix
   virtualisation.diskSize = 4096; # 4GB
   ```

3. **Memory:** Increase VM memory:
   ```nix
   virtualisation.memorySize = 2048; # 2GB
   ```

### Services fail to start

**Diagnosis:**
```bash
# In the VM
journalctl -u postgresql --no-pager
journalctl -u your-app --no-pager
systemctl status your-app
```

---

## Development Mode

### How to disable security for local development?

Create a development configuration:

```rust
fn security_config() -> AppState {
    if std::env::var("DEVELOPMENT").is_ok() {
        AppState {
            password_policy: PasswordPolicy::builder()
                .min_length(1)
                .build(),
            lockout_policy: LockoutPolicy::builder()
                .max_attempts(1000)
                .build(),
            session_policy: SessionPolicy::builder()
                .idle_timeout(Duration::from_secs(86400))
                .max_lifetime(Duration::from_secs(86400))
                .build(),
            // ...
        }
    } else {
        // Production config
    }
}
```

Or use the development profile:
```bash
BARBICAN_PROFILE=development cargo run
```

### How to test without real JWT?

Create test utilities:
```rust
#[cfg(test)]
mod tests {
    fn mock_claims(user_id: &str) -> Claims {
        Claims {
            sub: user_id.to_string(),
            email: "test@example.com".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
        }
    }

    #[tokio::test]
    async fn test_handler() {
        let claims = mock_claims("user_123");
        // Pass claims directly to handler
    }
}
```

### How to skip rate limiting in tests?

```rust
#[cfg(test)]
let app = Router::new()
    .route("/", get(handler));
    // No rate limiting

#[cfg(not(test))]
let app = Router::new()
    .route("/", get(handler))
    .with_rate_limiting(100, 10);
```

---

## Getting Help

If your issue isn't covered here:

1. **Check logs:** `RUST_LOG=debug cargo run`
2. **Search issues:** https://github.com/Sauce65/barbican/issues
3. **Open an issue** with:
   - Barbican version
   - Rust version (`rustc --version`)
   - Error message
   - Minimal reproduction

---

## FAQ

### Q: Can I use Barbican without NixOS?

**A:** Yes. The Rust library works with any deployment method. NixOS modules are optional infrastructure hardening.

### Q: Is Barbican FedRAMP certified?

**A:** Barbican is a library that helps implement FedRAMP controls. Certification is for your complete system, not just libraries. Barbican provides the building blocks and audit traceability.

### Q: Can I use my own session store?

**A:** Yes. `SessionPolicy` validates sessions, but storage is up to you. Use Redis, PostgreSQL, or any backend.

### Q: How do I upgrade Barbican?

**A:** Update your dependency and check for breaking changes:
```bash
cargo update -p barbican
cargo build
```

Review the changelog for migration notes.

### Q: Does Barbican support async?

**A:** Yes. All middleware and handlers are async-compatible with Axum/Tokio.
