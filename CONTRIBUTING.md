# Contributing to barbican

This document describes the architecture, module responsibilities, and development practices for contributors.

## Architecture Overview

barbican is structured as a layered security infrastructure crate:

```
┌─────────────────────────────────────────────────┐
│         Application (uses barbican)          │
│  - Uses standard tracing macros (provider-agnostic)
│  - Calls SecurityConfig::from_env()             │
│  - Uses SecureRouter trait extension            │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│              barbican crate                  │
│  ┌─────────────┬──────────────┬──────────────┐ │
│  │   config    │   layers     │ observability│ │
│  │  (SC-2-7)   │ (applies MW) │   (SC-7,9)   │ │
│  └─────────────┴──────────────┴──────────────┘ │
│  ┌──────────────────────────────────────────┐  │
│  │  database (SC-8)  │  crypto  │  parse    │  │
│  │  (postgres feature)                      │  │
│  └──────────────────────────────────────────┘  │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│         Tower Middleware & SQLx                 │
│  - tower-http (CORS, limits, timeout, headers)  │
│  - tower-governor (rate limiting)               │
│  - sqlx (database, optional)                    │
└─────────────────────────────────────────────────┘
```

Key design principles:

1. **Opt-in via features**: Core is minimal, database and observability providers are optional
2. **Configuration over code**: All security settings configurable via env vars or builder
3. **Trait-based extension**: `SecureRouter` trait extends any `Router<S>`
4. **Provider-agnostic observability**: Application uses `tracing::info!()`, provider configured at startup
5. **Secure defaults**: All defaults chosen for security over convenience

## Module Responsibilities

### `config.rs` - Security Configuration (SC-2 through SC-7)

**File**: `src/config.rs`

**Purpose**: Centralized configuration for all security controls.

**Key types**:
- `SecurityConfig`: Main configuration struct
- `SecurityConfigBuilder`: Builder pattern for programmatic config
- `from_env()`: Environment variable parser

**Security controls**:
- SC-2: Security headers enable/disable
- SC-3: Rate limiting (per second, burst size, enable/disable)
- SC-4: Request size limits
- SC-5: Request timeouts
- SC-6: CORS origins (restrictive/permissive/allowlist)
- SC-7: Tracing enable/disable

**Adding new security controls**:

1. Add field to `SecurityConfig` struct:
   ```rust
   /// Enable new control (SC-XX)
   pub new_control_enabled: bool,
   ```

2. Update `Default` impl with secure default:
   ```rust
   new_control_enabled: true,
   ```

3. Add env var parsing in `from_env()`:
   ```rust
   let new_control_enabled = std::env::var("NEW_CONTROL_ENABLED")
       .map(|s| s.to_lowercase() != "false")
       .unwrap_or(true);
   ```

4. Add builder method:
   ```rust
   pub fn disable_new_control(mut self) -> Self {
       self.config.new_control_enabled = false;
       self
   }
   ```

5. Document in module docstring with NIST control mapping

### `layers.rs` - Security Middleware Application

**File**: `src/layers.rs`

**Purpose**: Applies tower middleware in correct order based on configuration.

**Key trait**:
- `SecureRouter`: Extension trait for `Router<S>` providing `with_security(config)`

**Middleware order** (innermost to outermost):
1. Timeout (innermost - closest to handler)
2. Request Body Limit
3. Rate Limiting
4. Security Headers
5. CORS
6. TraceLayer (outermost - logs everything)

**Why this order**:
- Timeout wraps handler directly (measures handler execution time)
- Size limit prevents large payloads before processing
- Rate limiting rejects requests before expensive operations
- Headers added to all responses (including errors from inner layers)
- CORS handles preflight before other processing
- Tracing logs all requests including those rejected by inner layers

**Adding new middleware**:

1. Check if control enabled in config:
   ```rust
   if config.new_control_enabled {
       router = router.layer(NewControlLayer::new());
   }
   ```

2. Insert at appropriate position in layer stack (consider order above)

3. Document NIST control reference in comment:
   ```rust
   // SC-XX: New Control - NIST 800-53 SC-XX
   ```

4. Add compliance mapping in docstring

### `database.rs` - PostgreSQL Connection Pooling (SC-8)

**File**: `src/database.rs` (requires `postgres` feature)

**Purpose**: Secure database connection pooling with SSL/TLS, timeouts, and health checks.

**Key types**:
- `DatabaseConfig`: Configuration struct with security-focused defaults
- `DatabaseConfigBuilder`: Builder pattern
- `SslMode`: Enum mapping to PostgreSQL SSL modes
- `create_pool()`: Async function to create configured pool
- `health_check()`: Verify connection health and SSL status
- `HealthStatus`: Result of health check
- `DatabaseError`: Database-specific errors

**Security features**:
- SSL modes: `Disable`, `Prefer`, `Require`, `VerifyCa`, `VerifyFull`
- Default: `Require` (enforces encryption)
- Connection limits prevent resource exhaustion
- Aggressive timeouts detect failures quickly
- Health checks ensure pool integrity
- SSL status verification

**Adding database features**:

1. Add field to `DatabaseConfig`:
   ```rust
   /// Description of new setting
   pub new_setting: Type,
   ```

2. Update `Default` impl with secure value

3. Add env var parsing in `from_env()`

4. Add builder method in `DatabaseConfigBuilder`

5. Apply setting in `create_pool()`:
   ```rust
   .new_setting(config.new_setting)
   ```

6. Document security implications in docstring

### `crypto.rs` - Cryptographic Utilities

**File**: `src/crypto.rs`

**Purpose**: Constant-time operations to prevent timing attacks.

**Key functions**:
- `constant_time_eq(&[u8], &[u8]) -> bool`: Constant-time byte comparison
- `constant_time_str_eq(&str, &str) -> bool`: Constant-time string comparison

**Implementation**: Uses `subtle` crate's `ConstantTimeEq` trait.

**Security rationale**: Standard comparison (`==`) uses early-exit optimization, creating timing side-channel. Attacker can measure response times to discover secrets byte-by-byte. Constant-time comparison takes same duration regardless of where inputs differ.

**Adding cryptographic utilities**:

1. Evaluate if operation needs constant-time property (secret comparison, HMAC validation, etc.)
2. Use `subtle` crate primitives where possible
3. Document security rationale in function docstring
4. Add tests verifying correct behavior (not timing - that requires specialized tooling)
5. Reference NIST/FIPS standards where applicable

### `parse.rs` - Configuration Parsing Utilities

**File**: `src/parse.rs`

**Purpose**: Parse human-readable configuration values.

**Key functions**:
- `parse_size(s: &str) -> usize`: Parse "10MB", "1GB", etc.
- `parse_duration(s: &str) -> Duration`: Parse "30s", "5m", etc.

**Supported formats**:
- Size: `"1GB"`, `"10MB"`, `"512KB"`, `"1024B"`, `"1024"`
- Duration: `"1h"`, `"5m"`, `"30s"`, `"100ms"`

**Error handling**: Defaults to safe fallback values (1MB for size, 30s for duration) if parsing fails.

**Adding parsers**:

1. Create public function with clear signature
2. Use safe fallback on parse failure
3. Document supported formats in docstring
4. Add comprehensive tests for all formats
5. Consider case-insensitivity (use `.to_lowercase()` or `.to_uppercase()`)

### `observability/` - Pluggable Logging and Metrics (SC-7, SC-9)

**Files**:
- `src/observability/mod.rs`: Public API and initialization
- `src/observability/config.rs`: Configuration types
- `src/observability/providers.rs`: Provider implementations
- `src/observability/events.rs`: Security event logging

**Purpose**: Provider-agnostic observability infrastructure. Application code uses standard `tracing` macros, provider configured at startup.

**Architecture**:
```
Application Code
    ↓ (uses tracing::info!(), etc.)
Observability Abstraction (this module)
    ↓ (routes to configured provider)
Providers (Stdout, Loki, OTLP, Prometheus)
```

**Key types**:

**`config.rs`**:
- `ObservabilityConfig`: Main configuration
- `LogProvider`: Enum of logging backends (`Stdout`, `Loki`, `Otlp`)
- `MetricsProvider`: Enum of metrics backends (`Prometheus`)
- `LogFormat`: Output format (`Pretty`, `Json`, `Compact`)
- `ObservabilityConfigBuilder`: Builder pattern

**`events.rs`**:
- `SecurityEvent`: Enum of auditable events (NIST AU-2 compliant)
- `Severity`: Event severity levels (`Low`, `Medium`, `High`, `Critical`)
- `security_event!()`: Macro for structured security logging

**`providers.rs`** (internal):
- `init_tracing()`: Configure tracing subscriber based on provider
- `init_metrics()`: Start metrics exporter (Prometheus)

**Security controls**:
- SC-7: Structured logging with tracing (JSON format for production)
- SC-9: Pluggable providers (Stdout, Loki, OTLP, Prometheus)
- AU-2: Audit events (SecurityEvent enum)
- AU-3: Audit record content (event category, severity, timestamp)

**Adding new log providers**:

1. Add feature to `Cargo.toml`:
   ```toml
   observability-newprovider = ["dep:newprovider-crate"]
   ```

2. Add variant to `LogProvider` enum:
   ```rust
   #[cfg(feature = "observability-newprovider")]
   NewProvider {
       endpoint: String,
       // provider-specific config
   },
   ```

3. Add env var parsing in `ObservabilityConfig::from_env()`:
   ```rust
   Ok("newprovider") => {
       #[cfg(feature = "observability-newprovider")]
       {
           let endpoint = env::var("NEWPROVIDER_ENDPOINT")?;
           LogProvider::NewProvider { endpoint }
       }
       #[cfg(not(feature = "observability-newprovider"))]
       {
           eprintln!("Warning: newprovider requested but feature not enabled");
           LogProvider::Stdout
       }
   }
   ```

4. Implement initialization in `providers.rs`:
   ```rust
   #[cfg(feature = "observability-newprovider")]
   LogProvider::NewProvider { endpoint } => {
       // Initialize provider-specific subscriber
   }
   ```

5. Document environment variables in README and config docstring

**Adding security events**:

1. Add variant to `SecurityEvent` enum in `events.rs`:
   ```rust
   /// Description of event
   NewSecurityEvent,
   ```

2. Add to appropriate category in `category()` method
3. Set severity in `severity()` method
4. Add string name in `name()` method
5. Document NIST AU-2 mapping in enum docstring
6. Add tests for category/severity/name

**Using security events**:
```rust
use barbican::observability::{SecurityEvent, security_event};

security_event!(
    SecurityEvent::NewSecurityEvent,
    user_id = %user.id,
    resource = "api/data",
    "Description of what happened"
);
```

## Testing Requirements

All new code must include tests:

### Unit Tests

Add `#[cfg(test)]` module to same file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_feature() {
        // Test implementation
    }
}
```

Run tests:
```bash
cargo test
cargo test --all-features  # Test all feature combinations
```

### Security Control Tests

When adding new security controls (SC-XX):

1. Create test that verifies control is applied when enabled
2. Create test that verifies control is NOT applied when disabled
3. Create test for configuration parsing (env vars, builder)
4. Document test in comments with control reference

Example:
```rust
#[test]
fn test_sc_new_control_enabled() {
    let config = SecurityConfig::builder()
        .enable_new_control()
        .build();
    assert!(config.new_control_enabled);
}

#[test]
fn test_sc_new_control_disabled() {
    let config = SecurityConfig::builder()
        .disable_new_control()
        .build();
    assert!(!config.new_control_enabled);
}
```

### Feature Tests

Test feature flag combinations:

```bash
# No features
cargo test --no-default-features

# Individual features
cargo test --no-default-features --features postgres
cargo test --no-default-features --features observability-loki

# Combined features
cargo test --features postgres,observability-loki,metrics-prometheus
```

## Code Style

### General Guidelines

- Use `tracing` for all logging, never `println!`
- Document all public items with `///` doc comments
- Include `# Examples` in doc comments for public APIs
- Reference NIST controls in comments: `// SC-2: Security Headers`
- Use builder pattern for configuration structs
- Provide both `from_env()` and builder methods
- Default to secure settings (encryption on, limits low, restrictive policies)

### Error Handling

- Create module-specific error enums (e.g., `DatabaseError`, `ObservabilityError`)
- Implement `std::fmt::Display` and `std::error::Error`
- Use `Result<T, SpecificError>` for fallible operations
- Log errors with appropriate severity:
  - `error!()` for unexpected failures
  - `warn!()` for degraded functionality
  - `info!()` for expected error conditions

Example:
```rust
#[derive(Debug)]
pub enum NewFeatureError {
    Configuration(String),
    Runtime(String),
}

impl std::fmt::Display for NewFeatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            Self::Runtime(msg) => write!(f, "Runtime error: {}", msg),
        }
    }
}

impl std::error::Error for NewFeatureError {}
```

### Documentation

Document security rationale for all security-relevant code:

```rust
/// Enable new security control.
///
/// # Security
///
/// This control implements NIST 800-53 SC-XX by [explanation].
/// When disabled, [risk description].
///
/// # Default
///
/// Enabled by default for production security.
pub fn enable_new_control(mut self) -> Self {
    self.config.new_control_enabled = true;
    self
}
```

### Async Code

- Use `async fn` for I/O operations (database, network)
- Do NOT use `async fn` for CPU-bound operations
- Document if function requires Tokio runtime
- Use `tokio::time::timeout()` for operations that might hang

### Feature Flags

When adding feature-gated code:

```rust
#[cfg(feature = "feature-name")]
pub use feature_module::{FeatureType, feature_function};

#[cfg(not(feature = "feature-name"))]
compile_error!("This code requires the 'feature-name' feature");
```

Provide fallback or helpful error when feature disabled:

```rust
#[cfg(not(feature = "postgres"))]
pub fn create_pool(_config: &DatabaseConfig) -> Result<(), DatabaseError> {
    Err(DatabaseError::Configuration(
        "postgres feature not enabled".into()
    ))
}
```

## Environment Variable Naming

Follow consistent naming conventions:

- Security controls: `CONTROL_NAME_ENABLED` (e.g., `SECURITY_HEADERS_ENABLED`)
- Numeric settings: `SETTING_NAME` (e.g., `RATE_LIMIT_PER_SECOND`)
- Duration settings: `SETTING_TIMEOUT` or `SETTING_DURATION` (e.g., `REQUEST_TIMEOUT`)
- Size settings: `MAX_SETTING_SIZE` (e.g., `MAX_REQUEST_SIZE`)
- Database settings: `DB_` prefix (e.g., `DB_MAX_CONNECTIONS`)
- Provider settings: `PROVIDER_` prefix (e.g., `LOKI_ENDPOINT`)

## Compliance Mapping

When implementing new features, map to compliance frameworks:

| Framework | Control Family | Reference |
|-----------|---------------|-----------|
| NIST 800-53 | SC (System and Communications Protection) | SC-2, SC-8, SC-28, etc. |
| NIST 800-53 | AU (Audit and Accountability) | AU-2, AU-3, AU-12 |
| NIST 800-53 | AC (Access Control) | AC-4, etc. |
| SOC 2 | CC (Common Criteria) | CC6.1, CC6.6, CC7.2, etc. |
| FedRAMP | Same as NIST 800-53 | SC-5, SC-8, etc. |

Document mapping in:
1. Function/struct docstring
2. Module docstring
3. README.md security controls table
4. SECURITY.md controls matrix

## Pull Request Process

1. Create feature branch: `git checkout -b feature/sc-xx-description`
2. Implement feature with tests
3. Run full test suite: `cargo test --all-features`
4. Run clippy: `cargo clippy --all-features -- -D warnings`
5. Run fmt: `cargo fmt --check`
6. Update documentation:
   - Module docstrings
   - README.md (env vars, features, controls table)
   - SECURITY.md (if adding security control)
7. Create PR with description:
   - What: Feature description
   - Why: Security rationale, compliance mapping
   - How: Implementation approach
   - Tests: Coverage summary

## Questions?

Open an issue for:
- Architecture questions
- New security control proposals
- Compliance mapping clarifications
- API design discussions
