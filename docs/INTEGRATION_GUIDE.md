# Integrating Barbican into an Existing Application

This guide walks through adding Barbican security controls to an existing Axum application. We'll take a typical web API and progressively add authentication, session management, input validation, and audit logging.

## Prerequisites

- An existing Axum application (0.8+)
- Rust 1.75+
- Basic familiarity with tower middleware

## Starting Point

We'll assume you have a typical Axum app structure:

```rust
// src/main.rs
use axum::{Router, routing::{get, post}, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct CreateUser {
    email: String,
    password: String,
    name: String,
}

#[derive(Serialize)]
struct User {
    id: i64,
    email: String,
    name: String,
}

async fn create_user(Json(input): Json<CreateUser>) -> Json<User> {
    // Your existing logic
    Json(User { id: 1, email: input.email, name: input.name })
}

async fn get_user(axum::extract::Path(id): axum::extract::Path<i64>) -> Json<User> {
    Json(User { id, email: "user@example.com".into(), name: "Test".into() })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

---

## Step 1: Add Barbican Dependency

```toml
# Cargo.toml
[dependencies]
barbican = { git = "https://github.com/Sauce65/barbican", features = ["postgres"] }

# Optional features based on your needs:
# - "postgres"           - Database support with SQLx
# - "hibp"               - Password breach checking
# - "fips"               - FIPS 140-3 cryptography
# - "observability-loki" - Send logs to Grafana Loki
# - "metrics-prometheus" - Prometheus metrics endpoint
```

---

## Step 2: Add Security Headers and Rate Limiting

The simplest integration adds HTTP security headers and rate limiting with two lines:

```rust
use barbican::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        // Add Barbican security layers
        .with_security_headers()           // HSTS, CSP, X-Frame-Options, etc.
        .with_rate_limiting(100, 10);      // 100 req/sec, burst of 10

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

**What this adds:**
- `Strict-Transport-Security` header (HSTS)
- `Content-Security-Policy` header
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- Rate limiting with 429 responses when exceeded

---

## Step 3: Add Request Timeout and Body Limits

Protect against slow-loris attacks and oversized payloads:

```rust
let app = Router::new()
    .route("/users", post(create_user))
    .route("/users/:id", get(get_user))
    .with_security_headers()
    .with_rate_limiting(100, 10)
    .with_request_timeout(Duration::from_secs(30))  // 30 second timeout
    .with_body_limit(1024 * 1024);                  // 1MB max body
```

---

## Step 4: Add Input Validation

Replace raw `Json` extractors with validated versions to prevent injection attacks.

### Before (vulnerable):

```rust
#[derive(Deserialize)]
struct CreateUser {
    email: String,
    password: String,
    name: String,
}

async fn create_user(Json(input): Json<CreateUser>) -> Json<User> {
    // No validation - XSS, SQLi possible
}
```

### After (validated):

```rust
use barbican::prelude::*;

#[derive(Deserialize)]
struct CreateUser {
    email: String,
    password: String,
    name: String,
}

impl Validate for CreateUser {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_email(&self.email)?;
        validate_length(&self.name, 1, 100, "name")?;
        validate_length(&self.password, 8, 128, "password")?;
        Ok(())
    }
}

async fn create_user(
    ValidatedJson(input): ValidatedJson<CreateUser>
) -> Result<Json<User>, AppError> {
    // Input is guaranteed valid
    // HTML in name is sanitized, email format verified
    Ok(Json(User { id: 1, email: input.email, name: sanitize_html(&input.name) }))
}
```

**What `ValidatedJson` does:**
- Runs your `Validate` implementation before the handler
- Returns 400 Bad Request with safe error messages on failure
- Prevents malformed data from reaching your business logic

---

## Step 5: Add Password Validation

When users set passwords, validate against NIST 800-63B requirements:

```rust
use barbican::prelude::*;

async fn create_user(
    ValidatedJson(input): ValidatedJson<CreateUser>
) -> Result<Json<User>, AppError> {
    // Get policy for your compliance level
    let policy = PasswordPolicy::fedramp_moderate(); // 15 char minimum

    // Validate password with context (prevents password = email)
    policy.validate(&input.password, Some(&input.name), Some(&input.email))
        .map_err(|e| AppError::validation(format!("Password: {}", e)))?;

    // Password is strong - proceed with hashing and storage
    Ok(Json(User { id: 1, email: input.email, name: input.name }))
}
```

**What password validation checks:**
- Minimum length (8/15/15 for Low/Moderate/High)
- Not based on username or email
- Not in common password lists
- Optional: not in breach databases (with `hibp` feature)

### Available Policies

```rust
PasswordPolicy::fedramp_low()      // 8 char min
PasswordPolicy::fedramp_moderate() // 15 char min (STIG requirement)
PasswordPolicy::fedramp_high()     // 15 char min

// Or customize:
PasswordPolicy::builder()
    .min_length(12)
    .require_mixed_case(true)
    .build()
```

---

## Step 6: Add Login Attempt Tracking

Protect against brute force attacks with account lockout:

```rust
use barbican::prelude::*;
use std::sync::Arc;

// Create tracker at app startup (stores attempts in memory)
let login_tracker = Arc::new(LoginTracker::new(
    LockoutPolicy::fedramp_moderate() // 3 attempts, 30 min lockout
));

// Add to app state
let app = Router::new()
    .route("/auth/login", post(login))
    .with_state(login_tracker);
```

```rust
#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

async fn login(
    State(tracker): State<Arc<LoginTracker>>,
    Json(input): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Check if already locked out
    if let Some(info) = tracker.check_lockout(&input.email) {
        return Err(AppError::locked_out(info.remaining_seconds()));
    }

    // Attempt authentication (your logic)
    match authenticate(&input.email, &input.password).await {
        Ok(user) => {
            tracker.record_success(&input.email);
            Ok(Json(LoginResponse { token: create_token(&user) }))
        }
        Err(_) => {
            let result = tracker.record_failure(&input.email);
            match result {
                AttemptResult::Locked(info) => {
                    Err(AppError::locked_out(info.remaining_seconds()))
                }
                AttemptResult::Warning(remaining) => {
                    Err(AppError::auth_failed(format!(
                        "Invalid credentials. {} attempts remaining.", remaining
                    )))
                }
                AttemptResult::Failed => {
                    Err(AppError::auth_failed("Invalid credentials"))
                }
            }
        }
    }
}
```

**Lockout policies by profile:**

| Profile | Max Attempts | Lockout Duration |
|---------|--------------|------------------|
| Low | 3 | 30 minutes |
| Moderate | 3 | 30 minutes |
| High | 3 | 3 hours |

---

## Step 7: Add Session Management

Track user sessions with idle and absolute timeouts:

```rust
use barbican::prelude::*;
use std::collections::HashMap;
use std::sync::RwLock;

// Session store (use Redis in production)
struct SessionStore {
    sessions: RwLock<HashMap<String, SessionState>>,
    policy: SessionPolicy,
}

impl SessionStore {
    fn new(policy: SessionPolicy) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            policy,
        }
    }

    fn create(&self, user_id: &str) -> String {
        let session = SessionState::new(user_id);
        let id = session.id().to_string();
        self.sessions.write().unwrap().insert(id.clone(), session);
        id
    }

    fn validate(&self, session_id: &str) -> Option<SessionState> {
        let sessions = self.sessions.read().unwrap();
        let session = sessions.get(session_id)?;

        if self.policy.is_valid(session) {
            Some(session.clone())
        } else {
            None // Expired
        }
    }

    fn touch(&self, session_id: &str) {
        if let Some(session) = self.sessions.write().unwrap().get_mut(session_id) {
            session.touch(); // Reset idle timer
        }
    }
}

// At startup
let sessions = Arc::new(SessionStore::new(
    SessionPolicy::fedramp_moderate() // 15 min idle, 15 min max
));
```

**Session policies by profile:**

| Profile | Idle Timeout | Max Lifetime |
|---------|--------------|--------------|
| Low | 15 min | 30 min |
| Moderate | 15 min | 15 min |
| High | 10 min | 10 min |

---

## Step 8: Add Audit Logging

Log security events for compliance:

```rust
use barbican::prelude::*;

async fn login(
    State(tracker): State<Arc<LoginTracker>>,
    Json(input): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    match authenticate(&input.email, &input.password).await {
        Ok(user) => {
            // Log successful authentication (AU-2, AU-3)
            info!(
                event = "authentication",
                outcome = "success",
                user_id = %user.id,
                email = %input.email,
                "User authenticated successfully"
            );

            tracker.record_success(&input.email);
            Ok(Json(LoginResponse { token: create_token(&user) }))
        }
        Err(e) => {
            // Log failed authentication attempt
            warn!(
                event = "authentication",
                outcome = "failure",
                email = %input.email,
                reason = %e,
                "Authentication failed"
            );

            tracker.record_failure(&input.email);
            Err(AppError::auth_failed("Invalid credentials"))
        }
    }
}
```

### Add Audit Middleware for All Requests

```rust
let app = Router::new()
    .route("/users", post(create_user))
    .route("/users/:id", get(get_user))
    .layer(audit_middleware())  // Logs all requests with timing
    .with_security_headers()
    .with_rate_limiting(100, 10);
```

This automatically logs:
- Request method and path
- Response status code
- Request duration
- Client IP (if available)
- User ID (if authenticated)

---

## Step 9: Add Secure Error Handling

Don't leak internal details in error responses:

```rust
use barbican::prelude::*;

// Configure error handling
let error_config = ErrorConfig::production(); // Hides internal details

// In handlers, use AppError which respects the config
async fn get_user(Path(id): Path<i64>) -> Result<Json<User>, AppError> {
    let user = db.find_user(id).await
        .map_err(|e| {
            // Log the real error internally
            error!(error = %e, user_id = %id, "Database error fetching user");
            // Return safe error to client
            AppError::internal("Unable to fetch user")
        })?;

    Ok(Json(user))
}
```

**Production vs Development:**

```rust
// Development - shows details for debugging
let config = ErrorConfig::development();
// Response: {"error": "Database error: connection refused", "details": "...stack trace..."}

// Production - hides internal details
let config = ErrorConfig::production();
// Response: {"error": "An internal error occurred", "request_id": "abc123"}
```

---

## Step 10: Full Integration Example

Here's the complete integrated application:

```rust
use axum::{Router, routing::{get, post}, Json, extract::{State, Path}};
use barbican::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

// === Types ===

#[derive(Deserialize)]
struct CreateUser {
    email: String,
    password: String,
    name: String,
}

impl Validate for CreateUser {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_email(&self.email)?;
        validate_length(&self.name, 1, 100, "name")?;
        validate_length(&self.password, 8, 128, "password")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct User {
    id: i64,
    email: String,
    name: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

// === App State ===

#[derive(Clone)]
struct AppState {
    login_tracker: Arc<LoginTracker>,
    password_policy: PasswordPolicy,
}

// === Handlers ===

async fn create_user(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<CreateUser>,
) -> Result<Json<User>, AppError> {
    // Validate password strength
    state.password_policy
        .validate(&input.password, Some(&input.name), Some(&input.email))
        .map_err(|e| AppError::validation(format!("Password: {}", e)))?;

    // Sanitize and create user
    let user = User {
        id: 1,
        email: input.email,
        name: sanitize_html(&input.name),
    };

    info!(event = "user_created", user_id = %user.id, "New user created");
    Ok(Json(user))
}

async fn login(
    State(state): State<AppState>,
    Json(input): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Check lockout
    if let Some(info) = state.login_tracker.check_lockout(&input.email) {
        warn!(event = "login_blocked", email = %input.email, "Login attempt while locked out");
        return Err(AppError::locked_out(info.remaining_seconds()));
    }

    // Your authentication logic here
    let authenticated = input.password == "correct"; // Replace with real auth

    if authenticated {
        state.login_tracker.record_success(&input.email);
        info!(event = "login_success", email = %input.email, "User logged in");
        Ok(Json(LoginResponse { token: "jwt_token_here".into() }))
    } else {
        let result = state.login_tracker.record_failure(&input.email);
        warn!(event = "login_failed", email = %input.email, "Invalid credentials");

        match result {
            AttemptResult::Locked(info) => {
                Err(AppError::locked_out(info.remaining_seconds()))
            }
            _ => Err(AppError::auth_failed("Invalid credentials"))
        }
    }
}

async fn get_user(Path(id): Path<i64>) -> Result<Json<User>, AppError> {
    // Your database logic here
    Ok(Json(User {
        id,
        email: "user@example.com".into(),
        name: "Test User".into(),
    }))
}

async fn health() -> &'static str {
    "OK"
}

// === Main ===

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    // Create app state with FedRAMP Moderate policies
    let state = AppState {
        login_tracker: Arc::new(LoginTracker::new(LockoutPolicy::fedramp_moderate())),
        password_policy: PasswordPolicy::fedramp_moderate(),
    };

    // Build router with all security layers
    let app = Router::new()
        .route("/health", get(health))
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/auth/login", post(login))
        .with_state(state)
        .layer(audit_middleware())
        .with_security_headers()
        .with_rate_limiting(100, 10)
        .with_request_timeout(Duration::from_secs(30))
        .with_body_limit(1024 * 1024);

    info!("Starting server on 0.0.0.0:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

---

## Development Mode

For local development without TLS:

```rust
// Use relaxed settings for development
let password_policy = if cfg!(debug_assertions) {
    PasswordPolicy::builder().min_length(4).build() // Relaxed for testing
} else {
    PasswordPolicy::fedramp_moderate()
};

let lockout_policy = if cfg!(debug_assertions) {
    LockoutPolicy::builder()
        .max_attempts(100) // Effectively disabled
        .lockout_duration(Duration::from_secs(1))
        .build()
} else {
    LockoutPolicy::fedramp_moderate()
};
```

Or use environment-based configuration:

```rust
let policy = match std::env::var("BARBICAN_PROFILE").as_deref() {
    Ok("development") => PasswordPolicy::builder().min_length(4).build(),
    Ok("fedramp-low") => PasswordPolicy::fedramp_low(),
    Ok("fedramp-high") => PasswordPolicy::fedramp_high(),
    _ => PasswordPolicy::fedramp_moderate(),
};
```

---

## Next Steps

- [API Reference](./API_REFERENCE.md) - Complete API documentation
- [Configuration Reference](./CONFIGURATION_REFERENCE.md) - All barbican.toml options
- [Testing Guide](./TESTING_GUIDE.md) - How to test your integration
- [Troubleshooting](./TROUBLESHOOTING.md) - Common issues and solutions
