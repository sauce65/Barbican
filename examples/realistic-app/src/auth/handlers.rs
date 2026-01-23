//! Authentication Handlers
//!
//! Implements secure registration and login with Barbican controls.

use axum::{extract::State, Json};
use barbican::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::AppError;
use crate::AppState;
use super::jwt;

// =============================================================================
// Registration (IA-5)
// =============================================================================

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: String,
}

impl Validate for RegisterRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_email(&self.email)?;
        validate_length(&self.name, 1, 100, "name")?;
        validate_length(&self.password, 1, 128, "password")?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: String,
    pub email: String,
    pub name: String,
}

/// Register a new user account
///
/// Validates:
/// - Email format (SI-10)
/// - Password strength per profile (IA-5)
/// - Name length and sanitization (SI-10)
pub async fn register(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    // Validate password against policy (IA-5)
    state.password_policy
        .validate(&input.password, Some(&input.name), Some(&input.email))?;

    // Check if user already exists
    // In production: query database
    // if db.user_exists(&input.email).await? {
    //     return Err(AppError::conflict("Email already registered"));
    // }

    // Hash password with Argon2
    let password_hash = hash_password(&input.password)?;

    // Create user in database
    let user_id = uuid::Uuid::new_v4().to_string();
    // In production: db.create_user(&user_id, &input.email, &password_hash, &input.name).await?;

    // Audit log (AU-2)
    info!(
        event = "user.registered",
        user_id = %user_id,
        email = %input.email,
        "New user registered"
    );

    Ok(Json(RegisterResponse {
        id: user_id,
        email: input.email,
        name: sanitize_html(&input.name),
    }))
}

// =============================================================================
// Login (AC-7, IA-2)
// =============================================================================

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
}

/// Authenticate user and issue JWT
///
/// Implements:
/// - Account lockout after failed attempts (AC-7)
/// - Audit logging of auth events (AU-2, AU-3)
pub async fn login(
    State(state): State<AppState>,
    Json(input): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Check if account is locked (AC-7)
    if let Some(info) = state.login_tracker.check_lockout(&input.email) {
        warn!(
            event = "auth.blocked",
            email = %input.email,
            remaining_secs = %info.remaining_seconds(),
            "Login attempt while locked out"
        );
        return Err(AppError::locked_out(info.remaining_seconds()));
    }

    // Attempt authentication
    // In production: lookup user and verify password
    let auth_result = authenticate_user(&input.email, &input.password).await;

    match auth_result {
        Ok(user_id) => {
            // Clear failed attempts on success
            state.login_tracker.record_success(&input.email);

            // Generate JWT
            let token = jwt::create_token(
                &user_id,
                &input.email,
                &state.config.jwt_secret,
                state.config.jwt_lifetime_secs,
            )?;

            // Audit successful login (AU-2)
            info!(
                event = "auth.success",
                user_id = %user_id,
                email = %input.email,
                "User authenticated"
            );

            Ok(Json(LoginResponse {
                token,
                expires_in: state.config.jwt_lifetime_secs,
            }))
        }
        Err(e) => {
            // Record failed attempt (AC-7)
            let result = state.login_tracker.record_failure(&input.email);

            // Audit failed login (AU-2)
            warn!(
                event = "auth.failed",
                email = %input.email,
                reason = %e,
                "Authentication failed"
            );

            match result {
                AttemptResult::Locked(info) => {
                    warn!(
                        event = "auth.lockout",
                        email = %input.email,
                        duration_secs = %info.remaining_seconds(),
                        "Account locked after failed attempts"
                    );
                    Err(AppError::locked_out(info.remaining_seconds()))
                }
                AttemptResult::Warning(remaining) => {
                    Err(AppError::auth_failed(format!(
                        "Invalid credentials. {} attempts remaining.",
                        remaining
                    )))
                }
                AttemptResult::Failed => {
                    Err(AppError::auth_failed("Invalid credentials"))
                }
            }
        }
    }
}

// =============================================================================
// Logout
// =============================================================================

#[derive(Serialize)]
pub struct LogoutResponse {
    pub message: String,
}

/// Logout user (invalidate session)
///
/// For JWT-based auth, client should discard token.
/// For additional security, implement token blocklist.
pub async fn logout(
    State(_state): State<AppState>,
    // claims: super::Claims, // Extracted by middleware
) -> Json<LogoutResponse> {
    // In production with token blocklist:
    // state.blocklist.add(&claims.jti, claims.exp).await;

    // For now, just acknowledge - client discards token
    Json(LogoutResponse {
        message: "Logged out successfully".into(),
    })
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Hash password with Argon2id
fn hash_password(password: &str) -> Result<String, AppError> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::SaltString;
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::internal(format!("Password hashing failed: {}", e)))
}

/// Verify password against stored hash
#[allow(dead_code)]
fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordVerifier};
    use argon2::password_hash::PasswordHash;

    PasswordHash::new(hash)
        .ok()
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

/// Authenticate user against database
///
/// In production, this queries the database.
/// For demo purposes, uses a hardcoded check.
async fn authenticate_user(email: &str, password: &str) -> Result<String, &'static str> {
    // In production:
    // let user = db.find_user_by_email(email).await?;
    // if verify_password(password, &user.password_hash) {
    //     Ok(user.id)
    // } else {
    //     Err("Invalid credentials")
    // }

    // Demo: accept any password with 15+ chars for "test@example.com"
    if email == "test@example.com" && password.len() >= 15 {
        Ok("user_123".into())
    } else {
        Err("Invalid credentials")
    }
}
