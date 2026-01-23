//! JWT Token Handling
//!
//! Creates and validates JSON Web Tokens for session management.

use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

use crate::error::AppError;

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// User email
    pub email: String,
    /// Expiration timestamp
    pub exp: i64,
    /// Issued at timestamp
    pub iat: i64,
    /// Token ID (for revocation tracking)
    pub jti: String,
}

impl Claims {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Get user ID
    pub fn user_id(&self) -> &str {
        &self.sub
    }
}

/// Create a new JWT token
pub fn create_token(
    user_id: &str,
    email: &str,
    secret: &str,
    lifetime_secs: u64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let exp = now + Duration::seconds(lifetime_secs as i64);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::internal(format!("Token creation failed: {}", e)))
}

/// Validate and decode a JWT token
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    let mut validation = Validation::default();
    validation.leeway = 0; // No clock skew tolerance

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                AppError::auth_failed("Token expired")
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                AppError::auth_failed("Invalid token")
            }
            _ => AppError::auth_failed("Token validation failed")
        }
    })
}
