//! Application Configuration
//!
//! Loads configuration from environment variables with secure defaults.

use barbican::encryption::EncryptionConfig;
use barbican::compliance::ComplianceProfile;
use anyhow::{Context, Result};

/// Application configuration loaded from environment
pub struct AppConfig {
    /// Compliance profile (FedRAMP Low/Moderate/High)
    pub profile: ComplianceProfile,

    /// JWT signing secret
    pub jwt_secret: String,

    /// JWT token lifetime in seconds
    pub jwt_lifetime_secs: u64,

    /// Database connection URL
    pub database_url: Option<String>,

    /// Encryption configuration for sensitive fields
    pub encryption_config: EncryptionConfig,
}

impl AppConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        // Compliance profile with fallback to Moderate
        let profile = std::env::var("BARBICAN_PROFILE")
            .unwrap_or_else(|_| "fedramp-moderate".into())
            .parse()
            .context("Invalid BARBICAN_PROFILE")?;

        // Required: JWT secret for token signing
        let jwt_secret = std::env::var("JWT_SECRET")
            .context("JWT_SECRET environment variable required")?;

        // Validate JWT secret length (should be at least 32 bytes)
        if jwt_secret.len() < 32 {
            anyhow::bail!("JWT_SECRET must be at least 32 characters");
        }

        // JWT lifetime based on session policy
        let jwt_lifetime_secs = match &profile {
            ComplianceProfile::FedRampHigh => 600,     // 10 minutes
            ComplianceProfile::FedRampModerate => 900, // 15 minutes
            _ => 1800,                                  // 30 minutes
        };

        // Optional: Database URL
        let database_url = std::env::var("DATABASE_URL").ok();

        // Encryption key for field-level encryption
        let encryption_config = EncryptionConfig::from_env()
            .context("ENCRYPTION_KEY environment variable required")?;

        Ok(Self {
            profile,
            jwt_secret,
            jwt_lifetime_secs,
            database_url,
            encryption_config,
        })
    }
}
