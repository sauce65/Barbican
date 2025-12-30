//! Rust configuration generator
//!
//! Generates Rust configuration module from barbican.toml

use crate::config::BarbicanConfig;
use crate::error::Result;
use crate::profile::ComplianceProfile;

use super::GeneratedFile;

/// Generate all Rust configuration files
pub fn generate(config: &BarbicanConfig) -> Result<Vec<GeneratedFile>> {
    let mut files = Vec::new();

    // Main configuration module
    files.push(generate_config_module(config)?);

    Ok(files)
}

/// Generate the barbican_config.rs module
fn generate_config_module(config: &BarbicanConfig) -> Result<GeneratedFile> {
    let profile = config.profile();
    let app_name = &config.app.name;
    let app_version = &config.app.version;

    // Compute all config values
    let idle_timeout_secs = config
        .session
        .as_ref()
        .and_then(|s| s.idle_timeout.as_ref())
        .and_then(|t| parse_duration_secs(t))
        .unwrap_or((profile.idle_timeout_minutes() * 60) as u64);

    let session_timeout_secs = config
        .session
        .as_ref()
        .and_then(|s| s.absolute_timeout.as_ref())
        .and_then(|t| parse_duration_secs(t))
        .unwrap_or((profile.session_timeout_minutes() * 60) as u64);

    let require_mfa = config
        .auth
        .as_ref()
        .and_then(|a| a.require_mfa)
        .unwrap_or(profile.requires_mfa());

    let max_attempts = config
        .auth
        .as_ref()
        .and_then(|a| a.max_login_attempts)
        .unwrap_or(profile.max_login_attempts());

    let lockout_secs = config
        .auth
        .as_ref()
        .and_then(|a| a.lockout_duration.as_ref())
        .and_then(|t| parse_duration_secs(t))
        .unwrap_or((profile.lockout_duration_minutes() * 60) as u64);

    let min_password = config
        .auth
        .as_ref()
        .and_then(|a| a.min_password_length)
        .unwrap_or(profile.min_password_length());

    let retention_days = config
        .observability
        .as_ref()
        .and_then(|o| o.retention_days)
        .unwrap_or(profile.min_retention_days());

    let pool_size = config
        .database
        .as_ref()
        .and_then(|d| d.pool_size)
        .unwrap_or(10);

    let tls_mode = if profile.requires_mtls() {
        "TlsMode::Strict"
    } else {
        "TlsMode::Required"
    };

    let ssl_mode = if profile.requires_ssl_verify_full() {
        "SslMode::VerifyFull"
    } else {
        "SslMode::Require"
    };

    let rust = format!(
        r#"// AUTO-GENERATED FROM barbican.toml - DO NOT EDIT
// Regenerate with: barbican generate rust
// Profile: {profile_name}
// Generated: {timestamp}

use barbican::prelude::*;
use std::time::Duration;

/// Configuration constants from barbican.toml
pub struct GeneratedConfig;

impl GeneratedConfig {{
    // =========================================================================
    // Application Metadata
    // =========================================================================

    /// Application name
    pub const APP_NAME: &'static str = "{app_name}";

    /// Application version
    pub const APP_VERSION: &'static str = "{app_version}";

    /// Compliance profile
    pub const PROFILE: ComplianceProfile = ComplianceProfile::{profile_variant};

    // =========================================================================
    // Session Timeouts (AC-11, AC-12)
    // =========================================================================

    /// Idle timeout in seconds (AC-11)
    pub const IDLE_TIMEOUT_SECS: u64 = {idle_timeout_secs};

    /// Maximum session lifetime in seconds (AC-12)
    pub const SESSION_TIMEOUT_SECS: u64 = {session_timeout_secs};

    /// Create session policy with profile-appropriate timeouts
    pub fn session_policy() -> SessionPolicy {{
        SessionPolicy::builder()
            .idle_timeout(Duration::from_secs(Self::IDLE_TIMEOUT_SECS))
            .max_lifetime(Duration::from_secs(Self::SESSION_TIMEOUT_SECS))
            .build()
    }}

    // =========================================================================
    // Login Security (AC-7)
    // =========================================================================

    /// Maximum failed login attempts before lockout
    pub const MAX_LOGIN_ATTEMPTS: u32 = {max_attempts};

    /// Lockout duration in seconds
    pub const LOCKOUT_DURATION_SECS: u64 = {lockout_secs};

    /// Create lockout policy
    pub fn lockout_policy() -> LockoutPolicy {{
        LockoutPolicy::builder()
            .max_attempts(Self::MAX_LOGIN_ATTEMPTS)
            .lockout_duration(Duration::from_secs(Self::LOCKOUT_DURATION_SECS))
            .build()
    }}

    // =========================================================================
    // Authentication (IA-2, IA-5)
    // =========================================================================

    /// Whether MFA is required for this profile
    pub const MFA_REQUIRED: bool = {mfa_required};

    /// Minimum password length (IA-5)
    pub const MIN_PASSWORD_LENGTH: usize = {min_password};

    /// Create MFA policy
    pub fn mfa_policy() -> MfaPolicy {{
        if Self::MFA_REQUIRED {{
            MfaPolicy::require_mfa()
        }} else {{
            MfaPolicy::none()
        }}
    }}

    /// Create password policy
    pub fn password_policy() -> PasswordPolicy {{
        PasswordPolicy::builder()
            .min_length(Self::MIN_PASSWORD_LENGTH)
            .build()
    }}

    // =========================================================================
    // TLS/Transport Security (SC-8)
    // =========================================================================

    /// Create security configuration with TLS enforcement
    pub fn security_config() -> SecurityConfig {{
        SecurityConfig::builder()
            .tls_mode({tls_mode})
            .audit(true)
            .build()
    }}

    // =========================================================================
    // Audit/Observability (AU-11)
    // =========================================================================

    /// Minimum log retention in days
    pub const MIN_RETENTION_DAYS: u32 = {retention_days};
{database_section}}}

// =============================================================================
// Router Extension
// =============================================================================

/// Extension trait for applying Barbican security to an Axum router
pub trait BarbicanApp {{
    /// Apply all security middleware from the generated configuration
    fn with_barbican(self) -> Self;
}}

impl<S> BarbicanApp for axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{{
    fn with_barbican(self) -> Self {{
        self.with_security(GeneratedConfig::security_config())
    }}
}}
"#,
        profile_name = profile.name(),
        timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        app_name = app_name,
        app_version = app_version,
        profile_variant = profile_variant(profile),
        idle_timeout_secs = idle_timeout_secs,
        session_timeout_secs = session_timeout_secs,
        max_attempts = max_attempts,
        lockout_secs = lockout_secs,
        mfa_required = require_mfa,
        min_password = min_password,
        tls_mode = tls_mode,
        retention_days = retention_days,
        database_section = if config.database.is_some() {
            format!(
                r#"
    // =========================================================================
    // Database (SC-8)
    // =========================================================================

    /// Database pool size
    pub const DB_POOL_SIZE: u32 = {pool_size};

    /// Database connection URL from environment
    #[cfg(feature = "postgres")]
    pub fn database_url() -> String {{
        std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set")
    }}

    /// Create database configuration
    #[cfg(feature = "postgres")]
    pub fn database_config(url: &str) -> DatabaseConfig {{
        DatabaseConfig::builder(url)
            .ssl_mode({ssl_mode})
            .max_connections(Self::DB_POOL_SIZE)
            .build()
    }}
"#,
                pool_size = pool_size,
                ssl_mode = ssl_mode,
            )
        } else {
            String::new()
        },
    );

    Ok(GeneratedFile::new("src/generated/barbican_config.rs", rust))
}

fn profile_variant(profile: ComplianceProfile) -> &'static str {
    match profile {
        ComplianceProfile::FedRampLow => "FedRampLow",
        ComplianceProfile::FedRampModerate => "FedRampModerate",
        ComplianceProfile::FedRampHigh => "FedRampHigh",
        ComplianceProfile::Soc2 => "Soc2",
        ComplianceProfile::Custom => "Custom",
    }
}

/// Parse a duration string like "30s" or "15m" into seconds
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();

    if let Some(secs) = s.strip_suffix('s') {
        return secs.trim().parse().ok();
    }

    if let Some(mins) = s.strip_suffix('m') {
        return mins.trim().parse::<u64>().ok().map(|m| m * 60);
    }

    if let Some(hours) = s.strip_suffix('h') {
        return hours.trim().parse::<u64>().ok().map(|h| h * 3600);
    }

    // Try parsing as plain number (assume seconds)
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_secs() {
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("15m"), Some(900));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("60"), Some(60));
    }
}
