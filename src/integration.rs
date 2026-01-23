//! Integration Support Module
//!
//! High-level APIs that simplify integrating Barbican into applications.
//! This module provides profile-aware factory functions that automatically
//! configure security components based on compliance requirements.
//!
//! # Quick Start
//!
//! ```ignore
//! use barbican::integration::*;
//! use barbican::compliance::ComplianceProfile;
//!
//! // Get compliance profile from environment
//! let profile = profile_from_env();
//!
//! // Create all policies from profile
//! let session_policy = session_policy_for_profile(profile);
//! let password_policy = password_policy_for_profile(profile);
//! let lockout_policy = lockout_policy_for_profile(profile);
//! let encryption_config = encryption_config_for_profile(profile);
//!
//! // Or create database config with SSL based on profile
//! #[cfg(feature = "postgres")]
//! let db_config = database_config_for_profile("postgres://...", profile);
//! ```
//!
//! # Import Cheatsheet
//!
//! Most types should be imported from the crate root:
//!
//! ```ignore
//! // Core types (always available)
//! use barbican::{
//!     SecurityConfig, SecureRouter,
//!     ComplianceConfig, ComplianceProfile, ComplianceValidator,
//!     SessionPolicy, SessionState, SessionTerminationReason,
//!     LockoutPolicy, LoginTracker, AttemptResult, LockoutInfo,
//!     PasswordPolicy, PasswordError, PasswordStrength,
//!     AlertConfig, AlertManager, Alert, AlertSeverity, AlertCategory,
//!     HealthChecker, HealthCheck, HealthStatus, HealthReport,
//!     KeyStore, KeyMetadata, RotationTracker, RotationPolicy,
//!     ValidationError, Validate,
//!     constant_time_eq, constant_time_str_eq,
//! };
//!
//! // Database types (require 'postgres' feature)
//! #[cfg(feature = "postgres")]
//! use barbican::{
//!     DatabaseConfig, DatabaseConfigBuilder, DatabaseError,
//!     SslMode, ChannelBinding, DbHealthStatus,
//!     create_pool, health_check,
//! };
//!
//! // Compliance artifacts (require 'compliance-artifacts' feature)
//! #[cfg(feature = "compliance-artifacts")]
//! use barbican::compliance::artifacts::{
//!     ComplianceTestReport, ControlTestArtifact, ArtifactBuilder,
//!     EvidenceCollector, EvidenceItem, TestSummary,
//! };
//!
//! // Supply chain types
//! use barbican::{
//!     Dependency, DependencySource, AuditResult,
//!     SbomMetadata, LicensePolicy,
//!     parse_cargo_lock, generate_cyclonedx_sbom,
//! };
//!
//! // Integration helpers
//! use barbican::integration::*;
//! ```

use crate::compliance::ComplianceProfile;
use crate::encryption::{EncryptionAlgorithm, EncryptionConfig};
use crate::login::LockoutPolicy;
use crate::password::PasswordPolicy;
use crate::session::SessionPolicy;
use crate::supply_chain::{
    generate_cyclonedx_sbom, parse_cargo_lock, AuditResult, SbomMetadata, SupplyChainError,
};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[cfg(feature = "postgres")]
use crate::database::{ChannelBinding, DatabaseConfig, DatabaseConfigBuilder, SslMode};

// ============================================================================
// Profile Detection
// ============================================================================

/// Get compliance profile from environment variable.
///
/// Reads `DPE_COMPLIANCE_PROFILE` or `BARBICAN_COMPLIANCE_PROFILE` environment
/// variable and returns the corresponding profile. Defaults to FedRAMP Moderate.
///
/// Supported values:
/// - `fedramp-low`, `low` → FedRAMP Low
/// - `fedramp-moderate`, `moderate` → FedRAMP Moderate (default)
/// - `fedramp-high`, `high` → FedRAMP High
/// - `soc2` → SOC 2 Type II
///
/// # Example
///
/// ```ignore
/// let profile = profile_from_env();
/// let session_policy = session_policy_for_profile(profile);
/// ```
pub fn profile_from_env() -> ComplianceProfile {
    let profile_str = std::env::var("DPE_COMPLIANCE_PROFILE")
        .or_else(|_| std::env::var("BARBICAN_COMPLIANCE_PROFILE"))
        .unwrap_or_else(|_| "fedramp-moderate".to_string());

    match profile_str.to_lowercase().as_str() {
        "fedramp-low" | "low" => ComplianceProfile::FedRampLow,
        "fedramp-high" | "high" => ComplianceProfile::FedRampHigh,
        "soc2" => ComplianceProfile::Soc2,
        _ => ComplianceProfile::FedRampModerate,
    }
}

// ============================================================================
// Profile-Aware Factory Functions
// ============================================================================

/// Create a session policy configured for the compliance profile.
///
/// Uses STIG-compliant values from `ComplianceProfile` methods:
/// - Idle timeout from `profile.idle_timeout()` (STIG UBTU-22-412020: 15 min)
/// - Concurrent session limits for AC-10 compliance
///
/// | Profile | Idle Timeout | Max Lifetime | Concurrent Sessions (AC-10) |
/// |---------|--------------|--------------|----------------------------|
/// | FedRAMP Low | 15 min | 12 hours | 5 |
/// | FedRAMP Moderate | 15 min | 8 hours | 3 |
/// | FedRAMP High | 10 min | 4 hours | 1 |
/// | SOC 2 | 15 min | 8 hours | 3 |
/// | Development | 24 hours | 24 hours | unlimited |
///
/// # Example
///
/// ```ignore
/// let policy = session_policy_for_profile(ComplianceProfile::FedRampHigh);
/// assert_eq!(policy.idle_timeout, Duration::from_secs(600));
/// assert_eq!(policy.max_concurrent_sessions, Some(1));
/// ```
pub fn session_policy_for_profile(profile: ComplianceProfile) -> SessionPolicy {
    let idle_timeout = profile.idle_timeout();

    match profile {
        ComplianceProfile::FedRampLow => SessionPolicy::builder()
            .idle_timeout(idle_timeout)
            .max_lifetime(Duration::from_secs(12 * 60 * 60)) // 12 hours
            .max_concurrent_sessions(Some(5)) // AC-10
            .build(),
        ComplianceProfile::Development => SessionPolicy::builder()
            .idle_timeout(idle_timeout) // 24 hours for dev
            .max_lifetime(Duration::from_secs(24 * 60 * 60)) // 24 hours
            .max_concurrent_sessions(None) // AC-10: unlimited for dev
            .build(),
        ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => SessionPolicy::builder()
            .idle_timeout(idle_timeout)
            .max_lifetime(Duration::from_secs(8 * 60 * 60)) // 8 hours
            .max_concurrent_sessions(Some(3)) // AC-10
            .build(),
        ComplianceProfile::FedRampHigh => SessionPolicy::builder()
            .idle_timeout(idle_timeout)
            .max_lifetime(Duration::from_secs(4 * 60 * 60)) // 4 hours
            .max_concurrent_sessions(Some(1)) // AC-10: strictest
            .require_reauth_for_sensitive(true)
            .reauth_timeout(Duration::from_secs(5 * 60)) // 5 min for sensitive
            .build(),
        ComplianceProfile::Custom => SessionPolicy::builder()
            .idle_timeout(Duration::from_secs(15 * 60))
            .max_lifetime(Duration::from_secs(8 * 60 * 60))
            .max_concurrent_sessions(None) // AC-10: unlimited for custom
            .build(),
    }
}

/// Create a password policy configured for the compliance profile.
///
/// Uses STIG-compliant values from `ComplianceProfile` methods:
/// - FedRAMP Low: 8 char min (NIST 800-63B with MFA compensation)
/// - FedRAMP Moderate: 15 char min (STIG UBTU-22-611035)
/// - FedRAMP High: 15 char min + breach database check
///
/// All profiles use NIST 800-63B compliant defaults which emphasize
/// length over complexity (no arbitrary character requirements).
///
/// # Example
///
/// ```ignore
/// let policy = password_policy_for_profile(ComplianceProfile::FedRampHigh);
/// policy.validate("MySecurePassword123!")?;
/// ```
pub fn password_policy_for_profile(profile: ComplianceProfile) -> PasswordPolicy {
    let min_length = profile.min_password_length();
    let requires_breach_check = profile.requires_breach_checking();

    match profile {
        ComplianceProfile::FedRampLow | ComplianceProfile::Development => PasswordPolicy::builder()
            .min_length(min_length)
            .build(),
        ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => PasswordPolicy::builder()
            .min_length(min_length)
            .check_common_passwords(true)
            .disallow_username_in_password(true)
            .build(),
        ComplianceProfile::FedRampHigh => PasswordPolicy::builder()
            .min_length(min_length)
            .check_common_passwords(true)
            .check_breach_database(requires_breach_check)
            .disallow_username_in_password(true)
            .disallow_email_in_password(true)
            .build(),
        ComplianceProfile::Custom => PasswordPolicy::default(),
    }
}

/// Create a lockout policy configured for the compliance profile.
///
/// Uses STIG-compliant values from `ComplianceProfile` methods:
/// - All FedRAMP profiles: 3 attempts (STIG UBTU-22-411045)
/// - FedRAMP Low/Moderate: 30 min lockout (STIG UBTU-22-411050)
/// - FedRAMP High: 3 hour lockout (FedRAMP baseline, admin release)
///
/// # Example
///
/// ```ignore
/// let policy = lockout_policy_for_profile(ComplianceProfile::FedRampHigh);
/// let tracker = LoginTracker::new(policy);
/// ```
pub fn lockout_policy_for_profile(profile: ComplianceProfile) -> LockoutPolicy {
    let max_attempts = profile.max_login_attempts();
    let lockout_duration = profile.lockout_duration();

    match profile {
        ComplianceProfile::FedRampLow => LockoutPolicy::builder()
            .max_attempts(max_attempts)
            .lockout_duration(lockout_duration)
            .progressive_lockout(false)
            .build(),
        ComplianceProfile::Development => LockoutPolicy::builder()
            .max_attempts(max_attempts)
            .lockout_duration(lockout_duration) // 1 minute for dev
            .progressive_lockout(false)
            .build(),
        ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => LockoutPolicy::builder()
            .max_attempts(max_attempts)
            .lockout_duration(lockout_duration)
            .progressive_lockout(true)
            .build(),
        ComplianceProfile::FedRampHigh => LockoutPolicy::builder()
            .max_attempts(max_attempts)
            .lockout_duration(lockout_duration) // 3 hours
            .progressive_lockout(true)
            .build(),
        ComplianceProfile::Custom => LockoutPolicy::relaxed(),
    }
}

/// Create an encryption config configured for the compliance profile.
///
/// All profiles use AES-256-GCM. Higher profiles require encryption
/// and database encryption verification.
///
/// # Example
///
/// ```ignore
/// let config = encryption_config_for_profile(ComplianceProfile::FedRampHigh);
/// assert!(config.require_encryption);
/// ```
pub fn encryption_config_for_profile(profile: ComplianceProfile) -> EncryptionConfig {
    match profile {
        ComplianceProfile::FedRampLow | ComplianceProfile::Development => EncryptionConfig {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            require_encryption: false,
            verify_database_encryption: false,
            verify_disk_encryption: false,
        },
        ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => EncryptionConfig {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            require_encryption: true,
            verify_database_encryption: true,
            verify_disk_encryption: false,
        },
        ComplianceProfile::FedRampHigh => EncryptionConfig {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            require_encryption: true,
            verify_database_encryption: true,
            verify_disk_encryption: true,
        },
        ComplianceProfile::Custom => EncryptionConfig {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            require_encryption: false,
            verify_database_encryption: false,
            verify_disk_encryption: false,
        },
    }
}

/// Create a key rotation policy configured for the compliance profile.
///
/// - FedRAMP Low: 365 day rotation
/// - FedRAMP Moderate/SOC 2: 90 day rotation
/// - FedRAMP High: 30 day rotation
pub fn rotation_policy_for_profile(
    profile: ComplianceProfile,
) -> crate::keys::RotationPolicy {
    match profile {
        ComplianceProfile::FedRampLow | ComplianceProfile::Development => {
            crate::keys::RotationPolicy::new(Duration::from_secs(365 * 24 * 60 * 60))
        }
        ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => {
            crate::keys::RotationPolicy::new(Duration::from_secs(90 * 24 * 60 * 60))
        }
        ComplianceProfile::FedRampHigh => {
            crate::keys::RotationPolicy::new(Duration::from_secs(30 * 24 * 60 * 60))
        }
        ComplianceProfile::Custom => crate::keys::RotationPolicy::default(),
    }
}

// ============================================================================
// Database Configuration (requires 'postgres' feature)
// ============================================================================

/// Create a database config with SSL settings for the compliance profile.
///
/// - FedRAMP Low: SSL required
/// - FedRAMP Moderate/SOC 2: Certificate verification required
/// - FedRAMP High: Full certificate verification + channel binding
///
/// # Example
///
/// ```ignore
/// let config = database_config_for_profile(
///     "postgres://user:pass@localhost/db",
///     ComplianceProfile::FedRampHigh
/// );
/// let pool = create_pool(config).await?;
/// ```
#[cfg(feature = "postgres")]
pub fn database_config_for_profile(
    database_url: impl Into<String>,
    profile: ComplianceProfile,
) -> DatabaseConfig {
    let ssl_mode = ssl_mode_for_profile(profile);
    let channel_binding = channel_binding_for_profile(profile);

    DatabaseConfigBuilder::new(database_url)
        .ssl_mode(ssl_mode)
        .channel_binding(channel_binding)
        .build()
}

/// Get the required SSL mode for a compliance profile.
#[cfg(feature = "postgres")]
pub fn ssl_mode_for_profile(profile: ComplianceProfile) -> SslMode {
    match profile {
        ComplianceProfile::FedRampHigh => SslMode::VerifyFull,
        ComplianceProfile::FedRampModerate | ComplianceProfile::Soc2 => SslMode::VerifyCa,
        ComplianceProfile::FedRampLow | ComplianceProfile::Development => SslMode::Require,
        ComplianceProfile::Custom => SslMode::Prefer,
    }
}

/// Get the required channel binding mode for a compliance profile.
#[cfg(feature = "postgres")]
pub fn channel_binding_for_profile(profile: ComplianceProfile) -> ChannelBinding {
    match profile {
        ComplianceProfile::FedRampHigh | ComplianceProfile::FedRampModerate => {
            ChannelBinding::Require
        }
        _ => ChannelBinding::Prefer,
    }
}

/// Validate database config against a compliance profile.
///
/// Returns a list of compliance findings. Empty list means compliant.
///
/// # Example
///
/// ```ignore
/// let config = DatabaseConfigBuilder::new("postgres://...")
///     .ssl_mode(SslMode::Prefer)
///     .build();
/// let findings = validate_database_config(&config, ComplianceProfile::FedRampHigh);
/// if !findings.is_empty() {
///     for finding in findings {
///         eprintln!("Compliance issue: {}", finding);
///     }
/// }
/// ```
#[cfg(feature = "postgres")]
pub fn validate_database_config(
    config: &DatabaseConfig,
    profile: ComplianceProfile,
) -> Vec<String> {
    let mut findings = Vec::new();

    let required_ssl = ssl_mode_for_profile(profile);
    let required_channel = channel_binding_for_profile(profile);

    // Check SSL mode
    let ssl_order = |mode: SslMode| -> u8 {
        match mode {
            SslMode::Disable => 0,
            SslMode::Prefer => 1,
            SslMode::Require => 2,
            SslMode::VerifyCa => 3,
            SslMode::VerifyFull => 4,
        }
    };

    if ssl_order(config.ssl_mode) < ssl_order(required_ssl) {
        findings.push(format!(
            "SC-8: {} requires ssl_mode {:?} or higher, found {:?}",
            profile.name(),
            required_ssl,
            config.ssl_mode
        ));
    }

    // Check channel binding for high-security profiles
    if matches!(
        profile,
        ComplianceProfile::FedRampHigh | ComplianceProfile::FedRampModerate
    ) && config.channel_binding != required_channel
    {
        findings.push(format!(
            "SC-8: {} requires channel_binding {:?}, found {:?}",
            profile.name(),
            required_channel,
            config.channel_binding
        ));
    }

    findings
}

// ============================================================================
// SBOM Builder
// ============================================================================

/// Builder for generating Software Bill of Materials (SBOM).
///
/// Provides a higher-level API for SBOM generation that handles
/// Cargo.lock parsing and CycloneDX output internally.
///
/// # Example
///
/// ```ignore
/// let sbom = SbomBuilder::new("myapp", "1.0.0")
///     .organization("My Company")
///     .from_cargo_lock("Cargo.lock")?
///     .build();
///
/// println!("{}", sbom.to_json()?);
/// ```
pub struct SbomBuilder {
    name: String,
    version: String,
    organization: Option<String>,
    dependencies: HashMap<String, crate::supply_chain::Dependency>,
}

impl SbomBuilder {
    /// Create a new SBOM builder for an application.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            organization: None,
            dependencies: HashMap::new(),
        }
    }

    /// Set the organization name.
    pub fn organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    /// Load dependencies from a Cargo.lock file.
    pub fn from_cargo_lock(mut self, path: impl AsRef<Path>) -> Result<Self, SupplyChainError> {
        self.dependencies = parse_cargo_lock(path)?;
        Ok(self)
    }

    /// Load dependencies from Cargo.lock content string.
    pub fn from_cargo_lock_content(mut self, content: &str) -> Result<Self, SupplyChainError> {
        self.dependencies = crate::supply_chain::parse_cargo_lock_content(content)?;
        Ok(self)
    }

    /// Build the SBOM as a CycloneDX JSON string.
    pub fn build(self) -> String {
        let mut metadata = SbomMetadata::new(&self.name, &self.version);
        if let Some(org) = self.organization {
            metadata = metadata.with_organization(org);
        }
        generate_cyclonedx_sbom(&metadata, &self.dependencies)
    }

    /// Build and return the dependency count.
    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }
}

/// Quick SBOM generation from the current project.
///
/// Looks for Cargo.lock in the current directory or parent directories.
///
/// # Example
///
/// ```ignore
/// if let Some(sbom) = generate_sbom_from_project("myapp", "1.0.0") {
///     std::fs::write("sbom.json", sbom)?;
/// }
/// ```
pub fn generate_sbom_from_project(name: &str, version: &str) -> Option<String> {
    // Look for Cargo.lock
    let lock_path = Path::new("Cargo.lock");
    if lock_path.exists() {
        return SbomBuilder::new(name, version)
            .from_cargo_lock(lock_path)
            .ok()
            .map(|b| b.build());
    }

    // Try parent directory
    let parent_lock = Path::new("../Cargo.lock");
    if parent_lock.exists() {
        return SbomBuilder::new(name, version)
            .from_cargo_lock(parent_lock)
            .ok()
            .map(|b| b.build());
    }

    None
}

// ============================================================================
// Supply Chain Auditing
// ============================================================================

/// Run cargo-audit and return results.
///
/// This is a convenience wrapper around `supply_chain::run_cargo_audit()`.
///
/// # Example
///
/// ```ignore
/// let audit = run_security_audit();
/// if audit.has_vulnerabilities() {
///     println!("Found {} vulnerabilities!", audit.vulnerability_count());
///     if audit.has_critical() {
///         println!("CRITICAL vulnerabilities present!");
///     }
/// }
/// ```
pub fn run_security_audit() -> AuditResult {
    crate::supply_chain::run_cargo_audit().unwrap_or_default()
}

// ============================================================================
// Implemented Controls Summary
// ============================================================================

/// Information about an implemented NIST 800-53 control.
#[derive(Debug, Clone)]
pub struct ControlInfo {
    /// Control identifier (e.g., "AC-7")
    pub id: &'static str,
    /// Control name
    pub name: &'static str,
    /// Brief description of implementation
    pub description: &'static str,
    /// Module providing the implementation
    pub module: &'static str,
}

/// Get a list of all NIST 800-53 controls implemented by Barbican.
///
/// Useful for generating compliance documentation.
///
/// # Example
///
/// ```ignore
/// for control in implemented_controls() {
///     println!("{}: {} ({})", control.id, control.name, control.module);
/// }
/// ```
pub fn implemented_controls() -> Vec<ControlInfo> {
    vec![
        ControlInfo {
            id: "AC-2",
            name: "Account Management",
            description: "OAuth/OIDC JWT claims with role management",
            module: "auth",
        },
        ControlInfo {
            id: "AC-4",
            name: "Information Flow Enforcement",
            description: "CORS enforcement via security layers",
            module: "layers",
        },
        ControlInfo {
            id: "AC-7",
            name: "Unsuccessful Logon Attempts",
            description: "Login tracking with account lockout",
            module: "login",
        },
        ControlInfo {
            id: "AC-11",
            name: "Device Lock",
            description: "Session idle timeout",
            module: "session",
        },
        ControlInfo {
            id: "AC-12",
            name: "Session Termination",
            description: "Session absolute timeout and termination",
            module: "session",
        },
        ControlInfo {
            id: "AU-2",
            name: "Auditable Events",
            description: "Security event definitions",
            module: "observability",
        },
        ControlInfo {
            id: "AU-3",
            name: "Content of Audit Records",
            description: "Structured audit records",
            module: "audit",
        },
        ControlInfo {
            id: "AU-9",
            name: "Protection of Audit Information",
            description: "Signed audit chains with HMAC",
            module: "audit::integrity",
        },
        ControlInfo {
            id: "AU-12",
            name: "Audit Record Generation",
            description: "HTTP audit middleware",
            module: "audit",
        },
        ControlInfo {
            id: "CA-7",
            name: "Continuous Monitoring",
            description: "Health check framework",
            module: "health",
        },
        ControlInfo {
            id: "CM-6",
            name: "Configuration Settings",
            description: "Security headers and timeouts",
            module: "layers",
        },
        ControlInfo {
            id: "IA-2",
            name: "Identification and Authentication",
            description: "MFA policy enforcement",
            module: "auth",
        },
        ControlInfo {
            id: "IA-3",
            name: "Device Identification",
            description: "mTLS client certificate verification",
            module: "tls",
        },
        ControlInfo {
            id: "IA-5",
            name: "Authenticator Management",
            description: "Password policy and secure handling",
            module: "password",
        },
        ControlInfo {
            id: "IA-5(1)",
            name: "Password-based Authentication",
            description: "NIST 800-63B password validation",
            module: "password",
        },
        ControlInfo {
            id: "IA-5(7)",
            name: "No Embedded Authenticators",
            description: "Secret detection scanner",
            module: "secrets",
        },
        ControlInfo {
            id: "IR-4",
            name: "Incident Handling",
            description: "Security alert generation",
            module: "alerting",
        },
        ControlInfo {
            id: "IR-5",
            name: "Incident Monitoring",
            description: "Alert management with rate limiting",
            module: "alerting",
        },
        ControlInfo {
            id: "SC-5",
            name: "Denial of Service Protection",
            description: "Rate limiting",
            module: "layers",
        },
        ControlInfo {
            id: "SC-8",
            name: "Transmission Confidentiality",
            description: "TLS enforcement and database SSL",
            module: "tls, database",
        },
        ControlInfo {
            id: "SC-8(1)",
            name: "Cryptographic Protection",
            description: "TLS requirement middleware",
            module: "tls",
        },
        ControlInfo {
            id: "SC-10",
            name: "Network Disconnect",
            description: "Session timeout enforcement",
            module: "session",
        },
        ControlInfo {
            id: "SC-12",
            name: "Cryptographic Key Establishment",
            description: "Key management with rotation",
            module: "keys",
        },
        ControlInfo {
            id: "SC-13",
            name: "Cryptographic Protection",
            description: "AES-256-GCM, constant-time comparison",
            module: "encryption, crypto",
        },
        ControlInfo {
            id: "SC-28",
            name: "Protection of Information at Rest",
            description: "Field-level encryption",
            module: "encryption",
        },
        ControlInfo {
            id: "SI-10",
            name: "Information Input Validation",
            description: "Input validation and sanitization",
            module: "validation",
        },
        ControlInfo {
            id: "SI-11",
            name: "Error Handling",
            description: "Secure error responses",
            module: "error",
        },
        ControlInfo {
            id: "SR-3",
            name: "Supply Chain Controls",
            description: "SBOM generation",
            module: "supply_chain",
        },
        ControlInfo {
            id: "SR-4",
            name: "Provenance",
            description: "Dependency vulnerability scanning",
            module: "supply_chain",
        },
        ControlInfo {
            id: "SA-11",
            name: "Developer Testing",
            description: "Security test utilities",
            module: "testing",
        },
        ControlInfo {
            id: "CA-8",
            name: "Penetration Testing",
            description: "XSS/SQLi payload generators",
            module: "testing",
        },
    ]
}

/// Get controls filtered by family (e.g., "AC", "SC", "AU").
pub fn controls_by_family(family: &str) -> Vec<ControlInfo> {
    implemented_controls()
        .into_iter()
        .filter(|c| c.id.starts_with(family))
        .collect()
}

// ============================================================================
// Feature Detection
// ============================================================================

/// Check which optional features are enabled.
#[derive(Debug, Clone)]
pub struct EnabledFeatures {
    pub postgres: bool,
    pub compliance_artifacts: bool,
    pub fips: bool,
    pub hibp: bool,
    pub observability_loki: bool,
    pub observability_otlp: bool,
    pub metrics_prometheus: bool,
}

impl EnabledFeatures {
    /// Detect which features are compiled in.
    pub fn detect() -> Self {
        Self {
            postgres: cfg!(feature = "postgres"),
            compliance_artifacts: cfg!(feature = "compliance-artifacts"),
            fips: cfg!(feature = "fips"),
            hibp: cfg!(feature = "hibp"),
            observability_loki: cfg!(feature = "observability-loki"),
            observability_otlp: cfg!(feature = "observability-otlp"),
            metrics_prometheus: cfg!(feature = "metrics-prometheus"),
        }
    }

    /// Print a summary of enabled features.
    pub fn summary(&self) -> String {
        let mut features = Vec::new();
        if self.postgres {
            features.push("postgres");
        }
        if self.compliance_artifacts {
            features.push("compliance-artifacts");
        }
        if self.fips {
            features.push("fips");
        }
        if self.hibp {
            features.push("hibp");
        }
        if self.observability_loki {
            features.push("observability-loki");
        }
        if self.observability_otlp {
            features.push("observability-otlp");
        }
        if self.metrics_prometheus {
            features.push("metrics-prometheus");
        }
        if features.is_empty() {
            "default".to_string()
        } else {
            features.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_factory_functions() {
        // Test session policy - uses profile.idle_timeout() (STIG UBTU-22-412020)
        let session = session_policy_for_profile(ComplianceProfile::FedRampHigh);
        assert_eq!(session.idle_timeout, Duration::from_secs(600)); // 10 min for High
        assert_eq!(session.max_lifetime, Duration::from_secs(4 * 60 * 60));

        let session_mod = session_policy_for_profile(ComplianceProfile::FedRampModerate);
        assert_eq!(session_mod.idle_timeout, Duration::from_secs(15 * 60)); // 15 min STIG

        // Test password policy - uses profile.min_password_length() (STIG UBTU-22-611035)
        let password = password_policy_for_profile(ComplianceProfile::FedRampHigh);
        assert_eq!(password.min_length, 15);
        assert!(password.check_common_passwords);

        // STIG requires 15 chars for Moderate too
        let password_mod = password_policy_for_profile(ComplianceProfile::FedRampModerate);
        assert_eq!(password_mod.min_length, 15); // STIG-compliant

        // Test lockout policy - uses profile.max_login_attempts() (STIG UBTU-22-411045: 3 attempts)
        let lockout = lockout_policy_for_profile(ComplianceProfile::FedRampModerate);
        assert_eq!(lockout.max_attempts, 3);
        assert_eq!(lockout.lockout_duration, Duration::from_secs(30 * 60)); // 30 min STIG

        // STIG requires 3 attempts for all FedRAMP profiles
        let lockout_low = lockout_policy_for_profile(ComplianceProfile::FedRampLow);
        assert_eq!(lockout_low.max_attempts, 3); // STIG-compliant (was 5)
        assert_eq!(lockout_low.lockout_duration, Duration::from_secs(30 * 60)); // 30 min STIG

        // Test encryption config
        let encryption = encryption_config_for_profile(ComplianceProfile::FedRampHigh);
        assert!(encryption.require_encryption);
        assert!(encryption.verify_database_encryption);
    }

    #[test]
    fn test_sbom_builder() {
        let builder = SbomBuilder::new("test-app", "1.0.0").organization("Test Org");

        assert_eq!(builder.dependency_count(), 0);
    }

    #[test]
    fn test_implemented_controls() {
        let controls = implemented_controls();
        assert!(controls.len() > 20);

        let ac_controls = controls_by_family("AC");
        assert!(ac_controls.len() >= 4);
    }

    #[test]
    fn test_enabled_features() {
        let features = EnabledFeatures::detect();
        let summary = features.summary();
        assert!(!summary.is_empty());
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn test_database_config_for_profile() {
        let config =
            database_config_for_profile("postgres://localhost/test", ComplianceProfile::FedRampHigh);
        assert_eq!(config.ssl_mode, SslMode::VerifyFull);
        assert_eq!(config.channel_binding, ChannelBinding::Require);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn test_validate_database_config() {
        let config = DatabaseConfigBuilder::new("postgres://localhost/test")
            .ssl_mode(SslMode::Prefer)
            .build();

        let findings = validate_database_config(&config, ComplianceProfile::FedRampHigh);
        assert!(!findings.is_empty());
        assert!(findings[0].contains("SC-8"));
    }
}
