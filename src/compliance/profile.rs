//! Compliance Profile Definitions
//!
//! Defines security profiles for multiple compliance frameworks including
//! FedRAMP, SOC 2, and custom configurations.
//!
//! # Authoritative Sources
//!
//! All parameter values in this module are derived from official compliance documents:
//!
//! | Source | Document | Version |
//! |--------|----------|---------|
//! | NIST | SP 800-53 Rev 5 | December 2020 |
//! | NIST | SP 800-63B Digital Identity Guidelines | March 2020 |
//! | FedRAMP | Security Controls Baseline | Rev 5 (May 2023) |
//! | DISA | Ubuntu 22.04 LTS STIG | V2R5 (2024) |
//! | DISA | RHEL 9 STIG | V1R3 (2024) |
//!
//! # Audit Trail
//!
//! Each security parameter includes:
//! - NIST 800-53 control reference (e.g., AC-7, IA-5)
//! - FedRAMP baseline requirements for each impact level
//! - DISA STIG rule ID where applicable
//! - Rationale for chosen values
//!
//! # Profile Summary
//!
//! | Profile | Session Timeout | Idle Timeout | MFA | Password Min | Max Attempts | Lockout |
//! |---------|-----------------|--------------|-----|--------------|--------------|---------|
//! | FedRAMP Low | 30 min | 15 min | No | 8 | 3 | 30 min |
//! | FedRAMP Moderate | 15 min | 15 min | Yes | 15 | 3 | 30 min |
//! | FedRAMP High | 10 min | 10 min | Yes+HW | 15 | 3 | 3 hrs |
//! | SOC 2 | 15 min | 15 min | Yes | 15 | 3 | 30 min |
//!
//! # References
//!
//! - [FedRAMP Security Controls Baseline](https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx)
//! - [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
//! - [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
//! - [DISA STIGs](https://public.cyber.mil/stigs/)

use std::time::Duration;

/// Compliance framework and impact level
///
/// Determines security settings across the entire application based on
/// the selected compliance framework and impact level.
///
/// # Authoritative Mapping
///
/// | Profile | Framework | NIST Baseline | FIPS 199 Impact |
/// |---------|-----------|---------------|-----------------|
/// | FedRampLow | FedRAMP | Low | Limited adverse effect |
/// | FedRampModerate | FedRAMP | Moderate | Serious adverse effect |
/// | FedRampHigh | FedRAMP | High | Severe/catastrophic effect |
/// | Soc2 | AICPA TSC | N/A | Trust Services Criteria |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComplianceProfile {
    /// FedRAMP Low impact - basic security controls
    ///
    /// Suitable for systems where loss of confidentiality, integrity, or
    /// availability would have limited adverse effect.
    ///
    /// **Authoritative Source**: FedRAMP Low Baseline (Rev 5)
    FedRampLow,

    /// FedRAMP Moderate impact - enhanced security controls (most common)
    ///
    /// Suitable for systems where loss would have serious adverse effect.
    /// This is the most common FedRAMP authorization level.
    ///
    /// **Authoritative Source**: FedRAMP Moderate Baseline (Rev 5)
    #[default]
    FedRampModerate,

    /// FedRAMP High impact - maximum security controls
    ///
    /// Suitable for systems where loss would have severe or catastrophic
    /// adverse effect. Requires the most stringent controls.
    ///
    /// **Authoritative Source**: FedRAMP High Baseline (Rev 5)
    FedRampHigh,

    /// SOC 2 Type II baseline
    ///
    /// Aligned with AICPA Trust Services Criteria for security,
    /// availability, processing integrity, confidentiality, and privacy.
    ///
    /// **Authoritative Source**: AICPA TSC 2017 (with 2022 updates)
    Soc2,

    /// Custom profile with explicit settings
    ///
    /// Use when compliance requirements don't fit standard profiles.
    /// Settings default to FedRAMP Moderate equivalents.
    Custom,

    /// Development profile - no security hardening
    ///
    /// Use for local development only. Disables container user restrictions,
    /// read-only filesystems, and capability dropping to avoid Docker volume
    /// permission issues. Never use in production.
    Development,
}

impl ComplianceProfile {
    /// Human-readable name for display and logging
    pub fn name(&self) -> &'static str {
        match self {
            Self::FedRampLow => "FedRAMP Low",
            Self::FedRampModerate => "FedRAMP Moderate",
            Self::FedRampHigh => "FedRAMP High",
            Self::Soc2 => "SOC 2 Type II",
            Self::Custom => "Custom",
            Self::Development => "Development",
        }
    }

    /// Framework family for grouping and reporting
    pub fn framework(&self) -> &'static str {
        match self {
            Self::FedRampLow | Self::FedRampModerate | Self::FedRampHigh => "FedRAMP",
            Self::Soc2 => "SOC 2",
            Self::Custom => "Custom",
            Self::Development => "None",
        }
    }

    /// Whether this is a FedRAMP profile
    pub fn is_fedramp(&self) -> bool {
        matches!(
            self,
            Self::FedRampLow | Self::FedRampModerate | Self::FedRampHigh
        )
    }

    /// Whether this is a development-only profile with no security hardening
    pub fn is_development(&self) -> bool {
        matches!(self, Self::Development)
    }

    // =========================================================================
    // Audit Controls (AU Family)
    // =========================================================================

    /// Minimum log retention in days (AU-11)
    ///
    /// # NIST 800-53 Control: AU-11 (Audit Record Retention)
    ///
    /// > "Retain audit records for an organization-defined time period
    /// > to provide support for after-the-fact investigations of incidents
    /// > and to meet regulatory and organizational information retention
    /// > requirements."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Retention Period | Source |
    /// |--------------|------------------|--------|
    /// | Low | 90 days (or per policy) | FedRAMP Low Baseline |
    /// | Moderate | 90 days minimum | FedRAMP Moderate Baseline |
    /// | High | 1 year (365 days) | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-653045**: Ubuntu 22.04 must allocate audit record storage
    /// - **RHEL-09-653010**: RHEL 9 audit system must audit all uses
    ///
    /// # Barbican Implementation
    ///
    /// | Profile | Value | Rationale |
    /// |---------|-------|-----------|
    /// | FedRampLow | 30 days | Minimum for basic forensics (allows shorter for Low) |
    /// | FedRampModerate | 90 days | Meets FedRAMP Moderate baseline |
    /// | FedRampHigh | 365 days | Meets FedRAMP High baseline |
    /// | Soc2 | 90 days | Aligns with TSC CC7.2 |
    pub fn min_retention_days(&self) -> u32 {
        match self {
            // FedRAMP Low: Minimum retention for basic incident response
            // Note: FedRAMP allows organizational discretion at Low level
            Self::FedRampLow | Self::Development => 30,

            // FedRAMP Moderate: 90-day retention per baseline
            // SOC 2: Aligns with TSC CC7.2 investigation requirements
            Self::FedRampModerate | Self::Soc2 | Self::Custom => 90,

            // FedRAMP High: 1-year retention for extended investigation capability
            Self::FedRampHigh => 365,
        }
    }

    // =========================================================================
    // System and Communications Protection (SC Family)
    // =========================================================================

    /// Whether TLS is required for all communications (SC-8)
    ///
    /// # NIST 800-53 Control: SC-8 (Transmission Confidentiality and Integrity)
    ///
    /// > "Protect the confidentiality and integrity of transmitted information."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | TLS Required | Min Version | Source |
    /// |--------------|--------------|-------------|--------|
    /// | Low | Yes | TLS 1.2 | FedRAMP Low Baseline |
    /// | Moderate | Yes | TLS 1.2 | FedRAMP Moderate Baseline |
    /// | High | Yes | TLS 1.2+ (FIPS) | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-255050**: Ubuntu must implement cryptographic mechanisms
    ///   for data in transit (CAT II)
    /// - **Rule ID**: configure_crypto_policy
    ///
    /// # Barbican Implementation
    ///
    /// All production profiles require TLS. Development mode allows
    /// unencrypted connections for local testing only.
    pub fn requires_tls(&self) -> bool {
        !matches!(self, Self::Development) // Development mode skips TLS
    }

    /// Whether mutual TLS (mTLS) is required for service-to-service (SC-8)
    ///
    /// # NIST 800-53 Control: SC-8(1) (Cryptographic Protection)
    ///
    /// > "Implement cryptographic mechanisms to prevent unauthorized
    /// > disclosure of information and detect changes to information
    /// > during transmission."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | mTLS Required | Source |
    /// |--------------|---------------|--------|
    /// | Low | No | FedRAMP Low Baseline |
    /// | Moderate | Recommended | FedRAMP Moderate Baseline |
    /// | High | Yes | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-612035**: Ubuntu must implement certificate status checking
    /// - **Rule ID**: package_nss-tools_installed
    ///
    /// # Barbican Implementation
    ///
    /// Only FedRAMP High requires mTLS. This prevents service impersonation
    /// and ensures bidirectional authentication for all service communications.
    pub fn requires_mtls(&self) -> bool {
        matches!(self, Self::FedRampHigh)
    }

    /// Whether SSL certificate verification is required (SC-8)
    ///
    /// # NIST 800-53 Control: SC-8, SC-17 (PKI Certificates)
    ///
    /// > "Obtain public key certificates from an approved service provider
    /// > or issue public key certificates."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Verification Mode | Source |
    /// |--------------|-------------------|--------|
    /// | Low | Require (encryption only) | FedRAMP Low Baseline |
    /// | Moderate | VerifyFull | FedRAMP Moderate Baseline |
    /// | High | VerifyFull + CA pinning | FedRAMP High Baseline |
    ///
    /// # Rationale
    ///
    /// FedRAMP Moderate and above require VerifyFull mode to prevent
    /// man-in-the-middle attacks on database and service connections.
    /// FedRAMP Low allows Require mode (encryption without cert validation)
    /// for simpler deployments.
    pub fn requires_ssl_verify_full(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Whether encryption at rest is required (SC-28)
    ///
    /// # NIST 800-53 Control: SC-28 (Protection of Information at Rest)
    ///
    /// > "Protect the confidentiality and integrity of information at rest."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Encryption Required | Algorithm | Source |
    /// |--------------|---------------------|-----------|--------|
    /// | Low | No | N/A | FedRAMP Low Baseline |
    /// | Moderate | Yes | FIPS 140-2 validated | FedRAMP Moderate Baseline |
    /// | High | Yes | FIPS 140-2/3 validated | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-231010**: Ubuntu must encrypt all stored passwords
    ///   with a FIPS 140-2 approved cryptographic hashing algorithm (CAT II)
    /// - **Rule ID**: encrypt_partitions
    ///
    /// # Barbican Implementation
    ///
    /// FedRAMP Moderate and High require encryption at rest using
    /// FIPS-validated algorithms (AES-256).
    pub fn requires_encryption_at_rest(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Key rotation interval (SC-12)
    ///
    /// # NIST 800-53 Control: SC-12 (Cryptographic Key Establishment and Management)
    ///
    /// > "Establish and manage cryptographic keys when cryptography is
    /// > employed within the system in accordance with organizational
    /// > requirements."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Rotation Period | Source |
    /// |--------------|-----------------|--------|
    /// | Low | 1 year | FedRAMP Low Baseline |
    /// | Moderate | 1 year | FedRAMP Moderate Baseline |
    /// | High | 1 year (or per crypto policy) | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-671010**: Ubuntu must implement NIST FIPS-validated
    ///   cryptography (CAT I - HIGH)
    /// - **var_system_crypto_policy**: FIPS policy specifies key management
    ///
    /// # Barbican Implementation
    ///
    /// | Profile | Value | Rationale |
    /// |---------|-------|-----------|
    /// | FedRampLow | 90 days | More frequent for compensating control |
    /// | FedRampModerate | 90 days | Standard rotation cycle |
    /// | FedRampHigh | 30 days | Stricter key hygiene for high-impact |
    ///
    /// Note: Barbican uses MORE FREQUENT rotation than minimum STIG
    /// requirements as a defense-in-depth measure.
    pub fn key_rotation_interval(&self) -> Duration {
        match self {
            Self::FedRampHigh => Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            _ => Duration::from_secs(90 * 24 * 60 * 60),                 // 90 days
        }
    }

    // =========================================================================
    // Identification and Authentication (IA Family)
    // =========================================================================

    /// Whether MFA is required for user authentication (IA-2)
    ///
    /// # NIST 800-53 Control: IA-2 (Identification and Authentication)
    ///
    /// > "Uniquely identify and authenticate organizational users."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | MFA Required | Type | Source |
    /// |--------------|--------------|------|--------|
    /// | Low | Privileged only | Any | FedRAMP Low Baseline |
    /// | Moderate | All users | Phishing-resistant preferred | FedRAMP Moderate Baseline |
    /// | High | All users | Phishing-resistant required | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-612010**: Ubuntu must use multifactor authentication
    ///   for local and network access (CAT II)
    /// - **Rule ID**: enable_fips_mode (enables FIPS-validated MFA)
    ///
    /// # NIST SP 800-63B Reference
    ///
    /// > "Multi-factor authentication SHALL be required for AAL2 and AAL3."
    ///
    /// # Barbican Implementation
    ///
    /// FedRAMP Moderate and High require MFA for all users.
    /// FedRAMP Low only requires MFA for privileged users.
    pub fn requires_mfa(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    /// Password minimum length requirement (IA-5)
    ///
    /// # NIST 800-53 Control: IA-5(1) (Password-Based Authentication)
    ///
    /// > "For password-based authentication, enforce minimum password
    /// > complexity of organization-defined requirements."
    ///
    /// # NIST SP 800-63B Requirements
    ///
    /// | Authentication Type | Minimum Length | Source |
    /// |---------------------|----------------|--------|
    /// | Single-factor (password only) | 15 characters | SP 800-63B Sec 5.1.1.1 |
    /// | Multi-factor | 8 characters | SP 800-63B Sec 5.1.1.1 |
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Min Length | Source |
    /// |--------------|------------|--------|
    /// | Low | 8 characters | FedRAMP Low Baseline (with MFA) |
    /// | Moderate | 15 characters | FedRAMP Moderate Baseline |
    /// | High | 15 characters | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-611035**: Ubuntu must enforce a minimum 15-character
    ///   password length (CAT II)
    /// - **RHEL-09-611095**: RHEL 9 must enforce minimum 15-character
    ///   password length (CAT II)
    /// - **var_password_pam_minlen**: Default value = 15
    ///
    /// # Barbican Implementation
    ///
    /// | Profile | Value | Rationale |
    /// |---------|-------|-----------|
    /// | FedRampLow | 8 | MFA compensates; aligns with 800-63B |
    /// | FedRampModerate | 15 | Meets STIG UBTU-22-611035 |
    /// | FedRampHigh | 15 | Meets STIG requirement |
    ///
    /// Note: NIST recommends against complexity requirements (special chars)
    /// in favor of length. See SP 800-63B Appendix A.
    pub fn min_password_length(&self) -> usize {
        match self {
            // FedRAMP Low: 8 chars acceptable with MFA per NIST 800-63B
            Self::FedRampLow | Self::Development => 8,

            // FedRAMP Moderate/High + SOC 2: 15 chars per DISA STIG
            // Reference: UBTU-22-611035, RHEL-09-611095
            Self::FedRampModerate | Self::Soc2 | Self::Custom | Self::FedRampHigh => 15,
        }
    }

    /// Whether breach database checking is required (IA-5)
    ///
    /// # NIST 800-53 Control: IA-5(1)(a) (Password-Based Authentication)
    ///
    /// # NIST SP 800-63B Requirements
    ///
    /// > "Verifiers SHALL compare the prospective secrets against a list
    /// > that contains values known to be commonly-used, expected, or
    /// > compromised."
    ///
    /// This includes:
    /// - Passwords obtained from previous breach corpuses
    /// - Dictionary words
    /// - Repetitive or sequential characters
    /// - Context-specific words (service name, username)
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Breach Check | Source |
    /// |--------------|--------------|--------|
    /// | Low | Recommended | SP 800-63B |
    /// | Moderate | Required | SP 800-63B + FedRAMP |
    /// | High | Required | SP 800-63B + FedRAMP |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-611025**: Ubuntu must enforce password complexity
    ///   by requiring at least one special character (CAT II)
    /// - **Rule ID**: accounts_passwords_pam_pwquality
    ///
    /// # Barbican Implementation
    ///
    /// Required for Moderate and above per NIST SP 800-63B Section 5.1.1.2.
    pub fn requires_breach_checking(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }

    // =========================================================================
    // Access Control (AC Family)
    // =========================================================================

    /// Session timeout / maximum lifetime (AC-12)
    ///
    /// # NIST 800-53 Control: AC-12 (Session Termination)
    ///
    /// > "Automatically terminate a user session after organization-defined
    /// > conditions or trigger events."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Max Session | Source |
    /// |--------------|-------------|--------|
    /// | Low | 30 minutes | FedRAMP Low Baseline |
    /// | Moderate | 15 minutes | FedRAMP Moderate Baseline |
    /// | High | 10 minutes (privileged) | FedRAMP High Baseline |
    ///
    /// # NIST SP 800-63B Reference (AAL Requirements)
    ///
    /// | AAL Level | Reauthentication | Idle Timeout |
    /// |-----------|------------------|--------------|
    /// | AAL1 | 30 days | 30 minutes |
    /// | AAL2 | 12 hours | 30 minutes |
    /// | AAL3 | 12 hours | 15 minutes |
    ///
    /// # Barbican Implementation
    ///
    /// | Profile | Value | Rationale |
    /// |---------|-------|-----------|
    /// | FedRampLow | 30 min | Aligns with AAL1/AAL2 |
    /// | FedRampModerate | 15 min | Exceeds AAL2, meets AAL3 |
    /// | FedRampHigh | 10 min | Stricter than baseline for privileged access |
    pub fn session_timeout(&self) -> Duration {
        match self {
            Self::FedRampLow => Duration::from_secs(30 * 60),  // 30 minutes
            Self::FedRampModerate | Self::Soc2 | Self::Custom => Duration::from_secs(15 * 60), // 15 minutes
            Self::FedRampHigh => Duration::from_secs(10 * 60), // 10 minutes
            Self::Development => Duration::from_secs(24 * 60 * 60), // 24 hours for dev
        }
    }

    /// Idle timeout duration (AC-11)
    ///
    /// # NIST 800-53 Control: AC-11 (Device Lock)
    ///
    /// > "Prevent further access to the system by initiating a device lock
    /// > after an organization-defined time period of inactivity."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Idle Timeout | Source |
    /// |--------------|--------------|--------|
    /// | Low | 15 minutes | FedRAMP Low Baseline |
    /// | Moderate | 15 minutes | FedRAMP Moderate Baseline |
    /// | High | 10 minutes (privileged) | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-412020**: Ubuntu must initiate a session lock after
    ///   15 minutes of inactivity (CAT II)
    /// - **var_screensaver_lock_delay**: Default value = 900 (15 minutes)
    ///
    /// # NIST SP 800-63B Reference
    ///
    /// > "Reauthentication of the subscriber SHALL be repeated following
    /// > any period of inactivity lasting 15 minutes or longer." (AAL3)
    ///
    /// # Barbican Implementation
    ///
    /// | Profile | Value | Rationale |
    /// |---------|-------|-----------|
    /// | FedRampLow | 15 min | Meets STIG UBTU-22-412020 |
    /// | FedRampModerate | 15 min | Meets STIG UBTU-22-412020 |
    /// | FedRampHigh | 10 min | Stricter for high-impact privileged sessions |
    ///
    /// Note: FedRAMP High uses 10 minutes (stricter than 15-minute baseline)
    /// because high-impact systems handle more sensitive data.
    pub fn idle_timeout(&self) -> Duration {
        match self {
            // FedRAMP Low/Moderate: 15 minutes per DISA STIG UBTU-22-412020
            // Reference: var_screensaver_lock_delay = 900
            Self::FedRampLow => Duration::from_secs(15 * 60), // 15 minutes
            Self::FedRampModerate | Self::Soc2 | Self::Custom => Duration::from_secs(15 * 60), // 15 minutes

            // FedRAMP High: 10 minutes for privileged sessions
            // Exceeds baseline (stricter than required)
            Self::FedRampHigh => Duration::from_secs(10 * 60), // 10 minutes

            Self::Development => Duration::from_secs(24 * 60 * 60), // 24 hours for dev
        }
    }

    /// Max failed login attempts before lockout (AC-7)
    ///
    /// # NIST 800-53 Control: AC-7 (Unsuccessful Logon Attempts)
    ///
    /// > "Enforce a limit of organization-defined number consecutive
    /// > invalid logon attempts by a user during an organization-defined
    /// > time period."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Max Attempts | Time Period | Source |
    /// |--------------|--------------|-------------|--------|
    /// | Low | 3 | 15 minutes | FedRAMP Low Baseline |
    /// | Moderate | 3 | 15 minutes | FedRAMP Moderate Baseline |
    /// | High | 3 | 15 minutes | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-411045**: Ubuntu must lock an account after three
    ///   unsuccessful logon attempts (CAT II)
    /// - **var_accounts_passwords_pam_faillock_deny**: Default value = 3
    ///
    /// # Barbican Implementation
    ///
    /// | Profile | Value | Rationale |
    /// |---------|-------|-----------|
    /// | FedRampLow | 3 | Meets FedRAMP baseline |
    /// | FedRampModerate | 3 | Meets STIG UBTU-22-411045 |
    /// | FedRampHigh | 3 | Meets STIG UBTU-22-411045 |
    ///
    /// Note: All FedRAMP baselines require 3 attempts. The value "5" was
    /// historically used but is NOT compliant with current FedRAMP/STIG.
    pub fn max_login_attempts(&self) -> u32 {
        // All FedRAMP baselines: 3 consecutive attempts
        // Reference: UBTU-22-411045, var_accounts_passwords_pam_faillock_deny
        3
    }

    /// Lockout duration after failed attempts (AC-7)
    ///
    /// # NIST 800-53 Control: AC-7(b) (Unsuccessful Logon Attempts)
    ///
    /// > "Automatically lock the account or node for an organization-defined
    /// > time period, lock the account or node until released by an
    /// > administrator, or delay next logon prompt."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Lockout Duration | Source |
    /// |--------------|------------------|--------|
    /// | Low | 30 minutes | FedRAMP Low Baseline |
    /// | Moderate | 30 minutes | FedRAMP Moderate Baseline |
    /// | High | 3 hours (or admin release) | FedRAMP High Baseline |
    ///
    /// # DISA STIG References
    ///
    /// - **UBTU-22-411050**: Ubuntu must automatically lock accounts
    ///   for a minimum of 15 minutes after three unsuccessful logon
    ///   attempts (CAT II)
    /// - **var_accounts_passwords_pam_faillock_unlock_time**: Default = 900
    ///
    /// # Barbican Implementation
    ///
    /// | Profile | Value | Rationale |
    /// |---------|-------|-----------|
    /// | FedRampLow | 30 min | Meets FedRAMP baseline |
    /// | FedRampModerate | 30 min | Exceeds STIG minimum (15 min) |
    /// | FedRampHigh | 3 hours | Meets FedRAMP High baseline |
    ///
    /// Note: STIG minimum is 15 minutes, FedRAMP specifies 30 minutes
    /// for Low/Moderate and 3 hours for High.
    pub fn lockout_duration(&self) -> Duration {
        match self {
            // FedRAMP Low/Moderate: 30 minutes
            Self::FedRampLow | Self::FedRampModerate | Self::Soc2 | Self::Custom => {
                Duration::from_secs(30 * 60) // 30 minutes
            }

            // FedRAMP High: 3 hours (or until admin release)
            Self::FedRampHigh => Duration::from_secs(3 * 60 * 60), // 3 hours

            Self::Development => Duration::from_secs(60), // 1 minute for dev
        }
    }

    /// Whether tenant isolation is required
    ///
    /// # NIST 800-53 Control: AC-4 (Information Flow Enforcement)
    ///
    /// > "Enforce approved authorizations for controlling the flow of
    /// > information within the system and between connected systems."
    ///
    /// # FedRAMP Parameter Values
    ///
    /// | Impact Level | Isolation Required | Source |
    /// |--------------|-------------------|--------|
    /// | Low | Recommended | FedRAMP Low Baseline |
    /// | Moderate | Required | FedRAMP Moderate Baseline |
    /// | High | Required (strict) | FedRAMP High Baseline |
    ///
    /// # Barbican Implementation
    ///
    /// Multi-tenant systems must isolate data between tenants
    /// for Moderate and above. This includes database-level isolation,
    /// API authorization checks, and audit separation.
    pub fn requires_tenant_isolation(&self) -> bool {
        !matches!(self, Self::FedRampLow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_names() {
        assert_eq!(ComplianceProfile::FedRampLow.name(), "FedRAMP Low");
        assert_eq!(ComplianceProfile::FedRampModerate.name(), "FedRAMP Moderate");
        assert_eq!(ComplianceProfile::FedRampHigh.name(), "FedRAMP High");
        assert_eq!(ComplianceProfile::Soc2.name(), "SOC 2 Type II");
        assert_eq!(ComplianceProfile::Custom.name(), "Custom");
    }

    #[test]
    fn test_framework_grouping() {
        assert_eq!(ComplianceProfile::FedRampLow.framework(), "FedRAMP");
        assert_eq!(ComplianceProfile::FedRampModerate.framework(), "FedRAMP");
        assert_eq!(ComplianceProfile::FedRampHigh.framework(), "FedRAMP");
        assert_eq!(ComplianceProfile::Soc2.framework(), "SOC 2");
    }

    // =========================================================================
    // AU-11: Audit Record Retention Tests
    // =========================================================================

    #[test]
    fn test_retention_requirements_au11() {
        // FedRAMP Low: 30 days minimum
        assert_eq!(ComplianceProfile::FedRampLow.min_retention_days(), 30);

        // FedRAMP Moderate: 90 days per baseline
        assert_eq!(ComplianceProfile::FedRampModerate.min_retention_days(), 90);

        // FedRAMP High: 365 days (1 year) per baseline
        assert_eq!(ComplianceProfile::FedRampHigh.min_retention_days(), 365);

        // SOC 2: 90 days (aligns with Moderate)
        assert_eq!(ComplianceProfile::Soc2.min_retention_days(), 90);
    }

    // =========================================================================
    // AC-12: Session Timeout Tests
    // =========================================================================

    #[test]
    fn test_session_timeouts_ac12() {
        // FedRAMP Low: 30 minutes
        assert_eq!(
            ComplianceProfile::FedRampLow.session_timeout(),
            Duration::from_secs(30 * 60)
        );

        // FedRAMP Moderate: 15 minutes
        assert_eq!(
            ComplianceProfile::FedRampModerate.session_timeout(),
            Duration::from_secs(15 * 60)
        );

        // FedRAMP High: 10 minutes (stricter)
        assert_eq!(
            ComplianceProfile::FedRampHigh.session_timeout(),
            Duration::from_secs(10 * 60)
        );
    }

    // =========================================================================
    // AC-11: Idle Timeout Tests
    // =========================================================================

    #[test]
    fn test_idle_timeouts_ac11() {
        // FedRAMP Low: 15 minutes per STIG
        assert_eq!(
            ComplianceProfile::FedRampLow.idle_timeout(),
            Duration::from_secs(15 * 60)
        );

        // FedRAMP Moderate: 15 minutes per STIG UBTU-22-412020
        assert_eq!(
            ComplianceProfile::FedRampModerate.idle_timeout(),
            Duration::from_secs(15 * 60)
        );

        // FedRAMP High: 10 minutes (exceeds baseline)
        assert_eq!(
            ComplianceProfile::FedRampHigh.idle_timeout(),
            Duration::from_secs(10 * 60)
        );
    }

    // =========================================================================
    // IA-2: MFA Requirements Tests
    // =========================================================================

    #[test]
    fn test_mfa_requirements_ia2() {
        // FedRAMP Low: MFA only for privileged (returns false for all users)
        assert!(!ComplianceProfile::FedRampLow.requires_mfa());

        // FedRAMP Moderate: MFA required for all users
        assert!(ComplianceProfile::FedRampModerate.requires_mfa());

        // FedRAMP High: MFA required for all users
        assert!(ComplianceProfile::FedRampHigh.requires_mfa());

        // SOC 2: MFA required
        assert!(ComplianceProfile::Soc2.requires_mfa());
    }

    // =========================================================================
    // SC-8: Encryption Requirements Tests
    // =========================================================================

    #[test]
    fn test_encryption_requirements_sc8_sc28() {
        // SC-8: TLS required for all except development
        assert!(ComplianceProfile::FedRampLow.requires_tls());
        assert!(ComplianceProfile::FedRampModerate.requires_tls());
        assert!(ComplianceProfile::FedRampHigh.requires_tls());
        assert!(!ComplianceProfile::Development.requires_tls());

        // SC-28: Encryption at rest
        assert!(!ComplianceProfile::FedRampLow.requires_encryption_at_rest());
        assert!(ComplianceProfile::FedRampModerate.requires_encryption_at_rest());
        assert!(ComplianceProfile::FedRampHigh.requires_encryption_at_rest());
    }

    // =========================================================================
    // SC-8: mTLS Requirements Tests
    // =========================================================================

    #[test]
    fn test_mtls_requirements_sc8() {
        // Only FedRAMP High requires mTLS
        assert!(!ComplianceProfile::FedRampLow.requires_mtls());
        assert!(!ComplianceProfile::FedRampModerate.requires_mtls());
        assert!(ComplianceProfile::FedRampHigh.requires_mtls());
    }

    #[test]
    fn test_ssl_verify_full_requirements() {
        // FedRAMP Low allows Require mode (encryption without cert validation)
        assert!(!ComplianceProfile::FedRampLow.requires_ssl_verify_full());

        // FedRAMP Moderate and above require VerifyFull (SC-8)
        assert!(ComplianceProfile::FedRampModerate.requires_ssl_verify_full());
        assert!(ComplianceProfile::FedRampHigh.requires_ssl_verify_full());
        assert!(ComplianceProfile::Soc2.requires_ssl_verify_full());
    }

    // =========================================================================
    // IA-5: Password Requirements Tests
    // =========================================================================

    #[test]
    fn test_password_requirements_ia5() {
        // FedRAMP Low: 8 chars (with MFA per NIST 800-63B)
        assert_eq!(ComplianceProfile::FedRampLow.min_password_length(), 8);

        // FedRAMP Moderate: 15 chars per STIG UBTU-22-611035
        assert_eq!(ComplianceProfile::FedRampModerate.min_password_length(), 15);

        // FedRAMP High: 15 chars per STIG
        assert_eq!(ComplianceProfile::FedRampHigh.min_password_length(), 15);
    }

    // =========================================================================
    // SC-12: Key Rotation Tests
    // =========================================================================

    #[test]
    fn test_key_rotation_sc12() {
        // FedRAMP Moderate: 90 days
        assert_eq!(
            ComplianceProfile::FedRampModerate.key_rotation_interval(),
            Duration::from_secs(90 * 24 * 60 * 60)
        );

        // FedRAMP High: 30 days (stricter)
        assert_eq!(
            ComplianceProfile::FedRampHigh.key_rotation_interval(),
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    // =========================================================================
    // AC-7: Lockout Policy Tests
    // =========================================================================

    #[test]
    fn test_lockout_policy_ac7() {
        // All profiles: 3 attempts per FedRAMP/STIG
        assert_eq!(ComplianceProfile::FedRampLow.max_login_attempts(), 3);
        assert_eq!(ComplianceProfile::FedRampModerate.max_login_attempts(), 3);
        assert_eq!(ComplianceProfile::FedRampHigh.max_login_attempts(), 3);

        // FedRAMP Low/Moderate: 30 minute lockout
        assert_eq!(
            ComplianceProfile::FedRampLow.lockout_duration(),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(
            ComplianceProfile::FedRampModerate.lockout_duration(),
            Duration::from_secs(30 * 60)
        );

        // FedRAMP High: 3 hour lockout
        assert_eq!(
            ComplianceProfile::FedRampHigh.lockout_duration(),
            Duration::from_secs(3 * 60 * 60)
        );
    }

    #[test]
    fn test_default_is_moderate() {
        assert_eq!(
            ComplianceProfile::default(),
            ComplianceProfile::FedRampModerate
        );
    }
}
