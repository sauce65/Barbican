//! STIG Rule Definitions and Mappings
//!
//! Comprehensive mapping of STIG rules to Barbican implementations for
//! formal traceability and audit compliance.
//!
//! # Supported STIGs
//!
//! - **Ubuntu 22.04 LTS STIG V2R3** (UBTU-22-*): OS-level security controls
//! - **PostgreSQL 15 STIG V2R6** (PGS15-00-*): Database security controls
//! - **Application Security STIG V5R3** (APSC-DV-*): Application-level controls
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::stig::mappings::{StigRule, ubuntu_22_04, postgresql_15};
//!
//! // Look up a rule
//! if let Some(rule) = ubuntu_22_04::get_rule("UBTU-22-411045") {
//!     println!("{}: {} ({})", rule.id, rule.title, rule.severity);
//!     println!("NIST Controls: {:?}", rule.nist_controls);
//!     println!("Barbican: {}", rule.barbican_impl);
//! }
//! ```

use super::types::StigSeverity;

/// A STIG rule definition with traceability metadata
#[derive(Debug, Clone)]
pub struct StigRule {
    /// STIG rule identifier (e.g., "UBTU-22-411045")
    pub id: &'static str,

    /// Human-readable title
    pub title: &'static str,

    /// Associated NIST 800-53 controls
    pub nist_controls: &'static [&'static str],

    /// Severity category (CAT I/II/III)
    pub severity: StigSeverity,

    /// Barbican implementation location
    pub barbican_impl: &'static str,

    /// Brief description of how Barbican implements this control
    pub implementation_notes: &'static str,
}

impl StigRule {
    /// Check if this rule maps to a specific NIST control
    pub fn maps_to_nist(&self, control: &str) -> bool {
        self.nist_controls.iter().any(|c| c.eq_ignore_ascii_case(control))
    }

    /// Check if this rule maps to a NIST control family (e.g., "AC")
    pub fn maps_to_family(&self, family: &str) -> bool {
        self.nist_controls.iter().any(|c| c.starts_with(family))
    }
}

/// Ubuntu 22.04 LTS STIG V2R3 rule definitions
pub mod ubuntu_22_04 {
    use super::{StigRule, StigSeverity};

    /// All Ubuntu 22.04 STIG rules implemented by Barbican
    pub const RULES: &[StigRule] = &[
        // AC-7: Unsuccessful Logon Attempts
        StigRule {
            id: "UBTU-22-411045",
            title: "Must lock an account after three unsuccessful login attempts",
            nist_controls: &["AC-7"],
            severity: StigSeverity::Medium,
            barbican_impl: "login.rs:LockoutPolicy",
            implementation_notes: "LockoutPolicy enforces max_login_attempts (default 3) with configurable lockout duration",
        },
        StigRule {
            id: "UBTU-22-411050",
            title: "Must automatically unlock accounts after 30 minutes",
            nist_controls: &["AC-7"],
            severity: StigSeverity::Medium,
            barbican_impl: "login.rs:LockoutPolicy",
            implementation_notes: "LockoutPolicy.lockout_duration configures automatic unlock (default 30 min for FedRAMP)",
        },
        // AC-11: Session Lock
        StigRule {
            id: "UBTU-22-412020",
            title: "Must initiate session lock after 15 minutes of inactivity",
            nist_controls: &["AC-11"],
            severity: StigSeverity::Medium,
            barbican_impl: "session.rs:SessionPolicy",
            implementation_notes: "SessionPolicy.idle_timeout enforces 15-minute idle lock for FedRAMP Moderate/High",
        },
        // IA-2: Identification and Authentication
        StigRule {
            id: "UBTU-22-612010",
            title: "Must use multifactor authentication for local access",
            nist_controls: &["IA-2", "IA-2(1)", "IA-2(2)"],
            severity: StigSeverity::High,
            barbican_impl: "auth.rs:MfaPolicy",
            implementation_notes: "MfaPolicy validates MFA completion via JWT amr claim; require_mfa enforces MFA",
        },
        StigRule {
            id: "UBTU-22-612035",
            title: "Must use PKI-based authentication for multifactor",
            nist_controls: &["IA-2(6)"],
            severity: StigSeverity::Medium,
            barbican_impl: "tls.rs, auth.rs:MfaPolicy",
            implementation_notes: "mTLS support in tls.rs; MfaPolicy.require_hardware validates hwk in amr claim",
        },
        // IA-5: Authenticator Management
        StigRule {
            id: "UBTU-22-611035",
            title: "Must enforce minimum 15-character password length",
            nist_controls: &["IA-5(1)"],
            severity: StigSeverity::Medium,
            barbican_impl: "password.rs:PasswordPolicy",
            implementation_notes: "PasswordPolicy.min_length set to 15 for STIG compliance (FedRAMP Moderate/High)",
        },
        // SC-8: Transmission Confidentiality and Integrity
        StigRule {
            id: "UBTU-22-255050",
            title: "Must encrypt all transmitted data",
            nist_controls: &["SC-8", "SC-8(1)"],
            severity: StigSeverity::High,
            barbican_impl: "tls.rs",
            implementation_notes: "TLS enforcement with configurable minimum version (TLS 1.2+)",
        },
        // SC-12: Cryptographic Key Establishment and Management
        StigRule {
            id: "UBTU-22-671010",
            title: "Must use valid cryptographic key management",
            nist_controls: &["SC-12"],
            severity: StigSeverity::Medium,
            barbican_impl: "keys.rs",
            implementation_notes: "Key rotation interval configuration; FIPS-compliant crypto with aws-lc-rs",
        },
        // SC-28: Protection of Information at Rest
        StigRule {
            id: "UBTU-22-231010",
            title: "Must encrypt partitions containing sensitive data",
            nist_controls: &["SC-28"],
            severity: StigSeverity::High,
            barbican_impl: "encryption.rs",
            implementation_notes: "AES-256-GCM field-level encryption; require_encryption_at_rest config",
        },
        // AU-11: Audit Record Retention
        StigRule {
            id: "UBTU-22-653045",
            title: "Must retain audit records for required period",
            nist_controls: &["AU-11"],
            severity: StigSeverity::Medium,
            barbican_impl: "audit/mod.rs, nix/modules/intrusion-detection.nix",
            implementation_notes: "Audit middleware with configurable retention; NixOS auditd configuration",
        },
        // Additional Ubuntu STIG rules for infrastructure modules
        StigRule {
            id: "UBTU-22-255010",
            title: "SSH must use FIPS 140-3 compliant cryptography",
            nist_controls: &["AC-17(2)", "SC-8"],
            severity: StigSeverity::High,
            barbican_impl: "nix/modules/hardened-ssh.nix",
            implementation_notes: "SSH configured with strong ciphers, KEX algorithms, and MACs",
        },
        StigRule {
            id: "UBTU-22-213010",
            title: "Must enable address space layout randomization",
            nist_controls: &["SI-16"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/kernel-hardening.nix",
            implementation_notes: "kernel.randomize_va_space = 2 via sysctl",
        },
        StigRule {
            id: "UBTU-22-251010",
            title: "Must configure firewall to deny network traffic by default",
            nist_controls: &["SC-7", "SC-7(5)"],
            severity: StigSeverity::High,
            barbican_impl: "nix/modules/vm-firewall.nix",
            implementation_notes: "Default DROP policy with explicit allowlist for inbound/outbound",
        },
        StigRule {
            id: "UBTU-22-651010",
            title: "Must generate audit records for privileged activities",
            nist_controls: &["AU-2", "AU-12"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/intrusion-detection.nix",
            implementation_notes: "auditd rules for execve, privileged commands, file deletions",
        },
        StigRule {
            id: "UBTU-22-252010",
            title: "Must synchronize time using authoritative source",
            nist_controls: &["AU-8", "AU-8(1)"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/time-sync.nix",
            implementation_notes: "NTP/chrony configuration for time synchronization",
        },
    ];

    /// Look up a rule by ID
    pub fn get_rule(id: &str) -> Option<&'static StigRule> {
        RULES.iter().find(|r| r.id == id)
    }

    /// Get all rules for a NIST control
    pub fn rules_for_nist(control: &str) -> Vec<&'static StigRule> {
        RULES.iter().filter(|r| r.maps_to_nist(control)).collect()
    }
}

/// PostgreSQL 15 STIG V2R6 rule definitions
pub mod postgresql_15 {
    use super::{StigRule, StigSeverity};

    /// All PostgreSQL 15 STIG rules implemented by Barbican
    pub const RULES: &[StigRule] = &[
        StigRule {
            id: "PGS15-00-000100",
            title: "Must use SSL/TLS for all connections",
            nist_controls: &["SC-8", "SC-8(1)"],
            severity: StigSeverity::High,
            barbican_impl: "nix/modules/secure-postgres.nix:enableSSL",
            implementation_notes: "PostgreSQL configured with ssl=on, ssl_min_protocol_version=TLSv1.2",
        },
        StigRule {
            id: "PGS15-00-000200",
            title: "Must authenticate clients using certificates",
            nist_controls: &["IA-5(2)"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/secure-postgres.nix:enableClientCert",
            implementation_notes: "Client certificate authentication via hostssl with cert clientcert=verify-full",
        },
        StigRule {
            id: "PGS15-00-000300",
            title: "Must enable audit logging",
            nist_controls: &["AU-2", "AU-3", "AU-12"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/secure-postgres.nix:enablePgaudit",
            implementation_notes: "pgaudit extension for object-level audit logging of write, role, ddl operations",
        },
        StigRule {
            id: "PGS15-00-000400",
            title: "Must use SCRAM-SHA-256 for password authentication",
            nist_controls: &["IA-5"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/secure-postgres.nix",
            implementation_notes: "password_encryption = scram-sha-256; authentication method scram-sha-256 in pg_hba.conf",
        },
        StigRule {
            id: "PGS15-00-000500",
            title: "Must protect audit log files",
            nist_controls: &["AU-9"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/secure-postgres.nix:logFileMode",
            implementation_notes: "log_file_mode = 0600; pg_log directory chmod 700",
        },
        StigRule {
            id: "PGS15-00-000600",
            title: "Must limit concurrent connections",
            nist_controls: &["SC-5"],
            severity: StigSeverity::Low,
            barbican_impl: "nix/modules/secure-postgres.nix:maxConnections",
            implementation_notes: "max_connections and superuser_reserved_connections configured",
        },
    ];

    /// Look up a rule by ID
    pub fn get_rule(id: &str) -> Option<&'static StigRule> {
        RULES.iter().find(|r| r.id == id)
    }

    /// Get all rules for a NIST control
    pub fn rules_for_nist(control: &str) -> Vec<&'static StigRule> {
        RULES.iter().filter(|r| r.maps_to_nist(control)).collect()
    }
}

/// Application Security and Development STIG V5R3 rule definitions
pub mod application_security {
    use super::{StigRule, StigSeverity};

    /// All Application Security STIG rules implemented by Barbican
    pub const RULES: &[StigRule] = &[
        // Input Validation (SI-10)
        StigRule {
            id: "APSC-DV-000160",
            title: "Must validate all input",
            nist_controls: &["SI-10"],
            severity: StigSeverity::High,
            barbican_impl: "validation.rs",
            implementation_notes: "Input validation utilities with XSS/SQLi prevention",
        },
        StigRule {
            id: "APSC-DV-000170",
            title: "Must encode output to prevent injection",
            nist_controls: &["SI-10"],
            severity: StigSeverity::High,
            barbican_impl: "validation.rs",
            implementation_notes: "Output encoding utilities for HTML/JS/URL contexts",
        },
        // Session Management (AC-11, AC-12)
        StigRule {
            id: "APSC-DV-000180",
            title: "Must terminate sessions after inactivity period",
            nist_controls: &["AC-11", "AC-12"],
            severity: StigSeverity::Medium,
            barbican_impl: "session.rs:SessionPolicy",
            implementation_notes: "Configurable idle_timeout and max_lifetime with JWT exp/iat validation",
        },
        // Authentication (IA-2)
        StigRule {
            id: "APSC-DV-000190",
            title: "Must implement multi-factor authentication",
            nist_controls: &["IA-2", "IA-2(1)", "IA-2(2)"],
            severity: StigSeverity::High,
            barbican_impl: "auth.rs:MfaPolicy",
            implementation_notes: "MFA enforcement via JWT amr claim validation",
        },
        StigRule {
            id: "APSC-DV-000200",
            title: "Must support hardware token authentication",
            nist_controls: &["IA-2(6)"],
            severity: StigSeverity::Medium,
            barbican_impl: "auth.rs:MfaPolicy",
            implementation_notes: "MfaPolicy.require_hardware checks for hwk in amr claim",
        },
        // Account Lockout (AC-7)
        StigRule {
            id: "APSC-DV-000210",
            title: "Must lock account after maximum login attempts",
            nist_controls: &["AC-7"],
            severity: StigSeverity::Medium,
            barbican_impl: "login.rs:LockoutPolicy",
            implementation_notes: "Progressive lockout with configurable attempts and duration",
        },
        // Password Policy (IA-5)
        StigRule {
            id: "APSC-DV-000220",
            title: "Must enforce password complexity requirements",
            nist_controls: &["IA-5(1)"],
            severity: StigSeverity::Medium,
            barbican_impl: "password.rs:PasswordPolicy",
            implementation_notes: "NIST 800-63B compliant policy with min length, no composition rules",
        },
        StigRule {
            id: "APSC-DV-000230",
            title: "Must check passwords against breach databases",
            nist_controls: &["IA-5(1)"],
            severity: StigSeverity::Medium,
            barbican_impl: "password.rs:PasswordPolicy",
            implementation_notes: "Optional HIBP integration with k-anonymity API",
        },
        // Access Control (AC-3)
        StigRule {
            id: "APSC-DV-000240",
            title: "Must enforce approved authorizations",
            nist_controls: &["AC-3"],
            severity: StigSeverity::High,
            barbican_impl: "auth.rs:Claims",
            implementation_notes: "Role/group-based authorization via JWT claims validation",
        },
        // Audit Logging (AU-2, AU-3)
        StigRule {
            id: "APSC-DV-000250",
            title: "Must log all authentication attempts",
            nist_controls: &["AU-2", "AU-3"],
            severity: StigSeverity::Medium,
            barbican_impl: "audit/mod.rs, login.rs",
            implementation_notes: "Security event logging for auth success/failure with AU-3 content",
        },
        // Error Handling (SI-11)
        StigRule {
            id: "APSC-DV-000260",
            title: "Must not expose sensitive information in errors",
            nist_controls: &["SI-11"],
            severity: StigSeverity::Medium,
            barbican_impl: "error.rs",
            implementation_notes: "Secure error handling that sanitizes internal details",
        },
        // Cryptography (SC-13)
        StigRule {
            id: "APSC-DV-000270",
            title: "Must use FIPS 140-2 validated cryptography",
            nist_controls: &["SC-13"],
            severity: StigSeverity::High,
            barbican_impl: "encryption.rs, keys.rs",
            implementation_notes: "AES-256-GCM encryption; FIPS mode via aws-lc-rs",
        },
    ];

    /// Look up a rule by ID
    pub fn get_rule(id: &str) -> Option<&'static StigRule> {
        RULES.iter().find(|r| r.id == id)
    }

    /// Get all rules for a NIST control
    pub fn rules_for_nist(control: &str) -> Vec<&'static StigRule> {
        RULES.iter().filter(|r| r.maps_to_nist(control)).collect()
    }
}

/// Anduril NixOS STIG V1 rule definitions
///
/// NixOS-specific controls from the Anduril NixOS STIG (2024-10-25).
/// These complement the Ubuntu STIG rules for NixOS deployments.
pub mod anduril_nixos {
    use super::{StigRule, StigSeverity};

    /// Anduril NixOS STIG rules implemented by Barbican
    pub const RULES: &[StigRule] = &[
        // Firewall (SC-7)
        StigRule {
            id: "V-268078",
            title: "Enable built-in firewall",
            nist_controls: &["SC-7", "SC-7(5)"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/vm-firewall.nix",
            implementation_notes: "networking.firewall.enable = true with default DROP policy",
        },
        // Audit (AU-2)
        StigRule {
            id: "V-268080",
            title: "Enable audit daemon",
            nist_controls: &["AU-2", "AU-12"],
            severity: StigSeverity::High,
            barbican_impl: "nix/modules/intrusion-detection.nix",
            implementation_notes: "security.auditd.enable and security.audit.enable = true",
        },
        // Account Lockout (AC-7)
        StigRule {
            id: "V-268081",
            title: "Lock after 3 failed attempts with 15-minute window",
            nist_controls: &["AC-7"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/secure-users.nix, login.rs",
            implementation_notes: "PAM faillock with deny=3 fail_interval=900",
        },
        // Password Length (IA-5)
        StigRule {
            id: "V-268134",
            title: "Enforce 15-character minimum password length",
            nist_controls: &["IA-5(1)"],
            severity: StigSeverity::High,
            barbican_impl: "password.rs:PasswordPolicy",
            implementation_notes: "pwquality.conf minlen=15 via environment.etc",
        },
        // USB Protection (CM-8)
        StigRule {
            id: "V-268139",
            title: "Enable USBguard for device management",
            nist_controls: &["CM-8", "CM-8(3)", "SC-41"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/usb-protection.nix",
            implementation_notes: "services.usbguard.enable with device allowlist",
        },
        // Mandatory Access Control (AC-3)
        StigRule {
            id: "V-268173",
            title: "Configure AppArmor mandatory access control",
            nist_controls: &["AC-3", "AC-3(3)", "AC-6", "SC-3"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/mandatory-access-control.nix",
            implementation_notes: "security.apparmor.enable with service confinement",
        },
        // Memory Protection (SI-16)
        StigRule {
            id: "V-268160",
            title: "Enable NX (No-Execute) memory protection",
            nist_controls: &["SI-16"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/kernel-hardening.nix",
            implementation_notes: "Kernel compiled with NX support; ASLR enabled",
        },
        StigRule {
            id: "V-268161",
            title: "Enable Address Space Layout Randomization (ASLR)",
            nist_controls: &["SI-16"],
            severity: StigSeverity::Medium,
            barbican_impl: "nix/modules/kernel-hardening.nix",
            implementation_notes: "kernel.randomize_va_space = 2 via sysctl",
        },
    ];

    /// Look up a rule by ID
    pub fn get_rule(id: &str) -> Option<&'static StigRule> {
        RULES.iter().find(|r| r.id == id)
    }

    /// Get all rules for a NIST control
    pub fn rules_for_nist(control: &str) -> Vec<&'static StigRule> {
        RULES.iter().filter(|r| r.maps_to_nist(control)).collect()
    }
}

/// Get a STIG rule from any supported STIG by ID
pub fn get_rule(id: &str) -> Option<&'static StigRule> {
    if id.starts_with("UBTU-22-") {
        ubuntu_22_04::get_rule(id)
    } else if id.starts_with("PGS15-") {
        postgresql_15::get_rule(id)
    } else if id.starts_with("APSC-") {
        application_security::get_rule(id)
    } else if id.starts_with("V-268") {
        anduril_nixos::get_rule(id)
    } else {
        None
    }
}

/// Get all implemented STIG rules
pub fn all_rules() -> impl Iterator<Item = &'static StigRule> {
    ubuntu_22_04::RULES
        .iter()
        .chain(postgresql_15::RULES.iter())
        .chain(application_security::RULES.iter())
        .chain(anduril_nixos::RULES.iter())
}

/// Get all rules for a specific NIST control across all STIGs
pub fn rules_for_nist(control: &str) -> Vec<&'static StigRule> {
    all_rules().filter(|r| r.maps_to_nist(control)).collect()
}

/// Get statistics about STIG coverage
pub struct StigCoverage {
    pub ubuntu_22_04_count: usize,
    pub postgresql_15_count: usize,
    pub application_security_count: usize,
    pub anduril_nixos_count: usize,
    pub total: usize,
    pub high_severity: usize,
    pub medium_severity: usize,
    pub low_severity: usize,
}

impl StigCoverage {
    /// Calculate coverage statistics
    pub fn calculate() -> Self {
        let ubuntu = ubuntu_22_04::RULES.len();
        let postgres = postgresql_15::RULES.len();
        let appsec = application_security::RULES.len();
        let nixos = anduril_nixos::RULES.len();
        let total = ubuntu + postgres + appsec + nixos;

        let high = all_rules().filter(|r| matches!(r.severity, StigSeverity::High)).count();
        let medium = all_rules().filter(|r| matches!(r.severity, StigSeverity::Medium)).count();
        let low = all_rules().filter(|r| matches!(r.severity, StigSeverity::Low)).count();

        Self {
            ubuntu_22_04_count: ubuntu,
            postgresql_15_count: postgres,
            application_security_count: appsec,
            anduril_nixos_count: nixos,
            total,
            high_severity: high,
            medium_severity: medium,
            low_severity: low,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubuntu_rule_lookup() {
        let rule = ubuntu_22_04::get_rule("UBTU-22-411045");
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.id, "UBTU-22-411045");
        assert!(rule.maps_to_nist("AC-7"));
    }

    #[test]
    fn test_postgresql_rule_lookup() {
        let rule = postgresql_15::get_rule("PGS15-00-000100");
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert!(rule.maps_to_nist("SC-8"));
    }

    #[test]
    fn test_appsec_rule_lookup() {
        let rule = application_security::get_rule("APSC-DV-000180");
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert!(rule.maps_to_nist("AC-11"));
        assert!(rule.maps_to_nist("AC-12"));
    }

    #[test]
    fn test_anduril_nixos_rule_lookup() {
        let rule = anduril_nixos::get_rule("V-268139");
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.id, "V-268139");
        assert!(rule.maps_to_nist("CM-8"));
    }

    #[test]
    fn test_generic_rule_lookup() {
        assert!(get_rule("UBTU-22-411045").is_some());
        assert!(get_rule("PGS15-00-000100").is_some());
        assert!(get_rule("APSC-DV-000180").is_some());
        assert!(get_rule("V-268139").is_some());
        assert!(get_rule("INVALID-00-000").is_none());
    }

    #[test]
    fn test_rules_for_nist_control() {
        let ac7_rules = rules_for_nist("AC-7");
        assert!(!ac7_rules.is_empty());
        // Should include both Ubuntu and AppSec rules for AC-7
        let has_ubuntu = ac7_rules.iter().any(|r| r.id.starts_with("UBTU"));
        let has_appsec = ac7_rules.iter().any(|r| r.id.starts_with("APSC"));
        assert!(has_ubuntu);
        assert!(has_appsec);
    }

    #[test]
    fn test_coverage_statistics() {
        let coverage = StigCoverage::calculate();
        assert!(coverage.total > 0);
        assert!(coverage.ubuntu_22_04_count > 0);
        assert!(coverage.postgresql_15_count > 0);
        assert!(coverage.application_security_count > 0);
        assert!(coverage.anduril_nixos_count > 0);
        assert_eq!(
            coverage.total,
            coverage.ubuntu_22_04_count
                + coverage.postgresql_15_count
                + coverage.application_security_count
                + coverage.anduril_nixos_count
        );
    }

    #[test]
    fn test_all_rules_have_implementations() {
        for rule in all_rules() {
            assert!(!rule.barbican_impl.is_empty(), "Rule {} has no implementation", rule.id);
            assert!(!rule.implementation_notes.is_empty(), "Rule {} has no notes", rule.id);
        }
    }

    #[test]
    fn test_family_matching() {
        let rule = ubuntu_22_04::get_rule("UBTU-22-411045").unwrap();
        assert!(rule.maps_to_family("AC"));
        assert!(!rule.maps_to_family("SC"));
    }
}
