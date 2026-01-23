//! Compliance Configuration Framework
//!
//! Provides FedRAMP, SOC 2, and NIST 800-53 compliant configuration
//! that drives security settings across the entire application.
//!
//! # Overview
//!
//! This module provides a unified compliance configuration system that:
//! - Defines security profiles for multiple frameworks (FedRAMP, SOC 2, etc.)
//! - Derives security settings from the selected profile
//! - Validates application components against compliance requirements
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::{ComplianceConfig, ComplianceProfile};
//!
//! // Initialize at startup
//! let config = ComplianceConfig::from_env();
//! barbican::compliance::init(config);
//!
//! // Access globally anywhere
//! let profile = barbican::compliance::config().profile;
//! ```
//!
//! # Compliance Controls
//!
//! - **AC-7**: Account lockout (login.rs)
//! - **AC-11**: Session lock / idle timeout (session.rs)
//! - **AC-12**: Session termination (session.rs)
//! - **AU-11**: Audit record retention
//! - **IA-2**: Multi-factor authentication (auth.rs)
//! - **IA-5**: Password policy (password.rs)
//! - **SC-8**: Transmission confidentiality (database.rs, TLS)
//! - **SC-12**: Key management (keys.rs)
//! - **SC-28**: Protection of information at rest (database.rs)

mod config;
mod profile;
mod validation;

#[cfg(feature = "compliance-artifacts")]
pub mod artifacts;

#[cfg(feature = "compliance-artifacts")]
pub mod control_tests;

#[cfg(feature = "stig")]
pub mod stig;

pub use config::{config, init, ComplianceConfig};
pub use profile::ComplianceProfile;
pub use validation::{ComplianceError, ComplianceReport, ComplianceValidator, ControlStatus};

#[cfg(feature = "compliance-artifacts")]
pub use artifacts::{
    ArtifactBuilder, CodeLocation, ComplianceTestReport, ControlTestArtifact, EvidenceCollector,
    EvidenceItem, EvidenceType, FamilySummary, ReportSignature, SigningError, TestSummary,
};

#[cfg(feature = "compliance-artifacts")]
pub use control_tests::{
    all_control_tests, generate_compliance_report, generate_compliance_report_for_profile,
};
