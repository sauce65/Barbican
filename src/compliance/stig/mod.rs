//! STIG Loader for ComplianceAsCode Content
//!
//! Parses STIG definitions from ComplianceAsCode YAML files and maps them
//! to NIST 800-53 controls for integration with Barbican's compliance framework.
//!
//! # Overview
//!
//! ComplianceAsCode is an open-source project that provides machine-readable
//! security compliance content. This module parses their YAML format and
//! correlates STIG controls to NIST 800-53 controls that Barbican validates.
//!
//! # Usage
//!
//! ```ignore
//! use barbican::compliance::stig::{StigLoader, StigControl};
//!
//! // Load a STIG control file
//! let loader = StigLoader::from_file("controls/stig_ubuntu2204.yml")?;
//!
//! // Get all controls
//! for control in loader.controls() {
//!     println!("{}: {} -> {:?}", control.id, control.title, control.nist_controls());
//! }
//!
//! // Find controls by NIST mapping
//! let ac7_controls = loader.controls_for_nist("AC-7");
//! ```
//!
//! # Configuration Generation
//!
//! Use the `config_gen` submodule to generate Barbican configuration from
//! STIG content:
//!
//! ```ignore
//! use barbican::compliance::stig::config_gen::StigConfigGenerator;
//!
//! let mut generator = StigConfigGenerator::new()
//!     .load_stig("controls/stig_ubuntu2204.yml")?
//!     .load_variables("content/")?
//!     .load_profiles("content/")?
//!     .select_profile("stig")?;
//!
//! let config = generator.generate_config()?;
//! ```
//!
//! # Data Sources
//!
//! Clone ComplianceAsCode content from:
//! ```bash
//! git clone --depth 1 https://github.com/ComplianceAsCode/content.git
//! ```
//!
//! Key paths:
//! - `controls/*.yml` - Control mapping files (STIG, CIS, NIST)
//! - `linux_os/guide/**/**/rule.yml` - Rule definitions with NIST references
//! - `products/*/profiles/*.profile` - Profile files with variable assignments
//! - `linux_os/guide/**/var_*.var` - Variable definition files

pub mod config_gen;

mod control;
mod loader;
mod rule;
mod types;
mod validator;

pub use control::{ControlFile, StigControl, ControlLevel, ControlStatus as StigControlStatus};
pub use loader::{StigLoader, StigLoaderError, StigStats, NistMappingReport};
pub use rule::{Rule, RuleReferences, Severity};
pub use types::{NistControl, StigMapping, StigSeverity};
pub use validator::{StigValidation, StigComplianceSummary};
