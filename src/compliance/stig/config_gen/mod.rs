//! STIG Configuration Generator
//!
//! Extracts values from ComplianceAsCode STIG content and generates
//! Barbican-compatible configuration. Supports both runtime `ComplianceConfig`
//! generation and static `barbican.toml` file output.
//!
//! # Overview
//!
//! This module bridges the gap between ComplianceAsCode's machine-readable
//! STIG content and Barbican's compliance configuration. It:
//!
//! 1. Parses variable definitions (`var_*.var` files)
//! 2. Parses profile files (`.profile` files with variable assignments)
//! 3. Maps ComplianceAsCode variables to NIST 800-53 controls
//! 4. Generates Barbican configuration with proper transforms
//!
//! # Usage
//!
//! ## Generate Runtime Configuration
//!
//! ```ignore
//! use barbican::compliance::stig::config_gen::StigConfigGenerator;
//!
//! // Load from ComplianceAsCode content directory
//! let mut generator = StigConfigGenerator::new()
//!     .load_stig("controls/stig_ubuntu2204.yml")?
//!     .load_variables("content/")?
//!     .load_profiles("content/")?
//!     .select_profile("stig")?;
//!
//! let config = generator.generate_config()?;
//! barbican::compliance::init(config);
//! ```
//!
//! ## Generate Static TOML File
//!
//! ```ignore
//! let mut generator = StigConfigGenerator::new()
//!     .load_profile_file("products/ubuntu2204/profiles/stig.profile")?;
//!
//! let toml = generator.generate_toml()?;
//! std::fs::write("barbican.toml", toml)?;
//! ```
//!
//! ## Generate Coverage Report
//!
//! ```ignore
//! let report = generator.generate_coverage_report();
//! println!("{}", report);
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │ STIG Controls   │    │ var_*.var       │    │ *.profile       │
//! │ (existing)      │    │ (variables)     │    │ (assignments)   │
//! └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
//!          │                      │                      │
//!          ▼                      ▼                      ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    MappingRegistry                           │
//! │  var_password_pam_minlen ──► IA-5 ──► PasswordMinLength     │
//! │  var_faillock_deny ────────► AC-7 ──► MaxLoginAttempts      │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
//! │ ComplianceConfig│  │ barbican.toml   │  │ CoverageReport  │
//! │ (Rust struct)   │  │ (TOML file)     │  │ (validation)    │
//! └─────────────────┘  └─────────────────┘  └─────────────────┘
//! ```
//!
//! # NIST Control Mapping
//!
//! | NIST Control | ComplianceAsCode Variable | Barbican Parameter |
//! |--------------|---------------------------|-------------------|
//! | AC-7 | `var_accounts_passwords_pam_faillock_deny` | `max_login_attempts` |
//! | AC-7 | `var_accounts_passwords_pam_faillock_unlock_time` | `lockout_duration` |
//! | AC-11 | `var_screensaver_lock_delay` | `session_idle_timeout` |
//! | AC-12 | (derived from AC-11) | `session_max_lifetime` |
//! | IA-2 | (rule: `enable_fips_mode`) | `require_mfa` |
//! | IA-5 | `var_password_pam_minlen` | `password_min_length` |
//! | SC-8 | (rule: `configure_crypto_policy`) | `require_tls` |
//! | SC-28 | (rule: `encrypt_partitions`) | `require_encryption_at_rest` |
//! | AU-11 | `var_auditd_max_log_file` | `min_retention_days` |

mod error;
mod generator;
mod profile_parser;
mod registry;
mod toml_writer;
mod variable;
mod verify;

pub use error::{GeneratorError, Result};
pub use generator::{CoverageReport, MappedParameter, StigConfigGenerator};
pub use profile_parser::{ProfileCollection, StigProfile};
pub use registry::{BarbicanParam, MappingRegistry, ParameterMapping, ValueTransform};
pub use variable::{VariableCollection, VariableDefinition, VariableType, VariableValue};
pub use verify::{
    ComparisonStatus, DeviationCategory, DeviationJustification, ParameterComparison,
    ProfileVerifier, VerificationReport,
};
