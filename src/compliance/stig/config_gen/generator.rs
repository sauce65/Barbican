//! STIG Configuration Generator
//!
//! Main pipeline that extracts values from ComplianceAsCode content and generates
//! Barbican-compatible configuration. Supports generating both runtime
//! `ComplianceConfig` structs and static `barbican.toml` files.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::compliance::config::ComplianceConfig;
use crate::compliance::ComplianceProfile;

use super::super::loader::StigLoader;
use super::error::{GeneratorError, Result};
use super::profile_parser::{ProfileCollection, StigProfile};
use super::registry::{BarbicanParam, MappingRegistry, ValueTransform};
use super::variable::{VariableCollection, VariableValue};

/// STIG Configuration Generator
///
/// Builder-pattern generator that loads STIG controls, variables, and profiles,
/// then generates Barbican configuration from the extracted values.
///
/// # Example
///
/// ```ignore
/// use barbican::compliance::stig::config_gen::StigConfigGenerator;
///
/// let mut generator = StigConfigGenerator::new()
///     .load_stig("controls/stig_ubuntu2204.yml")?
///     .load_variables("content/")?
///     .load_profile("stig")?;
///
/// let config = generator.generate_config()?;
/// ```
#[derive(Debug)]
pub struct StigConfigGenerator {
    /// Loaded variable definitions
    variables: VariableCollection,

    /// Loaded profiles
    profiles: ProfileCollection,

    /// Active profile (resolved with inheritance)
    active_profile: Option<StigProfile>,

    /// STIG loader (for rule existence checks)
    stig_loader: Option<StigLoader>,

    /// Mapping registry
    registry: MappingRegistry,

    /// Resolved parameter values
    resolved: HashMap<BarbicanParam, VariableValue>,

    /// Warnings generated during resolution
    warnings: Vec<String>,
}

impl StigConfigGenerator {
    /// Create a new generator with default mappings
    pub fn new() -> Self {
        Self {
            variables: VariableCollection::new(),
            profiles: ProfileCollection::new(),
            active_profile: None,
            stig_loader: None,
            registry: MappingRegistry::default_mappings(),
            resolved: HashMap::new(),
            warnings: Vec::new(),
        }
    }

    /// Create with a custom mapping registry
    pub fn with_registry(registry: MappingRegistry) -> Self {
        Self {
            registry,
            ..Self::new()
        }
    }

    /// Load STIG control file
    ///
    /// This enables rule existence checks for boolean-from-rule mappings.
    pub fn load_stig(mut self, path: impl AsRef<Path>) -> Result<Self> {
        self.stig_loader = Some(StigLoader::from_control_file(path)?);
        Ok(self)
    }

    /// Load STIG from YAML content
    pub fn load_stig_yaml(mut self, yaml: &str) -> Result<Self> {
        self.stig_loader = Some(StigLoader::from_yaml(yaml)?);
        Ok(self)
    }

    /// Load rules from ComplianceAsCode content directory
    ///
    /// This populates the STIG loader with rules for NIST mapping.
    pub fn load_rules_from_content(mut self, content_dir: impl AsRef<Path>) -> Result<Self> {
        if let Some(ref mut loader) = self.stig_loader {
            loader.load_rules_from_content(content_dir)?;
        }
        Ok(self)
    }

    /// Load variable definitions from ComplianceAsCode content
    pub fn load_variables(mut self, content_dir: impl AsRef<Path>) -> Result<Self> {
        self.variables = VariableCollection::load_from_content(content_dir)?;
        Ok(self)
    }

    /// Load profiles from ComplianceAsCode content
    pub fn load_profiles(mut self, content_dir: impl AsRef<Path>) -> Result<Self> {
        self.profiles = ProfileCollection::load_from_content(content_dir)?;
        Ok(self)
    }

    /// Load profiles for a specific product
    pub fn load_profiles_for_product(
        mut self,
        content_dir: impl AsRef<Path>,
        product: &str,
    ) -> Result<Self> {
        self.profiles = ProfileCollection::load_for_product(content_dir, product)?;
        Ok(self)
    }

    /// Select a profile by name
    ///
    /// The profile must be loaded via `load_profiles()` first.
    pub fn select_profile(mut self, profile_name: &str) -> Result<Self> {
        self.active_profile = self.profiles.get_resolved(profile_name);
        if self.active_profile.is_none() {
            return Err(GeneratorError::ProfileNotFound {
                profile: profile_name.to_string(),
                searched_paths: vec![],
            });
        }
        Ok(self)
    }

    /// Add a profile directly (for programmatic configuration)
    ///
    /// This adds the profile to the collection and makes it available for selection.
    /// Use `select_profile()` to activate it.
    pub fn add_profile(mut self, profile: StigProfile) -> Self {
        self.profiles.add(profile);
        self
    }

    /// Add a profile and immediately select it
    pub fn with_profile(mut self, profile: StigProfile) -> Self {
        let profile_id = profile.id.clone();
        self.profiles.add(profile);
        self.active_profile = self.profiles.get_resolved(&profile_id);
        self
    }

    /// Load a profile from a specific file
    pub fn load_profile_file(mut self, path: impl AsRef<Path>) -> Result<Self> {
        let profile = StigProfile::from_file(path)?;
        self.profiles.add(profile.clone());

        // If profile extends another, try to resolve
        self.active_profile = self.profiles.get_resolved(&profile.id);
        if self.active_profile.is_none() {
            self.active_profile = Some(profile);
        }

        Ok(self)
    }

    /// Add a variable definition manually
    pub fn add_variable(
        mut self,
        var: super::variable::VariableDefinition,
    ) -> Self {
        self.variables.add(var);
        self
    }

    /// Get the loaded STIG loader
    pub fn stig_loader(&self) -> Option<&StigLoader> {
        self.stig_loader.as_ref()
    }

    /// Get the active profile
    pub fn active_profile(&self) -> Option<&StigProfile> {
        self.active_profile.as_ref()
    }

    /// Get warnings generated during resolution
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Resolve all parameter values from loaded data
    fn resolve_values(&mut self) -> Result<()> {
        self.resolved.clear();
        self.warnings.clear();

        // Get rule IDs from STIG loader (for boolean-from-rule checks)
        let selected_rules: HashSet<String> = self
            .stig_loader
            .as_ref()
            .map(|loader| {
                loader
                    .controls()
                    .iter()
                    .flat_map(|c| c.rules.iter().cloned())
                    .collect()
            })
            .unwrap_or_default();

        // Also include rules selected in profile
        let profile_rules: HashSet<String> = self
            .active_profile
            .as_ref()
            .map(|p| p.selections.iter().cloned().collect())
            .unwrap_or_default();

        let all_rules: HashSet<_> = selected_rules.union(&profile_rules).collect();

        // Resolve each parameter from registry
        for mapping in self.registry.iter() {
            let value = self.resolve_single_param(mapping, &all_rules);
            if let Some(v) = value {
                self.resolved.insert(mapping.barbican_param, v);
            } else if let Some(ref default) = mapping.default {
                self.resolved.insert(mapping.barbican_param, default.clone());
                self.warnings.push(format!(
                    "Using default for {}: {:?}",
                    mapping.barbican_param, default
                ));
            } else {
                self.warnings.push(format!(
                    "No value found for {} (NIST {})",
                    mapping.barbican_param, mapping.nist_control
                ));
            }
        }

        // Calculate derived values
        self.calculate_derived_values();

        Ok(())
    }

    /// Resolve a single parameter value
    fn resolve_single_param(
        &self,
        mapping: &super::registry::ParameterMapping,
        selected_rules: &HashSet<&String>,
    ) -> Option<VariableValue> {
        // Handle boolean-from-rule mappings
        // Only derive from rule existence if we have profile/STIG data loaded
        if let ValueTransform::BoolFromRule(ref rule_id) = mapping.transform {
            // If we have no profile and no STIG data, return None to use default
            if self.active_profile.is_none() && self.stig_loader.is_none() {
                return None;
            }
            let exists = selected_rules.contains(&rule_id);
            return Some(VariableValue::Boolean(exists));
        }

        // Get variable name
        let var_name = mapping.cac_variable.as_ref()?;

        // First check profile for variable assignment
        if let Some(ref profile) = self.active_profile {
            if let Some(value_str) = profile.get_variable(var_name) {
                // Parse the string value based on the transform
                if let Some(value) = self.parse_profile_value(value_str, &mapping.transform) {
                    return mapping.transform.apply(&value);
                }
            }
        }

        // Fall back to variable definition default
        if let Some(var_def) = self.variables.get(var_name) {
            if let Some(default) = var_def.default_or_first() {
                return mapping.transform.apply(default);
            }
        }

        None
    }

    /// Parse a profile value string into a VariableValue
    fn parse_profile_value(&self, value_str: &str, transform: &ValueTransform) -> Option<VariableValue> {
        match transform {
            ValueTransform::SecondsToDuration => {
                value_str.parse::<i64>().ok().map(VariableValue::Integer)
            }
            ValueTransform::Identity => {
                // Try integer first, then string
                if let Ok(n) = value_str.parse::<i64>() {
                    Some(VariableValue::Integer(n))
                } else {
                    Some(VariableValue::String(value_str.to_string()))
                }
            }
            ValueTransform::BoolFromRule(_) => {
                // Already handled above
                None
            }
            ValueTransform::Multiplier { .. } => {
                value_str.parse::<i64>().ok().map(VariableValue::Integer)
            }
            ValueTransform::Custom(_) => {
                // Try integer first, then string
                if let Ok(n) = value_str.parse::<i64>() {
                    Some(VariableValue::Integer(n))
                } else {
                    Some(VariableValue::String(value_str.to_string()))
                }
            }
        }
    }

    /// Calculate values that are derived from other values
    fn calculate_derived_values(&mut self) {
        // Session max lifetime = 1.5x idle timeout
        if let Some(idle) = self.resolved.get(&BarbicanParam::SessionIdleTimeout) {
            if let Some(duration) = idle.as_duration() {
                let max_lifetime = Duration::from_secs_f64(duration.as_secs_f64() * 1.5);
                self.resolved
                    .insert(BarbicanParam::SessionMaxLifetime, VariableValue::Duration(max_lifetime));
            }
        }

        // Re-auth timeout = idle timeout or 15 minutes
        if !self.resolved.contains_key(&BarbicanParam::ReauthTimeout) {
            if let Some(idle) = self.resolved.get(&BarbicanParam::SessionIdleTimeout) {
                if let Some(duration) = idle.as_duration() {
                    // Re-auth timeout should be <= idle timeout
                    let reauth = duration.min(Duration::from_secs(15 * 60));
                    self.resolved
                        .insert(BarbicanParam::ReauthTimeout, VariableValue::Duration(reauth));
                }
            }
        }
    }

    /// Generate a ComplianceConfig from resolved values
    pub fn generate_config(&mut self) -> Result<ComplianceConfig> {
        self.resolve_values()?;

        // Helper closures for extracting values
        let get_duration = |resolved: &HashMap<BarbicanParam, VariableValue>, param: BarbicanParam, default: Duration| {
            resolved
                .get(&param)
                .and_then(|v| v.as_duration())
                .unwrap_or(default)
        };

        let get_bool = |resolved: &HashMap<BarbicanParam, VariableValue>, param: BarbicanParam, default: bool| {
            resolved
                .get(&param)
                .and_then(|v| v.as_boolean())
                .unwrap_or(default)
        };

        let get_int = |resolved: &HashMap<BarbicanParam, VariableValue>, param: BarbicanParam, default: i64| {
            resolved
                .get(&param)
                .and_then(|v| v.as_integer())
                .unwrap_or(default)
        };

        // Build config
        let config = ComplianceConfig {
            profile: ComplianceProfile::Custom,

            session_max_lifetime: get_duration(
                &self.resolved,
                BarbicanParam::SessionMaxLifetime,
                Duration::from_secs(15 * 60),
            ),
            session_idle_timeout: get_duration(
                &self.resolved,
                BarbicanParam::SessionIdleTimeout,
                Duration::from_secs(10 * 60),
            ),
            reauth_timeout: get_duration(
                &self.resolved,
                BarbicanParam::ReauthTimeout,
                Duration::from_secs(15 * 60),
            ),

            require_mfa: get_bool(&self.resolved, BarbicanParam::RequireMfa, true),
            require_hardware_mfa: get_bool(&self.resolved, BarbicanParam::RequireHardwareMfa, false),

            password_min_length: get_int(&self.resolved, BarbicanParam::PasswordMinLength, 15) as usize,
            password_check_breach_db: get_bool(&self.resolved, BarbicanParam::PasswordCheckBreachDb, false),

            max_login_attempts: get_int(&self.resolved, BarbicanParam::MaxLoginAttempts, 3) as u32,
            lockout_duration: get_duration(
                &self.resolved,
                BarbicanParam::LockoutDuration,
                Duration::from_secs(15 * 60),
            ),

            key_rotation_interval: get_duration(
                &self.resolved,
                BarbicanParam::KeyRotationInterval,
                Duration::from_secs(365 * 24 * 60 * 60),
            ),

            require_tls: get_bool(&self.resolved, BarbicanParam::RequireTls, true),
            require_mtls: get_bool(&self.resolved, BarbicanParam::RequireMtls, false),
            require_encryption_at_rest: get_bool(&self.resolved, BarbicanParam::RequireEncryptionAtRest, true),

            require_tenant_isolation: get_bool(&self.resolved, BarbicanParam::RequireTenantIsolation, true),

            min_retention_days: get_int(&self.resolved, BarbicanParam::MinRetentionDays, 90) as u32,
        };

        Ok(config)
    }

    /// Generate a TOML configuration string
    pub fn generate_toml(&mut self) -> Result<String> {
        self.resolve_values()?;
        super::toml_writer::write_toml(&self.resolved, self.active_profile.as_ref(), &self.warnings)
    }

    /// Generate a coverage report showing what was resolved
    pub fn generate_coverage_report(&self) -> CoverageReport {
        let mut mapped = Vec::new();
        let mut unmapped = Vec::new();
        let warnings = self.warnings.clone();

        for param in BarbicanParam::all() {
            if let Some(value) = self.resolved.get(param) {
                let source = self
                    .registry
                    .get_by_param(*param)
                    .and_then(|m| m.cac_variable.clone())
                    .unwrap_or_else(|| "derived".to_string());

                mapped.push(MappedParameter {
                    param: *param,
                    value: value.clone(),
                    source,
                    nist_control: param.nist_control().to_string(),
                });
            } else {
                unmapped.push(*param);
            }
        }

        CoverageReport {
            profile_name: self.active_profile.as_ref().map(|p| p.id.clone()),
            variables_loaded: self.variables.len(),
            parameters_mapped: mapped.len(),
            parameters_unmapped: unmapped.len(),
            mapped,
            unmapped,
            warnings,
        }
    }
}

impl Default for StigConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Report of configuration coverage
#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Profile name if one was selected
    pub profile_name: Option<String>,

    /// Number of variables loaded
    pub variables_loaded: usize,

    /// Number of parameters successfully mapped
    pub parameters_mapped: usize,

    /// Number of parameters without values
    pub parameters_unmapped: usize,

    /// Successfully mapped parameters
    pub mapped: Vec<MappedParameter>,

    /// Unmapped parameters
    pub unmapped: Vec<BarbicanParam>,

    /// Warnings generated during resolution
    pub warnings: Vec<String>,
}

impl std::fmt::Display for CoverageReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "STIG Configuration Coverage Report")?;
        writeln!(f, "===================================")?;
        if let Some(ref name) = self.profile_name {
            writeln!(f, "Profile: {}", name)?;
        }
        writeln!(f, "Variables Loaded: {}", self.variables_loaded)?;
        writeln!(
            f,
            "Parameters: {}/{} mapped",
            self.parameters_mapped,
            self.parameters_mapped + self.parameters_unmapped
        )?;
        writeln!(f)?;

        writeln!(f, "Mapped Parameters:")?;
        for param in &self.mapped {
            writeln!(
                f,
                "  {} ({}) = {} [from: {}]",
                param.param, param.nist_control, param.value, param.source
            )?;
        }

        if !self.unmapped.is_empty() {
            writeln!(f)?;
            writeln!(f, "Unmapped Parameters:")?;
            for param in &self.unmapped {
                writeln!(f, "  {} ({})", param, param.nist_control())?;
            }
        }

        if !self.warnings.is_empty() {
            writeln!(f)?;
            writeln!(f, "Warnings:")?;
            for warning in &self.warnings {
                writeln!(f, "  - {}", warning)?;
            }
        }

        Ok(())
    }
}

/// A successfully mapped parameter
#[derive(Debug, Clone)]
pub struct MappedParameter {
    /// Barbican parameter
    pub param: BarbicanParam,

    /// Resolved value
    pub value: VariableValue,

    /// Source (variable name or "derived")
    pub source: String,

    /// NIST control reference
    pub nist_control: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile_yaml() -> &'static str {
        r#"
id: test_stig
title: Test STIG Profile
selections:
  - var_password_pam_minlen=15
  - var_accounts_passwords_pam_faillock_deny=3
  - var_accounts_passwords_pam_faillock_unlock_time=900
  - var_screensaver_lock_delay=600
"#
    }

    #[test]
    fn test_generator_with_profile() {
        let profile = StigProfile::from_yaml(sample_profile_yaml(), "test_stig".into()).unwrap();

        let mut generator = StigConfigGenerator::new();
        generator.profiles.add(profile);
        generator = generator.select_profile("test_stig").unwrap();

        let config = generator.generate_config().unwrap();

        assert_eq!(config.password_min_length, 15);
        assert_eq!(config.max_login_attempts, 3);
        assert_eq!(config.lockout_duration, Duration::from_secs(900));
        assert_eq!(config.session_idle_timeout, Duration::from_secs(600));
    }

    #[test]
    fn test_derived_values() {
        let profile = StigProfile::from_yaml(sample_profile_yaml(), "test_stig".into()).unwrap();

        let mut generator = StigConfigGenerator::new();
        generator.profiles.add(profile);
        generator = generator.select_profile("test_stig").unwrap();

        let config = generator.generate_config().unwrap();

        // Session max lifetime should be 1.5x idle timeout
        assert_eq!(
            config.session_max_lifetime,
            Duration::from_secs(900) // 600 * 1.5
        );
    }

    #[test]
    fn test_coverage_report() {
        let profile = StigProfile::from_yaml(sample_profile_yaml(), "test_stig".into()).unwrap();

        let mut generator = StigConfigGenerator::new();
        generator.profiles.add(profile);
        generator = generator.select_profile("test_stig").unwrap();
        generator.generate_config().unwrap();

        let report = generator.generate_coverage_report();

        assert_eq!(report.profile_name, Some("test_stig".to_string()));
        assert!(report.parameters_mapped > 0);

        // Check display doesn't panic
        let _ = format!("{}", report);
    }

    #[test]
    fn test_default_values() {
        let mut generator = StigConfigGenerator::new();
        let config = generator.generate_config().unwrap();

        // Should use defaults
        assert!(config.password_min_length > 0);
        assert!(config.max_login_attempts > 0);
        assert!(config.require_tls);
    }
}
