//! Example: Generating Barbican configuration from STIG content
//!
//! This example demonstrates how to:
//! 1. Load STIG control files and variable definitions
//! 2. Select a profile with variable assignments
//! 3. Generate a ComplianceConfig for runtime use
//! 4. Generate a barbican.toml file for static configuration
//! 5. Generate a coverage report
//!
//! To run this example:
//!
//! ```bash
//! # With sample data (no external dependencies)
//! cargo run --example stig_config_gen --features stig
//!
//! # With real ComplianceAsCode content
//! git clone --depth 1 https://github.com/ComplianceAsCode/content.git /tmp/cac
//! cargo run --example stig_config_gen --features stig -- \
//!     --stig /tmp/cac/controls/stig_ubuntu2204.yml \
//!     --content /tmp/cac \
//!     --profile stig
//! ```

use barbican::compliance::stig::config_gen::{
    StigConfigGenerator, StigProfile, VariableDefinition,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check for command-line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--help" {
        print_help();
        return Ok(());
    }

    // If command-line args provided, use them; otherwise use sample data
    if args.contains(&"--stig".to_string()) || args.contains(&"--content".to_string()) {
        run_with_args(&args)?;
    } else {
        run_with_sample_data()?;
    }

    Ok(())
}

fn print_help() {
    println!(
        r#"STIG Configuration Generator Example

Usage:
  cargo run --example stig_config_gen --features stig [OPTIONS]

Options:
  --stig <path>       Path to STIG control file (e.g., controls/stig_ubuntu2204.yml)
  --content <path>    Path to ComplianceAsCode content directory
  --profile <name>    Profile name to load (e.g., stig, stig_gui)
  --toml              Output barbican.toml format
  --help              Show this help message

Examples:
  # Run with sample data
  cargo run --example stig_config_gen --features stig

  # Run with real ComplianceAsCode content
  git clone --depth 1 https://github.com/ComplianceAsCode/content.git /tmp/cac
  cargo run --example stig_config_gen --features stig -- \
      --stig /tmp/cac/controls/stig_ubuntu2204.yml \
      --content /tmp/cac \
      --profile stig
"#
    );
}

fn run_with_args(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut stig_path = None;
    let mut content_path = None;
    let mut profile_name = None;
    let mut output_toml = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--stig" => {
                stig_path = args.get(i + 1).cloned();
                i += 2;
            }
            "--content" => {
                content_path = args.get(i + 1).cloned();
                i += 2;
            }
            "--profile" => {
                profile_name = args.get(i + 1).cloned();
                i += 2;
            }
            "--toml" => {
                output_toml = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    println!("STIG Configuration Generator");
    println!("=============================\n");

    let mut generator = StigConfigGenerator::new();

    // Load STIG control file if provided
    if let Some(path) = stig_path {
        println!("Loading STIG control file: {}", path);
        generator = generator.load_stig(&path)?;
    }

    // Load variables and profiles from content directory
    if let Some(path) = &content_path {
        println!("Loading variables from: {}", path);
        generator = generator.load_variables(path)?;

        println!("Loading profiles from: {}", path);
        generator = generator.load_profiles(path)?;
    }

    // Select profile
    if let Some(name) = profile_name {
        println!("Selecting profile: {}", name);
        generator = generator.select_profile(&name)?;
    }

    println!();

    // Generate output
    if output_toml {
        let toml = generator.generate_toml()?;
        println!("{}", toml);
    } else {
        // Generate ComplianceConfig
        let config = generator.generate_config()?;

        println!("Generated ComplianceConfig:");
        println!("  Session Max Lifetime: {:?}", config.session_max_lifetime);
        println!("  Session Idle Timeout: {:?}", config.session_idle_timeout);
        println!("  Re-auth Timeout: {:?}", config.reauth_timeout);
        println!("  Require MFA: {}", config.require_mfa);
        println!("  Require Hardware MFA: {}", config.require_hardware_mfa);
        println!("  Password Min Length: {}", config.password_min_length);
        println!(
            "  Password Check Breach DB: {}",
            config.password_check_breach_db
        );
        println!("  Max Login Attempts: {}", config.max_login_attempts);
        println!("  Lockout Duration: {:?}", config.lockout_duration);
        println!("  Key Rotation Interval: {:?}", config.key_rotation_interval);
        println!("  Require TLS: {}", config.require_tls);
        println!("  Require mTLS: {}", config.require_mtls);
        println!(
            "  Require Encryption at Rest: {}",
            config.require_encryption_at_rest
        );
        println!(
            "  Require Tenant Isolation: {}",
            config.require_tenant_isolation
        );
        println!("  Min Retention Days: {}", config.min_retention_days);

        // Show coverage report
        println!("\n");
        let report = generator.generate_coverage_report();
        println!("{}", report);
    }

    // Show any warnings
    let warnings = generator.warnings();
    if !warnings.is_empty() {
        println!("\nWarnings:");
        for warning in warnings {
            println!("  - {}", warning);
        }
    }

    Ok(())
}

fn run_with_sample_data() -> Result<(), Box<dyn std::error::Error>> {
    println!("STIG Configuration Generator - Sample Data");
    println!("==========================================\n");
    println!("(Running with embedded sample data. Use --help for options.)\n");

    // Sample profile with variable assignments (like a STIG .profile file)
    let sample_profile_yaml = r#"
id: sample_stig
title: 'Sample STIG Profile for Ubuntu 22.04'
description: |-
  This is a sample STIG profile demonstrating the configuration generator.
  In production, you would load real ComplianceAsCode content.
selections:
  # Variable assignments (var_name=value format)
  - var_password_pam_minlen=15
  - var_accounts_passwords_pam_faillock_deny=3
  - var_accounts_passwords_pam_faillock_unlock_time=900
  - var_screensaver_lock_delay=600
  - var_system_crypto_policy=FIPS

  # Rule selections (for boolean-from-rule mappings)
  - enable_fips_mode
  - configure_crypto_policy
  - encrypt_partitions
"#;

    // Sample variable definition (like var_password_pam_minlen.var)
    let sample_var_yaml = r#"
documentation_complete: true
title: 'Password Minimum Length'
description: |-
  Minimum number of characters for passwords.
type: number
operator: equals
interactive: true
options:
  default: 14
  8: 8
  12: 12
  14: 14
  15: 15
"#;

    // Create generator with sample data
    let var = VariableDefinition::from_yaml(sample_var_yaml, "var_password_pam_minlen".into())?;
    let profile = StigProfile::from_yaml(sample_profile_yaml, "sample_stig".into())?;

    let mut generator = StigConfigGenerator::new()
        .add_variable(var)
        .with_profile(profile);

    // Generate ComplianceConfig
    let config = generator.generate_config()?;

    println!("Generated ComplianceConfig from Sample STIG Profile");
    println!("---------------------------------------------------\n");

    println!("Session Settings (AC-11, AC-12):");
    println!(
        "  session_max_lifetime = {:?}",
        config.session_max_lifetime
    );
    println!(
        "  session_idle_timeout = {:?}",
        config.session_idle_timeout
    );
    println!("  reauth_timeout = {:?}", config.reauth_timeout);

    println!("\nAuthentication Settings (IA-2):");
    println!("  require_mfa = {}", config.require_mfa);
    println!("  require_hardware_mfa = {}", config.require_hardware_mfa);

    println!("\nPassword Settings (IA-5):");
    println!("  password_min_length = {}", config.password_min_length);
    println!(
        "  password_check_breach_db = {}",
        config.password_check_breach_db
    );

    println!("\nLogin Security (AC-7):");
    println!("  max_login_attempts = {}", config.max_login_attempts);
    println!("  lockout_duration = {:?}", config.lockout_duration);

    println!("\nKey Management (SC-12):");
    println!(
        "  key_rotation_interval = {:?}",
        config.key_rotation_interval
    );

    println!("\nData Protection (SC-8, SC-28):");
    println!("  require_tls = {}", config.require_tls);
    println!("  require_mtls = {}", config.require_mtls);
    println!(
        "  require_encryption_at_rest = {}",
        config.require_encryption_at_rest
    );

    println!("\nMulti-tenancy:");
    println!(
        "  require_tenant_isolation = {}",
        config.require_tenant_isolation
    );

    println!("\nAudit (AU-11):");
    println!("  min_retention_days = {}", config.min_retention_days);

    // Generate TOML output
    println!("\n\n=== Generated barbican.toml ===\n");
    let toml = generator.generate_toml()?;
    println!("{}", toml);

    // Generate coverage report
    println!("\n=== Coverage Report ===\n");
    let report = generator.generate_coverage_report();
    println!("{}", report);

    Ok(())
}
