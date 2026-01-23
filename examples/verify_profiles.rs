//! Verify Barbican Profiles Against STIG Content
//!
//! This tool compares Barbican's hardcoded profile values against values derived
//! from official STIG content to identify discrepancies.
//!
//! # Usage
//!
//! ```bash
//! # With embedded sample data
//! cargo run --example verify_profiles --features stig
//!
//! # With real ComplianceAsCode content
//! git clone --depth 1 https://github.com/ComplianceAsCode/content.git /tmp/cac
//! cargo run --example verify_profiles --features stig -- \
//!     --content /tmp/cac \
//!     --product ubuntu2204 \
//!     --profile stig
//!
//! # CI mode (exit code 1 if discrepancies found)
//! cargo run --example verify_profiles --features stig -- --ci
//! ```
//!
//! # Purpose
//!
//! This is a **maintainer tool** for keeping Barbican's hardcoded profile values
//! in sync with official STIG requirements. Run this whenever:
//!
//! 1. A new STIG version is released (e.g., STIG V2R4 → V2R5)
//! 2. Before a Barbican release to verify profile accuracy
//! 3. When adding support for a new compliance framework
//!
//! # Understanding the Output
//!
//! - **Match**: Barbican's value equals the STIG value
//! - **STIG More Restrictive**: STIG requires stricter settings than Barbican
//!   (consider tightening Barbican's profile)
//! - **Profile More Restrictive**: Barbican is stricter than STIG
//!   (OK - exceeds requirements)

use barbican::compliance::stig::config_gen::{
    ProfileVerifier, StigConfigGenerator, StigProfile,
};
use barbican::compliance::ComplianceProfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.contains(&"--help".to_string()) {
        print_help();
        return Ok(());
    }

    let ci_mode = args.contains(&"--ci".to_string());

    // Parse arguments
    let content_path = get_arg(&args, "--content");
    let product = get_arg(&args, "--product").unwrap_or_else(|| "ubuntu2204".to_string());
    let profile_name = get_arg(&args, "--profile").unwrap_or_else(|| "stig".to_string());

    let mut generator = if let Some(content) = content_path {
        println!("Loading from ComplianceAsCode: {}", content);
        println!("Product: {}", product);
        println!("Profile: {}", profile_name);
        println!();

        StigConfigGenerator::new()
            .load_variables(&content)?
            .load_profiles_for_product(&content, &product)?
            .select_profile(&profile_name)?
    } else {
        println!("Using embedded sample STIG profile");
        println!("(Use --content to load real ComplianceAsCode data)");
        println!();

        let profile = StigProfile::from_yaml(sample_stig_profile(), "sample_stig".into())?;
        StigConfigGenerator::new().with_profile(profile)
    };

    // Verify against each FedRAMP profile
    let profiles = [
        ComplianceProfile::FedRampLow,
        ComplianceProfile::FedRampModerate,
        ComplianceProfile::FedRampHigh,
    ];

    let mut any_issues = false;

    for profile in profiles {
        let report = ProfileVerifier::verify(&mut generator, profile)?;

        if ci_mode {
            println!("{}", report.ci_summary());
            if !report.all_match() {
                any_issues = true;
            }
        } else {
            println!("{}", report);
            println!("{}", "=".repeat(60));
            println!();
        }
    }

    // Summary
    if ci_mode {
        if any_issues {
            println!();
            println!("⚠ Discrepancies found. Review and update profile.rs if needed.");
            std::process::exit(1);
        } else {
            println!();
            println!("✓ All profiles match STIG requirements.");
        }
    } else {
        println!();
        println!("Verification Complete");
        println!("=====================");
        println!();
        println!("What to do with discrepancies:");
        println!();
        println!("1. STIG More Restrictive:");
        println!("   - Review if Barbican's profile.rs should be updated");
        println!("   - Check if STIG changed in a recent revision");
        println!("   - Document any intentional deviations");
        println!();
        println!("2. Profile More Restrictive:");
        println!("   - Generally OK (exceeds minimum requirements)");
        println!("   - May indicate Barbican is ahead of STIG updates");
        println!();
        println!("3. To update profile.rs:");
        println!("   - Edit src/compliance/profile.rs");
        println!("   - Update the corresponding method (e.g., min_password_length())");
        println!("   - Add a comment referencing the STIG control ID");
    }

    Ok(())
}

fn print_help() {
    println!(
        r#"Verify Barbican Profiles Against STIG Content

USAGE:
    cargo run --example verify_profiles --features stig [OPTIONS]

OPTIONS:
    --content <path>    Path to ComplianceAsCode content directory
    --product <name>    Product name (default: ubuntu2204)
    --profile <name>    STIG profile name (default: stig)
    --ci                CI mode: exit 1 if discrepancies, minimal output
    --help              Show this help

EXAMPLES:
    # Quick check with sample data
    cargo run --example verify_profiles --features stig

    # Full verification against official content
    git clone --depth 1 https://github.com/ComplianceAsCode/content.git /tmp/cac
    cargo run --example verify_profiles --features stig -- \
        --content /tmp/cac \
        --product ubuntu2204 \
        --profile stig

    # CI pipeline usage
    cargo run --example verify_profiles --features stig -- --ci

STIG PROFILES AVAILABLE:
    Ubuntu 22.04: stig, stig_gui
    RHEL 9:       stig, stig_gui, cis, hipaa
    (varies by product)
"#
    );
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Sample STIG profile for testing without external dependencies
///
/// This represents typical STIG requirements. In production, load
/// real profiles from ComplianceAsCode content.
fn sample_stig_profile() -> &'static str {
    r#"
id: sample_stig
title: 'Sample STIG Profile (Ubuntu 22.04 STIG-like)'
description: |-
  Sample profile demonstrating typical STIG requirements.
  For accurate verification, use real ComplianceAsCode content.

selections:
  # Password policy (IA-5)
  # STIG typically requires 15 characters
  - var_password_pam_minlen=15

  # Account lockout (AC-7)
  # STIG requires lockout after 3 attempts, 15 minute lockout
  - var_accounts_passwords_pam_faillock_deny=3
  - var_accounts_passwords_pam_faillock_unlock_time=900

  # Session timeout (AC-11)
  # STIG typically requires 10 minute idle timeout
  - var_screensaver_lock_delay=600

  # Crypto policy (SC-8, SC-12)
  - var_system_crypto_policy=FIPS

  # Rules that indicate security features are required
  - enable_fips_mode
  - configure_crypto_policy
  - encrypt_partitions
  - smartcard_auth
"#
}
