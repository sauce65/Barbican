//! Generate a Signed Compliance Test Report
//!
//! This example demonstrates how to generate an auditor-verifiable compliance
//! test report that proves NIST 800-53 control implementations behave correctly.
//!
//! # Usage
//!
//! ```bash
//! # Generate report to default directory
//! cargo run --example generate_compliance_report --features compliance-artifacts
//!
//! # Generate report to custom directory
//! cargo run --example generate_compliance_report --features compliance-artifacts -- --output-dir ./reports
//!
//! # Generate and sign the report
//! cargo run --example generate_compliance_report --features compliance-artifacts -- --sign
//!
//! # Use custom signing key from environment
//! COMPLIANCE_SIGNING_KEY=my-secret-key cargo run --example generate_compliance_report --features compliance-artifacts -- --sign
//! ```
//!
//! # Output
//!
//! The report is written as a JSON file with a timestamped filename:
//! `compliance_report_2025-12-17T15-30-00Z.json`
//!
//! # Report Contents
//!
//! The generated report includes:
//! - Schema version and metadata (Barbican version, Rust version)
//! - Compliance profile (e.g., "FedRAMP Moderate")
//! - Individual test artifacts for each control
//! - Summary statistics (pass/fail counts, pass rate)
//! - Optional HMAC-SHA256 signature for integrity verification

use std::path::PathBuf;

use barbican::compliance::{
    generate_compliance_report_for_profile, ComplianceProfile, ComplianceTestReport,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse command line arguments
    let output_dir = parse_arg(&args, "--output-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./compliance-artifacts"));

    let profile = parse_profile(&args)?;
    let should_sign = args.iter().any(|a| a == "--sign");
    let key_id = parse_arg(&args, "--key-id").unwrap_or_else(|| "default-key".to_string());
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");

    if show_help {
        print_help();
        return Ok(());
    }

    println!("Barbican Compliance Report Generator");
    println!("====================================\n");

    // Generate the compliance test report
    println!("Running compliance tests...\n");
    let mut report = generate_compliance_report_for_profile(profile);

    // Print summary
    print_summary(&report, verbose);

    // Sign if requested
    if should_sign {
        let key = get_signing_key()?;
        println!("\nSigning report with key '{}'...", key_id);
        report.sign(&key, &key_id)?;
        println!("  Signature algorithm: HMAC-SHA256");
        println!("  Signed at: {}", report.signature.as_ref().unwrap().signed_at);
    }

    // Create output directory
    std::fs::create_dir_all(&output_dir)?;

    // Write report to file
    let path = report.write_to_file(&output_dir)?;
    println!("\nReport written to: {}", path.display());

    // Print verification instructions if signed
    if should_sign {
        println!("\nTo verify the report signature:");
        println!("  1. Load the report JSON");
        println!("  2. Remove the 'signature' field");
        println!("  3. Compute HMAC-SHA256 over the compact JSON");
        println!("  4. Compare with the stored signature (base64 decoded)");
    }

    Ok(())
}

fn print_help() {
    println!(
        r#"Barbican Compliance Report Generator

Generate auditor-verifiable compliance test reports for NIST 800-53 controls.

USAGE:
    cargo run --example generate_compliance_report --features compliance-artifacts [OPTIONS]

OPTIONS:
    --profile <PROFILE>   Compliance profile: low, moderate, high, soc2 (default: moderate)
    --output-dir <DIR>    Output directory for the report (default: ./compliance-artifacts)
    --sign                Sign the report with HMAC-SHA256
    --key-id <ID>         Key identifier to include in signature (default: default-key)
    --verbose, -v         Show detailed test results
    --help, -h            Show this help message

PROFILES:
    low, fedramp-low      FedRAMP Low impact baseline
    moderate, fedramp-moderate   FedRAMP Moderate impact baseline (default)
    high, fedramp-high    FedRAMP High impact baseline
    soc2                  SOC 2 Type II baseline

ENVIRONMENT:
    COMPLIANCE_SIGNING_KEY    Secret key for signing (default: generates a warning)

EXAMPLES:
    # Generate FedRAMP High report
    cargo run --example generate_compliance_report --features compliance-artifacts \
        -- --profile high

    # Generate signed FedRAMP Moderate report
    COMPLIANCE_SIGNING_KEY=my-secret cargo run --example generate_compliance_report \
        --features compliance-artifacts -- --sign --key-id prod-2025

    # Custom output directory with verbose output
    cargo run --example generate_compliance_report --features compliance-artifacts \
        -- --output-dir ./reports --verbose --profile high
"#
    );
}

fn print_summary(report: &ComplianceTestReport, verbose: bool) {
    println!("Compliance Profile: {}", report.compliance_profile);
    println!("Barbican Version:   {}", report.barbican_version);
    println!("Generated At:       {}", report.generated_at);
    println!();

    println!("Test Results:");
    println!("  Total Controls:   {}", report.summary.total_controls);
    println!(
        "  Passed:           {} ({})",
        report.summary.passed,
        format_with_color(report.summary.passed, true)
    );
    println!(
        "  Failed:           {} ({})",
        report.summary.failed,
        format_with_color(report.summary.failed, false)
    );
    println!("  Pass Rate:        {:.1}%", report.summary.pass_rate);
    println!(
        "  Duration:         {}ms",
        report.summary.total_duration_ms
    );

    // Print by family
    println!("\nBy Control Family:");
    let mut families: Vec<_> = report.summary.by_family.iter().collect();
    families.sort_by_key(|(k, _)| *k);
    for (family, summary) in families {
        let status = if summary.failed == 0 { "PASS" } else { "FAIL" };
        println!(
            "  {}: {}/{} {}",
            family, summary.passed, summary.total, status
        );
    }

    if verbose {
        println!("\nDetailed Results:");
        for artifact in &report.artifacts {
            let status = if artifact.passed { "PASS" } else { "FAIL" };
            println!(
                "  [{}] {} - {}",
                status, artifact.control_id, artifact.control_name
            );
            println!("       Test: {}", artifact.test_name);
            println!("       Location: {}", artifact.code_location);
            println!("       Duration: {}ms", artifact.duration_ms);
            println!("       Evidence items: {}", artifact.evidence.len());
            if let Some(reason) = &artifact.failure_reason {
                println!("       Failure: {}", reason);
            }
        }
    }

    // Print failed tests if any
    if report.summary.failed > 0 {
        println!("\nFailed Controls:");
        for artifact in report.failed_artifacts() {
            println!("  {} - {}", artifact.control_id, artifact.control_name);
            if let Some(reason) = &artifact.failure_reason {
                println!("    Reason: {}", reason);
            }
        }
    }
}

fn format_with_color(count: usize, is_good: bool) -> &'static str {
    if is_good && count > 0 {
        "green"
    } else if !is_good && count > 0 {
        "red"
    } else {
        "none"
    }
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn get_signing_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match std::env::var("COMPLIANCE_SIGNING_KEY") {
        Ok(key) => Ok(key.into_bytes()),
        Err(_) => {
            eprintln!("WARNING: No COMPLIANCE_SIGNING_KEY environment variable set.");
            eprintln!("         Using default development key. DO NOT use in production!\n");
            Ok(b"barbican-default-development-signing-key-not-for-production".to_vec())
        }
    }
}

fn parse_profile(args: &[String]) -> Result<ComplianceProfile, Box<dyn std::error::Error>> {
    let profile_str = parse_arg(args, "--profile").unwrap_or_else(|| "moderate".to_string());

    match profile_str.to_lowercase().as_str() {
        "low" | "fedramp-low" => Ok(ComplianceProfile::FedRampLow),
        "moderate" | "fedramp-moderate" => Ok(ComplianceProfile::FedRampModerate),
        "high" | "fedramp-high" => Ok(ComplianceProfile::FedRampHigh),
        "soc2" | "soc-2" => Ok(ComplianceProfile::Soc2),
        "custom" => Ok(ComplianceProfile::Custom),
        other => Err(format!(
            "Unknown profile '{}'. Valid profiles: low, moderate, high, soc2",
            other
        )
        .into()),
    }
}
