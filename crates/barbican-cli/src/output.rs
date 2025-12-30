//! Output formatting and display utilities
//!
//! Provides colored, formatted output for the CLI

use colored::Colorize;
use std::io::Write;

use crate::profile::ProfileRequirement;
use crate::validate::ValidationResult;

/// Print a success message
pub fn success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

/// Print an error message
pub fn error(msg: &str) {
    eprintln!("{} {}", "✗".red().bold(), msg);
}

/// Print a warning message
pub fn warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg);
}

/// Print an info message
pub fn info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), msg);
}

/// Print a header
pub fn header(msg: &str) {
    println!("\n{}", msg.bold().underline());
}

/// Print a subheader
pub fn subheader(msg: &str) {
    println!("\n{}", msg.bold());
}

/// Print validation results in a nice format
pub fn print_validation_result(result: &ValidationResult) {
    header(&format!("Validation: {}", result.profile.name()));

    // Summary line
    if result.passed {
        success(&format!(
            "All {} requirements satisfied",
            result.requirements.len()
        ));
    } else {
        error(&format!(
            "{} errors, {} warnings",
            result.error_count, result.warning_count
        ));
    }

    println!();

    // Group by status
    let satisfied: Vec<_> = result.satisfied().into_iter().collect();
    let failures: Vec<_> = result.failures().into_iter().collect();
    let warnings: Vec<_> = result.warnings().into_iter().collect();

    // Print failures first
    if !failures.is_empty() {
        subheader("Failures (must fix):");
        for req in failures {
            print_requirement(req, RequirementStatus::Failed);
        }
    }

    // Print warnings
    if !warnings.is_empty() {
        subheader("Warnings (recommended):");
        for req in warnings {
            print_requirement(req, RequirementStatus::Warning);
        }
    }

    // Print satisfied (condensed)
    if !satisfied.is_empty() {
        subheader("Satisfied:");
        for req in satisfied {
            print_requirement(req, RequirementStatus::Satisfied);
        }
    }

    println!();
}

enum RequirementStatus {
    Satisfied,
    Failed,
    Warning,
}

fn print_requirement(req: &ProfileRequirement, status: RequirementStatus) {
    let icon = match status {
        RequirementStatus::Satisfied => "✓".green(),
        RequirementStatus::Failed => "✗".red(),
        RequirementStatus::Warning => "⚠".yellow(),
    };

    let control = format!("[{}]", req.control).dimmed();
    let name = match status {
        RequirementStatus::Satisfied => req.name.green(),
        RequirementStatus::Failed => req.name.red(),
        RequirementStatus::Warning => req.name.yellow(),
    };

    println!("  {} {} {}", icon, control, name);
    println!("    {}", req.description.dimmed());
}

/// Print generated files
pub fn print_generated_files(files: &[crate::generate::GeneratedFile], output_dir: &std::path::Path) {
    subheader("Generated files:");

    for file in files {
        let full_path = output_dir.join(&file.path);
        let icon = "→".cyan();
        println!("  {} {}", icon, full_path.display());
    }
}

/// Print drift detection results
pub fn print_drift(drifted: &[String]) {
    if drifted.is_empty() {
        success("No drift detected - generated files are in sync");
    } else {
        warning(&format!("{} file(s) have drifted:", drifted.len()));
        for file in drifted {
            println!("  {} {}", "↔".yellow(), file);
        }
        println!();
        info("Run 'barbican build' to regenerate");
    }
}

/// Print a progress spinner for long operations
pub struct Spinner {
    pb: indicatif::ProgressBar,
}

impl Spinner {
    pub fn new(msg: &str) -> Self {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(msg.to_string());
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Self { pb }
    }

    pub fn finish_success(self, msg: &str) {
        self.pb.finish_and_clear();
        success(msg);
    }

    pub fn finish_error(self, msg: &str) {
        self.pb.finish_and_clear();
        error(msg);
    }
}

/// Format a duration in human-readable form
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// Print the CLI banner
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "{}",
        format!("Barbican CLI v{}", version).bold()
    );
    println!("{}", "NIST 800-53 Compliance Configuration Tool".dimmed());
}

/// Print a JSON report
pub fn print_json<T: serde::Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{}", json);
    Ok(())
}

/// Print help for the validate command
pub fn print_validate_help() {
    println!(
        r#"
{}

Validates your barbican.toml against the selected compliance profile.

{}
  barbican validate                 # Validate barbican.toml in current directory
  barbican validate -c config.toml  # Validate specific config file
  barbican validate --strict        # Fail on warnings too
  barbican validate --json          # Output as JSON

{}
  fedramp-low       FedRAMP Low impact baseline (~125 controls)
  fedramp-moderate  FedRAMP Moderate impact baseline (~325 controls)
  fedramp-high      FedRAMP High impact baseline (~421 controls)
  soc2              SOC 2 Type II baseline (~64 criteria)
"#,
        "Validate Configuration".bold(),
        "Examples:".bold(),
        "Profiles:".bold(),
    );
}
