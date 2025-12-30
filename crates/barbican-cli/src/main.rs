//! Barbican CLI - Configuration management and code generation tool
//!
//! This tool manages barbican.toml configurations, validates them against
//! compliance profiles, and generates Nix and Rust configuration code.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

mod config;
mod error;
mod generate;
mod output;
mod profile;
mod validate;

use config::BarbicanConfig;
use error::{CliError, Result};

/// Barbican CLI - NIST 800-53 Compliance Configuration Tool
#[derive(Parser)]
#[command(name = "barbican")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Path to barbican.toml configuration file
    #[arg(short, long, default_value = "barbican.toml", global = true)]
    config: PathBuf,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate configuration against compliance profile
    Validate {
        /// Treat warnings as errors
        #[arg(short, long)]
        strict: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Check deployed configuration for drift
        #[arg(long)]
        check_deployed: bool,
    },

    /// Generate configuration files
    Generate {
        /// What to generate: all, nix, rust
        #[arg(default_value = "all")]
        target: String,

        /// Output directory
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Don't write files, just print what would be generated
        #[arg(long)]
        dry_run: bool,
    },

    /// Validate and generate all outputs
    Build {
        /// Treat warnings as errors
        #[arg(short, long)]
        strict: bool,

        /// Output directory
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Check for drift between config and generated files
    Drift {
        /// Output directory to check
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Initialize a new barbican.toml
    Init {
        /// Compliance profile to use
        #[arg(short, long, default_value = "fedramp-moderate")]
        profile: String,

        /// Application name
        #[arg(short, long)]
        name: Option<String>,

        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,
    },

    /// Show information about a compliance profile
    Profile {
        /// Profile to show: fedramp-low, fedramp-moderate, fedramp-high, soc2
        #[arg(default_value = "fedramp-moderate")]
        name: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Validate {
            strict,
            json,
            check_deployed,
        } => cmd_validate(&cli.config, strict, json, check_deployed),

        Commands::Generate {
            target,
            output,
            dry_run,
        } => cmd_generate(&cli.config, &target, output, dry_run),

        Commands::Build { strict, output } => cmd_build(&cli.config, strict, output),

        Commands::Drift { output } => cmd_drift(&cli.config, output),

        Commands::Init {
            profile,
            name,
            force,
        } => cmd_init(&cli.config, &profile, name, force),

        Commands::Profile { name, json } => cmd_profile(&name, json),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            output::error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

// =============================================================================
// Command Implementations
// =============================================================================

fn cmd_validate(config_path: &PathBuf, strict: bool, json: bool, check_deployed: bool) -> Result<()> {
    // Load and parse config
    if !config_path.exists() {
        return Err(CliError::ConfigNotFound {
            path: config_path.clone(),
        });
    }

    let mut config = BarbicanConfig::from_file(config_path)?;
    config.resolve_defaults();

    // Validate
    let result = validate::validate_config(&config)?;

    if json {
        // JSON output for CI/CD
        let report = serde_json::json!({
            "profile": result.profile.name(),
            "passed": result.passed,
            "error_count": result.error_count,
            "warning_count": result.warning_count,
            "requirements": result.requirements.iter().map(|r| {
                serde_json::json!({
                    "control": r.control,
                    "name": r.name,
                    "required": r.required,
                    "satisfied": r.satisfied,
                    "description": r.description,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        output::print_validation_result(&result);
    }

    // Check for drift if requested
    if check_deployed {
        let output_dir = PathBuf::from(&config.deployment.output_dir);
        let drifted = generate::check_drift(&config, &output_dir)?;
        if !drifted.is_empty() {
            output::print_drift(&drifted);
            if strict {
                return Err(CliError::DriftDetected);
            }
        }
    }

    // Determine exit status
    if !result.passed {
        return Err(CliError::MultipleValidationFailures {
            count: result.error_count,
        });
    }

    if strict && result.warning_count > 0 {
        return Err(CliError::MultipleValidationFailures {
            count: result.warning_count,
        });
    }

    Ok(())
}

fn cmd_generate(config_path: &PathBuf, target: &str, output: Option<PathBuf>, dry_run: bool) -> Result<()> {
    // Load and parse config
    let mut config = BarbicanConfig::from_file(config_path)?;
    config.resolve_defaults();

    let output_dir = output.unwrap_or_else(|| PathBuf::from(&config.deployment.output_dir));

    output::info(&format!("Generating {} configuration...", target));

    let files = match target {
        "all" => {
            let mut all = generate::nix::generate(&config)?;
            all.extend(generate::rust::generate(&config)?);
            all
        }
        "nix" => generate::nix::generate(&config)?,
        "rust" => generate::rust::generate(&config)?,
        _ => {
            return Err(CliError::InvalidValue {
                field: "target".to_string(),
                message: format!("Unknown target: {}. Use 'all', 'nix', or 'rust'", target),
            });
        }
    };

    if dry_run {
        output::subheader("Would generate:");
        for file in &files {
            println!("\n{}", "─".repeat(60));
            println!("{}", file.path);
            println!("{}", "─".repeat(60));
            println!("{}", file.content);
        }
    } else {
        // Create output directory
        std::fs::create_dir_all(&output_dir).map_err(|e| CliError::OutputDirCreation {
            path: output_dir.clone(),
            source: e,
        })?;

        // Write files
        for file in &files {
            file.write(&output_dir)?;
        }

        output::print_generated_files(&files, &output_dir);
        output::success(&format!("Generated {} file(s)", files.len()));
    }

    Ok(())
}

fn cmd_build(config_path: &PathBuf, strict: bool, output: Option<PathBuf>) -> Result<()> {
    output::print_banner();
    println!();

    // Step 1: Validate
    output::info("Validating configuration...");

    let mut config = BarbicanConfig::from_file(config_path)?;
    config.resolve_defaults();

    let result = validate::validate_config(&config)?;
    output::print_validation_result(&result);

    if !result.passed {
        return Err(CliError::MultipleValidationFailures {
            count: result.error_count,
        });
    }

    if strict && result.warning_count > 0 {
        output::error("Strict mode: warnings treated as errors");
        return Err(CliError::MultipleValidationFailures {
            count: result.warning_count,
        });
    }

    // Step 2: Generate
    let output_dir = output.unwrap_or_else(|| PathBuf::from(&config.deployment.output_dir));

    output::info("Generating configuration files...");

    std::fs::create_dir_all(&output_dir).map_err(|e| CliError::OutputDirCreation {
        path: output_dir.clone(),
        source: e,
    })?;

    let gen_result = generate::generate_all(&config, &output_dir)?;
    output::print_generated_files(&gen_result.files, &output_dir);

    // Summary
    println!();
    output::success(&format!(
        "Build complete: {} validated, {} files generated",
        config.profile().name(),
        gen_result.files.len()
    ));

    Ok(())
}

fn cmd_drift(config_path: &PathBuf, output: Option<PathBuf>) -> Result<()> {
    let mut config = BarbicanConfig::from_file(config_path)?;
    config.resolve_defaults();

    let output_dir = output.unwrap_or_else(|| PathBuf::from(&config.deployment.output_dir));

    output::info(&format!(
        "Checking drift against {}...",
        output_dir.display()
    ));

    let drifted = generate::check_drift(&config, &output_dir)?;
    output::print_drift(&drifted);

    if !drifted.is_empty() {
        Err(CliError::DriftDetected)
    } else {
        Ok(())
    }
}

fn cmd_init(config_path: &PathBuf, profile: &str, name: Option<String>, force: bool) -> Result<()> {
    if config_path.exists() && !force {
        return Err(CliError::ValidationFailed {
            message: format!(
                "{} already exists. Use --force to overwrite.",
                config_path.display()
            ),
        });
    }

    // Validate profile
    let profile_enum = profile::ComplianceProfile::parse(profile).ok_or_else(|| {
        CliError::InvalidProfile {
            profile: profile.to_string(),
        }
    })?;

    let app_name = name.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my-app".to_string())
    });

    let template = generate_init_template(&app_name, profile_enum);

    std::fs::write(config_path, &template)?;

    output::success(&format!("Created {}", config_path.display()));
    output::info(&format!("Profile: {}", profile_enum.name()));
    output::info("Edit the configuration and run 'barbican build' to generate files");

    Ok(())
}

fn cmd_profile(name: &str, json: bool) -> Result<()> {
    let profile = profile::ComplianceProfile::parse(name).ok_or_else(|| CliError::InvalidProfile {
        profile: name.to_string(),
    })?;

    if json {
        let info = serde_json::json!({
            "name": profile.name(),
            "config_name": profile.config_name(),
            "framework": profile.framework(),
            "requirements": {
                "session_timeout_minutes": profile.session_timeout_minutes(),
                "idle_timeout_minutes": profile.idle_timeout_minutes(),
                "max_login_attempts": profile.max_login_attempts(),
                "lockout_duration_minutes": profile.lockout_duration_minutes(),
                "min_password_length": profile.min_password_length(),
                "min_retention_days": profile.min_retention_days(),
                "key_rotation_days": profile.key_rotation_days(),
                "requires_mfa": profile.requires_mfa(),
                "requires_mtls": profile.requires_mtls(),
                "requires_encryption_at_rest": profile.requires_encryption_at_rest(),
                "requires_egress_filtering": profile.requires_egress_filtering(),
                "requires_breach_checking": profile.requires_breach_checking(),
            },
            "applicable_controls": profile.applicable_control_count(),
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        output::header(&format!("Profile: {}", profile.name()));
        println!("Framework: {}", profile.framework());
        println!("Applicable Controls: ~{}", profile.applicable_control_count());

        output::subheader("Session Management (AC-11, AC-12):");
        println!("  Session Timeout: {} minutes", profile.session_timeout_minutes());
        println!("  Idle Timeout: {} minutes", profile.idle_timeout_minutes());

        output::subheader("Authentication (IA-2, AC-7):");
        println!("  MFA Required: {}", profile.requires_mfa());
        println!("  Max Login Attempts: {}", profile.max_login_attempts());
        println!("  Lockout Duration: {} minutes", profile.lockout_duration_minutes());
        println!("  Min Password Length: {} characters", profile.min_password_length());
        println!("  Breach Checking: {}", profile.requires_breach_checking());

        output::subheader("Data Protection (SC-8, SC-28, SC-12):");
        println!("  TLS Required: true");
        println!("  mTLS Required: {}", profile.requires_mtls());
        println!("  Encryption at Rest: {}", profile.requires_encryption_at_rest());
        println!("  Key Rotation: {} days", profile.key_rotation_days());

        output::subheader("Network Security (SC-7):");
        println!("  Egress Filtering: {}", profile.requires_egress_filtering());

        output::subheader("Audit (AU-11):");
        println!("  Min Log Retention: {} days", profile.min_retention_days());
    }

    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

fn generate_init_template(app_name: &str, profile: profile::ComplianceProfile) -> String {
    format!(
        r#"# Barbican Configuration
# Profile: {}
# Documentation: https://github.com/yourorg/barbican

[app]
name = "{}"
profile = "{}"
version = "0.1.0"

[deployment]
platform = "nixos"
output_dir = "generated"

# Database Configuration
# Uncomment and configure for your database
# [database]
# type = "postgres"
# url = "${{DATABASE_URL}}"
# pool_size = 10
# statement_timeout = "30s"
# allowed_clients = ["10.0.0.0/8"]

# Observability Configuration
[observability]
metrics = "prometheus"
logging = "loki"
tracing = true
# retention_days = {}  # Derived from profile

# Network Configuration
# Uncomment and configure your firewall rules
# [network]
# listen = "0.0.0.0:8080"
# egress_filtering = {}
#
# [[network.allowed_ingress]]
# port = 8080
# from = "10.0.0.0/8"
# proto = "tcp"

# Secrets Configuration
# Uncomment for Vault integration
# [secrets]
# provider = "vault"
# address = "${{VAULT_ADDR}}"

# Backup Configuration
# Uncomment for database backups
# [backup]
# enabled = true
# schedule = "02:00"
# retention_days = 30
# encryption = {}
"#,
        profile.name(),
        app_name,
        profile.config_name(),
        profile.min_retention_days(),
        profile.requires_egress_filtering(),
        profile.requires_encryption_at_rest(),
    )
}
