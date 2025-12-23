//! Observability Stack Generator CLI
//!
//! Generates FedRAMP-compliant observability infrastructure configurations
//! for Prometheus, Loki, Grafana, and supporting components.
//!
//! # Usage
//!
//! ```bash
//! # Generate with defaults (FedRAMP Moderate)
//! generate_observability_stack --app-name myapp --app-port 8080 --output ./observability
//!
//! # Generate for FedRAMP High
//! generate_observability_stack --app-name myapp --app-port 8080 --output ./observability --profile fedramp-high
//!
//! # Validate only (no generation)
//! generate_observability_stack --app-name myapp --app-port 8080 --output ./observability --validate-only
//! ```

use barbican::compliance::ComplianceProfile;
use barbican::observability::stack::ObservabilityStack;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn print_usage(program: &str) {
    eprintln!(
        r#"Barbican Observability Stack Generator

Generate FedRAMP-compliant observability infrastructure (Prometheus, Loki, Grafana).

USAGE:
    {program} [OPTIONS]

REQUIRED OPTIONS:
    --app-name <NAME>       Application name (used for labels, service names)
    --app-port <PORT>       Application metrics port
    --output <DIR>          Output directory for generated configs

OPTIONAL:
    --profile <PROFILE>     Compliance profile (default: fedramp-moderate)
                            Values: fedramp-low, fedramp-moderate, fedramp-high, soc2
    --validate-only         Validate configuration without generating files
    --quiet                 Suppress output except errors
    --help, -h              Show this help message

EXAMPLES:
    # Generate for a typical web application
    {program} --app-name myapp --app-port 3000 --output ./observability

    # Generate for FedRAMP High compliance
    {program} --app-name myapp --app-port 8443 --output ./observability --profile fedramp-high

    # Validate existing configuration
    {program} --app-name myapp --app-port 8080 --output ./observability --validate-only

GENERATED FILES:
    loki/                   Loki configuration (log aggregation)
    prometheus/             Prometheus configuration (metrics)
    prometheus/rules/       Alert rules
    grafana/                Grafana configuration (dashboards)
    alertmanager/           Alertmanager configuration
    docker-compose.yml      Docker Compose orchestration
    scripts/                Management scripts
    docs/                   FedRAMP compliance documentation

NIST 800-53 CONTROLS:
    AU-2    Audit Events              AU-4    Audit Storage Capacity
    AU-6    Audit Review              AU-9    Protection of Audit Info
    CA-7    Continuous Monitoring     IR-4    Incident Handling
    IR-5    Incident Monitoring       SI-4    Information System Monitoring
"#,
        program = program
    );
}

fn parse_profile(s: &str) -> Option<ComplianceProfile> {
    match s.to_lowercase().as_str() {
        "fedramp-low" | "low" => Some(ComplianceProfile::FedRampLow),
        "fedramp-moderate" | "moderate" => Some(ComplianceProfile::FedRampModerate),
        "fedramp-high" | "high" => Some(ComplianceProfile::FedRampHigh),
        "soc2" => Some(ComplianceProfile::Soc2),
        _ => None,
    }
}

struct Args {
    app_name: String,
    app_port: u16,
    output: PathBuf,
    profile: ComplianceProfile,
    validate_only: bool,
    quiet: bool,
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    if args.len() == 1 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string())
    {
        print_usage(program);
        std::process::exit(0);
    }

    let mut app_name: Option<String> = None;
    let mut app_port: Option<u16> = None;
    let mut output: Option<PathBuf> = None;
    let mut profile = ComplianceProfile::FedRampModerate;
    let mut validate_only = false;
    let mut quiet = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--app-name" => {
                i += 1;
                if i >= args.len() {
                    return Err("--app-name requires a value".to_string());
                }
                app_name = Some(args[i].clone());
            }
            "--app-port" => {
                i += 1;
                if i >= args.len() {
                    return Err("--app-port requires a value".to_string());
                }
                app_port = Some(
                    args[i]
                        .parse()
                        .map_err(|_| format!("Invalid port: {}", args[i]))?,
                );
            }
            "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err("--output requires a value".to_string());
                }
                output = Some(PathBuf::from(&args[i]));
            }
            "--profile" => {
                i += 1;
                if i >= args.len() {
                    return Err("--profile requires a value".to_string());
                }
                profile = parse_profile(&args[i]).ok_or_else(|| {
                    format!(
                        "Invalid profile: {}. Use: fedramp-low, fedramp-moderate, fedramp-high, soc2",
                        args[i]
                    )
                })?;
            }
            "--validate-only" => {
                validate_only = true;
            }
            "--quiet" => {
                quiet = true;
            }
            arg => {
                return Err(format!("Unknown argument: {}", arg));
            }
        }
        i += 1;
    }

    let app_name = app_name.ok_or("--app-name is required")?;
    let app_port = app_port.ok_or("--app-port is required")?;
    let output = output.ok_or("--output is required")?;

    Ok(Args {
        app_name,
        app_port,
        output,
        profile,
        validate_only,
        quiet,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Run with --help for usage information.");
            return ExitCode::from(1);
        }
    };

    if !args.quiet {
        println!("==============================================");
        println!("  Barbican Observability Stack Generator");
        println!("  NIST 800-53 Compliant Infrastructure");
        println!("==============================================");
        println!();
        println!("Application:  {}", args.app_name);
        println!("Metrics Port: {}", args.app_port);
        println!("Output:       {}", args.output.display());
        println!("Profile:      {}", args.profile.name());
        println!();
    }

    // Build the stack
    let stack = match ObservabilityStack::builder()
        .app_name(&args.app_name)
        .app_port(args.app_port)
        .output_dir(&args.output)
        .compliance_profile(args.profile)
        .build()
    {
        Ok(stack) => stack,
        Err(e) => {
            eprintln!("Error building stack configuration: {}", e);
            return ExitCode::from(1);
        }
    };

    // Validate
    if !args.quiet {
        println!("Validating configuration...");
    }

    let validation = match stack.validate() {
        Ok(report) => report,
        Err(e) => {
            eprintln!("Error validating configuration: {}", e);
            return ExitCode::from(1);
        }
    };

    if !args.quiet {
        println!();
        validation.print_summary();
        println!();
    }

    if !validation.passed {
        eprintln!("Validation failed. Fix the issues above before generating.");
        return ExitCode::from(1);
    }

    if args.validate_only {
        if !args.quiet {
            println!("Validation passed. Use without --validate-only to generate files.");
        }
        return ExitCode::SUCCESS;
    }

    // Generate files
    if !args.quiet {
        println!("Generating observability stack...");
    }

    let report = match stack.generate() {
        Ok(report) => report,
        Err(e) => {
            eprintln!("Error generating files: {}", e);
            return ExitCode::from(1);
        }
    };

    if !args.quiet {
        println!();
        report.print_summary();
        println!();
        println!("==============================================");
        println!("  Generation Complete!");
        println!("==============================================");
        println!();
        println!("Next steps:");
        println!("  1. Review generated configurations in {}", args.output.display());
        println!("  2. Generate TLS certificates:");
        println!("       nix run .#vault-dev  # Start Vault PKI");
        println!("       nix run .#vault-cert-server prometheus");
        println!("       nix run .#vault-cert-server loki");
        println!("       nix run .#vault-cert-server grafana");
        println!("  3. Configure secrets in {}/secrets/", args.output.display());
        println!("  4. Start the stack:");
        println!("       cd {} && docker-compose up -d", args.output.display());
        println!();
        println!("Documentation: {}/docs/", args.output.display());
    }

    ExitCode::SUCCESS
}
