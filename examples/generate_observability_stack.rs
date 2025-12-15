//! Example: Generate FedRAMP-compliant observability stack
//!
//! Run with: cargo run --example generate_observability_stack

use barbican::observability::stack::{
    ObservabilityStack,
    FedRampProfile,
    GrafanaSso,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "portcullis".to_string());

    let output_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "./observability-stack".to_string());

    println!("Generating FedRAMP Moderate observability stack for '{}'", app_name);
    println!("Output directory: {}", output_dir);
    println!();

    // Build the observability stack configuration
    let mut builder = ObservabilityStack::builder()
        .app_name(&app_name)
        .app_port(3443)
        .output_dir(&output_dir)
        .fedramp_profile(FedRampProfile::Moderate);

    // Optionally configure SSO
    // builder = builder.grafana(
    //     GrafanaConfig::default_for_profile(&FedRampProfile::Moderate)
    //         .with_sso(GrafanaSso {
    //             client_id: "grafana".to_string(),
    //             client_secret_env: "GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET".to_string(),
    //             auth_url: format!("https://{}.localhost:3443/authorize", app_name),
    //             token_url: format!("https://{}.localhost:3443/token", app_name),
    //             api_url: format!("https://{}.localhost:3443/userinfo", app_name),
    //             scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
    //             role_attribute_path: None,
    //             auto_login: true,
    //         })
    // );

    let stack = builder.build()?;

    // Validate configuration
    println!("Validating FedRAMP compliance...");
    let validation = stack.validate()?;
    validation.print_summary();
    println!();

    if !validation.passed {
        eprintln!("Warning: Validation failed, but continuing with generation...");
    }

    // Generate all configuration files
    println!("Generating configuration files...");
    let report = stack.generate()?;
    report.print_summary();

    println!();
    println!("Stack generation complete!");
    println!();
    println!("Next steps:");
    println!("  1. cd {}", output_dir);
    println!("  2. cp .env.example .env && edit .env with secure passwords");
    println!("  3. ./scripts/gen-certs.sh");
    println!("  4. docker-compose up -d");

    Ok(())
}
