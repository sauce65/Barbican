//! Example: Loading and querying STIG controls from ComplianceAsCode
//!
//! This example demonstrates how to:
//! 1. Load a STIG control file from ComplianceAsCode
//! 2. Query controls by NIST mapping
//! 3. Get statistics about STIG coverage
//!
//! To run this example:
//! 1. Clone ComplianceAsCode: git clone --depth 1 https://github.com/ComplianceAsCode/content.git
//! 2. Run: cargo run --example stig_loader --features stig

use barbican::compliance::stig::{StigLoader, StigSeverity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sample STIG control file content (Ubuntu 22.04 STIG excerpt)
    let yaml = r#"
policy: 'Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide (STIG)'
title: 'Canonical Ubuntu 22.04 LTS STIG'
id: stig_ubuntu2204
version: V2R3
source: https://www.cyber.mil/stigs/downloads/
reference_type: stigid
product: ubuntu2204

levels:
  - id: high
  - id: medium
  - id: low

controls:
  - id: UBTU-22-211015
    title: 'Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.'
    levels:
      - high
    rules:
      - disable_ctrlaltdel_reboot
    status: automated

  - id: UBTU-22-212010
    title: 'Ubuntu 22.04 LTS, when booted, must require authentication upon booting.'
    levels:
      - high
    rules:
      - grub2_password
      - grub2_uefi_password
    status: automated

  - id: UBTU-22-212015
    title: 'Ubuntu 22.04 LTS must initiate session audits at system startup.'
    levels:
      - medium
    rules:
      - grub2_audit_argument
    status: automated

  - id: UBTU-22-411045
    title: 'Ubuntu 22.04 LTS must enforce a minimum 15-character password length.'
    levels:
      - medium
    rules:
      - accounts_password_pam_minlen
    status: automated

  - id: UBTU-22-412020
    title: 'Ubuntu 22.04 LTS must lock an account after three unsuccessful login attempts.'
    levels:
      - medium
    rules:
      - accounts_passwords_pam_faillock_deny
    status: automated
"#;

    // Sample rule definitions with NIST mappings
    let rule_ctrlaltdel = r#"
documentation_complete: true
title: 'Disable Ctrl-Alt-Delete Reboot'
description: Prevent reboot via Ctrl-Alt-Delete key sequence
severity: high
references:
  nist: AC-6,CM-6
"#;

    let rule_password_minlen = r#"
documentation_complete: true
title: 'Set Password Minimum Length'
description: Enforce minimum password length
severity: medium
references:
  nist: IA-5(1)(a),IA-5(1)(h)
"#;

    let rule_faillock = r#"
documentation_complete: true
title: 'Lock Account After Failed Attempts'
description: Configure account lockout after failed login attempts
severity: medium
references:
  nist: AC-7(a),AC-7(b)
"#;

    // Load the STIG control file
    let mut loader = StigLoader::from_yaml(yaml)?;

    // Add rules to enable NIST mapping
    loader.add_rule(
        "disable_ctrlaltdel_reboot",
        barbican::compliance::stig::Rule::from_yaml(rule_ctrlaltdel)?,
    );
    loader.add_rule(
        "accounts_password_pam_minlen",
        barbican::compliance::stig::Rule::from_yaml(rule_password_minlen)?,
    );
    loader.add_rule(
        "accounts_passwords_pam_faillock_deny",
        barbican::compliance::stig::Rule::from_yaml(rule_faillock)?,
    );

    // Print statistics
    println!("STIG Loader Example");
    println!("===================\n");

    let stats = loader.stats();
    println!("{}", stats);

    // Query by severity
    println!("\nCAT I (High) Controls:");
    for mapping in loader.cat_i_controls() {
        println!("  {} - {}", mapping.stig_id, mapping.title);
    }

    println!("\nCAT II (Medium) Controls:");
    for mapping in loader.cat_ii_controls() {
        println!("  {} - {}", mapping.stig_id, mapping.title);
    }

    // Query by NIST control
    println!("\n\nControls mapping to AC-7 (Unsuccessful Logon Attempts):");
    for mapping in loader.controls_for_nist("AC-7") {
        println!(
            "  {} [{}] - {}",
            mapping.stig_id, mapping.severity, mapping.title
        );
    }

    println!("\nControls mapping to IA-5 (Authenticator Management):");
    for mapping in loader.controls_for_nist("IA-5") {
        println!(
            "  {} [{}] - {}",
            mapping.stig_id, mapping.severity, mapping.title
        );
    }

    // Show all covered NIST controls
    println!("\n\nNIST 800-53 Controls Covered:");
    let mut covered: Vec<_> = loader.covered_nist_controls().into_iter().collect();
    covered.sort();
    for ctrl in covered {
        println!("  {}", ctrl);
    }

    // Generate NIST mapping report
    println!("\n\nNIST Mapping Report:");
    let report = loader.nist_mapping_report();
    for (nist_id, entries) in &report.by_nist_control {
        println!("\n  {}:", nist_id);
        for entry in entries {
            let status = if entry.automated {
                "automated"
            } else {
                "manual"
            };
            println!("    - {} [{}] ({})", entry.stig_id, entry.severity, status);
        }
    }

    Ok(())
}
