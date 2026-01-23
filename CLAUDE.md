# Barbican - LLM Context Guide

This document provides context for AI assistants working with the Barbican codebase.

## What is Barbican?

Barbican is a **security-focused infrastructure library** for Rust/Axum web applications that implements NIST SP 800-53 Rev 5 controls. It provides:

1. **Rust middleware and utilities** for application-level security
2. **NixOS modules** for infrastructure-level security
3. **CLI tool** for generating configuration from `barbican.toml`

The goal is **FedRAMP compliance** (Low/Moderate/High profiles) through secure-by-default components.

## Repository Structure

```
barbican/
├── src/                          # Main Rust library
│   ├── lib.rs                    # Library entry point, module exports
│   ├── prelude.rs                # Convenience re-exports
│   ├── auth.rs                   # OAuth/OIDC JWT validation (AC-2, IA-2)
│   ├── session.rs                # Session management (AC-11, AC-12)
│   ├── login.rs                  # Brute force protection (AC-7)
│   ├── password.rs               # NIST 800-63B validation (IA-5)
│   ├── validation.rs             # Input validation, XSS/SQLi prevention (SI-10)
│   ├── encryption.rs             # AES-256-GCM field encryption (SC-28)
│   ├── tls.rs                    # TLS enforcement, mTLS (SC-8)
│   ├── layers.rs                 # Security headers, CORS, rate limiting
│   ├── config.rs                 # Configuration types and loading
│   ├── error.rs                  # Secure error handling (SI-11)
│   ├── keys.rs                   # Cryptographic key management (SC-12)
│   ├── secrets.rs                # Secret detection for CI/CD (IA-5(7))
│   ├── health.rs                 # Health check framework (CA-7)
│   ├── alerting.rs               # Incident alerting (IR-4, IR-5)
│   ├── testing.rs                # Security test utilities (SA-11)
│   ├── supply_chain.rs           # SBOM generation, vuln scanning (SR-3/4)
│   ├── crypto.rs                 # Constant-time comparison utilities
│   ├── database.rs               # Database connection handling
│   ├── parse.rs                  # Parsing utilities
│   ├── rate_limit.rs             # Tiered rate limiting
│   ├── integration.rs            # Integration tests
│   ├── jwt_secret.rs             # JWT secret handling
│   ├── audit/                    # Audit logging subsystem
│   │   ├── mod.rs                # Audit middleware and events (AU-2/3/12)
│   │   └── integrity.rs          # HMAC chain for tamper detection (AU-9)
│   ├── compliance/               # Compliance profile system
│   │   ├── mod.rs                # Profile exports
│   │   ├── profile.rs            # FedRAMP profile definitions
│   │   └── stig/                 # STIG/ComplianceAsCode integration
│   │       ├── mod.rs            # STIG module exports
│   │       ├── loader.rs         # STIG YAML loader
│   │       ├── control.rs        # Control definitions
│   │       ├── rule.rs           # Rule parsing
│   │       ├── types.rs          # NIST control types
│   │       ├── validator.rs      # STIG compliance validation
│   │       └── config_gen/       # Configuration generation from STIG
│   │           ├── mod.rs        # Config gen exports
│   │           ├── generator.rs  # Main generator pipeline
│   │           ├── variable.rs   # Variable definition parser
│   │           ├── profile_parser.rs # Profile parser
│   │           ├── registry.rs   # NIST → Barbican mapping
│   │           ├── verify.rs     # Profile verification
│   │           ├── toml_writer.rs # TOML output
│   │           └── error.rs      # Error types
│   └── observability/            # Logging/metrics subsystem
│       └── mod.rs                # Loki, OTLP, Prometheus integration
│
├── crates/
│   └── barbican-cli/             # CLI tool for code generation
│       └── src/
│           ├── main.rs           # CLI entry point
│           ├── lib.rs            # Library interface
│           ├── config.rs         # TOML config parsing
│           └── generate/
│               ├── mod.rs        # Generator exports
│               ├── rust.rs       # Rust config generator
│               └── nix.rs        # NixOS module generator
│
├── nix/
│   ├── modules/                  # NixOS security modules
│   │   ├── default.nix           # Module exports
│   │   ├── secure-users.nix      # User hardening (AC-2, AC-6)
│   │   ├── secure-postgres.nix   # Hardened PostgreSQL (IA-5(2), SC-8)
│   │   ├── hardened-ssh.nix      # SSH hardening (AC-7)
│   │   ├── hardened-nginx.nix    # Nginx hardening (SC-8, CM-6)
│   │   ├── secrets-management.nix# Age encryption (IA-5)
│   │   ├── observability.nix     # Loki/Prometheus/Grafana (SI-4, AU-6)
│   │   ├── observability-auth.nix# Grafana/Prometheus auth (IA-2, AC-3)
│   │   ├── vm-firewall.nix       # iptables with egress filtering (SC-7)
│   │   ├── database-backup.nix   # Encrypted backups (CP-9)
│   │   ├── resource-limits.nix   # Memory/CPU quotas (SC-6)
│   │   ├── kernel-hardening.nix  # Kernel sysctl hardening (SI-16)
│   │   ├── time-sync.nix         # NTP configuration (AU-8)
│   │   ├── intrusion-detection.nix # AIDE + auditd (SI-4, SI-7)
│   │   ├── systemd-hardening.nix # Process isolation (AC-6, SC-39)
│   │   ├── vault-pki.nix         # Certificate management (SC-12, SC-17)
│   │   ├── doctor.nix            # Diagnostic health checks (CM-4, SI-6)
│   │   └── oidc-provider.nix     # Keycloak OIDC setup (IA-2, AC-2)
│   ├── tests/                    # NixOS VM tests
│   ├── lib/                      # Nix library functions
│   │   ├── network-zones.nix     # Network segmentation helpers
│   │   ├── pki.nix               # Certificate generation scripts
│   │   └── systemd-hardening-lib.nix # Systemd hardening helpers
│   ├── profiles/                 # FedRAMP security profiles (align with Rust ComplianceProfile)
│   │   ├── development.nix       # Local dev only (no hardening)
│   │   ├── fedramp-low.nix       # FedRAMP Low baseline
│   │   ├── fedramp-moderate.nix  # FedRAMP Moderate baseline (most common)
│   │   └── fedramp-high.nix      # FedRAMP High baseline (maximum security)
│   ├── apps.nix                  # Flake apps (audit, vault-*, observability-*)
│   ├── checks.nix                # Security checks and VM tests
│   ├── package.nix               # Package definitions
│   └── devshell.nix              # Development shell
│
├── examples/
│   ├── fedramp-low/              # FedRAMP Low example
│   ├── fedramp-moderate/         # FedRAMP Moderate example
│   └── fedramp-high/             # FedRAMP High example
│       ├── barbican.toml         # Security configuration
│       ├── Cargo.toml            # Rust dependencies
│       ├── flake.nix             # NixOS deployment
│       ├── src/
│       │   ├── main.rs           # Application code
│       │   └── generated/        # Generated Rust config
│       ├── nix/
│       │   └── generated/        # Generated NixOS config
│       └── secrets/              # Age-encrypted secrets
│
├── flake.nix                     # Main Nix flake
├── Cargo.toml                    # Workspace manifest
└── docs/
    ├── AUDIT_GUIDE.md            # Compliance audit guide
    └── STIG_TRACEABILITY.md      # STIG rule to implementation mapping
```

## Design Philosophy

### 1. Single Source of Truth

`barbican.toml` is the central configuration file. The CLI generates both Rust and NixOS configuration from it:

```
barbican.toml
     │
     ├─► barbican generate rust ─► src/generated/barbican_config.rs
     │
     └─► barbican generate nix  ─► nix/generated/barbican.nix
```

### 2. Profile-Driven Defaults

When you set `profile = "fedramp-moderate"` in `barbican.toml`, all controls default to FedRAMP Moderate requirements. You override only what differs.

### 3. Secure by Default

All components are configured for maximum security. Users opt-out of protections, never opt-in. For example:
- Rate limiting is on by default
- Security headers are applied automatically
- TLS is required, not optional

### 4. Layer Separation

- **Application layer** (Rust): auth, validation, encryption, session management
- **Infrastructure layer** (NixOS): firewall, kernel hardening, PostgreSQL, SSH

## STIG Traceability

Barbican maps all security controls to official STIG rule IDs for audit compliance:

| STIG | Version | Scope |
|------|---------|-------|
| Ubuntu 22.04 LTS STIG | V2R3 | OS-level security (UBTU-22-*) |
| PostgreSQL 15 STIG | V2R6 | Database security (PGS15-00-*) |
| Application Security STIG | V5R3 | Application security (APSC-DV-*) |
| CIS Nginx Benchmark | 2.0 | Reverse proxy (CIS-NGINX-*) |

See `docs/STIG_TRACEABILITY.md` for the complete mapping matrix.

### Programmatic Access

```rust
use barbican::compliance::stig::mappings::{get_rule, rules_for_nist};

// Look up a STIG rule
if let Some(rule) = get_rule("UBTU-22-411045") {
    println!("{}: {}", rule.id, rule.title);
}

// Find rules for a NIST control
let ac7_rules = rules_for_nist("AC-7");
```

### BarbicanParam STIG Mappings

Each configuration parameter includes STIG traceability:

```rust
use barbican::compliance::stig::config_gen::BarbicanParam;

let param = BarbicanParam::MaxLoginAttempts;
let rules = param.stig_rules(); // ["UBTU-22-411045", "APSC-DV-000210"]
```

## Key Patterns

### Axum Router Extension Trait

The `SecureRouter` trait extends `axum::Router`:

```rust
use barbican::prelude::*;

let app = Router::new()
    .route("/", get(handler))
    .with_security_headers()      // HSTS, CSP, X-Frame-Options
    .with_rate_limiting(100, 10)  // 100/sec, burst 10
    .with_request_timeout(Duration::from_secs(30))
    .with_body_limit(1024 * 1024);
```

### Profile-Based Configuration

Each module has `::fedramp_low()`, `::fedramp_moderate()`, `::fedramp_high()` constructors:

```rust
let session_policy = SessionPolicy::fedramp_moderate(); // 15 min session, 15 min idle
let password_policy = PasswordPolicy::fedramp_moderate(); // 15 char min (STIG)
let lockout_policy = LockoutPolicy::fedramp_moderate(); // 3 attempts, 30 min
```

Profile values are derived from NIST 800-53 Rev 5 and DISA STIGs:

| Profile | Session | Idle | Password | Attempts | Lockout |
|---------|---------|------|----------|----------|---------|
| Low | 30m | 15m | 8 | 3 | 30m |
| Moderate | 15m | 15m | 15 | 3 | 30m |
| High | 10m | 10m | 15 | 3 | 3h |

### NixOS Module Options

Modules use the `barbican.*` namespace:

```nix
{
  barbican.securePostgres = {
    enable = true;
    enableClientCert = true;
    databases = [ "myapp" ];
  };

  barbican.vmFirewall = {
    enableEgressFiltering = true;
    allowedInbound = [
      { port = 443; protocol = "tcp"; }
    ];
  };
}
```

## CLI Tool

Location: `crates/barbican-cli/`

### Commands

```bash
barbican generate rust  # Generate src/generated/barbican_config.rs
barbican generate nix   # Generate nix/generated/barbican.nix
barbican validate       # Validate barbican.toml
barbican show-config    # Show effective configuration
```

### Configuration Format

```toml
[app]
name = "my-app"
profile = "fedramp-moderate"  # or fedramp-low, fedramp-high

[database]
enable = true
name = "my_db"
require_ssl = true
enable_client_cert = true

[session]
session_timeout_minutes = 15
idle_timeout_minutes = 10

[auth]
require_mfa = true
jwt_issuer = "https://auth.example.com"

[firewall]
allowed_inbound = [
    { port = 443, protocol = "tcp", source = "0.0.0.0/0" }
]
enable_egress_filtering = true

[rate_limit]
requests_per_second = 100
burst = 10
```

## NixOS Integration

### Flake Structure

Example flakes import barbican modules:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    barbican.url = "path:../..";  # or github:Sauce65/barbican
  };

  outputs = { nixpkgs, barbican, ... }: {
    nixosConfigurations.myvm = nixpkgs.lib.nixosSystem {
      modules = [
        barbican.nixosModules.all     # Import all barbican modules
        ./nix/generated/barbican.nix  # Generated configuration
      ];
    };
  };
}
```

### Module Loading

`barbican.nixosModules.all` imports all modules. Individual modules use camelCase:

```nix
barbican.nixosModules.secureUsers
barbican.nixosModules.securePostgres
barbican.nixosModules.hardenedSSH
barbican.nixosModules.hardenedNginx
barbican.nixosModules.secretsManagement
barbican.nixosModules.observability
barbican.nixosModules.observabilityAuth
barbican.nixosModules.vmFirewall
barbican.nixosModules.databaseBackup
barbican.nixosModules.resourceLimits
barbican.nixosModules.kernelHardening
barbican.nixosModules.timeSync
barbican.nixosModules.intrusionDetection
barbican.nixosModules.systemdHardening
barbican.nixosModules.vaultPki
barbican.nixosModules.doctor
barbican.nixosModules.oidcProvider
barbican.nixosModules.usbProtection
barbican.nixosModules.mandatoryAccessControl
```

### FedRAMP Security Profiles

Pre-configured profiles aligned with Rust `ComplianceProfile` enum:
- `barbican.nixosModules.development` - Local development only (no hardening)
- `barbican.nixosModules.fedrampLow` - FedRAMP Low baseline (limited impact)
- `barbican.nixosModules.fedrampModerate` - FedRAMP Moderate baseline (most common)
- `barbican.nixosModules.fedrampHigh` - FedRAMP High baseline (maximum security)

Each profile automatically sets `BARBICAN_COMPLIANCE_PROFILE` environment variable
so Rust `*_for_profile()` functions return matching policies.

### Library Functions

```nix
barbican.lib.networkZones  # Network segmentation helpers
barbican.lib.pki           # Certificate generation scripts
barbican.lib.systemdHardening # Systemd hardening helpers
```

### Flake Apps

```bash
nix run .#audit              # Run security audit
nix run .#vault-dev          # Start Vault dev server
nix run .#vault-cert-server  # Issue server certificate
nix run .#vault-cert-client  # Issue client certificate
nix run .#vault-cert-postgres # Issue PostgreSQL certs
nix run .#observability-init # Setup observability stack
nix run .#test-<module>      # Run individual module tests
```

### Templates

```bash
nix flake init -t .#microvm-stack  # MicroVM with Barbican hardening
```

## Feature Flags

In `Cargo.toml`:

| Feature | Purpose |
|---------|---------|
| `postgres` | SQLx PostgreSQL support |
| `observability-stdout` | Default JSON logging to stdout |
| `observability-loki` | Push logs to Grafana Loki |
| `observability-otlp` | OpenTelemetry Protocol export |
| `metrics-prometheus` | Prometheus metrics endpoint |
| `hibp` | Have I Been Pwned password checking |
| `compliance-artifacts` | Generate audit evidence files |
| `fips` | FIPS 140-3 crypto via AWS-LC |
| `stig` | STIG/ComplianceAsCode parsing and config generation |

## Common Tasks

### Adding a New NIST Control

1. Identify the control family (AC, AU, IA, SC, SI, etc.)
2. Add Rust implementation in appropriate `src/*.rs` file
3. Add NixOS implementation in `nix/modules/*.nix` if infrastructure-level
4. Update `NIST_800_53_CONTROL_RESEARCH.md` with control details
5. Add tests in the same file or `src/compliance/`
6. Update CLI generators if config options needed

### Adding a New NixOS Module

1. Create `nix/modules/my-module.nix`
2. Export in `nix/modules/default.nix`
3. Add to `flake.nix` nixosModules
4. Update CLI's `generate/nix.rs` if config-driven

### Modifying Code Generation

- Rust generation: `crates/barbican-cli/src/generate/rust.rs`
- Nix generation: `crates/barbican-cli/src/generate/nix.rs`
- Config parsing: `crates/barbican-cli/src/config.rs`

### Running Tests

```bash
cargo test                          # All Rust tests
cargo test --features postgres      # With database
nix flake check                     # NixOS VM tests
```

## Gotchas and Quirks

### Package Names with Hyphens

Nix attribute access for hyphenated names requires quotes:
```nix
# Wrong: pkgs.hello-world
# Right: pkgs."hello-world"
```

The CLI handles this in `generate/nix.rs`.

### nixpkgs Version

Barbican targets **nixpkgs 24.11**. The `services.postgresql.extensions` option exists in 24.11 but was named `extraPlugins` in 24.05.

### Empty Lists in Nix

Empty lists with inline comments break Nix syntax:
```nix
# Wrong: allowedClients = [ # empty ];
# Right: allowedClients = [ ];
```

### Binary vs Package Names

Rust binaries use snake_case (`hello_fedramp_high`), but Cargo package names often use hyphens (`hello-fedramp-high`). The CLI generates both correctly.

### Example Flake Path Dependencies

The example apps use `barbican = { path = "../.." }` in their Cargo.toml, which doesn't work in Nix's isolated build sandbox. The flakes work around this by:

1. Using the full barbican repo as source: `src = final.runCommand "barbican-src" {} ''cp -r ${barbican} $out; chmod -R u+w $out''`
2. Setting `sourceRoot` in `postUnpack` to navigate to the example subdirectory
3. Using `rustPlatformLatest` from rust-overlay for edition2024 support

**Future simplification:** When barbican is published to crates.io, change the dependency to `barbican = { version = "0.1" }` and simplify to `src = ./.` in the flakes.

## NIST Control Reference

See `NIST_800_53_CONTROL_RESEARCH.md` for complete mapping of:
- 56+ directly implemented controls
- 20+ infrastructure controls
- Control-to-code traceability
- Profile-specific requirements

## Testing Architecture

- Unit tests: Same file as implementation
- Integration tests: `src/integration.rs`
- Compliance tests: `src/compliance/` (with `compliance-artifacts` feature)
- NixOS tests: `nix/tests/*.nix` (run via `nix flake check`)

## Dependencies

Key dependencies:
- `axum 0.8` - Web framework
- `tower-http` - HTTP middleware
- `tower_governor` - Rate limiting
- `sqlx` - PostgreSQL (optional)
- `aes-gcm` - Encryption
- `hmac`, `sha2` - Audit integrity
- `aws-lc-rs` - FIPS crypto (optional)

## Build Commands

```bash
# Development
cargo build
cargo run --example fedramp_moderate

# With features
cargo build --features "postgres,fips,compliance-artifacts"

# NixOS VM
nix build .#nixosConfigurations.fedramp-high-vm.config.system.build.vm
./result/bin/run-*-vm

# Check everything
nix flake check
```
