# Barbican

NIST 800-53 compliant security infrastructure for Rust/Axum applications with NixOS deployment.

Barbican provides **secure-by-default** building blocks that implement 56+ NIST SP 800-53 Rev 5 controls, enabling FedRAMP Low, Moderate, and High compliance for web applications.

## Quick Start

### 1. Add Barbican to your project

```toml
# Cargo.toml
[dependencies]
barbican = { git = "https://github.com/Sauce65/barbican", features = ["postgres"] }
```

### 2. Create a configuration file

```toml
# barbican.toml
[app]
name = "my-secure-app"
profile = "fedramp-moderate"

[database]
enable = true
name = "my_app_db"
require_ssl = true

[firewall]
allowed_inbound = [
    { port = 443, protocol = "tcp", source = "0.0.0.0/0" }
]
```

### 3. Generate configuration

```bash
# Install the CLI
cargo install --path crates/barbican-cli

# Generate Rust config and NixOS modules
barbican generate rust
barbican generate nix
```

### 4. Use in your application

```rust
use barbican::prelude::*;

#[tokio::main]
async fn main() {
    // Initialize observability (structured logging, metrics)
    barbican::observability::init_stdout("my-app", "info");

    // Build secure router with all middleware applied
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .with_security_headers()           // HSTS, CSP, X-Frame-Options
        .with_rate_limiting(100, 10)       // 100 req/s, burst of 10
        .with_request_timeout(Duration::from_secs(30))
        .with_body_limit(1024 * 1024);     // 1MB max body

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Features

### Compliance Profiles

Barbican supports three FedRAMP impact levels with pre-configured security settings:

| Setting | Low | Moderate | High |
|---------|-----|----------|------|
| Session Timeout | 30 min | 15 min | 10 min |
| Idle Timeout | 15 min | 10 min | 5 min |
| MFA Required | Privileged only | All users | All users |
| Min Password Length | 8 chars | 12 chars | 14 chars |
| mTLS Required | No | No | Yes |
| Encryption at Rest | No | Yes | Yes |
| Key Rotation | 90 days | 90 days | 30 days |

### Rust Security Components

| Module | Purpose | NIST Controls |
|--------|---------|---------------|
| `auth` | OAuth/OIDC JWT validation, MFA enforcement | AC-2, IA-2, IA-2(1) |
| `session` | Session management with idle/absolute timeouts | AC-11, AC-12, SC-10 |
| `login` | Brute force protection with account lockout | AC-7 |
| `password` | NIST 800-63B compliant password validation | IA-5, IA-5(1) |
| `validation` | Input validation, XSS/SQLi prevention | SI-10 |
| `encryption` | AES-256-GCM field-level encryption | SC-28 |
| `tls` | TLS enforcement, mTLS support | SC-8, SC-8(1), IA-3 |
| `layers` | Security headers, rate limiting, CORS | CM-6, SC-5, AC-4 |
| `audit` | Structured audit logging with integrity | AU-2, AU-3, AU-9, AU-12 |
| `alerting` | Security incident alerting | IR-4, IR-5 |
| `health` | Health check framework | CA-7 |
| `keys` | Cryptographic key management | SC-12 |
| `secrets` | Secret detection for CI/CD | IA-5(7) |
| `supply_chain` | SBOM generation, vulnerability scanning | SR-3, SR-4 |
| `testing` | Security test utilities | SA-11, CA-8 |
| `error` | Secure error handling | SI-11 |

### NixOS Security Modules

| Module | Purpose | NIST Controls |
|--------|---------|---------------|
| `secureUsers` | User account hardening, SSH key management | AC-2, AC-6 |
| `securePostgres` | Hardened PostgreSQL with SSL, pgaudit | IA-5(2), SC-8, AU-2, AU-9 |
| `hardenedSSH` | Public key only, fail2ban integration | AC-7, IA-5(1) |
| `hardenedNginx` | Nginx security hardening | SC-8, CM-6 |
| `secretsManagement` | Age encryption for secrets | IA-5 |
| `observability` | Loki/Prometheus/Grafana stack | SI-4, AU-6, CA-7 |
| `observabilityAuth` | Grafana/Prometheus authentication | IA-2, AC-3 |
| `vmFirewall` | iptables with egress filtering | SC-7, SC-7(5) |
| `databaseBackup` | Automated encrypted backups | CP-9, CP-9(1) |
| `resourceLimits` | Memory/CPU quotas | SC-6 |
| `kernelHardening` | ASLR, sysctl hardening | SI-16 |
| `timeSync` | NTP with authentication | AU-8 |
| `intrusionDetection` | AIDE file integrity, auditd | SI-4, SI-7 |
| `systemdHardening` | Process isolation, capabilities | AC-6, SI-3, SC-39 |
| `vaultPki` | Certificate management with HashiCorp Vault | SC-12, SC-17 |
| `doctor` | Diagnostic health checks | CM-4, SI-6 |
| `oidcProvider` | Keycloak OIDC provider setup | IA-2, AC-2 |

## Architecture

### Design Philosophy

Barbican follows these principles:

1. **Secure by Default**: All components are configured for maximum security. You opt-out of protections, never opt-in.

2. **Single Source of Truth**: `barbican.toml` defines your security posture. The CLI generates both Rust configuration and NixOS modules from this single file.

3. **Profile-Driven Defaults**: Choosing a profile (e.g., `fedramp-moderate`) automatically applies appropriate defaults for all controls.

4. **Compile-Time Safety**: Generated Rust code provides type-safe access to configuration with the flexibility of runtime values where appropriate.

5. **Infrastructure as Code**: NixOS modules ensure your deployment environment matches your security requirements with reproducible builds.

### Code Generation Pipeline

```
barbican.toml
     │
     ├──► barbican generate rust ──► src/generated/barbican_config.rs
     │                                (Rust configuration module)
     │
     └──► barbican generate nix  ──► nix/generated/barbican.nix
                                     (NixOS configuration)
```

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      NixOS Host                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Hardened Kernel (SI-16)                │   │
│  │  - ASLR enabled                                     │   │
│  │  - Kernel pointer restriction                       │   │
│  │  - Network stack hardening                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Firewall   │  │  Your App    │  │   PostgreSQL     │  │
│  │   (SC-7)     │  │  (Axum +     │  │   (Hardened)     │  │
│  │              │  │   Barbican)  │  │                  │  │
│  │ - Egress     │  │              │  │ - SSL required   │  │
│  │   filtering  │  │ - Auth       │  │ - Client certs   │  │
│  │ - Default    │  │ - Sessions   │  │ - pgaudit        │  │
│  │   DROP       │  │ - Validation │  │ - Backups        │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Observability Stack                    │   │
│  │  Prometheus │ Loki │ Grafana (all hardened)        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Optional Features

Enable features in `Cargo.toml` as needed:

```toml
[dependencies]
barbican = {
    git = "https://github.com/Sauce65/barbican",
    features = [
        "postgres",              # PostgreSQL database support
        "observability-loki",    # Send logs to Loki
        "observability-otlp",    # OpenTelemetry export
        "metrics-prometheus",    # Prometheus metrics
        "hibp",                  # Password breach checking
        "compliance-artifacts",  # Generate audit evidence
        "fips",                  # FIPS 140-3 cryptography
    ]
}
```

| Feature | Description |
|---------|-------------|
| `postgres` | SQLx PostgreSQL support |
| `observability-stdout` | Default stdout JSON logging |
| `observability-loki` | Push logs to Grafana Loki |
| `observability-otlp` | OpenTelemetry Protocol export |
| `metrics-prometheus` | Prometheus metrics endpoint |
| `hibp` | Have I Been Pwned password checking (IA-5(1)) |
| `compliance-artifacts` | Generate auditor-verifiable test reports |
| `fips` | FIPS 140-3 validated crypto via AWS-LC (SC-13) |

## Examples

See the `examples/` directory for complete working examples:

- [`examples/fedramp-low/`](examples/fedramp-low/) - Basic security for limited impact systems
- [`examples/fedramp-moderate/`](examples/fedramp-moderate/) - Enhanced security (most common)
- [`examples/fedramp-high/`](examples/fedramp-high/) - Maximum security with mTLS

Each example includes:
- `barbican.toml` - Security configuration
- `src/main.rs` - Application code
- `flake.nix` - NixOS deployment configuration
- `src/generated/` - Generated Rust configuration
- `nix/generated/` - Generated NixOS modules

### Running an Example

```bash
cd examples/fedramp-moderate

# Enter development shell
nix develop

# Build and run
cargo run

# Or build and test the NixOS VM
nix build .#nixosConfigurations.fedramp-moderate-vm.config.system.build.vm
./result/bin/run-*-vm
```

## CLI Reference

### Generate Rust Configuration

```bash
barbican generate rust [OPTIONS]

Options:
  -c, --config <FILE>    Config file path [default: barbican.toml]
  -o, --output <DIR>     Output directory [default: src/generated]
```

Generates:
- `mod.rs` - Module exports
- `barbican_config.rs` - Type-safe configuration

### Generate NixOS Configuration

```bash
barbican generate nix [OPTIONS]

Options:
  -c, --config <FILE>    Config file path [default: barbican.toml]
  -o, --output <DIR>     Output directory [default: nix/generated]
```

Generates:
- `barbican.nix` - NixOS module configuration

## Integration with Existing Projects

### Adding to an Axum Application

```rust
use axum::{Router, routing::get};
use barbican::prelude::*;
use std::time::Duration;

// Your existing router
let app = Router::new()
    .route("/api/users", get(list_users))
    .route("/api/users/:id", get(get_user));

// Add Barbican security layers
let secured_app = app
    .with_security_headers()
    .with_rate_limiting(100, 10)
    .with_request_timeout(Duration::from_secs(30))
    .with_body_limit(1024 * 1024);
```

### Adding Password Validation

```rust
use barbican::password::{PasswordPolicy, PasswordStrength};

let policy = PasswordPolicy::fedramp_moderate();

match policy.validate("user_password", Some("username"), Some("user@example.com")) {
    Ok(PasswordStrength::Strong) => println!("Password accepted"),
    Ok(strength) => println!("Password weak: {:?}", strength),
    Err(e) => println!("Password rejected: {}", e),
}
```

### Adding Session Management

```rust
use barbican::session::{SessionPolicy, SessionState};

let policy = SessionPolicy::fedramp_moderate();
let session = SessionState::new("user_123");

// Check session validity on each request
if !policy.is_valid(&session) {
    return Err(SessionExpired);
}

// Update activity on user action
session.touch();
```

### Adding Login Protection

```rust
use barbican::login::{LoginTracker, LockoutPolicy};

let policy = LockoutPolicy::fedramp_moderate(); // 3 attempts, 30 min lockout
let tracker = LoginTracker::new(policy);

// Record failed attempt
tracker.record_failed_attempt("user@example.com");

// Check if locked out
if tracker.is_locked_out("user@example.com") {
    return Err(AccountLocked);
}
```

## NixOS Integration

### Using Barbican Modules

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    barbican.url = "github:Sauce65/barbican";
  };

  outputs = { self, nixpkgs, barbican, ... }: {
    nixosConfigurations.myserver = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        barbican.nixosModules.all
        ./nix/generated/barbican.nix
        ./hardware-configuration.nix
      ];
    };
  };
}
```

### Available NixOS Modules

Import individual modules, profiles, or use `all` for everything:

```nix
# Import all modules
barbican.nixosModules.all

# Or import a pre-configured profile
barbican.nixosModules.minimal   # Development/testing (basic security)
barbican.nixosModules.standard  # Staging (balanced security)
barbican.nixosModules.hardened  # Production (FedRAMP-aligned)

# Or import individual modules (camelCase naming)
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
```

### Security Profiles

Barbican provides pre-configured security profiles for common deployment scenarios:

| Profile | Use Case | Modules Included |
|---------|----------|------------------|
| `minimal` | Development/testing | secureUsers, timeSync |
| `standard` | Staging/internal | + hardenedSSH, kernelHardening, resourceLimits, vmFirewall |
| `hardened` | Production/FedRAMP | + intrusionDetection, systemdHardening (all modules) |

### Flake Apps

Run security tools directly:

```bash
# Run full security audit
nix run github:Sauce65/barbican#audit

# Start Vault dev server for PKI
nix run github:Sauce65/barbican#vault-dev

# Issue certificates
nix run github:Sauce65/barbican#vault-cert-server -- localhost
nix run github:Sauce65/barbican#vault-cert-client -- worker-1
nix run github:Sauce65/barbican#vault-cert-postgres

# Generate observability stack config
nix run github:Sauce65/barbican#observability-init

# Run individual NixOS tests
nix run github:Sauce65/barbican#test-secure-postgres
nix run github:Sauce65/barbican#test-vault-pki
```

### Library Functions

Barbican exports helper functions for custom configurations:

```nix
# Network zone helpers (SC-7)
barbican.lib.networkZones.mkZones { ... }
barbican.lib.networkZones.mkIP zone host
barbican.lib.networkZones.mkZoneFirewallRules zones allowedFlows

# PKI certificate generation (SC-12, SC-17)
barbican.lib.pki.mkCAScript { name, days, algorithm }
barbican.lib.pki.mkServerCertScript { name, caName, commonName, sans }
barbican.lib.pki.mkClientCertScript { name, caName, commonName }
barbican.lib.pki.mkPKISetupScript { name, servers, clients }

# Systemd hardening helpers (AC-6, SC-39)
barbican.lib.systemdHardening
```

### Templates

Bootstrap new projects with security built-in:

```bash
# Create a new MicroVM project with Barbican hardening
nix flake init -t github:Sauce65/barbican#microvm-stack
```

## Testing

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features "postgres,compliance-artifacts"

# Run NixOS integration tests
nix flake check
```

## Documentation

- [Audit Guide](docs/AUDIT_GUIDE.md) - Step-by-step compliance audit guide
- [NIST Control Research](NIST_800_53_CONTROL_RESEARCH.md) - Detailed control mapping
- [LLM Context](CLAUDE.md) - AI assistant context for this codebase

## License

MIT OR Apache-2.0
