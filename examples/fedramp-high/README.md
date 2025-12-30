# FedRAMP High Example

A hello-world application demonstrating FedRAMP High security controls using Barbican.

## Structure

```
fedramp-high/
├── barbican.toml              # Security configuration (single source of truth)
├── flake.nix                  # NixOS deployment configuration
├── Cargo.toml                 # Rust dependencies
├── src/
│   ├── main.rs                # Application code
│   └── generated/
│       ├── mod.rs
│       └── barbican_config.rs # Generated from barbican.toml
├── nix/generated/
│   └── barbican.nix           # Generated NixOS module config
└── secrets/
    └── secrets.nix            # Agenix secret definitions
```

## Security Controls (FedRAMP High)

| Control | Implementation |
|---------|----------------|
| SC-8    | mTLS required (`TlsMode::Strict`) |
| SC-13   | FIPS 140-2/3 crypto required |
| AC-7    | 3 login attempts, 30min lockout |
| AC-11   | 5 minute idle timeout |
| AC-12   | 10 minute max session |
| AU-11   | 365 day log retention |
| IA-2    | MFA required |
| IA-5    | 14 character password minimum |
| SI-4    | AIDE + auditd intrusion detection |
| SI-16   | Kernel hardening enabled |

## Development

```bash
# Enter development shell
nix develop

# Run the application
cargo run

# Test endpoints
curl http://localhost:3000/       # Returns profile settings
curl http://localhost:3000/health # Health check
```

## Regenerate Configuration

After modifying `barbican.toml`:

```bash
# Regenerate Rust config
barbican generate rust --config barbican.toml

# Regenerate Nix config
barbican generate nix --config barbican.toml
```

## Deployment

### 1. Set up secrets

```bash
# Generate age key
age-keygen -o ~/.config/agenix/keys.txt

# Edit secrets/secrets.nix with your public key

# Create the secrets
cd secrets
agenix -e db-password.age    # Enter database password
agenix -e app-env.age        # Enter: DATABASE_URL=postgres://...
```

### 2. Build and deploy

```bash
# Build the VM configuration
nix build .#nixosConfigurations.fedramp-high-vm.config.system.build.toplevel

# Or build just the package
nix build

# Run checks
nix flake check
```

## Configuration Reference

The `barbican.toml` controls both Rust and NixOS configuration:

```toml
[app]
profile = "fedramp-high"  # Sets all security defaults

[database]
pool_size = 10            # Connection pool size
# SSL and mTLS derived from profile

[network]
[[network.allowed_ingress]]
port = 3000
from = "10.0.0.0/8"       # Internal network only
```

See the [Barbican documentation](../../README.md) for full configuration options.
