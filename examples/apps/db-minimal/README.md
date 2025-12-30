# db-minimal: Secure PostgreSQL with Barbican

A minimal example demonstrating how to build a secure application using Barbican's NixOS modules and field-level encryption.

## What This Demonstrates

- **Nix-first workflow**: Database spun up via flake, compile-time SQL checking
- **Barbican integration**: `securePostgres` module for hardened PostgreSQL
- **Field-level encryption**: AES-256-GCM encryption for PII fields
- **NIST 800-53 controls**: SC-8, SC-28, AU-2, AU-3, SC-39

## Quick Start

```bash
# Enter development shell (starts PostgreSQL automatically)
nix develop

# Set encryption key (or let it auto-generate for dev)
export ENCRYPTION_KEY=$(openssl rand -hex 32)

# Build and run
cargo build   # Compile-time SQL validation
cargo run     # Start server on :3000
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  nix develop                                                     │
│  ├── Starts PostgreSQL with schema                              │
│  ├── Sets DATABASE_URL                                          │
│  └── Enables compile-time sqlx::query! checking                 │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│  Application (src/main.rs)                                       │
│  ├── DatabaseConfig::builder() → secure connection              │
│  ├── FieldEncryptor → AES-256-GCM for PII                       │
│  └── sqlx::query!() → compile-time checked SQL                  │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│  PostgreSQL (via nix develop or barbican.securePostgres)        │
│  ├── users (email_encrypted, phone_encrypted, ssn_encrypted)    │
│  ├── documents (content_encrypted)                              │
│  └── audit_log                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Development Workflow

### 1. Enter the dev shell

```bash
nix develop
```

This automatically:
- Starts a local PostgreSQL instance
- Creates the `dbminimal` database
- Applies the schema from `schema.sql`
- Sets `DATABASE_URL` for sqlx compile-time checking

### 2. Build with compile-time SQL validation

```bash
cargo build
```

The `sqlx::query!` macros connect to the database at compile time to:
- Validate SQL syntax
- Check column names and types
- Generate type-safe Rust bindings

### 3. Run the application

```bash
export ENCRYPTION_KEY=$(openssl rand -hex 32)
cargo run
```

### 4. Test the API

```bash
# Health check
curl http://localhost:3000/health

# Create user (email/phone/ssn encrypted before storage)
curl -X POST http://localhost:3000/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "phone": "+1-555-0100",
    "ssn": "123-45-6789"
  }'

# List users (decrypted in response, SSN never returned)
curl http://localhost:3000/users

# Create encrypted document
curl -X POST http://localhost:3000/users/<id>/documents \
  -H "Content-Type: application/json" \
  -d '{"title": "Medical Record", "content": "Patient data..."}'
```

## Production Deployment

### NixOS Module

Add to your `flake.nix`:

```nix
{
  inputs.db-minimal.url = "github:sauce65/Barbican?dir=examples/apps/db-minimal";

  outputs = { self, nixpkgs, db-minimal, ... }: {
    nixosConfigurations.myserver = nixpkgs.lib.nixosSystem {
      modules = [
        db-minimal.nixosModules.default
        # Your other modules...
      ];
    };
  };
}
```

This enables:
- `barbican.securePostgres` - Hardened PostgreSQL with:
  - TLS encryption (SC-8)
  - scram-sha-256 authentication
  - pgaudit logging (AU-2)
  - Process isolation (SC-39)
- `barbican.databaseBackup` - Encrypted backups with:
  - age encryption (SC-28)
  - S3/rclone offsite transport (MP-5)

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `ENCRYPTION_KEY` | Yes (prod) | 64 hex chars (256-bit key) |

Generate a production key:
```bash
openssl rand -hex 32
```

## Security Controls

| Control | Implementation |
|---------|----------------|
| SC-8 | TLS database connections via `DatabaseConfig` |
| SC-28 | Field-level AES-256-GCM encryption |
| SC-13 | NIST-approved cryptography (FIPS optional) |
| SC-39 | systemd process isolation |
| AU-2 | pgaudit + application audit_log table |
| AU-3 | Actor, action, resource, timestamp in audit records |

## Schema

```sql
-- Sensitive fields stored encrypted
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    email_encrypted TEXT NOT NULL,     -- PII: encrypted
    phone_encrypted TEXT,              -- PII: encrypted
    ssn_encrypted TEXT,                -- Highly sensitive: encrypted, never returned
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

-- Document content encrypted
CREATE TABLE documents (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    title VARCHAR(255) NOT NULL,
    content_encrypted TEXT NOT NULL,   -- Encrypted
    ...
);

-- Audit trail (plaintext metadata)
CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ,
    actor VARCHAR(255),
    action VARCHAR(50),
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB
);
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/users` | List users |
| POST | `/users` | Create user |
| GET | `/users/{id}` | Get user |
| PUT | `/users/{id}` | Update user |
| DELETE | `/users/{id}` | Delete user |
| GET | `/users/{id}/documents` | List user's documents |
| POST | `/users/{id}/documents` | Create document |
| GET | `/documents/{id}` | Get document |

## Files

```
db-minimal/
├── flake.nix      # Nix flake with devShell and NixOS module
├── Cargo.toml     # Rust dependencies
├── schema.sql     # Database schema
├── src/
│   └── main.rs    # Application code with sqlx::query!
└── README.md
```
