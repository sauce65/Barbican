# Barbican FedRAMP Database Examples

Three complete examples demonstrating how to implement secure database applications at each FedRAMP authorization level using Barbican.

## Quick Comparison

| Feature | Low | Moderate | High |
|---------|-----|----------|------|
| **TLS** | Preferred | Required | Required + Channel Binding |
| **Field Encryption** | No (infra only) | AES-256-GCM | FIPS AES-256-GCM |
| **FIPS Crypto** | No | No | **Required** |
| **Audit Logging** | Basic | Enhanced + hash | **Signed chain** |
| **Session Timeout** | Standard | 30 min idle | **15 min idle** |
| **Max Session** | 8 hours | 8 hours | **4 hours** |
| **MFA** | No | No | **Required** |
| **RBAC** | Basic | Role-based | Role-based + time-limited |
| **Key Management** | Env var | Env var | **HSM/KMS** |

## Control Mapping

### Encryption & Cryptography

| Control | Low | Moderate | High |
|---------|-----|----------|------|
| **SC-8** (Transmission) | TLS preferred | TLS required | mTLS preferred |
| **SC-13** (FIPS Crypto) | N/A | NIST-approved | **FIPS 140-3** |
| **SC-28** (Data at Rest) | Disk/TDE | Field-level | Field-level + HSM |
| **SC-12** (Key Mgmt) | Manual | Manual + tracking | **HSM/KMS + rotation** |

### Audit & Accountability

| Control | Low | Moderate | High |
|---------|-----|----------|------|
| **AU-2** (Events) | Basic CRUD | Comprehensive | Comprehensive |
| **AU-3** (Content) | Who, what, when | + where, outcome | + MFA status, session |
| **AU-9** (Protection) | None | Hash integrity | **HMAC-SHA256 chain** |

### Access Control

| Control | Low | Moderate | High |
|---------|-----|----------|------|
| **AC-3** (Enforcement) | Basic | Role-based | Fine-grained RBAC |
| **AC-6** (Least Privilege) | Default role | Default role | Time-limited roles |
| **AC-11** (Session Lock) | None | 30 min idle | **15 min idle** |
| **AC-12** (Termination) | None | 8 hour max | **4 hour max** |

### Identification & Authentication

| Control | Low | Moderate | High |
|---------|-----|----------|------|
| **IA-2** (Auth) | Password | Password | **MFA required** |
| **IA-2(1)** (MFA Privileged) | N/A | N/A | **Required** |
| **IA-2(2)** (MFA Non-Priv) | N/A | N/A | **Required** |

## Directory Structure

```
examples/apps/
├── README.md                 # This file
├── db-fedramp-low/          # FedRAMP Low baseline
│   ├── Cargo.toml
│   ├── flake.nix
│   ├── schema.sql
│   └── src/main.rs
├── db-fedramp-moderate/     # FedRAMP Moderate baseline
│   ├── Cargo.toml
│   ├── flake.nix
│   ├── schema.sql
│   └── src/main.rs
├── db-fedramp-high/         # FedRAMP High baseline
│   ├── Cargo.toml
│   ├── flake.nix
│   ├── schema.sql
│   └── src/main.rs
└── db-minimal/              # Simple example (pre-FedRAMP)
```

## Running the Examples

Each example uses Nix flakes for reproducible development environments:

```bash
# FedRAMP Low
cd db-fedramp-low
nix develop
cargo run

# FedRAMP Moderate
cd db-fedramp-moderate
nix develop
cargo run

# FedRAMP High (non-FIPS for development)
cd db-fedramp-high
nix develop
cargo run

# FedRAMP High (FIPS mode for production)
cd db-fedramp-high
nix develop
cargo run --features fips
```

## API Endpoints

All three examples expose the same REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check with security status |
| GET | `/users` | List users |
| POST | `/users` | Create user |
| GET | `/users/:id` | Get user |
| DELETE | `/users/:id` | Delete user |
| GET | `/users/:id/documents` | List user's documents |
| POST | `/users/:id/documents` | Create document |

## Barbican Features Used

### FedRAMP Low
```rust
// Basic database config with TLS preferred
let config = DatabaseConfig::builder()
    .ssl_mode(SslMode::Prefer)
    .build();

// Simple audit logging
sqlx::query!("INSERT INTO audit_log ...").execute(&pool).await;
```

### FedRAMP Moderate
```rust
// TLS required + field encryption
let config = DatabaseConfig::builder()
    .ssl_mode(SslMode::Require)
    .build();

let encryptor = FieldEncryptor::new(&key)?;
let encrypted = encryptor.encrypt_string(&pii_data)?;

// Session management
let policy = SessionPolicy::builder()
    .max_lifetime(Duration::from_secs(8 * 60 * 60))
    .idle_timeout(Duration::from_secs(30 * 60))
    .build();

// RBAC
let roles = get_user_roles(&pool, user_id).await;
```

### FedRAMP High
```rust
// mTLS + FIPS crypto
let config = DatabaseConfig::builder()
    .ssl_mode(SslMode::Require)
    .channel_binding(ChannelBinding::Require)
    .build();

// FIPS verification
assert!(EncryptionAlgorithm::is_fips_mode());

// Signed audit chain (AU-9)
let audit_config = AuditIntegrityConfig::new(signing_key);
let mut chain = AuditChain::new(audit_config);
let record = chain.append("create", "admin", "user", ...);

// MFA enforcement (IA-2)
let mfa_policy = MfaPolicy::require_mfa();
if !mfa_policy.is_satisfied(&claims) {
    return Err(StatusCode::FORBIDDEN);
}

// Key rotation tracking (SC-12)
let mut tracker = RotationTracker::new();
tracker.register("encryption-key", RotationPolicy::days(90));
if tracker.needs_rotation("encryption-key") {
    warn!("Key rotation required!");
}

// Strict session policy
let policy = SessionPolicy::builder()
    .max_lifetime(Duration::from_secs(4 * 60 * 60))  // 4 hours
    .idle_timeout(Duration::from_secs(15 * 60))       // 15 minutes
    .build();
```

## Production Checklist

### FedRAMP Low
- [ ] Enable TLS on database
- [ ] Configure disk encryption
- [ ] Enable audit logging
- [ ] Deploy with NixOS module

### FedRAMP Moderate
- [ ] All of Low, plus:
- [ ] Set `ENCRYPTION_KEY` from secrets manager
- [ ] Verify TLS is enforced
- [ ] Configure session timeouts
- [ ] Set up RBAC roles
- [ ] Enable pgaudit

### FedRAMP High
- [ ] All of Moderate, plus:
- [ ] Build with `--features fips`
- [ ] Verify FIPS certificate in `/health`
- [ ] Configure HSM/KMS for key management
- [ ] Set `AUDIT_SIGNING_KEY` from HSM
- [ ] Integrate MFA provider (Okta, Entra, etc.)
- [ ] Configure 90-day key rotation
- [ ] Enable mTLS if possible

## Health Check Response Examples

### FedRAMP Low
```json
{
  "status": "healthy",
  "database_connected": true,
  "baseline": "FedRAMP Low"
}
```

### FedRAMP Moderate
```json
{
  "status": "healthy",
  "database_connected": true,
  "database_ssl": true,
  "encryption_available": true,
  "baseline": "FedRAMP Moderate"
}
```

### FedRAMP High
```json
{
  "status": "healthy",
  "database_connected": true,
  "database_ssl": true,
  "fips_mode": true,
  "fips_certificate": "AWS-LC FIPS 140-3 Certificate #4631",
  "encryption_algorithm": "Aes256Gcm",
  "baseline": "FedRAMP High"
}
```

## Schema Differences

| Table | Low | Moderate | High |
|-------|-----|----------|------|
| `users` | Plaintext | `*_encrypted` fields | `*_encrypted` + SSN |
| `documents` | Plaintext | `content_encrypted` | `content_encrypted` + classification |
| `audit_log` | Basic | + hash, details | N/A (uses `audit_chain`) |
| `audit_chain` | N/A | N/A | Signed, chained records |
| `sessions` | N/A | Present | Present + MFA tracking |
| `user_roles` | N/A | Present | Present + expiration |
| `key_metadata` | N/A | N/A | Key lifecycle tracking |

## References

- [FedRAMP Security Controls](https://www.fedramp.gov/documents/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Barbican Documentation](../../README.md)
