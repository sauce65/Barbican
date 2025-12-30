# db-minimal: Secure PostgreSQL with Barbican

A minimal example demonstrating how to build a secure application with Barbican's PostgreSQL and field-level encryption features.

## What This Example Shows

- **Secure Database Connections**: TLS/mTLS with connection pooling and timeouts
- **Field-Level Encryption**: Transparent encryption of sensitive data (PII) before storage
- **Sensitive vs Non-Sensitive Data**: Clear separation of encrypted and plaintext fields
- **CRUD Operations**: Complete API for users and documents
- **Audit Logging**: Compliance-ready audit trail (AU-2, AU-3)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │   Axum      │    │  FieldEncryptor │    │  DatabaseConfig │ │
│  │   Router    │    │  (AES-256-GCM)  │    │  (TLS/mTLS)     │ │
│  └──────┬──────┘    └────────┬────────┘    └────────┬────────┘ │
│         │                    │                      │           │
│         ▼                    ▼                      ▼           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Repository Layer                          ││
│  │  - Encrypt sensitive fields before INSERT                   ││
│  │  - Decrypt sensitive fields after SELECT                    ││
│  │  - Non-sensitive fields stored as plaintext                 ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (TLS encrypted connection)
┌─────────────────────────────────────────────────────────────────┐
│                       PostgreSQL                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  users table                                                 ││
│  │  ├── id, username, display_name (plaintext)                 ││
│  │  └── email_encrypted, phone_encrypted, ssn_encrypted        ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- PostgreSQL 14+ with SSL enabled
- Rust 1.75+
- Barbican library

## Quick Start

### 1. Create the Database

```bash
createdb dbminimal
```

### 2. Set Environment Variables

```bash
# Required: Database connection
export DATABASE_URL="postgres://localhost/dbminimal"

# Required for production: 256-bit encryption key (hex-encoded)
# Generate with: openssl rand -hex 32
export ENCRYPTION_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Optional: For production, use SSL
# export DATABASE_URL="postgres://user:pass@host/db?sslmode=verify-full"
# export DB_SSL_ROOT_CERT="/path/to/ca.crt"
```

### 3. Run the Application

```bash
cd examples/apps/db-minimal
cargo run
```

### 4. Test the API

```bash
# Health check
curl http://localhost:3000/health

# Create a user (sensitive data will be encrypted)
curl -X POST http://localhost:3000/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "display_name": "John Doe",
    "email": "john@example.com",
    "phone": "+1-555-0123",
    "ssn": "123-45-6789"
  }'

# List users (sensitive data decrypted for response)
curl http://localhost:3000/users

# Get a specific user
curl http://localhost:3000/users/<user-id>

# Update a user
curl -X PUT http://localhost:3000/users/<user-id> \
  -H "Content-Type: application/json" \
  -d '{"email": "newemail@example.com"}'

# Create a document (content encrypted)
curl -X POST http://localhost:3000/users/<user-id>/documents \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Medical Record",
    "content": "Patient shows signs of improvement..."
  }'

# List user documents
curl http://localhost:3000/users/<user-id>/documents
```

## Key Concepts

### Sensitive vs Non-Sensitive Data

| Field Type | Storage | Example Fields |
|------------|---------|----------------|
| Non-sensitive | Plaintext | username, display_name, created_at |
| Sensitive (PII) | Encrypted | email, phone, SSN |
| Highly Sensitive | Encrypted, never returned | SSN (in API responses) |

### Field-Level Encryption

```rust
// Encrypt before storage
let email_encrypted = encryptor.encrypt_string(&email)?;
sqlx::query!("INSERT INTO users (email_encrypted) VALUES ($1)", email_encrypted);

// Decrypt after retrieval
let row = sqlx::query!("SELECT email_encrypted FROM users WHERE id = $1", id);
let email = encryptor.decrypt_string(&row.email_encrypted)?;
```

Each encryption produces unique ciphertext (random nonces), preventing pattern analysis.

### Database Security

```rust
let db_config = DatabaseConfig::builder(&database_url)
    .application_name("db-minimal")
    .ssl_mode(SslMode::VerifyFull)      // TLS with cert verification
    .max_connections(5)                  // Connection pool limits
    .statement_timeout(Duration::from_secs(30))  // Query timeout
    .build();
```

## NIST 800-53 Controls Demonstrated

| Control | Description | Implementation |
|---------|-------------|----------------|
| SC-8 | Transmission Confidentiality | TLS database connections |
| SC-28 | Protection at Rest | Field-level AES-256-GCM encryption |
| SC-13 | Cryptographic Protection | NIST-approved algorithms |
| AU-2 | Audit Events | Audit log table |
| AU-3 | Content of Audit Records | Actor, action, resource, timestamp |

## Production Considerations

### Encryption Key Management

```bash
# Generate a secure key
openssl rand -hex 32

# Store in a secrets manager (AWS Secrets Manager, Vault, etc.)
# Never commit keys to version control!
```

### Database SSL

```bash
# For production, use verify-full mode
export DATABASE_URL="postgres://user:pass@host/db?sslmode=verify-full"
export DB_SSL_ROOT_CERT="/etc/ssl/certs/ca.crt"

# For mTLS (client certificate authentication)
export DB_SSL_CERT="/etc/ssl/certs/client.crt"
export DB_SSL_KEY="/etc/ssl/private/client.key"
```

### Key Rotation

When rotating encryption keys:

1. Add new key to configuration
2. Re-encrypt all sensitive fields with new key
3. Remove old key after migration

```rust
// Re-encryption pseudocode
let old_encryptor = FieldEncryptor::new(&old_key)?;
let new_encryptor = FieldEncryptor::new(&new_key)?;

for user in users {
    let email = old_encryptor.decrypt_string(&user.email_encrypted)?;
    let new_encrypted = new_encryptor.encrypt_string(&email)?;
    update_user(user.id, new_encrypted).await?;
}
```

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check with DB and encryption status |
| GET | /users | List all users |
| POST | /users | Create a user |
| GET | /users/:id | Get a user by ID |
| PUT | /users/:id | Update a user |
| DELETE | /users/:id | Delete a user |
| GET | /users/:id/documents | List user's documents |
| POST | /users/:id/documents | Create a document |
| GET | /documents/:id | Get a document by ID |

### Health Response

```json
{
  "status": "healthy",
  "database_connected": true,
  "database_ssl": true,
  "encryption_available": true
}
```

### User Object

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "display_name": "John Doe",
  "email": "john@example.com",
  "phone": "+1-555-0123",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

Note: SSN is never returned in API responses even though it's stored encrypted.

## License

MIT - See Barbican license for details.
