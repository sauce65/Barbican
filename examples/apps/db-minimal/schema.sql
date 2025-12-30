-- Barbican db-minimal Example Schema
-- Demonstrates handling sensitive vs non-sensitive data

-- Users table: mix of sensitive and non-sensitive fields
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,

    -- Non-sensitive: can be stored in plaintext
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Sensitive: stored encrypted (ciphertext in DB)
    -- These fields contain field-level encrypted data
    email_encrypted TEXT NOT NULL,        -- PII: email address
    phone_encrypted TEXT,                 -- PII: phone number
    ssn_encrypted TEXT                    -- Highly sensitive: SSN
);

-- Documents table: demonstrates encrypted content
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Non-sensitive metadata
    title VARCHAR(255) NOT NULL,
    content_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Sensitive: encrypted document content
    content_encrypted TEXT NOT NULL
);

-- Audit log: demonstrates secure audit trail (non-sensitive metadata)
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    details JSONB
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor);
