-- FedRAMP High Baseline Schema
-- Maximum security: FIPS crypto, HSM keys, signed audit chain, MFA, strict RBAC

-- Users table with encrypted PII (SC-28 with FIPS)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Encrypted PII fields (FIPS 140-3 AES-256-GCM)
    email_encrypted TEXT NOT NULL,
    phone_encrypted TEXT,
    ssn_encrypted TEXT  -- Highly sensitive, never returned in API
);

-- Documents with encrypted content
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
    classification VARCHAR(50) NOT NULL DEFAULT 'internal',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Encrypted content (FIPS AES-256-GCM)
    content_encrypted TEXT NOT NULL
);

-- Signed audit chain (AU-9 with cryptographic protection)
-- Each record is HMAC-signed and chained to previous
CREATE TABLE IF NOT EXISTS audit_chain (
    id UUID PRIMARY KEY,
    sequence_num BIGSERIAL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Who (IA-2 compliant - includes MFA status)
    actor VARCHAR(255) NOT NULL,
    actor_role VARCHAR(100),
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    auth_method VARCHAR(50),  -- pwd, otp, hwk, etc.

    -- What
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,

    -- Context
    source_ip VARCHAR(45),
    user_agent TEXT,
    session_id UUID,

    -- Outcome
    success BOOLEAN NOT NULL DEFAULT TRUE,
    details JSONB,

    -- Cryptographic integrity (AU-9)
    previous_hash VARCHAR(64),  -- Hash of previous record (chain)
    record_signature VARCHAR(128) NOT NULL,  -- HMAC-SHA256 signature
    algorithm VARCHAR(20) NOT NULL DEFAULT 'HMAC-SHA256'
);

-- Session management with strict controls (AC-11, AC-12)
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    -- MFA status (IA-2)
    mfa_completed BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_method VARCHAR(50),

    -- Context
    source_ip VARCHAR(45),
    user_agent TEXT,

    -- State
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    terminated_reason VARCHAR(100),
    terminated_at TIMESTAMPTZ
);

-- Enhanced RBAC (AC-3, AC-6)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ,  -- Time-limited roles
    PRIMARY KEY (user_id, role)
);

-- Key metadata tracking (SC-12)
CREATE TABLE IF NOT EXISTS key_metadata (
    key_id VARCHAR(255) PRIMARY KEY,
    purpose VARCHAR(50) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    state VARCHAR(20) NOT NULL DEFAULT 'active'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_classification ON documents(classification);
CREATE INDEX IF NOT EXISTS idx_audit_chain_timestamp ON audit_chain(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_chain_sequence ON audit_chain(sequence_num);
CREATE INDEX IF NOT EXISTS idx_audit_chain_actor ON audit_chain(actor);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
