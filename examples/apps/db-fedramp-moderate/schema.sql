-- FedRAMP Moderate Baseline Schema
-- Enhanced security: field-level encryption, RBAC, session tracking, protected audit logs

-- Users table with encrypted PII fields (SC-28)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Encrypted PII fields (field-level encryption)
    email_encrypted TEXT NOT NULL,
    phone_encrypted TEXT
);

-- Documents with encrypted content
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Encrypted content (SC-28)
    content_encrypted TEXT NOT NULL
);

-- Enhanced audit log (AU-2, AU-3, AU-9)
-- More detailed than Low baseline
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Who
    actor VARCHAR(255) NOT NULL,
    actor_role VARCHAR(100),

    -- What
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,

    -- Context
    source_ip VARCHAR(45),
    user_agent TEXT,

    -- Outcome
    success BOOLEAN NOT NULL DEFAULT TRUE,
    details JSONB,

    -- Integrity (AU-9) - hash of record for tamper detection
    record_hash VARCHAR(64)
);

-- Session tracking table (AC-11, AC-12)
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Session metadata
    source_ip VARCHAR(45),
    user_agent TEXT,

    -- State
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Role assignments for RBAC (AC-3, AC-6)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by VARCHAR(255),
    PRIMARY KEY (user_id, role)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
