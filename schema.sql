-- Loki Password Manager Relational Database Schema
-- Production-grade PostgreSQL with RLS and Audit Chaining

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    lockdown_enabled BOOLEAN DEFAULT FALSE,
    lockdown_reason TEXT,
    lockdown_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Argon2id account login hash
    kdf_salt VARCHAR(64) NOT NULL,       -- Hex salt for client-side Master Password Argon2id KEK
    full_name VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret_encrypted VARCHAR(255),  -- Server-side TOTP validation secret
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. User Cryptographic Keys (Public key & Client-Encrypted Private Key)
CREATE TABLE user_crypto_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE NOT NULL,
    public_key VARCHAR(128) NOT NULL,              -- Curve25519 public key (Base64)
    encrypted_private_key TEXT NOT NULL,           -- Encrypted with User KEK (Base64)
    private_key_nonce VARCHAR(64) NOT NULL,        -- Nonce for encrypted private key
    crypto_version VARCHAR(32) DEFAULT 'v1-xchacha20poly1305',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Organization Memberships & RBAC Roles
CREATE TYPE org_role AS ENUM ('owner', 'admin', 'manager', 'member', 'auditor', 'guest');

CREATE TABLE organization_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    role org_role NOT NULL DEFAULT 'member',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, user_id)
);

-- 5. Clients (e.g., TecnoMart, Gold N Glow, Agency Internal)
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    name VARCHAR(255) NOT NULL,
    identifier VARCHAR(100) NOT NULL,
    description TEXT,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, identifier)
);

-- 6. Vaults
CREATE TABLE vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    key_version INT DEFAULT 1,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. Vault Key Wrappers (Encrypted Vault DEKs per authorized user)
CREATE TABLE vault_key_wrappers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES vaults(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    key_version INT NOT NULL DEFAULT 1,
    wrapped_key TEXT NOT NULL, -- Vault DEK sealed with recipient user's Curve25519 public key
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(vault_id, user_id, key_version)
);

-- 8. Vault Folders
CREATE TABLE folders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES vaults(id) ON DELETE CASCADE NOT NULL,
    name VARCHAR(255) NOT NULL,
    parent_id UUID REFERENCES folders(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 9. Vault Items (Encrypted Credentials & Secrets)
CREATE TYPE item_type AS ENUM (
    'login', 'api_key', 'secure_note', 'totp', 
    'ssh_key', 'database', 'environment', 'recovery_codes', 'certificate', 'custom'
);

CREATE TYPE risk_level AS ENUM ('normal', 'sensitive', 'critical');

CREATE TABLE vault_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES vaults(id) ON DELETE CASCADE NOT NULL,
    folder_id UUID REFERENCES folders(id) ON DELETE SET NULL,
    item_type item_type NOT NULL DEFAULT 'login',
    risk_level risk_level NOT NULL DEFAULT 'normal',
    title VARCHAR(255) NOT NULL,                   -- Non-sensitive title
    url VARCHAR(1024),                             -- Non-sensitive URL
    tags TEXT[],                                   -- Non-sensitive tags
    
    -- Encrypted payload (client-side AEAD)
    ciphertext TEXT NOT NULL,                      -- Base64 XChaCha20-Poly1305 ciphertext of secrets payload
    nonce VARCHAR(64) NOT NULL,                    -- Base64 24-byte nonce
    crypto_version VARCHAR(32) DEFAULT 'v1-xchacha20poly1305',
    key_version INT NOT NULL DEFAULT 1,            -- Matches vault DEK key_version
    
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ
);

-- 10. Encrypted Attachments
CREATE TABLE attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id UUID REFERENCES vault_items(id) ON DELETE CASCADE NOT NULL,
    filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    storage_path VARCHAR(512) NOT NULL,
    ciphertext_hash VARCHAR(64) NOT NULL,          -- SHA-256 integrity hash of encrypted file
    nonce VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 11. Sessions & Devices
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    token_hash VARCHAR(64) UNIQUE NOT NULL,        -- SHA-256 hash of refresh token
    device_name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_active_at TIMESTAMPTZ DEFAULT NOW()
);

-- 12. Recovery Keys & Emergency Access
CREATE TABLE recovery_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE NOT NULL,
    recovery_key_hash VARCHAR(64) NOT NULL,        -- SHA-256 hash of recovery passphrase
    wrapped_private_key TEXT NOT NULL,             -- User private key encrypted with key derived from recovery phrase
    nonce VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    used_at TIMESTAMPTZ
);

-- 13. Cryptographically Chained Audit Logs (Tamper-evident)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB,
    prev_hash VARCHAR(64) NOT NULL,                -- Previous row hash
    signature VARCHAR(64) NOT NULL,               -- SHA-256 (prev_hash + row_data + secret)
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vault_items_vault ON vault_items(vault_id) WHERE is_deleted = FALSE;
CREATE INDEX idx_vault_key_wrappers_user ON vault_key_wrappers(user_id, vault_id);
CREATE INDEX idx_sessions_user ON sessions(user_id) WHERE revoked = FALSE;
CREATE INDEX idx_audit_org ON audit_logs(org_id, created_at DESC);
