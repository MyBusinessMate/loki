# DATA-FLOW.md: End-to-End Cryptographic & Application Data Flows

## 1. Authentication vs Vault Unlock Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser as Client UI
    participant Crypto as Crypto Engine (Memory)
    participant API as Loki API Server
    participant DB as PostgreSQL Database

    Note over User, DB: PHASE 1: Account Authentication (Identity)
    User->>Browser: Enters email & account password
    Browser->>API: POST /api/auth/login (email, password)
    API->>DB: Query user hash, verify rate limit & lockouts
    DB-->>API: User record (Argon2id password hash)
    API->>API: Verify password with Argon2id
    API-->>Browser: Set HttpOnly Session Cookie + Return User Info & Crypto Salt

    Note over User, DB: PHASE 2: Vault Unlock (Zero-Knowledge Key Derivation)
    User->>Browser: Enters Master Password
    Browser->>Crypto: deriveKey(masterPassword, userSalt, Argon2id)
    Crypto->>Crypto: Computes User KEK (256-bit)
    Browser->>API: GET /api/crypto/user-keys
    API-->>Browser: Encrypted User Private Key Blob
    Browser->>Crypto: decryptPrivateKey(blob, userKEK)
    Crypto->>Crypto: User Private Key (Curve25519) stored in transient memory
    Browser->>API: GET /api/vaults/:vaultId/key
    API-->>Browser: Wrapped Vault DEK
    Browser->>Crypto: unsealVaultDEK(wrappedKey, userPrivateKey)
    Crypto->>Crypto: Vault DEK (256-bit) ready in transient memory
    Note over Browser, Crypto: Vault Unlocked! Secrets can now be encrypted/decrypted locally.
```

---

## 2. Vault Item Encryption Flow (Create Credential)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Client UI
    participant Crypto as Crypto Engine
    participant API as Backend API
    participant DB as PostgreSQL Database
    participant Audit as Tamper-Evident Audit

    User->>UI: Types Username, Password, TOTP Seed, Notes
    UI->>UI: Validate form schema locally
    UI->>Crypto: encryptItemSecrets(secretsJson, vaultDEK)
    Crypto->>Crypto: Generate CSPRNG 24-byte Nonce
    Crypto->>Crypto: AEAD XChaCha20-Poly1305 Encrypt
    Crypto-->>UI: { ciphertext, nonce, crypto_version: "v1-xchacha20poly1305", key_version: 1 }
    UI->>UI: Scrub sensitive plaintext form fields
    UI->>API: POST /api/vaults/:vaultId/items (Metadata + Ciphertext payload)
    API->>API: Verify Authentication & Vault Write Permissions
    API->>DB: INSERT into vault_items (encrypted ciphertext only)
    API->>Audit: Record ITEM_CREATE (without secret fields)
    API-->>UI: 201 Created (Item ID, timestamps)
```

---

## 3. Read & Decrypt Credential Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Client UI
    participant Crypto as Crypto Engine
    participant API as Backend API
    participant DB as PostgreSQL Database

    User->>UI: Clicks item in client vault
    UI->>API: GET /api/vaults/:vaultId/items/:itemId
    API->>API: Check user tenant, client access & vault membership
    API->>DB: SELECT ciphertext, nonce, item_type, title FROM vault_items
    DB-->>API: Item record
    API-->>UI: Return encrypted record
    UI->>Crypto: decryptItemSecrets(ciphertext, nonce, vaultDEK)
    Crypto->>Crypto: Authenticated decryption with Poly1305 verification
    Crypto-->>UI: Decrypted secrets (Username, Password, TOTP)
    UI->>UI: Render in secure ephemeral state (masked password)
    User->>UI: Clicks "Copy Password"
    UI->>UI: Copy to clipboard + arm 30s auto-clear timer
```

---

## 4. Vault Sharing Flow (Re-wrapping for Recipient)

```mermaid
sequenceDiagram
    autonumber
    actor Owner
    participant OwnerUI as Owner Client
    participant API as Backend API
    participant RecipientUI as Recipient Client
    actor Recipient

    Owner->>OwnerUI: Shares Vault with Team Member (User B)
    OwnerUI->>API: GET /api/users/:userBId/public-key
    API-->>OwnerUI: User B Curve25519 Public Key
    OwnerUI->>OwnerUI: crypto_box_seal(vaultDEK, userBPublicKey)
    OwnerUI->>API: POST /api/vaults/:vaultId/members (userBId, role, wrappedKey)
    API->>API: Verify Owner is admin/owner
    API-->>OwnerUI: Success
    Recipient->>RecipientUI: Logs in & unlocks vault
    RecipientUI->>API: GET /api/vaults/:vaultId/key
    API-->>RecipientUI: Wrapped Key for Recipient
    RecipientUI->>RecipientUI: crypto_box_seal_open(wrappedKey, recipientPrivateKey)
    RecipientUI->>RecipientUI: Recipient now holds Vault DEK locally!
```

---

## 5. Key Rotation Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant Client as Admin Client
    participant API as Backend API
    participant DB as Database

    Admin->>Client: Triggers "Rotate Vault Encryption Key"
    Client->>API: GET /api/vaults/:vaultId/items (All encrypted items)
    API-->>Client: All vault items (key_version = N)
    Client->>Client: Decrypt all items using old Vault DEK (N)
    Client->>Client: Generate fresh 256-bit random Vault DEK (N+1)
    Client->>Client: Re-encrypt all items with new DEK & fresh nonces
    Client->>API: GET /api/vaults/:vaultId/members/public-keys
    API-->>Client: Public keys of all active vault members
    Client->>Client: Wrap new DEK for each active member
    Client->>API: POST /api/vaults/:vaultId/rotate-key (re-encrypted items + wrapped keys)
    API->>DB: Atomically update items & wrapped keys in a single transaction
    API-->>Client: Vault Key Rotation Complete (key_version = N+1)
```

---

## 6. Incident Lockdown Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant UI as Admin UI
    participant API as Backend API
    participant DB as Database

    Admin->>UI: Initiates Emergency Organization Lockdown
    UI->>API: POST /api/org/lockdown (Re-auth password + TOTP confirmation)
    API->>API: Verify super-admin credentials
    API->>DB: UPDATE organizations SET lockdown_enabled = TRUE
    API->>DB: DELETE FROM sessions WHERE org_id = currentOrg (Terminate all sessions except admin)
    API->>DB: Revoke all export & share tokens
    API->>DB: INSERT into audit_logs (EVENT_LOCKDOWN_TRIGGERED)
    API-->>UI: Lockdown Active: All standard operations frozen
```
