# KEY-MANAGEMENT.md: Loki Key Lifecycle & Management Architecture

## 1. Key Hierarchy Breakdown

```
[ Master Password ]
       │
       ▼ (Argon2id + 16-byte CSPRNG Salt)
[ User KEK (256-bit) ]
       │
       ▼ (XChaCha20-Poly1305 Decrypt)
[ User Private Key (Curve25519) ]
       │
       ▼ (crypto_box_seal_open)
[ Vault DEK (256-bit) ]
       │
       ├─────────────────────────────────┐
       ▼ (XChaCha20-Poly1305)            ▼ (XChaCha20-Poly1305)
[ Item Secrets ]                 [ Encrypted Attachments ]
```

## 2. Key Lifecycle Stages

### Stage 1: Account Creation & Keypair Generation
1. Client generates 16-byte random salt via `sodium.randombytes_buf(16)`.
2. Client derives 256-bit User KEK using Argon2id (`timeCost: 3`, `memoryCost: 65536`, `hashLength: 32`).
3. Client generates Curve25519 keypair via `crypto_box_keypair()`.
4. Client encrypts Private Key using User KEK and a fresh 24-byte nonce.
5. Client transmits Public Key and Encrypted Private Key package to backend. Plaintext private key and KEK are scrubbed.

### Stage 2: Vault Creation & Key Wrapping
1. Client generates 256-bit random Vault DEK via CSPRNG.
2. Client wraps Vault DEK using Creator's Public Key (`crypto_box_seal`).
3. Vault record created on server; wrapped key stored in `vault_key_wrappers`.

### Stage 3: Vault Sharing (Team Access)
1. Creator requests recipient's Curve25519 public key.
2. Creator unseals Vault DEK in local memory.
3. Creator seals Vault DEK with recipient's public key.
4. Uploads recipient's wrapped key record to `/api/vaults/:vaultId/share`.

### Stage 4: Vault Key Rotation
1. Client generates new random Vault DEK (`key_version = N + 1`).
2. Client decrypts all active vault items with DEK $N$.
3. Client re-encrypts all items with DEK $N+1$ using fresh nonces.
4. Client wraps DEK $N+1$ for all active members.
5. Client submits batch re-encryption transaction to `/api/vaults/:vaultId/rotate-key`.
