# CRYPTOGRAPHY.md: Loki Cryptographic Architecture

## 1. Selected Cryptographic Primitives & Justification

| Primitive / Operation | Algorithm / Standard | Library Implementation | Security Level / Parameters |
|---|---|---|---|
| **Key Derivation Function (KDF)** | Argon2id | `argon2` / `libsodium` | `opslimit: crypto_pwhash_OPSLIMIT_INTERACTIVE` (or 3 passes), `memlimit: 67108864` (64 MB), salt: 16 bytes CSPRNG |
| **Authenticated Symmetric Encryption (AEAD)** | XChaCha20-Poly1305-IETF | `libsodium-wrappers` (`crypto_aead_xchacha20poly1305_ietf_*`) | 256-bit key, 192-bit (24-byte) random nonce, 128-bit authentication tag |
| **Asymmetric Key Exchange / Wrapping** | X25519 (ECDH) + HKDF | `libsodium-wrappers` (`crypto_box_seal` / `crypto_box_curve25519xchacha20poly1305`) | Curve25519 (128-bit security level) |
| **User Keypair** | Curve25519 / Ed25519 | `libsodium-wrappers` (`crypto_box_keypair`) | Per-user public key stored on server; private key encrypted client-side with user KEK |
| **CSPRNG** | OS Entropy via WebCrypto / Sodium | `crypto.getRandomValues()` / `sodium.randombytes_buf` | Cryptographically secure random bytes |
| **Data Integrity / Hash Chaining** | SHA-256 HMAC / BLAKE2b | `libsodium-wrappers` (`crypto_generichash`) | 256-bit hash for tamper-evident audit logs and blind indexes |
| **Time-based One-Time Passwords (TOTP)** | RFC 6238 HMAC-SHA1 | `otplib` | 30s window, 6 digits, base32 secret encrypted at rest |

---

## 2. Key Hierarchy Architecture

```
                      [ Master Password (User Memory) ]
                                      |
                                      v (Argon2id + User Salt)
                            [ User KEK (256-bit) ]
                                      |
                   +------------------+------------------+
                   |                                     |
                   v                                     v
       Decrypt User Encrypted                Decrypt User Recovery
       Private Key Blob                      Wrapped Secret
                   |                                     |
                   v                                     v
         [ User Private Key ]                   [ Account Restored ]
            (Curve25519)
                   |
                   v (X25519 Unwrap)
          [ Vault DEK (256-bit) ]
                   |
       +-----------+-----------+
       |                       |
       v                       v
Decrypt Item Secrets     Decrypt File Attachments
(XChaCha20-Poly1305)     (XChaCha20-Poly1305)
```

1. **User Master Password**: Enters client memory during Vault Unlock only. Never leaves client, never stored in persistent browser storage (`localStorage` / `sessionStorage`), scrubbed from memory on auto-lock.
2. **User KEK (Key Encryption Key)**: Derived from the master password and a 16-byte random salt using Argon2id. Used solely to encrypt/decrypt the user's asymmetric private key.
3. **User Asymmetric Keypair (`crypto_box_keypair`)**:
   - `publicKey`: Stored on the server in `user_crypto_keys`. Available to team members to wrap/share vault keys.
   - `privateKey`: Encrypted client-side with the user KEK via XChaCha20-Poly1305, uploaded as an encrypted blob (`encrypted_private_key`, `nonce`). Never accessible to server.
4. **Vault DEK (Data Encryption Key)**:
   - 256-bit cryptographically random key generated per vault.
   - Wrapped for each authorized vault member using their respective public key (`crypto_box_seal`).
   - Stored in `vault_key_wrappers` table on server.
5. **Item & Attachment Encryption**:
   - Each vault item's sensitive fields (username, password, notes, totp, custom_fields) are serialized into a JSON buffer and encrypted with the Vault DEK using XChaCha20-Poly1305 with a freshly generated 24-byte random nonce.

---

## 3. Cryptographic Payload Specification

All encrypted payloads follow the standardized JSON structure:

```json
{
  "ciphertext": "<base64_encoded_ciphertext_and_tag>",
  "nonce": "<base64_encoded_24_byte_nonce>",
  "crypto_version": "v1-xchacha20poly1305",
  "key_version": 1
}
```

- **Algorithm**: `crypto_aead_xchacha20poly1305_ietf`
- **Nonce uniqueness**: 192-bit nonce space guarantees that random collisions are virtually impossible ($< 2^{-32}$ probability even after millions of encryptions).
- **Authentication Tag**: Poly1305 128-bit MAC is appended to ciphertext and verified before decryption returns any byte. Any bit flipping or truncation causes immediate cryptographic rejection.

---

## 4. Key Wrapping for Shared Vaults & Team Collaboration

When User A (Admin) grants User B access to a Vault:
1. Client A fetches User B's public key from `/api/users/:userId/public-key`.
2. Client A unwraps the Vault DEK in local memory using User A's private key.
3. Client A wraps the Vault DEK with User B's public key via `crypto_box_seal(vault_dek, user_b_public_key)`.
4. Client A uploads the wrapped key package to `/api/vaults/:vaultId/members/:userId/key`.
5. User B signs in, unlocks their private key using their master password, downloads the wrapped key package, and unseals the Vault DEK.
6. The server never observes the raw Vault DEK at any point in the transaction.

---

## 5. Safe Key Rotation Workflow
Vault keys can be rotated without service interruption:
1. Client generates new random Vault DEK (`key_version = N + 1`).
2. Client decrypts all active vault items with old DEK ($N$).
3. Client re-encrypts all items with new DEK ($N+1$) and fresh 24-byte nonces.
4. Client fetches public keys for all currently active members of the vault.
5. Client creates wrapped key packages for each active member using the new DEK.
6. Client submits the batch re-encryption transaction to the server.
7. Any user subsequently accessing the vault uses the versioned wrapped key corresponding to `key_version = N + 1`.
