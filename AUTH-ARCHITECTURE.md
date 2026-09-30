# AUTH-ARCHITECTURE.md: Authentication & Session Lifecycle Architecture

## 1. Authentication vs Vault Unlock Boundary

| Property | Account Authentication | Vault Unlock |
|---|---|---|
| **Purpose** | Identity Verification & Session Issuance | Client-side Cryptographic Decryption of Secrets |
| **Credentials** | Email + Account Password + MFA (TOTP) | Master Password + Per-User KDF Salt |
| **Server Role** | Verifies Argon2id login hash, issues JWT session | Delivers ciphertext blobs and public keys only |
| **Output** | 15-minute Access Token + 7-day Refresh Token | Transient 256-bit KEK and Vault DEK in client memory |
| **Storage** | HttpOnly Cookie / Secure In-Memory Token | NEVER stored in browser storage (`localStorage`, `sessionStorage`, cookies) |

---

## 2. Session Management & Refresh Token Rotation
- **Token Lineage**: Every refresh token is single-use.
- **Reuse Detection Trigger**: If an expired or already-used refresh token is presented, the server treats it as token theft (Threat T23) and revokes the entire token family across all devices for that user.
- **Idle & Absolute Timeout**: Auto-lock runs after 5 minutes of inactivity; sessions expire after 7 days absolute.
