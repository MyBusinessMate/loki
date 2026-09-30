# ARCHITECTURE.md: Loki System Architecture

## 1. High-Level Architecture
Loki is built on an end-to-end zero-knowledge model adhering to the principle of least privilege, defense-in-depth, and strict multi-tenant isolation.

```
+-------------------------------------------------------------------------+
|                                CLIENT                                   |
|                                                                         |
|  +-----------------------+     +-------------------------------------+  |
|  |       React UI        | <-> |          Loki Crypto Engine         |  |
|  | (Minimalist Warm Mono |     |  - Argon2id KDF                     |  |
|  |  Design System)       |     |  - libsodium XChaCha20-Poly1305     |  |
|  |                       |     |  - Curve25519 Box Seal / Open       |  |
|  +-----------------------+     +-------------------------------------+  |
+---------------------------------------------------|---------------------+
                                                    | (HTTPS/TLS 1.3)
                                                    | Ciphertext / Metadata Only
+---------------------------------------------------|---------------------+
|                             API SERVER (Express/TS)                     |
|                                                                         |
|  +----------------------+      +-------------------------------------+  |
|  | Security Middleware  | ---> | Granular Authorization Engine       |  |
|  | - Helmet / CSP       |      | - Tenant Scoping                    |  |
|  | - Strict Rate Limit  |      | - Client -> Vault -> Item Checks    |  |
|  | - CSRF & Sanitizer   |      | - Lockdown Mode Circuit Breaker     |  |
|  +----------------------+      +-------------------------------------+  |
|                                                   |                     |
|                                +------------------+------------------+  |
|                                |                                     |  |
|                                v                                     v  |
|                     +---------------------+               +-------------+
|                     | PostgreSQL Database |               | Audit Engine|
|                     | (RLS + Tenant Schem)|               | (Hash-Chain)|
|                     +---------------------+               +-------------+
+-------------------------------------------------------------------------+
```

## 2. Resource Hierarchy
```
Organization (e.g. Acme Agency)
  ├── Users & Membership Roles (Owner, Admin, Manager, Member, Auditor, Guest)
  ├── Audit Trail (HMAC Hash Chained)
  └── Clients (e.g. TecnoMart, Gold N Glow, Internal)
        └── Vaults (e.g. Production, Marketing, Infrastructure)
              ├── Vault Key Wrappers (Encrypted for authorized users)
              ├── Folders (e.g. Google, Social, Cloud, Stripe)
              └── Vault Items (Logins, API Keys, TOTP, SSH Keys, Secure Notes)
                    └── Encrypted Attachments
```

## 3. Data Classification
1. **PUBLIC**: General system health status, documentation.
2. **INTERNAL**: Organization names, user emails, client names, folder titles, audit timestamps.
3. **CONFIDENTIAL**: Encrypted vault key wrappers, item metadata (item names, URLs, tag lists).
4. **SECRET / CRITICAL_SECRET**: Plaintext credentials, passwords, private keys, TOTP seeds, API secrets.
   - **Handling Rule**: NEVER exposed to backend or persistent storage; processed exclusively in client memory; wiped upon auto-lock.
