# SECURITY.md: Loki Security Policy & Operational Hardening

## 1. Security Philosophy
Loki is designed as a zero-knowledge password and secret manager for client-servicing agencies. The core architecture dictates that even in the case of a complete database theft or root infrastructure takeover, raw client secrets cannot be decrypted without the client-side master password and private keys.

## 2. Reporting Security Vulnerabilities
If you discover a potential security vulnerability in Loki, do NOT disclose it publicly or open a public GitHub issue.
- Please email: `security@loki.dev`
- PGP Public Key fingerprint: `A1B2 C3D4 E5F6 0123 4567 89AB CDEF 0123 4567 89AB`
- We commit to acknowledging receipt within 24 hours and providing an evaluation or patch plan within 72 hours.

## 3. Threat Mitigation Summary
- **Zero Plaintext Secrets on Server**: Cryptographic operations occur strictly within client memory.
- **Argon2id Key Derivation**: High memory and iteration parameters prevent GPU/ASIC accelerated attacks.
- **Multi-Tenant Scoping**: All requests undergo server-side tenant, client, vault, and item authorization checks.
- **Append-Only Tamper-Evident Audit Trails**: Every audit event is chained via HMAC-SHA256 signatures.
