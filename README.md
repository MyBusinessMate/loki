# Loki — Production-Grade Agency Password Manager

Loki is a security-critical, zero-knowledge, self-hosted agency password and credential manager. It is designed so that even in the event of a full database leak, unencrypted backup theft, or API server compromise, client secrets remain undecryptable without client-side master passwords and private keys.

---

## 1. Key Highlights & Security Guarantees
- **True Zero-Knowledge Client Encryption**: Sensitive fields (passwords, usernames, TOTP secrets, notes) are encrypted client-side using **XChaCha20-Poly1305** with 24-byte random nonces before transmission.
- **Audited Argon2id Key Derivation**: User KEKs (Key Encryption Keys) are derived using **Argon2id** (64MB memory, 3 passes, 256-bit output).
- **Asymmetric Key Wrapping**: Shared vaults utilize **Curve25519** box sealing (`crypto_box_seal` / `crypto_box_seal_open`) to wrap Vault DEKs (Data Encryption Keys) for team members.
- **Tamper-Evident Chained Audit Logs**: Every audit record is HMAC-SHA256 chained to its predecessor to prevent tampering.
- **Automatic Secret Redaction**: All audit log pipelines automatically scrub passwords, API keys, and tokens.
- **Incident Lockdown Mode**: Single-click kill switch instantly revokes all employee sessions and freezes export capabilities.
- **Minimalist Dark Monochrome Interface**: Engineered adhering to a high-contrast editorial aesthetic in pure black and white (`#000000` / `#ededed`), with zero generic fluff.

---

## 2. Quickstart

### Prerequisites
- Node.js >= 20.x
- npm >= 10.x

### Installation
```bash
git clone https://github.com/agency/loki.git
cd loki
npm install
```

### Running Tests
Run the comprehensive cryptographic, authorization, audit, and E2E security test suites:
```bash
npm run test
# or
npx vitest run
```

### Building for Production
```bash
npx vite build
```

---

## 3. Security Documentation Index
- [THREAT-MODEL.md](file:///c:/Users/techt/loki/THREAT-MODEL.md) — 36 explicit threat vectors analyzed with preventive, detection, and recovery controls.
- [CRYPTOGRAPHY.md](file:///c:/Users/techt/loki/CRYPTOGRAPHY.md) — Cryptographic primitives, key hierarchy, and AEAD serialization.
- [KEY-MANAGEMENT.md](file:///c:/Users/techt/loki/KEY-MANAGEMENT.md) — Key derivation, unwrap/wrap flows, and key rotation.
- [ARCHITECTURE.md](file:///c:/Users/techt/loki/ARCHITECTURE.md) — High-level system architecture and resource hierarchy.
- [AUTH-ARCHITECTURE.md](file:///c:/Users/techt/loki/AUTH-ARCHITECTURE.md) — Identity authentication vs zero-knowledge vault unlock.
- [AUTHORIZATION.md](file:///c:/Users/techt/loki/AUTHORIZATION.md) — Multi-tenant RBAC and database row-level access controls.
- [DATA-FLOW.md](file:///c:/Users/techt/loki/DATA-FLOW.md) — Mermaid diagrams for credential lifecycles.
- [SECURITY.md](file:///c:/Users/techt/loki/SECURITY.md) — Vulnerability reporting and security standards.
- [INCIDENT-RESPONSE.md](file:///c:/Users/techt/loki/INCIDENT-RESPONSE.md) — Lockdown triggers and triage workflows.
- [BACKUP-DISASTER-RECOVERY.md](file:///c:/Users/techt/loki/BACKUP-DISASTER-RECOVERY.md) — Encrypted backups and restoration procedures.
- [TESTING.md](file:///c:/Users/techt/loki/TESTING.md) — Complete test coverage matrix.
- [DEPLOYMENT.md](file:///c:/Users/techt/loki/DEPLOYMENT.md) — Hardened deployment with Docker and Nginx.
