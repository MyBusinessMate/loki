# Loki — Agency Credential & Secret Governance Platform

Loki is a security-critical, zero-knowledge, agency credential and password management platform built for modern digital agencies.

It enforces strict tenant and client separation, client-side authenticated encryption (XChaCha20-Poly1305), salted Argon2id password hashing, a canonical three-role governance hierarchy (`timekeeper`, `agent`, `variant`), supervising timekeeper observations ("Under observation of"), emergency code-based credential deletions, and automated audit logging.

---

## 1. Core Architecture & Highlights

- **Canonical Three-Role Hierarchy**:
  - `timekeeper`: Full administrative authority over organization settings, user lifecycle, client assignments, platform access, observation supervisors, and emergency approvals.
  - `agent`: Client account manager restricted to assigned clients and assigned platforms. Credential editing requires verifying the existing password. Credential deletions require timekeeper approval or an active supervising timekeeper's authorization code.
  - `variant`: Read-only viewer for permitted clients/platforms. Revealing and copying decrypted secrets is permitted, but all mutation operations (create, update, delete) are strictly blocked.
- **Strict Cryptographic Boundary**:
  - **User Login Passwords**: Hashed with **Argon2id** (64MB memory, 3 passes, 256-bit output). Passwords are never reversibly encrypted or stored in plaintext.
  - **Client Platform Secrets**: Authenticated encryption via **XChaCha20-Poly1305** using fresh 24-byte nonces for every encryption operation. Plaintext exists only in client memory during decryption.
  - **Timekeeper Authorization Codes**: Stored as secure hashes with strict rate-limiting and audit event recording.
- **"Under Observation Of" Governance**:
  - Every Agent is supervised by 1 to 3 Timekeepers.
  - Immediate credential deletion (`delete-with-code`) is valid only when authorized by an active supervising Timekeeper.
- **Cloud NoSQL Storage & Client Isolation**:
  - Cloud Firestore integration with client separation where platform secrets reside in dedicated sub-tables (`/clients/{clientId}/platforms/{credentialId}`).
- **Route Guarding & 404 Isolation**:
  - Direct routes `/timekeeper`, `/agent`, and `/variant` return strict 404 Not Found responses for unauthorized roles.
- **Dual Developer Path**:
  - Works with Firebase MCP / direct cloud tooling, or portable environment variables (`.env` via `.env.example`).
- **Responsive Aesthetics**:
  - Built with clean dark green & black palette (`#080A09` / `#101412` / `#3FAF63`), Geist/Inter typography, and zero monospaced fonts. Fully responsive across 320px to 1280px+ viewports.

---

## 2. Quickstart

### Prerequisites
- Node.js >= 20.x
- npm >= 10.x

### Installation
```bash
git clone https://github.com/MyBusinessMate/loki.git
cd loki
npm install
```

### Environment Configuration
Copy the provided `.env.example` template:
```bash
cp .env.example .env
```
Fill in the isolated Firebase project credentials (`loki-agency-vault`).

### Running the Test Suite
Loki includes unit, integration, cryptographic, and end-to-end security test suites:
```bash
npm test
```

### Production Build
```bash
npm run build
```

---

## 3. Documentation Index

- [ROLE-PERMISSIONS.md](file:///c:/Users/techt/loki/ROLE-PERMISSIONS.md) — Canonical three-role model, permission matrix, and scoping rules.
- [AUTH-FLOW.md](file:///c:/Users/techt/loki/AUTH-FLOW.md) — End-to-end authentication, authorization, Argon2id hashing, and authorization code flows.
- [FIREBASE.md](file:///c:/Users/techt/loki/FIREBASE.md) — Cloud NoSQL Firestore architecture, client isolation, and dual workflow setup.
- [CRYPTOGRAPHY.md](file:///c:/Users/techt/loki/CRYPTOGRAPHY.md) — Cryptographic primitives, key hierarchy, and AEAD serialization.
- [SECURITY.md](file:///c:/Users/techt/loki/SECURITY.md) — Security policies, password limits, and vulnerability handling.
- [TESTING.md](file:///c:/Users/techt/loki/TESTING.md) — Test suite breakdown and verification logs.
- [THREAT-MODEL.md](file:///c:/Users/techt/loki/THREAT-MODEL.md) — Attack vector analysis and mitigations.
- [DATA-FLOW.md](file:///c:/Users/techt/loki/DATA-FLOW.md) — Data flow and lifecycle diagrams.
- [ARCHITECTURE.md](file:///c:/Users/techt/loki/ARCHITECTURE.md) — Architectural overview.
- [.env.example](file:///c:/Users/techt/loki/.env.example) — Safe environment variable template.
