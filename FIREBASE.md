# Loki Firebase Architecture & Cloud NoSQL Specification

This document details the Firebase and Google Cloud Firestore integration for Loki.

---

## 1. Project Configuration & Isolation

- **Dedicated Isolated Project**: `loki-agency-vault`
- **Region**: Cloud Firestore Multi-Region / Standard
- **Isolation Guarantee**: Loki maintains strict isolation from any other agency or personal Google Cloud projects.

---

## 2. Dual Developer Workflow (Section 30)

Loki seamlessly supports both local and remote development paths without requiring hardcoded secrets:

### Path A: Direct Cloud / MCP Tooling Workflow
When running in an IDE or environment equipped with Firebase MCP or logged-in Google Cloud SDK credentials:
- MCP connects directly to the dedicated Firestore instance.
- Project IDs and web application configurations are automatically supplied via `firebaseConfig.ts`.

### Path B: Portable Environment Variable Workflow (`.env`)
When developing in CI/CD, staging, or without MCP access:
- Copy `.env.example` to `.env`.
- Supply standard environment variables:
  ```bash
  VITE_FIREBASE_PROJECT_ID=loki-agency-vault
  VITE_FIREBASE_API_KEY=AIzaSy...
  VITE_FIREBASE_AUTH_DOMAIN=loki-agency-vault.firebaseapp.com
  VITE_FIREBASE_STORAGE_BUCKET=loki-agency-vault.firebasestorage.app
  VITE_FIREBASE_MESSAGING_SENDER_ID=362141834407
  VITE_FIREBASE_APP_ID=1:362141834407:web:fcccca568b840ac0a68f82
  ```
- The application automatically falls back to these variables, requiring zero code modifications.

---

## 3. NoSQL Firestore Schema & Client Table Separation (Section 33)

To ensure strict tenant and client segregation, client platform credentials are stored in isolated sub-collections under each client document:

```
/clients/{clientId}
  ├── id: string (UUID)
  ├── name: string
  ├── identifier: string (slug)
  ├── description?: string
  ├── createdAt: ISO 8601 string
  └── /platforms/{platformCredentialId}  <-- Separate NoSQL Platform Table
        ├── id: string (UUID)
        ├── clientId: string
        ├── platformName: string (e.g. "Instagram", "Shopify Admin")
        ├── keyLabel?: string
        ├── usernameCiphertext?: string
        ├── passwordCiphertext: string (XChaCha20-Poly1305 ciphertext)
        ├── passwordNonce: string (Base64 random 24-byte nonce)
        ├── url?: string
        ├── createdAt: ISO 8601 string
        └── updatedAt: ISO 8601 string

/users/{userId}
  ├── id: string
  ├── email: string
  ├── fullName: string
  ├── role: "timekeeper" | "agent" | "variant"
  ├── isActive: boolean
  ├── companyEmail?: string
  ├── personalEmail?: string
  ├── phoneNumber?: string
  ├── roleInCompany?: string
  ├── assignedClients: string[]
  ├── assignedPlatforms: Record<string, string[]>
  ├── supervisingTimekeepers: string[] (1-3 Timekeeper user IDs)
  ├── createdByTimekeeperId?: string
  └── lastPasswordChangedAt?: string

/deletion_requests/{requestId}
  ├── id: string
  ├── clientId: string
  ├── clientName: string
  ├── credentialId: string
  ├── platformName: string
  ├── requestedByUserId: string
  ├── requestedByEmail: string
  ├── reason: string
  ├── status: "pending" | "approved" | "rejected"
  ├── createdAt: ISO 8601 string
  ├── reviewedBy?: string
  └── reviewedAt?: string

/audit_logs/{auditId}
  ├── id: string
  ├── action: string
  ├── details: string
  ├── user: string (Email or User ID)
  └── timestamp: ISO 8601 string
```

---

## 4. Firestore Security Rules (Section 34)

Firestore rules located in `firestore.rules` enforce:
1. **Unauthenticated Read/Write Denial**: Anonymous requests are denied across all collections.
2. **Role Restrictions**: Mutation of `/users` and `/clients` requires Timekeeper authorization.
3. **Platform Credential Scoping**: Agents can only access `/clients/{clientId}/platforms` for clients explicitly assigned to their user record.
4. **Deletion Protection**: Non-Timekeeper roles cannot delete documents from `/platforms` directly; they must interact via `/deletion_requests`.
