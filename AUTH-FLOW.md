# Loki Agency Credential Manager: Authentication & Authorization Flow

This document details the exact end-to-end authentication, session management, and authorization flows implemented in Loki.

---

## 1. Authentication Flow

```
User
  │
  ▼
[ Login Screen ]  ──── (Email & Login Password)
  │
  ▼
[ Server: /api/auth/login ]
  │
  ├─► Lookup User Record by Email
  │     └─► Check Account Status (isActive === true, isSuspended === false)
  │
  ├─► Argon2id Hash Verification
  │     └─► argon2.verify(user.passwordHash, plainPassword)
  │     └─► If invalid: HTTP 401 Unauthorized
  │
  ├─► Fetch Active Organization Membership & Canonical Role
  │     └─► Canonical: 'timekeeper' | 'agent' | 'variant'
  │
  ├─► Session Generation
  │     ├─► Generate cryptographically secure Session ID (UUIDv4)
  │     ├─► Sign short-lived Access Token (JWT, RS256/EdDSA equivalent)
  │     └─► Generate high-entropy Refresh Token with single-use rotation tracking
  │
  └─► Return Auth Session Response
        └─► { user, tokens: { accessToken, refreshToken, expiresIn: 900 } }
```

---

## 2. Authorization Flow

```
Inbound API Request / Protected Route Access
  │
  ▼
[ Authorization Header: Bearer <accessToken> ]
  │
  ├─► Token Validation & Expiry Check
  │     └─► If invalid or expired: HTTP 401 Unauthorized
  │
  ├─► Emergency Lockdown Mode Check
  │     └─► If org.lockdownEnabled === true and user.role !== 'timekeeper':
  │           └─► Immediately reject (HTTP 423 Locked)
  │
  ├─► Session Active & Revocation Check
  │     └─► If session revoked in database: HTTP 401 Unauthorized
  │
  ├─► Role & Resource Scoping Check
  │     ├─► Check Client Assignment:
  │     │     - Timekeeper: Full access to all clients
  │     │     - Agent / Variant: Access ONLY if client is in user.assignedClients
  │     │
  │     ├─► Check Platform-Level Assignment:
  │     │     - If user.assignedPlatforms[clientId] is configured:
  │     │         Access restricted to specified platforms only
  │     │
  │     └─► Check Action Permission:
  │           - create / update: timekeeper, agent (variant DENIED)
  │           - delete: timekeeper direct; agent requires request or code
  │           - admin / user management: timekeeper ONLY
  │
  └─► Access Granted (Proceed to business logic)
```

---

## 3. User Login Password Flow (Argon2id)

```
User Password (Registration / Self-Service Change / Timekeeper Reset)
  │
  ▼
[ Complexity Validation (Section 20) ]
  ├─ Minimum 8, Maximum 30 characters
  ├─ At least 1 uppercase letter (A-Z)
  ├─ At least 1 lowercase letter (a-z)
  ├─ At least 1 numeric digit (0-9)
  └─ At least 1 special character (!@#$%^&* etc.)
  │
  ▼
[ Password Change Policy Check (Section 19) ]
  ├─ Quota: Maximum 3 changes per calendar month
  ├─ Cooldown: 3-day (72-hour) cooldown between self-changes
  └─ Exception: Supervising Timekeeper who created the user account can reset during cooldown
  │
  ▼
[ Argon2id Hashing ]
  ├─ Unique random 16-byte cryptographic salt generated
  ├─ Memory: 64 MB (65,536 KB), Iterations: 3, Parallelism: 4
  └─ Output: Salted Argon2id hash string ($argon2id$v=19$m=65536,t=3,p=4$...)
  │
  ▼
[ Storage in NoSQL Cloud Firestore / Database ]
  └─ Plaintext password is NEVER stored, logged, or cached.
```

---

## 4. Supervising Timekeeper Authorization Code Flow (Section 10-13)

```
Agent Requests Immediate Deletion of a Credential
  │
  ▼
Agent enters 6-8 character Authorization Code
  │
  ▼
[ Rate Limiting & Lockout Check ]
  └─ 5 failed attempts locks agent out for 5 minutes
  │
  ▼
[ Verification Against "Under Observation Of" Supervisors ]
  ├─ Retrieve agent.supervisingTimekeepers (1 to 3 timekeepers)
  ├─ Filter to ACTIVE Timekeepers in the same organization
  ├─ For each active supervisor:
  │    └─ Verify code against stored Argon2id hash/salt
  │
  ├─► If No Match or Unrelated Timekeeper:
  │     └─ Reject with HTTP 403 Forbidden, log failed audit event
  │
  └─► If Valid Supervising Timekeeper Code Match:
        ├─ Delete credential immediately from database & Firestore
        ├─ Record immutable audit event with supervising Timekeeper attribution
        └─ Return HTTP 200 OK
```
