# Loki Role & Permission Governance Specification

This document defines the canonical role system, permission matrix, supervisory hierarchies, and scoping rules for Loki.

---

## 1. Canonical Three-Role System

Loki enforces exactly **THREE** application roles across the UI, API authorization, database records, and Firestore rules:

1. **`timekeeper`** (replaces legacy `admin` / `owner`):
   Highest administrative authority. Governs organization settings, user lifecycle, client assignments, platform secrets, supervisor relations, and emergency lockdown.
2. **`agent`** (replaces legacy `manager` / `member`):
   Client account manager. Operates strictly within assigned clients and assigned platforms. Can create and edit platform credentials (requiring old password verification). Deletions require either timekeeper review or immediate emergency authorization via a supervising timekeeper's authorization code.
3. **`variant`** (replaces legacy `viewer` / `auditor` / `guest`):
   Read-only auditor. Can view permitted client details, reveal passwords in memory, and copy decrypted secrets to the clipboard. Cannot create, edit, or delete any credentials or users.

---

## 2. Authoritative Permission Matrix (Section 63)

| Action | Timekeeper | Agent | Variant |
|---|:---:|:---:|:---:|
| Manage users (Create, edit, suspend, delete) | **Yes** | No | No |
| Manage roles & role assignment | **Yes** | No | No |
| Assign clients to users | **Yes** | No | No |
| Assign platform-level permissions | **Yes** | No | No |
| Configure "Under Observation Of" supervisors | **Yes** | No | No |
| View client directory | **All** | Assigned Only | Assigned Only |
| View client platform credentials | **All** | Assigned & Permitted Only | Assigned & Permitted Only |
| Add client platform credentials | **Yes** | Assigned Only | No |
| Update client platform credentials | **Yes** | Assigned Only (Must verify old password) | No |
| Delete credential directly | **Yes** | No | No |
| Send credential deletion request | **Yes** | **Yes** | No |
| Immediate deletion with timekeeper code | **Yes** | **Yes** (Supervising TK only) | No |
| Review / approve deletion requests | **Yes** | No | No |
| Review / approve password overrides | **Yes** | No | No |
| Reset user password (Administrative override) | **Yes** (Creator TK only) | No | No |
| View audit trail | **Yes** | No | No |
| Trigger Emergency Organization Lockdown | **Yes** | No | No |

---

## 3. Scoping & Least-Privilege Hierarchy

Access is evaluated hierarchically at the most specific applicable level:

```
[ Organization Isolation ]
       │
       ▼
[ Client-Level Assignment ]
       │
       ├─► Timekeeper: Access to all agency clients
       └─► Agent / Variant: Access ONLY to clients explicitly in assignedClients
       │
       ▼
[ Platform-Level Scoping ]
       │
       ├─► If assignedPlatforms[clientId] is defined and non-empty:
       │     └─► User is granted access ONLY to the listed platforms (e.g. Instagram, Facebook)
       │     └─► All other platform credentials for that client are strictly DENIED
       └─► If assignedPlatforms[clientId] is empty/unspecified:
             └─► Access permitted to all platforms of that assigned client
```

---

## 4. "Under Observation Of" Supervisory Rules (Section 11-13)

- Every `agent` must have between **1 and 3** supervising `timekeepers`.
- If an agent requests immediate credential deletion using `delete-with-code`:
  1. The code must belong to an **active** Timekeeper listed in the agent's `supervisingTimekeepers`.
  2. If the Timekeeper has left the company, been deactivated, or downgraded, their code is immediately invalid.
  3. Codes belonging to unrelated Timekeepers (not supervising this agent) are rejected with HTTP 403.
  4. If an agent has zero active supervising Timekeepers, emergency code-based deletion is unavailable.

---

## 5. Administrative Role Downgrade (Section 14 & 52)

When a `timekeeper` is downgraded to `agent` or `variant`:
1. Administrative permissions are revoked immediately across all active sessions and JWT claims.
2. The user is stripped of Timekeeper capabilities in database records and caches.
3. Any active supervisory responsibilities ("Under observation of") are reassigned to remaining active Timekeepers.
4. A full audit event is permanently recorded in the immutable audit log.
