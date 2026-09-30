# AUTHORIZATION.md: Multi-Tenant RBAC & Resource Authorization

## 1. Hierarchy of Authority
All authorization decisions occur strictly on the server:
```
Organization
  └── Client
        └── Vault
              └── Folder
                    └── Vault Item
```

## 2. Organization Roles (RBAC)

| Role | Client Access | Vault Read | Item Create/Edit | Item Reveal/Copy | Vault Share | Export | Key Rotate | Lockdown |
|---|---|---|---|---|---|---|---|---|
| **Owner** | Full | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Admin** | Full | Yes | Yes | Yes | Yes | Yes | Yes | No |
| **Manager** | Full | Yes | Yes | Yes | Yes | Yes | No | No |
| **Member** | Assigned Only | Assigned Only | Yes | Yes | No | No | No | No |
| **Auditor** | Read-Only | Read-Only | No | No | No | No | No | No |
| **Guest** | Assigned Read | Assigned Read | No | Yes | No | No | No | No |

## 3. Defense Against IDOR / BOLA (Threat T10, T11, T12)
- Server NEVER trusts client-supplied `organizationId` or `clientId`.
- Every SQL query enforces `WHERE org_id = context.orgId`.
- Even if an attacker manipulates a `vaultId` parameter to point to another tenant's vault, the query evaluates empty and returns a `403 Forbidden` error.
