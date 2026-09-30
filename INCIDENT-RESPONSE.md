# INCIDENT-RESPONSE.md: Incident Response & Emergency Lockdown Playbook

## 1. Incident Classification Levels

| Severity | Definition | Examples | SLA |
|---|---|---|---|
| **SEV-1 (Critical)** | Active account compromise, suspect employee device stolen, unauthorized export | Stolen session token, employee laptop stolen with vault unlocked | Immediate (< 15 mins) |
| **SEV-2 (High)** | Tampered audit signature, brute force attempt bursts | DB hash chain failure, failed login rate-limit trip | 1 hour |
| **SEV-3 (Medium)** | Nonce anomalies, suspicious IP geolocation jump | User logged in from new country | 4 hours |

---

## 2. Emergency Organization Lockdown Procedure (SEV-1)
1. **Trigger Lockdown**:
   - Agency Owner calls `POST /api/org/lockdown` with reason payload.
2. **Automated Server Actions**:
   - Organization `lockdown_enabled` flag is set to `true`.
   - All active user sessions and refresh tokens across the organization are revoked immediately.
   - All credential exports and vault shares are hard-disabled at the API layer.
   - High-priority audit record `LOCKDOWN_MODE_ENABLED` is written to the chained ledger.
3. **Investigation & Forensic Steps**:
   - Inspect chained audit trail via `GET /api/audit-logs`.
   - Identify affected client vaults.
   - Force key rotation on all vaults previously accessible to compromised team members.
