# BACKUP-DISASTER-RECOVERY.md: Backup & Disaster Recovery Architecture

## 1. Zero-Knowledge Backup Philosophy
In Loki, backups are designed under the core principle that:
> **Even if unencrypted database dumps and snapshots are exfiltrated by an attacker or rogue hosting provider, zero client credentials or secrets are compromised.**

All sensitive item fields, files, notes, and private keys remain encrypted with high-entropy cryptographic keys (XChaCha20-Poly1305 and Curve25519) that only authorized clients possess.

---

## 2. Backup Procedures

### Automated Database Snapshots
1. Daily full PostgreSQL database dump via `pg_dump`:
   ```bash
   pg_dump -Fc --no-acl --no-owner loki_production > /backups/loki_$(date +%Y%m%d_%H%M%S).dump
   ```
2. Backup files are immediately encrypted at rest using AES-256-GCM with an independent offsite KMS key before transmission to isolated cloud storage:
   ```bash
   openssl enc -aes-256-gcm -salt -in /backups/loki_*.dump -out /backups/loki_*.enc -pass file:/etc/loki/backup.key
   ```
3. Backup archives are pushed to immutable write-once-read-many (WORM) cloud object storage with 30-day versioning retention.

---

## 3. Disaster Recovery & Restoration Verification Protocol

To verify that backups are operational (Section 41):
1. **Provision Test Restoration Database**: Spin up an isolated PostgreSQL instance.
2. **Decrypt Archive**:
   ```bash
   openssl enc -d -aes-256-gcm -in loki_backup.enc -out loki_restore.dump -pass file:/etc/loki/backup.key
   ```
3. **Restore Database**:
   ```bash
   pg_restore --clean --if-exists -d loki_test loki_restore.dump
   ```
4. **Execute Cryptographic Verification Test**:
   - Run `npx vitest run src/test/audit.service.test.ts` on the restored database.
   - Verify audit trail HMAC chain integrity passes (`verifyChainIntegrity`).
   - Authenticate test user and verify local client unwrap and decrypt on restored test items.
