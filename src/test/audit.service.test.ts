import { describe, it, expect, beforeEach } from 'vitest';
import { LokiAuditService } from '../audit/audit.service.js';

describe('LokiAuditService Test Suite (Section 25 & 71 Compliance)', () => {
  const orgId = 'org-agency-101';

  beforeEach(() => {
    LokiAuditService.clear();
  });

  it('TEST-AUDIT-01: Generates cryptographically chained audit events with valid initial integrity', async () => {
    const e1 = await LokiAuditService.recordEvent({
      orgId,
      userId: 'user-1',
      action: 'VAULT_CREATE',
      resourceType: 'vault',
      resourceId: 'vault-1',
    });

    const e2 = await LokiAuditService.recordEvent({
      orgId,
      userId: 'user-1',
      action: 'ITEM_CREATE',
      resourceType: 'item',
      resourceId: 'item-101',
    });

    expect(e2.prevHash).toBe(e1.signature);

    const verification = LokiAuditService.verifyChainIntegrity(orgId);
    expect(verification.isValid).toBe(true);
  });

  it('TEST-AUDIT-02: Detects tampering or modification of historical audit record signatures', async () => {
    await LokiAuditService.recordEvent({
      orgId,
      userId: 'user-1',
      action: 'USER_LOGIN',
      resourceType: 'user',
    });

    const maliciousTamperTarget = await LokiAuditService.recordEvent({
      orgId,
      userId: 'user-2',
      action: 'EXPORT_VAULT',
      resourceType: 'vault',
    });

    await LokiAuditService.recordEvent({
      orgId,
      userId: 'user-2',
      action: 'USER_LOGOUT',
      resourceType: 'user',
    });

    // Adversary tampers with the action to cover their tracks
    maliciousTamperTarget.action = 'VIEW_DASHBOARD';

    const verification = LokiAuditService.verifyChainIntegrity(orgId);
    expect(verification.isValid).toBe(false);
    expect(verification.brokenAtRecordId).toBe(maliciousTamperTarget.id);
  });

  it('TEST-AUDIT-03: Scrubber automatically redacts passwords and secrets from metadata', async () => {
    const event = await LokiAuditService.recordEvent({
      orgId,
      userId: 'user-admin',
      action: 'CREDENTIAL_UPDATE',
      resourceType: 'item',
      metadata: {
        itemTitle: 'Production Stripe Key',
        password: 'DangerousPlaintextPassword123!',
        apiKey: 'sk_live_secret12345',
        nested: {
          masterPassword: 'MasterPasswordNeverLog!',
          safeField: 'audit_ok',
        },
      },
    });

    expect(event.metadata.itemTitle).toBe('Production Stripe Key');
    expect(event.metadata.password).toBe('[REDACTED_BY_LOKI_AUDIT_FILTER]');
    expect(event.metadata.apiKey).toBe('[REDACTED_BY_LOKI_AUDIT_FILTER]');
    expect(event.metadata.nested.masterPassword).toBe('[REDACTED_BY_LOKI_AUDIT_FILTER]');
    expect(event.metadata.nested.safeField).toBe('audit_ok');
  });
});
