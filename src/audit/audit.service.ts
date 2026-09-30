import crypto from 'crypto';

export interface AuditRecord {
  id: string;
  orgId: string;
  userId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, any>;
  prevHash: string;
  signature: string;
  timestamp: string;
}

const FORBIDDEN_LOG_KEYS = [
  'password',
  'masterpassword',
  'secret',
  'apikey',
  'privatekey',
  'recoverycode',
  'token',
  'totp',
  'seed',
  'kek',
  'dek',
];

/**
 * Loki Audit Logging Engine with Cryptographic Hash Chaining
 * Section 25, 29, 71 compliance:
 * - Append-only hash chaining
 * - Automatic redaction of sensitive fields
 * - Anti-tampering signature
 */
export class LokiAuditService {
  private static hmacSecret = process.env.AUDIT_HMAC_SECRET || 'loki-production-audit-secret-hmac-2026';
  private static genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
  private static auditLogs: AuditRecord[] = [];

  /**
   * Sanitizes metadata to strictly forbid any accidental secret leaks
   */
  static sanitizeMetadata(data: Record<string, any>): Record<string, any> {
    const clean: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      const lower = key.toLowerCase();
      const isForbidden = FORBIDDEN_LOG_KEYS.some((f) => lower.includes(f));
      if (isForbidden) {
        clean[key] = '[REDACTED_BY_LOKI_AUDIT_FILTER]';
      } else if (typeof value === 'object' && value !== null) {
        clean[key] = this.sanitizeMetadata(value);
      } else {
        clean[key] = value;
      }
    }
    return clean;
  }

  /**
   * Compute row signature: HMAC-SHA256(prevHash + action + resourceType + resourceId + timestamp)
   */
  static computeSignature(prevHash: string, data: Omit<AuditRecord, 'signature' | 'prevHash'>): string {
    const serialized = `${prevHash}|${data.id}|${data.orgId}|${data.userId || ''}|${data.action}|${data.resourceType}|${data.resourceId || ''}|${data.timestamp}|${JSON.stringify(data.metadata)}`;
    return crypto.createHmac('sha256', this.hmacSecret).update(serialized).digest('hex');
  }

  /**
   * Create and record a chained audit event
   */
  static async recordEvent(params: {
    orgId: string;
    userId: string | null;
    action: string;
    resourceType: string;
    resourceId?: string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
    metadata?: Record<string, any>;
  }): Promise<AuditRecord> {
    const orgLogs = this.auditLogs.filter((l) => l.orgId === params.orgId);
    const lastRecord = orgLogs.length > 0 ? orgLogs[orgLogs.length - 1] : null;
    const prevHash = lastRecord ? lastRecord.signature : this.genesisHash;

    const sanitizedMeta = this.sanitizeMetadata(params.metadata || {});

    const partialRecord: Omit<AuditRecord, 'signature' | 'prevHash'> = {
      id: crypto.randomUUID(),
      orgId: params.orgId,
      userId: params.userId || null,
      action: params.action,
      resourceType: params.resourceType,
      resourceId: params.resourceId || null,
      ipAddress: params.ipAddress || null,
      userAgent: params.userAgent || null,
      metadata: sanitizedMeta,
      timestamp: new Date().toISOString(),
    };

    const signature = this.computeSignature(prevHash, partialRecord);

    const fullRecord: AuditRecord = {
      ...partialRecord,
      prevHash,
      signature,
    };

    this.auditLogs.push(fullRecord);
    return fullRecord;
  }

  /**
   * Verifies the cryptographic integrity of an organization's audit trail
   */
  static verifyChainIntegrity(orgId: string): { isValid: boolean; brokenAtRecordId?: string } {
    const orgLogs = this.auditLogs.filter((l) => l.orgId === orgId);
    let currentPrevHash = this.genesisHash;

    for (const record of orgLogs) {
      if (record.prevHash !== currentPrevHash) {
        return { isValid: false, brokenAtRecordId: record.id };
      }
      const expectedSig = this.computeSignature(record.prevHash, record);
      if (record.signature !== expectedSig) {
        return { isValid: false, brokenAtRecordId: record.id };
      }
      currentPrevHash = record.signature;
    }

    return { isValid: true };
  }

  static getOrgLogs(orgId: string): AuditRecord[] {
    return this.auditLogs.filter((l) => l.orgId === orgId);
  }

  static clear(): void {
    this.auditLogs = [];
  }
}
