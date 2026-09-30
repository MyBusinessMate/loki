import { describe, it, expect, beforeEach } from 'vitest';
import { db } from '../db/database.js';
import { LokiAuthService } from '../auth/auth.service.js';
import { LokiAuthorizationService } from '../auth/authorization.service.js';

describe('Loki Security & Authorization Suite (Canonical Roles Compliance)', () => {
  const orgA = 'org-tenant-alpha';
  const orgB = 'org-tenant-beta';

  beforeEach(() => {
    db.clear();

    // Create Org A
    db.saveOrg({
      id: orgA,
      name: 'Alpha Agency',
      slug: 'alpha',
      lockdownEnabled: false,
    });

    // Create Org B
    db.saveOrg({
      id: orgB,
      name: 'Beta Agency',
      slug: 'beta',
      lockdownEnabled: false,
    });
  });

  it('TEST-SEC-01: Cross-organization access is strictly forbidden (Tenant Isolation)', async () => {
    const userA = {
      id: 'user-a',
      email: 'alice@alpha.com',
      fullName: 'Alice Alpha',
      passwordHash: 'dummy',
      kdfSalt: 'salt',
      isActive: true,
      isSuspended: false,
      mfaEnabled: false,
    };
    db.saveUser(userA);
    db.saveMembership({
      id: 'mem-a',
      orgId: orgA,
      userId: userA.id,
      role: 'agent',
      isActive: true,
    });

    const clientInOrgB = {
      id: 'client-in-b',
      orgId: orgB,
      name: 'Secret Client in Beta',
      identifier: 'scb',
      isArchived: false,
    };
    db.saveClient(clientInOrgB);

    const contextAlice = {
      userId: userA.id,
      email: userA.email,
      orgId: orgA,
      role: 'agent' as const,
      sessionId: 'sess-a',
    };

    // Alice attempts to access client belonging to Org B
    expect(() => {
      LokiAuthorizationService.authorizeClient(contextAlice, clientInOrgB.id);
    }).toThrow(/Forbidden: Client not found or access denied/);
  });

  it('TEST-SEC-02: Horizontal privilege escalation blocked (Agent accessing unassigned vault)', async () => {
    const userMember = {
      id: 'user-member',
      email: 'bob@alpha.com',
      fullName: 'Bob Agent',
      passwordHash: 'dummy',
      kdfSalt: 'salt',
      isActive: true,
      isSuspended: false,
      mfaEnabled: false,
    };
    db.saveUser(userMember);
    db.saveMembership({
      id: 'mem-bob',
      orgId: orgA,
      userId: userMember.id,
      role: 'agent',
      isActive: true,
    });

    const vaultPrivate = {
      id: 'vault-exec-finance',
      orgId: orgA,
      clientId: 'client-internal',
      name: 'Executive Payroll',
      keyVersion: 1,
      isArchived: false,
    };
    db.saveVault(vaultPrivate);

    const contextBob = {
      userId: userMember.id,
      email: userMember.email,
      orgId: orgA,
      role: 'agent' as const,
      sessionId: 'sess-bob',
    };

    // Bob has no key wrapper for this private vault
    expect(() => {
      LokiAuthorizationService.authorizeVault(contextBob, vaultPrivate.id);
    }).toThrow(/Forbidden: User is not authorized to access this vault/);
  });

  it('TEST-SEC-03: Vertical privilege escalation blocked (Variant attempting edit/delete)', async () => {
    const contextVariant = {
      userId: 'user-variant',
      email: 'viewer@alpha.com',
      orgId: orgA,
      role: 'variant' as const,
      sessionId: 'sess-variant',
    };

    expect(() => {
      LokiAuthorizationService.authorizeAction(contextVariant.role, 'delete');
    }).toThrow(/Forbidden: Role 'variant' lacks permission for 'delete'/);
  });

  it('TEST-SEC-04: Refresh token rotation revokes lineage upon token reuse', async () => {
    const user = {
      id: 'user-rot',
      email: 'user@alpha.com',
      fullName: 'User Rot',
      passwordHash: 'dummy',
      kdfSalt: 'salt',
      isActive: true,
      isSuspended: false,
      mfaEnabled: false,
    };
    db.saveUser(user);
    db.saveMembership({
      id: 'mem-rot',
      orgId: orgA,
      userId: user.id,
      role: 'agent',
      isActive: true,
    });

    // 1. Initial Login
    const tokens1 = await LokiAuthService.createSession(user, orgA, 'agent', {});

    // 2. Legitimate Refresh
    const tokens2 = await LokiAuthService.rotateRefreshToken(tokens1.refreshToken, {});
    expect(tokens2.accessToken).toBeDefined();

    // 3. Attacker attempts to reuse the already-consumed tokens1.refreshToken!
    await expect(LokiAuthService.rotateRefreshToken(tokens1.refreshToken, {})).rejects.toThrow(
      /Invalid or revoked refresh token/
    );

    // 4. Verify legitimate tokens2 session is now also revoked due to reuse detection
    const remainingActiveSessions = Array.from(db.sessions.values()).filter(
      (s) => s.userId === user.id && !s.revoked
    );
    expect(remainingActiveSessions.length).toBe(0);
  });

  it('TEST-SEC-05: Organization Lockdown mode rejects non-owner requests immediately', async () => {
    const user = {
      id: 'user-lock',
      email: 'user-lock@alpha.com',
      fullName: 'User Lock',
      passwordHash: 'dummy',
      kdfSalt: 'salt',
      isActive: true,
      isSuspended: false,
      mfaEnabled: false,
    };
    db.saveUser(user);
    db.saveMembership({
      id: 'mem-lock',
      orgId: orgA,
      userId: user.id,
      role: 'agent',
      isActive: true,
    });

    const tokens = await LokiAuthService.createSession(user, orgA, 'agent', {});

    // Admin triggers lockdown
    const org = db.getOrg(orgA);
    if (org) org.lockdownEnabled = true;

    // Subsequent access token verification fails
    expect(() => {
      LokiAuthService.verifyAccessToken(tokens.accessToken);
    }).toThrow(/Organization is currently in emergency lockdown mode/);
  });
});
