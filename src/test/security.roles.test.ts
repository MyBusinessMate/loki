import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { app } from '../server.js';
import { db } from '../db/database.js';
import { LokiAuthService } from '../auth/auth.service.js';
import { LokiCryptoService } from '../crypto/crypto.service.js';
import { User } from '../types/models.js';

describe('Loki Roles, Observation, Security Rules & Cryptography Suite', () => {
  beforeEach(() => {
    db.clear();
  });

  // --- 1. PASSWORD COMPLEXITY & VALIDATION TESTS (Section 20) ---
  describe('Password Policy & Validation (Section 20)', () => {
    it('should reject passwords shorter than 8 characters', () => {
      const res = LokiAuthService.validatePasswordComplexity('Aa1!short');
      // 'Aa1!short' is 9 chars so it's valid, let's test 7 chars:
      const tooShort = LokiAuthService.validatePasswordComplexity('Aa1!sho');
      expect(tooShort.valid).toBe(false);
      expect(tooShort.error).toMatch(/at least 8 characters/);
    });

    it('should reject passwords longer than 30 characters', () => {
      const tooLong = LokiAuthService.validatePasswordComplexity('A1!abcdefghijklmnopqrstuvwxyz12345');
      expect(tooLong.valid).toBe(false);
      expect(tooLong.error).toMatch(/30 characters/i);
    });

    it('should reject passwords missing uppercase letters', () => {
      const res = LokiAuthService.validatePasswordComplexity('lowercase123!@#');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/uppercase/);
    });

    it('should reject passwords missing lowercase letters', () => {
      const res = LokiAuthService.validatePasswordComplexity('UPPERCASE123!@#');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/lowercase/);
    });

    it('should reject passwords missing numbers', () => {
      const res = LokiAuthService.validatePasswordComplexity('NoNumbersHere!@#');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/number/);
    });

    it('should reject passwords missing special characters', () => {
      const res = LokiAuthService.validatePasswordComplexity('NoSpecialChars1234');
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/special character/);
    });

    it('should accept valid compliant passwords', () => {
      const res = LokiAuthService.validatePasswordComplexity('SuperSecure#2026!');
      expect(res.valid).toBe(true);
      expect(res.error).toBeUndefined();
    });
  });

  // --- 2. USER PASSWORD LIMITS & COOLDOWN (Section 19) ---
  describe('Password Change Limits & Cooldown (Section 19)', () => {
    it('enforces 3 changes per calendar month and 3-day cooldown on self-service changes', () => {
      const user: User = {
        id: 'user-agent-01',
        email: 'agent01@agency.com',
        fullName: 'Agent Zero',
        passwordHash: 'dummy',
        kdfSalt: 'salt',
        isActive: true,
        isSuspended: false,
        mfaEnabled: false,
        createdByTimekeeperId: 'tk-boss-01',
        passwordHistory: [],
        lastPasswordChangedAt: undefined,
      };

      // 1. Initial change should be allowed
      let elig = LokiAuthService.verifyPasswordChangeEligibility(user, user.id);
      expect(elig.allowed).toBe(true);

      // Simulate a change performed 1 hour ago
      const oneHourAgo = new Date(Date.now() - 3600 * 1000).toISOString();
      user.lastPasswordChangedAt = oneHourAgo;
      user.passwordHistory = [oneHourAgo];

      // 2. Self change within 3 days is blocked by cooldown
      elig = LokiAuthService.verifyPasswordChangeEligibility(user, user.id);
      expect(elig.allowed).toBe(false);
      expect(elig.reason).toMatch(/cooldown active/i);

      // 3. Exception: Creator Timekeeper can reset during cooldown! (Section 19)
      const tkElig = LokiAuthService.verifyPasswordChangeEligibility(user, 'tk-boss-01');
      expect(tkElig.allowed).toBe(true);

      // 4. An unrelated timekeeper cannot bypass if not the creator
      const unrelatedElig = LokiAuthService.verifyPasswordChangeEligibility(user, 'tk-stranger-99');
      expect(unrelatedElig.allowed).toBe(false);

      // 5. Simulate 3 changes this month
      const now = new Date();
      const currentYear = now.getFullYear();
      const currentMonth = now.getMonth();
      const change1 = new Date(currentYear, currentMonth, 1, 1, 0, 0).toISOString();
      const change2 = new Date(currentYear, currentMonth, 1, 2, 0, 0).toISOString();
      const change3 = new Date(currentYear, currentMonth, 1, 3, 0, 0).toISOString();

      user.passwordHistory = [change1, change2, change3];

      // Exceeded 3 changes per month
      elig = LokiAuthService.verifyPasswordChangeEligibility(user, user.id);
      expect(elig.allowed).toBe(false);
      expect(elig.reason).toMatch(/monthly limit reached/i);
    });
  });

  // --- 3. TIMEKEEPER OBSERVATION & AUTHORIZATION CODE DELETION (Section 10, 11, 12, 13) ---
  describe('Authorization Code Deletion & Observation (Section 10-13)', () => {
    it('allows agent deletion using supervising timekeeper code, rejects unrelated or disabled code', async () => {
      const orgId = 'org-loki-primary';
      db.saveOrg({ id: orgId, name: 'Loki Primary', slug: 'loki-primary', lockdownEnabled: false });

      // 1. Create Supervising Timekeeper 1
      const tk1Pass = 'PassTkOne#2026';
      const tk1Hash = await LokiAuthService.hashLoginPassword(tk1Pass);
      const tk1CodeRecord = await LokiAuthService.hashAuthorizationCode('TK-AUTH-1111');
      const timekeeper1: User = {
        id: 'tk-supervisor-1',
        email: 'supervisor1@agency.com',
        fullName: 'Supervisor Timekeeper One',
        passwordHash: tk1Hash,
        kdfSalt: 'salt1',
        isActive: true,
        isSuspended: false,
        mfaEnabled: false,
        authCodeHash: tk1CodeRecord.hash,
        authCodeSalt: tk1CodeRecord.salt,
      };
      db.saveUser(timekeeper1);
      db.saveMembership({ id: 'mem-tk1', orgId, userId: timekeeper1.id, role: 'timekeeper', isActive: true });

      // 2. Create Inactive Supervising Timekeeper 2 (Section 13: Left company / disabled)
      const tk2CodeRecord = await LokiAuthService.hashAuthorizationCode('TK-AUTH-2222');
      const timekeeper2: User = {
        id: 'tk-supervisor-2',
        email: 'supervisor2@agency.com',
        fullName: 'Supervisor Timekeeper Two (Inactive)',
        passwordHash: 'dummy',
        kdfSalt: 'salt2',
        isActive: false, // Inactive!
        isSuspended: false,
        mfaEnabled: false,
        authCodeHash: tk2CodeRecord.hash,
        authCodeSalt: tk2CodeRecord.salt,
      };
      db.saveUser(timekeeper2);
      db.saveMembership({ id: 'mem-tk2', orgId, userId: timekeeper2.id, role: 'timekeeper', isActive: false });

      // 3. Create Unrelated Timekeeper (not supervising this agent)
      const tkUnrelatedCodeRecord = await LokiAuthService.hashAuthorizationCode('TK-AUTH-9999');
      const timekeeperUnrelated: User = {
        id: 'tk-unrelated',
        email: 'unrelated@agency.com',
        fullName: 'Unrelated Timekeeper',
        passwordHash: 'dummy',
        kdfSalt: 'saltU',
        isActive: true,
        isSuspended: false,
        mfaEnabled: false,
        authCodeHash: tkUnrelatedCodeRecord.hash,
        authCodeSalt: tkUnrelatedCodeRecord.salt,
      };
      db.saveUser(timekeeperUnrelated);
      db.saveMembership({ id: 'mem-tku', orgId, userId: timekeeperUnrelated.id, role: 'timekeeper', isActive: true });

      // 4. Create Client and Credential
      const clientId = 'client-nike';
      db.saveClient({ id: clientId, orgId, name: 'Nike Agency Client', identifier: 'nike', isArchived: false });

      const credId = 'cred-nike-ig';
      db.savePlatformCredential({
        id: credId,
        clientId,
        platformName: 'Instagram',
        passwordCiphertext: 'enc_nike_ig_secret',
        passwordNonce: 'nonce_nike',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: timekeeper1.id,
      });

      // 5. Create Agent with "Under Observation Of" = [tk-supervisor-1, tk-supervisor-2]
      const agentPass = 'AgentPass#2026';
      const agentHash = await LokiAuthService.hashLoginPassword(agentPass);
      const agentUser: User = {
        id: 'agent-alex',
        email: 'alex@agency.com',
        fullName: 'Alex Agent',
        passwordHash: agentHash,
        kdfSalt: 'saltA',
        isActive: true,
        isSuspended: false,
        mfaEnabled: false,
        assignedClients: [clientId],
        assignedPlatforms: { [clientId]: ['Instagram'] },
        supervisingTimekeepers: [timekeeper1.id, timekeeper2.id], // Under observation of
        createdByTimekeeperId: timekeeper1.id,
      };
      db.saveUser(agentUser);
      db.saveMembership({ id: 'mem-agent', orgId, userId: agentUser.id, role: 'agent', isActive: true });

      const agentTokens = await LokiAuthService.createSession(agentUser, orgId, 'agent', {});

      // A. Try deleting with unrelated Timekeeper code -> MUST FAIL (Section 12)
      const resUnrelated = await request(app)
        .post(`/api/clients/${clientId}/platforms/${credId}/delete-with-code`)
        .set('Authorization', `Bearer ${agentTokens.accessToken}`)
        .set('X-Loki-CSRF-Protection', '1')
        .send({ authorizationCode: 'TK-AUTH-9999' });

      expect(resUnrelated.status).toBe(403);
      expect(resUnrelated.body.error).toMatch(/Invalid authorization code/i);

      // B. Try deleting with inactive Timekeeper code (Section 13) -> MUST FAIL
      const resInactive = await request(app)
        .post(`/api/clients/${clientId}/platforms/${credId}/delete-with-code`)
        .set('Authorization', `Bearer ${agentTokens.accessToken}`)
        .set('X-Loki-CSRF-Protection', '1')
        .send({ authorizationCode: 'TK-AUTH-2222' });

      expect(resInactive.status).toBe(403);

      // C. Delete with active supervising Timekeeper code (Section 12) -> MUST SUCCEED
      const resSuccess = await request(app)
        .post(`/api/clients/${clientId}/platforms/${credId}/delete-with-code`)
        .set('Authorization', `Bearer ${agentTokens.accessToken}`)
        .set('X-Loki-CSRF-Protection', '1')
        .send({ authorizationCode: 'TK-AUTH-1111' });

      expect(resSuccess.status).toBe(200);
      expect(resSuccess.body.success).toBe(true);

      // Confirm credential was removed from database
      expect(db.getPlatformCredential(clientId, credId)).toBeUndefined();
    });
  });

  // --- 4. ROUTE GUARDING 404 BEHAVIOR (Section 35 & 36) ---
  describe('Route Guarding & 404 Not Found (Section 36)', () => {
    it('returns 404 for unauthorized role paths', async () => {
      const orgId = 'org-loki-primary';
      db.saveOrg({ id: orgId, name: 'Loki Primary', slug: 'loki-primary', lockdownEnabled: false });

      // Create Agent
      const agent: User = {
        id: 'user-agent-guarded',
        email: 'guarded.agent@agency.com',
        fullName: 'Guarded Agent',
        passwordHash: 'dummy',
        kdfSalt: 'salt',
        isActive: true,
        isSuspended: false,
        mfaEnabled: false,
      };
      db.saveUser(agent);
      db.saveMembership({ id: 'mem-g-a', orgId, userId: agent.id, role: 'agent', isActive: true });
      const agentTokens = await LokiAuthService.createSession(agent, orgId, 'agent', {});

      // Agent attempting /timekeeper or /project/timekeeper -> Returns 404
      const resTkGuard = await request(app)
        .get('/timekeeper')
        .set('Authorization', `Bearer ${agentTokens.accessToken}`);

      expect(resTkGuard.status).toBe(404);
      expect(resTkGuard.body.error).toMatch(/Not Found/i);

      const resProjTkGuard = await request(app)
        .get('/project/timekeeper')
        .set('Authorization', `Bearer ${agentTokens.accessToken}`);

      expect(resProjTkGuard.status).toBe(404);

      // Create Variant
      const variant: User = {
        id: 'user-variant-guarded',
        email: 'guarded.variant@agency.com',
        fullName: 'Guarded Variant',
        passwordHash: 'dummy',
        kdfSalt: 'salt',
        isActive: true,
        isSuspended: false,
        mfaEnabled: false,
      };
      db.saveUser(variant);
      db.saveMembership({ id: 'mem-g-v', orgId, userId: variant.id, role: 'variant', isActive: true });
      const variantTokens = await LokiAuthService.createSession(variant, orgId, 'variant', {});

      // Variant attempting /agent or /project/agent -> Returns 404
      const resAgentGuard = await request(app)
        .get('/agent')
        .set('Authorization', `Bearer ${variantTokens.accessToken}`);

      expect(resAgentGuard.status).toBe(404);

      // Timekeeper accessing /timekeeper -> 200 OK
      const tk: User = {
        id: 'user-tk-guarded',
        email: 'guarded.tk@agency.com',
        fullName: 'Guarded Timekeeper',
        passwordHash: 'dummy',
        kdfSalt: 'salt',
        isActive: true,
        isSuspended: false,
        mfaEnabled: false,
      };
      db.saveUser(tk);
      db.saveMembership({ id: 'mem-g-tk', orgId, userId: tk.id, role: 'timekeeper', isActive: true });
      const tkTokens = await LokiAuthService.createSession(tk, orgId, 'timekeeper', {});

      const resTkAllowed = await request(app)
        .get('/timekeeper')
        .set('Authorization', `Bearer ${tkTokens.accessToken}`);

      expect(resTkAllowed.status).toBe(200);
    });
  });

  // --- 5. CRYPTOGRAPHIC RANDOMIZATION & TAMPERING (Section 25 & 57) ---
  describe('Cryptographic Authenticated Encryption & Nonce Randomization (Section 25 & 57)', () => {
    it('produces distinct ciphertexts when encrypting identical plaintext twice due to fresh nonces', async () => {
      const vaultDEK = await LokiCryptoService.generateVaultDEK();
      const secret = 'Chatgpt26@';

      const encA = await LokiCryptoService.encryptItem({ password: secret }, vaultDEK);
      const encB = await LokiCryptoService.encryptItem({ password: secret }, vaultDEK);

      // Ciphertexts must NOT be identical (Section 25)
      expect(encA.ciphertext).not.toBe(encB.ciphertext);
      expect(encA.nonce).not.toBe(encB.nonce);

      // Decryption of both recovers exact original secret
      const decA = await LokiCryptoService.decryptItem<{ password: string }>(
        { ciphertext: encA.ciphertext, nonce: encA.nonce, crypto_version: 'v1-xchacha20poly1305', key_version: 1 },
        vaultDEK
      );
      const decB = await LokiCryptoService.decryptItem<{ password: string }>(
        { ciphertext: encB.ciphertext, nonce: encB.nonce, crypto_version: 'v1-xchacha20poly1305', key_version: 1 },
        vaultDEK
      );

      expect(decA.password).toBe(secret);
      expect(decB.password).toBe(secret);
    });

    it('rejects tampered ciphertext and modified nonces with cryptographic exception (Section 57)', async () => {
      const vaultDEK = await LokiCryptoService.generateVaultDEK();
      const secret = 'SecretPlatformPassword#2026';
      const enc = await LokiCryptoService.encryptItem({ password: secret }, vaultDEK);

      // Tamper ciphertext
      const tamperedCiphertext = enc.ciphertext.substring(0, enc.ciphertext.length - 4) + 'AAAA';

      await expect(
        LokiCryptoService.decryptItem(
          { ciphertext: tamperedCiphertext, nonce: enc.nonce, crypto_version: 'v1-xchacha20poly1305', key_version: 1 },
          vaultDEK
        )
      ).rejects.toThrow();

      // Tamper nonce
      const tamperedNonce = 'AAAAAAAAAAAAAAAAAAAA' + enc.nonce.substring(20);
      await expect(
        LokiCryptoService.decryptItem(
          { ciphertext: enc.ciphertext, nonce: tamperedNonce, crypto_version: 'v1-xchacha20poly1305', key_version: 1 },
          vaultDEK
        )
      ).rejects.toThrow();
    });
  });
});
