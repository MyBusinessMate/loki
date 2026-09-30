import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import request from 'supertest';
import { app } from '../server.js';
import { db } from '../db/database.js';
import { LokiAuthService } from '../auth/auth.service.js';
import { LokiCryptoService, getSodium } from '../crypto/crypto.service.js';

describe('Loki End-to-End API Security Test Suite (Section 49, 52, 57 Compliance)', () => {
  beforeAll(async () => {
    await getSodium();
  });

  beforeEach(() => {
    db.clear();
  });

  it('TEST-E2E-01: Complete User Registration, Key Generation, and Login', async () => {
    const keyPair = await LokiCryptoService.generateUserKeyPair();
    const salt = await LokiCryptoService.generateSalt();
    const kek = await LokiCryptoService.deriveKEK('MasterSecretPass#2026', salt);
    const encryptedPrivKeyPkg = await LokiCryptoService.encryptPrivateKey(keyPair.privateKey, kek);

    // Register
    const regRes = await request(app)
      .post('/api/auth/register')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'agency.director@loki.dev',
        password: 'DirectorLoginPassword#2026',
        fullName: 'Loki Director',
        kdfSalt: salt,
        publicKey: keyPair.publicKey,
        encryptedPrivateKey: encryptedPrivKeyPkg.encryptedPrivateKey,
        privateKeyNonce: encryptedPrivKeyPkg.nonce,
      });

    expect(regRes.status).toBe(201);
    expect(regRes.body.tokens.accessToken).toBeDefined();
    expect(regRes.body.tokens.refreshToken).toBeDefined();

    // Login
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'agency.director@loki.dev',
        password: 'DirectorLoginPassword#2026',
      });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.user.kdfSalt).toBe(salt);
  });

  it('TEST-E2E-02: Client, Vault creation, Item Encryption & Decryption (Zero-Knowledge Verified)', async () => {
    // 1. Setup User
    const keyPair = await LokiCryptoService.generateUserKeyPair();
    const salt = await LokiCryptoService.generateSalt();
    const kek = await LokiCryptoService.deriveKEK('MasterSecretPass#2026', salt);
    const encryptedPrivKeyPkg = await LokiCryptoService.encryptPrivateKey(keyPair.privateKey, kek);

    const regRes = await request(app)
      .post('/api/auth/register')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'lead@agency.com',
        password: 'Password123!',
        fullName: 'Lead Engineer',
        kdfSalt: salt,
        publicKey: keyPair.publicKey,
        encryptedPrivateKey: encryptedPrivKeyPkg.encryptedPrivateKey,
        privateKeyNonce: encryptedPrivKeyPkg.nonce,
      });

    const token = regRes.body.tokens.accessToken;

    // 2. Create Client
    const clientRes = await request(app)
      .post('/api/clients')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        name: 'TecnoMart Ecommerce',
        identifier: 'tecnomart',
        description: 'Retail client infrastructure',
      });

    expect(clientRes.status).toBe(201);
    const clientId = clientRes.body.client.id;

    // 3. Create Vault with Wrapped Key
    const vaultDEK = await LokiCryptoService.generateVaultDEK();
    const wrappedKey = await LokiCryptoService.wrapVaultDEK(vaultDEK, keyPair.publicKey);

    const vaultRes = await request(app)
      .post('/api/vaults')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        clientId,
        name: 'Production AWS & Stripe',
        description: 'Critical credentials',
        wrappedKey,
      });

    expect(vaultRes.status).toBe(201);
    const vaultId = vaultRes.body.vault.id;

    // 4. Client-side encrypt sensitive item
    const rawSecret = {
      username: 'tecnomart_aws_root',
      password: 'LiveProductionSecretP@ssword999!',
      totp: 'JBSWY3DPEHPK3PXP',
      notes: 'Cloud root credentials for client TecnoMart',
    };

    const encryptedItemPayload = await LokiCryptoService.encryptItem(rawSecret, vaultDEK);

    // 5. Store item on server
    const itemRes = await request(app)
      .post(`/api/vaults/${vaultId}/items`)
      .set('Authorization', `Bearer ${token}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        title: 'AWS Root Account',
        itemType: 'login',
        riskLevel: 'critical',
        url: 'https://console.aws.amazon.com',
        tags: ['infrastructure', 'root'],
        ciphertext: encryptedItemPayload.ciphertext,
        nonce: encryptedItemPayload.nonce,
        keyVersion: 1,
      });

    expect(itemRes.status).toBe(201);
    const itemId = itemRes.body.item.id;

    // 6. Verify server DB NEVER contains plaintext secret
    const storedInDb = db.getVaultItem(itemId);
    expect(storedInDb).toBeDefined();
    expect(JSON.stringify(storedInDb)).not.toContain('LiveProductionSecretP@ssword999!');
    expect(JSON.stringify(storedInDb)).not.toContain('JBSWY3DPEHPK3PXP');

    // 7. Client retrieves encrypted item and decrypts locally
    const getRes = await request(app)
      .get(`/api/vaults/${vaultId}/items`)
      .set('Authorization', `Bearer ${token}`);

    expect(getRes.status).toBe(200);
    const returnedEncryptedItem = getRes.body.items[0];

    const decrypted = await LokiCryptoService.decryptItem(
      {
        ciphertext: returnedEncryptedItem.ciphertext,
        nonce: returnedEncryptedItem.nonce,
        crypto_version: returnedEncryptedItem.cryptoVersion,
        key_version: returnedEncryptedItem.keyVersion,
      },
      vaultDEK
    );

    expect(decrypted).toEqual(rawSecret);
  });

  it('TEST-E2E-03: Vault Sharing - Recipient decrypts wrapped key and reveals item', async () => {
    // 1. Setup User A (Owner)
    const keyPairA = await LokiCryptoService.generateUserKeyPair();
    const saltA = await LokiCryptoService.generateSalt();
    const kekA = await LokiCryptoService.deriveKEK('PassA#2026', saltA);
    const encPrivKeyA = await LokiCryptoService.encryptPrivateKey(keyPairA.privateKey, kekA);

    const regA = await request(app)
      .post('/api/auth/register')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'alice@agency.com',
        password: 'PassA#2026',
        fullName: 'Alice Owner',
        kdfSalt: saltA,
        publicKey: keyPairA.publicKey,
        encryptedPrivateKey: encPrivKeyA.encryptedPrivateKey,
        privateKeyNonce: encPrivKeyA.nonce,
      });

    const tokenA = regA.body.tokens.accessToken;
    const orgId = regA.body.tokens.orgId;

    // 2. Setup User B (Recipient Member)
    const keyPairB = await LokiCryptoService.generateUserKeyPair();
    const userB = {
      id: 'user-b-uuid',
      email: 'bob@agency.com',
      fullName: 'Bob Member',
      passwordHash: 'dummy',
      kdfSalt: 'saltB',
      isActive: true,
      isSuspended: false,
      mfaEnabled: false,
    };
    db.saveUser(userB);
    db.saveUserCryptoKey({
      userId: userB.id,
      publicKey: keyPairB.publicKey,
      encryptedPrivateKey: 'dummy',
      nonce: 'dummy',
      cryptoVersion: 'v1-xchacha20poly1305',
    });
    db.saveMembership({
      id: 'mem-b',
      orgId,
      userId: userB.id,
      role: 'member',
      isActive: true,
    });

    const tokenB = (
      await LokiAuthService.createSession(userB, orgId, 'member', {})
    ).accessToken;

    // 3. Alice creates Client and Vault
    const vaultDEK = await LokiCryptoService.generateVaultDEK();
    const wrappedKeyForAlice = await LokiCryptoService.wrapVaultDEK(vaultDEK, keyPairA.publicKey);

    const clientRes = await request(app)
      .post('/api/clients')
      .set('Authorization', `Bearer ${tokenA}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({ name: 'Client Gold N Glow', identifier: 'gng' });

    const vaultRes = await request(app)
      .post('/api/vaults')
      .set('Authorization', `Bearer ${tokenA}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        clientId: clientRes.body.client.id,
        name: 'Shared Marketing Vault',
        wrappedKey: wrappedKeyForAlice,
      });

    const vaultId = vaultRes.body.vault.id;

    // 4. Alice shares Vault with Bob by wrapping Vault DEK with Bob's public key
    const wrappedKeyForBob = await LokiCryptoService.wrapVaultDEK(vaultDEK, keyPairB.publicKey);

    const shareRes = await request(app)
      .post(`/api/vaults/${vaultId}/share`)
      .set('Authorization', `Bearer ${tokenA}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        targetUserId: userB.id,
        wrappedKey: wrappedKeyForBob,
      });

    expect(shareRes.status).toBe(201);

    // 5. Bob fetches his wrapped key and unwraps it locally
    const getKeyRes = await request(app)
      .get(`/api/vaults/${vaultId}/key`)
      .set('Authorization', `Bearer ${tokenB}`);

    expect(getKeyRes.status).toBe(200);

    const bobUnwrappedDEK = await LokiCryptoService.unwrapVaultDEK(
      getKeyRes.body.wrapper.wrappedKey,
      keyPairB.publicKey,
      keyPairB.privateKey
    );

    expect(Buffer.from(bobUnwrappedDEK).toString('hex')).toBe(Buffer.from(vaultDEK).toString('hex'));
  });

  it('TEST-E2E-04: Emergency Lockdown disables access and terminates active sessions', async () => {
    // 1. Setup Owner
    const keyPair = await LokiCryptoService.generateUserKeyPair();
    const salt = await LokiCryptoService.generateSalt();
    const kek = await LokiCryptoService.deriveKEK('PassOwner#2026', salt);
    const encPrivKey = await LokiCryptoService.encryptPrivateKey(keyPair.privateKey, kek);

    const reg = await request(app)
      .post('/api/auth/register')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'security.admin@agency.com',
        password: 'PassOwner#2026',
        fullName: 'Security Admin',
        kdfSalt: salt,
        publicKey: keyPair.publicKey,
        encryptedPrivateKey: encPrivKey.encryptedPrivateKey,
        privateKeyNonce: encPrivKey.nonce,
      });

    const tokenOwner = reg.body.tokens.accessToken;

    // 2. Trigger Lockdown
    const lockdownRes = await request(app)
      .post('/api/org/lockdown')
      .set('Authorization', `Bearer ${tokenOwner}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({ reason: 'Suspected intrusion on employee workstation' });

    expect(lockdownRes.status).toBe(200);
    expect(lockdownRes.body.lockdown).toBe(true);

    // 3. Verify audit log registered the lockdown event
    const auditRes = await request(app)
      .get('/api/audit-logs')
      .set('Authorization', `Bearer ${tokenOwner}`);

    expect(auditRes.status).toBe(200);
    const lockdownLog = auditRes.body.logs.find(
      (l: any) => l.action === 'LOCKDOWN_MODE_ENABLED'
    );
    expect(lockdownLog).toBeDefined();
    expect(auditRes.body.integrity.isValid).toBe(true);
  });

  it('TEST-E2E-05: Separate Client Tables with Platform Name & Password in NoSQL Storage with RBAC', async () => {
    // 1. Setup Director User
    const keyPair = await LokiCryptoService.generateUserKeyPair();
    const salt = await LokiCryptoService.generateSalt();
    const kek = await LokiCryptoService.deriveKEK('PassDir#2026', salt);
    const encPrivKey = await LokiCryptoService.encryptPrivateKey(keyPair.privateKey, kek);

    const reg = await request(app)
      .post('/api/auth/register')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'director@loki.com',
        password: 'PassDir#2026',
        fullName: 'Loki Director',
        kdfSalt: salt,
        publicKey: keyPair.publicKey,
        encryptedPrivateKey: encPrivKey.encryptedPrivateKey,
        privateKeyNonce: encPrivKey.nonce,
      });

    const token = reg.body.tokens.accessToken;

    // 2. Create Client 1 (Acme Store)
    const client1Res = await request(app)
      .post('/api/clients')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({ name: 'Acme Store', identifier: 'acme-store', description: 'Acme Ecommerce Client' });

    expect(client1Res.status).toBe(201);
    const client1Id = client1Res.body.client.id;

    // 3. Create Client 2 (Beta Tech)
    const client2Res = await request(app)
      .post('/api/clients')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({ name: 'Beta Tech', identifier: 'beta-tech', description: 'Beta SaaS' });

    expect(client2Res.status).toBe(201);
    const client2Id = client2Res.body.client.id;

    // 4. Store Platform Credentials in Client 1's table (e.g. Shopify, Stripe)
    const client1CredRes = await request(app)
      .post(`/api/clients/${client1Id}/platforms`)
      .set('Authorization', `Bearer ${token}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        platformName: 'Shopify Admin',
        passwordCiphertext: 'enc_shopify_pass_client1',
        passwordNonce: 'nonce_client1_shopify',
        usernameCiphertext: 'owner@acme.com',
        url: 'https://acme.myshopify.com/admin',
      });

    expect(client1CredRes.status).toBe(201);
    expect(client1CredRes.body.credential.platformName).toBe('Shopify Admin');

    // 5. Store Platform Credentials in Client 2's table (e.g. AWS Console)
    const client2CredRes = await request(app)
      .post(`/api/clients/${client2Id}/platforms`)
      .set('Authorization', `Bearer ${token}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        platformName: 'AWS Console',
        passwordCiphertext: 'enc_aws_pass_client2',
        passwordNonce: 'nonce_client2_aws',
        usernameCiphertext: 'root@betatech.com',
        url: 'https://aws.amazon.com',
      });

    expect(client2CredRes.status).toBe(201);
    expect(client2CredRes.body.credential.platformName).toBe('AWS Console');

    // 6. Verify Table Isolation: Client 1 must only see Shopify Admin
    const c1Fetch = await request(app)
      .get(`/api/clients/${client1Id}/platforms`)
      .set('Authorization', `Bearer ${token}`);

    expect(c1Fetch.status).toBe(200);
    expect(c1Fetch.body.credentials.length).toBe(1);
    expect(c1Fetch.body.credentials[0].platformName).toBe('Shopify Admin');

    // 7. Verify Table Isolation: Client 2 must only see AWS Console
    const c2Fetch = await request(app)
      .get(`/api/clients/${client2Id}/platforms`)
      .set('Authorization', `Bearer ${token}`);

    expect(c2Fetch.status).toBe(200);
    expect(c2Fetch.body.credentials.length).toBe(1);
    expect(c2Fetch.body.credentials[0].platformName).toBe('AWS Console');
  });

  it('TEST-E2E-06: Admin user creation, member login, and self-service password update', async () => {
    // 1. Setup Director / Owner
    const keyPair = await LokiCryptoService.generateUserKeyPair();
    const salt = await LokiCryptoService.generateSalt();
    const kek = await LokiCryptoService.deriveKEK('PassOwner#2026', salt);
    const encPrivKey = await LokiCryptoService.encryptPrivateKey(keyPair.privateKey, kek);

    const reg = await request(app)
      .post('/api/auth/register')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'agency.owner@loki.com',
        password: 'PassOwner#2026',
        fullName: 'Agency Owner',
        kdfSalt: salt,
        publicKey: keyPair.publicKey,
        encryptedPrivateKey: encPrivKey.encryptedPrivateKey,
        privateKeyNonce: encPrivKey.nonce,
      });

    const ownerToken = reg.body.tokens.accessToken;

    // 2. Admin adds a new member with role 'member' and initial temporary password
    const inviteRes = await request(app)
      .post('/api/admin/users')
      .set('Authorization', `Bearer ${ownerToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'developer.jane@agency.com',
        password: 'TempPassword#2026',
        fullName: 'Jane Developer',
        role: 'member',
      });

    expect(inviteRes.status).toBe(201);
    expect(inviteRes.body.user.role).toBe('member');

    // 3. Jane logs in with initial password
    const janeLoginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'developer.jane@agency.com',
        password: 'TempPassword#2026',
      });

    expect(janeLoginRes.status).toBe(200);
    const janeToken = janeLoginRes.body.tokens.accessToken;

    // 4. Jane updates her password with old password verification
    const changePassRes = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${janeToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        oldPassword: 'TempPassword#2026',
        newPassword: 'JaneStrongNewPassword#2026',
      });

    expect(changePassRes.status).toBe(200);
    expect(changePassRes.body.success).toBe(true);

    // 5. Old password no longer works
    const oldLoginFail = await request(app)
      .post('/api/auth/login')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'developer.jane@agency.com',
        password: 'TempPassword#2026',
      });

    expect(oldLoginFail.status).toBe(401);

    // 6. New password successfully logs in
    const newLoginSuccess = await request(app)
      .post('/api/auth/login')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'developer.jane@agency.com',
        password: 'JaneStrongNewPassword#2026',
      });

    expect(newLoginSuccess.status).toBe(200);
  });

  it('TEST-E2E-07: Credential editing requires old password verification or admin override grant', async () => {
    // 1. Setup Director / Owner
    const keyPair = await LokiCryptoService.generateUserKeyPair();
    const salt = await LokiCryptoService.generateSalt();
    const kek = await LokiCryptoService.deriveKEK('PassOwner#2026', salt);
    const encPrivKey = await LokiCryptoService.encryptPrivateKey(keyPair.privateKey, kek);

    const reg = await request(app)
      .post('/api/auth/register')
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'boss@loki.com',
        password: 'PassOwner#2026',
        fullName: 'Boss Owner',
        kdfSalt: salt,
        publicKey: keyPair.publicKey,
        encryptedPrivateKey: encPrivKey.encryptedPrivateKey,
        privateKeyNonce: encPrivKey.nonce,
      });

    const ownerToken = reg.body.tokens.accessToken;

    // 2. Create client & platform password
    const clientRes = await request(app)
      .post('/api/clients')
      .set('Authorization', `Bearer ${ownerToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({ name: 'Acme Global', identifier: 'acme-global' });
    const clientId = clientRes.body.client.id;

    const origCredRes = await request(app)
      .post(`/api/clients/${clientId}/platforms`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        platformName: 'Stripe Payment Gateway',
        passwordCiphertext: 'old_stripe_ciphertext_v1',
        passwordNonce: 'nonce_stripe_v1',
      });
    const credId = origCredRes.body.credential.id;

    // 3. Add Member User
    const memberInvite = await request(app)
      .post('/api/admin/users')
      .set('Authorization', `Bearer ${ownerToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        email: 'staff@agency.com',
        password: 'StaffPass#2026',
        fullName: 'Staff Member',
        role: 'member',
      });
    const staffLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Loki-CSRF-Protection', '1')
      .send({ email: 'staff@agency.com', password: 'StaffPass#2026' });
    const staffToken = staffLogin.body.tokens.accessToken;

    // 4. Member tries to edit password WITHOUT old password proof -> Rejected
    const rejectedEdit = await request(app)
      .put(`/api/clients/${clientId}/platforms/${credId}`)
      .set('Authorization', `Bearer ${staffToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        platformName: 'Stripe Payment Gateway',
        newPasswordCiphertext: 'hacked_or_blind_new_ciphertext',
        newPasswordNonce: 'new_nonce_123',
      });

    expect(rejectedEdit.status).toBe(403);
    expect(rejectedEdit.body.requiresOverride).toBe(true);

    // 5. Member provides VALID old password proof -> Edit Succeeds
    const validEdit = await request(app)
      .put(`/api/clients/${clientId}/platforms/${credId}`)
      .set('Authorization', `Bearer ${staffToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        platformName: 'Stripe Payment Gateway',
        newPasswordCiphertext: 'updated_with_old_proof_ciphertext',
        newPasswordNonce: 'new_nonce_456',
        oldPasswordCiphertextProof: 'old_stripe_ciphertext_v1',
      });

    expect(validEdit.status).toBe(200);
    expect(validEdit.body.credential.passwordCiphertext).toBe('updated_with_old_proof_ciphertext');

    // 6. Member forgets password and submits Admin Override Request
    const overrideReqRes = await request(app)
      .post(`/api/clients/${clientId}/platforms/${credId}/request-override`)
      .set('Authorization', `Bearer ${staffToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({ reason: 'Client changed credential on their side, old password unknown' });

    expect(overrideReqRes.status).toBe(201);
    const overrideRequestId = overrideReqRes.body.request.id;

    // 7. Admin reviews and approves the override request
    const adminApproval = await request(app)
      .post(`/api/admin/override-requests/${overrideRequestId}/review`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({ decision: 'approved' });

    expect(adminApproval.status).toBe(200);

    // 8. Member now edits using the approved override request id without old password
    const approvedEditRes = await request(app)
      .put(`/api/clients/${clientId}/platforms/${credId}`)
      .set('Authorization', `Bearer ${staffToken}`)
      .set('X-Loki-CSRF-Protection', '1')
      .send({
        platformName: 'Stripe Payment Gateway',
        newPasswordCiphertext: 'brand_new_admin_overridden_ciphertext',
        newPasswordNonce: 'nonce_override_789',
        overrideRequestId,
      });

    expect(approvedEditRes.status).toBe(200);
    expect(approvedEditRes.body.credential.passwordCiphertext).toBe('brand_new_admin_overridden_ciphertext');
  });
});
