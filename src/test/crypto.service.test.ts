import { describe, it, expect, beforeAll } from 'vitest';
import { LokiCryptoService, getSodium } from '../crypto/crypto.service.js';

describe('LokiCryptoService Test Suite (Section 50 Security Verification)', () => {
  beforeAll(async () => {
    await getSodium();
  });

  it('TEST-CRYPTO-01: Encrypt then decrypt returns exact original plaintext', async () => {
    const vaultDEK = await LokiCryptoService.generateVaultDEK();
    const sensitivePayload = {
      username: 'client_admin',
      password: 'SuperSecretProductionPassword#2026',
      totp: 'JBSWY3DPEHPK3PXP',
      notes: 'Root access to production payment gateway',
    };

    const encrypted = await LokiCryptoService.encryptItem(sensitivePayload, vaultDEK);
    expect(encrypted.ciphertext).toBeDefined();
    expect(encrypted.nonce).toBeDefined();
    expect(encrypted.ciphertext).not.toContain('SuperSecretProductionPassword#2026');

    const decrypted = await LokiCryptoService.decryptItem(encrypted, vaultDEK);
    expect(decrypted).toEqual(sensitivePayload);
  });

  it('TEST-CRYPTO-02: Decryption with wrong key fails cryptographically', async () => {
    const keyA = await LokiCryptoService.generateVaultDEK();
    const keyB = await LokiCryptoService.generateVaultDEK();

    const encrypted = await LokiCryptoService.encryptItem({ secret: 'critical-key' }, keyA);
    await expect(LokiCryptoService.decryptItem(encrypted, keyB)).rejects.toThrow();
  });

  it('TEST-CRYPTO-03: Tampered ciphertext or tag fails authentication check', async () => {
    const vaultDEK = await LokiCryptoService.generateVaultDEK();
    const encrypted = await LokiCryptoService.encryptItem({ secret: 'data' }, vaultDEK);

    // Tamper with base64 ciphertext
    const rawBuffer = Buffer.from(encrypted.ciphertext, 'base64');
    rawBuffer[5] ^= 0xff; // Flip bits
    const tamperedPayload = {
      ...encrypted,
      ciphertext: rawBuffer.toString('base64'),
    };

    await expect(LokiCryptoService.decryptItem(tamperedPayload, vaultDEK)).rejects.toThrow();
  });

  it('TEST-CRYPTO-04: Modified nonce fails authentication check', async () => {
    const vaultDEK = await LokiCryptoService.generateVaultDEK();
    const encrypted = await LokiCryptoService.encryptItem({ secret: 'data' }, vaultDEK);

    const rawNonce = Buffer.from(encrypted.nonce, 'base64');
    rawNonce[0] ^= 0x01;
    const tamperedNoncePayload = {
      ...encrypted,
      nonce: rawNonce.toString('base64'),
    };

    await expect(LokiCryptoService.decryptItem(tamperedNoncePayload, vaultDEK)).rejects.toThrow();
  });

  it('TEST-CRYPTO-05: Argon2id KDF behaves deterministically for identical password & salt', async () => {
    const salt = await LokiCryptoService.generateSalt();
    const pass = 'masterPassword$ecure123!';

    const kek1 = await LokiCryptoService.deriveKEK(pass, salt);
    const kek2 = await LokiCryptoService.deriveKEK(pass, salt);

    expect(Buffer.from(kek1).toString('hex')).toBe(Buffer.from(kek2).toString('hex'));
  });

  it('TEST-CRYPTO-06: Different salt produces completely different KEK', async () => {
    const salt1 = await LokiCryptoService.generateSalt();
    const salt2 = await LokiCryptoService.generateSalt();
    const pass = 'masterPassword$ecure123!';

    const kek1 = await LokiCryptoService.deriveKEK(pass, salt1);
    const kek2 = await LokiCryptoService.deriveKEK(pass, salt2);

    expect(Buffer.from(kek1).toString('hex')).not.toBe(Buffer.from(kek2).toString('hex'));
  });

  it('TEST-CRYPTO-07: Key Wrapping (Sealing) and Unwrapping (Unsealing) works across asymmetric keypairs', async () => {
    const vaultDEK = await LokiCryptoService.generateVaultDEK();
    const userKeyPair = await LokiCryptoService.generateUserKeyPair();

    // Wrap vault DEK using user's public key
    const wrappedKey = await LokiCryptoService.wrapVaultDEK(vaultDEK, userKeyPair.publicKey);
    expect(wrappedKey).toBeDefined();

    // Recipient unwraps with own keypair
    const unwrappedDEK = await LokiCryptoService.unwrapVaultDEK(
      wrappedKey,
      userKeyPair.publicKey,
      userKeyPair.privateKey
    );

    expect(Buffer.from(unwrappedDEK).toString('hex')).toBe(Buffer.from(vaultDEK).toString('hex'));
  });

  it('TEST-CRYPTO-08: Unauthorized user keypair cannot unwrap sealed vault DEK', async () => {
    const vaultDEK = await LokiCryptoService.generateVaultDEK();
    const userAuthorized = await LokiCryptoService.generateUserKeyPair();
    const userAttacker = await LokiCryptoService.generateUserKeyPair();

    const wrappedKey = await LokiCryptoService.wrapVaultDEK(vaultDEK, userAuthorized.publicKey);

    // Attacker tries to unwrap
    await expect(
      LokiCryptoService.unwrapVaultDEK(wrappedKey, userAttacker.publicKey, userAttacker.privateKey)
    ).rejects.toThrow();
  });

  it('TEST-CRYPTO-09: User Private Key client-side encryption and recovery with KEK', async () => {
    const userKeyPair = await LokiCryptoService.generateUserKeyPair();
    const salt = await LokiCryptoService.generateSalt();
    const kek = await LokiCryptoService.deriveKEK('MyMasterPass#2026', salt);

    const encryptedPrivKeyPkg = await LokiCryptoService.encryptPrivateKey(userKeyPair.privateKey, kek);
    expect(encryptedPrivKeyPkg.encryptedPrivateKey).not.toBe(userKeyPair.privateKey);

    const decryptedPrivKey = await LokiCryptoService.decryptPrivateKey(encryptedPrivKeyPkg, kek);
    expect(decryptedPrivKey).toBe(userKeyPair.privateKey);
  });

  it('TEST-CRYPTO-10: CSPRNG Password Generator produces strong high-entropy strings', () => {
    const pwd1 = LokiCryptoService.generatePassword({ length: 32 });
    const pwd2 = LokiCryptoService.generatePassword({ length: 32 });
    expect(pwd1.length).toBe(32);
    expect(pwd2.length).toBe(32);
    expect(pwd1).not.toBe(pwd2);
  });
});
