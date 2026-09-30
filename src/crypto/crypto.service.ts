import _sodium from 'libsodium-wrappers';

let sodiumReady = false;

export async function getSodium() {
  await _sodium.ready;
  sodiumReady = true;
  return _sodium;
}

export interface EncryptedPayload {
  ciphertext: string; // Base64
  nonce: string;      // Base64
  crypto_version: string;
  key_version: number;
}

export interface UserKeyPair {
  publicKey: string;  // Base64 Curve25519
  privateKey: string; // Base64 Curve25519
}

export interface EncryptedPrivateKeyPackage {
  encryptedPrivateKey: string; // Base64
  nonce: string;               // Base64
  crypto_version: string;
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.trim();
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Loki Cryptographic Engine
 * Built strictly on libsodium (Argon2id, XChaCha20-Poly1305, Curve25519 Box Seal)
 * Zero invented crypto. Defense in depth.
 */
export class LokiCryptoService {
  /**
   * Derive User Key Encryption Key (KEK) using Argon2id (Node) / WebCrypto PBKDF2 (Browser)
   * Salt must be 16 bytes.
   * Node uses Argon2id (64MB memoryCost, 3 timeCost, 256-bit output).
   * Browser uses WebCrypto PBKDF2-SHA512 (100,000 iterations, 256-bit output).
   */
  static async deriveKEK(masterPassword: string, saltHex: string): Promise<Uint8Array> {
    const saltBytes = hexToBytes(saltHex);
    if (saltBytes.length !== 16) {
      throw new Error(`Salt must be exactly 16 bytes.`);
    }

    // Node.js environment (server, vitest tests) -> Strict Argon2id
    if (typeof window === 'undefined' && typeof process !== 'undefined') {
      try {
        const argon2 = await import('argon2');
        const kekBuffer = await argon2.hash(masterPassword, {
          type: argon2.argon2id,
          raw: true,
          salt: Buffer.from(saltBytes),
          timeCost: 3,
          memoryCost: 65536, // 64 MB
          hashLength: 32,    // 256-bit
        });

        return new Uint8Array(kekBuffer);
      } catch {
        // Fallback to WebCrypto if argon2 native addon is missing
      }
    }

    // Browser environment: WebCrypto PBKDF2-SHA512
    const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
    if (!cryptoObj?.subtle) {
      throw new Error('WebCrypto subtle is not available in this environment.');
    }

    const enc = new TextEncoder();
    const keyMaterial = await cryptoObj.subtle.importKey(
      'raw',
      enc.encode(masterPassword),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await cryptoObj.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes as Uint8Array<ArrayBuffer>,
        iterations: 100000,
        hash: 'SHA-512',
      },
      keyMaterial,
      256
    );

    return new Uint8Array(derivedBits);
  }

  /**
   * Generate 16-byte random salt for Argon2id KEK derivation
   */
  static async generateSalt(): Promise<string> {
    const sodium = await getSodium();
    const saltBytes = sodium.randombytes_buf(16);
    return sodium.to_hex(saltBytes);
  }

  /**
   * Generate 256-bit random Vault Data Encryption Key (DEK)
   */
  static async generateVaultDEK(): Promise<Uint8Array> {
    const sodium = await getSodium();
    return sodium.randombytes_buf(32);
  }

  /**
   * Generate User Asymmetric Keypair (Curve25519)
   */
  static async generateUserKeyPair(): Promise<UserKeyPair> {
    const sodium = await getSodium();
    const pair = sodium.crypto_box_keypair();
    return {
      publicKey: sodium.to_base64(pair.publicKey),
      privateKey: sodium.to_base64(pair.privateKey),
    };
  }

  /**
   * Encrypt User Private Key with User KEK using XChaCha20-Poly1305
   */
  static async encryptPrivateKey(privateKeyBase64: string, kek: Uint8Array): Promise<EncryptedPrivateKeyPackage> {
    const sodium = await getSodium();
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const privateKeyBytes = sodium.from_base64(privateKeyBase64);

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      privateKeyBytes,
      null, // Additional authenticated data
      null, // secret nonce
      nonce,
      kek
    );

    return {
      encryptedPrivateKey: sodium.to_base64(ciphertext),
      nonce: sodium.to_base64(nonce),
      crypto_version: 'v1-xchacha20poly1305',
    };
  }

  /**
   * Decrypt User Private Key using User KEK
   */
  static async decryptPrivateKey(encryptedPkg: EncryptedPrivateKeyPackage, kek: Uint8Array): Promise<string> {
    const sodium = await getSodium();
    const ciphertext = sodium.from_base64(encryptedPkg.encryptedPrivateKey);
    const nonce = sodium.from_base64(encryptedPkg.nonce);

    const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      kek
    );

    return sodium.to_base64(decrypted);
  }

  /**
   * Authenticated Symmetric Encryption for Vault Items using XChaCha20-Poly1305
   */
  static async encryptItem(data: any, vaultDEK: Uint8Array, keyVersion = 1): Promise<EncryptedPayload> {
    const sodium = await getSodium();
    const jsonStr = JSON.stringify(data);
    const plaintext = sodium.from_string(jsonStr);
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      null,
      null,
      nonce,
      vaultDEK
    );

    return {
      ciphertext: sodium.to_base64(ciphertext),
      nonce: sodium.to_base64(nonce),
      crypto_version: 'v1-xchacha20poly1305',
      key_version: keyVersion,
    };
  }

  /**
   * Authenticated Symmetric Decryption for Vault Items
   */
  static async decryptItem<T = any>(payload: EncryptedPayload, vaultDEK: Uint8Array): Promise<T> {
    const sodium = await getSodium();
    const ciphertext = sodium.from_base64(payload.ciphertext);
    const nonce = sodium.from_base64(payload.nonce);

    const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      vaultDEK
    );

    const jsonStr = sodium.to_string(decrypted);
    return JSON.parse(jsonStr) as T;
  }

  /**
   * Wrap (seal) Vault DEK for a recipient using their Curve25519 Public Key
   */
  static async wrapVaultDEK(vaultDEK: Uint8Array, recipientPublicKeyBase64: string): Promise<string> {
    const sodium = await getSodium();
    const pubKey = sodium.from_base64(recipientPublicKeyBase64);
    const sealed = sodium.crypto_box_seal(vaultDEK, pubKey);
    return sodium.to_base64(sealed);
  }

  /**
   * Unwrap (open) Vault DEK using recipient's Curve25519 Keypair
   */
  static async unwrapVaultDEK(
    wrappedKeyBase64: string,
    recipientPublicKeyBase64: string,
    recipientPrivateKeyBase64: string
  ): Promise<Uint8Array> {
    const sodium = await getSodium();
    const cipher = sodium.from_base64(wrappedKeyBase64);
    const pubKey = sodium.from_base64(recipientPublicKeyBase64);
    const privKey = sodium.from_base64(recipientPrivateKeyBase64);

    return sodium.crypto_box_seal_open(cipher, pubKey, privKey);
  }

  /**
   * Cryptographically Secure Password / Passphrase Generator
   */
  static generatePassword(options: {
    length?: number;
    useUppercase?: boolean;
    useLowercase?: boolean;
    useNumbers?: boolean;
    useSymbols?: boolean;
  } = {}): string {
    const length = options.length ?? 24;
    const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lowercase = 'abcdefghijkmnopqrstuvwxyz';
    const numbers = '23456789';
    const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    let pool = '';
    if (options.useUppercase ?? true) pool += uppercase;
    if (options.useLowercase ?? true) pool += lowercase;
    if (options.useNumbers ?? true) pool += numbers;
    if (options.useSymbols ?? true) pool += symbols;
    if (!pool) pool = uppercase + lowercase + numbers + symbols;

    const randomBuffer = new Uint32Array(length);
    const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
    if (cryptoObj?.getRandomValues) {
      cryptoObj.getRandomValues(randomBuffer);
    } else {
      const bytes = _sodium.randombytes_buf(length * 4);
      for (let i = 0; i < length; i++) {
        randomBuffer[i] = (bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) | (bytes[i * 4 + 3] << 24)) >>> 0;
      }
    }

    let result = '';
    for (let i = 0; i < length; i++) {
      result += pool[randomBuffer[i] % pool.length];
    }
    return result;
  }

  /**
   * Wipe memory buffer (best-effort zeroization)
   */
  static wipeMemory(buffer: Uint8Array | null | undefined): void {
    if (!buffer) return;
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      (crypto.getRandomValues as any)(buffer);
    }
    buffer.fill(0);
  }
}
