export type OrgRole = 'owner' | 'admin' | 'manager' | 'member' | 'auditor' | 'guest';

export interface User {
  id: string;
  email: string;
  fullName: string;
  passwordHash: string; // Argon2id hash for account login
  kdfSalt: string;      // Hex salt for client-side Master Password KEK
  isActive: boolean;
  isSuspended: boolean;
  mfaEnabled: boolean;
  mfaSecret?: string;   // TOTP secret for login MFA
}

export interface UserCryptoKeyRecord {
  userId: string;
  publicKey: string;              // Base64 Curve25519
  encryptedPrivateKey: string;   // Base64 ciphertext
  nonce: string;                 // Base64 24-byte nonce
  cryptoVersion: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  lockdownEnabled: boolean;
  lockdownReason?: string;
  lockdownAt?: string;
}

export interface OrganizationMembership {
  id: string;
  orgId: string;
  userId: string;
  role: OrgRole;
  isActive: boolean;
}

export interface ClientEntity {
  id: string;
  orgId: string;
  name: string;
  identifier: string;
  description?: string;
  isArchived: boolean;
}

export interface Vault {
  id: string;
  orgId: string;
  clientId: string;
  name: string;
  description?: string;
  keyVersion: number;
  isArchived: boolean;
}

export interface VaultKeyWrapper {
  id: string;
  vaultId: string;
  userId: string;
  keyVersion: number;
  wrappedKey: string; // Sealed with recipient's public key
}

export interface VaultFolder {
  id: string;
  vaultId: string;
  name: string;
}

export type ItemType =
  | 'login'
  | 'api_key'
  | 'secure_note'
  | 'totp'
  | 'ssh_key'
  | 'database'
  | 'environment'
  | 'recovery_codes'
  | 'certificate'
  | 'custom';

export type RiskLevel = 'normal' | 'sensitive' | 'critical';

export interface VaultItem {
  id: string;
  vaultId: string;
  folderId?: string | null;
  itemType: ItemType;
  riskLevel: RiskLevel;
  title: string;
  url?: string;
  tags: string[];
  ciphertext: string;
  nonce: string;
  cryptoVersion: string;
  keyVersion: number;
  createdBy: string;
  isDeleted: boolean;
  createdAt: string;
  updatedAt: string;
  lastAccessedAt?: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  tokenHash: string;
  deviceName: string;
  ipAddress: string;
  userAgent: string;
  expiresAt: string;
  revoked: boolean;
  createdAt: string;
  lastActiveAt: string;
}

export interface AttachmentRecord {
  id: string;
  itemId: string;
  filename: string;
  mimeType: string;
  fileSizeBytes: number;
  ciphertextHash: string;
  nonce: string;
  storagePath: string;
  createdAt: string;
}

export interface PasswordOverrideRequest {
  id: string;
  clientId: string;
  credentialId: string;
  requestedByUserId: string;
  requestedByEmail: string;
  reason: string;
  status: 'pending' | 'approved' | 'rejected';
  createdAt: string;
  reviewedBy?: string;
  reviewedAt?: string;
}

export interface ClientPlatformKeyRecord {
  id: string;
  clientId: string;
  platformName: string;
  keyLabel?: string;
  passwordCiphertext: string;
  passwordNonce: string;
  usernameCiphertext?: string;
  url?: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}
