export type OrgRole = 'timekeeper' | 'agent' | 'variant';

// Backward-compatibility alias during refactoring if needed:
export type LegacyRole = 'owner' | 'admin' | 'manager' | 'member' | 'auditor' | 'guest';

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
  companyEmail?: string;
  personalEmail?: string;
  phoneNumber?: string;
  roleInCompany?: string; // Business title e.g. "Social Media Director"
  assignedClients?: string[]; // Array of client IDs
  assignedPlatforms?: Record<string, string[]>; // Map clientId -> array of allowed platform names
  supervisingTimekeepers?: string[]; // Max 3 timekeeper user IDs ("Under observation of")
  createdByTimekeeperId?: string; // Timekeeper who created the account
  passwordHistory?: string[]; // Historical timestamps of password changes
  lastPasswordChangedAt?: string; // ISO date of last password change
  authCodeHash?: string; // Argon2id/SHA256 hash of secret authorization code (timekeepers only)
  authCodeSalt?: string;
  avatarUrl?: string; // Approved profile avatar image URL/path
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
  createdAt?: string;
  updatedAt?: string;
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

export interface DeletionRequest {
  id: string;
  clientId: string;
  clientName?: string;
  credentialId: string;
  platformName: string;
  requestedByUserId: string;
  requestedByEmail: string;
  reason: string;
  status: 'pending' | 'approved' | 'rejected';
  createdAt: string;
  reviewedBy?: string;
  reviewedAt?: string;
}

export interface PasswordOverrideRequest {
  id: string;
  clientId: string;
  credentialId: string;
  platformName?: string;
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
  usernameNonce?: string;
  url?: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface AllowedDomainRecord {
  domain: string;
  addedBy?: string;
  createdAt: string;
  updatedAt: string;
}

export interface PasswordHealthStats {
  total: number;
  strong: number;
  weak: number;
  compromisedOrReused: number;
}

export interface PlatformCountStat {
  platformName: string;
  count: number;
}

export interface AvatarOption {
  id: string;
  name: string;
  url: string;
  roleCategory?: OrgRole | 'all';
  isDefault?: boolean;
}

