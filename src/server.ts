import express, { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import cors from 'cors';
import { db } from './db/database.js';
import { LokiAuthService, AuthContext } from './auth/auth.service.js';
import { LokiAuthorizationService } from './auth/authorization.service.js';
import { LokiAuditService } from './audit/audit.service.js';
import { VaultItem, ClientEntity, Vault, VaultKeyWrapper, RiskLevel, ItemType, User, OrgRole } from './types/models.js';

export const app = express();

// Security Middleware (Section 38, 39)
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

// Anti-CSRF Custom Header Verification for mutating calls
app.use((req: Request, res: Response, next: NextFunction) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const csrfHeader = req.header('X-Loki-CSRF-Protection');
    if (!csrfHeader && !req.path.startsWith('/api/auth/login') && !req.path.startsWith('/api/auth/register')) {
      return res.status(403).json({ error: 'Missing required security header: X-Loki-CSRF-Protection' });
    }
  }
  next();
});

// Authentication Middleware
export interface AuthenticatedRequest extends Request {
  auth?: AuthContext;
}

export const requireAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.substring(7);
  try {
    const context = LokiAuthService.verifyAccessToken(token);
    req.auth = context;
    next();
  } catch (err: any) {
    return res.status(401).json({ error: err.message });
  }
};

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req: Request, res: Response) => {
  const { email, password, fullName, kdfSalt, publicKey, encryptedPrivateKey, privateKeyNonce } = req.body;
  if (!email || !password || !fullName || !kdfSalt || !publicKey || !encryptedPrivateKey || !privateKeyNonce) {
    return res.status(400).json({ error: 'Missing required registration parameters' });
  }

  if (db.findUserByEmail(email)) {
    return res.status(409).json({ error: 'User with this email already exists' });
  }

  const passwordHash = await LokiAuthService.hashLoginPassword(password);
  const userId = crypto.randomUUID();
  const orgId = crypto.randomUUID();

  // Create User
  const newUser = {
    id: userId,
    email,
    passwordHash,
    kdfSalt,
    fullName,
    isActive: true,
    isSuspended: false,
    mfaEnabled: false,
  };
  db.saveUser(newUser);

  // Store User Asymmetric Crypto Key Record
  db.saveUserCryptoKey({
    userId,
    publicKey,
    encryptedPrivateKey,
    nonce: privateKeyNonce,
    cryptoVersion: 'v1-xchacha20poly1305',
  });

  // Create Default Agency Organization
  const newOrg = {
    id: orgId,
    name: `${fullName}'s Agency`,
    slug: `org-${userId.substring(0, 8)}`,
    lockdownEnabled: false,
  };
  db.saveOrg(newOrg);

  // Assign Owner Membership
  db.saveMembership({
    id: crypto.randomUUID(),
    orgId,
    userId,
    role: 'owner',
    isActive: true,
  });

  // Issue Session Tokens
  const tokens = await LokiAuthService.createSession(newUser, orgId, 'owner', {
    ipAddress: req.ip,
    userAgent: req.header('user-agent'),
  });

  res.status(201).json({
    user: { id: newUser.id, email: newUser.email, fullName: newUser.fullName },
    tokens: { ...tokens, orgId },
  });
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = db.findUserByEmail(email);
  if (!user || !user.isActive || user.isSuspended) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const isValid = await LokiAuthService.verifyLoginPassword(user.passwordHash, password);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const membership = Array.from(db.memberships.values()).find(
    (m) => m.userId === user.id && m.isActive
  );
  if (!membership) {
    return res.status(403).json({ error: 'No active organization found' });
  }

  const tokens = await LokiAuthService.createSession(user, membership.orgId, membership.role, {
    ipAddress: req.ip,
    userAgent: req.header('user-agent'),
  });

  res.json({
    user: { id: user.id, email: user.email, fullName: user.fullName, kdfSalt: user.kdfSalt },
    tokens,
  });
});

// User self-service change account password
app.post('/api/auth/change-password', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }

  const user = db.findUserById(req.auth!.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const isOldValid = await LokiAuthService.verifyLoginPassword(user.passwordHash, oldPassword);
  if (!isOldValid) {
    return res.status(401).json({ error: 'Incorrect current password' });
  }

  const newHash = await LokiAuthService.hashLoginPassword(newPassword);
  user.passwordHash = newHash;
  db.saveUser(user);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'USER_PASSWORD_CHANGE',
    resourceType: 'user',
    resourceId: user.id,
    metadata: { email: user.email },
  });

  res.json({ success: true, message: 'Password updated successfully' });
});

// Admin endpoint: List all users in organization
app.get('/api/admin/users', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'manage_permissions');

  const members = db.listOrgMembers(req.auth!.orgId);
  const userList = members.map((m) => ({
    id: m.user.id,
    email: m.user.email,
    fullName: m.user.fullName,
    role: m.membership.role,
    isActive: m.user.isActive,
  }));

  res.json({ users: userList });
});

// Admin endpoint: Create/Invite a new user with email, initial password, and role
app.post('/api/admin/users', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'manage_permissions');

  const { email, password, fullName, role } = req.body;
  if (!email || !password || !fullName || !role) {
    return res.status(400).json({ error: 'Email, initial password, full name, and role are required' });
  }

  if (db.findUserByEmail(email)) {
    return res.status(409).json({ error: 'User with this email already exists' });
  }

  const passwordHash = await LokiAuthService.hashLoginPassword(password);
  const newUserId = crypto.randomUUID();
  const kdfSalt = crypto.randomBytes(16).toString('hex');

  const newUser: User = {
    id: newUserId,
    email,
    fullName,
    passwordHash,
    kdfSalt,
    isActive: true,
    isSuspended: false,
    mfaEnabled: false,
  };
  db.saveUser(newUser);

  db.saveMembership({
    id: crypto.randomUUID(),
    orgId: req.auth!.orgId,
    userId: newUserId,
    role: role as OrgRole,
    isActive: true,
  });

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'USER_INVITE',
    resourceType: 'user',
    resourceId: newUserId,
    metadata: { email, role, fullName },
  });

  res.status(201).json({
    user: { id: newUser.id, email: newUser.email, fullName: newUser.fullName, role },
  });
});

// Retrieve User's Encrypted Private Key for Vault Unlock
app.get('/api/crypto/user-keys', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const keyRecord = db.getUserCryptoKey(req.auth!.userId);
  if (!keyRecord) {
    return res.status(404).json({ error: 'User crypto keys not initialized' });
  }
  res.json({
    publicKey: keyRecord.publicKey,
    encryptedPrivateKey: keyRecord.encryptedPrivateKey,
    nonce: keyRecord.nonce,
    cryptoVersion: keyRecord.cryptoVersion,
  });
});

// --- CLIENT ROUTES ---
app.get('/api/clients', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const clients = db.listClients(req.auth!.orgId);
  res.json({ clients });
});

app.post('/api/clients', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'create');
  const { name, identifier, description } = req.body;
  if (!name || !identifier) {
    return res.status(400).json({ error: 'Name and identifier are required' });
  }

  const client: ClientEntity = {
    id: crypto.randomUUID(),
    orgId: req.auth!.orgId,
    name,
    identifier,
    description,
    isArchived: false,
  };
  db.saveClient(client);

  res.status(201).json({ client });
});

// --- FIREBASE NOSQL CLIENT PLATFORM CREDENTIAL ROUTES ---
// Retrieve platform credentials from client's dedicated table
app.get('/api/clients/:clientId/platforms', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'read');

    const creds = db.listPlatformCredentials(clientId);
    res.json({ credentials: creds });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Add platform credential to client's dedicated table
app.post('/api/clients/:clientId/platforms', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'create');

    const { platformName, passwordCiphertext, passwordNonce, usernameCiphertext, url } = req.body;
    if (!platformName || !passwordCiphertext || !passwordNonce) {
      return res.status(400).json({ error: 'platformName, passwordCiphertext, and passwordNonce are required' });
    }

    const cred = {
      id: crypto.randomUUID(),
      clientId,
      platformName,
      passwordCiphertext,
      passwordNonce,
      usernameCiphertext,
      url,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: req.auth!.userId,
    };

    db.savePlatformCredential(cred);

    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'ITEM_CREATE',
      resourceType: 'platform_credential',
      resourceId: cred.id,
      metadata: { clientId, platformName },
    });

    res.status(201).json({ credential: cred });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Delete platform credential from client's dedicated table
app.delete('/api/clients/:clientId/platforms/:platformId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    const platformId = req.params.platformId as string;
    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'delete');

    db.deletePlatformCredential(clientId, platformId);

    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'ITEM_DELETE',
      resourceType: 'platform_credential',
      resourceId: platformId,
      metadata: { clientId },
    });

    res.json({ success: true });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Update/Edit platform credential in client's dedicated table
// Requirement: Must provide old password proof OR have an approved admin override
app.put('/api/clients/:clientId/platforms/:platformId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    const platformId = req.params.platformId as string;
    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'edit');

    const cred = db.getPlatformCredential(clientId, platformId);
    if (!cred) {
      return res.status(404).json({ error: 'Platform credential not found' });
    }

    const {
      platformName,
      newPasswordCiphertext,
      newPasswordNonce,
      oldPasswordCiphertextProof,
      overrideRequestId,
      usernameCiphertext,
      url,
    } = req.body;

    if (!newPasswordCiphertext || !newPasswordNonce) {
      return res.status(400).json({ error: 'newPasswordCiphertext and newPasswordNonce are required' });
    }

    // Role check: Admin or Owner can edit directly
    const isAdminOrOwner = ['owner', 'admin'].includes(req.auth!.role);

    if (!isAdminOrOwner) {
      // Non-admin MUST provide either verified old password proof OR an approved override request
      let hasApprovedOverride = false;
      if (overrideRequestId) {
        const override = db.getPasswordOverrideRequest(overrideRequestId);
        if (
          override &&
          override.credentialId === platformId &&
          override.requestedByUserId === req.auth!.userId &&
          override.status === 'approved'
        ) {
          hasApprovedOverride = true;
        }
      }

      if (!hasApprovedOverride) {
        if (!oldPasswordCiphertextProof) {
          return res.status(403).json({
            error: 'Old password verification required. If you do not know the old password, submit an admin override request.',
            requiresOverride: true,
          });
        }
        // Verify old ciphertext proof matches stored record
        if (oldPasswordCiphertextProof !== cred.passwordCiphertext) {
          return res.status(403).json({
            error: 'Invalid old password verification proof. Request admin override if unknown.',
            requiresOverride: true,
          });
        }
      }
    }

    // Apply updates
    if (platformName) cred.platformName = platformName;
    cred.passwordCiphertext = newPasswordCiphertext;
    cred.passwordNonce = newPasswordNonce;
    if (usernameCiphertext !== undefined) cred.usernameCiphertext = usernameCiphertext;
    if (url !== undefined) cred.url = url;
    cred.updatedAt = new Date().toISOString();

    db.savePlatformCredential(cred);

    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'ITEM_UPDATE',
      resourceType: 'platform_credential',
      resourceId: platformId,
      metadata: { clientId, platformName: cred.platformName },
    });

    res.json({ success: true, credential: cred });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Request Admin Override to change password when old password is unknown
app.post('/api/clients/:clientId/platforms/:platformId/request-override', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    const platformId = req.params.platformId as string;
    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'read');

    const cred = db.getPlatformCredential(clientId, platformId);
    if (!cred) {
      return res.status(404).json({ error: 'Platform credential not found' });
    }

    const { reason } = req.body;
    const overrideReq = {
      id: crypto.randomUUID(),
      clientId,
      credentialId: platformId,
      requestedByUserId: req.auth!.userId,
      requestedByEmail: req.auth!.email,
      reason: reason || 'Lost or forgot previous password',
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    db.savePasswordOverrideRequest(overrideReq);

    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'OVERRIDE_REQUEST_SUBMITTED',
      resourceType: 'override_request',
      resourceId: overrideReq.id,
      metadata: { clientId, credentialId: platformId, reason: overrideReq.reason },
    });

    res.status(201).json({ request: overrideReq });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Admin endpoint: List pending or all password override requests
app.get('/api/admin/override-requests', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'manage_permissions');

  const requests = db.listPasswordOverrideRequests();
  res.json({ requests });
});

// Admin endpoint: Review (approve or reject) a password override request
app.post('/api/admin/override-requests/:requestId/review', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'manage_permissions');

  const requestId = req.params.requestId as string;
  const { decision } = req.body; // 'approved' | 'rejected'

  if (!['approved', 'rejected'].includes(decision)) {
    return res.status(400).json({ error: "Decision must be 'approved' or 'rejected'" });
  }

  const override = db.getPasswordOverrideRequest(requestId);
  if (!override) {
    return res.status(404).json({ error: 'Override request not found' });
  }

  override.status = decision;
  override.reviewedBy = req.auth!.userId;
  override.reviewedAt = new Date().toISOString();

  db.savePasswordOverrideRequest(override);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: `OVERRIDE_REQUEST_${decision.toUpperCase()}`,
    resourceType: 'override_request',
    resourceId: requestId,
    metadata: { decision, requestedBy: override.requestedByEmail },
  });

  res.json({ success: true, request: override });
});

// --- VAULT ROUTES ---
app.get('/api/vaults', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const clientId = req.query.clientId as string | undefined;
  const vaults = db.listVaults(req.auth!.orgId, clientId);
  res.json({ vaults });
});

app.post('/api/vaults', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'create');
  const { clientId, name, description, wrappedKey } = req.body;
  if (!clientId || !name || !wrappedKey) {
    return res.status(400).json({ error: 'clientId, name, and wrappedKey are required' });
  }

  LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'create');

  const vaultId = crypto.randomUUID();
  const vault: Vault = {
    id: vaultId,
    orgId: req.auth!.orgId,
    clientId,
    name,
    description,
    keyVersion: 1,
    isArchived: false,
  };
  db.saveVault(vault);

  // Save creator's wrapped key
  const wrapper: VaultKeyWrapper = {
    id: crypto.randomUUID(),
    vaultId,
    userId: req.auth!.userId,
    keyVersion: 1,
    wrappedKey,
  };
  db.saveVaultKeyWrapper(wrapper);

  res.status(201).json({ vault, wrapper });
});

// Retrieve User's Wrapped Key for a Vault
app.get('/api/vaults/:vaultId/key', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const vaultId = req.params.vaultId as string;
    LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'read');

    const wrapper = db.getVaultKeyWrapper(vaultId, req.auth!.userId);
    if (!wrapper) {
      return res.status(404).json({ error: 'No wrapped key found for this user and vault' });
    }

    res.json({ wrapper });
  } catch (err: any) {
    return res.status(403).json({ error: err.message });
  }
});

// --- VAULT ITEM (CREDENTIALS) ROUTES ---
// Server NEVER receives plaintext secrets
app.get('/api/vaults/:vaultId/items', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const vaultId = req.params.vaultId as string;
  LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'read');

  const items = db.listVaultItems(vaultId);
  res.json({ items });
});

app.post('/api/vaults/:vaultId/items', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const vaultId = req.params.vaultId as string;
  LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'create');

  const { title, itemType, riskLevel, url, tags, ciphertext, nonce, keyVersion } = req.body;
  if (!title || !ciphertext || !nonce) {
    return res.status(400).json({ error: 'title, ciphertext, and nonce are required' });
  }

  const item: VaultItem = {
    id: crypto.randomUUID(),
    vaultId,
    title,
    itemType: (itemType as ItemType) || 'login',
    riskLevel: (riskLevel as RiskLevel) || 'normal',
    url,
    tags: tags || [],
    ciphertext,
    nonce,
    cryptoVersion: 'v1-xchacha20poly1305',
    keyVersion: keyVersion || 1,
    createdBy: req.auth!.userId,
    isDeleted: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.saveVaultItem(item);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'ITEM_CREATE',
    resourceType: 'item',
    resourceId: item.id,
    metadata: { title: item.title, riskLevel: item.riskLevel },
  });

  res.status(201).json({ item });
});

app.delete('/api/vaults/:vaultId/items/:itemId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const vaultId = req.params.vaultId as string;
  const itemId = req.params.itemId as string;
  LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'delete');

  const item = db.getVaultItem(itemId);
  if (item) {
    item.isDeleted = true;
    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'ITEM_DELETE',
      resourceType: 'item',
      resourceId: itemId,
      metadata: { title: item.title },
    });
  }

  res.json({ success: true });
});

// --- SHARING & KEY ROTATION ROUTES ---
// Get public key of a member to wrap a vault key
app.get('/api/users/:targetUserId/public-key', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const targetUserId = req.params.targetUserId as string;
  const keyRecord = db.getUserCryptoKey(targetUserId);
  if (!keyRecord) {
    return res.status(404).json({ error: 'User public key not found' });
  }
  res.json({ publicKey: keyRecord.publicKey });
});

// Add member to vault with wrapped DEK
app.post('/api/vaults/:vaultId/share', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const vaultId = req.params.vaultId as string;
  LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'share');

  const { targetUserId, wrappedKey, keyVersion } = req.body;
  if (!targetUserId || !wrappedKey) {
    return res.status(400).json({ error: 'targetUserId and wrappedKey are required' });
  }

  const wrapper: VaultKeyWrapper = {
    id: crypto.randomUUID(),
    vaultId,
    userId: targetUserId,
    keyVersion: keyVersion || 1,
    wrappedKey,
  };
  db.saveVaultKeyWrapper(wrapper);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'VAULT_SHARE',
    resourceType: 'vault',
    resourceId: vaultId,
    metadata: { sharedWithUserId: targetUserId },
  });

  res.status(201).json({ success: true, wrapper });
});

// Rotate Vault Key
app.post('/api/vaults/:vaultId/rotate-key', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const vaultId = req.params.vaultId as string;
  LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'rotate_key');

  const { newKeyVersion, reEncryptedItems, newWrappedKeys } = req.body;
  if (!newKeyVersion || !reEncryptedItems || !newWrappedKeys) {
    return res.status(400).json({ error: 'newKeyVersion, reEncryptedItems, and newWrappedKeys are required' });
  }

  const vault = db.getVault(vaultId);
  if (!vault) return res.status(404).json({ error: 'Vault not found' });

  // Atomic update
  vault.keyVersion = newKeyVersion;

  // Update re-encrypted items
  for (const it of reEncryptedItems) {
    const existing = db.getVaultItem(it.id);
    if (existing) {
      existing.ciphertext = it.ciphertext;
      existing.nonce = it.nonce;
      existing.keyVersion = newKeyVersion;
      existing.updatedAt = new Date().toISOString();
    }
  }

  // Update wrapped keys
  for (const wk of newWrappedKeys) {
    const wrapper: VaultKeyWrapper = {
      id: crypto.randomUUID(),
      vaultId,
      userId: wk.userId,
      keyVersion: newKeyVersion,
      wrappedKey: wk.wrappedKey,
    };
    db.saveVaultKeyWrapper(wrapper);
  }

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'KEY_ROTATION',
    resourceType: 'vault',
    resourceId: vaultId,
    metadata: { newKeyVersion, itemsUpdatedCount: reEncryptedItems.length },
  });

  res.json({ success: true, newKeyVersion });
});

// --- AUDIT & DASHBOARD ROUTES ---
app.get('/api/audit-logs', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'read');
  const logs = LokiAuditService.getOrgLogs(req.auth!.orgId);
  const integrity = LokiAuditService.verifyChainIntegrity(req.auth!.orgId);
  res.json({ logs, integrity });
});

// Emergency Lockdown Trigger
app.post('/api/org/lockdown', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  LokiAuthorizationService.authorizeAction(req.auth!.role, 'lockdown');
  const { reason } = req.body;

  const org = db.getOrg(req.auth!.orgId);
  if (!org) return res.status(404).json({ error: 'Organization not found' });

  org.lockdownEnabled = true;
  org.lockdownReason = reason || 'Security Incident Lockdown';
  org.lockdownAt = new Date().toISOString();

  // Terminate all sessions across organization except current owner session
  db.revokeAllOrgSessions(req.auth!.orgId, req.auth!.userId);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'LOCKDOWN_MODE_ENABLED',
    resourceType: 'organization',
    resourceId: req.auth!.orgId,
    metadata: { reason: org.lockdownReason },
  });

  res.json({ success: true, lockdown: true });
});
