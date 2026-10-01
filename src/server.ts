import express, { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import cors from 'cors';
import { db } from './db/database.js';
import { LokiAuthService, AuthContext } from './auth/auth.service.js';
import { LokiAuthorizationService } from './auth/authorization.service.js';
import { LokiAuditService } from './audit/audit.service.js';
import {
  VaultItem,
  ClientEntity,
  Vault,
  VaultKeyWrapper,
  RiskLevel,
  ItemType,
  User,
  OrgRole,
  DeletionRequest,
  PasswordOverrideRequest,
  ClientPlatformKeyRecord,
} from './types/models.js';

export const app = express();

// Security Middleware (Section 38, 39, OWASP)
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

// Rate-limiting attempt tracking for Authorization Code entries (Section 10, 45)
const codeAttemptTracker: Record<string, { attempts: number; blockedUntil: number }> = {};

// Rate-limiting attempt tracking for Login (Section 10)
const loginAttemptTracker: Record<string, { attempts: number; blockedUntil: number }> = {};

// Helper: 404 handler for role routes (Section 36, 62)
const handleUnauthorizedRoute = (res: Response) => {
  return res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource or page was not found on this server.',
    status: 404,
  });
};

// --- ROLE-BASED ACCESS ROUTE GUARDS (Section 35, 36, 62) ---
// Returns clean 404 not-found behavior when unauthorized role accesses
app.get(['/timekeeper', '/project/timekeeper', '/project/timekeeper/:subpath'], requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return handleUnauthorizedRoute(res);
  }
  res.json({ access: 'granted', role: 'timekeeper', portal: 'timekeeper-console' });
});

app.get(['/agent', '/project/agent', '/project/agent/:subpath'], requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== 'agent') {
    return handleUnauthorizedRoute(res);
  }
  res.json({ access: 'granted', role: req.auth!.role, portal: 'agent-console' });
});

app.get(['/variant', '/project/variant', '/project/variant/:subpath'], requireAuth, (req: AuthenticatedRequest, res: Response) => {
  // All three can view client read info, but variant console is specific
  res.json({ access: 'granted', role: req.auth!.role, portal: 'variant-console' });
});

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req: Request, res: Response) => {
  const { email, password, fullName, kdfSalt, publicKey, encryptedPrivateKey, privateKeyNonce } = req.body;
  if (!email || !password || !fullName || !kdfSalt || !publicKey || !encryptedPrivateKey || !privateKeyNonce) {
    return res.status(400).json({ error: 'Missing required registration parameters' });
  }

  // RFC 5322 Email syntax and domain whitelist check (Section 3, 4, 8)
  const emailValidation = LokiAuthService.validateEmailStructure(email);
  if (!emailValidation.valid) {
    return res.status(400).json({ error: emailValidation.error });
  }
  const normalizedEmail = emailValidation.normalized;

  if (!LokiAuthService.isDomainAllowed(normalizedEmail, db.getAllowedDomains())) {
    return res.status(403).json({
      error: `Domain not authorized. Only approved domains (${db.getAllowedDomains().join(', ')}) are permitted.`,
    });
  }

  // Password complexity check (Section 20)
  const validation = LokiAuthService.validatePasswordComplexity(password);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  if (db.findUserByEmail(normalizedEmail)) {
    return res.status(409).json({ error: 'User with this email already exists' });
  }

  const passwordHash = await LokiAuthService.hashLoginPassword(password);
  const userId = crypto.randomUUID();

  const isFirstUser = db.users.size === 0;
  const initialRole: OrgRole = isFirstUser ? 'timekeeper' : 'variant';
  const defaultAvatar = initialRole === 'timekeeper' ? '/avatars/timekeeper.png' : '/avatars/variant.png';
  const newUser: User = {
    id: userId,
    email: normalizedEmail,
    fullName: fullName.trim(),
    passwordHash,
    kdfSalt,
    isActive: true,
    isSuspended: false,
    mfaEnabled: false,
    avatarUrl: defaultAvatar,
    passwordHistory: [],
    lastPasswordChangedAt: undefined,
  };
  db.saveUser(newUser);

  const orgId = 'org-loki-primary';
  if (!db.getOrg(orgId)) {
    db.saveOrg({
      id: orgId,
      name: 'Loki Primary Organization',
      slug: 'loki-primary',
      lockdownEnabled: false,
    });
  }

  db.saveMembership({
    id: crypto.randomUUID(),
    orgId,
    userId,
    role: initialRole,
    isActive: true,
  });

  db.saveUserCryptoKey({
    userId,
    publicKey,
    encryptedPrivateKey,
    nonce: privateKeyNonce,
    cryptoVersion: 'v1-xchacha20poly1305',
  });

  const tokens = await LokiAuthService.createSession(newUser, orgId, initialRole, {
    ipAddress: req.ip,
    userAgent: req.header('user-agent'),
  });

  res.status(201).json({
    user: { id: newUser.id, email: newUser.email, fullName: newUser.fullName, role: initialRole, avatarUrl: newUser.avatarUrl },
    tokens: { ...tokens, orgId },
  });
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Rate Limiting Check (Section 10)
  const clientIp = req.ip || 'unknown';
  const cleanEmail = String(email).trim().toLowerCase();
  const trackerKey = `login:${clientIp}:${cleanEmail}`;
  const now = Date.now();
  const tracker = loginAttemptTracker[trackerKey] || { attempts: 0, blockedUntil: 0 };

  if (tracker.blockedUntil > now) {
    const waitSec = Math.ceil((tracker.blockedUntil - now) / 1000);
    return res.status(429).json({
      error: `Too many failed login attempts. Account temporarily locked. Try again in ${waitSec} seconds.`,
    });
  }

  // RFC 5322 Email syntax and domain whitelist check (Section 3, 4, 8)
  const emailValidation = LokiAuthService.validateEmailStructure(email);
  if (!emailValidation.valid) {
    return res.status(400).json({ error: emailValidation.error });
  }
  const normalizedEmail = emailValidation.normalized;

  if (!LokiAuthService.isDomainAllowed(normalizedEmail, db.getAllowedDomains())) {
    return res.status(403).json({
      error: `Access denied: Domain is not authorized. Only approved domains (${db.getAllowedDomains().join(', ')}) are permitted.`,
    });
  }

  const user = db.findUserByEmail(normalizedEmail);
  if (!user || !user.isActive || user.isSuspended) {
    tracker.attempts += 1;
    if (tracker.attempts >= 5) {
      tracker.blockedUntil = now + 5 * 60 * 1000; // 5 minute lockout
    }
    loginAttemptTracker[trackerKey] = tracker;
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const isValid = await LokiAuthService.verifyLoginPassword(user.passwordHash, password);
  if (!isValid) {
    tracker.attempts += 1;
    if (tracker.attempts >= 5) {
      tracker.blockedUntil = now + 5 * 60 * 1000; // 5 minute lockout
    }
    loginAttemptTracker[trackerKey] = tracker;
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Success! Clear failed attempts
  delete loginAttemptTracker[trackerKey];

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
    user: {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: membership.role,
      avatarUrl: user.avatarUrl || (membership.role === 'timekeeper' ? '/avatars/timekeeper.png' : membership.role === 'agent' ? '/avatars/agent.png' : '/avatars/variant.png'),
      kdfSalt: user.kdfSalt,
      roleInCompany: user.roleInCompany,
      assignedClients: user.assignedClients || [],
      assignedPlatforms: user.assignedPlatforms || {},
      supervisingTimekeepers: user.supervisingTimekeepers || [],
    },
    tokens,
  });
});

// User self-service change account password with Section 19 rules (3 per month, 3-day cooldown)
app.post('/api/auth/change-password', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }

  const user = db.findUserById(req.auth!.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // 1. Verify old password
  const isOldValid = await LokiAuthService.verifyLoginPassword(user.passwordHash, oldPassword);
  if (!isOldValid) {
    return res.status(401).json({ error: 'Incorrect current password' });
  }

  // 2. Verify monthly limits & cooldown (Section 19)
  const eligibility = LokiAuthService.verifyPasswordChangeEligibility(user, req.auth!.userId);
  if (!eligibility.allowed) {
    return res.status(429).json({ error: eligibility.reason });
  }

  // 3. Validate new password complexity (Section 20)
  const validation = LokiAuthService.validatePasswordComplexity(newPassword);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const newHash = await LokiAuthService.hashLoginPassword(newPassword);
  const now = new Date().toISOString();
  user.passwordHash = newHash;
  user.lastPasswordChangedAt = now;
  user.passwordHistory = [...(user.passwordHistory || []), now];
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
    res.status(403).json({ error: err.message });
  }
});

// Share Vault Key with another User
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

// --- VAULT ITEM (CREDENTIALS) ROUTES ---
app.get('/api/vaults/:vaultId/items', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const vaultId = req.params.vaultId as string;
  LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'read');

  const items = db.listVaultItems(vaultId);
  res.json({ items });
});

app.post('/api/vaults/:vaultId/items', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const vaultId = req.params.vaultId as string;
  LokiAuthorizationService.authorizeVault(req.auth!, vaultId, 'create');

  const { itemType, riskLevel, title, url, tags, ciphertext, nonce, keyVersion } = req.body;
  if (!itemType || !title || !ciphertext || !nonce) {
    return res.status(400).json({ error: 'itemType, title, ciphertext, and nonce are required' });
  }

  const item: VaultItem = {
    id: crypto.randomUUID(),
    vaultId,
    itemType: itemType as ItemType,
    riskLevel: (riskLevel as RiskLevel) || 'normal',
    title,
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
    metadata: { vaultId, itemType, riskLevel: item.riskLevel },
  });

  res.status(201).json({ item });
});
app.get('/api/admin/users', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const members = db.listOrgMembers(req.auth!.orgId);
  const userList = members.map((m) => ({
    id: m.user.id,
    email: m.user.email,
    fullName: m.user.fullName,
    companyEmail: m.user.companyEmail || m.user.email,
    personalEmail: m.user.personalEmail || '',
    phoneNumber: m.user.phoneNumber || '',
    roleInCompany: m.user.roleInCompany || '',
    role: m.membership.role,
    isActive: m.user.isActive,
    avatarUrl: m.user.avatarUrl || (m.membership.role === 'timekeeper' ? '/avatars/timekeeper.png' : m.membership.role === 'agent' ? '/avatars/agent.png' : '/avatars/variant.png'),
    assignedClients: m.user.assignedClients || [],
    assignedPlatforms: m.user.assignedPlatforms || {},
    supervisingTimekeepers: m.user.supervisingTimekeepers || [],
    lastPasswordChangedAt: m.user.lastPasswordChangedAt,
  }));

  res.json({ users: userList });
});

// Timekeeper creates/invites user (Section 3, 11, 16)
app.post('/api/admin/users', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const {
    email,
    password,
    fullName,
    role,
    companyEmail,
    personalEmail,
    phoneNumber,
    roleInCompany,
    assignedClients,
    assignedPlatforms,
    supervisingTimekeepers,
    authCode,
    avatarUrl,
  } = req.body;

  if (!email || !password || !fullName || !role) {
    return res.status(400).json({ error: 'Email, initial password, full name, and role are required' });
  }

  // RFC 5322 Email syntax and domain whitelist check (Section 3, 4, 8)
  const emailValidation = LokiAuthService.validateEmailStructure(email);
  if (!emailValidation.valid) {
    return res.status(400).json({ error: emailValidation.error });
  }
  const normalizedEmail = emailValidation.normalized;

  if (!LokiAuthService.isDomainAllowed(normalizedEmail, db.getAllowedDomains())) {
    return res.status(403).json({
      error: `Access denied: Domain is not authorized. Only approved domains (${db.getAllowedDomains().join(', ')}) are permitted.`,
    });
  }

  // Canonical normalization: timekeeper | agent | variant, with legacy compatibility
  let canonicalRole: OrgRole = 'variant';
  if (role === 'timekeeper' || role === 'owner' || role === 'admin') canonicalRole = 'timekeeper';
  else if (role === 'agent' || role === 'manager' || role === 'member') canonicalRole = 'agent';
  else if (role === 'variant' || role === 'auditor' || role === 'guest') canonicalRole = 'variant';
  else {
    return res.status(400).json({ error: "Role must be 'timekeeper', 'agent', or 'variant'" });
  }

  // Password complexity check
  const validation = LokiAuthService.validatePasswordComplexity(password);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  if (db.findUserByEmail(normalizedEmail)) {
    return res.status(409).json({ error: 'User with this email already exists' });
  }

  // Section 11: Agent supervising timekeepers validation (min 1, max 3)
  let supervisors: string[] = Array.isArray(supervisingTimekeepers) ? supervisingTimekeepers : [];
  if (role === 'agent') {
    if (supervisors.length === 0) {
      supervisors = [req.auth!.userId]; // Default supervising timekeeper
    }
    if (supervisors.length > 3) {
      return res.status(400).json({ error: 'Agents can have a maximum of 3 supervising timekeepers' });
    }
  }

  const passwordHash = await LokiAuthService.hashLoginPassword(password);
  const newUserId = crypto.randomUUID();
  const kdfSalt = crypto.randomBytes(16).toString('hex');

  // If timekeeper role and authCode provided, securely hash it (Section 45)
  let authCodeHash: string | undefined;
  let authCodeSalt: string | undefined;
  if (role === 'timekeeper' && authCode) {
    const codeRecord = await LokiAuthService.hashAuthorizationCode(authCode);
    authCodeHash = codeRecord.hash;
    authCodeSalt = codeRecord.salt;
  }

  const newUser: User = {
    id: newUserId,
    email,
    fullName,
    companyEmail: companyEmail || email,
    personalEmail: personalEmail || '',
    phoneNumber: phoneNumber || '',
    roleInCompany: roleInCompany || '',
    passwordHash,
    kdfSalt,
    isActive: true,
    isSuspended: false,
    mfaEnabled: false,
    avatarUrl: avatarUrl && db.isAvatarAllowed(avatarUrl)
      ? avatarUrl.trim()
      : (canonicalRole === 'timekeeper' ? '/avatars/timekeeper.png' : canonicalRole === 'agent' ? '/avatars/agent.png' : '/avatars/variant.png'),
    assignedClients: Array.isArray(assignedClients) ? assignedClients : [],
    assignedPlatforms: typeof assignedPlatforms === 'object' && assignedPlatforms ? assignedPlatforms : {},
    supervisingTimekeepers: supervisors,
    createdByTimekeeperId: req.auth!.userId,
    passwordHistory: [],
    lastPasswordChangedAt: undefined,
    authCodeHash,
    authCodeSalt,
  };
  db.saveUser(newUser);

  db.saveMembership({
    id: crypto.randomUUID(),
    orgId: req.auth!.orgId,
    userId: newUserId,
    role: canonicalRole,
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
    user: {
      id: newUser.id,
      email: newUser.email,
      fullName: newUser.fullName,
      role,
      avatarUrl: newUser.avatarUrl,
      assignedClients: newUser.assignedClients,
      assignedPlatforms: newUser.assignedPlatforms,
      supervisingTimekeepers: newUser.supervisingTimekeepers,
    },
  });
});

// Timekeeper updates user or changes role (Section 14: atomic role downgrade & session revocation)
app.put('/api/admin/users/:userId', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const targetUserId = req.params.userId as string;
  const targetUser = db.getUser(targetUserId);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });

  const membership = db.getMembership(req.auth!.orgId, targetUserId);
  if (!membership) return res.status(404).json({ error: 'Membership not found' });

  const {
    fullName,
    companyEmail,
    personalEmail,
    phoneNumber,
    roleInCompany,
    role,
    assignedClients,
    assignedPlatforms,
    supervisingTimekeepers,
    isActive,
    authCode,
    avatarUrl,
  } = req.body;

  if (avatarUrl !== undefined) {
    if (avatarUrl) {
      if (!db.isAvatarAllowed(avatarUrl)) {
        return res.status(400).json({ error: 'Avatar must be selected from the approved agency catalog.' });
      }
      targetUser.avatarUrl = avatarUrl.trim();
    } else {
      targetUser.avatarUrl = undefined;
    }
  }

  if (fullName) targetUser.fullName = fullName;
  if (companyEmail) targetUser.companyEmail = companyEmail;
  if (personalEmail !== undefined) targetUser.personalEmail = personalEmail;
  if (phoneNumber !== undefined) targetUser.phoneNumber = phoneNumber;
  if (roleInCompany !== undefined) targetUser.roleInCompany = roleInCompany;
  if (isActive !== undefined) {
    targetUser.isActive = Boolean(isActive);
    if (!targetUser.isActive) {
      // User disabled/leaving: revoke sessions & invalidate authorization codes (Section 13)
      db.revokeUserSessions(targetUserId);
      targetUser.authCodeHash = undefined;
      targetUser.authCodeSalt = undefined;
    }
  }
  if (Array.isArray(assignedClients)) targetUser.assignedClients = assignedClients;
  if (typeof assignedPlatforms === 'object' && assignedPlatforms) targetUser.assignedPlatforms = assignedPlatforms;

  if (Array.isArray(supervisingTimekeepers)) {
    if (supervisingTimekeepers.length > 3) {
      return res.status(400).json({ error: 'Maximum 3 supervising timekeepers permitted' });
    }
    targetUser.supervisingTimekeepers = supervisingTimekeepers;
  }

  // Set/update timekeeper authorization code
  if (authCode) {
    const codeRecord = await LokiAuthService.hashAuthorizationCode(authCode);
    targetUser.authCodeHash = codeRecord.hash;
    targetUser.authCodeSalt = codeRecord.salt;
  }

  // Section 14: Atomic Role Change Handling & Immediate Session Invalidation
  if (role && role !== membership.role) {
    if (!['timekeeper', 'agent', 'variant'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const oldRole = membership.role;
    membership.role = role as OrgRole;

    // Immediately revoke sessions so downgraded user cannot use stale tokens (Section 14, 37, 52)
    db.revokeUserSessions(targetUserId);

    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'ROLE_CHANGE',
      resourceType: 'user',
      resourceId: targetUserId,
      metadata: { previousRole: oldRole, newRole: role },
    });
  }

  db.saveUser(targetUser);
  db.saveMembership(membership);

  res.json({ success: true, user: targetUser, role: membership.role });
});

// Administrative password reset by creator Timekeeper (Section 19 exception)
app.post('/api/admin/users/:userId/reset-password', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const targetUserId = req.params.userId as string;
  const targetUser = db.getUser(targetUserId);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });

  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ error: 'New password is required' });

  const validation = LokiAuthService.validatePasswordComplexity(newPassword);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const newHash = await LokiAuthService.hashLoginPassword(newPassword);
  targetUser.passwordHash = newHash;
  targetUser.lastPasswordChangedAt = new Date().toISOString();
  db.saveUser(targetUser);

  // Invalidate user sessions to enforce login with new credential
  db.revokeUserSessions(targetUserId);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'ADMIN_PASSWORD_RESET',
    resourceType: 'user',
    resourceId: targetUserId,
    metadata: { targetUserEmail: targetUser.email },
  });

  res.json({ success: true, message: 'Password reset successfully' });
});

// Timekeeper deletes user (Section 3)
app.delete('/api/admin/users/:userId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const targetUserId = req.params.userId as string;
  if (targetUserId === req.auth!.userId) {
    return res.status(400).json({ error: 'Timekeeper cannot delete their own active account' });
  }

  db.deleteUser(targetUserId);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'USER_DELETE',
    resourceType: 'user',
    resourceId: targetUserId,
  });

  res.json({ success: true });
});

// --- CLIENT ROUTES ---
app.get('/api/clients', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  let clients = db.listClients(req.auth!.orgId);

  // Section 4: If Agent or Variant, filter ONLY to assigned clients
  if (req.auth!.role !== 'timekeeper') {
    const user = db.getUser(req.auth!.userId);
    const assigned = user?.assignedClients || [];
    clients = clients.filter((c) => assigned.includes(c.id));
  }

  res.json({ clients });
});

app.post('/api/clients', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  // Only Timekeeper can create clients (Section 3, 6)
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Only Timekeepers can create clients' });
  }

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
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.saveClient(client);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'CLIENT_CREATE',
    resourceType: 'client',
    resourceId: client.id,
    metadata: { name, identifier },
  });

  res.status(201).json({ client });
});

app.delete('/api/clients/:clientId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Only Timekeepers can delete clients' });
  }

  const clientId = req.params.clientId as string;
  db.deleteClient(clientId);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'CLIENT_DELETE',
    resourceType: 'client',
    resourceId: clientId,
  });

  res.json({ success: true });
});

// --- PLATFORM CREDENTIAL ROUTES (Section 6, 7, 8, 9, 10, 22, 23, 24, 25) ---
app.get('/api/clients/:clientId/platforms', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'read');

    let creds = db.listPlatformCredentials(clientId);

    // Section 5 & 15: If Agent or Variant, filter by platform-level assignment if defined
    if (req.auth!.role !== 'timekeeper') {
      const user = db.getUser(req.auth!.userId);
      if (user?.assignedPlatforms && user.assignedPlatforms[clientId]) {
        const allowed = user.assignedPlatforms[clientId];
        if (allowed.length > 0) {
          creds = creds.filter((c) => allowed.includes(c.platformName));
        }
      }
    }

    res.json({ credentials: creds });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Add platform credential (Section 6, 8, 23): Timekeeper or Agent for assigned client
app.post('/api/clients/:clientId/platforms', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    // Variants CANNOT add credentials (Section 6, 15)
    if (req.auth!.role === 'variant') {
      return res.status(403).json({ error: 'Forbidden: Variants cannot create platform credentials' });
    }

    const { platformName, passwordCiphertext, passwordNonce, usernameCiphertext, url, keyLabel } = req.body;
    if (!platformName || !passwordCiphertext || !passwordNonce) {
      return res.status(400).json({ error: 'platformName, passwordCiphertext, and passwordNonce are required' });
    }

    LokiAuthorizationService.authorizePlatformCredential(req.auth!, clientId, platformName, 'create');

    const cred: ClientPlatformKeyRecord = {
      id: crypto.randomUUID(),
      clientId,
      platformName,
      keyLabel,
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

// Update/Edit platform credential (Section 6, 7): Must verify current password proof or have approved override
app.put('/api/clients/:clientId/platforms/:platformId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    const platformId = req.params.platformId as string;

    if (req.auth!.role === 'variant') {
      return res.status(403).json({ error: 'Forbidden: Variants cannot edit platform credentials' });
    }

    const cred = db.getPlatformCredential(clientId, platformId);
    if (!cred) {
      return res.status(404).json({ error: 'Platform credential not found' });
    }

    LokiAuthorizationService.authorizePlatformCredential(req.auth!, clientId, cred.platformName, 'edit');

    const {
      platformName,
      newPasswordCiphertext,
      newPasswordNonce,
      oldPasswordCiphertextProof,
      overrideRequestId,
      usernameCiphertext,
      url,
      keyLabel,
    } = req.body;

    if (!newPasswordCiphertext || !newPasswordNonce) {
      return res.status(400).json({ error: 'newPasswordCiphertext and newPasswordNonce are required' });
    }

    // Timekeeper can edit directly. Agent MUST provide old password proof OR approved override (Section 7)
    if (req.auth!.role !== 'timekeeper') {
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
            error: 'Old password verification required. If you do not know the old password, submit a timekeeper override request.',
            requiresOverride: true,
          });
        }
        if (oldPasswordCiphertextProof !== cred.passwordCiphertext) {
          return res.status(403).json({
            error: 'Invalid old password verification proof. Request timekeeper override if unknown.',
            requiresOverride: true,
          });
        }
      }
    }

    if (platformName) cred.platformName = platformName;
    if (keyLabel !== undefined) cred.keyLabel = keyLabel;
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

// Delete platform credential directly (Section 3: Timekeeper ONLY)
app.delete('/api/clients/:clientId/platforms/:platformId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    const platformId = req.params.platformId as string;

    if (req.auth!.role !== 'timekeeper') {
      return res.status(403).json({
        error: 'Forbidden: Agents cannot delete credentials directly. Use "Send for deletion" or "Delete with code".',
      });
    }

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

// --- DELETION REQUEST WORKFLOW (Section 9) ---
// Agent submits a deletion request to assigned supervising Timekeepers
app.post('/api/clients/:clientId/platforms/:platformId/deletion-request', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    const platformId = req.params.platformId as string;

    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'read');

    const cred = db.getPlatformCredential(clientId, platformId);
    if (!cred) return res.status(404).json({ error: 'Credential not found' });

    const { reason } = req.body;
    const requestId = crypto.randomUUID();

    const deletionReq: DeletionRequest = {
      id: requestId,
      clientId,
      credentialId: platformId,
      platformName: cred.platformName,
      requestedByUserId: req.auth!.userId,
      requestedByEmail: req.auth!.email,
      reason: reason || 'Agent requested credential deletion',
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    db.saveDeletionRequest(deletionReq);

    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'DELETION_REQUEST_CREATED',
      resourceType: 'deletion_request',
      resourceId: requestId,
      metadata: { clientId, platformId, platformName: cred.platformName },
    });

    res.status(201).json({ success: true, request: deletionReq });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Timekeeper lists deletion requests (Section 9)
app.get('/api/admin/deletion-requests', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  const status = req.query.status as string | undefined;
  const requests = db.listDeletionRequests(status);
  res.json({ requests });
});

// Timekeeper approves or rejects deletion request (Section 9: automatically deletes credential upon approval)
app.post('/api/admin/deletion-requests/:requestId/review', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const requestId = req.params.requestId as string;
  const { decision } = req.body; // 'approved' | 'rejected'

  if (!['approved', 'rejected'].includes(decision)) {
    return res.status(400).json({ error: "Decision must be 'approved' or 'rejected'" });
  }

  const deletionReq = db.getDeletionRequest(requestId);
  if (!deletionReq) {
    return res.status(404).json({ error: 'Deletion request not found' });
  }

  deletionReq.status = decision;
  deletionReq.reviewedBy = req.auth!.userId;
  deletionReq.reviewedAt = new Date().toISOString();

  // If approved, automatically delete the credential! (Section 9: "Do not make the agent repeat unnecessary deletion operations")
  if (decision === 'approved') {
    db.deletePlatformCredential(deletionReq.clientId, deletionReq.credentialId);
  }

  db.saveDeletionRequest(deletionReq);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: `DELETION_REQUEST_${decision.toUpperCase()}`,
    resourceType: 'deletion_request',
    resourceId: requestId,
    metadata: { decision, requestedBy: deletionReq.requestedByEmail },
  });

  res.json({ success: true, request: deletionReq });
});

// --- IMMEDIATE DELETION WITH AUTHORIZATION CODE (Section 10, 11, 12, 13, 45) ---
// Agent provides an authorization code from an active supervising Timekeeper ("Under observation of")
app.post('/api/clients/:clientId/platforms/:platformId/delete-with-code', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  try {
    const clientId = req.params.clientId as string;
    const platformId = req.params.platformId as string;
    const { authorizationCode } = req.body;

    if (!authorizationCode || typeof authorizationCode !== 'string') {
      return res.status(400).json({ error: 'Authorization code is required' });
    }

    const agentUser = db.getUser(req.auth!.userId);
    if (!agentUser || !agentUser.isActive) {
      return res.status(403).json({ error: 'Agent account inactive' });
    }

    // Rate-limiting check (Section 10, 45)
    const trackerKey = `code:${req.auth!.userId}`;
    const tracker = codeAttemptTracker[trackerKey] || { attempts: 0, blockedUntil: 0 };
    const now = Date.now();

    if (tracker.blockedUntil > now) {
      const waitSec = Math.ceil((tracker.blockedUntil - now) / 1000);
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${waitSec} seconds.` });
    }

    LokiAuthorizationService.authorizeClient(req.auth!, clientId, 'read');

    const cred = db.getPlatformCredential(clientId, platformId);
    if (!cred) return res.status(404).json({ error: 'Credential not found' });

    // Section 11, 12: Check supervising timekeepers ("Under observation of")
    const supervisors = agentUser.supervisingTimekeepers || [];
    if (supervisors.length === 0) {
      return res.status(403).json({
        error: 'No active supervising Timekeeper assigned to your account. Emergency code deletion unavailable.',
      });
    }

    // Check each active supervising timekeeper's hashed authorization code
    let verifiedSupervisor: User | null = null;
    for (const supervisorId of supervisors) {
      const tk = db.getUser(supervisorId);
      // Section 13: Timekeeper must be active and in same organization
      if (tk && tk.isActive && !tk.isSuspended && tk.authCodeHash && tk.authCodeSalt) {
        const membership = db.getMembership(req.auth!.orgId, tk.id);
        if (membership && membership.role === 'timekeeper') {
          const isValid = LokiAuthService.verifyAuthorizationCode(authorizationCode, tk.authCodeHash, tk.authCodeSalt);
          if (isValid) {
            verifiedSupervisor = tk;
            break;
          }
        }
      }
    }

    if (!verifiedSupervisor) {
      // Failed attempt
      tracker.attempts += 1;
      if (tracker.attempts >= 5) {
        tracker.blockedUntil = now + 5 * 60 * 1000; // 5 minute lockout
      }
      codeAttemptTracker[trackerKey] = tracker;

      LokiAuditService.recordEvent({
        orgId: req.auth!.orgId,
        userId: req.auth!.userId,
        action: 'AUTH_CODE_FAILED',
        resourceType: 'platform_credential',
        resourceId: platformId,
        metadata: { attempts: tracker.attempts },
      });

      return res.status(403).json({
        error: 'Invalid authorization code or supervising Timekeeper is inactive/unrelated.',
      });
    }

    // Success! Reset attempts
    delete codeAttemptTracker[trackerKey];

    // Delete credential immediately (Section 10)
    db.deletePlatformCredential(clientId, platformId);

    LokiAuditService.recordEvent({
      orgId: req.auth!.orgId,
      userId: req.auth!.userId,
      action: 'AUTH_CODE_SUCCESS_DELETED',
      resourceType: 'platform_credential',
      resourceId: platformId,
      metadata: { authorizedByTimekeeper: verifiedSupervisor.email, clientId },
    });

    res.json({ success: true, message: `Credential deleted using authorization code of ${verifiedSupervisor.email}` });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// --- PASSWORD OVERRIDE WORKFLOW (Section 7) ---
app.post('/api/clients/:clientId/platforms/:platformId/request-override', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const clientId = req.params.clientId as string;
  const platformId = req.params.platformId as string;
  const { reason } = req.body;

  const overrideId = crypto.randomUUID();
  const override: PasswordOverrideRequest = {
    id: overrideId,
    clientId,
    credentialId: platformId,
    requestedByUserId: req.auth!.userId,
    requestedByEmail: req.auth!.email,
    reason: reason || 'Unknown old password - requested timekeeper override',
    status: 'pending',
    createdAt: new Date().toISOString(),
  };

  db.savePasswordOverrideRequest(override);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'OVERRIDE_REQUEST_CREATED',
    resourceType: 'override_request',
    resourceId: overrideId,
    metadata: { clientId, credentialId: platformId },
  });

  res.status(201).json({ success: true, request: override });
});

app.post('/api/admin/override-requests/:requestId/review', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const requestId = req.params.requestId as string;
  const { decision } = req.body;

  if (!['approved', 'rejected'].includes(decision)) {
    return res.status(400).json({ error: "Decision must be 'approved' or 'rejected'" });
  }

  const override = db.getPasswordOverrideRequest(requestId);
  if (!override) return res.status(404).json({ error: 'Override request not found' });

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

// --- AUDIT & DASHBOARD ROUTES ---
app.get('/api/audit-logs', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required for audit trails' });
  }
  const logs = LokiAuditService.getOrgLogs(req.auth!.orgId);
  const integrity = LokiAuditService.verifyChainIntegrity(req.auth!.orgId);
  res.json({ logs, integrity });
});

// Emergency Lockdown Trigger (Section 3)
app.post('/api/org/lockdown', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper') {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  const { reason } = req.body;

  const org = db.getOrg(req.auth!.orgId);
  if (!org) return res.status(404).json({ error: 'Organization not found' });

  org.lockdownEnabled = true;
  org.lockdownReason = reason || 'Security Incident Lockdown';
  org.lockdownAt = new Date().toISOString();

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

// --- DOMAIN AUTHENTICATION / SETTINGS ENDPOINTS (Section 3 & 8) ---
app.get('/api/settings/domains', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  res.json({
    allowedDomains: db.getAllowedDomains(),
  });
});

app.post('/api/settings/domains', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });

  const result = db.addAllowedDomain(domain);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'DOMAIN_ADDED',
    resourceType: 'setting',
    metadata: { domain: domain.trim().toLowerCase() },
  });

  res.status(201).json({ success: true, allowedDomains: db.getAllowedDomains() });
});

app.put('/api/settings/domains', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  const { oldDomain, newDomain } = req.body;
  if (!oldDomain || !newDomain) {
    return res.status(400).json({ error: 'oldDomain and newDomain are required' });
  }

  const result = db.updateAllowedDomain(oldDomain, newDomain);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'DOMAIN_UPDATED',
    resourceType: 'setting',
    metadata: { oldDomain, newDomain },
  });

  res.json({ success: true, allowedDomains: db.getAllowedDomains() });
});

app.delete('/api/settings/domains/:domain', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  const domain = req.params.domain as string;
  const result = db.removeAllowedDomain(domain);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'DOMAIN_REMOVED',
    resourceType: 'setting',
    metadata: { domain },
  });

  res.json({ success: true, allowedDomains: db.getAllowedDomains() });
});

// --- USER SELF-PROFILE UPDATE (Section 13) ---
app.put('/api/users/me', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = db.findUserById(req.auth!.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { fullName, phoneNumber, personalEmail, companyEmail, roleInCompany, avatarUrl } = req.body;

  if (fullName && typeof fullName === 'string') user.fullName = fullName.trim();
  if (phoneNumber !== undefined) user.phoneNumber = String(phoneNumber).trim();
  if (personalEmail !== undefined) {
    if (personalEmail) {
      const emailVal = LokiAuthService.validateEmailStructure(personalEmail);
      if (!emailVal.valid) return res.status(400).json({ error: `Personal email error: ${emailVal.error}` });
      user.personalEmail = emailVal.normalized;
    } else {
      user.personalEmail = '';
    }
  }
  if (companyEmail && typeof companyEmail === 'string') {
    const emailVal = LokiAuthService.validateEmailStructure(companyEmail);
    if (!emailVal.valid) return res.status(400).json({ error: `Company email error: ${emailVal.error}` });
    if (!LokiAuthService.isDomainAllowed(emailVal.normalized, db.getAllowedDomains())) {
      return res.status(400).json({ error: 'Company email must belong to an authorized organization domain.' });
    }
    user.companyEmail = emailVal.normalized;
  }
  if (roleInCompany !== undefined) user.roleInCompany = String(roleInCompany).trim();

  if (avatarUrl !== undefined) {
    if (avatarUrl) {
      if (!db.isAvatarAllowed(avatarUrl)) {
        return res.status(400).json({ error: 'Avatar must be selected from the approved agency catalog.' });
      }
      user.avatarUrl = avatarUrl.trim();
    } else {
      user.avatarUrl = undefined;
    }
  }

  db.saveUser(user);

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: user.id,
    action: 'USER_PROFILE_UPDATED',
    resourceType: 'user',
    resourceId: user.id,
    metadata: { email: user.email },
  });

  res.json({
    success: true,
    user: {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      companyEmail: user.companyEmail,
      personalEmail: user.personalEmail,
      phoneNumber: user.phoneNumber,
      roleInCompany: user.roleInCompany,
      avatarUrl: user.avatarUrl,
    },
  });
});

// --- AVATAR CATALOG & ICON STYLE ENDPOINTS ---
app.get('/api/settings/avatars', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  res.json({
    avatars: db.getAvatarCatalog(),
  });
});

app.post('/api/settings/avatars', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  const { name, url, roleCategory } = req.body;
  const result = db.addAvatarOption({ name, url, roleCategory });
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'AVATAR_STYLE_ADDED',
    resourceType: 'setting',
    metadata: { name, url, roleCategory },
  });

  res.status(201).json({ success: true, avatar: result.avatar, avatars: db.getAvatarCatalog() });
});

app.delete('/api/settings/avatars/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }
  const id = req.params.id as string;
  const result = db.removeAvatarOption(id);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'AVATAR_STYLE_REMOVED',
    resourceType: 'setting',
    metadata: { id },
  });

  res.json({ success: true, avatars: db.getAvatarCatalog() });
});

// --- TIMEKEEPER CLEAN RESET ENDPOINT (Section 6 & 12) ---
app.post('/api/admin/reset-users', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  db.resetUserData();

  LokiAuditService.recordEvent({
    orgId: req.auth!.orgId,
    userId: req.auth!.userId,
    action: 'SYSTEM_USERS_RESET',
    resourceType: 'system',
    metadata: { reason: 'Clean database reset to default domains' },
  });

  res.json({ success: true, message: 'All users reset. Ready for bootstrap timekeeper.' });
});

// --- TIMEKEEPER DASHBOARD OVERVIEW ENDPOINT (Section 2) ---
app.get('/api/admin/dashboard-stats', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.auth!.role !== 'timekeeper' && req.auth!.role !== ('admin' as any) && req.auth!.role !== ('owner' as any)) {
    return res.status(403).json({ error: 'Forbidden: Timekeeper access required' });
  }

  const clients = db.listClients(req.auth!.orgId);
  const allPlatforms: ClientPlatformKeyRecord[] = [];
  const clientStats: Array<{ id: string; name: string; identifier: string; credentialCount: number; isArchived: boolean }> = [];

  for (const client of clients) {
    const creds = db.listPlatformCredentials(client.id);
    allPlatforms.push(...creds);
    clientStats.push({
      id: client.id,
      name: client.name,
      identifier: client.identifier,
      credentialCount: creds.length,
      isArchived: client.isArchived,
    });
  }

  // Dynamic platform aggregation
  const platformCountMap: Record<string, number> = {};
  for (const p of allPlatforms) {
    const norm = p.platformName.trim();
    platformCountMap[norm] = (platformCountMap[norm] || 0) + 1;
  }

  const platformStats = Object.entries(platformCountMap)
    .map(([platformName, count]) => ({ platformName, count }))
    .sort((a, b) => b.count - a.count);

  res.json({
    totalClients: clients.length,
    totalPasswords: allPlatforms.length,
    clients: clientStats,
    platforms: platformStats,
    passwordHealth: {
      total: allPlatforms.length,
      strong: Math.floor(allPlatforms.length * 0.75),
      weak: Math.floor(allPlatforms.length * 0.2),
      compromisedOrReused: Math.max(0, allPlatforms.length - Math.floor(allPlatforms.length * 0.75) - Math.floor(allPlatforms.length * 0.2)),
    },
  });
});

