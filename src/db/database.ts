import {
  User,
  UserCryptoKeyRecord,
  Organization,
  OrganizationMembership,
  ClientEntity,
  Vault,
  VaultKeyWrapper,
  VaultFolder,
  VaultItem,
  SessionRecord,
  OrgRole,
  DeletionRequest,
  PasswordOverrideRequest,
  ClientPlatformKeyRecord,
  AvatarOption,
} from '../types/models.js';

/**
 * Loki In-Memory / PostgreSQL Database Storage Service
 * Provides robust multi-tenant data access, atomic consistency, supervision relationships,
 * and deletion request lifecycle management.
 */
export class LokiDatabase {
  public users: Map<string, User> = new Map();
  public userCryptoKeys: Map<string, UserCryptoKeyRecord> = new Map();
  public organizations: Map<string, Organization> = new Map();
  public memberships: Map<string, OrganizationMembership> = new Map();
  public clients: Map<string, ClientEntity> = new Map();
  public clientPlatforms: Map<string, ClientPlatformKeyRecord> = new Map();
  public overrideRequests: Map<string, PasswordOverrideRequest> = new Map();
  public deletionRequests: Map<string, DeletionRequest> = new Map();
  public vaults: Map<string, Vault> = new Map();
  public vaultKeyWrappers: Map<string, VaultKeyWrapper> = new Map();
  public folders: Map<string, VaultFolder> = new Map();
  public vaultItems: Map<string, VaultItem> = new Map();
  public sessions: Map<string, SessionRecord> = new Map();
  public allowedDomains: Set<string> = new Set(['@gmail.com', '@mybusinessmate.ai']);
  public avatarCatalog: Map<string, AvatarOption> = new Map();

  constructor() {
    this.seedDefaultState();
  }

  seedDefaultState() {
    this.allowedDomains = new Set(['@gmail.com', '@mybusinessmate.ai']);
    this.seedDefaultAvatars();
  }

  seedDefaultAvatars() {
    this.avatarCatalog.clear();
    const defaults: AvatarOption[] = [
      { id: 'timekeeper-default', name: 'Timekeeper Sovereign', url: '/avatars/timekeeper.png', roleCategory: 'timekeeper', isDefault: true },
      { id: 'agent-default', name: 'Agent Sentinel', url: '/avatars/agent.png', roleCategory: 'agent', isDefault: true },
      { id: 'variant-default', name: 'Variant Operative', url: '/avatars/variant.png', roleCategory: 'variant', isDefault: true },
      { id: 'loki-crest', name: 'Loki Agency Crest', url: '/logo.png', roleCategory: 'all', isDefault: false },
    ];
    for (const a of defaults) {
      this.avatarCatalog.set(a.id, a);
    }
  }

  clear() {
    this.users.clear();
    this.userCryptoKeys.clear();
    this.organizations.clear();
    this.memberships.clear();
    this.clients.clear();
    this.clientPlatforms.clear();
    this.overrideRequests.clear();
    this.deletionRequests.clear();
    this.vaults.clear();
    this.vaultKeyWrappers.clear();
    this.folders.clear();
    this.vaultItems.clear();
    this.sessions.clear();
    this.allowedDomains = new Set(['@gmail.com', '@mybusinessmate.ai']);
    this.seedDefaultAvatars();
  }

  // --- Domain Authentication Operations ---
  getAllowedDomains(): string[] {
    return Array.from(this.allowedDomains);
  }

  addAllowedDomain(domain: string): { success: boolean; error?: string } {
    const clean = domain.trim().toLowerCase();
    const formatted = clean.startsWith('@') ? clean : `@${clean}`;
    if (!/^@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(formatted)) {
      return { success: false, error: 'Invalid domain format. Example: @mybusinessmate.ai' };
    }
    this.allowedDomains.add(formatted);
    return { success: true };
  }

  removeAllowedDomain(domain: string): { success: boolean; error?: string } {
    const clean = domain.trim().toLowerCase();
    const formatted = clean.startsWith('@') ? clean : `@${clean}`;
    if (this.allowedDomains.size <= 1) {
      return { success: false, error: 'Cannot remove the only remaining allowed domain.' };
    }
    if (!this.allowedDomains.has(formatted)) {
      return { success: false, error: 'Domain not found.' };
    }
    this.allowedDomains.delete(formatted);
    return { success: true };
  }

  updateAllowedDomain(oldDomain: string, newDomain: string): { success: boolean; error?: string } {
    const cleanOld = oldDomain.trim().toLowerCase();
    const oldFormatted = cleanOld.startsWith('@') ? cleanOld : `@${cleanOld}`;
    const cleanNew = newDomain.trim().toLowerCase();
    const newFormatted = cleanNew.startsWith('@') ? cleanNew : `@${cleanNew}`;

    if (!/^@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(newFormatted)) {
      return { success: false, error: 'Invalid new domain format.' };
    }
    if (!this.allowedDomains.has(oldFormatted)) {
      return { success: false, error: 'Original domain not found.' };
    }
    this.allowedDomains.delete(oldFormatted);
    this.allowedDomains.add(newFormatted);
    return { success: true };
  }

  // --- Reset User Data (Section 6 & 12 Clean Reset) ---
  resetUserData(): void {
    this.users.clear();
    this.userCryptoKeys.clear();
    this.memberships.clear();
    this.sessions.clear();
    this.vaultKeyWrappers.clear();
    this.deletionRequests.clear();
    this.overrideRequests.clear();
    this.allowedDomains = new Set(['@gmail.com', '@mybusinessmate.ai']);
    this.seedDefaultAvatars();
  }

  // --- Avatar Catalog Operations ---
  getAvatarCatalog(): AvatarOption[] {
    return Array.from(this.avatarCatalog.values());
  }

  addAvatarOption(option: { id?: string; name: string; url: string; roleCategory?: OrgRole | 'all' }): { success: boolean; avatar?: AvatarOption; error?: string } {
    if (!option.name || !option.name.trim()) {
      return { success: false, error: 'Avatar name is required.' };
    }
    if (!option.url || !option.url.trim()) {
      return { success: false, error: 'Avatar URL or path is required.' };
    }
    const cleanUrl = option.url.trim();
    if (!cleanUrl.startsWith('/') && !cleanUrl.startsWith('https://')) {
      return { success: false, error: 'Avatar URL must be a relative path (/avatars/...) or secure HTTPS URL.' };
    }

    const id = option.id || `avatar-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const newAvatar: AvatarOption = {
      id,
      name: option.name.trim(),
      url: cleanUrl,
      roleCategory: option.roleCategory || 'all',
      isDefault: false,
    };
    this.avatarCatalog.set(id, newAvatar);
    return { success: true, avatar: newAvatar };
  }

  removeAvatarOption(id: string): { success: boolean; error?: string } {
    const existing = this.avatarCatalog.get(id);
    if (!existing) {
      return { success: false, error: 'Avatar option not found.' };
    }
    if (existing.isDefault) {
      return { success: false, error: 'Cannot remove system default role avatars.' };
    }
    this.avatarCatalog.delete(id);
    return { success: true };
  }

  isAvatarAllowed(url: string): boolean {
    if (!url || typeof url !== 'string') return false;
    const clean = url.trim();
    if (['/avatars/timekeeper.png', '/avatars/agent.png', '/avatars/variant.png', '/timekeeper.png', '/agent.png', '/variant.png', '/logo.png'].includes(clean)) {
      return true;
    }
    return Array.from(this.avatarCatalog.values()).some((a) => a.url === clean);
  }

  // --- User Operations ---
  findUserByEmail(email: string): User | undefined {
    return Array.from(this.users.values()).find((u) => u.email.toLowerCase() === email.toLowerCase());
  }

  findUserById(id: string): User | undefined {
    return this.users.get(id);
  }

  getUser(id: string): User | undefined {
    return this.users.get(id);
  }

  saveUser(user: User): void {
    this.users.set(user.id, user);
  }

  deleteUser(userId: string): void {
    this.users.delete(userId);
    // Remove memberships and revoke sessions
    for (const [mid, m] of this.memberships.entries()) {
      if (m.userId === userId) {
        this.memberships.delete(mid);
      }
    }
    this.revokeUserSessions(userId);
  }

  // --- Crypto Key Records ---
  getUserCryptoKey(userId: string): UserCryptoKeyRecord | undefined {
    return this.userCryptoKeys.get(userId);
  }

  saveUserCryptoKey(record: UserCryptoKeyRecord): void {
    this.userCryptoKeys.set(record.userId, record);
  }

  // --- Organization & Membership ---
  getOrg(orgId: string): Organization | undefined {
    return this.organizations.get(orgId);
  }

  saveOrg(org: Organization): void {
    this.organizations.set(org.id, org);
  }

  getMembership(orgId: string, userId: string): OrganizationMembership | undefined {
    return Array.from(this.memberships.values()).find(
      (m) => m.orgId === orgId && m.userId === userId && m.isActive
    );
  }

  saveMembership(membership: OrganizationMembership): void {
    this.memberships.set(membership.id, membership);
  }

  listOrgMembers(orgId: string): { user: User; membership: OrganizationMembership }[] {
    const list: { user: User; membership: OrganizationMembership }[] = [];
    for (const m of this.memberships.values()) {
      if (m.orgId === orgId && m.isActive) {
        const u = this.users.get(m.userId);
        if (u) list.push({ user: u, membership: m });
      }
    }
    return list;
  }

  // --- Clients ---
  listClients(orgId: string): ClientEntity[] {
    return Array.from(this.clients.values()).filter((c) => c.orgId === orgId && !c.isArchived);
  }

  getClient(clientId: string): ClientEntity | undefined {
    return this.clients.get(clientId);
  }

  saveClient(client: ClientEntity): void {
    this.clients.set(client.id, client);
  }

  deleteClient(clientId: string): void {
    const c = this.clients.get(clientId);
    if (c) {
      c.isArchived = true;
    }
  }

  // --- Client-Separated Platform Credentials ---
  listPlatformCredentials(clientId: string): ClientPlatformKeyRecord[] {
    return Array.from(this.clientPlatforms.values()).filter((cp) => cp.clientId === clientId);
  }

  savePlatformCredential(cred: ClientPlatformKeyRecord): void {
    this.clientPlatforms.set(`${cred.clientId}:${cred.id}`, cred);
  }

  getPlatformCredential(clientId: string, platformId: string): ClientPlatformKeyRecord | undefined {
    return this.clientPlatforms.get(`${clientId}:${platformId}`);
  }

  deletePlatformCredential(clientId: string, platformId: string): void {
    this.clientPlatforms.delete(`${clientId}:${platformId}`);
  }

  // --- Deletion Requests (Section 9, 10) ---
  saveDeletionRequest(req: DeletionRequest): void {
    this.deletionRequests.set(req.id, req);
  }

  getDeletionRequest(requestId: string): DeletionRequest | undefined {
    return this.deletionRequests.get(requestId);
  }

  listDeletionRequests(status?: string): DeletionRequest[] {
    const list = Array.from(this.deletionRequests.values());
    if (status) {
      return list.filter((r) => r.status === status);
    }
    return list;
  }

  // --- Password Change Override Requests ---
  savePasswordOverrideRequest(req: PasswordOverrideRequest): void {
    this.overrideRequests.set(req.id, req);
  }

  getPasswordOverrideRequest(requestId: string): PasswordOverrideRequest | undefined {
    return this.overrideRequests.get(requestId);
  }

  listPasswordOverrideRequests(status?: string): PasswordOverrideRequest[] {
    const list = Array.from(this.overrideRequests.values());
    if (status) {
      return list.filter((r) => r.status === status);
    }
    return list;
  }

  // --- Vaults & Key Wrappers ---
  listVaults(orgId: string, clientId?: string): Vault[] {
    return Array.from(this.vaults.values()).filter(
      (v) => v.orgId === orgId && (!clientId || v.clientId === clientId) && !v.isArchived
    );
  }

  getVault(vaultId: string): Vault | undefined {
    return this.vaults.get(vaultId);
  }

  saveVault(vault: Vault): void {
    this.vaults.set(vault.id, vault);
  }

  getVaultKeyWrapper(vaultId: string, userId: string, keyVersion?: number): VaultKeyWrapper | undefined {
    return Array.from(this.vaultKeyWrappers.values()).find(
      (w) =>
        w.vaultId === vaultId &&
        w.userId === userId &&
        (keyVersion === undefined || w.keyVersion === keyVersion)
    );
  }

  listVaultKeyWrappers(vaultId: string): VaultKeyWrapper[] {
    return Array.from(this.vaultKeyWrappers.values()).filter((w) => w.vaultId === vaultId);
  }

  saveVaultKeyWrapper(wrapper: VaultKeyWrapper): void {
    this.vaultKeyWrappers.set(wrapper.id, wrapper);
  }

  removeVaultKeyWrapper(vaultId: string, userId: string): void {
    for (const [id, w] of this.vaultKeyWrappers.entries()) {
      if (w.vaultId === vaultId && w.userId === userId) {
        this.vaultKeyWrappers.delete(id);
      }
    }
  }

  // --- Folders ---
  listFolders(vaultId: string): VaultFolder[] {
    return Array.from(this.folders.values()).filter((f) => f.vaultId === vaultId);
  }

  saveFolder(folder: VaultFolder): void {
    this.folders.set(folder.id, folder);
  }

  // --- Items ---
  listVaultItems(vaultId: string): VaultItem[] {
    return Array.from(this.vaultItems.values()).filter((i) => i.vaultId === vaultId && !i.isDeleted);
  }

  getVaultItem(itemId: string): VaultItem | undefined {
    const item = this.vaultItems.get(itemId);
    return item && !item.isDeleted ? item : undefined;
  }

  saveVaultItem(item: VaultItem): void {
    this.vaultItems.set(item.id, item);
  }

  // --- Sessions ---
  saveSession(session: SessionRecord): void {
    this.sessions.set(session.id, session);
  }

  findSessionByTokenHash(tokenHash: string): SessionRecord | undefined {
    return Array.from(this.sessions.values()).find(
      (s) => s.tokenHash === tokenHash && new Date(s.expiresAt) > new Date()
    );
  }

  revokeUserSessions(userId: string): void {
    for (const s of this.sessions.values()) {
      if (s.userId === userId) {
        s.revoked = true;
      }
    }
  }

  revokeAllOrgSessions(orgId: string, exceptUserId?: string): void {
    const orgUserIds = new Set(
      Array.from(this.memberships.values())
        .filter((m) => m.orgId === orgId)
        .map((m) => m.userId)
    );

    for (const s of this.sessions.values()) {
      if (orgUserIds.has(s.userId) && s.userId !== exceptUserId) {
        s.revoked = true;
      }
    }
  }
}

export const db = new LokiDatabase();
