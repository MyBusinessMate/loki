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
} from '../types/models.js';

/**
 * Loki In-Memory / PostgreSQL Database Storage Service
 * Provides robust multi-tenant data access, atomic consistency, and isolation
 */
export class LokiDatabase {
  public users: Map<string, User> = new Map();
  public userCryptoKeys: Map<string, UserCryptoKeyRecord> = new Map();
  public organizations: Map<string, Organization> = new Map();
  public memberships: Map<string, OrganizationMembership> = new Map();
  public clients: Map<string, ClientEntity> = new Map();
  public clientPlatforms: Map<string, any> = new Map();
  public overrideRequests: Map<string, any> = new Map();
  public vaults: Map<string, Vault> = new Map();
  public vaultKeyWrappers: Map<string, VaultKeyWrapper> = new Map();
  public folders: Map<string, VaultFolder> = new Map();
  public vaultItems: Map<string, VaultItem> = new Map();
  public sessions: Map<string, SessionRecord> = new Map();

  constructor() {
    this.seedDefaultState();
  }

  seedDefaultState() {
    // Default system seed will be dynamically initialized or loaded per test
  }

  clear() {
    this.users.clear();
    this.userCryptoKeys.clear();
    this.organizations.clear();
    this.memberships.clear();
    this.clients.clear();
    this.clientPlatforms.clear();
    this.overrideRequests.clear();
    this.vaults.clear();
    this.vaultKeyWrappers.clear();
    this.folders.clear();
    this.vaultItems.clear();
    this.sessions.clear();
  }

  // --- User Operations ---
  findUserByEmail(email: string): User | undefined {
    return Array.from(this.users.values()).find((u) => u.email.toLowerCase() === email.toLowerCase());
  }

  findUserById(id: string): User | undefined {
    return this.users.get(id);
  }

  saveUser(user: User): void {
    this.users.set(user.id, user);
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

  // --- Client-Separated Platform Credentials ---
  listPlatformCredentials(clientId: string): any[] {
    return Array.from(this.clientPlatforms.values()).filter((cp: any) => cp.clientId === clientId);
  }

  savePlatformCredential(cred: any): void {
    this.clientPlatforms.set(`${cred.clientId}:${cred.id}`, cred);
  }

  getPlatformCredential(clientId: string, platformId: string): any | undefined {
    return this.clientPlatforms.get(`${clientId}:${platformId}`);
  }

  deletePlatformCredential(clientId: string, platformId: string): void {
    this.clientPlatforms.delete(`${clientId}:${platformId}`);
  }

  // --- Password Change Override Requests ---
  savePasswordOverrideRequest(req: any): void {
    this.overrideRequests.set(req.id, req);
  }

  getPasswordOverrideRequest(requestId: string): any | undefined {
    return this.overrideRequests.get(requestId);
  }

  listPasswordOverrideRequests(status?: string): any[] {
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
