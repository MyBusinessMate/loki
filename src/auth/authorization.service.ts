import { AuthContext } from '../auth/auth.service.js';
import { db } from '../db/database.js';
import { OrgRole } from '../types/models.js';

export type ResourceAction =
  | 'read'
  | 'reveal'
  | 'copy'
  | 'create'
  | 'edit'
  | 'share'
  | 'export'
  | 'delete'
  | 'manage_permissions'
  | 'rotate_key'
  | 'lockdown';

const ROLE_PERMISSIONS: Record<OrgRole, ResourceAction[]> = {
  owner: [
    'read',
    'reveal',
    'copy',
    'create',
    'edit',
    'share',
    'export',
    'delete',
    'manage_permissions',
    'rotate_key',
    'lockdown',
  ],
  admin: [
    'read',
    'reveal',
    'copy',
    'create',
    'edit',
    'share',
    'export',
    'delete',
    'manage_permissions',
    'rotate_key',
  ],
  manager: ['read', 'reveal', 'copy', 'create', 'edit', 'share', 'export'],
  member: ['read', 'reveal', 'copy', 'create', 'edit'],
  auditor: ['read'],
  guest: ['read', 'reveal', 'copy'],
};

/**
 * Loki Authorization Guard
 * Section 10, 11, 12, 52 compliance:
 * - Server-side RBAC validation
 * - Strict multi-tenant organization boundary checks
 * - Explicit resource verification (Client -> Vault -> Item)
 * - Zero reliance on user-submitted IDs
 */
export class LokiAuthorizationService {
  /**
   * Verify organization membership & active status
   */
  static authorizeOrg(context: AuthContext, targetOrgId: string): void {
    if (context.orgId !== targetOrgId) {
      throw new Error('Forbidden: Cross-organization access denied');
    }

    const membership = db.getMembership(targetOrgId, context.userId);
    if (!membership || !membership.isActive) {
      throw new Error('Forbidden: Active membership required');
    }
  }

  /**
   * Verify role permission for general actions
   */
  static authorizeAction(role: OrgRole, action: ResourceAction): void {
    const allowed = ROLE_PERMISSIONS[role] || [];
    if (!allowed.includes(action)) {
      throw new Error(`Forbidden: Role '${role}' lacks permission for '${action}'`);
    }
  }

  /**
   * Authorize access to a specific Client
   */
  static authorizeClient(context: AuthContext, clientId: string, action: ResourceAction = 'read'): void {
    this.authorizeOrg(context, context.orgId);
    this.authorizeAction(context.role, action);

    const client = db.getClient(clientId);
    if (!client || client.orgId !== context.orgId || client.isArchived) {
      throw new Error('Forbidden: Client not found or access denied');
    }
  }

  /**
   * Authorize access to a specific Vault
   */
  static authorizeVault(context: AuthContext, vaultId: string, action: ResourceAction = 'read'): void {
    this.authorizeOrg(context, context.orgId);
    this.authorizeAction(context.role, action);

    const vault = db.getVault(vaultId);
    if (!vault || vault.orgId !== context.orgId || vault.isArchived) {
      throw new Error('Forbidden: Vault not found or access denied');
    }

    // Verify user has key wrapper or is admin/owner
    if (context.role !== 'owner' && context.role !== 'admin') {
      const wrapper = db.getVaultKeyWrapper(vaultId, context.userId);
      if (!wrapper) {
        throw new Error('Forbidden: User is not authorized to access this vault');
      }
    }
  }

  /**
   * Authorize access to a specific Vault Item
   */
  static authorizeItem(context: AuthContext, itemId: string, action: ResourceAction = 'read'): void {
    const item = db.getVaultItem(itemId);
    if (!item) {
      throw new Error('Forbidden: Item not found');
    }

    this.authorizeVault(context, item.vaultId, action);
  }
}
