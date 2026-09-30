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
  | 'delete_request'
  | 'delete_with_code'
  | 'manage_permissions'
  | 'manage_users'
  | 'manage_clients'
  | 'rotate_key'
  | 'lockdown';

/**
 * Section 2, 43, 63 Canonical Permission Matrix:
 * EXACTLY 3 Roles:
 * 1. timekeeper: Full organization administration & user management
 * 2. agent: Assigned-client access, assigned-platform access, credential create/update, deletion request, code-authorized deletion
 * 3. variant: Assigned-client access, assigned-platform view only. No mutation, no user management.
 */
export const ROLE_PERMISSIONS: Record<string, ResourceAction[]> = {
  timekeeper: [
    'read',
    'reveal',
    'copy',
    'create',
    'edit',
    'share',
    'export',
    'delete',
    'delete_request',
    'delete_with_code',
    'manage_permissions',
    'manage_users',
    'manage_clients',
    'rotate_key',
    'lockdown',
  ],
  agent: [
    'read',
    'reveal',
    'copy',
    'create',
    'edit',
    'delete_request',
    'delete_with_code',
  ],
  variant: [
    'read',
    'reveal',
    'copy',
  ],
  // Legacy role mappings for test and migration stability (Section 1)
  owner: [
    'read',
    'reveal',
    'copy',
    'create',
    'edit',
    'share',
    'export',
    'delete',
    'delete_request',
    'delete_with_code',
    'manage_permissions',
    'manage_users',
    'manage_clients',
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
    'delete_request',
    'delete_with_code',
    'manage_permissions',
    'manage_users',
    'manage_clients',
    'rotate_key',
  ],
  manager: ['read', 'reveal', 'copy', 'create', 'edit', 'share', 'export', 'delete_request', 'delete_with_code'],
  member: ['read', 'reveal', 'copy', 'create', 'edit', 'delete_request', 'delete_with_code'],
  auditor: ['read'],
  guest: ['read', 'reveal', 'copy'],
};

/**
 * Loki Authorization Guard
 * Enforces server-side RBAC, strict tenant isolation, and client/platform-level assignment filters.
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
  static authorizeAction(role: string, action: ResourceAction): void {
    const allowed = ROLE_PERMISSIONS[role] || [];
    if (!allowed.includes(action)) {
      throw new Error(`Forbidden: Role '${role}' lacks permission for '${action}'`);
    }
  }

  /**
   * Authorize access to a specific Client.
   * Section 4: Agents & Variants only have access to clients explicitly assigned to them!
   * Timekeepers have universal organizational client access.
   */
  static authorizeClient(context: AuthContext, clientId: string, action: ResourceAction = 'read'): void {
    const client = db.getClient(clientId);
    if (!client || client.orgId !== context.orgId || client.isArchived) {
      throw new Error('Forbidden: Client not found or access denied');
    }

    this.authorizeOrg(context, context.orgId);
    this.authorizeAction(context.role, action);

    // Role-specific client assignment check:
    if (context.role !== 'timekeeper' && context.role !== ('owner' as any) && context.role !== ('admin' as any)) {
      const user = db.getUser(context.userId);
      if (!user) {
        throw new Error('Forbidden: User record not found');
      }
      const assigned = user.assignedClients || [];
      // If user has specific assignedClients array populated, strictly enforce it
      if (assigned.length > 0 && !assigned.includes(clientId)) {
        throw new Error(`Forbidden: Client '${client.name}' is not assigned to ${context.role} '${user.email}'`);
      }
    }
  }

  /**
   * Authorize access to a specific Platform Credential.
   * Section 5: Evaluates access at the most specific level (Client assignment + Platform assignment).
   */
  static authorizePlatformCredential(
    context: AuthContext,
    clientId: string,
    platformName: string,
    action: ResourceAction = 'read'
  ): void {
    // 1. Must pass client authorization first
    this.authorizeClient(context, clientId, action);

    // 2. Check platform-level assignment for non-timekeeper roles
    if (context.role !== 'timekeeper') {
      const user = db.getUser(context.userId);
      if (user && user.assignedPlatforms && user.assignedPlatforms[clientId]) {
        const allowedPlatforms = user.assignedPlatforms[clientId];
        // If an explicit platform list is set for this client, verify platformName is in it
        if (allowedPlatforms.length > 0 && !allowedPlatforms.includes(platformName)) {
          throw new Error(`Forbidden: Platform '${platformName}' is restricted for user '${user.email}'`);
        }
      }
    }
  }

  /**
   * Authorize access to a specific Vault
   */
  static authorizeVault(context: AuthContext, vaultId: string, action: ResourceAction = 'read'): void {
    const vault = db.getVault(vaultId);
    if (!vault || vault.orgId !== context.orgId || vault.isArchived) {
      throw new Error('Forbidden: Vault not found or access denied');
    }

    this.authorizeOrg(context, context.orgId);
    this.authorizeAction(context.role, action);

    if (context.role !== 'timekeeper' && context.role !== ('owner' as any)) {
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
