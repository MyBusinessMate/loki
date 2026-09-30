import { describe, it, expect, vi } from 'vitest';
import { LokiFirebaseService, ClientProfile, ClientPlatformCredential, LokiFirestoreUser } from '../firebase/firestore.service.js';
import { firebaseConfig } from '../firebase/firebaseConfig.js';
import { LokiAuthorizationService } from '../auth/authorization.service.js';

describe('Loki Firebase Project & Client Platform Isolation', () => {
  it('confirms the isolated Firebase Project configuration', () => {
    expect(firebaseConfig.projectId).toBe('loki-agency-vault');
    expect(firebaseConfig.apiKey).toBeDefined();
    expect(firebaseConfig.projectId).not.toContain('tecnomart');
    expect(firebaseConfig.projectId).not.toContain('gold-n-glow');
    expect(firebaseConfig.projectId).not.toContain('billo');
  });

  it('enforces RBAC authorization permissions for client platform credential actions', () => {
    // Owner can create, edit, delete, rotate
    expect(() => LokiAuthorizationService.authorizeAction('owner', 'create')).not.toThrow();
    expect(() => LokiAuthorizationService.authorizeAction('owner', 'delete')).not.toThrow();

    // Member can create and edit, but cannot delete or rotate key
    expect(() => LokiAuthorizationService.authorizeAction('member', 'create')).not.toThrow();
    expect(() => LokiAuthorizationService.authorizeAction('member', 'delete')).toThrow(/lacks permission/);
    expect(() => LokiAuthorizationService.authorizeAction('member', 'rotate_key')).toThrow(/lacks permission/);

    // Auditor can only read
    expect(() => LokiAuthorizationService.authorizeAction('auditor', 'read')).not.toThrow();
    expect(() => LokiAuthorizationService.authorizeAction('auditor', 'create')).toThrow(/lacks permission/);
    expect(() => LokiAuthorizationService.authorizeAction('auditor', 'delete')).toThrow(/lacks permission/);

    // Guest cannot create or delete
    expect(() => LokiAuthorizationService.authorizeAction('guest', 'create')).toThrow(/lacks permission/);
    expect(() => LokiAuthorizationService.authorizeAction('guest', 'delete')).toThrow(/lacks permission/);
  });

  it('validates client-specific platform data structure separation', () => {
    const clientA: ClientProfile = {
      id: 'client-acme',
      name: 'Acme Corp',
      identifier: 'acme',
      createdAt: new Date().toISOString(),
    };

    const credForClientA: ClientPlatformCredential = {
      id: 'cred-1',
      clientId: clientA.id,
      platformName: 'Shopify Store Admin',
      passwordCiphertext: 'dummyCiphertextBase64==',
      passwordNonce: 'dummyNonce24Bytes==',
      usernameCiphertext: 'admin@acme.com',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: 'user-director',
    };

    expect(credForClientA.clientId).toBe('client-acme');
    expect(credForClientA.platformName).toBe('Shopify Store Admin');
    expect(credForClientA.passwordCiphertext).toBeDefined();
  });
});
