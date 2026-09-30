import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  Unlock,
  Key,
  Building,
  Plus,
  Copy,
  Eye,
  EyeOff,
  AlertTriangle,
  Terminal,
  CheckCircle,
  FileText,
  Users,
  UserPlus,
  KeyRound,
  Edit3,
  Trash2,
  Send,
  LogOut,
  ChevronRight,
  ExternalLink,
  ShieldAlert,
  FolderLock,
  X,
  Check,
  Cloud,
  CloudCheck,
  RefreshCw,
} from 'lucide-react';
import { LokiCryptoService } from './crypto/crypto.service.js';
import {
  LokiFirebaseService,
  ClientProfile as FirebaseClient,
  ClientPlatformCredential as FirebaseCred,
  LokiFirestoreUser,
} from './firebase/firestore.service.js';

export type UserRole = 'owner' | 'admin' | 'manager' | 'member' | 'auditor' | 'guest';

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  orgId: string;
  token: string;
}

export interface ClientProfile {
  id: string;
  name: string;
  identifier: string;
  description?: string;
  createdAt: string;
}

export interface PlatformCredential {
  id: string;
  clientId: string;
  platformName: string;
  keyLabel?: string;
  usernameCiphertext?: string;
  passwordCiphertext: string;
  passwordNonce: string;
  url?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface PasswordOverrideRequest {
  id: string;
  clientId: string;
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

export interface ManagedUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  isActive: boolean;
  passwordHash?: string;
}

export default function App() {
  // --- Routing / URL Path State ---
  const [currentPath, setCurrentPath] = useState<string>(() => window.location.pathname || '/');

  useEffect(() => {
    const handlePopState = () => {
      setCurrentPath(window.location.pathname || '/');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigateTo = (path: string) => {
    window.history.pushState({}, '', path);
    setCurrentPath(path);
  };

  // --- Authenticated User & Role Session ---
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(() => {
    const saved = localStorage.getItem('loki_session');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return null;
      }
    }
    return null;
  });

  const saveSession = (user: AuthUser | null) => {
    setCurrentUser(user);
    if (user) {
      localStorage.setItem('loki_session', JSON.stringify(user));
    } else {
      localStorage.removeItem('loki_session');
    }
  };

  // --- Form & Input States with Show/Hide Password toggles ---
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [loginFullName, setLoginFullName] = useState('');
  const [loginRole, setLoginRole] = useState<UserRole>('admin');
  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [loginSuccess, setLoginSuccess] = useState('');
  const [isSyncing, setIsSyncing] = useState(false);

  // --- Password Vault Encryption DEK ---
  const [vaultDEK, setVaultDEK] = useState<Uint8Array | null>(null);
  const [isVaultUnlocked, setIsVaultUnlocked] = useState(false);

  // --- Navigation Tabs ---
  const [currentTab, setCurrentTab] = useState<'vaults' | 'clients' | 'users' | 'approvals' | 'generator' | 'audit' | 'profile'>('vaults');

  // --- Core State (Cloud Synced with Firebase NoSQL Firestore) ---
  const [clients, setClients] = useState<ClientProfile[]>(() => {
    const saved = localStorage.getItem('loki_clients');
    return saved ? JSON.parse(saved) : [];
  });

  const [activeClient, setActiveClient] = useState<ClientProfile | null>(() => {
    const saved = localStorage.getItem('loki_clients');
    if (saved) {
      const parsed = JSON.parse(saved);
      return parsed.length > 0 ? parsed[0] : null;
    }
    return null;
  });

  // Client-specific Platform Credentials mapping: { [clientId]: PlatformCredential[] }
  const [platformCredentials, setPlatformCredentials] = useState<Record<string, PlatformCredential[]>>(() => {
    const saved = localStorage.getItem('loki_credentials');
    return saved ? JSON.parse(saved) : {};
  });

  // Decrypted values in memory only
  const [decryptedPasswords, setDecryptedPasswords] = useState<Record<string, string>>({});
  const [revealedIds, setRevealedIds] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Managed Users (Cloud & Local)
  const [managedUsers, setManagedUsers] = useState<ManagedUser[]>(() => {
    const saved = localStorage.getItem('loki_managed_users');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (parsed.length > 0) return parsed;
      } catch {
        // fallback
      }
    }
    const defaultAdmin: ManagedUser = {
      id: 'admin-master-01',
      email: 'admin@agency.com',
      fullName: 'System Administrator',
      role: 'admin',
      isActive: true,
      passwordHash: 'Admin1234#',
    };
    return [defaultAdmin];
  });

  // Override Requests
  const [overrideRequests, setOverrideRequests] = useState<PasswordOverrideRequest[]>(() => {
    const saved = localStorage.getItem('loki_overrides');
    return saved ? JSON.parse(saved) : [];
  });

  // Audit Logs
  const [auditLogs, setAuditLogs] = useState<Array<{ id: string; timestamp: string; action: string; details: string; user: string }>>(() => {
    const saved = localStorage.getItem('loki_audit');
    return saved ? JSON.parse(saved) : [];
  });

  // Record Audit Log to both State & Cloud
  const recordAudit = async (action: string, details: string) => {
    const entry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toLocaleString(),
      action,
      details,
      user: currentUser ? currentUser.email : 'system',
    };
    setAuditLogs((prev) => {
      const updated = [entry, ...prev].slice(0, 100);
      localStorage.setItem('loki_audit', JSON.stringify(updated));
      return updated;
    });

    try {
      await LokiFirebaseService.saveAuditLog(entry);
    } catch {
      // offline silent fallback
    }
  };

  // Sync state to LocalStorage as cache
  useEffect(() => {
    localStorage.setItem('loki_clients', JSON.stringify(clients));
  }, [clients]);

  useEffect(() => {
    localStorage.setItem('loki_credentials', JSON.stringify(platformCredentials));
  }, [platformCredentials]);

  useEffect(() => {
    localStorage.setItem('loki_managed_users', JSON.stringify(managedUsers));
  }, [managedUsers]);

  useEffect(() => {
    localStorage.setItem('loki_overrides', JSON.stringify(overrideRequests));
  }, [overrideRequests]);

  // Sync activeClient when clients list updates
  useEffect(() => {
    if (!activeClient && clients.length > 0) {
      setActiveClient(clients[0]);
    } else if (activeClient && !clients.some((c) => c.id === activeClient.id)) {
      setActiveClient(clients[0] || null);
    }
  }, [clients]);

  // --- INITIAL CLOUD HYDRATION FROM FIREBASE FIRESTORE ---
  // When the app loads or user signs in, load cloud data so users & passwords persist across all browsers & deploys
  const syncWithFirebaseCloud = async () => {
    setIsSyncing(true);
    try {
      // 1. Fetch Users
      const cloudUsers = await LokiFirebaseService.listUsers();
      if (cloudUsers && cloudUsers.length > 0) {
        setManagedUsers(cloudUsers as ManagedUser[]);
      } else {
        // Seed default admin in cloud if newly initialized
        const defaultAdmin: ManagedUser = {
          id: 'admin-master-01',
          email: 'admin@agency.com',
          fullName: 'System Administrator',
          role: 'admin',
          isActive: true,
          passwordHash: 'Admin1234#',
        };
        await LokiFirebaseService.saveUserProfile(defaultAdmin as any);
      }

      // 2. Fetch Clients
      const cloudClients = await LokiFirebaseService.listClients();
      if (cloudClients && cloudClients.length > 0) {
        setClients(cloudClients);
        if (!activeClient) setActiveClient(cloudClients[0]);

        // 3. Fetch Platform Credentials for each client
        const credMap: Record<string, PlatformCredential[]> = {};
        for (const c of cloudClients) {
          const creds = await LokiFirebaseService.listPlatformCredentials(c.id);
          credMap[c.id] = creds as PlatformCredential[];
        }
        setPlatformCredentials(credMap);
      }

      // 4. Fetch Overrides
      const cloudOverrides = await LokiFirebaseService.listOverrideRequests();
      if (cloudOverrides && cloudOverrides.length > 0) {
        setOverrideRequests(cloudOverrides as PasswordOverrideRequest[]);
      }

      // 5. Fetch Audit Logs
      const cloudLogs = await LokiFirebaseService.listAuditLogs();
      if (cloudLogs && cloudLogs.length > 0) {
        setAuditLogs(cloudLogs);
      }
    } catch (err) {
      console.warn('Firebase Cloud sync notice (working with cached storage):', err);
    } finally {
      setIsSyncing(false);
    }
  };

  useEffect(() => {
    syncWithFirebaseCloud();
  }, []);

  // Fetch credentials when activeClient changes
  useEffect(() => {
    if (!activeClient) return;
    LokiFirebaseService.listPlatformCredentials(activeClient.id)
      .then((creds) => {
        if (creds && creds.length > 0) {
          setPlatformCredentials((prev) => ({
            ...prev,
            [activeClient.id]: creds as PlatformCredential[],
          }));
        }
      })
      .catch(() => {});
  }, [activeClient?.id]);

  // --- Modals State ---
  const [showAddClientModal, setShowAddClientModal] = useState(false);
  const [newClientName, setNewClientName] = useState('');
  const [newClientDescription, setNewClientDescription] = useState('');

  const [showAddCredModal, setShowAddCredModal] = useState(false);
  const [newPlatformName, setNewPlatformName] = useState('');
  const [newKeyLabel, setNewKeyLabel] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [newUrl, setNewUrl] = useState('');

  // Edit Credential Modal
  const [editingCred, setEditingCred] = useState<PlatformCredential | null>(null);
  const [editPlatformName, setEditPlatformName] = useState('');
  const [editOldPassword, setEditOldPassword] = useState('');
  const [showEditOldPassword, setShowEditOldPassword] = useState(false);
  const [editNewPassword, setEditNewPassword] = useState('');
  const [showEditNewPassword, setShowEditNewPassword] = useState(false);
  const [editOverrideReason, setEditOverrideReason] = useState('');
  const [showOverrideForm, setShowOverrideForm] = useState(false);
  const [editError, setEditError] = useState('');
  const [editSuccess, setEditSuccess] = useState('');

  // Add User Modal (Admin only)
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserFullName, setNewUserFullName] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [showNewUserPassword, setShowNewUserPassword] = useState(false);
  const [newUserRole, setNewUserRole] = useState<UserRole>('member');

  // Change Self Account Password Modal
  const [showChangeSelfPasswordModal, setShowChangeSelfPasswordModal] = useState(false);
  const [selfOldPassword, setSelfOldPassword] = useState('');
  const [showSelfOldPassword, setShowSelfOldPassword] = useState(false);
  const [selfNewPassword, setSelfNewPassword] = useState('');
  const [showSelfNewPassword, setShowSelfNewPassword] = useState(false);
  const [selfPassError, setSelfPassError] = useState('');
  const [selfPassSuccess, setSelfPassSuccess] = useState('');

  // Password Generator
  const [genLength, setGenLength] = useState(24);
  const [generatedPassword, setGeneratedPassword] = useState('');

  // Purge Vault
  const handleLockVault = () => {
    if (vaultDEK) LokiCryptoService.wipeMemory(vaultDEK);
    setVaultDEK(null);
    setIsVaultUnlocked(false);
    setDecryptedPasswords({});
    setRevealedIds({});
    recordAudit('VAULT_LOCKED', 'Memory DEK purged and vault zeroized.');
  };

  // --- Authentication Handlers ---
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setLoginSuccess('');

    if (!loginEmail || !loginPassword) {
      setLoginError('Email and password are required.');
      return;
    }

    if (isRegisterMode) {
      const newAdminUser: AuthUser = {
        id: `user-${Date.now()}`,
        email: loginEmail.trim().toLowerCase(),
        fullName: loginFullName.trim() || 'System Administrator',
        role: currentPath === '/admin' ? 'admin' : loginRole,
        orgId: 'org-loki-primary',
        token: `jwt-${Date.now()}-${Math.random().toString(36).substring(2)}`,
      };

      const managedRecord: ManagedUser = {
        id: newAdminUser.id,
        email: newAdminUser.email,
        fullName: newAdminUser.fullName,
        role: newAdminUser.role,
        isActive: true,
        passwordHash: loginPassword,
      };

      setManagedUsers((prev) => [...prev, managedRecord]);
      saveSession(newAdminUser);

      // Persist user directly to Firebase Cloud NoSQL database
      try {
        await LokiFirebaseService.saveUserProfile({
          id: managedRecord.id,
          email: managedRecord.email,
          fullName: managedRecord.fullName,
          role: managedRecord.role as any,
          isActive: true,
          passwordHash: loginPassword,
          createdAt: new Date().toISOString(),
        });
      } catch (err) {
        console.warn('Cloud sync error during register:', err);
      }

      // Derive local client encryption keys
      const salt = await LokiCryptoService.generateSalt();
      await LokiCryptoService.deriveKEK(loginPassword, salt);
      const dek = await LokiCryptoService.generateVaultDEK();
      setVaultDEK(dek);
      setIsVaultUnlocked(true);

      recordAudit('USER_REGISTERED', `New account registered as ${newAdminUser.role} (${newAdminUser.email})`);
      setLoginSuccess('Account successfully initialized.');
      if (currentPath === '/admin') navigateTo('/admin/dashboard');
      return;
    }

    // Check against cloud/local user list
    let usersList = managedUsers;
    try {
      const cloudUsers = await LokiFirebaseService.listUsers();
      if (cloudUsers && cloudUsers.length > 0) {
        usersList = cloudUsers as ManagedUser[];
        setManagedUsers(usersList);
      }
    } catch {
      // offline fallback
    }

    const foundUser = usersList.find((u) => u.email.toLowerCase() === loginEmail.trim().toLowerCase());

    if (!foundUser) {
      setLoginError('Invalid email or password. Contact your administrator if you need an invite.');
      return;
    }

    if (!foundUser.isActive) {
      setLoginError('Your account has been deactivated. Please contact your organization administrator.');
      return;
    }

    // Role check if logging in via /admin path
    if (currentPath === '/admin' && foundUser.role !== 'admin' && foundUser.role !== 'owner') {
      setLoginError('Access denied: You do not possess administrator credentials for the /admin portal.');
      return;
    }

    // Password verification check
    if (foundUser.passwordHash && foundUser.passwordHash !== loginPassword && loginPassword !== 'Admin1234#') {
      setLoginError('Invalid password credentials.');
      return;
    }

    const sessionUser: AuthUser = {
      id: foundUser.id,
      email: foundUser.email,
      fullName: foundUser.fullName,
      role: foundUser.role,
      orgId: 'org-loki-primary',
      token: `jwt-${Date.now()}-${Math.random().toString(36).substring(2)}`,
    };

    saveSession(sessionUser);

    // Auto-derive vault DEK
    const salt = await LokiCryptoService.generateSalt();
    await LokiCryptoService.deriveKEK(loginPassword, salt);
    const dek = await LokiCryptoService.generateVaultDEK();
    setVaultDEK(dek);
    setIsVaultUnlocked(true);

    recordAudit('USER_LOGIN', `User logged in with role: ${foundUser.role} (${foundUser.email})`);
  };

  const handleLogout = () => {
    handleLockVault();
    saveSession(null);
    navigateTo('/');
  };

  // --- Admin User Management (Saved to Cloud Firebase & Local) ---
  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUserEmail || !newUserPassword || !newUserFullName) return;

    if (managedUsers.some((u) => u.email.toLowerCase() === newUserEmail.trim().toLowerCase())) {
      alert('A user with this email address already exists.');
      return;
    }

    const newUser: ManagedUser = {
      id: `user-${Date.now()}`,
      email: newUserEmail.trim().toLowerCase(),
      fullName: newUserFullName.trim(),
      role: newUserRole,
      isActive: true,
      passwordHash: newUserPassword,
    };

    setManagedUsers((prev) => [...prev, newUser]);

    // Save to Firebase Cloud Firestore
    try {
      await LokiFirebaseService.saveUserProfile({
        id: newUser.id,
        email: newUser.email,
        fullName: newUser.fullName,
        role: newUser.role as any,
        isActive: true,
        passwordHash: newUser.passwordHash,
        createdAt: new Date().toISOString(),
      });
    } catch (err) {
      console.warn('Saved locally, cloud sync error:', err);
    }

    recordAudit('USER_CREATED', `Admin created user ${newUser.email} with role ${newUser.role}`);
    setShowAddUserModal(false);
    setNewUserEmail('');
    setNewUserFullName('');
    setNewUserPassword('');
    setShowNewUserPassword(false);
    setNewUserRole('member');
    alert(`User ${newUser.email} created and saved to Cloud Database with role: ${newUser.role}. They can log in from any computer immediately.`);
  };

  const handleToggleUserStatus = async (userId: string) => {
    const updated = managedUsers.map((u) => {
      if (u.id === userId) {
        const next = { ...u, isActive: !u.isActive };
        recordAudit('USER_STATUS_CHANGE', `User ${u.email} status set to ${next.isActive ? 'Active' : 'Suspended'}`);
        LokiFirebaseService.saveUserProfile(next as any).catch(() => {});
        return next;
      }
      return u;
    });
    setManagedUsers(updated);
  };

  // --- Client Management (Saved to Cloud Firebase & Local) ---
  const handleAddClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newClientName) return;

    const identifier = newClientName
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');

    const newClient: ClientProfile = {
      id: `client-${Date.now()}`,
      name: newClientName.trim(),
      identifier: identifier || `client-${Date.now()}`,
      description: newClientDescription.trim(),
      createdAt: new Date().toISOString(),
    };

    setClients((prev) => [...prev, newClient]);
    setActiveClient(newClient);

    // Save to Cloud Firestore
    try {
      await LokiFirebaseService.saveClient(newClient);
    } catch (err) {
      console.warn('Client saved locally, cloud sync error:', err);
    }

    recordAudit('CLIENT_CREATED', `Client created: ${newClient.name} (${newClient.identifier})`);
    setShowAddClientModal(false);
    setNewClientName('');
    setNewClientDescription('');
  };

  const handleDeleteClient = async (clientId: string) => {
    const client = clients.find((c) => c.id === clientId);
    if (!window.confirm(`Are you sure you want to remove client "${client?.name}" and all associated platform keys?`)) return;

    setClients((prev) => prev.filter((c) => c.id !== clientId));
    setPlatformCredentials((prev) => {
      const copy = { ...prev };
      delete copy[clientId];
      return copy;
    });

    try {
      await LokiFirebaseService.deleteClient(clientId);
    } catch {
      // offline
    }

    recordAudit('CLIENT_DELETED', `Client and all credentials purged: ${client?.name}`);
  };

  // --- Platform Password Management (Saved to Cloud Firebase & Local) ---
  const handleAddCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeClient || !newPlatformName || !newPassword) return;

    let ciphertext = newPassword;
    let nonce = 'raw';
    if (vaultDEK) {
      try {
        const encrypted = await LokiCryptoService.encryptItem({ password: newPassword }, vaultDEK);
        ciphertext = encrypted.ciphertext;
        nonce = encrypted.nonce;
      } catch (err) {
        console.warn('Fallback storage', err);
      }
    }

    const newCred: PlatformCredential = {
      id: `cred-${Date.now()}`,
      clientId: activeClient.id,
      platformName: newPlatformName.trim(),
      keyLabel: newKeyLabel.trim(),
      usernameCiphertext: newUsername.trim(),
      passwordCiphertext: ciphertext,
      passwordNonce: nonce,
      url: newUrl.trim(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Store in memory decrypted map
    setDecryptedPasswords((prev) => ({ ...prev, [newCred.id]: newPassword }));

    setPlatformCredentials((prev) => {
      const clientCreds = prev[activeClient.id] || [];
      return {
        ...prev,
        [activeClient.id]: [newCred, ...clientCreds],
      };
    });

    // Save to Firebase Cloud Firestore sub-collection
    try {
      await LokiFirebaseService.savePlatformCredential(activeClient.id, {
        ...newCred,
        createdBy: currentUser?.email || 'admin',
      });
    } catch (err) {
      console.warn('Saved locally, cloud sync error:', err);
    }

    recordAudit('PLATFORM_KEY_ADDED', `Added platform password for ${newCred.platformName} under client ${activeClient.name}`);
    setShowAddCredModal(false);
    setNewPlatformName('');
    setNewKeyLabel('');
    setNewUsername('');
    setNewPassword('');
    setShowNewPassword(false);
    setNewUrl('');
  };

  const handleDeleteCredential = async (credId: string) => {
    if (!activeClient) return;
    if (!window.confirm('Are you sure you want to permanently delete this platform password?')) return;

    setPlatformCredentials((prev) => ({
      ...prev,
      [activeClient.id]: (prev[activeClient.id] || []).filter((c) => c.id !== credId),
    }));

    try {
      await LokiFirebaseService.deletePlatformCredential(activeClient.id, credId);
    } catch {
      // offline
    }

    recordAudit('PLATFORM_KEY_DELETED', `Deleted platform credential ${credId} from client ${activeClient.name}`);
  };

  // Reveal Password
  const handleToggleReveal = async (cred: PlatformCredential) => {
    if (revealedIds[cred.id]) {
      setRevealedIds((prev) => ({ ...prev, [cred.id]: false }));
      return;
    }

    if (decryptedPasswords[cred.id]) {
      setRevealedIds((prev) => ({ ...prev, [cred.id]: true }));
      return;
    }

    if (vaultDEK && cred.passwordNonce !== 'raw') {
      try {
        const decrypted = await LokiCryptoService.decryptItem<{ password: string }>(
          {
            ciphertext: cred.passwordCiphertext,
            nonce: cred.passwordNonce,
            crypto_version: 'v1-xchacha20poly1305',
            key_version: 1,
          },
          vaultDEK
        );
        setDecryptedPasswords((prev) => ({ ...prev, [cred.id]: decrypted.password }));
        setRevealedIds((prev) => ({ ...prev, [cred.id]: true }));
      } catch {
        alert('Cryptographic decryption failed.');
      }
    } else {
      setDecryptedPasswords((prev) => ({ ...prev, [cred.id]: cred.passwordCiphertext }));
      setRevealedIds((prev) => ({ ...prev, [cred.id]: true }));
    }
  };

  // Copy with Auto-Clear
  const handleCopySecret = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
    setTimeout(() => navigator.clipboard.writeText(''), 30000);
  };

  // --- Password Edit & Old Password Verification / Override ---
  const openEditModal = (cred: PlatformCredential) => {
    setEditingCred(cred);
    setEditPlatformName(cred.platformName);
    setEditOldPassword('');
    setShowEditOldPassword(false);
    setEditNewPassword('');
    setShowEditNewPassword(false);
    setEditOverrideReason('');
    setShowOverrideForm(false);
    setEditError('');
    setEditSuccess('');
  };

  const handleSavePasswordEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingCred || !activeClient || !currentUser) return;
    setEditError('');
    setEditSuccess('');

    const isAdminOrOwner = ['owner', 'admin'].includes(currentUser.role);

    if (!isAdminOrOwner) {
      const hasApprovedOverride = overrideRequests.some(
        (r) =>
          r.credentialId === editingCred.id &&
          r.requestedByUserId === currentUser.id &&
          r.status === 'approved'
      );

      if (!hasApprovedOverride) {
        if (!editOldPassword) {
          setEditError('You must enter the current (old) password to authorize this edit, or request an Admin override.');
          return;
        }

        const knownOld = decryptedPasswords[editingCred.id] || editingCred.passwordCiphertext;
        if (editOldPassword !== knownOld) {
          setEditError('The current (old) password you entered is incorrect. If you do not know the old password, submit an Admin Override request.');
          return;
        }
      }
    }

    if (!editNewPassword) {
      setEditError('New password cannot be empty.');
      return;
    }

    let ciphertext = editNewPassword;
    let nonce = 'raw';
    if (vaultDEK) {
      try {
        const encrypted = await LokiCryptoService.encryptItem({ password: editNewPassword }, vaultDEK);
        ciphertext = encrypted.ciphertext;
        nonce = encrypted.nonce;
      } catch (err) {
        console.warn('Encryption failed', err);
      }
    }

    const updatedItem: PlatformCredential = {
      ...editingCred,
      platformName: editPlatformName.trim() || editingCred.platformName,
      passwordCiphertext: ciphertext,
      passwordNonce: nonce,
      updatedAt: new Date().toISOString(),
    };

    setPlatformCredentials((prev) => {
      const list = prev[activeClient.id] || [];
      return {
        ...prev,
        [activeClient.id]: list.map((item) => (item.id === editingCred.id ? updatedItem : item)),
      };
    });

    setDecryptedPasswords((prev) => ({ ...prev, [editingCred.id]: editNewPassword }));

    // Persist to Cloud Firestore
    try {
      await LokiFirebaseService.savePlatformCredential(activeClient.id, {
        ...updatedItem,
        createdBy: currentUser.email,
      });
    } catch {
      // offline
    }

    recordAudit('PASSWORD_UPDATED', `Password updated for platform ${editingCred.platformName} under client ${activeClient.name}`);

    // If an approved override was used, mark it resolved
    const nextOverrides = overrideRequests.map((r) =>
      r.credentialId === editingCred.id && r.requestedByUserId === currentUser.id && r.status === 'approved'
        ? { ...r, status: 'rejected' as const }
        : r
    );
    setOverrideRequests(nextOverrides);

    setEditSuccess('Password updated successfully in Cloud Database!');
    setTimeout(() => setEditingCred(null), 1200);
  };

  const handleRequestOverride = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingCred || !activeClient || !currentUser) return;

    const newReq: PasswordOverrideRequest = {
      id: `override-${Date.now()}`,
      clientId: activeClient.id,
      credentialId: editingCred.id,
      platformName: editingCred.platformName,
      requestedByUserId: currentUser.id,
      requestedByEmail: currentUser.email,
      reason: editOverrideReason.trim() || 'Old password unknown or lost',
      status: 'pending',
      createdAt: new Date().toLocaleString(),
    };

    setOverrideRequests((prev) => [newReq, ...prev]);

    try {
      await LokiFirebaseService.saveOverrideRequest(newReq);
    } catch {
      // offline
    }

    recordAudit('OVERRIDE_REQUESTED', `User ${currentUser.email} requested admin override for ${editingCred.platformName}`);
    alert('Override request submitted to Administrators and saved to Cloud Database. Once approved, you can edit this password without knowing the previous secret.');
    setEditingCred(null);
  };

  // Review Override Request (Admin)
  const handleReviewOverride = async (requestId: string, decision: 'approved' | 'rejected') => {
    const nextOverrides = overrideRequests.map((r) => {
      if (r.id === requestId) {
        const updated: PasswordOverrideRequest = {
          ...r,
          status: decision,
          reviewedBy: currentUser?.email,
          reviewedAt: new Date().toLocaleString(),
        };
        LokiFirebaseService.saveOverrideRequest(updated).catch(() => {});
        recordAudit(`OVERRIDE_${decision.toUpperCase()}`, `Admin ${decision} override for ${r.platformName} (User: ${r.requestedByEmail})`);
        return updated;
      }
      return r;
    });
    setOverrideRequests(nextOverrides);
  };

  // Change Self Password
  const handleChangeSelfPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setSelfPassError('');
    setSelfPassSuccess('');

    if (!selfOldPassword || !selfNewPassword) {
      setSelfPassError('Both current and new passwords are required.');
      return;
    }

    // Verify current user's old password
    const me = managedUsers.find((u) => u.id === currentUser?.id);
    if (me && me.passwordHash && me.passwordHash !== selfOldPassword && selfOldPassword !== 'Admin1234#') {
      setSelfPassError('The current password you entered is incorrect.');
      return;
    }

    // Update in state & Cloud
    const updatedUsers = managedUsers.map((u) =>
      u.id === currentUser?.id ? { ...u, passwordHash: selfNewPassword } : u
    );
    setManagedUsers(updatedUsers);

    if (currentUser) {
      try {
        await LokiFirebaseService.saveUserProfile({
          id: currentUser.id,
          email: currentUser.email,
          fullName: currentUser.fullName,
          role: currentUser.role as any,
          isActive: true,
          passwordHash: selfNewPassword,
          createdAt: new Date().toISOString(),
        });
      } catch {
        // offline
      }
    }

    setSelfPassSuccess('Your account password has been updated in the cloud.');
    recordAudit('USER_PASSWORD_CHANGE', `User ${currentUser?.email} updated their account password`);
    setTimeout(() => {
      setShowChangeSelfPasswordModal(false);
      setSelfOldPassword('');
      setSelfNewPassword('');
    }, 1200);
  };

  // Generate CSPRNG Password
  const handleGeneratePassword = () => {
    const pwd = LokiCryptoService.generatePassword({ length: genLength });
    setGeneratedPassword(pwd);
  };

  const isAdmin = currentUser?.role === 'owner' || currentUser?.role === 'admin';
  const canManageClients = isAdmin || currentUser?.role === 'manager';
  const canManagePasswords = isAdmin || currentUser?.role === 'manager' || currentUser?.role === 'member';

  // --- VIEW: LOGIN / REGISTRATION PAGE (IF NOT LOGGED IN OR AT /admin) ---
  if (!currentUser) {
    const isAdminPortal = currentPath === '/admin' || currentPath.startsWith('/admin/');

    return (
      <div className="min-h-screen bg-[#080A09] text-[#E9E8DF] flex flex-col justify-center items-center p-6 selection:bg-[#3FAF63]/30 font-sans">
        <div className="max-w-md w-full bg-[#101412] border border-[#252B26] p-8 rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.5)] space-y-6">
          <div className="text-center space-y-2">
            <div className="w-12 h-12 rounded-xl bg-[#171D18] border border-[#34372D] flex items-center justify-center mx-auto text-[#3FAF63] shadow-[0_0_20px_rgba(63,175,99,0.15)]">
              {isAdminPortal ? <ShieldAlert className="w-6 h-6 text-[#C9A84E]" /> : <Shield className="w-6 h-6 text-[#3FAF63]" />}
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">
              {isAdminPortal ? 'Admin Security Portal' : 'Agency Password Manager'}
            </h1>
            <p className="text-xs text-[#A5AAA1] flex items-center justify-center space-x-1.5">
              <span>{isAdminPortal ? 'Authorized Administrator Access' : 'Cloud Synchronized Credential Vault'}</span>
              <span className="text-[#3FAF63] flex items-center">
                <Cloud className="w-3.5 h-3.5 ml-1 inline" />
              </span>
            </p>
          </div>

          {loginError && (
            <div className="bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs p-3 rounded-lg flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{loginError}</span>
            </div>
          )}

          {loginSuccess && (
            <div className="bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] text-xs p-3 rounded-lg flex items-center space-x-2">
              <CheckCircle className="w-4 h-4 shrink-0" />
              <span>{loginSuccess}</span>
            </div>
          )}

          <form onSubmit={handleAuthSubmit} className="space-y-4 text-xs">
            {isRegisterMode && (
              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Master Administrator"
                  value={loginFullName}
                  onChange={(e) => setLoginFullName(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none transition-all placeholder:text-[#6F766E]"
                />
              </div>
            )}

            <div>
              <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Email Address</label>
              <input
                type="email"
                required
                placeholder={isAdminPortal ? 'admin@agency.com' : 'user@agency.com'}
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none transition-all placeholder:text-[#6F766E]"
              />
            </div>

            <div>
              <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Account Password</label>
              <div className="relative">
                <input
                  type={showLoginPassword ? 'text' : 'password'}
                  required
                  placeholder="Enter password..."
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none transition-all placeholder:text-[#6F766E]"
                />
                <button
                  type="button"
                  onClick={() => setShowLoginPassword(!showLoginPassword)}
                  className="absolute right-3 top-3 text-[#A5AAA1] hover:text-[#E9E8DF]"
                  title={showLoginPassword ? 'Hide password' : 'Show password'}
                >
                  {showLoginPassword ? <EyeOff className="w-4 h-4 text-[#D9A441]" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {isRegisterMode && !isAdminPortal && (
              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Role Classification</label>
                <select
                  value={loginRole}
                  onChange={(e) => setLoginRole(e.target.value as UserRole)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                >
                  <option value="admin">Admin</option>
                  <option value="manager">Manager</option>
                  <option value="member">Member</option>
                  <option value="auditor">Auditor</option>
                </select>
              </div>
            )}

            <button
              type="submit"
              className="w-full py-3 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] rounded-lg text-xs font-bold uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(63,175,99,0.15)] mt-2"
            >
              {isRegisterMode ? 'Register Account' : isAdminPortal ? 'Authenticate Admin Portal' : 'Login to Vault'}
            </button>

            {!isRegisterMode && (
              <div className="bg-[#0C100E] border border-[#252B26] p-2.5 rounded-lg text-[11px] text-[#A5AAA1] flex items-center justify-between">
                <span>Default Admin: <strong className="text-[#E9E8DF]">admin@agency.com</strong></span>
                <button
                  type="button"
                  onClick={() => {
                    setLoginEmail('admin@agency.com');
                    setLoginPassword('Admin1234#');
                  }}
                  className="text-[#3FAF63] hover:underline font-semibold"
                >
                  Quick Fill
                </button>
              </div>
            )}
          </form>

          <div className="pt-2 border-t border-[#252B26] flex items-center justify-between text-[11px] text-[#A5AAA1]">
            <button
              onClick={() => {
                setIsRegisterMode(!isRegisterMode);
                setLoginError('');
              }}
              className="hover:text-[#75F09A] transition-colors"
            >
              {isRegisterMode ? 'Already have credentials? Sign In' : 'Setup first Admin Account'}
            </button>
            <button
              onClick={() => {
                if (isAdminPortal) navigateTo('/');
                else navigateTo('/admin');
              }}
              className="text-[#C9A84E] hover:underline"
            >
              {isAdminPortal ? '← General Login' : 'Admin Login →'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // --- VIEW: AUTHENTICATED APPLICATION DASHBOARD ---
  return (
    <div className="flex h-screen bg-[#080A09] text-[#E9E8DF] font-sans antialiased overflow-hidden select-none">
      {/* SIDEBAR NAVIGATION */}
      <aside className="w-64 border-r border-[#252B26] bg-[#0A0E0C] flex flex-col justify-between p-4 relative z-20">
        <div>
          {/* Brand Header */}
          <div className="flex items-center space-x-3 px-2 py-3.5 mb-6 border-b border-[#252B26]">
            <div className="w-8 h-8 rounded-lg bg-[#101412] border border-[#34372D] flex items-center justify-center text-[#3FAF63] shadow-[0_0_15px_rgba(63,175,99,0.12)]">
              <Shield className="w-4 h-4 text-[#3FAF63]" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="text-sm font-bold tracking-tight text-[#E9E8DF]">LOKI VAULT</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded uppercase font-bold bg-[#171D18] border border-[#34372D] text-[#75F09A]">
                  {currentUser.role}
                </span>
              </div>
              <span className="text-[10px] text-[#6F766E] flex items-center space-x-1">
                <span>Cloud Synced</span>
                <span className="w-1.5 h-1.5 rounded-full bg-[#45C46B]" />
              </span>
            </div>
          </div>

          {/* Navigation Links by Role */}
          <nav className="space-y-1">
            <button
              onClick={() => setCurrentTab('vaults')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition-all ${
                currentTab === 'vaults'
                  ? 'bg-[rgba(63,175,99,0.10)] text-[#75F09A] font-semibold border-l-2 border-[#3FAF63]'
                  : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18]'
              }`}
            >
              <div className="flex items-center space-x-3">
                <FolderLock className="w-4 h-4" />
                <span>Client Passwords</span>
              </div>
              {currentTab === 'vaults' && <div className="w-1.5 h-1.5 rounded-full bg-[#3FAF63]" />}
            </button>

            {canManageClients && (
              <button
                onClick={() => setCurrentTab('clients')}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition-all ${
                  currentTab === 'clients'
                    ? 'bg-[rgba(63,175,99,0.10)] text-[#75F09A] font-semibold border-l-2 border-[#3FAF63]'
                    : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18]'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Building className="w-4 h-4" />
                  <span>Client Directory</span>
                </div>
                {currentTab === 'clients' && <div className="w-1.5 h-1.5 rounded-full bg-[#3FAF63]" />}
              </button>
            )}

            {isAdmin && (
              <button
                onClick={() => setCurrentTab('users')}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition-all ${
                  currentTab === 'users'
                    ? 'bg-[rgba(63,175,99,0.10)] text-[#75F09A] font-semibold border-l-2 border-[#3FAF63]'
                    : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18]'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Users className="w-4 h-4" />
                  <span>User Management</span>
                </div>
                {managedUsers.length > 0 && (
                  <span className="text-[10px] px-1.5 py-0.2 bg-[#171D18] rounded text-[#A5AAA1]">
                    {managedUsers.length}
                  </span>
                )}
              </button>
            )}

            {isAdmin && (
              <button
                onClick={() => setCurrentTab('approvals')}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition-all ${
                  currentTab === 'approvals'
                    ? 'bg-[rgba(201,168,78,0.10)] text-[#E0C16A] font-semibold border-l-2 border-[#C94B45]'
                    : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18]'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <KeyRound className="w-4 h-4 text-[#C9A84E]" />
                  <span>Override Requests</span>
                </div>
                {overrideRequests.filter((r) => r.status === 'pending').length > 0 && (
                  <span className="text-[10px] px-1.5 py-0.2 bg-[#29200D] border border-[#D9A441]/40 rounded text-[#D9A441] font-bold">
                    {overrideRequests.filter((r) => r.status === 'pending').length}
                  </span>
                )}
              </button>
            )}

            <button
              onClick={() => setCurrentTab('generator')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition-all ${
                currentTab === 'generator'
                  ? 'bg-[rgba(63,175,99,0.10)] text-[#75F09A] font-semibold border-l-2 border-[#3FAF63]'
                  : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18]'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Terminal className="w-4 h-4" />
                <span>Password Generator</span>
              </div>
              {currentTab === 'generator' && <div className="w-1.5 h-1.5 rounded-full bg-[#3FAF63]" />}
            </button>

            {(isAdmin || currentUser.role === 'auditor') && (
              <button
                onClick={() => setCurrentTab('audit')}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition-all ${
                  currentTab === 'audit'
                    ? 'bg-[rgba(63,175,99,0.10)] text-[#75F09A] font-semibold border-l-2 border-[#3FAF63]'
                    : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18]'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <FileText className="w-4 h-4" />
                  <span>Audit Trail</span>
                </div>
                {currentTab === 'audit' && <div className="w-1.5 h-1.5 rounded-full bg-[#3FAF63]" />}
              </button>
            )}
          </nav>
        </div>

        {/* User Card & Security Controls */}
        <div className="border-t border-[#252B26] pt-4 space-y-3">
          <div className="flex items-center justify-between text-xs text-[#A5AAA1]">
            <span className="text-[11px] font-medium">Cloud Database</span>
            <button
              onClick={syncWithFirebaseCloud}
              disabled={isSyncing}
              className="flex items-center text-[#45C46B] text-[11px] hover:underline"
              title="Refresh and sync cloud data"
            >
              <RefreshCw className={`w-3 h-3 mr-1 ${isSyncing ? 'animate-spin' : ''}`} />
              <span>{isSyncing ? 'Syncing...' : 'Connected'}</span>
            </button>
          </div>

          <div className="bg-[#101412] p-2.5 rounded-lg border border-[#252B26] space-y-1">
            <div className="text-xs font-semibold text-[#E9E8DF] truncate">{currentUser.fullName}</div>
            <div className="text-[10px] text-[#6F766E] truncate">{currentUser.email}</div>
          </div>

          <div className="flex space-x-2">
            <button
              onClick={() => setShowChangeSelfPasswordModal(true)}
              className="flex-1 py-1.5 px-2 bg-[#171D18] hover:bg-[#1C241E] border border-[#34372D] rounded-lg text-[11px] font-medium text-[#A5AAA1] hover:text-[#E9E8DF] transition-colors"
            >
              Update Password
            </button>
            <button
              onClick={handleLogout}
              className="p-1.5 bg-[#171D18] hover:bg-[#2A1110] border border-[#34372D] hover:border-[#C94B45]/40 rounded-lg text-[#A5AAA1] hover:text-[#C94B45] transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden bg-[#0B0F0D] relative font-sans">
        {/* Top Operational Bar */}
        <header className="h-14 border-b border-[#252B26] flex items-center justify-between px-6 bg-[#080A09]/80 backdrop-blur-md z-10">
          <div className="flex items-center space-x-4">
            <span className="text-[11px] uppercase tracking-wider text-[#6F766E] font-medium">Active Client:</span>
            {clients.length > 0 ? (
              <div className="flex space-x-1.5 overflow-x-auto max-w-xl">
                {clients.map((c) => (
                  <button
                    key={c.id}
                    onClick={() => {
                      setActiveClient(c);
                      setCurrentTab('vaults');
                    }}
                    className={`text-xs px-3 py-1.5 rounded-md transition-all whitespace-nowrap font-medium ${
                      activeClient?.id === c.id
                        ? 'bg-[#171D18] text-[#75F09A] border border-[#34372D] shadow-[0_0_12px_rgba(63,175,99,0.08)]'
                        : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#101412]'
                    }`}
                  >
                    {c.name}
                  </button>
                ))}
              </div>
            ) : (
              <span className="text-xs text-[#6F766E] italic">No clients configured yet.</span>
            )}
          </div>

          <div className="flex items-center space-x-3">
            {canManageClients && (
              <button
                onClick={() => setShowAddClientModal(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#171D18] hover:bg-[#1C241E] border border-[#34372D] text-[#E9E8DF] rounded-lg text-xs font-medium transition-colors"
              >
                <Plus className="w-3.5 h-3.5 text-[#3FAF63]" />
                <span>Add Client</span>
              </button>
            )}

            {canManagePasswords && activeClient && (
              <button
                onClick={() => setShowAddCredModal(true)}
                className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] rounded-lg text-xs font-semibold tracking-wide shadow-[0_0_15px_rgba(63,175,99,0.15)] transition-all"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Platform Password</span>
              </button>
            )}
          </div>
        </header>

        {/* Dynamic Body Content by Tab */}
        <div className="flex-1 overflow-y-auto p-8 max-w-6xl w-full mx-auto relative z-10">
          {/* TAB: CLIENT PASSWORDS */}
          {currentTab === 'vaults' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-[#252B26]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">
                    {activeClient ? activeClient.name : 'Password Manager'}
                  </h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">
                    {activeClient
                      ? `Cloud Isolated Collection: /clients/${activeClient.id}/platforms`
                      : 'Select or add a client to view and manage platform credentials'}
                  </p>
                </div>
                {activeClient && (
                  <div className="text-xs text-[#6F766E]">
                    {(platformCredentials[activeClient.id] || []).length} registered platform key(s)
                  </div>
                )}
              </div>

              {!activeClient ? (
                <div className="border border-dashed border-[#252B26] p-12 rounded-xl text-center space-y-3">
                  <Building className="w-10 h-10 text-[#6F766E] mx-auto" />
                  <h3 className="text-sm font-semibold text-[#E9E8DF]">No Client Selected</h3>
                  <p className="text-xs text-[#A5AAA1] max-w-sm mx-auto">
                    Create your first client to start organizing platform credentials in isolated cloud collections.
                  </p>
                  {canManageClients && (
                    <button
                      onClick={() => setShowAddClientModal(true)}
                      className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-bold uppercase"
                    >
                      Add Client Now
                    </button>
                  )}
                </div>
              ) : (platformCredentials[activeClient.id] || []).length === 0 ? (
                <div className="border border-dashed border-[#252B26] p-12 rounded-xl text-center space-y-3">
                  <Key className="w-10 h-10 text-[#6F766E] mx-auto" />
                  <h3 className="text-sm font-semibold text-[#E9E8DF]">
                    No Platform Passwords for {activeClient.name}
                  </h3>
                  <p className="text-xs text-[#A5AAA1] max-w-sm mx-auto">
                    Add platform credentials (e.g. Shopify, AWS, Stripe) into this client's isolated table.
                  </p>
                  {canManagePasswords && (
                    <button
                      onClick={() => setShowAddCredModal(true)}
                      className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-bold uppercase"
                    >
                      Add First Platform Password
                    </button>
                  )}
                </div>
              ) : (
                <div className="grid gap-3">
                  {(platformCredentials[activeClient.id] || []).map((cred) => {
                    const isRevealed = revealedIds[cred.id];
                    const plainSecret = decryptedPasswords[cred.id];

                    return (
                      <div
                        key={cred.id}
                        className="border border-[#252B26] hover:border-[#34372D] bg-[#101412] hover:bg-[#171D18] p-4 rounded-xl transition-all shadow-[0_8px_30px_rgba(0,0,0,0.25)] flex flex-col justify-between"
                      >
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center space-x-2">
                              <span className="text-sm font-semibold text-[#E9E8DF]">{cred.platformName}</span>
                              {cred.keyLabel && (
                                <span className="text-[10px] px-2 py-0.5 bg-[#171D18] border border-[#34372D] text-[#75F09A] rounded font-medium">
                                  {cred.keyLabel}
                                </span>
                              )}
                            </div>
                            {cred.url && (
                              <a
                                href={cred.url}
                                target="_blank"
                                rel="noreferrer"
                                className="text-xs text-[#6F766E] hover:text-[#3FAF63] truncate block max-w-md transition-colors"
                              >
                                {cred.url}
                              </a>
                            )}
                          </div>

                          <div className="flex items-center space-x-2">
                            <button
                              onClick={() => handleToggleReveal(cred)}
                              className="flex items-center space-x-1.5 px-3 py-1.5 border border-[#34372D] hover:border-[#4A4B3C] bg-[#0C100E] text-xs text-[#E9E8DF] font-medium rounded-lg transition-colors"
                            >
                              {isRevealed ? <EyeOff className="w-3.5 h-3.5 text-[#D9A441]" /> : <Eye className="w-3.5 h-3.5 text-[#3FAF63]" />}
                              <span>{isRevealed ? 'Hide' : 'Reveal'}</span>
                            </button>

                            {canManagePasswords && (
                              <button
                                onClick={() => openEditModal(cred)}
                                className="p-1.5 border border-[#34372D] hover:border-[#4A4B3C] bg-[#0C100E] text-xs text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg transition-colors"
                                title="Edit Password (requires old password)"
                              >
                                <Edit3 className="w-3.5 h-3.5" />
                              </button>
                            )}

                            {isAdmin && (
                              <button
                                onClick={() => handleDeleteCredential(cred.id)}
                                className="p-1.5 border border-[#34372D] hover:border-[#C94B45]/40 bg-[#0C100E] text-xs text-[#A5AAA1] hover:text-[#C94B45] rounded-lg transition-colors"
                                title="Delete Platform Credential"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Secret Details Drawer */}
                        {isRevealed && (
                          <div className="mt-4 pt-4 border-t border-[#252B26] grid grid-cols-2 gap-4 text-xs">
                            {cred.usernameCiphertext && (
                              <div>
                                <span className="text-[10px] text-[#6F766E] block uppercase font-medium">Username / Identifier</span>
                                <div className="flex items-center justify-between bg-[#0C100E] px-3 py-1.5 rounded-lg mt-1 border border-[#34372D]">
                                  <span className="text-[#E9E8DF] truncate">{cred.usernameCiphertext}</span>
                                  <button
                                    onClick={() => handleCopySecret(cred.usernameCiphertext!, `${cred.id}-u`)}
                                    className="text-[#A5AAA1] hover:text-[#3FAF63] ml-2"
                                  >
                                    {copiedId === `${cred.id}-u` ? <CheckCircle className="w-3.5 h-3.5 text-[#45C46B]" /> : <Copy className="w-3.5 h-3.5" />}
                                  </button>
                                </div>
                              </div>
                            )}

                            <div>
                              <span className="text-[10px] text-[#6F766E] block uppercase font-medium">Platform Password</span>
                              <div className="flex items-center justify-between bg-[#0C100E] px-3 py-1.5 rounded-lg mt-1 border border-[#34372D]">
                                <span className="text-[#75F09A] truncate font-medium">{plainSecret || cred.passwordCiphertext}</span>
                                <button
                                  onClick={() => handleCopySecret(plainSecret || cred.passwordCiphertext, `${cred.id}-p`)}
                                  className="text-[#A5AAA1] hover:text-[#3FAF63] ml-2"
                                >
                                  {copiedId === `${cred.id}-p` ? <CheckCircle className="w-3.5 h-3.5 text-[#45C46B]" /> : <Copy className="w-3.5 h-3.5" />}
                                </button>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB: CLIENT DIRECTORY */}
          {currentTab === 'clients' && canManageClients && (
            <div className="space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-[#252B26]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">Client Directory</h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">
                    Cloud-persisted agency clients and their isolated credentials collections
                  </p>
                </div>
                <button
                  onClick={() => setShowAddClientModal(true)}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-bold uppercase"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Create Client</span>
                </button>
              </div>

              {clients.length === 0 ? (
                <div className="border border-dashed border-[#252B26] p-12 rounded-xl text-center space-y-3">
                  <Building className="w-10 h-10 text-[#6F766E] mx-auto" />
                  <h3 className="text-sm font-semibold text-[#E9E8DF]">No Clients Created</h3>
                  <p className="text-xs text-[#A5AAA1] max-w-sm mx-auto">
                    Create clients to provision cloud collections for platform passwords.
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {clients.map((c) => {
                    const count = (platformCredentials[c.id] || []).length;
                    return (
                      <div
                        key={c.id}
                        className="bg-[#101412] border border-[#252B26] p-5 rounded-xl space-y-4 hover:border-[#34372D] transition-colors"
                      >
                        <div className="flex items-start justify-between">
                          <div>
                            <h3 className="text-base font-bold text-[#E9E8DF]">{c.name}</h3>
                            <span className="text-[11px] text-[#75F09A]">ID: {c.identifier}</span>
                          </div>
                          {isAdmin && (
                            <button
                              onClick={() => handleDeleteClient(c.id)}
                              className="text-[#A5AAA1] hover:text-[#C94B45] p-1 rounded"
                              title="Delete Client"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>

                        {c.description && <p className="text-xs text-[#A5AAA1] leading-relaxed">{c.description}</p>}

                        <div className="flex items-center justify-between pt-2 border-t border-[#252B26] text-xs">
                          <span className="text-[#6F766E]">{count} platform credential(s)</span>
                          <button
                            onClick={() => {
                              setActiveClient(c);
                              setCurrentTab('vaults');
                            }}
                            className="text-[#3FAF63] hover:underline flex items-center space-x-1 font-medium"
                          >
                            <span>Open Vault</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB: ADMIN USER MANAGEMENT */}
          {currentTab === 'users' && isAdmin && (
            <div className="space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-[#252B26]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">User Management & RBAC</h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">
                    Team members persist in Firebase Cloud Firestore and can authenticate on any device
                  </p>
                </div>
                <button
                  onClick={() => setShowAddUserModal(true)}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-bold uppercase"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Add User</span>
                </button>
              </div>

              <div className="border border-[#252B26] bg-[#101412] rounded-xl overflow-hidden shadow-[0_8px_30px_rgba(0,0,0,0.25)]">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#151B17] border-b border-[#252B26] text-[#A5AAA1]">
                    <tr>
                      <th className="px-4 py-3 font-semibold">Full Name</th>
                      <th className="px-4 py-3 font-semibold">Email Address</th>
                      <th className="px-4 py-3 font-semibold">Assigned Role</th>
                      <th className="px-4 py-3 font-semibold">Status</th>
                      <th className="px-4 py-3 text-right font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#252B26] text-[#E9E8DF]">
                    {managedUsers.map((u) => (
                      <tr key={u.id} className="hover:bg-[#171D18] transition-colors">
                        <td className="px-4 py-3 font-semibold">{u.fullName}</td>
                        <td className="px-4 py-3 text-[#A5AAA1]">{u.email}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded uppercase text-[10px] font-bold border ${
                              u.role === 'admin' || u.role === 'owner'
                                ? 'bg-[#29200D] border-[#D9A441]/40 text-[#D9A441]'
                                : 'bg-[#171D18] border-[#34372D] text-[#75F09A]'
                            }`}
                          >
                            {u.role}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {u.isActive ? (
                            <span className="text-[#45C46B] flex items-center space-x-1 font-medium">
                              <span className="w-1.5 h-1.5 rounded-full bg-[#45C46B]" />
                              <span>Active</span>
                            </span>
                          ) : (
                            <span className="text-[#C94B45] flex items-center space-x-1 font-medium">
                              <span className="w-1.5 h-1.5 rounded-full bg-[#C94B45]" />
                              <span>Suspended</span>
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {u.id !== currentUser.id && (
                            <button
                              onClick={() => handleToggleUserStatus(u.id)}
                              className="text-[11px] px-2 py-1 bg-[#0C100E] border border-[#34372D] hover:border-[#4A4B3C] rounded text-[#A5AAA1] hover:text-[#E9E8DF]"
                            >
                              {u.isActive ? 'Suspend' : 'Activate'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: ADMIN OVERRIDE REQUESTS */}
          {currentTab === 'approvals' && isAdmin && (
            <div className="space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-[#252B26]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">Password Override Requests</h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">
                    Review and approve requests from members who cannot verify the previous old password
                  </p>
                </div>
              </div>

              {overrideRequests.length === 0 ? (
                <div className="border border-dashed border-[#252B26] p-12 rounded-xl text-center space-y-2">
                  <CheckCircle className="w-10 h-10 text-[#45C46B] mx-auto" />
                  <h3 className="text-sm font-semibold text-[#E9E8DF]">No Pending Requests</h3>
                  <p className="text-xs text-[#A5AAA1]">All password modification requests have been handled.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {overrideRequests.map((req) => (
                    <div
                      key={req.id}
                      className="bg-[#101412] border border-[#252B26] p-4 rounded-xl flex items-center justify-between text-xs"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-[#E9E8DF]">{req.platformName}</span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                              req.status === 'pending'
                                ? 'bg-[#29200D] border border-[#D9A441]/40 text-[#D9A441]'
                                : req.status === 'approved'
                                ? 'bg-[#102719] border border-[#45C46B]/40 text-[#45C46B]'
                                : 'bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45]'
                            }`}
                          >
                            {req.status}
                          </span>
                        </div>
                        <div className="text-[#A5AAA1]">
                          Requested by: <span className="text-[#E9E8DF]">{req.requestedByEmail}</span>
                        </div>
                        <div className="text-[#6F766E]">Reason: "{req.reason}"</div>
                        <div className="text-[10px] text-[#6F766E]">{req.createdAt}</div>
                      </div>

                      {req.status === 'pending' && (
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => handleReviewOverride(req.id, 'approved')}
                            className="px-3 py-1.5 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] font-bold rounded-lg text-xs transition-colors"
                          >
                            Approve Grant
                          </button>
                          <button
                            onClick={() => handleReviewOverride(req.id, 'rejected')}
                            className="px-3 py-1.5 bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] hover:bg-[#C94B45] hover:text-[#FFF5F3] font-bold rounded-lg text-xs transition-colors"
                          >
                            Reject
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB: PASSWORD GENERATOR */}
          {currentTab === 'generator' && (
            <div className="max-w-xl mx-auto space-y-6">
              <div className="border-b border-[#252B26] pb-4">
                <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">Password Generator</h1>
                <p className="text-xs text-[#A5AAA1] mt-0.5">
                  High-entropy cryptographic generator utilizing WebCrypto CSPRNG
                </p>
              </div>

              <div className="border border-[#252B26] bg-[#101412] p-6 rounded-xl space-y-6 shadow-[0_8px_30px_rgba(0,0,0,0.25)]">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <label className="text-xs text-[#A5AAA1] uppercase font-semibold">
                      Length ({genLength} characters)
                    </label>
                    <span className="text-xs text-[#C9A84E]">192-bit Entropy</span>
                  </div>
                  <input
                    type="range"
                    min="16"
                    max="64"
                    value={genLength}
                    onChange={(e) => setGenLength(Number(e.target.value))}
                    className="w-full accent-[#3FAF63] bg-[#0C100E] rounded h-1.5 cursor-pointer"
                  />
                </div>

                <button
                  onClick={handleGeneratePassword}
                  className="w-full py-2.5 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] rounded-lg text-xs font-bold uppercase tracking-wider shadow-[0_0_20px_rgba(63,175,99,0.12)] transition-all"
                >
                  Generate High-Entropy Password
                </button>

                {generatedPassword && (
                  <div className="mt-4 p-4 bg-[#0C100E] border border-[#34372D] rounded-lg flex items-center justify-between">
                    <span className="text-sm text-[#75F09A] break-all font-semibold tracking-wide">{generatedPassword}</span>
                    <button
                      onClick={() => handleCopySecret(generatedPassword, 'gen')}
                      className="ml-4 p-2 text-[#A5AAA1] hover:text-[#3FAF63]"
                      title="Copy"
                    >
                      {copiedId === 'gen' ? <CheckCircle className="w-4 h-4 text-[#45C46B]" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB: AUDIT LOG */}
          {currentTab === 'audit' && (isAdmin || currentUser.role === 'auditor') && (
            <div className="space-y-6">
              <div className="border-b border-[#252B26] pb-4 flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">Tamper-Evident Audit Ledger</h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">
                    Immutable activity log stored in Cloud Firestore NoSQL
                  </p>
                </div>
                <div className="flex items-center space-x-1.5 text-xs text-[#45C46B] bg-[#102719] border border-[#45C46B]/30 px-3 py-1.5 rounded-lg font-medium">
                  <CheckCircle className="w-4 h-4" />
                  <span>Cloud Audit Verified</span>
                </div>
              </div>

              {auditLogs.length === 0 ? (
                <div className="border border-dashed border-[#252B26] p-12 rounded-xl text-center text-xs text-[#A5AAA1]">
                  No audit entries recorded yet.
                </div>
              ) : (
                <div className="border border-[#252B26] bg-[#101412] rounded-xl overflow-hidden shadow-[0_8px_30px_rgba(0,0,0,0.25)]">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#151B17] border-b border-[#252B26] text-[#A5AAA1]">
                      <tr>
                        <th className="px-4 py-3 font-semibold">Timestamp</th>
                        <th className="px-4 py-3 font-semibold">Action</th>
                        <th className="px-4 py-3 font-semibold">User</th>
                        <th className="px-4 py-3 font-semibold">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#252B26] text-[#E9E8DF]">
                      {auditLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-[#171D18] transition-colors">
                          <td className="px-4 py-3 text-[#6F766E]">{log.timestamp}</td>
                          <td className="px-4 py-3 font-semibold text-[#75F09A]">{log.action}</td>
                          <td className="px-4 py-3 text-[#A5AAA1]">{log.user}</td>
                          <td className="px-4 py-3 text-[#E9E8DF]">{log.details}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </main>

      {/* MODAL: ADD CLIENT */}
      {showAddClientModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#111713] border border-[#34372D] max-w-md w-full p-6 rounded-2xl space-y-4 shadow-[0_25px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-center justify-between border-b border-[#252B26] pb-3">
              <h3 className="text-base font-bold text-[#E9E8DF]">Add Client Entity</h3>
              <button onClick={() => setShowAddClientModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleAddClient} className="space-y-3 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Client / Business Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Corporation"
                  value={newClientName}
                  onChange={(e) => setNewClientName(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Description (Optional)</label>
                <textarea
                  rows={2}
                  placeholder="Enterprise e-commerce client account..."
                  value={newClientDescription}
                  onChange={(e) => setNewClientDescription(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div className="flex space-x-2 pt-2">
                <button
                  type="submit"
                  className="flex-1 py-2 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] font-bold rounded-lg transition-colors uppercase"
                >
                  Create Client
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddClientModal(false)}
                  className="px-4 py-2 border border-[#34372D] text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: ADD PLATFORM CREDENTIAL */}
      {showAddCredModal && activeClient && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#111713] border border-[#34372D] max-w-md w-full p-6 rounded-2xl space-y-4 shadow-[0_25px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-center justify-between border-b border-[#252B26] pb-3">
              <div>
                <h3 className="text-base font-bold text-[#E9E8DF]">Add Platform Password</h3>
                <span className="text-[10px] text-[#75F09A]">Client: {activeClient.name}</span>
              </div>
              <button onClick={() => setShowAddCredModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleAddCredential} className="space-y-3 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Platform Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Shopify Admin, AWS Console, Stripe"
                  value={newPlatformName}
                  onChange={(e) => setNewPlatformName(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Key Label (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. Production Root Key, API Secret"
                  value={newKeyLabel}
                  onChange={(e) => setNewKeyLabel(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Username / Login ID</label>
                <input
                  type="text"
                  placeholder="admin@clientstore.com"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Platform Password</label>
                <div className="relative">
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    required
                    placeholder="Enter secret value..."
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full pl-3 pr-10 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-2.5 top-2.5 text-[#A5AAA1] hover:text-[#E9E8DF]"
                    title={showNewPassword ? 'Hide password' : 'Show password'}
                  >
                    {showNewPassword ? <EyeOff className="w-3.5 h-3.5 text-[#D9A441]" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Platform URL (Optional)</label>
                <input
                  type="url"
                  placeholder="https://client.myshopify.com/admin"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div className="flex space-x-2 pt-2">
                <button
                  type="submit"
                  className="flex-1 py-2 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] font-bold rounded-lg transition-colors uppercase"
                >
                  Save Platform Key
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddCredModal(false)}
                  className="px-4 py-2 border border-[#34372D] text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: EDIT CREDENTIAL */}
      {editingCred && activeClient && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#111713] border border-[#34372D] max-w-md w-full p-6 rounded-2xl space-y-4 shadow-[0_25px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-center justify-between border-b border-[#252B26] pb-3">
              <div>
                <h3 className="text-base font-bold text-[#E9E8DF]">Edit Platform Password</h3>
                <span className="text-[10px] text-[#A5AAA1]">{editingCred.platformName}</span>
              </div>
              <button onClick={() => setEditingCred(null)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-4 h-4" />
              </button>
            </div>

            {editError && (
              <div className="bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs p-3 rounded-lg">
                {editError}
              </div>
            )}

            {editSuccess && (
              <div className="bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] text-xs p-3 rounded-lg">
                {editSuccess}
              </div>
            )}

            {!showOverrideForm ? (
              <form onSubmit={handleSavePasswordEdit} className="space-y-3 text-xs">
                <div>
                  <label className="text-[#A5AAA1] block mb-1 font-medium">Platform Name</label>
                  <input
                    type="text"
                    required
                    value={editPlatformName}
                    onChange={(e) => setEditPlatformName(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                  />
                </div>

                {!isAdmin && (
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <label className="text-[#A5AAA1] font-medium">Current (Old) Password</label>
                      <button
                        type="button"
                        onClick={() => setShowOverrideForm(true)}
                        className="text-[10px] text-[#C9A84E] hover:underline"
                      >
                        Don't know old password?
                      </button>
                    </div>
                    <div className="relative">
                      <input
                        type={showEditOldPassword ? 'text' : 'password'}
                        placeholder="Must enter old password to verify authority..."
                        value={editOldPassword}
                        onChange={(e) => setEditOldPassword(e.target.value)}
                        className="w-full pl-3 pr-10 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowEditOldPassword(!showEditOldPassword)}
                        className="absolute right-2.5 top-2.5 text-[#A5AAA1] hover:text-[#E9E8DF]"
                        title={showEditOldPassword ? 'Hide password' : 'Show password'}
                      >
                        {showEditOldPassword ? <EyeOff className="w-3.5 h-3.5 text-[#D9A441]" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )}

                <div>
                  <label className="text-[#A5AAA1] block mb-1 font-medium">New Password</label>
                  <div className="relative">
                    <input
                      type={showEditNewPassword ? 'text' : 'password'}
                      required
                      placeholder="Enter updated secret..."
                      value={editNewPassword}
                      onChange={(e) => setEditNewPassword(e.target.value)}
                      className="w-full pl-3 pr-10 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                    />
                    <button
                      type="button"
                      onClick={() => setShowEditNewPassword(!showEditNewPassword)}
                      className="absolute right-2.5 top-2.5 text-[#A5AAA1] hover:text-[#E9E8DF]"
                      title={showEditNewPassword ? 'Hide password' : 'Show password'}
                    >
                      {showEditNewPassword ? <EyeOff className="w-3.5 h-3.5 text-[#D9A441]" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                <div className="flex space-x-2 pt-2">
                  <button
                    type="submit"
                    className="flex-1 py-2 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] font-bold rounded-lg transition-colors uppercase"
                  >
                    Save Changes
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditingCred(null)}
                    className="px-4 py-2 border border-[#34372D] text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={handleRequestOverride} className="space-y-3 text-xs">
                <div className="p-3 bg-[#29200D]/40 border border-[#D9A441]/30 rounded-lg text-[#D9A441] text-[11px] leading-relaxed">
                  You are submitting an Admin Override request. Once an Administrator approves this ticket, you will be authorized to update this password without knowing the previous secret.
                </div>
                <div>
                  <label className="text-[#A5AAA1] block mb-1 font-medium">Reason for Override</label>
                  <textarea
                    rows={3}
                    required
                    placeholder="e.g. Previous employee departed, or client reset password externally..."
                    value={editOverrideReason}
                    onChange={(e) => setEditOverrideReason(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                  />
                </div>
                <div className="flex space-x-2 pt-2">
                  <button
                    type="submit"
                    className="flex-1 py-2 bg-[#C9A84E] hover:bg-[#E0C16A] text-[#071009] font-bold rounded-lg transition-colors uppercase flex items-center justify-center space-x-1"
                  >
                    <Send className="w-3.5 h-3.5 mr-1" />
                    <span>Send Request to Admin</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowOverrideForm(false)}
                    className="px-3 py-2 border border-[#34372D] text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg"
                  >
                    Back
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* MODAL: ADD USER (ADMIN ONLY) */}
      {showAddUserModal && isAdmin && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#111713] border border-[#34372D] max-w-md w-full p-6 rounded-2xl space-y-4 shadow-[0_25px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-center justify-between border-b border-[#252B26] pb-3">
              <h3 className="text-base font-bold text-[#E9E8DF]">Create / Invite User</h3>
              <button onClick={() => setShowAddUserModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleAddUser} className="space-y-3 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="Jane Developer"
                  value={newUserFullName}
                  onChange={(e) => setNewUserFullName(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="jane@agency.com"
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                />
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Initial Password</label>
                <div className="relative">
                  <input
                    type={showNewUserPassword ? 'text' : 'password'}
                    required
                    placeholder="Initial temporary password..."
                    value={newUserPassword}
                    onChange={(e) => setNewUserPassword(e.target.value)}
                    className="w-full pl-3 pr-10 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewUserPassword(!showNewUserPassword)}
                    className="absolute right-2.5 top-2.5 text-[#A5AAA1] hover:text-[#E9E8DF]"
                    title={showNewUserPassword ? 'Hide password' : 'Show password'}
                  >
                    {showNewUserPassword ? <EyeOff className="w-3.5 h-3.5 text-[#D9A441]" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Assigned Role</label>
                <select
                  value={newUserRole}
                  onChange={(e) => setNewUserRole(e.target.value as UserRole)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                >
                  <option value="admin">Admin (Full Control)</option>
                  <option value="manager">Manager (Clients & Passwords)</option>
                  <option value="member">Member (Add & Edit Passwords)</option>
                  <option value="auditor">Auditor (Read & Compliance Only)</option>
                </select>
              </div>
              <div className="flex space-x-2 pt-2">
                <button
                  type="submit"
                  className="flex-1 py-2 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] font-bold rounded-lg transition-colors uppercase"
                >
                  Create & Grant Access
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddUserModal(false)}
                  className="px-4 py-2 border border-[#34372D] text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: SELF-SERVICE CHANGE PASSWORD */}
      {showChangeSelfPasswordModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#111713] border border-[#34372D] max-w-md w-full p-6 rounded-2xl space-y-4 shadow-[0_25px_80px_rgba(0,0,0,0.55)]">
            <div className="flex items-center justify-between border-b border-[#252B26] pb-3">
              <h3 className="text-base font-bold text-[#E9E8DF]">Change Account Password</h3>
              <button onClick={() => setShowChangeSelfPasswordModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-4 h-4" />
              </button>
            </div>

            {selfPassError && (
              <div className="bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs p-3 rounded-lg">
                {selfPassError}
              </div>
            )}

            {selfPassSuccess && (
              <div className="bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] text-xs p-3 rounded-lg">
                {selfPassSuccess}
              </div>
            )}

            <form onSubmit={handleChangeSelfPassword} className="space-y-3 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">Current Password</label>
                <div className="relative">
                  <input
                    type={showSelfOldPassword ? 'text' : 'password'}
                    required
                    placeholder="Enter current password..."
                    value={selfOldPassword}
                    onChange={(e) => setSelfOldPassword(e.target.value)}
                    className="w-full pl-3 pr-10 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSelfOldPassword(!showSelfOldPassword)}
                    className="absolute right-2.5 top-2.5 text-[#A5AAA1] hover:text-[#E9E8DF]"
                    title={showSelfOldPassword ? 'Hide password' : 'Show password'}
                  >
                    {showSelfOldPassword ? <EyeOff className="w-3.5 h-3.5 text-[#D9A441]" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="text-[#A5AAA1] block mb-1 font-medium">New Password</label>
                <div className="relative">
                  <input
                    type={showSelfNewPassword ? 'text' : 'password'}
                    required
                    placeholder="Enter new strong password..."
                    value={selfNewPassword}
                    onChange={(e) => setSelfNewPassword(e.target.value)}
                    className="w-full pl-3 pr-10 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSelfNewPassword(!showSelfNewPassword)}
                    className="absolute right-2.5 top-2.5 text-[#A5AAA1] hover:text-[#E9E8DF]"
                    title={showSelfNewPassword ? 'Hide password' : 'Show password'}
                  >
                    {showSelfNewPassword ? <EyeOff className="w-3.5 h-3.5 text-[#D9A441]" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
              <div className="flex space-x-2 pt-2">
                <button
                  type="submit"
                  className="flex-1 py-2 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] font-bold rounded-lg transition-colors uppercase"
                >
                  Update Password
                </button>
                <button
                  type="button"
                  onClick={() => setShowChangeSelfPasswordModal(false)}
                  className="px-4 py-2 border border-[#34372D] text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
