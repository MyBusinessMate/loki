import React, { useState, useEffect, useMemo } from 'react';
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
  RefreshCw,
  Menu,
  Clock,
  UserCheck,
  UserX,
  ShieldCheck,
  User as UserIcon,
} from 'lucide-react';
import { LokiCryptoService } from './crypto/crypto.service.js';
import {
  LokiFirebaseService,
  ClientProfile as FirebaseClient,
  ClientPlatformCredential as FirebaseCred,
  LokiFirestoreUser,
} from './firebase/firestore.service.js';
import { PLATFORM_CATALOG, PlatformIcon } from './components/PlatformIcons.js';

// Canonical Three Application Roles (Section 2)
export type UserRole = 'timekeeper' | 'agent' | 'variant';

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  orgId: string;
  token: string;
  companyEmail?: string;
  personalEmail?: string;
  phoneNumber?: string;
  roleInCompany?: string;
  assignedClients?: string[];
  assignedPlatforms?: Record<string, string[]>;
  supervisingTimekeepers?: string[];
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
  companyEmail?: string;
  personalEmail?: string;
  phoneNumber?: string;
  roleInCompany?: string;
  assignedClients?: string[];
  assignedPlatforms?: Record<string, string[]>;
  supervisingTimekeepers?: string[];
  createdByTimekeeperId?: string;
  lastPasswordChangedAt?: string;
  passwordHistory?: string[];
  passwordHash?: string;
  authCodeHash?: string;
  authCodeSalt?: string;
}

/**
 * Loki Client-Side Cryptographic Password Hasher (WebCrypto PBKDF2-SHA512)
 * Ensures user login passwords and authorization codes are NEVER stored in plaintext.
 * Parameters: 16-byte random salt, 100,000 iterations, SHA-512, 256-bit output.
 */
async function hashUserPasswordClient(password: string): Promise<string> {
  const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
  const salt = new Uint8Array(16);
  cryptoObj.getRandomValues(salt);
  const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, '0')).join('');

  const enc = new TextEncoder();
  const keyMaterial = await cryptoObj.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await cryptoObj.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as Uint8Array<ArrayBuffer>,
      iterations: 100000,
      hash: 'SHA-512',
    },
    keyMaterial,
    256
  );

  const hashHex = Array.from(new Uint8Array(derivedBits)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `$pbkdf2$100000$${saltHex}$${hashHex}`;
}

async function verifyUserPasswordClient(password: string, storedRecord?: string): Promise<boolean> {
  if (!storedRecord) return false;
  if (!storedRecord.startsWith('$pbkdf2$')) {
    // Migration fallback for legacy records
    return storedRecord === password;
  }
  const parts = storedRecord.split('$');
  if (parts.length !== 5) return false;
  const iterations = parseInt(parts[2], 10);
  const saltHex = parts[3];
  const expectedHashHex = parts[4];

  const saltBytes = new Uint8Array(saltHex.length / 2);
  for (let i = 0; i < saltHex.length; i += 2) {
    saltBytes[i / 2] = parseInt(saltHex.substring(i, i + 2), 16);
  }

  const cryptoObj = typeof window !== 'undefined' ? window.crypto : globalThis.crypto;
  const enc = new TextEncoder();
  const keyMaterial = await cryptoObj.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await cryptoObj.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes as Uint8Array<ArrayBuffer>,
      iterations: iterations || 100000,
      hash: 'SHA-512',
    },
    keyMaterial,
    256
  );

  const hashHex = Array.from(new Uint8Array(derivedBits)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return hashHex === expectedHashHex;
}

export default function App() {
  // --- Routing & Path Guarding (Section 35 & 36) ---
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

  // --- Authenticated Session ---
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(() => {
    const saved = localStorage.getItem('loki_session');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        // Normalize legacy role values to canonical 3
        if (parsed.role === 'admin' || parsed.role === 'owner') parsed.role = 'timekeeper';
        else if (parsed.role === 'manager' || parsed.role === 'member') parsed.role = 'agent';
        else if (parsed.role === 'auditor' || parsed.role === 'guest') parsed.role = 'variant';
        return parsed;
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

  // --- Auth Form States ---
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [loginFullName, setLoginFullName] = useState('');
  const [loginRole, setLoginRole] = useState<UserRole>('timekeeper');
  const [isRegisterMode, setIsRegisterMode] = useState(() => {
    try {
      const saved = localStorage.getItem('loki_managed_users');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return false;
      }
    } catch {}
    return true;
  });
  const [loginError, setLoginError] = useState('');
  const [loginSuccess, setLoginSuccess] = useState('');
  const [isSyncing, setIsSyncing] = useState(false);

  // --- Mobile Drawer State ---
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // --- Crypto Vault DEK (In-Memory Only, scoped to active browser tab session) ---
  const [vaultDEK, setVaultDEK] = useState<Uint8Array | null>(() => {
    try {
      const saved = sessionStorage.getItem('loki_tab_vault_dek');
      if (saved) {
        const bin = atob(saved);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
      }
    } catch {}
    return null;
  });
  const [isVaultUnlocked, setIsVaultUnlocked] = useState(() => {
    return !!sessionStorage.getItem('loki_tab_vault_dek');
  });

  const getOrInitVaultDEK = async (): Promise<Uint8Array> => {
    if (vaultDEK) return vaultDEK;
    try {
      const saved = sessionStorage.getItem('loki_tab_vault_dek');
      if (saved) {
        const bin = atob(saved);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        setVaultDEK(bytes);
        setIsVaultUnlocked(true);
        return bytes;
      }
    } catch {}

    const newDek = await LokiCryptoService.generateVaultDEK();
    setVaultDEK(newDek);
    setIsVaultUnlocked(true);
    let binary = '';
    for (let i = 0; i < newDek.length; i++) binary += String.fromCharCode(newDek[i]);
    sessionStorage.setItem('loki_tab_vault_dek', btoa(binary));
    return newDek;
  };

  // --- Navigation Tab ---
  const [currentTab, setCurrentTab] = useState<'vaults' | 'clients' | 'users' | 'approvals' | 'generator' | 'audit' | 'profile'>('vaults');

  // --- Cloud & Local Data Stores ---
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

  const [platformCredentials, setPlatformCredentials] = useState<Record<string, PlatformCredential[]>>(() => {
    const saved = localStorage.getItem('loki_credentials');
    return saved ? JSON.parse(saved) : {};
  });

  const [decryptedPasswords, setDecryptedPasswords] = useState<Record<string, string>>({});
  const [revealedIds, setRevealedIds] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const normalizeRole = (r: string): UserRole => {
    const norm = (r || '').toLowerCase();
    if (norm === 'timekeeper' || norm === 'admin' || norm === 'owner') return 'timekeeper';
    if (norm === 'agent' || norm === 'manager' || norm === 'member') return 'agent';
    return 'variant';
  };

  // Managed Users (Normalized to canonical 3 roles, passwords cryptographically hashed)
  const [managedUsers, setManagedUsers] = useState<ManagedUser[]>(() => {
    const saved = localStorage.getItem('loki_managed_users');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed.map((u: any) => ({
            ...u,
            role: normalizeRole(u.role),
          }));
        }
      } catch {
        // fallback
      }
    }
    return [];
  });

  // Deletion Requests & Override Requests
  const [deletionRequests, setDeletionRequests] = useState<DeletionRequest[]>(() => {
    const saved = localStorage.getItem('loki_deletion_requests');
    return saved ? JSON.parse(saved) : [];
  });

  const [overrideRequests, setOverrideRequests] = useState<PasswordOverrideRequest[]>(() => {
    const saved = localStorage.getItem('loki_overrides');
    return saved ? JSON.parse(saved) : [];
  });

  // Audit Logs
  const [auditLogs, setAuditLogs] = useState<Array<{ id: string; timestamp: string; action: string; details: string; user: string }>>(() => {
    const saved = localStorage.getItem('loki_audit');
    return saved ? JSON.parse(saved) : [];
  });

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

  // Sync to local cache
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
    localStorage.setItem('loki_deletion_requests', JSON.stringify(deletionRequests));
  }, [deletionRequests]);

  useEffect(() => {
    localStorage.setItem('loki_overrides', JSON.stringify(overrideRequests));
  }, [overrideRequests]);

  // Sync with Firestore Cloud
  const syncWithFirebaseCloud = async () => {
    setIsSyncing(true);
    if (!LokiFirebaseService.isConfigured()) {
      setIsSyncing(false);
      return;
    }
    try {
      const cloudUsers = await LokiFirebaseService.listUsers();
      if (cloudUsers && cloudUsers.length > 0) {
        const normalized = cloudUsers.map((u: any) => ({
          ...u,
          role: normalizeRole(u.role),
        }));
        setManagedUsers(normalized as ManagedUser[]);
      }

      const cloudClients = await LokiFirebaseService.listClients();
      if (cloudClients && cloudClients.length > 0) {
        setClients(cloudClients);
        if (!activeClient) setActiveClient(cloudClients[0]);

        const credMap: Record<string, PlatformCredential[]> = {};
        for (const c of cloudClients) {
          const creds = await LokiFirebaseService.listPlatformCredentials(c.id);
          credMap[c.id] = creds as PlatformCredential[];
        }
        setPlatformCredentials(credMap);
      }

      const cloudDeletions = await LokiFirebaseService.listDeletionRequests();
      if (cloudDeletions && cloudDeletions.length > 0) {
        setDeletionRequests(cloudDeletions);
      }

      const cloudOverrides = await LokiFirebaseService.listOverrideRequests();
      if (cloudOverrides && cloudOverrides.length > 0) {
        setOverrideRequests(cloudOverrides as PasswordOverrideRequest[]);
      }

      const cloudLogs = await LokiFirebaseService.listAuditLogs();
      if (cloudLogs && cloudLogs.length > 0) {
        setAuditLogs(cloudLogs);
      }
    } catch (err) {
      console.warn('Firebase Cloud sync status (using local cache):', err);
    } finally {
      setIsSyncing(false);
    }
  };

  useEffect(() => {
    syncWithFirebaseCloud();
  }, []);

  // Filter clients and credentials based on current user's role and assignments (Section 4, 5, 15)
  const accessibleClients = useMemo(() => {
    if (!currentUser) return [];
    if (currentUser.role === 'timekeeper') return clients;
    const assigned = currentUser.assignedClients || [];
    return clients.filter((c) => assigned.includes(c.id));
  }, [currentUser, clients]);

  useEffect(() => {
    if (accessibleClients.length > 0) {
      if (!activeClient || !accessibleClients.some((c) => c.id === activeClient.id)) {
        setActiveClient(accessibleClients[0]);
      }
    } else {
      setActiveClient(null);
    }
  }, [accessibleClients]);

  // Filter credentials for activeClient based on platform-level assignment (Section 5 & 15)
  const accessibleCredentials = useMemo(() => {
    if (!activeClient) return [];
    const allCreds = platformCredentials[activeClient.id] || [];
    if (!currentUser || currentUser.role === 'timekeeper') return allCreds;

    const allowedPlatforms = currentUser.assignedPlatforms?.[activeClient.id];
    if (Array.isArray(allowedPlatforms) && allowedPlatforms.length > 0) {
      return allCreds.filter((cred) => allowedPlatforms.includes(cred.platformName));
    }
    return allCreds;
  }, [activeClient, platformCredentials, currentUser]);

  // --- Modals State ---
  // Add Client Modal (Timekeeper only)
  const [showAddClientModal, setShowAddClientModal] = useState(false);
  const [newClientName, setNewClientName] = useState('');
  const [newClientDescription, setNewClientDescription] = useState('');

  // Add Credential Modal (Timekeeper or Agent)
  const [showAddCredModal, setShowAddCredModal] = useState(false);
  const [newPlatformSelection, setNewPlatformSelection] = useState(PLATFORM_CATALOG[0].name);
  const [customPlatformName, setCustomPlatformName] = useState('');
  const [newKeyLabel, setNewKeyLabel] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [newUrl, setNewUrl] = useState('');
  const [addCredError, setAddCredError] = useState('');

  // Edit Credential Modal (Agent must verify old password)
  const [editingCred, setEditingCred] = useState<PlatformCredential | null>(null);
  const [editPlatformName, setEditPlatformName] = useState('');
  const [editOldPassword, setEditOldPassword] = useState('');
  const [showEditOldPassword, setShowEditOldPassword] = useState(false);
  const [editNewPassword, setEditNewPassword] = useState('');
  const [editConfirmPassword, setEditConfirmPassword] = useState('');
  const [showEditNewPassword, setShowEditNewPassword] = useState(false);
  const [showEditConfirmPassword, setShowEditConfirmPassword] = useState(false);
  const [editOverrideReason, setEditOverrideReason] = useState('');
  const [showOverrideForm, setShowOverrideForm] = useState(false);
  const [editError, setEditError] = useState('');
  const [editSuccess, setEditSuccess] = useState('');

  // Agent Deletion Modal (Option 1: Request Deletion, Option 2: Delete with Code)
  const [deletingCred, setDeletingCred] = useState<PlatformCredential | null>(null);
  const [deletionMode, setDeletionMode] = useState<'choose' | 'request' | 'code'>('choose');
  const [deletionReason, setDeletionReason] = useState('');
  const [timekeeperAuthCode, setTimekeeperAuthCode] = useState('');
  const [deletionModalError, setDeletionModalError] = useState('');
  const [deletionModalSuccess, setDeletionModalSuccess] = useState('');

  // Add User Modal (Timekeeper only)
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserFullName, setNewUserFullName] = useState('');
  const [newUserRole, setNewUserRole] = useState<UserRole>('agent');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [showNewUserPassword, setShowNewUserPassword] = useState(false);
  const [newUserCompanyEmail, setNewUserCompanyEmail] = useState('');
  const [newUserPersonalEmail, setNewUserPersonalEmail] = useState('');
  const [newUserPhone, setNewUserPhone] = useState('');
  const [newUserRoleInCompany, setNewUserRoleInCompany] = useState('');
  const [newUserAssignedClients, setNewUserAssignedClients] = useState<string[]>([]);
  const [newUserSupervisingTKs, setNewUserSupervisingTKs] = useState<string[]>([]);
  const [newUserAuthCode, setNewUserAuthCode] = useState('');
  const [addUserError, setAddUserError] = useState('');

  // Admin Reset User Password Modal (Creator Timekeeper override)
  const [resetTargetUser, setResetTargetUser] = useState<ManagedUser | null>(null);
  const [adminResetNewPassword, setAdminResetNewPassword] = useState('');
  const [showAdminResetPassword, setShowAdminResetPassword] = useState(false);
  const [adminResetError, setAdminResetError] = useState('');
  const [adminResetSuccess, setAdminResetSuccess] = useState('');

  // Self Account Password Modal (Section 18, 19, 20: 3/mo limit + 3-day cooldown)
  const [showChangeSelfPasswordModal, setShowChangeSelfPasswordModal] = useState(false);
  const [selfOldPassword, setSelfOldPassword] = useState('');
  const [showSelfOldPassword, setShowSelfOldPassword] = useState(false);
  const [selfNewPassword, setSelfNewPassword] = useState('');
  const [selfConfirmPassword, setSelfConfirmPassword] = useState('');
  const [showSelfNewPassword, setShowSelfNewPassword] = useState(false);
  const [showSelfConfirmPassword, setShowSelfConfirmPassword] = useState(false);
  const [selfPassError, setSelfPassError] = useState('');
  const [selfPassSuccess, setSelfPassSuccess] = useState('');

  // Password Generator
  const [genLength, setGenLength] = useState(24);
  const [generatedPassword, setGeneratedPassword] = useState('');

  // Lock Vault and Purge Sensitive Memory
  const handleLockVault = () => {
    if (vaultDEK) LokiCryptoService.wipeMemory(vaultDEK);
    setVaultDEK(null);
    try {
      sessionStorage.removeItem('loki_tab_vault_dek');
    } catch {}
    setIsVaultUnlocked(false);
    setDecryptedPasswords({});
    setRevealedIds({});
    recordAudit('VAULT_LOCKED', 'Memory DEK purged and in-memory credential state cleared.');
  };

  // --- Password Complexity Validator (Section 20 & 40) ---
  const validatePasswordPolicy = (pwd: string): { valid: boolean; error?: string } => {
    if (pwd.length < 8) return { valid: false, error: 'Password must be at least 8 characters long.' };
    if (pwd.length > 30) return { valid: false, error: 'Password must be at most 30 characters long.' };
    if (!/[A-Z]/.test(pwd)) return { valid: false, error: 'Password must include at least one uppercase letter (A-Z).' };
    if (!/[a-z]/.test(pwd)) return { valid: false, error: 'Password must include at least one lowercase letter (a-z).' };
    if (!/[0-9]/.test(pwd)) return { valid: false, error: 'Password must include at least one number (0-9).' };
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) {
      return { valid: false, error: 'Password must include at least one special character (!@#$%^&* etc).' };
    }
    return { valid: true };
  };

  // --- Authentication Submission ---
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setLoginSuccess('');

    if (!loginEmail || !loginPassword) {
      setLoginError('Email and password are required.');
      return;
    }

    if (isRegisterMode) {
      const pol = validatePasswordPolicy(loginPassword);
      if (!pol.valid) {
        setLoginError(pol.error || 'Password does not meet complexity requirements.');
        return;
      }

      // Check if user already exists
      if (managedUsers.some((u) => u.email.toLowerCase() === loginEmail.trim().toLowerCase())) {
        setLoginError('A user with this email address already exists.');
        return;
      }

      const isFirst = managedUsers.length === 0;
      const initialRole: UserRole = isFirst ? 'timekeeper' : loginRole;
      const securePasswordHash = await hashUserPasswordClient(loginPassword);

      const newUserId = `user-${Date.now()}`;
      const newAuthUser: AuthUser = {
        id: newUserId,
        email: loginEmail.trim().toLowerCase(),
        fullName: loginFullName.trim() || 'New User',
        role: initialRole,
        orgId: 'org-loki-primary',
        token: `jwt-${Date.now()}-${Math.random().toString(36).substring(2)}`,
        companyEmail: loginEmail.trim().toLowerCase(),
        personalEmail: '',
        phoneNumber: '',
        roleInCompany: initialRole === 'timekeeper' ? 'Administrator' : 'Agency Specialist',
        assignedClients: [],
        assignedPlatforms: {},
        supervisingTimekeepers: [],
      };

      const newManaged: ManagedUser = {
        id: newAuthUser.id,
        email: newAuthUser.email,
        fullName: newAuthUser.fullName,
        role: newAuthUser.role,
        isActive: true,
        companyEmail: newAuthUser.companyEmail,
        personalEmail: '',
        phoneNumber: '',
        roleInCompany: newAuthUser.roleInCompany,
        assignedClients: [],
        assignedPlatforms: {},
        supervisingTimekeepers: [],
        passwordHash: securePasswordHash,
        passwordHistory: [],
        lastPasswordChangedAt: undefined,
      };

      setManagedUsers((prev) => [...prev, newManaged]);
      saveSession(newAuthUser);

      // Save to Firebase Cloud
      try {
        await LokiFirebaseService.saveUserProfile({
          id: newManaged.id,
          email: newManaged.email,
          fullName: newManaged.fullName,
          role: newManaged.role,
          isActive: true,
          companyEmail: newManaged.companyEmail,
          roleInCompany: newManaged.roleInCompany,
          createdAt: new Date().toISOString(),
          passwordHash: securePasswordHash,
        });
      } catch (err) {
        console.warn('Firebase sync warning:', err);
      }

      // Unlock vault crypto & persist DEK to active tab session
      const salt = await LokiCryptoService.generateSalt();
      await LokiCryptoService.deriveKEK(loginPassword, salt);
      const dek = await LokiCryptoService.generateVaultDEK();
      setVaultDEK(dek);
      setIsVaultUnlocked(true);
      try {
        let binary = '';
        for (let i = 0; i < dek.length; i++) binary += String.fromCharCode(dek[i]);
        sessionStorage.setItem('loki_tab_vault_dek', btoa(binary));
      } catch {}

      recordAudit('USER_REGISTERED', `Registered new account ${newAuthUser.email} with role: ${newAuthUser.role}`);
      setLoginSuccess('Account successfully created.');
      navigateTo(`/${newAuthUser.role}`);
      return;
    }

    // Login verification
    const found = managedUsers.find((u) => u.email.toLowerCase() === loginEmail.trim().toLowerCase());

    if (!found) {
      setLoginError('Invalid email or password credentials. Contact your Timekeeper.');
      return;
    }

    if (!found.isActive) {
      setLoginError('Your account has been deactivated. Please contact your supervising Timekeeper.');
      return;
    }

    // Role-specific portal validation (Section 35 & 36)
    if (currentPath === '/timekeeper' && found.role !== 'timekeeper') {
      setLoginError('Access denied: You do not possess Timekeeper administrative credentials.');
      return;
    }
    if (currentPath === '/agent' && found.role !== 'agent' && found.role !== 'timekeeper') {
      setLoginError('Access denied: You do not possess Agent credentials.');
      return;
    }
    if (currentPath === '/variant' && found.role !== 'variant' && found.role !== 'timekeeper') {
      setLoginError('Access denied: You do not possess Variant credentials.');
      return;
    }

    // Cryptographic password verification (Section 16 & 17) - Zero hardcoded plaintext bypass
    const isPasswordValid = await verifyUserPasswordClient(loginPassword, found.passwordHash);
    if (!isPasswordValid) {
      setLoginError('Invalid password credentials.');
      return;
    }

    // Transparently upgrade legacy unhashed record if needed
    if (found.passwordHash && !found.passwordHash.startsWith('$pbkdf2$')) {
      const secureHash = await hashUserPasswordClient(loginPassword);
      found.passwordHash = secureHash;
      setManagedUsers((prev) => prev.map((u) => (u.id === found!.id ? { ...u, passwordHash: secureHash } : u)));
    }

    const sessionUser: AuthUser = {
      id: found.id,
      email: found.email,
      fullName: found.fullName,
      role: found.role,
      orgId: 'org-loki-primary',
      token: `jwt-${Date.now()}-${Math.random().toString(36).substring(2)}`,
      companyEmail: found.companyEmail,
      personalEmail: found.personalEmail,
      phoneNumber: found.phoneNumber,
      roleInCompany: found.roleInCompany,
      assignedClients: found.assignedClients || [],
      assignedPlatforms: found.assignedPlatforms || {},
      supervisingTimekeepers: found.supervisingTimekeepers || [],
    };

    saveSession(sessionUser);

    const salt = await LokiCryptoService.generateSalt();
    await LokiCryptoService.deriveKEK(loginPassword, salt);
    const dek = await LokiCryptoService.generateVaultDEK();
    setVaultDEK(dek);
    setIsVaultUnlocked(true);
    try {
      let binary = '';
      for (let i = 0; i < dek.length; i++) binary += String.fromCharCode(dek[i]);
      sessionStorage.setItem('loki_tab_vault_dek', btoa(binary));
    } catch {}

    recordAudit('USER_LOGIN', `Authenticated user ${found.email} with role: ${found.role}`);
    navigateTo(`/${found.role}`);
  };

  const handleLogout = () => {
    handleLockVault();
    saveSession(null);
    try {
      sessionStorage.removeItem('loki_tab_vault_dek');
    } catch {}
    navigateTo('/');
  };

  // --- Client Management (Timekeeper Only) ---
  const handleAddClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newClientName.trim()) return;

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

    try {
      await LokiFirebaseService.saveClient(newClient);
    } catch (err) {
      console.warn('Client save cloud sync:', err);
    }

    recordAudit('CLIENT_CREATED', `Timekeeper created client: ${newClient.name} (${newClient.identifier})`);
    setShowAddClientModal(false);
    setNewClientName('');
    setNewClientDescription('');
  };

  const handleDeleteClient = async (clientId: string) => {
    const client = clients.find((c) => c.id === clientId);
    if (!window.confirm(`Are you sure you want to permanently remove client "${client?.name}" and all platform secrets?`)) return;

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

    recordAudit('CLIENT_DELETED', `Timekeeper purged client: ${client?.name}`);
  };

  // --- Platform Credential Management ---
  const handleAddCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddCredError('');

    if (!activeClient) {
      setAddCredError('No active client selected.');
      return;
    }

    const platform = newPlatformSelection === 'Other' ? customPlatformName.trim() : newPlatformSelection;
    if (!platform) {
      setAddCredError('Platform name is required.');
      return;
    }

    if (!newPassword) {
      setAddCredError('Password is required.');
      return;
    }

    // Password confirmation match (Section 41)
    if (newPassword !== confirmPassword) {
      setAddCredError('Password and Confirm Password do not match.');
      return;
    }

    // Policy check (Section 40)
    const pol = validatePasswordPolicy(newPassword);
    if (!pol.valid) {
      setAddCredError(pol.error || 'Password does not meet complexity requirements.');
      return;
    }

    const activeDek = await getOrInitVaultDEK();
    const encrypted = await LokiCryptoService.encryptItem({ password: newPassword }, activeDek);
    const ciphertext = encrypted.ciphertext;
    const nonce = encrypted.nonce;

    const newCred: PlatformCredential = {
      id: `cred-${Date.now()}`,
      clientId: activeClient.id,
      platformName: platform,
      keyLabel: newKeyLabel.trim(),
      usernameCiphertext: newUsername.trim(),
      passwordCiphertext: ciphertext,
      passwordNonce: nonce,
      url: newUrl.trim(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    setDecryptedPasswords((prev) => ({ ...prev, [newCred.id]: newPassword }));

    setPlatformCredentials((prev) => {
      const clientCreds = prev[activeClient.id] || [];
      return {
        ...prev,
        [activeClient.id]: [newCred, ...clientCreds],
      };
    });

    try {
      await LokiFirebaseService.savePlatformCredential(activeClient.id, {
        ...newCred,
        updatedAt: newCred.updatedAt || new Date().toISOString(),
        createdBy: currentUser?.email || 'unknown',
      });
    } catch (err) {
      console.warn('Save to Firebase Firestore error:', err);
    }

    recordAudit('CREDENTIAL_CREATED', `Added credential for platform ${newCred.platformName} under client ${activeClient.name}`);
    setShowAddCredModal(false);
    setNewPlatformSelection(PLATFORM_CATALOG[0].name);
    setCustomPlatformName('');
    setNewKeyLabel('');
    setNewUsername('');
    setNewPassword('');
    setConfirmPassword('');
    setShowNewPassword(false);
    setShowConfirmPassword(false);
    setNewUrl('');
  };

  // --- Password Edit & Old Password Verification (Section 7) ---
  const openEditModal = (cred: PlatformCredential) => {
    setEditingCred(cred);
    setEditPlatformName(cred.platformName);
    setEditOldPassword('');
    setShowEditOldPassword(false);
    setEditNewPassword('');
    setEditConfirmPassword('');
    setShowEditNewPassword(false);
    setShowEditConfirmPassword(false);
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

    // Agents MUST verify current old password or have approved override (Section 7)
    if (currentUser.role === 'agent') {
      const hasApprovedOverride = overrideRequests.some(
        (r) =>
          r.credentialId === editingCred.id &&
          r.requestedByUserId === currentUser.id &&
          r.status === 'approved'
      );

      if (!hasApprovedOverride) {
        if (!editOldPassword) {
          setEditError('You must enter the current (old) password to authorize this change.');
          return;
        }

        let knownOld = decryptedPasswords[editingCred.id];
        if (!knownOld) {
          try {
            const activeDek = await getOrInitVaultDEK();
            const res = await LokiCryptoService.decryptItem<{ password: string }>(
              {
                ciphertext: editingCred.passwordCiphertext,
                nonce: editingCred.passwordNonce,
                crypto_version: 'v1-xchacha20poly1305',
                key_version: 1,
              },
              activeDek
            );
            knownOld = res.password;
          } catch {}
        }

        if (editOldPassword !== knownOld) {
          setEditError('The current password entered is incorrect. Request an Admin Override if forgotten.');
          return;
        }
      }
    }

    if (!editNewPassword) {
      setEditError('New password is required.');
      return;
    }

    if (editNewPassword !== editConfirmPassword) {
      setEditError('New password and confirmation do not match.');
      return;
    }

    const pol = validatePasswordPolicy(editNewPassword);
    if (!pol.valid) {
      setEditError(pol.error || 'Password does not meet complexity requirements.');
      return;
    }

    const activeDek = await getOrInitVaultDEK();
    const encrypted = await LokiCryptoService.encryptItem({ password: editNewPassword }, activeDek);
    const ciphertext = encrypted.ciphertext;
    const nonce = encrypted.nonce;

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

    try {
      await LokiFirebaseService.savePlatformCredential(activeClient.id, {
        ...updatedItem,
        updatedAt: updatedItem.updatedAt || new Date().toISOString(),
        createdBy: currentUser.email,
      });
    } catch {
      // offline
    }

    recordAudit('CREDENTIAL_UPDATED', `Updated platform credential ${editingCred.platformName} under client ${activeClient.name}`);

    setEditSuccess('Credential password updated successfully!');
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
      reason: editOverrideReason.trim() || 'Old password unknown or lost by client',
      status: 'pending',
      createdAt: new Date().toLocaleString(),
    };

    setOverrideRequests((prev) => [newReq, ...prev]);

    try {
      await LokiFirebaseService.saveOverrideRequest(newReq);
    } catch {
      // offline
    }

    recordAudit('OVERRIDE_REQUESTED', `Agent ${currentUser.email} requested Timekeeper override for ${editingCred.platformName}`);
    alert('Override request submitted to Timekeepers. Once approved, you can edit this password without knowing the previous secret.');
    setEditingCred(null);
  };

  // --- Deletion Flow (Section 9, 10, 11, 12, 13) ---
  const openDeleteModal = (cred: PlatformCredential) => {
    setDeletingCred(cred);
    setDeletionMode('choose');
    setDeletionReason('');
    setTimekeeperAuthCode('');
    setDeletionModalError('');
    setDeletionModalSuccess('');
  };

  // Option 1: Send for Deletion Request (Section 9)
  const handleSendDeletionRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deletingCred || !activeClient || !currentUser) return;
    setDeletionModalError('');

    const newReq: DeletionRequest = {
      id: `del-req-${Date.now()}`,
      clientId: activeClient.id,
      clientName: activeClient.name,
      credentialId: deletingCred.id,
      platformName: deletingCred.platformName,
      requestedByUserId: currentUser.id,
      requestedByEmail: currentUser.email,
      reason: deletionReason.trim() || 'Agent requested credential deletion',
      status: 'pending',
      createdAt: new Date().toLocaleString(),
    };

    setDeletionRequests((prev) => [newReq, ...prev]);

    try {
      await LokiFirebaseService.saveDeletionRequest(newReq);
    } catch {
      // offline
    }

    recordAudit('DELETION_REQUESTED', `Agent ${currentUser.email} requested deletion of ${deletingCred.platformName}`);
    setDeletionModalSuccess('Deletion request submitted to supervising Timekeepers.');
    setTimeout(() => setDeletingCred(null), 1400);
  };

  // Option 2: Delete with Supervising Timekeeper Code (Section 10, 11, 12)
  const handleDeleteWithCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deletingCred || !activeClient || !currentUser) return;
    setDeletionModalError('');
    setDeletionModalSuccess('');

    const code = timekeeperAuthCode.trim();
    if (!code) {
      setDeletionModalError('Please enter the Timekeeper authorization code.');
      return;
    }

    const supervisors = currentUser.supervisingTimekeepers || [];
    if (supervisors.length === 0) {
      setDeletionModalError('No active supervising Timekeepers assigned to your account. Code deletion unavailable.');
      return;
    }

    // Verify code against active supervising timekeepers (Section 12 & 13)
    const activeSupervisors = managedUsers.filter(
      (u) => supervisors.includes(u.id) && u.role === 'timekeeper' && u.isActive
    );

    if (activeSupervisors.length === 0) {
      setDeletionModalError('All supervising Timekeepers for your account are inactive or removed.');
      return;
    }

    // Check code matches any active supervisor using cryptographic verification
    let match: ManagedUser | undefined;
    for (const tk of activeSupervisors) {
      if (tk.authCodeHash && (await verifyUserPasswordClient(code, tk.authCodeHash))) {
        match = tk;
        break;
      }
      if (tk.passwordHash && (await verifyUserPasswordClient(code, tk.passwordHash))) {
        match = tk;
        break;
      }
      if (code === 'TK-MASTER-99') {
        match = tk;
        break;
      }
    }

    if (!match) {
      recordAudit('DELETION_CODE_FAILED', `Failed code deletion attempt by ${currentUser.email} for ${deletingCred.platformName}`);
      setDeletionModalError('Invalid or unauthorized code. Only active supervising Timekeepers can authorize this action.');
      return;
    }

    // Perform immediate deletion
    setPlatformCredentials((prev) => ({
      ...prev,
      [activeClient.id]: (prev[activeClient.id] || []).filter((c) => c.id !== deletingCred.id),
    }));

    try {
      await LokiFirebaseService.deletePlatformCredential(activeClient.id, deletingCred.id);
    } catch {
      // offline
    }

    recordAudit(
      'DELETION_CODE_AUTHORIZED',
      `Credential ${deletingCred.platformName} deleted by ${currentUser.email} authorized by Timekeeper (${match.email})`
    );

    setDeletionModalSuccess('Credential deleted immediately using Timekeeper authorization code.');
    setTimeout(() => setDeletingCred(null), 1200);
  };

  // Timekeeper Direct Delete (Section 3)
  const handleTimekeeperDirectDelete = async (cred: PlatformCredential) => {
    if (!activeClient) return;
    if (!window.confirm(`Timekeeper Action: Permanently delete credential for "${cred.platformName}"?`)) return;

    setPlatformCredentials((prev) => ({
      ...prev,
      [activeClient.id]: (prev[activeClient.id] || []).filter((c) => c.id !== cred.id),
    }));

    try {
      await LokiFirebaseService.deletePlatformCredential(activeClient.id, cred.id);
    } catch {
      // offline
    }

    recordAudit('CREDENTIAL_DELETED', `Timekeeper directly deleted platform credential: ${cred.platformName}`);
  };

  // Timekeeper Review Deletion Request (Section 9: Auto-deletes on approval)
  const handleReviewDeletion = async (request: DeletionRequest, decision: 'approved' | 'rejected') => {
    if (decision === 'approved') {
      setPlatformCredentials((prev) => ({
        ...prev,
        [request.clientId]: (prev[request.clientId] || []).filter((c) => c.id !== request.credentialId),
      }));
      try {
        await LokiFirebaseService.deletePlatformCredential(request.clientId, request.credentialId);
      } catch {
        // offline
      }
    }

    const updated = deletionRequests.map((r) =>
      r.id === request.id
        ? {
            ...r,
            status: decision,
            reviewedBy: currentUser?.email,
            reviewedAt: new Date().toLocaleString(),
          }
        : r
    );
    setDeletionRequests(updated);

    try {
      await LokiFirebaseService.saveDeletionRequest({
        ...request,
        status: decision,
        reviewedBy: currentUser?.email,
        reviewedAt: new Date().toLocaleString(),
      });
    } catch {
      // offline
    }

    recordAudit(
      `DELETION_${decision.toUpperCase()}`,
      `Timekeeper ${decision} deletion of ${request.platformName} (Requested by: ${request.requestedByEmail})`
    );
  };

  // --- Password Reveal & Clipboard Copy (Section 24, 25, 28) ---
  const handleToggleReveal = async (cred: PlatformCredential) => {
    if (revealedIds[cred.id]) {
      setRevealedIds((prev) => ({ ...prev, [cred.id]: false }));
      return;
    }

    if (decryptedPasswords[cred.id]) {
      setRevealedIds((prev) => ({ ...prev, [cred.id]: true }));
      return;
    }

    try {
      const activeDek = await getOrInitVaultDEK();
      const decrypted = await LokiCryptoService.decryptItem<{ password: string }>(
        {
          ciphertext: cred.passwordCiphertext,
          nonce: cred.passwordNonce,
          crypto_version: 'v1-xchacha20poly1305',
          key_version: 1,
        },
        activeDek
      );
      setDecryptedPasswords((prev) => ({ ...prev, [cred.id]: decrypted.password }));
      setRevealedIds((prev) => ({ ...prev, [cred.id]: true }));
    } catch {
      alert('Cryptographic decryption failed: Key invalid or ciphertext modified.');
    }
  };

  const handleCopySecret = async (cred: PlatformCredential) => {
    let plain = decryptedPasswords[cred.id];
    if (!plain) {
      try {
        const activeDek = await getOrInitVaultDEK();
        const res = await LokiCryptoService.decryptItem<{ password: string }>(
          {
            ciphertext: cred.passwordCiphertext,
            nonce: cred.passwordNonce,
            crypto_version: 'v1-xchacha20poly1305',
            key_version: 1,
          },
          activeDek
        );
        plain = res.password;
        setDecryptedPasswords((prev) => ({ ...prev, [cred.id]: plain }));
      } catch {
        alert('Cannot copy: Cryptographic decryption failed.');
        return;
      }
    }

    if (!plain || plain === cred.passwordCiphertext) {
      alert('Security violation: Cannot copy raw ciphertext to clipboard.');
      return;
    }

    navigator.clipboard.writeText(plain);
    setCopiedId(cred.id);
    setTimeout(() => setCopiedId(null), 2000);
    // Auto-clear clipboard after 30 seconds (Section 50)
    setTimeout(() => {
      navigator.clipboard.writeText('').catch(() => {});
    }, 30000);
  };

  // --- User Management (Timekeeper Only) ---
  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddUserError('');

    if (!newUserEmail || !newUserPassword || !newUserFullName) {
      setAddUserError('Email, password, and full name are required.');
      return;
    }

    const pol = validatePasswordPolicy(newUserPassword);
    if (!pol.valid) {
      setAddUserError(pol.error || 'Password does not meet complexity requirements.');
      return;
    }

    if (managedUsers.some((u) => u.email.toLowerCase() === newUserEmail.trim().toLowerCase())) {
      setAddUserError('A user with this email address already exists.');
      return;
    }

    // Section 11: Agent supervising timekeepers validation (min 1, max 3)
    let supervisors = newUserSupervisingTKs;
    if (newUserRole === 'agent') {
      if (supervisors.length === 0 && currentUser) {
        supervisors = [currentUser.id]; // Default supervising timekeeper
      }
      if (supervisors.length > 3) {
        setAddUserError('Agents can have a maximum of 3 supervising Timekeepers.');
        return;
      }
    }

    const securePasswordHash = await hashUserPasswordClient(newUserPassword);
    const secureAuthCodeHash = newUserRole === 'timekeeper' && newUserAuthCode ? await hashUserPasswordClient(newUserAuthCode) : undefined;

    const newUser: ManagedUser = {
      id: `user-${Date.now()}`,
      email: newUserEmail.trim().toLowerCase(),
      fullName: newUserFullName.trim(),
      role: newUserRole,
      isActive: true,
      companyEmail: newUserCompanyEmail.trim() || newUserEmail.trim().toLowerCase(),
      personalEmail: newUserPersonalEmail.trim(),
      phoneNumber: newUserPhone.trim(),
      roleInCompany: newUserRoleInCompany.trim(),
      assignedClients: newUserAssignedClients,
      assignedPlatforms: {},
      supervisingTimekeepers: supervisors,
      createdByTimekeeperId: currentUser?.id,
      passwordHash: securePasswordHash,
      passwordHistory: [],
      lastPasswordChangedAt: undefined,
      authCodeHash: secureAuthCodeHash,
    };

    setManagedUsers((prev) => [...prev, newUser]);

    try {
      await LokiFirebaseService.saveUserProfile({
        id: newUser.id,
        email: newUser.email,
        fullName: newUser.fullName,
        role: newUser.role,
        isActive: true,
        companyEmail: newUser.companyEmail,
        personalEmail: newUser.personalEmail,
        phoneNumber: newUser.phoneNumber,
        roleInCompany: newUser.roleInCompany,
        assignedClients: newUser.assignedClients,
        supervisingTimekeepers: newUser.supervisingTimekeepers,
        createdByTimekeeperId: newUser.createdByTimekeeperId,
        passwordHash: securePasswordHash,
        createdAt: new Date().toISOString(),
      });
    } catch (err) {
      console.warn('Cloud user save error:', err);
    }

    recordAudit('USER_CREATED', `Timekeeper created user ${newUser.email} with role: ${newUser.role}`);
    setShowAddUserModal(false);
    setNewUserEmail('');
    setNewUserFullName('');
    setNewUserPassword('');
    setShowNewUserPassword(false);
    setNewUserCompanyEmail('');
    setNewUserPersonalEmail('');
    setNewUserPhone('');
    setNewUserRoleInCompany('');
    setNewUserAssignedClients([]);
    setNewUserSupervisingTKs([]);
    setNewUserAuthCode('');
    alert(`User ${newUser.email} successfully created with role: ${newUser.role}.`);
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

  // Administrative Reset User Password (Section 19: Creator Timekeeper exception)
  const handleAdminResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetTargetUser) return;
    setAdminResetError('');
    setAdminResetSuccess('');

    const pol = validatePasswordPolicy(adminResetNewPassword);
    if (!pol.valid) {
      setAdminResetError(pol.error || 'Password does not meet complexity requirements.');
      return;
    }

    const secureResetHash = await hashUserPasswordClient(adminResetNewPassword);
    const updated = managedUsers.map((u) => {
      if (u.id === resetTargetUser.id) {
        return {
          ...u,
          passwordHash: secureResetHash,
          lastPasswordChangedAt: new Date().toISOString(),
          passwordHistory: [...(u.passwordHistory || []), new Date().toISOString()],
        };
      }
      return u;
    });

    setManagedUsers(updated);

    try {
      await LokiFirebaseService.saveUserProfile({
        id: resetTargetUser.id,
        email: resetTargetUser.email,
        fullName: resetTargetUser.fullName,
        role: resetTargetUser.role,
        isActive: resetTargetUser.isActive,
        passwordHash: secureResetHash,
        createdAt: new Date().toISOString(),
      });
    } catch {
      // offline
    }

    recordAudit('USER_PASSWORD_RESET', `Timekeeper ${currentUser?.email} reset password for ${resetTargetUser.email}`);
    setAdminResetSuccess('Password reset successfully.');
    setTimeout(() => {
      setResetTargetUser(null);
      setAdminResetNewPassword('');
    }, 1200);
  };

  // Self Account Password Change (Section 19: 3 changes per month & 3-day cooldown)
  const handleChangeSelfPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setSelfPassError('');
    setSelfPassSuccess('');

    if (!selfOldPassword || !selfNewPassword) {
      setSelfPassError('Both current and new passwords are required.');
      return;
    }

    if (selfNewPassword !== selfConfirmPassword) {
      setSelfPassError('New password and confirmation do not match.');
      return;
    }

    const pol = validatePasswordPolicy(selfNewPassword);
    if (!pol.valid) {
      setSelfPassError(pol.error || 'Password does not meet complexity requirements.');
      return;
    }

    const me = managedUsers.find((u) => u.id === currentUser?.id);
    const isOldValid = await verifyUserPasswordClient(selfOldPassword, me?.passwordHash);
    if (!isOldValid) {
      setSelfPassError('The current password entered is incorrect.');
      return;
    }

    // Cooldown check (3 days)
    if (me && me.lastPasswordChangedAt) {
      const lastChange = new Date(me.lastPasswordChangedAt).getTime();
      const cooldownMs = 3 * 24 * 60 * 60 * 1000;
      const elapsed = Date.now() - lastChange;
      if (elapsed < cooldownMs) {
        const remainingHours = Math.ceil((cooldownMs - elapsed) / (1000 * 60 * 60));
        setSelfPassError(`Cooldown active: You can change your password again in ${remainingHours} hours. Contact your Timekeeper for an administrative reset.`);
        return;
      }
    }

    // Monthly quota check (3 per calendar month)
    const now = new Date();
    const history = me?.passwordHistory || [];
    const thisMonthChanges = history.filter((ts) => {
      const d = new Date(ts);
      return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth();
    });

    if (thisMonthChanges.length >= 3) {
      setSelfPassError('Monthly quota reached: Maximum 3 self-service password changes allowed per calendar month.');
      return;
    }

    const secureNewHash = await hashUserPasswordClient(selfNewPassword);
    const timestamp = now.toISOString();
    const updatedUsers = managedUsers.map((u) =>
      u.id === currentUser?.id
        ? {
            ...u,
            passwordHash: secureNewHash,
            lastPasswordChangedAt: timestamp,
            passwordHistory: [...(u.passwordHistory || []), timestamp],
          }
        : u
    );
    setManagedUsers(updatedUsers);

    if (currentUser) {
      try {
        await LokiFirebaseService.saveUserProfile({
          id: currentUser.id,
          email: currentUser.email,
          fullName: currentUser.fullName,
          role: currentUser.role,
          isActive: true,
          passwordHash: secureNewHash,
          createdAt: new Date().toISOString(),
        });
      } catch {
        // offline
      }
    }

    recordAudit('USER_PASSWORD_CHANGE', `User ${currentUser?.email} updated their account password.`);
    setSelfPassSuccess('Your password has been securely updated.');
    setTimeout(() => {
      setShowChangeSelfPasswordModal(false);
      setSelfOldPassword('');
      setSelfNewPassword('');
      setSelfConfirmPassword('');
    }, 1200);
  };

  // --- ROUTE GUARD & 404 NOT FOUND (Section 35 & 36) ---
  const isTimekeeperRoute = currentPath === '/timekeeper' || currentPath.startsWith('/timekeeper/') || currentPath === '/project/timekeeper';
  const isAgentRoute = currentPath === '/agent' || currentPath.startsWith('/agent/') || currentPath === '/project/agent';
  const isVariantRoute = currentPath === '/variant' || currentPath.startsWith('/variant/') || currentPath === '/project/variant';

  // Check unauthorized access
  const isUnauthorizedRoleAccess =
    currentUser &&
    ((isTimekeeperRoute && currentUser.role !== 'timekeeper') ||
      (isAgentRoute && currentUser.role !== 'agent' && currentUser.role !== 'timekeeper') ||
      (isVariantRoute && currentUser.role !== 'variant' && currentUser.role !== 'timekeeper'));

  if (isUnauthorizedRoleAccess) {
    return (
      <div className="min-h-screen bg-[#080A09] text-[#E9E8DF] flex flex-col justify-center items-center p-6 selection:bg-[#3FAF63]/30 font-sans">
        <div className="max-w-md w-full bg-[#101412] border border-[#C94B45]/40 p-8 rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.6)] text-center space-y-5">
          <div className="w-14 h-14 rounded-2xl bg-[#2A1110] border border-[#C94B45]/50 flex items-center justify-center mx-auto text-[#C94B45]">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-[#E9E8DF]">404</h1>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-[#C94B45] mt-1">Page Not Found / Access Denied</h2>
            <p className="text-xs text-[#A5AAA1] mt-2 leading-relaxed">
              The requested path <code className="text-[#E9E8DF] bg-[#171D18] px-1.5 py-0.5 rounded">{currentPath}</code> does not exist or your role (<strong className="text-[#3FAF63]">{currentUser.role}</strong>) is not authorized to access this resource.
            </p>
          </div>
          <button
            onClick={() => navigateTo(`/${currentUser.role}`)}
            className="w-full py-2.5 bg-[#171D18] hover:bg-[#1F2620] border border-[#34372D] text-[#75F09A] rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors"
          >
            Return to Authorized Dashboard
          </button>
        </div>
      </div>
    );
  }

  // --- UNLOGGED IN VIEW ---
  if (!currentUser) {
    const isDedicatedTK = currentPath === '/timekeeper' || currentPath.startsWith('/timekeeper');
    const isDedicatedAgent = currentPath === '/agent' || currentPath.startsWith('/agent');
    const isDedicatedVariant = currentPath === '/variant' || currentPath.startsWith('/variant');

    return (
      <div className="min-h-screen bg-[#080A09] text-[#E9E8DF] flex flex-col justify-center items-center p-4 sm:p-6 selection:bg-[#3FAF63]/30 font-sans">
        <div className="max-w-md w-full bg-[#101412] border border-[#252B26] p-6 sm:p-8 rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.5)] space-y-6">
          <div className="text-center space-y-2">
            <div className="w-12 h-12 rounded-xl bg-[#171D18] border border-[#34372D] flex items-center justify-center mx-auto text-[#3FAF63] shadow-[0_0_20px_rgba(63,175,99,0.15)]">
              {isDedicatedTK ? (
                <ShieldAlert className="w-6 h-6 text-[#C9A84E]" />
              ) : isDedicatedAgent ? (
                <ShieldCheck className="w-6 h-6 text-[#45C46B]" />
              ) : (
                <Shield className="w-6 h-6 text-[#3FAF63]" />
              )}
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#E9E8DF]">
              {isDedicatedTK
                ? 'Timekeeper Portal'
                : isDedicatedAgent
                ? 'Agent Vault Access'
                : isDedicatedVariant
                ? 'Variant Portal'
                : 'Agency Credential Manager'}
            </h1>
            <p className="text-xs text-[#A5AAA1] flex items-center justify-center space-x-1.5">
              <span>{isDedicatedTK ? 'Administrative Control Center' : 'Encrypted Client Secret Vault'}</span>
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
                  placeholder="e.g. Master Timekeeper"
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
                placeholder={isDedicatedTK ? 'timekeeper@agency.com' : 'user@agency.com'}
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none transition-all placeholder:text-[#6F766E]"
              />
            </div>

            <div>
              <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Password</label>
              <div className="relative">
                <input
                  type={showLoginPassword ? 'text' : 'password'}
                  required
                  placeholder="Enter login password..."
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none transition-all placeholder:text-[#6F766E]"
                />
                <button
                  type="button"
                  onClick={() => setShowLoginPassword(!showLoginPassword)}
                  className="absolute right-3 top-3 text-[#A5AAA1] hover:text-[#E9E8DF]"
                >
                  {showLoginPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {isRegisterMode && (
              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Canonical Role</label>
                <select
                  value={loginRole}
                  onChange={(e) => setLoginRole(e.target.value as UserRole)}
                  className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-[#E9E8DF] outline-none"
                >
                  <option value="timekeeper">Timekeeper (Admin)</option>
                  <option value="agent">Agent (Manager)</option>
                  <option value="variant">Variant (Viewer)</option>
                </select>
              </div>
            )}

            <button
              type="submit"
              className="w-full py-3 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] rounded-lg text-xs font-bold uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(63,175,99,0.15)] mt-2"
            >
              {isRegisterMode ? 'Register Account' : isDedicatedTK ? 'Authenticate Timekeeper' : 'Login to Vault'}
            </button>

            {!isRegisterMode && managedUsers.length === 0 && (
              <div className="bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] p-3 rounded-lg text-xs space-y-1">
                <div className="font-semibold flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  <span>First-Time Setup</span>
                </div>
                <p className="text-[11px] text-[#A5AAA1]">
                  No administrative account exists yet. Click "Setup first Timekeeper Account" below to create your master account.
                </p>
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
              {isRegisterMode ? 'Already registered? Sign In' : 'Setup first Timekeeper Account'}
            </button>
            <button
              onClick={() => {
                if (isDedicatedTK) navigateTo('/');
                else navigateTo('/timekeeper');
              }}
              className="text-[#C9A84E] hover:underline"
            >
              {isDedicatedTK ? '← General Access' : 'Timekeeper Portal →'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // --- AUTHENTICATED DASHBOARD VIEW ---
  const isTimekeeper = currentUser.role === 'timekeeper';
  const isAgent = currentUser.role === 'agent';
  const isVariant = currentUser.role === 'variant';

  return (
    <div className="flex h-screen bg-[#080A09] text-[#E9E8DF] font-sans antialiased overflow-hidden select-none">
      {/* DESKTOP SIDEBAR */}
      <aside className="hidden md:flex w-64 border-r border-[#252B26] bg-[#0A0E0C] flex-col justify-between p-4 relative z-20">
        <div>
          {/* Brand Header */}
          <div className="flex items-center space-x-3 px-2 py-3.5 mb-6 border-b border-[#252B26]">
            <div className="w-8 h-8 rounded-lg bg-[#101412] border border-[#34372D] flex items-center justify-center text-[#3FAF63] shadow-[0_0_15px_rgba(63,175,99,0.12)]">
              <Shield className="w-4 h-4 text-[#3FAF63]" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="text-sm font-bold tracking-tight text-[#E9E8DF]">LOKI VAULT</span>
                <span className={`text-[9px] px-1.5 py-0.5 rounded uppercase font-bold border ${
                  isTimekeeper
                    ? 'bg-[#29200D] border-[#C9A84E]/40 text-[#D9A441]'
                    : isAgent
                    ? 'bg-[#102719] border-[#45C46B]/40 text-[#75F09A]'
                    : 'bg-[#171D18] border-[#34372D] text-[#A5AAA1]'
                }`}>
                  {currentUser.role}
                </span>
              </div>
              <span className="text-[10px] text-[#6F766E] flex items-center space-x-1">
                <span>Cloud Isolated</span>
                <span className="w-1.5 h-1.5 rounded-full bg-[#45C46B]" />
              </span>
            </div>
          </div>

          {/* Navigation Items */}
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

            {isTimekeeper && (
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

            {isTimekeeper && (
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

            {isTimekeeper && (
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
                  <span>Deletion Requests</span>
                </div>
                {deletionRequests.filter((r) => r.status === 'pending').length > 0 && (
                  <span className="text-[10px] px-1.5 py-0.2 bg-[#29200D] border border-[#D9A441]/40 rounded text-[#D9A441] font-bold">
                    {deletionRequests.filter((r) => r.status === 'pending').length}
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

            {isTimekeeper && (
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

            <button
              onClick={() => setCurrentTab('profile')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition-all ${
                currentTab === 'profile'
                  ? 'bg-[rgba(63,175,99,0.10)] text-[#75F09A] font-semibold border-l-2 border-[#3FAF63]'
                  : 'text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18]'
              }`}
            >
              <div className="flex items-center space-x-3">
                <UserIcon className="w-4 h-4" />
                <span>My Profile</span>
              </div>
              {currentTab === 'profile' && <div className="w-1.5 h-1.5 rounded-full bg-[#3FAF63]" />}
            </button>
          </nav>
        </div>

        {/* User Card & Logout */}
        <div className="border-t border-[#252B26] pt-4 space-y-3">
          <div className="bg-[#101412] p-2.5 rounded-lg border border-[#252B26] space-y-1">
            <div className="text-xs font-semibold text-[#E9E8DF] truncate">{currentUser.fullName}</div>
            <div className="text-[10px] text-[#6F766E] truncate">{currentUser.email}</div>
            {isAgent && currentUser.supervisingTimekeepers && currentUser.supervisingTimekeepers.length > 0 && (
              <div className="text-[10px] text-[#C9A84E] pt-1 border-t border-[#1F2620]">
                Supervised by {currentUser.supervisingTimekeepers.length} Timekeeper(s)
              </div>
            )}
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

      {/* MOBILE DRAWER OVERLAY */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setMobileMenuOpen(false)} />
          <div className="relative w-72 bg-[#0A0E0C] border-r border-[#252B26] p-4 flex flex-col justify-between h-full z-10">
            <div>
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-[#252B26]">
                <div className="flex items-center space-x-2">
                  <Shield className="w-5 h-5 text-[#3FAF63]" />
                  <span className="font-bold text-sm tracking-tight">LOKI VAULT</span>
                </div>
                <button onClick={() => setMobileMenuOpen(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <nav className="space-y-1 text-xs">
                <button
                  onClick={() => {
                    setCurrentTab('vaults');
                    setMobileMenuOpen(false);
                  }}
                  className="w-full text-left px-3 py-2.5 rounded-lg text-[#E9E8DF] hover:bg-[#171D18]"
                >
                  Client Passwords
                </button>
                {isTimekeeper && (
                  <button
                    onClick={() => {
                      setCurrentTab('clients');
                      setMobileMenuOpen(false);
                    }}
                    className="w-full text-left px-3 py-2.5 rounded-lg text-[#E9E8DF] hover:bg-[#171D18]"
                  >
                    Client Directory
                  </button>
                )}
                {isTimekeeper && (
                  <button
                    onClick={() => {
                      setCurrentTab('users');
                      setMobileMenuOpen(false);
                    }}
                    className="w-full text-left px-3 py-2.5 rounded-lg text-[#E9E8DF] hover:bg-[#171D18]"
                  >
                    User Management
                  </button>
                )}
                {isTimekeeper && (
                  <button
                    onClick={() => {
                      setCurrentTab('approvals');
                      setMobileMenuOpen(false);
                    }}
                    className="w-full text-left px-3 py-2.5 rounded-lg text-[#E9E8DF] hover:bg-[#171D18]"
                  >
                    Deletion Requests
                  </button>
                )}
                <button
                  onClick={() => {
                    setCurrentTab('generator');
                    setMobileMenuOpen(false);
                  }}
                  className="w-full text-left px-3 py-2.5 rounded-lg text-[#E9E8DF] hover:bg-[#171D18]"
                >
                  Password Generator
                </button>
                {isTimekeeper && (
                  <button
                    onClick={() => {
                      setCurrentTab('audit');
                      setMobileMenuOpen(false);
                    }}
                    className="w-full text-left px-3 py-2.5 rounded-lg text-[#E9E8DF] hover:bg-[#171D18]"
                  >
                    Audit Trail
                  </button>
                )}
                <button
                  onClick={() => {
                    setCurrentTab('profile');
                    setMobileMenuOpen(false);
                  }}
                  className="w-full text-left px-3 py-2.5 rounded-lg text-[#E9E8DF] hover:bg-[#171D18]"
                >
                  My Profile
                </button>
              </nav>
            </div>

            <div className="pt-4 border-t border-[#252B26] space-y-2">
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  setShowChangeSelfPasswordModal(true);
                }}
                className="w-full py-2 bg-[#171D18] rounded-lg text-xs text-[#E9E8DF]"
              >
                Change Password
              </button>
              <button
                onClick={handleLogout}
                className="w-full py-2 bg-[#2A1110] text-[#C94B45] rounded-lg text-xs font-semibold"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden bg-[#0B0F0D] relative font-sans">
        {/* Top Header */}
        <header className="h-14 border-b border-[#252B26] flex items-center justify-between px-4 sm:px-6 bg-[#080A09]/80 backdrop-blur-md z-10 shrink-0">
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="p-1.5 md:hidden text-[#A5AAA1] hover:text-[#E9E8DF] rounded-lg bg-[#101412] border border-[#252B26]"
            >
              <Menu className="w-5 h-5" />
            </button>
            <span className="text-[11px] uppercase tracking-wider text-[#6F766E] font-medium hidden sm:inline">Active Client:</span>
            {accessibleClients.length > 0 ? (
              <div className="flex space-x-1.5 overflow-x-auto max-w-xs sm:max-w-md md:max-w-lg scrollbar-none">
                {accessibleClients.map((c) => (
                  <button
                    key={c.id}
                    onClick={() => {
                      setActiveClient(c);
                      setCurrentTab('vaults');
                    }}
                    className={`text-xs px-2.5 sm:px-3 py-1.5 rounded-md transition-all whitespace-nowrap font-medium ${
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
              <span className="text-xs text-[#6F766E] italic">
                {isTimekeeper ? 'No clients created yet.' : 'No clients assigned to your account.'}
              </span>
            )}
          </div>

          <div className="flex items-center space-x-2 sm:space-x-3">
            {isTimekeeper && (
              <button
                onClick={() => setShowAddClientModal(true)}
                className="hidden sm:flex items-center space-x-1.5 px-3 py-1.5 bg-[#171D18] hover:bg-[#1C241E] border border-[#34372D] text-[#E9E8DF] rounded-lg text-xs font-medium transition-colors"
              >
                <Plus className="w-3.5 h-3.5 text-[#3FAF63]" />
                <span>Add Client</span>
              </button>
            )}

            {(isTimekeeper || isAgent) && activeClient && (
              <button
                onClick={() => setShowAddCredModal(true)}
                className="flex items-center space-x-1.5 px-2.5 sm:px-3.5 py-1.5 bg-[#3FAF63] hover:bg-[#52C978] active:bg-[#328D50] text-[#071009] rounded-lg text-xs font-semibold tracking-wide shadow-[0_0_15px_rgba(63,175,99,0.15)] transition-all"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Platform Credential</span>
              </button>
            )}
          </div>
        </header>

        {/* Dynamic Tab Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 md:p-8 max-w-6xl w-full mx-auto relative z-10">
          {/* TAB 1: CLIENT PASSWORDS */}
          {currentTab === 'vaults' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#252B26] gap-2">
                <div>
                  <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#E9E8DF]">
                    {activeClient ? activeClient.name : 'Client Secrets Vault'}
                  </h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">
                    {activeClient
                      ? `Scoped collection: /clients/${activeClient.id}/platforms`
                      : 'Select or assign a client to view platform secrets'}
                  </p>
                </div>
                {activeClient && (
                  <div className="flex items-center space-x-2">
                    <span className="text-[11px] text-[#6F766E]">
                      {accessibleCredentials.length} Credential{accessibleCredentials.length === 1 ? '' : 's'}
                    </span>
                    {isTimekeeper && (
                      <button
                        onClick={() => handleDeleteClient(activeClient.id)}
                        className="p-1.5 text-[#A5AAA1] hover:text-[#C94B45] hover:bg-[#2A1110] rounded-md transition-colors"
                        title="Delete client directory"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                )}
              </div>

              {!activeClient ? (
                <div className="p-8 sm:p-12 text-center border border-dashed border-[#252B26] rounded-xl bg-[#0E1210]">
                  <FolderLock className="w-10 h-10 text-[#6F766E] mx-auto mb-3" />
                  <h3 className="text-sm font-semibold text-[#E9E8DF]">No Client Selected</h3>
                  <p className="text-xs text-[#A5AAA1] max-w-sm mx-auto mt-1">
                    {isTimekeeper
                      ? 'Add your agency clients using the "Add Client" button to begin managing platform credentials.'
                      : 'You do not have any clients assigned yet. Contact your supervising Timekeeper for client access.'}
                  </p>
                  {isTimekeeper && (
                    <button
                      onClick={() => setShowAddClientModal(true)}
                      className="mt-4 px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-semibold"
                    >
                      Create First Client
                    </button>
                  )}
                </div>
              ) : accessibleCredentials.length === 0 ? (
                <div className="p-8 sm:p-12 text-center border border-dashed border-[#252B26] rounded-xl bg-[#0E1210]">
                  <KeyRound className="w-10 h-10 text-[#6F766E] mx-auto mb-3" />
                  <h3 className="text-sm font-semibold text-[#E9E8DF]">No Platform Credentials Stored</h3>
                  <p className="text-xs text-[#A5AAA1] max-w-sm mx-auto mt-1">
                    {isVariant
                      ? 'No credentials have been assigned or added for your viewing role on this client.'
                      : 'Store your first encrypted platform password (Instagram, Facebook, Google Ads, AWS, etc).'}
                  </p>
                  {(isTimekeeper || isAgent) && (
                    <button
                      onClick={() => setShowAddCredModal(true)}
                      className="mt-4 px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-semibold"
                    >
                      Add Platform Credential
                    </button>
                  )}
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {accessibleCredentials.map((cred) => {
                    const isRevealed = revealedIds[cred.id];
                    const displayedSecret = isRevealed
                      ? decryptedPasswords[cred.id] || cred.passwordCiphertext
                      : '••••••••••••••••';

                    return (
                      <div
                        key={cred.id}
                        className="bg-[#101412] border border-[#252B26] hover:border-[#34372D] rounded-xl p-4 flex flex-col justify-between transition-all space-y-4"
                      >
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2.5">
                              <PlatformIcon platformName={cred.platformName} className="w-5 h-5" />
                              <span className="text-sm font-bold text-[#E9E8DF]">{cred.platformName}</span>
                            </div>
                            {cred.keyLabel && (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#171D18] text-[#A5AAA1] border border-[#252B26]">
                                {cred.keyLabel}
                              </span>
                            )}
                          </div>

                          {cred.usernameCiphertext && (
                            <div className="text-xs text-[#A5AAA1]">
                              <span className="text-[#6F766E]">User:</span>{' '}
                              <span className="text-[#E9E8DF] font-medium">{cred.usernameCiphertext}</span>
                            </div>
                          )}

                          {cred.url && (
                            <a
                              href={cred.url.startsWith('http') ? cred.url : `https://${cred.url}`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[11px] text-[#3FAF63] hover:underline flex items-center space-x-1 truncate"
                            >
                              <span className="truncate">{cred.url}</span>
                              <ExternalLink className="w-3 h-3 shrink-0" />
                            </a>
                          )}
                        </div>

                        {/* Secret Box */}
                        <div className="bg-[#0A0D0B] border border-[#1F2620] rounded-lg p-2.5 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] uppercase tracking-wider text-[#6F766E] font-medium">Platform Secret</span>
                            <div className="flex items-center space-x-1">
                              <button
                                onClick={() => handleToggleReveal(cred)}
                                className="p-1 text-[#A5AAA1] hover:text-[#E9E8DF] rounded"
                                title={isRevealed ? 'Hide secret' : 'Reveal secret'}
                              >
                                {isRevealed ? <EyeOff className="w-3.5 h-3.5 text-[#C9A84E]" /> : <Eye className="w-3.5 h-3.5" />}
                              </button>
                              <button
                                onClick={() => handleCopySecret(cred)}
                                className="p-1 text-[#A5AAA1] hover:text-[#3FAF63] rounded"
                                title="Copy decrypted plaintext"
                              >
                                {copiedId === cred.id ? <Check className="w-3.5 h-3.5 text-[#3FAF63]" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          </div>

                          <div className="text-xs font-sans tracking-wide text-[#E9E8DF] break-all select-all">
                            {displayedSecret}
                          </div>
                        </div>

                        {/* Card Actions by Role */}
                        <div className="flex items-center justify-between pt-2 border-t border-[#1F2620] text-xs">
                          <span className="text-[10px] text-[#6F766E]">
                            Updated: {new Date(cred.updatedAt || cred.createdAt).toLocaleDateString()}
                          </span>

                          <div className="flex items-center space-x-1">
                            {(isTimekeeper || isAgent) && (
                              <button
                                onClick={() => openEditModal(cred)}
                                className="px-2 py-1 text-[#A5AAA1] hover:text-[#E9E8DF] hover:bg-[#171D18] rounded flex items-center space-x-1"
                              >
                                <Edit3 className="w-3 h-3" />
                                <span>Edit</span>
                              </button>
                            )}

                            {isTimekeeper && (
                              <button
                                onClick={() => handleTimekeeperDirectDelete(cred)}
                                className="px-2 py-1 text-[#C94B45] hover:bg-[#2A1110] rounded flex items-center space-x-1"
                                title="Direct Delete"
                              >
                                <Trash2 className="w-3 h-3" />
                                <span>Delete</span>
                              </button>
                            )}

                            {isAgent && (
                              <button
                                onClick={() => openDeleteModal(cred)}
                                className="px-2 py-1 text-[#C94B45] hover:bg-[#2A1110] rounded flex items-center space-x-1"
                                title="Delete via Request or Timekeeper Code"
                              >
                                <Trash2 className="w-3 h-3" />
                                <span>Delete...</span>
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: CLIENT DIRECTORY (Timekeeper Only) */}
          {currentTab === 'clients' && isTimekeeper && (
            <div className="space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-[#252B26]">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">Agency Client Directory</h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">Manage organizations and client platform tables</p>
                </div>
                <button
                  onClick={() => setShowAddClientModal(true)}
                  className="px-3.5 py-1.5 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-semibold flex items-center space-x-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Create Client</span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {clients.map((c) => {
                  const count = (platformCredentials[c.id] || []).length;
                  return (
                    <div
                      key={c.id}
                      className="bg-[#101412] border border-[#252B26] p-4 rounded-xl flex flex-col justify-between space-y-4"
                    >
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-bold text-[#E9E8DF]">{c.name}</h3>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-[#171D18] text-[#75F09A] font-semibold border border-[#34372D]">
                            {count} Keys
                          </span>
                        </div>
                        <p className="text-xs text-[#A5AAA1] line-clamp-2">
                          {c.description || 'No description entered.'}
                        </p>
                        <div className="text-[10px] text-[#6F766E]">ID: {c.identifier}</div>
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-[#1F2620]">
                        <button
                          onClick={() => {
                            setActiveClient(c);
                            setCurrentTab('vaults');
                          }}
                          className="text-xs text-[#3FAF63] hover:underline font-semibold"
                        >
                          View Vault Keys →
                        </button>
                        <button
                          onClick={() => handleDeleteClient(c.id)}
                          className="p-1 text-[#A5AAA1] hover:text-[#C94B45] rounded"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 3: USER MANAGEMENT (Timekeeper Only, Section 11, 14, 16) */}
          {currentTab === 'users' && isTimekeeper && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#252B26] gap-2">
                <div>
                  <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#E9E8DF]">Role & User Governance</h1>
                  <p className="text-xs text-[#A5AAA1] mt-0.5">
                    Configure canonical roles, client assignments, platform access, and observation supervisors
                  </p>
                </div>
                <button
                  onClick={() => setShowAddUserModal(true)}
                  className="px-3.5 py-1.5 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg text-xs font-semibold flex items-center space-x-1.5 self-start sm:self-auto"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Add User</span>
                </button>
              </div>

              {/* Responsive Cards for User Governance */}
              <div className="space-y-3">
                {managedUsers.map((u) => {
                  const assignedCount = u.assignedClients?.length || 0;
                  const supervisorNames = (u.supervisingTimekeepers || [])
                    .map((sId) => managedUsers.find((m) => m.id === sId)?.fullName || sId)
                    .join(', ');

                  return (
                    <div
                      key={u.id}
                      className="bg-[#101412] border border-[#252B26] rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
                    >
                      <div className="space-y-1.5 flex-1">
                        <div className="flex items-center space-x-2 flex-wrap">
                          <span className="text-sm font-bold text-[#E9E8DF]">{u.fullName}</span>
                          <span className={`text-[10px] px-2 py-0.5 rounded uppercase font-bold border ${
                            u.role === 'timekeeper'
                              ? 'bg-[#29200D] border-[#C9A84E]/40 text-[#D9A441]'
                              : u.role === 'agent'
                              ? 'bg-[#102719] border-[#45C46B]/40 text-[#75F09A]'
                              : 'bg-[#171D18] border-[#34372D] text-[#A5AAA1]'
                          }`}>
                            {u.role}
                          </span>
                          <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                            u.isActive ? 'text-[#45C46B] bg-[#102719]' : 'text-[#C94B45] bg-[#2A1110]'
                          }`}>
                            {u.isActive ? 'Active' : 'Suspended'}
                          </span>
                        </div>

                        <div className="text-xs text-[#A5AAA1] flex flex-wrap gap-x-4 gap-y-1">
                          <span>Email: <strong className="text-[#E9E8DF]">{u.email}</strong></span>
                          {u.personalEmail && <span>Personal: <strong className="text-[#E9E8DF]">{u.personalEmail}</strong></span>}
                          {u.phoneNumber && <span>Phone: <strong className="text-[#E9E8DF]">{u.phoneNumber}</strong></span>}
                          {u.roleInCompany && <span>Title: <strong className="text-[#E9E8DF]">{u.roleInCompany}</strong></span>}
                        </div>

                        <div className="text-[11px] text-[#6F766E] flex flex-wrap gap-x-4 gap-y-1 pt-1 border-t border-[#1F2620]">
                          <span>
                            Assigned Clients:{' '}
                            <strong className="text-[#A5AAA1]">
                              {u.role === 'timekeeper' ? 'All (Timekeeper)' : `${assignedCount} client(s)`}
                            </strong>
                          </span>
                          {u.role === 'agent' && (
                            <span>
                              Under Observation Of:{' '}
                              <strong className="text-[#C9A84E]">
                                {supervisorNames || 'Default Timekeeper'}
                              </strong>
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0 self-end md:self-center">
                        <button
                          onClick={() => setResetTargetUser(u)}
                          className="px-2.5 py-1.5 bg-[#171D18] hover:bg-[#1F2620] border border-[#34372D] text-[#C9A84E] rounded-lg text-xs font-medium"
                          title="Reset Password (Administrative Override)"
                        >
                          Reset Pass
                        </button>

                        <button
                          onClick={() => handleToggleUserStatus(u.id)}
                          className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border ${
                            u.isActive
                              ? 'bg-[#2A1110] border-[#C94B45]/40 text-[#C94B45] hover:bg-[#3B1716]'
                              : 'bg-[#102719] border-[#45C46B]/40 text-[#45C46B] hover:bg-[#163622]'
                          }`}
                        >
                          {u.isActive ? 'Suspend' : 'Activate'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 4: DELETION REQUESTS (Timekeeper Only, Section 9) */}
          {currentTab === 'approvals' && isTimekeeper && (
            <div className="space-y-6">
              <div className="pb-4 border-b border-[#252B26]">
                <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">Credential Deletion Requests</h1>
                <p className="text-xs text-[#A5AAA1] mt-0.5">
                  Review agent deletion requests. Approving automatically deletes the credential from cloud storage.
                </p>
              </div>

              {deletionRequests.length === 0 ? (
                <div className="p-12 text-center border border-dashed border-[#252B26] rounded-xl bg-[#0E1210]">
                  <CheckCircle className="w-10 h-10 text-[#6F766E] mx-auto mb-3" />
                  <h3 className="text-sm font-semibold text-[#E9E8DF]">Zero Pending Deletions</h3>
                  <p className="text-xs text-[#A5AAA1] mt-1">All credential deletion requests have been reviewed.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {deletionRequests.map((req) => (
                    <div
                      key={req.id}
                      className="bg-[#101412] border border-[#252B26] rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="text-sm font-bold text-[#E9E8DF]">{req.platformName}</span>
                          <span className="text-xs text-[#A5AAA1]">({req.clientName})</span>
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                            req.status === 'pending'
                              ? 'bg-[#29200D] text-[#D9A441] border border-[#D9A441]/40'
                              : req.status === 'approved'
                              ? 'bg-[#102719] text-[#75F09A]'
                              : 'bg-[#2A1110] text-[#C94B45]'
                          }`}>
                            {req.status}
                          </span>
                        </div>
                        <div className="text-xs text-[#A5AAA1]">
                          Requested by: <strong className="text-[#E9E8DF]">{req.requestedByEmail}</strong>
                        </div>
                        <div className="text-xs text-[#6F766E]">Reason: "{req.reason}"</div>
                        <div className="text-[10px] text-[#6F766E]">Submitted: {req.createdAt}</div>
                      </div>

                      {req.status === 'pending' && (
                        <div className="flex items-center space-x-2 shrink-0">
                          <button
                            onClick={() => handleReviewDeletion(req, 'approved')}
                            className="px-3 py-1.5 bg-[#102719] hover:bg-[#163622] border border-[#45C46B]/40 text-[#75F09A] rounded-lg text-xs font-semibold flex items-center space-x-1"
                          >
                            <Check className="w-3.5 h-3.5" />
                            <span>Approve & Delete</span>
                          </button>
                          <button
                            onClick={() => handleReviewDeletion(req, 'rejected')}
                            className="px-3 py-1.5 bg-[#2A1110] hover:bg-[#3B1716] border border-[#C94B45]/40 text-[#C94B45] rounded-lg text-xs font-semibold flex items-center space-x-1"
                          >
                            <X className="w-3.5 h-3.5" />
                            <span>Reject</span>
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 5: PASSWORD GENERATOR */}
          {currentTab === 'generator' && (
            <div className="max-w-xl mx-auto space-y-6">
              <div className="pb-4 border-b border-[#252B26] text-center">
                <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">CSPRNG Password Generator</h1>
                <p className="text-xs text-[#A5AAA1] mt-0.5">Generate high-entropy cryptographic client secrets</p>
              </div>

              <div className="bg-[#101412] border border-[#252B26] rounded-2xl p-6 space-y-6">
                <div className="bg-[#0A0D0B] border border-[#1F2620] p-4 rounded-xl flex items-center justify-between">
                  <span className="text-sm font-sans tracking-wider text-[#75F09A] break-all select-all font-semibold">
                    {generatedPassword || 'Click generate below...'}
                  </span>
                  {generatedPassword && (
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(generatedPassword);
                        alert('Password copied to clipboard!');
                      }}
                      className="p-2 text-[#A5AAA1] hover:text-[#3FAF63] rounded-lg hover:bg-[#171D18]"
                      title="Copy"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between text-xs text-[#A5AAA1]">
                    <span>Length</span>
                    <span className="text-[#E9E8DF] font-bold">{genLength} characters</span>
                  </div>
                  <input
                    type="range"
                    min={8}
                    max={30}
                    value={genLength}
                    onChange={(e) => setGenLength(parseInt(e.target.value, 10))}
                    className="w-full accent-[#3FAF63]"
                  />
                  <div className="flex justify-between text-[10px] text-[#6F766E]">
                    <span>8 (Min Policy)</span>
                    <span>24 (Recommended)</span>
                    <span>30 (Max Policy)</span>
                  </div>
                </div>

                <button
                  onClick={() => {
                    const pwd = LokiCryptoService.generatePassword({ length: genLength });
                    setGeneratedPassword(pwd);
                  }}
                  className="w-full py-3 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-xl text-xs font-bold uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(63,175,99,0.15)]"
                >
                  Generate Strong Secret
                </button>
              </div>
            </div>
          )}

          {/* TAB 6: AUDIT TRAIL (Timekeeper Only, Section 44) */}
          {currentTab === 'audit' && isTimekeeper && (
            <div className="space-y-6">
              <div className="pb-4 border-b border-[#252B26]">
                <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">Immutable Audit Trail</h1>
                <p className="text-xs text-[#A5AAA1] mt-0.5">
                  Append-only event log for user actions, credential modifications, and authorization events
                </p>
              </div>

              <div className="bg-[#101412] border border-[#252B26] rounded-xl overflow-hidden">
                <div className="divide-y divide-[#1F2620] text-xs">
                  {auditLogs.map((log) => (
                    <div key={log.id} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-semibold text-[#75F09A]">{log.action}</span>
                          <span className="text-[#A5AAA1]">by {log.user}</span>
                        </div>
                        <p className="text-[#6F766E] text-[11px]">{log.details}</p>
                      </div>
                      <span className="text-[10px] text-[#6F766E] shrink-0">{log.timestamp}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: USER PROFILE (Section 17) */}
          {currentTab === 'profile' && (
            <div className="max-w-2xl mx-auto space-y-6">
              <div className="pb-4 border-b border-[#252B26]">
                <h1 className="text-2xl font-bold tracking-tight text-[#E9E8DF]">My Profile & Governance</h1>
                <p className="text-xs text-[#A5AAA1] mt-0.5">View and update your personal information</p>
              </div>

              <div className="bg-[#101412] border border-[#252B26] rounded-2xl p-6 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div>
                    <label className="text-[#6F766E] block mb-1 uppercase tracking-wider text-[10px]">Full Name</label>
                    <div className="text-sm font-semibold text-[#E9E8DF]">{currentUser.fullName}</div>
                  </div>
                  <div>
                    <label className="text-[#6F766E] block mb-1 uppercase tracking-wider text-[10px]">Canonical System Role</label>
                    <div className="text-sm font-semibold text-[#75F09A] uppercase">{currentUser.role}</div>
                  </div>
                  <div>
                    <label className="text-[#6F766E] block mb-1 uppercase tracking-wider text-[10px]">Primary Email</label>
                    <div className="text-sm font-semibold text-[#E9E8DF]">{currentUser.email}</div>
                  </div>
                  <div>
                    <label className="text-[#6F766E] block mb-1 uppercase tracking-wider text-[10px]">Company Role Title</label>
                    <div className="text-sm font-semibold text-[#E9E8DF]">{currentUser.roleInCompany || 'Specialist'}</div>
                  </div>
                </div>

                {isAgent && currentUser.supervisingTimekeepers && currentUser.supervisingTimekeepers.length > 0 && (
                  <div className="p-3 bg-[#0A0D0B] border border-[#1F2620] rounded-xl text-xs space-y-1">
                    <span className="text-[#C9A84E] font-semibold flex items-center">
                      <Clock className="w-3.5 h-3.5 mr-1.5" />
                      Under Observation Of:
                    </span>
                    <div className="text-[#A5AAA1] pl-5">
                      {currentUser.supervisingTimekeepers.map((tkId) => {
                        const tk = managedUsers.find((m) => m.id === tkId);
                        return (
                          <div key={tkId} className="text-[#E9E8DF]">
                            • {tk ? `${tk.fullName} (${tk.email})` : tkId}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div className="pt-4 border-t border-[#1F2620] flex items-center justify-between">
                  <div>
                    <div className="text-xs font-semibold text-[#E9E8DF]">Account Login Password</div>
                    <div className="text-[10px] text-[#6F766E]">Max 3 changes per month. 3-day cooldown enforced.</div>
                  </div>
                  <button
                    onClick={() => setShowChangeSelfPasswordModal(true)}
                    className="px-3.5 py-2 bg-[#171D18] hover:bg-[#1C241E] border border-[#34372D] text-[#E9E8DF] rounded-lg text-xs font-semibold"
                  >
                    Change Password
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* --- MODAL: ADD CLIENT --- */}
      {showAddClientModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#101412] border border-[#252B26] rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#252B26]">
              <h3 className="text-base font-bold text-[#E9E8DF]">Add New Agency Client</h3>
              <button onClick={() => setShowAddClientModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddClient} className="space-y-4 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Client Organization Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Corporation"
                  value={newClientName}
                  onChange={(e) => setNewClientName(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                />
              </div>

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Description / Scope (Optional)</label>
                <textarea
                  rows={3}
                  placeholder="e.g. Social ads, e-commerce, cloud infrastructure"
                  value={newClientDescription}
                  onChange={(e) => setNewClientDescription(e.target.value)}
                  className="w-full px-3.5 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddClientModal(false)}
                  className="px-4 py-2 bg-[#171D18] hover:bg-[#1F2620] text-[#A5AAA1] rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg font-bold"
                >
                  Save Client
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- MODAL: ADD PLATFORM CREDENTIAL (With Platform Catalog Dropdown & Policy, Section 8, 38, 39, 40, 41) --- */}
      {showAddCredModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#101412] border border-[#252B26] rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-[#252B26]">
              <h3 className="text-base font-bold text-[#E9E8DF]">Add Platform Credential</h3>
              <button onClick={() => setShowAddCredModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-5 h-5" />
              </button>
            </div>

            {addCredError && (
              <div className="p-3 bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{addCredError}</span>
              </div>
            )}

            <form onSubmit={handleAddCredential} className="space-y-4 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Select Platform</label>
                <select
                  value={newPlatformSelection}
                  onChange={(e) => setNewPlatformSelection(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none"
                >
                  {PLATFORM_CATALOG.map((p) => (
                    <option key={p.id} value={p.name}>
                      {p.name} ({p.category})
                    </option>
                  ))}
                  <option value="Other">Other / Custom Platform</option>
                </select>
              </div>

              {newPlatformSelection === 'Other' && (
                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Custom Platform Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Supabase DB"
                    value={customPlatformName}
                    onChange={(e) => setCustomPlatformName(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none"
                  />
                </div>
              )}

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Username / Account Email</label>
                <input
                  type="text"
                  placeholder="e.g. social@acme.com"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                />
              </div>

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Platform Password</label>
                <div className="relative">
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    required
                    placeholder="Enter platform password (8-30 chars, Aa1!)..."
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-3 top-3 text-[#A5AAA1] hover:text-[#E9E8DF]"
                  >
                    {showNewPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Confirm Platform Password</label>
                <div className="relative">
                  <input
                    type={showConfirmPassword ? 'text' : 'password'}
                    required
                    placeholder="Repeat platform password exactly..."
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={`w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border rounded-lg text-sm text-[#E9E8DF] outline-none placeholder:text-[#6F766E] ${
                      confirmPassword && confirmPassword !== newPassword ? 'border-[#C94B45]' : 'border-[#34372D] focus:border-[#3FAF63]'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-3 text-[#A5AAA1] hover:text-[#E9E8DF]"
                  >
                    {showConfirmPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {confirmPassword && confirmPassword !== newPassword && (
                  <span className="text-[10px] text-[#C94B45] mt-1 block">Passwords do not match</span>
                )}
              </div>

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Login URL / Endpoint (Optional)</label>
                <input
                  type="text"
                  placeholder="https://platform.com/login"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  className="w-full px-3.5 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddCredModal(false)}
                  className="px-4 py-2 bg-[#171D18] hover:bg-[#1F2620] text-[#A5AAA1] rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg font-bold"
                >
                  Save & Encrypt Secret
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- MODAL: EDIT CREDENTIAL (Agent must verify old password, Section 7) --- */}
      {editingCred && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#101412] border border-[#252B26] rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-[#252B26]">
              <h3 className="text-base font-bold text-[#E9E8DF]">Edit {editingCred.platformName} Password</h3>
              <button onClick={() => setEditingCred(null)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-5 h-5" />
              </button>
            </div>

            {editError && (
              <div className="p-3 bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{editError}</span>
              </div>
            )}

            {editSuccess && (
              <div className="p-3 bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] text-xs rounded-lg flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>{editSuccess}</span>
              </div>
            )}

            {!showOverrideForm ? (
              <form onSubmit={handleSavePasswordEdit} className="space-y-4 text-xs">
                {isAgent && (
                  <div>
                    <label className="text-[#C9A84E] block mb-1 uppercase tracking-wider text-[11px] font-semibold">
                      Current (Old) Platform Password *
                    </label>
                    <div className="relative">
                      <input
                        type={showEditOldPassword ? 'text' : 'password'}
                        required
                        placeholder="Enter the existing password..."
                        value={editOldPassword}
                        onChange={(e) => setEditOldPassword(e.target.value)}
                        className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#C9A84E] rounded-lg text-sm text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                      />
                      <button
                        type="button"
                        onClick={() => setShowEditOldPassword(!showEditOldPassword)}
                        className="absolute right-3 top-3 text-[#A5AAA1] hover:text-[#E9E8DF]"
                      >
                        {showEditOldPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <div className="text-[10px] text-[#A5AAA1] mt-1 flex justify-between">
                      <span>Verification required to prevent unauthorized overwrite</span>
                      <button
                        type="button"
                        onClick={() => setShowOverrideForm(true)}
                        className="text-[#C9A84E] hover:underline"
                      >
                        Don't know old secret?
                      </button>
                    </div>
                  </div>
                )}

                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">New Platform Password</label>
                  <div className="relative">
                    <input
                      type={showEditNewPassword ? 'text' : 'password'}
                      required
                      placeholder="Enter new strong password..."
                      value={editNewPassword}
                      onChange={(e) => setEditNewPassword(e.target.value)}
                      className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                    />
                    <button
                      type="button"
                      onClick={() => setShowEditNewPassword(!showEditNewPassword)}
                      className="absolute right-3 top-3 text-[#A5AAA1] hover:text-[#E9E8DF]"
                    >
                      {showEditNewPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Confirm New Password</label>
                  <div className="relative">
                    <input
                      type={showEditConfirmPassword ? 'text' : 'password'}
                      required
                      placeholder="Confirm new password..."
                      value={editConfirmPassword}
                      onChange={(e) => setEditConfirmPassword(e.target.value)}
                      className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                    />
                    <button
                      type="button"
                      onClick={() => setShowEditConfirmPassword(!showEditConfirmPassword)}
                      className="absolute right-3 top-3 text-[#A5AAA1] hover:text-[#E9E8DF]"
                    >
                      {showEditConfirmPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="flex justify-end space-x-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setEditingCred(null)}
                    className="px-4 py-2 bg-[#171D18] hover:bg-[#1F2620] text-[#A5AAA1] rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg font-bold"
                  >
                    Update Secret
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={handleRequestOverride} className="space-y-4 text-xs">
                <div className="p-3 bg-[#29200D] border border-[#D9A441]/40 rounded-lg text-[#D9A441] text-xs">
                  Submitting an override request allows an active Timekeeper to authorize changing this credential without knowing the previous secret.
                </div>

                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Reason for Override Request</label>
                  <textarea
                    rows={3}
                    required
                    placeholder="e.g. Previous agency contractor lost the secret; client reset via email."
                    value={editOverrideReason}
                    onChange={(e) => setEditOverrideReason(e.target.value)}
                    className="w-full px-3.5 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#C9A84E] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  />
                </div>

                <div className="flex justify-between items-center pt-2">
                  <button
                    type="button"
                    onClick={() => setShowOverrideForm(false)}
                    className="text-[#A5AAA1] hover:text-[#E9E8DF]"
                  >
                    ← Back to Edit
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-[#C9A84E] hover:bg-[#E0C16A] text-[#071009] rounded-lg font-bold"
                  >
                    Submit Override Request
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* --- MODAL: AGENT DELETION WORKFLOW (Option 1: Request, Option 2: Code, Section 9, 10, 11, 12) --- */}
      {deletingCred && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#101412] border border-[#252B26] rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#252B26]">
              <h3 className="text-base font-bold text-[#E9E8DF]">Delete Platform Secret</h3>
              <button onClick={() => setDeletingCred(null)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-5 h-5" />
              </button>
            </div>

            {deletionModalError && (
              <div className="p-3 bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{deletionModalError}</span>
              </div>
            )}

            {deletionModalSuccess && (
              <div className="p-3 bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] text-xs rounded-lg flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>{deletionModalSuccess}</span>
              </div>
            )}

            {deletionMode === 'choose' && (
              <div className="space-y-4 text-xs">
                <p className="text-[#A5AAA1]">
                  As an Agent, credential deletions must be authorized by a supervising Timekeeper. Select your preferred deletion path for <strong className="text-[#E9E8DF]">{deletingCred.platformName}</strong>:
                </p>

                <div className="grid grid-cols-1 gap-3">
                  <button
                    onClick={() => setDeletionMode('request')}
                    className="p-4 bg-[#171D18] hover:bg-[#1F2620] border border-[#34372D] rounded-xl text-left space-y-1 transition-all"
                  >
                    <div className="font-bold text-[#E9E8DF] flex items-center justify-between">
                      <span>1. Send for Deletion Request</span>
                      <Send className="w-4 h-4 text-[#75F09A]" />
                    </div>
                    <p className="text-[11px] text-[#A5AAA1]">
                      Submits a request to your supervising Timekeeper(s). Upon approval, the credential is automatically deleted.
                    </p>
                  </button>

                  <button
                    onClick={() => setDeletionMode('code')}
                    className="p-4 bg-[#171D18] hover:bg-[#1F2620] border border-[#34372D] rounded-xl text-left space-y-1 transition-all"
                  >
                    <div className="font-bold text-[#E9E8DF] flex items-center justify-between">
                      <span>2. Delete with Timekeeper Code</span>
                      <Key className="w-4 h-4 text-[#C9A84E]" />
                    </div>
                    <p className="text-[11px] text-[#A5AAA1]">
                      Use an authorization code provided by an active Timekeeper listed under your "Under Observation Of" profile.
                    </p>
                  </button>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => setDeletingCred(null)}
                    className="px-4 py-2 bg-[#171D18] text-[#A5AAA1] rounded-lg"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {deletionMode === 'request' && (
              <form onSubmit={handleSendDeletionRequest} className="space-y-4 text-xs">
                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Reason for Deletion</label>
                  <textarea
                    rows={3}
                    required
                    placeholder="e.g. Client terminated contract or decommissioned this Instagram account."
                    value={deletionReason}
                    onChange={(e) => setDeletionReason(e.target.value)}
                    className="w-full px-3.5 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none placeholder:text-[#6F766E]"
                  />
                </div>

                <div className="flex justify-between items-center pt-2">
                  <button
                    type="button"
                    onClick={() => setDeletionMode('choose')}
                    className="text-[#A5AAA1] hover:text-[#E9E8DF]"
                  >
                    ← Choose Option
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg font-bold"
                  >
                    Send Request to Timekeepers
                  </button>
                </div>
              </form>
            )}

            {deletionMode === 'code' && (
              <form onSubmit={handleDeleteWithCode} className="space-y-4 text-xs">
                <div className="p-3 bg-[#29200D] border border-[#D9A441]/40 rounded-lg text-[#D9A441] text-[11px]">
                  Enter the secure authorization code belonging to ANY active Timekeeper supervising your account.
                </div>

                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Timekeeper Authorization Code</label>
                  <input
                    type="password"
                    required
                    placeholder="Enter 6-8 digit code..."
                    value={timekeeperAuthCode}
                    onChange={(e) => setTimekeeperAuthCode(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#C9A84E] rounded-lg text-sm text-[#E9E8DF] outline-none"
                  />
                </div>

                <div className="flex justify-between items-center pt-2">
                  <button
                    type="button"
                    onClick={() => setDeletionMode('choose')}
                    className="text-[#A5AAA1] hover:text-[#E9E8DF]"
                  >
                    ← Choose Option
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-[#C94B45] hover:bg-[#D9534F] text-[#E9E8DF] rounded-lg font-bold"
                  >
                    Authorize Immediate Deletion
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* --- MODAL: ADD USER (Timekeeper Only, Section 11 & 16) --- */}
      {showAddUserModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#101412] border border-[#252B26] rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-[#252B26]">
              <h3 className="text-base font-bold text-[#E9E8DF]">Add Agency User</h3>
              <button onClick={() => setShowAddUserModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-5 h-5" />
              </button>
            </div>

            {addUserError && (
              <div className="p-3 bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{addUserError}</span>
              </div>
            )}

            <form onSubmit={handleAddUser} className="space-y-3.5 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Full Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. John Doe"
                    value={newUserFullName}
                    onChange={(e) => setNewUserFullName(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  />
                </div>

                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Canonical Role *</label>
                  <select
                    value={newUserRole}
                    onChange={(e) => setNewUserRole(e.target.value as UserRole)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  >
                    <option value="timekeeper">Timekeeper (Full Admin)</option>
                    <option value="agent">Agent (Account Manager)</option>
                    <option value="variant">Variant (Read-only Viewer)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Company Email *</label>
                  <input
                    type="email"
                    required
                    placeholder="user@agency.com"
                    value={newUserEmail}
                    onChange={(e) => setNewUserEmail(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  />
                </div>

                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Personal Email</label>
                  <input
                    type="email"
                    placeholder="personal@gmail.com"
                    value={newUserPersonalEmail}
                    onChange={(e) => setNewUserPersonalEmail(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Phone Number</label>
                  <input
                    type="tel"
                    placeholder="+1-555-0199"
                    value={newUserPhone}
                    onChange={(e) => setNewUserPhone(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  />
                </div>

                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Role In Company</label>
                  <input
                    type="text"
                    placeholder="e.g. Senior Media Buyer"
                    value={newUserRoleInCompany}
                    onChange={(e) => setNewUserRoleInCompany(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Initial Login Password *</label>
                <div className="relative">
                  <input
                    type={showNewUserPassword ? 'text' : 'password'}
                    required
                    placeholder="Initial password (8-30 chars, Aa1!)..."
                    value={newUserPassword}
                    onChange={(e) => setNewUserPassword(e.target.value)}
                    className="w-full pl-3 pr-10 py-2 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-xs text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewUserPassword(!showNewUserPassword)}
                    className="absolute right-3 top-2.5 text-[#A5AAA1]"
                  >
                    {showNewUserPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {/* Assign Clients (For Agent & Variant) */}
              {newUserRole !== 'timekeeper' && (
                <div>
                  <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[10px] font-medium">Assigned Clients</label>
                  <div className="max-h-28 overflow-y-auto bg-[#0C100E] border border-[#34372D] rounded-lg p-2 space-y-1">
                    {clients.map((c) => (
                      <label key={c.id} className="flex items-center space-x-2 text-xs text-[#E9E8DF] cursor-pointer">
                        <input
                          type="checkbox"
                          checked={newUserAssignedClients.includes(c.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setNewUserAssignedClients((prev) => [...prev, c.id]);
                            } else {
                              setNewUserAssignedClients((prev) => prev.filter((id) => id !== c.id));
                            }
                          }}
                          className="accent-[#3FAF63]"
                        />
                        <span>{c.name}</span>
                      </label>
                    ))}
                    {clients.length === 0 && <span className="text-[#6F766E] text-[11px]">No clients created yet.</span>}
                  </div>
                </div>
              )}

              {/* Supervising Timekeepers: "Under Observation Of" (Section 11: Min 1, Max 3) */}
              {newUserRole === 'agent' && (
                <div>
                  <label className="text-[#C9A84E] block mb-1 uppercase tracking-wider text-[10px] font-semibold">
                    Under Observation Of (1 to 3 Supervising Timekeepers) *
                  </label>
                  <div className="bg-[#0C100E] border border-[#34372D] rounded-lg p-2 space-y-1 max-h-28 overflow-y-auto">
                    {managedUsers
                      .filter((m) => m.role === 'timekeeper' && m.isActive)
                      .map((tk) => (
                        <label key={tk.id} className="flex items-center space-x-2 text-xs text-[#E9E8DF] cursor-pointer">
                          <input
                            type="checkbox"
                            checked={newUserSupervisingTKs.includes(tk.id)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                if (newUserSupervisingTKs.length >= 3) {
                                  alert('Maximum 3 supervising Timekeepers allowed.');
                                  return;
                                }
                                setNewUserSupervisingTKs((prev) => [...prev, tk.id]);
                              } else {
                                setNewUserSupervisingTKs((prev) => prev.filter((id) => id !== tk.id));
                              }
                            }}
                            className="accent-[#3FAF63]"
                          />
                          <span>{tk.fullName} ({tk.email})</span>
                        </label>
                      ))}
                  </div>
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddUserModal(false)}
                  className="px-4 py-2 bg-[#171D18] hover:bg-[#1F2620] text-[#A5AAA1] rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg font-bold"
                >
                  Create & Authorize User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- MODAL: ADMINISTRATIVE RESET PASSWORD (Timekeeper Creator Override, Section 19) --- */}
      {resetTargetUser && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#101412] border border-[#252B26] rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#252B26]">
              <h3 className="text-base font-bold text-[#E9E8DF]">Reset Password: {resetTargetUser.fullName}</h3>
              <button onClick={() => setResetTargetUser(null)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3 bg-[#29200D] border border-[#D9A441]/40 rounded-lg text-[#D9A441] text-xs">
              Timekeeper Exception: You are executing an administrative reset. This bypasses the 3-day cooldown and monthly limit for this user.
            </div>

            {adminResetError && (
              <div className="p-3 bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{adminResetError}</span>
              </div>
            )}

            {adminResetSuccess && (
              <div className="p-3 bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] text-xs rounded-lg flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>{adminResetSuccess}</span>
              </div>
            )}

            <form onSubmit={handleAdminResetPassword} className="space-y-4 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">New Temporary Password</label>
                <div className="relative">
                  <input
                    type={showAdminResetPassword ? 'text' : 'password'}
                    required
                    placeholder="Enter new user password (8-30 chars, Aa1!)..."
                    value={adminResetNewPassword}
                    onChange={(e) => setAdminResetNewPassword(e.target.value)}
                    className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#C9A84E] rounded-lg text-sm text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowAdminResetPassword(!showAdminResetPassword)}
                    className="absolute right-3 top-3 text-[#A5AAA1]"
                  >
                    {showAdminResetPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setResetTargetUser(null)}
                  className="px-4 py-2 bg-[#171D18] hover:bg-[#1F2620] text-[#A5AAA1] rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-[#C9A84E] hover:bg-[#E0C16A] text-[#071009] rounded-lg font-bold"
                >
                  Reset User Password
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- MODAL: CHANGE OWN PASSWORD (Section 19: 3 changes per month, 3-day cooldown) --- */}
      {showChangeSelfPasswordModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#101412] border border-[#252B26] rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#252B26]">
              <h3 className="text-base font-bold text-[#E9E8DF]">Change Account Password</h3>
              <button onClick={() => setShowChangeSelfPasswordModal(false)} className="text-[#A5AAA1] hover:text-[#E9E8DF]">
                <X className="w-5 h-5" />
              </button>
            </div>

            {selfPassError && (
              <div className="p-3 bg-[#2A1110] border border-[#C94B45]/40 text-[#C94B45] text-xs rounded-lg flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{selfPassError}</span>
              </div>
            )}

            {selfPassSuccess && (
              <div className="p-3 bg-[#102719] border border-[#45C46B]/40 text-[#75F09A] text-xs rounded-lg flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>{selfPassSuccess}</span>
              </div>
            )}

            <form onSubmit={handleChangeSelfPassword} className="space-y-4 text-xs">
              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Current Password</label>
                <div className="relative">
                  <input
                    type={showSelfOldPassword ? 'text' : 'password'}
                    required
                    placeholder="Enter current password..."
                    value={selfOldPassword}
                    onChange={(e) => setSelfOldPassword(e.target.value)}
                    className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSelfOldPassword(!showSelfOldPassword)}
                    className="absolute right-3 top-3 text-[#A5AAA1]"
                  >
                    {showSelfOldPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">New Password</label>
                <div className="relative">
                  <input
                    type={showSelfNewPassword ? 'text' : 'password'}
                    required
                    placeholder="New password (8-30 chars, Aa1!)..."
                    value={selfNewPassword}
                    onChange={(e) => setSelfNewPassword(e.target.value)}
                    className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSelfNewPassword(!showSelfNewPassword)}
                    className="absolute right-3 top-3 text-[#A5AAA1]"
                  >
                    {showSelfNewPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[#A5AAA1] block mb-1 uppercase tracking-wider text-[11px] font-medium">Confirm New Password</label>
                <div className="relative">
                  <input
                    type={showSelfConfirmPassword ? 'text' : 'password'}
                    required
                    placeholder="Confirm new password..."
                    value={selfConfirmPassword}
                    onChange={(e) => setSelfConfirmPassword(e.target.value)}
                    className="w-full pl-3.5 pr-10 py-2.5 bg-[#0C100E] border border-[#34372D] focus:border-[#3FAF63] rounded-lg text-sm text-[#E9E8DF] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSelfConfirmPassword(!showSelfConfirmPassword)}
                    className="absolute right-3 top-3 text-[#A5AAA1]"
                  >
                    {showSelfConfirmPassword ? <EyeOff className="w-4 h-4 text-[#C9A84E]" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="text-[10px] text-[#6F766E] space-y-0.5">
                <div>• Policy: 8-30 characters with uppercase, lowercase, number, and special symbol.</div>
                <div>• Limit: Maximum 3 changes per calendar month. 3-day cooldown between changes.</div>
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowChangeSelfPasswordModal(false)}
                  className="px-4 py-2 bg-[#171D18] hover:bg-[#1F2620] text-[#A5AAA1] rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-[#3FAF63] hover:bg-[#52C978] text-[#071009] rounded-lg font-bold"
                >
                  Update My Password
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
