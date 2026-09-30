import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  collection,
  getDocs,
  deleteDoc,
  updateDoc,
  Firestore,
} from 'firebase/firestore';
import { firebaseConfig } from './firebaseConfig.js';
import { OrgRole, DeletionRequest, PasswordOverrideRequest } from '../types/models.js';

export interface ClientPlatformCredential {
  id: string;
  clientId: string;
  platformName: string;
  keyLabel?: string;
  passwordCiphertext: string;
  passwordNonce: string;
  usernameCiphertext?: string;
  url?: string;
  createdAt: string;
  updatedAt?: string;
  createdBy: string;
}

export interface ClientProfile {
  id: string;
  name: string;
  identifier: string;
  description?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface LokiFirestoreUser {
  id: string;
  email: string;
  fullName: string;
  role: OrgRole;
  isActive: boolean;
  kdfSalt?: string;
  publicKey?: string;
  companyEmail?: string;
  personalEmail?: string;
  phoneNumber?: string;
  roleInCompany?: string;
  assignedClients?: string[];
  assignedPlatforms?: Record<string, string[]>;
  supervisingTimekeepers?: string[];
  createdByTimekeeperId?: string;
  passwordHistory?: string[];
  lastPasswordChangedAt?: string;
  authCodeHash?: string;
  authCodeSalt?: string;
  createdAt: string;
  updatedAt?: string;
}

/**
 * Loki Firebase NoSQL Storage Service
 * Strictly operates on the isolated project `loki-agency-vault`
 * Implements client separation where each client has its own dedicated collection/sub-tables
 * containing platform name & encrypted password records.
 */
export class LokiFirebaseService {
  private static dbInstance: Firestore | null = null;

  public static getDb(): Firestore {
    if (!this.dbInstance) {
      const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();
      this.dbInstance = getFirestore(app);
    }
    return this.dbInstance;
  }

  /**
   * Register or update client's metadata document
   */
  public static async saveClient(client: ClientProfile): Promise<void> {
    const firestore = this.getDb();
    const clientRef = doc(firestore, 'clients', client.id);
    await setDoc(clientRef, {
      ...client,
      updatedAt: new Date().toISOString(),
    }, { merge: true });
  }

  /**
   * List all registered agency clients
   */
  public static async listClients(): Promise<ClientProfile[]> {
    const firestore = this.getDb();
    const clientsRef = collection(firestore, 'clients');
    const snapshot = await getDocs(clientsRef);
    return snapshot.docs.map((docSnap) => docSnap.data() as ClientProfile);
  }

  /**
   * Save credential to client's separate platform table
   * Path: /clients/{clientId}/platforms/{platformId}
   */
  public static async savePlatformCredential(
    clientId: string,
    cred: ClientPlatformCredential
  ): Promise<void> {
    const firestore = this.getDb();
    const credRef = doc(firestore, 'clients', clientId, 'platforms', cred.id);
    await setDoc(credRef, {
      ...cred,
      clientId,
      updatedAt: new Date().toISOString(),
    }, { merge: true });
  }

  /**
   * List all platform credentials for a specific client
   */
  public static async listPlatformCredentials(
    clientId: string
  ): Promise<ClientPlatformCredential[]> {
    const firestore = this.getDb();
    const platformsRef = collection(firestore, 'clients', clientId, 'platforms');
    const snapshot = await getDocs(platformsRef);
    return snapshot.docs.map((docSnap) => docSnap.data() as ClientPlatformCredential);
  }

  /**
   * Delete a platform credential from a client's table
   */
  public static async deletePlatformCredential(
    clientId: string,
    platformId: string
  ): Promise<void> {
    const firestore = this.getDb();
    const credRef = doc(firestore, 'clients', clientId, 'platforms', platformId);
    await deleteDoc(credRef);
  }

  /**
   * Store and manage RBAC User Profiles in Firestore
   */
  public static async saveUserProfile(user: LokiFirestoreUser & { passwordHash?: string }): Promise<void> {
    const firestore = this.getDb();
    const userRef = doc(firestore, 'users', user.id);
    await setDoc(userRef, {
      ...user,
      updatedAt: new Date().toISOString(),
    }, { merge: true });
  }

  /**
   * Get user profile by userId for RBAC authorization check
   */
  public static async getUserProfile(userId: string): Promise<any | null> {
    const firestore = this.getDb();
    const userRef = doc(firestore, 'users', userId);
    const snap = await getDoc(userRef);
    return snap.exists() ? snap.data() : null;
  }

  /**
   * List all registered users from Firestore
   */
  public static async listUsers(): Promise<any[]> {
    const firestore = this.getDb();
    const usersRef = collection(firestore, 'users');
    const snapshot = await getDocs(usersRef);
    return snapshot.docs.map((docSnap) => docSnap.data());
  }

  /**
   * Delete user from Firestore
   */
  public static async deleteUser(userId: string): Promise<void> {
    const firestore = this.getDb();
    const userRef = doc(firestore, 'users', userId);
    await deleteDoc(userRef);
  }

  /**
   * Delete client from Firestore
   */
  public static async deleteClient(clientId: string): Promise<void> {
    const firestore = this.getDb();
    const clientRef = doc(firestore, 'clients', clientId);
    await deleteDoc(clientRef);
  }

  /**
   * Save password override request in Firestore
   */
  public static async saveOverrideRequest(req: PasswordOverrideRequest | any): Promise<void> {
    const firestore = this.getDb();
    const reqRef = doc(firestore, 'override_requests', req.id);
    await setDoc(reqRef, {
      ...req,
      updatedAt: new Date().toISOString(),
    }, { merge: true });
  }

  /**
   * List all password override requests from Firestore
   */
  public static async listOverrideRequests(): Promise<any[]> {
    const firestore = this.getDb();
    const reqsRef = collection(firestore, 'override_requests');
    const snapshot = await getDocs(reqsRef);
    return snapshot.docs.map((d) => d.data());
  }

  /**
   * Save deletion request in Firestore (Section 9)
   */
  public static async saveDeletionRequest(req: DeletionRequest): Promise<void> {
    const firestore = this.getDb();
    const reqRef = doc(firestore, 'deletion_requests', req.id);
    await setDoc(reqRef, {
      ...req,
      updatedAt: new Date().toISOString(),
    }, { merge: true });
  }

  /**
   * List deletion requests from Firestore
   */
  public static async listDeletionRequests(): Promise<DeletionRequest[]> {
    const firestore = this.getDb();
    const reqsRef = collection(firestore, 'deletion_requests');
    const snapshot = await getDocs(reqsRef);
    return snapshot.docs.map((d) => d.data() as DeletionRequest);
  }

  /**
   * Save audit log entry to Firestore
   */
  public static async saveAuditLog(entry: any): Promise<void> {
    const firestore = this.getDb();
    const logRef = doc(firestore, 'audit_logs', entry.id);
    await setDoc(logRef, entry, { merge: true });
  }

  /**
   * List audit logs from Firestore
   */
  public static async listAuditLogs(): Promise<any[]> {
    const firestore = this.getDb();
    const logsRef = collection(firestore, 'audit_logs');
    const snapshot = await getDocs(logsRef);
    return snapshot.docs.map((d) => d.data());
  }
}
