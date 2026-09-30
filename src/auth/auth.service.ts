import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import { db } from '../db/database.js';
import { User, SessionRecord, OrgRole } from '../types/models.js';
import { LokiAuditService } from '../audit/audit.service.js';

const JWT_SECRET = process.env.JWT_SECRET || 'loki-production-jwt-signing-secret-2026-strict-key';
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_DAYS = 7;

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface AuthContext {
  userId: string;
  email: string;
  orgId: string;
  role: OrgRole;
  sessionId: string;
}

/**
 * Loki Authentication Service
 * Manages identity, Argon2id verification, session tracking, token rotation,
 * strict password complexity policy, 3-per-month password change limits, and 3-day cooldown.
 */
export class LokiAuthService {
  /**
   * Section 20 & 40: Password Validation Policy
   * - Minimum 8 characters
   * - Maximum 30 characters
   * - At least 1 uppercase letter
   * - At least 1 lowercase letter
   * - At least 1 number
   * - At least 1 special character
   */
  static validatePasswordComplexity(password: string): { valid: boolean; error?: string } {
    if (!password || typeof password !== 'string') {
      return { valid: false, error: 'Password is required' };
    }
    if (password.length < 8) {
      return { valid: false, error: 'Password must be at least 8 characters long' };
    }
    if (password.length > 30) {
      return { valid: false, error: 'Password cannot exceed 30 characters' };
    }
    if (!/[A-Z]/.test(password)) {
      return { valid: false, error: 'Password must include at least one uppercase letter' };
    }
    if (!/[a-z]/.test(password)) {
      return { valid: false, error: 'Password must include at least one lowercase letter' };
    }
    if (!/[0-9]/.test(password)) {
      return { valid: false, error: 'Password must include at least one number' };
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
      return { valid: false, error: 'Password must include at least one special character' };
    }
    return { valid: true };
  }

  /**
   * Hash account login password using Argon2id (Section 18)
   */
  static async hashLoginPassword(password: string): Promise<string> {
    const check = this.validatePasswordComplexity(password);
    if (!check.valid) {
      throw new Error(check.error);
    }
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
    });
  }

  /**
   * Verify account login password
   */
  static async verifyLoginPassword(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  /**
   * Section 19: User Password Change Limit & Cooldown
   * - Maximum 3 changes per calendar month
   * - 3-day cooldown between self changes
   * - Exception: Timekeeper who originally created that user may reset within cooldown
   */
  static verifyPasswordChangeEligibility(user: User, requestingUserId: string): { allowed: boolean; reason?: string } {
    const isSelf = user.id === requestingUserId;
    const isCreatorTimekeeper = user.createdByTimekeeperId === requestingUserId;

    if (!isSelf && !isCreatorTimekeeper) {
      return { allowed: false, reason: 'Only the account owner or original supervising creator timekeeper may reset this password' };
    }

    // Creator timekeeper bypasses cooldown and monthly quota
    if (isCreatorTimekeeper && !isSelf) {
      return { allowed: true };
    }

    const now = new Date();
    const history = user.passwordHistory || [];

    // Filter changes in current calendar month
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth();
    const changesThisMonth = history.filter((timestampStr) => {
      const d = new Date(timestampStr);
      return d.getFullYear() === currentYear && d.getMonth() === currentMonth;
    });

    if (changesThisMonth.length >= 3) {
      return {
        allowed: false,
        reason: 'Monthly limit reached: Maximum 3 password changes allowed per calendar month.',
      };
    }

    if (user.lastPasswordChangedAt) {
      const lastChange = new Date(user.lastPasswordChangedAt);
      const cooldownPeriodMs = 3 * 24 * 60 * 60 * 1000; // 3 days in ms
      const timeSinceLastChange = now.getTime() - lastChange.getTime();

      if (timeSinceLastChange < cooldownPeriodMs) {
        const remainingHours = Math.ceil((cooldownPeriodMs - timeSinceLastChange) / (1000 * 60 * 60));
        return {
          allowed: false,
          reason: `Password change cooldown active. You can change your password again in ${remainingHours} hours. Contact your supervising Timekeeper for an administrative reset.`,
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Section 45: Secure Hash for Timekeeper Authorization Codes
   */
  static async hashAuthorizationCode(code: string): Promise<{ hash: string; salt: string }> {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHmac('sha256', salt).update(code.trim()).digest('hex');
    return { hash, salt };
  }

  static verifyAuthorizationCode(code: string, storedHash: string, salt: string): boolean {
    const computed = crypto.createHmac('sha256', salt).update(code.trim()).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(computed, 'utf-8'), Buffer.from(storedHash, 'utf-8'));
  }

  /**
   * Issue a new Session and Token Pair
   */
  static async createSession(
    user: User,
    orgId: string,
    role: OrgRole,
    reqMeta: { ipAddress?: string; userAgent?: string; deviceName?: string }
  ): Promise<TokenPair> {
    const rawRefreshToken = crypto.randomBytes(40).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');
    const sessionId = crypto.randomUUID();

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_DAYS);

    const session: SessionRecord = {
      id: sessionId,
      userId: user.id,
      tokenHash,
      deviceName: reqMeta.deviceName || 'Web Client',
      ipAddress: reqMeta.ipAddress || '127.0.0.1',
      userAgent: reqMeta.userAgent || 'Unknown',
      expiresAt: expiresAt.toISOString(),
      revoked: false,
      createdAt: new Date().toISOString(),
      lastActiveAt: new Date().toISOString(),
    };

    db.saveSession(session);

    const accessToken = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        orgId,
        role,
        sessionId,
      },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_TTL }
    );

    await LokiAuditService.recordEvent({
      orgId,
      userId: user.id,
      action: 'USER_LOGIN',
      resourceType: 'session',
      resourceId: sessionId,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
    });

    return {
      accessToken,
      refreshToken: rawRefreshToken,
    };
  }

  /**
   * Refresh Token Rotation with reuse detection
   */
  static async rotateRefreshToken(
    oldRawRefreshToken: string,
    reqMeta: { ipAddress?: string; userAgent?: string }
  ): Promise<TokenPair> {
    const oldHash = crypto.createHash('sha256').update(oldRawRefreshToken).digest('hex');
    const session = db.findSessionByTokenHash(oldHash);

    if (!session || session.revoked) {
      if (session) {
        db.revokeUserSessions(session.userId);
      }
      throw new Error('Invalid or revoked refresh token');
    }

    session.revoked = true;

    const user = db.findUserById(session.userId);
    if (!user || !user.isActive || user.isSuspended) {
      throw new Error('User inactive or suspended');
    }

    const membership = Array.from(db.memberships.values()).find(
      (m) => m.userId === user.id && m.isActive
    );
    if (!membership) {
      throw new Error('Active organization membership required');
    }

    return this.createSession(user, membership.orgId, membership.role, {
      ...reqMeta,
      deviceName: session.deviceName,
    });
  }

  /**
   * Verify and decode Access Token
   */
  static verifyAccessToken(token: string): AuthContext {
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      const session = db.sessions.get(decoded.sessionId);
      if (!session || session.revoked || new Date(session.expiresAt) < new Date()) {
        throw new Error('Session revoked or expired');
      }

      const org = db.getOrg(decoded.orgId);
      if (org?.lockdownEnabled && decoded.role !== 'timekeeper') {
        throw new Error('Organization is currently in emergency lockdown mode');
      }

      return {
        userId: decoded.sub,
        email: decoded.email,
        orgId: decoded.orgId,
        role: decoded.role,
        sessionId: decoded.sessionId,
      };
    } catch (err: any) {
      throw new Error(`Authentication failure: ${err.message}`);
    }
  }

  /**
   * Explicit Session Revocation
   */
  static async revokeSession(sessionId: string, orgId: string, performedByUserId: string): Promise<void> {
    const session = db.sessions.get(sessionId);
    if (session) {
      session.revoked = true;
      await LokiAuditService.recordEvent({
        orgId,
        userId: performedByUserId,
        action: 'SESSION_REVOKE',
        resourceType: 'session',
        resourceId: sessionId,
      });
    }
  }
}
