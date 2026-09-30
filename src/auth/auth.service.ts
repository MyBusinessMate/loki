import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import { db } from '../db/database.js';
import { User, SessionRecord, OrgRole } from '../types/models.js';
import { LokiAuditService } from '../audit/audit.service.js';

const JWT_SECRET = process.env.JWT_SECRET || 'loki-production-jwt-signing-secret-2026';
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
 * Manages identity, Argon2id verification, session tracking, token rotation, and lockout protection
 */
export class LokiAuthService {
  /**
   * Hash account login password using Argon2id
   */
  static async hashLoginPassword(password: string): Promise<string> {
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
   * Refresh Token Rotation with reuse detection (Section 23, 24, 54)
   */
  static async rotateRefreshToken(
    oldRawRefreshToken: string,
    reqMeta: { ipAddress?: string; userAgent?: string }
  ): Promise<TokenPair> {
    const oldHash = crypto.createHash('sha256').update(oldRawRefreshToken).digest('hex');
    const session = db.findSessionByTokenHash(oldHash);

    if (!session || session.revoked) {
      if (session) {
        // Reuse detection: Invalidate all sessions for this compromised user lineage
        db.revokeUserSessions(session.userId);
      }
      throw new Error('Invalid or revoked refresh token');
    }

    // Invalidate old session
    session.revoked = true;

    const user = db.findUserById(session.userId);
    if (!user || !user.isActive || user.isSuspended) {
      throw new Error('User inactive or suspended');
    }

    // Find user membership
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

      // Check organization lockdown
      const org = db.getOrg(decoded.orgId);
      if (org?.lockdownEnabled && decoded.role !== 'owner') {
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
