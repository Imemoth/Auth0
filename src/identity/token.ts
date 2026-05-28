import jwt from 'jsonwebtoken';
import { addDays, randomId, randomToken, sha256 } from '../shared/crypto.js';
import { unauthorized } from '../shared/http-error.js';
import type { AppConfig } from '../config.js';
import type { AssuranceLevel, RefreshTokenRecord, Session } from './types.js';
import { InMemoryIdentityStore } from './store.js';
import { AuditLogger } from './audit.js';

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  aal: AssuranceLevel;
  mfa: boolean;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
}

export class TokenService {
  constructor(private readonly config: AppConfig, private readonly store: InMemoryIdentityStore, private readonly audit: AuditLogger) {}

  issueAccessToken(session: Session): string {
    return jwt.sign(
      {
        sub: session.userId,
        sid: session.id,
        aal: session.assuranceLevel,
        mfa: session.assuranceLevel !== 'AAL1_PASSWORD'
      },
      this.config.jwt.accessTokenSecret,
      {
        algorithm: 'HS256',
        issuer: this.config.jwt.issuer,
        audience: this.config.jwt.audience,
        expiresIn: this.config.jwt.accessTokenTtlSeconds
      }
    );
  }

  verifyAccessToken(token: string): AccessTokenClaims {
    return jwt.verify(token, this.config.jwt.accessTokenSecret, {
      algorithms: ['HS256'],
      issuer: this.config.jwt.issuer,
      audience: this.config.jwt.audience
    }) as AccessTokenClaims;
  }

  issueRefreshToken(session: Session, parentTokenId?: string, familyId?: string): { plain: string; record: RefreshTokenRecord } {
    const plain = randomToken(48);
    const record: RefreshTokenRecord = {
      id: randomId('rt'),
      sessionId: session.id,
      userId: session.userId,
      tokenHash: sha256(plain),
      familyId: familyId ?? randomId('rtf'),
      parentTokenId,
      createdAt: new Date(),
      expiresAt: addDays(new Date(), this.config.refreshTokenTtlDays)
    };
    this.store.refreshTokens.set(record.id, record);
    return { plain, record };
  }

  rotateRefreshToken(plainRefreshToken: string): { session: Session; refreshToken: string } {
    const current = this.store.findRefreshTokenByHash(sha256(plainRefreshToken));
    if (!current) unauthorized('INVALID_REFRESH_TOKEN', 'Refresh token is invalid.');

    const session = this.store.sessions.get(current.sessionId);
    if (!session || session.status !== 'ACTIVE') unauthorized('SESSION_INACTIVE', 'Session is not active.');

    const now = new Date();
    if (current.expiresAt <= now) unauthorized('REFRESH_TOKEN_EXPIRED', 'Refresh token expired.');

    if (current.revokedAt || current.usedAt) {
      this.store.revokeRefreshTokenFamily(current.familyId, true);
      session.status = 'REVOKED';
      session.revokedAt = now;
      this.audit.write({
        type: 'REFRESH_TOKEN_REUSE_DETECTED',
        userId: current.userId,
        severity: 'CRITICAL',
        message: 'Refresh-token reuse detected; session and token family revoked.',
        metadata: { sessionId: session.id, familyId: current.familyId }
      });
      unauthorized('REFRESH_TOKEN_REUSE_DETECTED', 'Refresh token reuse detected.');
    }

    current.usedAt = now;
    current.rotatedAt = now;
    current.revokedAt = now;
    session.lastSeenAt = now;

    const next = this.issueRefreshToken(session, current.id, current.familyId);
    return { session, refreshToken: next.plain };
  }
}
