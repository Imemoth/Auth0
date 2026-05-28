export type UserStatus = 'PENDING_EMAIL_VERIFICATION' | 'ACTIVE' | 'LOCKED' | 'SUSPENDED' | 'DELETED';
export type SessionStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED';
export type AssuranceLevel = 'AAL1_PASSWORD' | 'AAL2_MFA' | 'AAL3_PHISHING_RESISTANT';
export type AuditSeverity = 'INFO' | 'WARN' | 'CRITICAL';

export interface RequestContext {
  ipAddress?: string;
  userAgent?: string;
  deviceFingerprint?: string;
}

export interface User {
  id: string;
  email: string;
  emailVerifiedAt?: Date;
  status: UserStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface PasswordCredential {
  id: string;
  userId: string;
  passwordHash: string;
  passwordAlgo: 'argon2id';
  passwordUpdatedAt: Date;
  createdAt: Date;
}

export interface Authenticator {
  id: string;
  userId: string;
  type: 'TOTP' | 'WEBAUTHN' | 'SMS' | 'EMAIL_OTP';
  name: string;
  secretEncrypted?: string;
  enabledAt?: Date;
  lastUsedAt?: Date;
  createdAt: Date;
}

export interface Session {
  id: string;
  userId: string;
  status: SessionStatus;
  assuranceLevel: AssuranceLevel;
  mfaCompletedAt?: Date;
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  revokedAt?: Date;
  ipAddress?: string;
  userAgent?: string;
  deviceFingerprint?: string;
  riskScore: number;
}

export interface RefreshTokenRecord {
  id: string;
  sessionId: string;
  userId: string;
  tokenHash: string;
  familyId: string;
  parentTokenId?: string;
  createdAt: Date;
  usedAt?: Date;
  rotatedAt?: Date;
  expiresAt: Date;
  revokedAt?: Date;
  reuseDetectedAt?: Date;
}

export interface VerificationToken {
  id: string;
  userId: string;
  type: 'EMAIL_VERIFICATION' | 'PASSWORD_RESET' | 'EMAIL_CHANGE' | 'PHONE_CHANGE';
  tokenHash: string;
  expiresAt: Date;
  consumedAt?: Date;
  createdAt: Date;
}

export interface PendingMfaChallenge {
  id: string;
  userId: string;
  challengeTokenHash: string;
  expiresAt: Date;
  consumedAt?: Date;
  createdAt: Date;
  context: RequestContext;
}

export interface PendingTotpSetup {
  userId: string;
  secret: string;
  otpauthUrl: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface AuditEvent {
  id: string;
  type: string;
  userId?: string;
  severity: AuditSeverity;
  message: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  createdAt: Date;
}
