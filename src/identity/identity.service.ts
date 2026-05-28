import { addHours, addMinutes, randomId, randomToken, sha256 } from '../shared/crypto.js';
import { badRequest, forbidden, notFound, unauthorized } from '../shared/http-error.js';
import type { AppConfig } from '../config.js';
import { AuditLogger } from './audit.js';
import { MfaService } from './mfa.js';
import { PasswordHasher, PasswordPolicy } from './password.js';
import { InMemoryIdentityStore } from './store.js';
import { TokenService } from './token.js';
import type { RequestContext, Session, User } from './types.js';

export class IdentityService {
  readonly passwordPolicy: PasswordPolicy;

  constructor(
    private readonly config: AppConfig,
    public readonly store: InMemoryIdentityStore,
    private readonly passwordHasher: PasswordHasher,
    private readonly tokenService: TokenService,
    private readonly mfaService: MfaService,
    private readonly audit: AuditLogger
  ) {
    this.passwordPolicy = new PasswordPolicy(config.passwordMinLength);
  }

  async register(input: { email: string; password: string; context: RequestContext }) {
    const email = input.email.trim().toLowerCase();
    this.passwordPolicy.assertValid(input.password);
    if (this.store.findUserByEmail(email)) badRequest('EMAIL_ALREADY_REGISTERED', 'Email is already registered.');

    const now = new Date();
    const user: User = { id: randomId('usr'), email, status: 'PENDING_EMAIL_VERIFICATION', createdAt: now, updatedAt: now };
    this.store.createUser(user);
    this.store.credentialsByUserId.set(user.id, {
      id: randomId('cred'),
      userId: user.id,
      passwordHash: await this.passwordHasher.hash(input.password),
      passwordAlgo: 'argon2id',
      passwordUpdatedAt: now,
      createdAt: now
    });

    const devEmailVerificationToken = randomToken(32);
    this.store.verificationTokens.set(randomId('vtok'), {
      id: randomId('vtok'),
      userId: user.id,
      type: 'EMAIL_VERIFICATION',
      tokenHash: sha256(devEmailVerificationToken),
      expiresAt: addHours(now, 24),
      createdAt: now
    });

    this.audit.write({ type: 'USER_REGISTERED', userId: user.id, message: 'User registered.', context: input.context });
    return { user: this.publicUser(user), devEmailVerificationToken };
  }

  verifyEmail(token: string) {
    const record = this.store.findVerificationTokenByHash(sha256(token));
    if (!record || record.consumedAt || record.expiresAt <= new Date()) unauthorized('INVALID_VERIFICATION_TOKEN', 'Verification token is invalid or expired.');

    const user = this.store.findUserById(record.userId);
    if (!user) notFound('USER_NOT_FOUND', 'User not found.');

    record.consumedAt = new Date();
    user.emailVerifiedAt = new Date();
    user.status = 'ACTIVE';
    this.store.updateUser(user);
    this.audit.write({ type: 'EMAIL_VERIFIED', userId: user.id, message: 'Email verified.' });
    return { user: this.publicUser(user) };
  }

  async login(input: { email: string; password: string; context: RequestContext }) {
    const email = input.email.trim().toLowerCase();
    const user = this.store.findUserByEmail(email);
    if (!user) unauthorized('INVALID_CREDENTIALS', 'Invalid credentials.');

    const credential = this.store.credentialsByUserId.get(user.id);
    const ok = credential ? await this.passwordHasher.verify(input.password, credential.passwordHash) : false;
    if (!ok) {
      this.audit.write({ type: 'LOGIN_FAILED', userId: user.id, severity: 'WARN', message: 'Invalid password.', context: input.context });
      unauthorized('INVALID_CREDENTIALS', 'Invalid credentials.');
    }
    if (user.status !== 'ACTIVE') forbidden('USER_NOT_ACTIVE', `User status is ${user.status}.`);

    if (this.mfaService.hasEnabledMfa(user.id)) {
      const challengeToken = randomToken(40);
      this.store.mfaChallenges.set(randomId('mfach'), {
        id: randomId('mfach'),
        userId: user.id,
        challengeTokenHash: sha256(challengeToken),
        expiresAt: addMinutes(new Date(), 5),
        createdAt: new Date(),
        context: input.context
      });
      this.audit.write({ type: 'MFA_CHALLENGE_CREATED', userId: user.id, message: 'MFA required.', context: input.context });
      return { status: 'MFA_REQUIRED' as const, challengeToken };
    }

    const session = this.createSession(user.id, 'AAL1_PASSWORD', input.context);
    const refresh = this.tokenService.issueRefreshToken(session);
    this.audit.write({ type: 'LOGIN_SUCCEEDED', userId: user.id, message: 'Login succeeded.', context: input.context });
    return this.tokenPair(session, refresh.plain);
  }

  completeMfa(input: { challengeToken: string; code: string; context: RequestContext }) {
    const challenge = this.store.findMfaChallengeByHash(sha256(input.challengeToken));
    if (!challenge || challenge.consumedAt || challenge.expiresAt <= new Date()) unauthorized('INVALID_MFA_CHALLENGE', 'MFA challenge is invalid or expired.');
    if (!this.mfaService.verifyTotp(challenge.userId, input.code)) unauthorized('INVALID_MFA_CODE', 'MFA code is invalid.');

    challenge.consumedAt = new Date();
    const session = this.createSession(challenge.userId, 'AAL2_MFA', input.context, new Date());
    const refresh = this.tokenService.issueRefreshToken(session);
    this.audit.write({ type: 'MFA_COMPLETED', userId: challenge.userId, message: 'MFA completed.', context: input.context });
    return this.tokenPair(session, refresh.plain);
  }

  refresh(refreshToken: string) {
    const rotated = this.tokenService.rotateRefreshToken(refreshToken);
    return this.tokenPair(rotated.session, rotated.refreshToken);
  }

  logout(input: { sessionId: string; refreshToken?: string; context: RequestContext }) {
    const session = this.store.sessions.get(input.sessionId);
    if (!session) notFound('SESSION_NOT_FOUND', 'Session not found.');
    session.status = 'REVOKED';
    session.revokedAt = new Date();
    if (input.refreshToken) {
      const record = this.store.findRefreshTokenByHash(sha256(input.refreshToken));
      if (record) this.store.revokeRefreshTokenFamily(record.familyId);
    }
    this.audit.write({ type: 'SESSION_REVOKED', userId: session.userId, message: 'Session revoked.', metadata: { sessionId: session.id }, context: input.context });
    return { ok: true };
  }

  async startTotpSetup(userId: string) {
    const user = this.requireUser(userId);
    const setup = await this.mfaService.startTotpSetup(user.id, user.email);
    this.audit.write({ type: 'TOTP_SETUP_STARTED', userId: user.id, message: 'TOTP setup started.' });
    return setup;
  }

  verifyTotpSetup(userId: string, code: string) {
    const authn = this.mfaService.verifyTotpSetup(userId, code);
    const recoveryCodes = this.mfaService.generateRecoveryCodes();
    this.audit.write({ type: 'MFA_ENABLED', userId, message: 'TOTP MFA enabled.' });
    return { authenticatorId: authn.id, recoveryCodes };
  }

  listSessions(userId: string) {
    return this.store.listSessions(userId).map(({ id, status, assuranceLevel, createdAt, lastSeenAt, expiresAt, revokedAt, ipAddress, userAgent }) => ({ id, status, assuranceLevel, createdAt, lastSeenAt, expiresAt, revokedAt, ipAddress, userAgent }));
  }

  requireSession(sessionId: string): Session {
    const session = this.store.sessions.get(sessionId);
    if (!session || session.status !== 'ACTIVE') unauthorized('SESSION_INACTIVE', 'Session is inactive.');
    if (session.expiresAt <= new Date()) {
      session.status = 'EXPIRED';
      unauthorized('SESSION_EXPIRED', 'Session expired.');
    }
    return session;
  }

  requireUser(userId: string): User {
    const user = this.store.findUserById(userId);
    if (!user) notFound('USER_NOT_FOUND', 'User not found.');
    return user;
  }

  publicUser(user: User) {
    return { id: user.id, email: user.email, emailVerifiedAt: user.emailVerifiedAt, status: user.status, createdAt: user.createdAt, updatedAt: user.updatedAt };
  }

  private createSession(userId: string, assuranceLevel: Session['assuranceLevel'], context: RequestContext, mfaCompletedAt?: Date): Session {
    const now = new Date();
    const session: Session = {
      id: randomId('sess'),
      userId,
      status: 'ACTIVE',
      assuranceLevel,
      mfaCompletedAt,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: addHours(now, this.config.sessionAbsoluteTimeoutHours),
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      deviceFingerprint: context.deviceFingerprint,
      riskScore: 0
    };
    this.store.sessions.set(session.id, session);
    return session;
  }

  private tokenPair(session: Session, refreshToken: string) {
    return {
      status: 'AUTHENTICATED' as const,
      tokenType: 'Bearer',
      accessToken: this.tokenService.issueAccessToken(session),
      expiresIn: this.config.jwt.accessTokenTtlSeconds,
      refreshToken,
      sessionId: session.id,
      assuranceLevel: session.assuranceLevel
    };
  }
}
