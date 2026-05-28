import type { AuditEvent, Authenticator, PasswordCredential, PendingMfaChallenge, PendingTotpSetup, RefreshTokenRecord, Session, User, VerificationToken } from './types.js';

export class InMemoryIdentityStore {
  readonly users = new Map<string, User>();
  readonly usersByEmail = new Map<string, string>();
  readonly credentialsByUserId = new Map<string, PasswordCredential>();
  readonly authenticators = new Map<string, Authenticator>();
  readonly sessions = new Map<string, Session>();
  readonly refreshTokens = new Map<string, RefreshTokenRecord>();
  readonly verificationTokens = new Map<string, VerificationToken>();
  readonly mfaChallenges = new Map<string, PendingMfaChallenge>();
  readonly totpSetups = new Map<string, PendingTotpSetup>();
  readonly auditEvents: AuditEvent[] = [];

  createUser(user: User): User {
    this.users.set(user.id, user);
    this.usersByEmail.set(user.email, user.id);
    return user;
  }

  findUserByEmail(email: string): User | undefined {
    const userId = this.usersByEmail.get(email.toLowerCase());
    return userId ? this.users.get(userId) : undefined;
  }

  findUserById(userId: string): User | undefined {
    return this.users.get(userId);
  }

  updateUser(user: User): User {
    user.updatedAt = new Date();
    this.users.set(user.id, user);
    this.usersByEmail.set(user.email, user.id);
    return user;
  }

  listAuthenticators(userId: string): Authenticator[] {
    return [...this.authenticators.values()].filter((item) => item.userId === userId);
  }

  listSessions(userId: string): Session[] {
    return [...this.sessions.values()].filter((session) => session.userId === userId);
  }

  findRefreshTokenByHash(tokenHash: string): RefreshTokenRecord | undefined {
    return [...this.refreshTokens.values()].find((token) => token.tokenHash === tokenHash);
  }

  revokeRefreshTokenFamily(familyId: string, reuseDetected = false): void {
    const now = new Date();
    for (const token of this.refreshTokens.values()) {
      if (token.familyId === familyId) {
        token.revokedAt ??= now;
        if (reuseDetected) token.reuseDetectedAt ??= now;
      }
    }
  }

  findVerificationTokenByHash(tokenHash: string): VerificationToken | undefined {
    return [...this.verificationTokens.values()].find((token) => token.tokenHash === tokenHash);
  }

  findMfaChallengeByHash(challengeTokenHash: string): PendingMfaChallenge | undefined {
    return [...this.mfaChallenges.values()].find((challenge) => challenge.challengeTokenHash === challengeTokenHash);
  }
}
