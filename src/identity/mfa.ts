import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { addMinutes, randomId } from '../shared/crypto.js';
import { unauthorized } from '../shared/http-error.js';
import { InMemoryIdentityStore } from './store.js';
import type { Authenticator, PendingTotpSetup } from './types.js';

export class MfaService {
  constructor(private readonly store: InMemoryIdentityStore) {}

  hasEnabledMfa(userId: string): boolean {
    return this.store.listAuthenticators(userId).some((item) => item.enabledAt);
  }

  async startTotpSetup(userId: string, email: string): Promise<PendingTotpSetup & { qrCodeDataUrl: string }> {
    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(email, 'Auth0-style Identity Service', secret);
    const setup: PendingTotpSetup = {
      userId,
      secret,
      otpauthUrl,
      createdAt: new Date(),
      expiresAt: addMinutes(new Date(), 10)
    };
    this.store.totpSetups.set(userId, setup);
    return { ...setup, qrCodeDataUrl: await QRCode.toDataURL(otpauthUrl) };
  }

  verifyTotpSetup(userId: string, code: string): Authenticator {
    const setup = this.store.totpSetups.get(userId);
    if (!setup || setup.expiresAt <= new Date()) unauthorized('TOTP_SETUP_EXPIRED', 'TOTP setup expired.');
    if (!authenticator.check(code, setup.secret)) unauthorized('INVALID_TOTP_CODE', 'TOTP code is invalid.');

    const record: Authenticator = {
      id: randomId('authn'),
      userId,
      type: 'TOTP',
      name: 'Authenticator app',
      secretEncrypted: setup.secret,
      enabledAt: new Date(),
      createdAt: new Date()
    };
    this.store.authenticators.set(record.id, record);
    this.store.totpSetups.delete(userId);
    return record;
  }

  verifyTotp(userId: string, code: string): boolean {
    const authn = this.store.listAuthenticators(userId).find((item) => item.type === 'TOTP' && item.enabledAt && item.secretEncrypted);
    if (!authn?.secretEncrypted) return false;
    const ok = authenticator.check(code, authn.secretEncrypted);
    if (ok) authn.lastUsedAt = new Date();
    return ok;
  }

  generateRecoveryCodes(): string[] {
    return Array.from({ length: 10 }, () => `${Math.random().toString(36).slice(2, 6).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`);
  }
}
