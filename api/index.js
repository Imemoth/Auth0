import crypto from 'node:crypto';

const state = globalThis.__identityState ??= {
  users: new Map(),
  usersByEmail: new Map(),
  sessions: new Map(),
  refreshTokens: new Map(),
  verificationTokens: new Map(),
  mfaChallenges: new Map(),
  totpSetups: new Map(),
  audit: []
};

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

function token(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function audit(type, userId, message, metadata = {}) {
  const event = { id: id('aud'), type, userId, message, metadata, createdAt: new Date().toISOString() };
  state.audit.push(event);
  return event;
}

async function readBody(req) {
  if (req.method === 'GET') return {};
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, expected] = stored.split(':');
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

function base32Encode(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of input.replace(/=+$/g, '').toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function hotp(secret, counter) {
  const key = base32Decode(secret);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  msg.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

function verifyTotp(secret, code) {
  const now = Math.floor(Date.now() / 1000 / 30);
  return [-1, 0, 1].some((offset) => hotp(secret, now + offset) === String(code));
}

function issueTokens(user, assuranceLevel = 'AAL1_PASSWORD') {
  const sessionId = id('sess');
  const accessToken = token(32);
  const refreshToken = token(48);
  const session = {
    id: sessionId,
    userId: user.id,
    accessTokenHash: sha256(accessToken),
    assuranceLevel,
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString()
  };
  state.sessions.set(sessionId, session);
  state.refreshTokens.set(sha256(refreshToken), { userId: user.id, sessionId, active: true, familyId: id('rtf'), createdAt: new Date().toISOString() });
  return { status: 'AUTHENTICATED', tokenType: 'Bearer', accessToken, refreshToken, sessionId, assuranceLevel, expiresIn: 300 };
}

function getBearerUser(req) {
  const header = req.headers.authorization || '';
  const accessToken = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!accessToken) return null;
  const hash = sha256(accessToken);
  for (const session of state.sessions.values()) {
    if (session.accessTokenHash === hash && session.status === 'ACTIVE') {
      const user = state.users.get(session.userId);
      return user ? { user, session } : null;
    }
  }
  return null;
}

function publicUser(user) {
  return { id: user.id, email: user.email, emailVerifiedAt: user.emailVerifiedAt, status: user.status, mfaEnabled: Boolean(user.totpSecret) };
}

export default async function handler(req, res) {
  const url = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  const path = url.pathname;
  const body = await readBody(req);

  try {
    if (path === '/health') {
      return json(res, 200, { ok: true, service: 'identity-vercel-api', time: new Date().toISOString() });
    }

    if (path === '/auth/register' && req.method === 'POST') {
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      if (!email.includes('@')) return json(res, 400, { error: { code: 'INVALID_EMAIL', message: 'Invalid email.' } });
      if (password.length < 12) return json(res, 400, { error: { code: 'PASSWORD_TOO_SHORT', message: 'Password must be at least 12 characters.' } });
      if (state.usersByEmail.has(email)) return json(res, 400, { error: { code: 'EMAIL_ALREADY_REGISTERED', message: 'Email already registered.' } });
      const user = { id: id('usr'), email, passwordHash: passwordHash(password), status: 'PENDING_EMAIL_VERIFICATION', createdAt: new Date().toISOString() };
      state.users.set(user.id, user);
      state.usersByEmail.set(email, user.id);
      const verificationToken = token(32);
      state.verificationTokens.set(sha256(verificationToken), { userId: user.id, active: true });
      audit('USER_REGISTERED', user.id, 'User registered.');
      return json(res, 200, { user: publicUser(user), devEmailVerificationToken: verificationToken });
    }

    if (path === '/auth/verify-email' && req.method === 'POST') {
      const record = state.verificationTokens.get(sha256(String(body.token || '')));
      if (!record?.active) return json(res, 401, { error: { code: 'INVALID_VERIFICATION_TOKEN', message: 'Invalid verification token.' } });
      const user = state.users.get(record.userId);
      record.active = false;
      user.status = 'ACTIVE';
      user.emailVerifiedAt = new Date().toISOString();
      audit('EMAIL_VERIFIED', user.id, 'Email verified.');
      return json(res, 200, { user: publicUser(user) });
    }

    if (path === '/auth/login' && req.method === 'POST') {
      const email = String(body.email || '').trim().toLowerCase();
      const userId = state.usersByEmail.get(email);
      const user = userId ? state.users.get(userId) : null;
      if (!user || !verifyPassword(String(body.password || ''), user.passwordHash)) return json(res, 401, { error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials.' } });
      if (user.status !== 'ACTIVE') return json(res, 403, { error: { code: 'USER_NOT_ACTIVE', message: `User status is ${user.status}.` } });
      if (user.totpSecret) {
        const challengeToken = token(32);
        state.mfaChallenges.set(sha256(challengeToken), { userId: user.id, active: true, createdAt: Date.now() });
        audit('MFA_CHALLENGE_CREATED', user.id, 'MFA challenge created.');
        return json(res, 200, { status: 'MFA_REQUIRED', challengeToken });
      }
      audit('LOGIN_SUCCEEDED', user.id, 'Login succeeded.');
      return json(res, 200, issueTokens(user));
    }

    if (path === '/auth/mfa/complete' && req.method === 'POST') {
      const challenge = state.mfaChallenges.get(sha256(String(body.challengeToken || '')));
      if (!challenge?.active) return json(res, 401, { error: { code: 'INVALID_MFA_CHALLENGE', message: 'Invalid MFA challenge.' } });
      const user = state.users.get(challenge.userId);
      if (!user?.totpSecret || !verifyTotp(user.totpSecret, body.code)) return json(res, 401, { error: { code: 'INVALID_MFA_CODE', message: 'Invalid MFA code.' } });
      challenge.active = false;
      audit('MFA_COMPLETED', user.id, 'MFA completed.');
      return json(res, 200, issueTokens(user, 'AAL2_MFA'));
    }

    if (path === '/auth/token/refresh' && req.method === 'POST') {
      const currentHash = sha256(String(body.refreshToken || ''));
      const record = state.refreshTokens.get(currentHash);
      if (!record?.active) return json(res, 401, { error: { code: 'INVALID_REFRESH_TOKEN', message: 'Invalid refresh token.' } });
      record.active = false;
      const user = state.users.get(record.userId);
      audit('TOKEN_REFRESHED', user.id, 'Refresh token rotated.');
      return json(res, 200, issueTokens(user));
    }

    if (path === '/auth/logout' && req.method === 'POST') {
      const auth = getBearerUser(req);
      if (!auth) return json(res, 401, { error: { code: 'MISSING_OR_INVALID_TOKEN', message: 'Missing or invalid token.' } });
      auth.session.status = 'REVOKED';
      if (body.refreshToken) {
        const rt = state.refreshTokens.get(sha256(String(body.refreshToken)));
        if (rt) rt.active = false;
      }
      audit('SESSION_REVOKED', auth.user.id, 'Session revoked.');
      return json(res, 200, { ok: true });
    }

    if (path === '/auth/mfa/totp/setup' && req.method === 'POST') {
      const auth = getBearerUser(req);
      if (!auth) return json(res, 401, { error: { code: 'MISSING_OR_INVALID_TOKEN', message: 'Missing or invalid token.' } });
      const secret = base32Encode(crypto.randomBytes(20));
      const otpauthUrl = `otpauth://totp/Auth0-style:${encodeURIComponent(auth.user.email)}?secret=${secret}&issuer=Auth0-style`;
      state.totpSetups.set(auth.user.id, { secret, otpauthUrl, createdAt: Date.now() });
      audit('TOTP_SETUP_STARTED', auth.user.id, 'TOTP setup started.');
      return json(res, 200, { secret, otpauthUrl, qrCodeDataUrl: '', note: 'Scan otpauthUrl manually or enter the secret in your authenticator app.' });
    }

    if (path === '/auth/mfa/totp/verify-setup' && req.method === 'POST') {
      const auth = getBearerUser(req);
      if (!auth) return json(res, 401, { error: { code: 'MISSING_OR_INVALID_TOKEN', message: 'Missing or invalid token.' } });
      const setup = state.totpSetups.get(auth.user.id);
      if (!setup || !verifyTotp(setup.secret, body.code)) return json(res, 401, { error: { code: 'INVALID_TOTP_CODE', message: 'Invalid TOTP code.' } });
      auth.user.totpSecret = setup.secret;
      state.totpSetups.delete(auth.user.id);
      audit('MFA_ENABLED', auth.user.id, 'TOTP MFA enabled.');
      return json(res, 200, { authenticatorId: id('authn'), recoveryCodes: Array.from({ length: 10 }, () => `${token(3).toUpperCase()}-${token(3).toUpperCase()}`) });
    }

    if (path === '/me' && req.method === 'GET') {
      const auth = getBearerUser(req);
      if (!auth) return json(res, 401, { error: { code: 'MISSING_OR_INVALID_TOKEN', message: 'Missing or invalid token.' } });
      return json(res, 200, { user: publicUser(auth.user), session: auth.session });
    }

    if (path === '/auth/sessions' && req.method === 'GET') {
      const auth = getBearerUser(req);
      if (!auth) return json(res, 401, { error: { code: 'MISSING_OR_INVALID_TOKEN', message: 'Missing or invalid token.' } });
      const sessions = [...state.sessions.values()].filter((session) => session.userId === auth.user.id);
      return json(res, 200, { sessions });
    }

    if (path === '/admin/audit-events' && req.method === 'GET') {
      return json(res, 200, { events: state.audit.slice(-100).reverse() });
    }

    return json(res, 404, { error: { code: 'NOT_FOUND', message: 'Route not found.' }, path, method: req.method });
  } catch (error) {
    return json(res, 500, { error: { code: 'INTERNAL_ERROR', message: error?.message || 'Internal error.' } });
  }
}
