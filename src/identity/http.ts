import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { HttpError, unauthorized } from '../shared/http-error.js';
import { IdentityService } from './identity.service.js';
import { TokenService } from './token.js';
import type { RequestContext } from './types.js';

const RegisterSchema = z.object({ email: z.string().email(), password: z.string().min(1) });
const VerifyEmailSchema = z.object({ token: z.string().min(1) });
const LoginSchema = z.object({ email: z.string().email(), password: z.string().min(1), deviceFingerprint: z.string().optional() });
const MfaCompleteSchema = z.object({ challengeToken: z.string().min(1), code: z.string().min(4) });
const RefreshSchema = z.object({ refreshToken: z.string().min(1) });
const LogoutSchema = z.object({ refreshToken: z.string().optional() });
const VerifyTotpSetupSchema = z.object({ code: z.string().min(4) });

export function registerIdentityRoutes(app: FastifyInstance, identity: IdentityService, tokens: TokenService) {
  app.setErrorHandler((err, _request, reply) => {
    if (err instanceof HttpError) return reply.status(err.statusCode).send({ error: { code: err.code, message: err.message } });
    app.log.error(err);
    return reply.status(500).send({ error: { code: 'INTERNAL_ERROR', message: 'Internal server error.' } });
  });

  app.get('/health', async () => ({ ok: true, service: 'identity', time: new Date().toISOString() }));
  app.post('/auth/register', async (request) => identity.register({ ...RegisterSchema.parse(request.body), context: requestContext(request) }));
  app.post('/auth/verify-email', async (request) => identity.verifyEmail(VerifyEmailSchema.parse(request.body).token));
  app.post('/auth/login', async (request) => {
    const body = LoginSchema.parse(request.body);
    return identity.login({ email: body.email, password: body.password, context: requestContext(request, body.deviceFingerprint) });
  });
  app.post('/auth/mfa/complete', async (request) => identity.completeMfa({ ...MfaCompleteSchema.parse(request.body), context: requestContext(request) }));
  app.post('/auth/token/refresh', async (request) => identity.refresh(RefreshSchema.parse(request.body).refreshToken));

  app.post('/auth/logout', { preHandler: requireAuth(identity, tokens) }, async (request) => {
    const body = LogoutSchema.parse(request.body ?? {});
    return identity.logout({ sessionId: request.auth!.sid, refreshToken: body.refreshToken, context: requestContext(request) });
  });

  app.get('/me', { preHandler: requireAuth(identity, tokens) }, async (request) => {
    const session = identity.requireSession(request.auth!.sid);
    const user = identity.requireUser(session.userId);
    return { user: identity.publicUser(user), session };
  });

  app.get('/auth/sessions', { preHandler: requireAuth(identity, tokens) }, async (request) => ({ sessions: identity.listSessions(request.auth!.sub) }));
  app.post('/auth/mfa/totp/setup', { preHandler: requireAuth(identity, tokens) }, async (request) => identity.startTotpSetup(request.auth!.sub));
  app.post('/auth/mfa/totp/verify-setup', { preHandler: requireAuth(identity, tokens) }, async (request) => identity.verifyTotpSetup(request.auth!.sub, VerifyTotpSetupSchema.parse(request.body).code));
  app.get('/admin/audit-events', async () => ({ events: identity.store.auditEvents.slice(-100).reverse() }));
}

function requestContext(request: FastifyRequest, deviceFingerprint?: string): RequestContext {
  return { ipAddress: request.ip, userAgent: request.headers['user-agent'], deviceFingerprint };
}

function requireAuth(identity: IdentityService, tokens: TokenService) {
  return async (request: FastifyRequest, _reply: FastifyReply) => {
    const header = request.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice('Bearer '.length) : undefined;
    if (!token) unauthorized('MISSING_ACCESS_TOKEN', 'Missing bearer access token.');
    const claims = tokens.verifyAccessToken(token);
    identity.requireSession(claims.sid);
    request.auth = claims;
  };
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: { sub: string; sid: string; aal: string; mfa: boolean };
  }
}
