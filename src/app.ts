import Fastify from 'fastify';
import { loadConfig } from './config.js';
import { AuditLogger } from './identity/audit.js';
import { registerIdentityRoutes } from './identity/http.js';
import { IdentityService } from './identity/identity.service.js';
import { MfaService } from './identity/mfa.js';
import { PasswordHasher } from './identity/password.js';
import { InMemoryIdentityStore } from './identity/store.js';
import { TokenService } from './identity/token.js';

const config = loadConfig();
const store = new InMemoryIdentityStore();
const audit = new AuditLogger(store);
const passwordHasher = new PasswordHasher();
const mfa = new MfaService(store);
const tokens = new TokenService(config, store, audit);
const identity = new IdentityService(config, store, passwordHasher, tokens, mfa, audit);

export function buildApp() {
  const app = Fastify({ logger: true });
  registerIdentityRoutes(app, identity, tokens);
  return app;
}

export { config };
