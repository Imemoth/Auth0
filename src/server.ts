import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { loadConfig } from './config.js';
import { AuditLogger } from './identity/audit.js';
import { registerIdentityRoutes } from './identity/http.js';
import { IdentityService } from './identity/identity.service.js';
import { MfaService } from './identity/mfa.js';
import { PasswordHasher } from './identity/password.js';
import { InMemoryIdentityStore } from './identity/store.js';
import { TokenService } from './identity/token.js';

const config = loadConfig();
const app = Fastify({ logger: true });
const store = new InMemoryIdentityStore();
const audit = new AuditLogger(store);
const passwordHasher = new PasswordHasher();
const mfa = new MfaService(store);
const tokens = new TokenService(config, store, audit);
const identity = new IdentityService(config, store, passwordHasher, tokens, mfa, audit);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

await app.register(fastifyStatic, { root: path.join(__dirname, '..', 'public'), prefix: '/' });
app.get('/mock', async (_request, reply) => reply.sendFile('mock.html'));
registerIdentityRoutes(app, identity, tokens);
await app.listen({ port: config.port, host: '0.0.0.0' });
