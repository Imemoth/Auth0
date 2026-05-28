import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fastifyStatic from '@fastify/static';
import { buildApp, config } from './app.js';

const app = buildApp();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

await app.register(fastifyStatic, {
  root: path.join(__dirname, '..', 'public'),
  prefix: '/'
});

app.get('/mock', async (_request, reply) => reply.sendFile('mock.html'));

try {
  await app.listen({ port: config.port, host: '0.0.0.0' });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
