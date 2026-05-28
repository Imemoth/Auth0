import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';

const app = Fastify({ logger: true });
const port = Number(process.env.PORT ?? 4000);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

await app.register(fastifyStatic, {
  root: path.join(__dirname, '..', 'public'),
  prefix: '/'
});

app.get('/health', async () => ({ ok: true, service: 'identity', time: new Date().toISOString() }));
app.get('/mock', async (_request, reply) => reply.sendFile('mock.html'));

await app.listen({ port, host: '0.0.0.0' });
