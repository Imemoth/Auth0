# Auth0-style Identity Service

Self-hosted identity-management foundation for a financial application.

## Current scope

This initial implementation contains:

- user registration with email-verification state
- password credential handling with Argon2id
- login with short-lived JWT access tokens
- refresh-token rotation with reuse detection
- server-side session registry
- TOTP MFA setup and MFA challenge completion
- audit events for sensitive identity actions
- lightweight browser mock page for manual testing

## Local development

```bash
npm install
cp .env.example .env
npm run dev
```

Open locally:

```text
http://localhost:4000/mock
```

## Vercel

The app is Vercel-compatible through `api/index.ts` and `vercel.json` rewrites.

Expected routes on Vercel:

```text
/mock          -> static mock UI
/mock.html     -> static mock UI
/health        -> serverless Fastify API
/auth/*        -> serverless Fastify API
/me            -> serverless Fastify API
/admin/*       -> serverless Fastify API
```

## Security note

Starter foundation only. Before regulated production use, add persistent storage, KMS-backed secrets, immutable audit storage, rate limiting, security review, penetration testing, and compliance validation.
