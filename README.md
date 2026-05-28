# Auth0-style Identity Service

Self-hosted identity-management foundation for a financial application.

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

## Vercel status

The root and `/mock` routes are static mock UI routes. `/health` is a minimal Vercel-native serverless function used to validate runtime stability before enabling the full auth API on Vercel.

Expected routes after this hotfix:

```text
/         -> static mock UI
/mock     -> static mock UI
/mock.html -> static mock UI
/health   -> minimal Vercel function
```

## Security note

Starter foundation only. Before regulated production use, add persistent storage, KMS-backed secrets, immutable audit storage, rate limiting, security review, penetration testing, and compliance validation.
