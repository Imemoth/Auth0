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

## Boundary

Identity answers **who the user is** and how strong the authentication was.
Financial authorization, object-level account access, and bank-consent validation should remain separate modules.

```text
identity       -> user, credentials, MFA, sessions, token lifecycle
authorization  -> roles, permissions, object-level access
consent        -> bank-account access grants and scopes
audit          -> append-only security events
risk           -> step-up and suspicious activity decisions
```

## Local development

```bash
npm install
cp .env.example .env
npm run dev
```

Open the mock test page:

```text
http://localhost:4000/mock
```

## Security note

Starter foundation only. Before regulated production use, add persistent storage, KMS-backed secrets, immutable audit storage, rate limiting, security review, penetration testing, and compliance validation.
