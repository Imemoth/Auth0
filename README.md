# Auth0-style Identity Service

This repository contains a self-hosted identity-management foundation for a financial application.

## Scope

The first implementation focuses on the core identity layer:

- user registration and email-verification state
- password credential handling with Argon2id
- login with access tokens and refresh-token rotation
- TOTP-based MFA setup and challenge completion
- server-side session registry
- refresh-token family reuse detection
- audit events for sensitive identity actions
- a lightweight mock page for manual testing

## Important boundary

Identity answers **who the user is** and how strong the authentication was.
Financial authorization, object-level account access, and bank-consent validation belong to separate modules.

```text
identity       -> user, credential, MFA, session, token lifecycle
authorization  -> role, permission, object-level access
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

Then open:

```text
http://localhost:4000/mock
```

## Security note

This is an initial foundation, not a finished regulated-production identity provider. Before production use, add persistent storage, KMS-backed secrets, security reviews, penetration testing, full audit immutability, and compliance validation.
