# Manual test flow

Run locally:

```bash
npm install
cp .env.example .env
npm run dev
```

Open:

```text
http://localhost:4000/mock
```

## Happy path

1. Click **Register**.
2. The response contains `devEmailVerificationToken`.
3. Click **Verify**.
4. Click **Login**.
5. Copy/store the returned access and refresh tokens if needed.
6. Click **Start TOTP setup**.
7. Scan the QR code in an authenticator app.
8. Enter the setup code and click **Verify setup**.
9. Logout.
10. Login again. The API returns `MFA_REQUIRED` and a challenge token.
11. Enter a current TOTP code and click **Complete MFA**.
12. Test **Refresh**, **Sessions**, **GET /me**, and **Audit**.

## Expected security behaviors

- Email must be verified before login.
- If TOTP MFA is enabled, first-factor login does not issue full access/refresh tokens.
- Refresh tokens rotate.
- Refresh-token reuse revokes the whole token family and session.
- Sessions are server-side tracked.
