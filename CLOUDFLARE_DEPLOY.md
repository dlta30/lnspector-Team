# Cloudflare deployment (D1)

This branch prepares the existing Flask dashboard to run on Cloudflare Python Workers and use the existing D1 database `3en-inspect`.

## Important status

- The Worker entrypoint is `src/worker.py`.
- The Flask app uses the D1 binding named `DB` through `d1_database.py`.
- The old Render redirect has been removed from both Worker entrypoint files.
- This is a migration branch. Do not switch production traffic or delete the old database until the deployment and end-to-end tests pass.
- D1 calls are bridged into the synchronous Flask app. Review session/report workflows carefully under concurrent requests before production use.

## Required Cloudflare secrets

In **Workers & Pages → 3en → Settings → Variables and Secrets**, add these as encrypted secrets:

- `INSPECTOR_OWNER_PASSWORD` — strong initial owner password.
- `INSPECTOR_SECRET_KEY` — long random Flask session secret.
- `INSPECTOR_API_KEY` — API key used by the desktop client to submit reports.

Add these optional encrypted secrets only if the corresponding features are used:

- `INSPECTOR_DEPUTY_PASSWORD`
- `DISCORD_OAUTH_CLIENT_ID`
- `DISCORD_OAUTH_CLIENT_SECRET`
- `DISCORD_OAUTH_REDIRECT_URI`
- `DISCORD_GUILD_ID`
- `DISCORD_ALLOWED_ROLE_ID`
- `DISCORD_BOT_TOKEN`
- `DISCORD_WEBHOOK_URL`
- `GITHUB_ACTIONS_TOKEN`

Add `PUBLIC_DASHBOARD_URL` as a variable after the first successful deploy, using the exact `workers.dev` URL Cloudflare assigns. Then set `DISCORD_OAUTH_REDIRECT_URI` to `PUBLIC_DASHBOARD_URL/auth/discord/callback` and add that exact URL to the Discord application's OAuth2 Redirects.

Never paste secret values into GitHub, source files, or chat.

## Deploy from the repository

From the repository root, after connecting Wrangler to the correct Cloudflare account:

```bash
npx wrangler deploy
```

The Wrangler config already points to D1 database `3en-inspect`. Do not run destructive SQL or delete the previous Render database.

## Test before switching users

1. Open `/health` and confirm the service responds.
2. Sign in with the configured owner account.
3. Confirm staff accounts and permissions.
4. Create a test one-use session and confirm it expires/changes state correctly.
5. Submit a test report from a consented test client.
6. Open the report, generate/download its PDF, and review the audit event.
7. Test Discord login and webhook delivery only if configured.
8. Repeat a deployment and verify the test data remains in D1.

Do not consider the migration complete until these tests pass. The old hosting and its data should remain untouched until then.
