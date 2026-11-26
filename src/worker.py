import importlib
import os

from workers import WorkerEntrypoint, Response, wsgi


ENV_KEYS = (
    "INSPECTOR_OWNER_USER",
    "INSPECTOR_OWNER_PASSWORD",
    "INSPECTOR_DEPUTY_PASSWORD",
    "INSPECTOR_API_KEY",
    "SCANNER_API_KEY",
    "INSPECTOR_SECRET_KEY",
    "APP_SECRET",
    "DISCORD_OAUTH_CLIENT_ID",
    "DISCORD_OAUTH_CLIENT_SECRET",
    "DISCORD_OAUTH_REDIRECT_URI",
    "DISCORD_GUILD_ID",
    "DISCORD_ALLOWED_ROLE_ID",
    "DISCORD_BOT_TOKEN",
    "GITHUB_ACTIONS_TOKEN",
    "GITHUB_REPOSITORY",
    "PUBLIC_DASHBOARD_URL",
)


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        if getattr(self.env, "DB", None) is None:
            return Response(
                "Cloudflare D1 binding DB is missing. Check wrangler.jsonc.",
                status=503,
            )

        # The existing Flask dashboard reads secrets from environment variables.
        # Copy only explicitly supported bindings from the Worker environment.
        for key in ENV_KEYS:
            value = getattr(self.env, key, None)
            if value is not None:
                os.environ[key] = str(value)

        # D1 replaces the old Render PostgreSQL/Hyperdrive connection.
        os.environ.pop("DATABASE_URL", None)
        os.environ["CLOUDFLARE_D1"] = "1"

        try:
            dashboard = importlib.import_module("dashboard_server")
            return await wsgi.fetch(dashboard.app, request, self.env)
        except Exception:
            # Do not expose secrets or internal stack traces to visitors.
            return Response(
                "3EN Inspect is temporarily unavailable. Check Worker logs.",
                status=500,
            )
