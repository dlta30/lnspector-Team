import os
from urllib.parse import quote

from workers import WorkerEntrypoint, Response, wsgi


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # Lightweight platform probe: do not import the full Flask/Pyodide app
        # or initialize database drivers just to answer health checks.
        if request.url.split("?", 1)[0].rstrip("/").endswith("/health"):
            return Response(
                '{"ok":true,"service":"3EN Inspect Team worker","mode":"edge-probe"}',
                headers={"content-type": "application/json; charset=utf-8"},
            )

        try:
            hyperdrive = self.env.HYPERDRIVE
        except AttributeError:
            return Response(
                "Hyperdrive binding is missing. Add a Hyperdrive binding named HYPERDRIVE.",
                status=503,
            )

        database_url = (
            "postgresql://"
            + quote(hyperdrive.user, safe="")
            + ":"
            + quote(hyperdrive.password, safe="")
            + "@"
            + hyperdrive.host
            + ":"
            + str(hyperdrive.port)
            + "/"
            + quote(hyperdrive.database, safe="")
        )
        os.environ["DATABASE_URL"] = database_url

        # Use a direct import so the Python Workers bundler includes the local module.
        import dashboard_server

        return await wsgi.fetch(dashboard_server.app, request, self.env)
