import os
from urllib.parse import quote

from workers import WorkerEntrypoint, Response, wsgi


class Default(WorkerEntrypoint):
    async def fetch(self, request):
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
