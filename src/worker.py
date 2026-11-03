import importlib
import os
import sys
from urllib.parse import quote

from workers import WorkerEntrypoint, Response, wsgi


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        try:
            hyperdrive = self.env.HYPERDRIVE
            # Build the connection URL from the secret Hyperdrive binding at runtime.
            # No database credentials are stored in the repository.
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

            dashboard = sys.modules.get("dashboard_server")
            if dashboard is None:
                dashboard = importlib.import_module("dashboard_server")

            return await wsgi.fetch(dashboard.app, request, self.env)
        except AttributeError:
            return Response(
                "Hyperdrive binding is missing. Add a Hyperdrive binding named HYPERDRIVE.",
                status=503,
            )
