from workers import WorkerEntrypoint, Response

OLD_HOST = "https://threeen-fight.onrender.com"


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # Cloudflare's free Python Worker runtime is not suitable for this
        # full Flask dashboard. Send visitors back to the existing Render app.
        incoming = request.url
        suffix = incoming.split("/", 3)
        path_and_query = "/" + suffix[3] if len(suffix) > 3 else "/"
        destination = OLD_HOST + path_and_query
        return Response.redirect(destination, status=302)
