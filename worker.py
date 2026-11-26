# Compatibility entrypoint. Wrangler is configured to use src/worker.py.
# Keep this file from redirecting users back to the retired Render deployment.
from src.worker import Default
