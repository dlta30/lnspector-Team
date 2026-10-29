# 3eN Inspector Team
**by: ROITH**

A consent-based Windows inspection client with a Flask reporting dashboard.

## Current client scope
- Requires an explicit consent checkbox and a confirmation before scanning.
- Lists running process metadata and computes SHA-256 hashes for readable process executables.
- Collects Windows Run-key startup entry names and command strings; it does not execute startup items.
- Adds basic FiveM/Fortnite process context and configurable name-based indicators for manual review.
- Hides detailed findings from the inspected user and prepares a JSON report for the administrator.
- Requires explicit confirmation before uploading the report to the dashboard.
- Does not read browser data, credentials, personal documents, keystrokes, or memory; it does not provide remote control.
- The current indicators are heuristics only. They are not proof of cheating, and they can miss tools or flag legitimate software.

## Dashboard
The optional Flask dashboard in `dashboard_server.py` supports staff login/permissions, two-hour one-use inspection session codes, report storage, report details, PDF downloads, audit events, and optional Discord webhook notifications.

Required deployment environment variables:
- `INSPECTOR_OWNER_PASSWORD`: strong owner password
- `INSPECTOR_SECRET_KEY`: long random Flask session secret
- `DISCORD_WEBHOOK_URL`: optional; configure only in the hosting provider's secret/environment settings
- `INSPECTOR_OWNER_USER`: optional owner username (defaults to `owner`)
- `INSPECTOR_DB`: optional database path

Install dependencies with `python -m pip install -r requirements.txt`. Run locally with `python dashboard_server.py`. In production, use HTTPS and a production WSGI server; configure the hosting provider's start command and environment variables. Do not expose Flask's development server directly to the public internet.

## Keep accounts, sessions, reports, and audit history across deploys

SQLite data survives application restarts and deploys **only when the database file is stored on persistent storage**. Render's default service filesystem is ephemeral.

For the Render service `3en-fight`:
1. Open the service in the Render Dashboard.
2. Add a **Persistent Disk** and set its mount path to `/var/data` (choose a size appropriate for your reports).
3. In **Environment**, set `INSPECTOR_DB=/var/data/inspector_dashboard.sqlite3`.
4. Save changes and wait for the service to redeploy.
5. Open **Logs** and verify the startup line says `Inspector database path: /var/data/inspector_dashboard.sqlite3`.
6. Create a test report, redeploy once, then sign in and verify that the same report and staff accounts remain.

The app already blocks deletion of reports, sessions, audit events, and staff accounts through its retention triggers. This does not replace backups: periodically back up the SQLite database from the persistent disk. Attaching a new empty disk does **not** automatically recover records that were stored on the old ephemeral filesystem. Export/back up existing records before switching storage if you need to preserve them.

## Build a Windows EXE
Open [Build Windows Inspector EXE](https://github.com/dlta30/lnspector-Team/actions/workflows/build-windows-client.yml).

### Generic EXE
Run the workflow with both inputs empty. Download the artifact ZIP from a successful workflow run and extract the EXE.

### Session-specific EXE
1. Sign in to the dashboard and open **Sessions**.
2. Create a fresh one-time session code.
3. Open the workflow link above and choose **Run workflow**.
4. Enter the session code and the dashboard HTTPS URL (for example, your Render service URL).
5. Wait for a successful build, open the run, and download its artifact ZIP.
6. Extract the EXE and send it only to the device owner, after explaining the scan and obtaining their permission.

The session code is valid for one report and expires after two hours. The EXE has the code and dashboard URL prefilled. It still requires the device owner to approve the scan and separately approve report upload. Build artifacts are retained for 14 days; create a fresh build when needed.

## Report flow
1. The device owner launches the EXE and approves the scan.
2. The client gathers the declared metadata and keeps detailed findings out of its visible result panel.
3. The device owner explicitly confirms sending the report.
4. The dashboard validates the one-time session code, stores the report, and attempts a compact Discord notification if `DISCORD_WEBHOOK_URL` is configured.
5. Authorized staff review **Reports** and can download the PDF.

## Important security and accuracy notes
- This is a focused inspection utility, not a complete anti-cheat or malware scanner.
- A process name, file path, hash, or startup entry is only a lead for manual review. Do not use it alone as grounds for punishment.
- Report data can contain device names, executable paths, and running-process details. Restrict dashboard access and retain reports only as long as needed.
- Never commit a Discord webhook, password, API token, or other secret to this repository or embed it in the EXE.
- A successful build does not prove the app works correctly on every Windows device. Test the EXE, hosted API, PDF generation, and Discord delivery with a test session before using it operationally.
