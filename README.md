# 3EN INSPECTOR TEAM
**by: ROITH**

A Windows desktop inspection utility with a dark red/black UI.

## Current capabilities
- Consent confirmation before scanning.
- Windows process inventory and Microsoft Defender status checks.
- Inventory of executable/script files in selected user and program folders, with file-count and time limits.
- SHA-256 hashes for keyword-matched candidates only; file contents are not uploaded.
- Search/filter and sortable result table.
- Local password setup on first launch, with password prompt on later launches.
- JSON and CSV export, PDF report generation, and opening the local reports folder.
- Saved report/session list, with double-click or button to open a selected report.
- Event log page and settings page.
- Optional request for Microsoft Defender to perform its own quick scan.
- Optional Discord webhook delivery of the generated PDF report after explicit user action.
- Automatically saves reports under `Documents/3EN_Inspector_Team`.

## Download the Windows EXE
1. Open the [latest successful build](https://github.com/dlta30/lnspector-Team/actions/runs/40390309601).
2. Scroll to **Artifacts** and download **3EN-Inspector-Team-Windows**.
3. Extract the ZIP file.
4. Run `3EN_Inspector_Team.exe` on Windows.

The artifact is a build output, not a signed installer. Windows SmartScreen may show a warning for unsigned builds. The build workflow succeeding confirms packaging completed; it does not replace testing on your own Windows computer.

## Important limitations
This is a **Windows desktop application**, not a Render-hosted web app. It does not let an inspector remotely scan another player's computer through a URL, and it does not provide a central dashboard, online inspector accounts, session codes, or a remote agent. A player must run it on their own Windows computer and affirm consent.

The scan uses process names, file paths, Defender status, and filename/path keyword heuristics. These are review leads, not proof of cheating or malware; false positives and missed detections are possible. It is not a complete anti-cheat scanner.

Never commit a Discord webhook URL or other secret to this public repository. Configure it privately inside the app. The local password protects normal app entry but is not a substitute for Windows account security or encrypted storage.


## Optional central web dashboard (new)

The repository now includes `dashboard_server.py`, an optional Flask dashboard for central report storage, staff accounts, owner-controlled report permissions, and an event log. It is separate from the Windows desktop app; the desktop app is **not yet automatically connected** to it. To run the dashboard locally:

1. Install Python 3.11+ and dependencies: `python -m pip install -r requirements.txt`.
2. Set environment variables before first launch:
   - `INSPECTOR_OWNER_USER=owner` (or your preferred owner username)
   - `INSPECTOR_OWNER_PASSWORD` to a strong password of at least 12 characters
   - `INSPECTOR_SECRET_KEY` to a long random secret
   - `INSPECTOR_API_KEY` to a separate long random key for report submissions
3. Start it with `python dashboard_server.py`, then open `http://127.0.0.1:5000`.

On Windows PowerShell, set a variable for the current terminal with `$env:INSPECTOR_OWNER_PASSWORD="use-a-long-unique-password"` (repeat for the other variables). Do not commit real secrets to GitHub. The owner can create inspector/viewer accounts and set report-view permissions. Report ingestion is disabled until `INSPECTOR_API_KEY` is configured.

**Security and deployment:** this is an initial optional dashboard, not a hardened public production service. Keep it bound to localhost or a trusted private network unless you add HTTPS, a production WSGI server, rate limiting, CSRF protection, secure cookie settings, and deployment secrets. Never expose the development server directly to the public internet. The API accepts JSON report data only (not file uploads or remote commands). The desktop client integration, end-to-end tests, and hosted deployment are still outstanding.
