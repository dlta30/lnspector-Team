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
   - `INSPECTOR_STAFF_JOIN_PASSWORD` to a shared password you distribute privately; first-time staff usernames create pending viewer accounts with no permissions
3. Start it with `python dashboard_server.py`, then open `http://127.0.0.1:5000`.

On Windows PowerShell, set a variable for the current terminal with `$env:INSPECTOR_OWNER_PASSWORD="use-a-long-unique-password"` (repeat for the other variables). Do not commit real secrets to GitHub. The owner can create inspector/viewer accounts and set report-view permissions. A new staff member can enter their Discord username and the owner-configured `INSPECTOR_STAFF_JOIN_PASSWORD` to create a pending account; the account starts as a viewer with no report permissions. The owner can promote it to Inspector in Staff & permissions. A typed Discord username is not verified as ownership of that Discord account, so verify identity before granting access. Inspectors can create a two-hour session code from **Sessions**; the desktop user enters that code and explicitly approves sending one JSON report. Each code can be used once. The older API-key endpoint remains optional.

**Security and deployment:** this is an initial optional dashboard, not a hardened public production service. Keep it bound to localhost or a trusted private network unless you add HTTPS, a production WSGI server, rate limiting, CSRF protection, secure cookie settings, and deployment secrets. Never expose the development server directly to the public internet. The API accepts JSON report data only (not file uploads or remote commands). The desktop app now has central dashboard URL settings and a report-send flow using one-time session codes. End-to-end tests and hosted deployment are still outstanding.


## Session-code workflow

1. Start the dashboard on the trusted inspection host and sign in as owner or inspector.
2. Open **Sessions** and create a code. It expires after two hours and accepts one report.
3. On the player's Windows app, open **لوحة المشرف المركزية** in the left menu and set the dashboard URL.
4. After the local scan finishes, choose **إرسال التقرير بموافقة**, enter the code, and confirm sharing.
5. Open **Reports** in the dashboard to review the submitted JSON. The code is not a remote-control channel and cannot start a scan; the device owner must run the app and approve the scan and upload.

The session-code endpoint accepts JSON report data only and does not accept uploaded files or remote commands. Treat report contents as private because paths and process names may be sensitive.


## Discord report-room notifications

The central dashboard can post a compact notification to a Discord channel whenever a one-time session report is accepted. In the Discord channel, open **Edit Channel → Integrations → Webhooks → New Webhook**, copy the webhook URL, and add it to the dashboard host's environment as `DISCORD_WEBHOOK_URL`. Restart/redeploy the dashboard after setting it. Do not commit the URL to GitHub or put it in the desktop EXE. Notifications include the report ID, session code, device label, and summary only; the full process inventory and executable paths stay in the dashboard. The server must have outbound HTTPS access to Discord. The `/api/v1/session-report` response includes `discord_notified` so a client can tell whether the notification was delivered.

## Session-specific desktop builds

Use `build_session_exe.bat` on Windows to package `inspector_client.py` with a session code compiled into that build. Create a fresh session code in the dashboard for each inspection and build a separate EXE for that code. The code is one-time and expires after two hours. The EXE is not automatically generated by the dashboard; this build step is separate. The desktop app requires explicit consent and only uploads its report after the user confirms.
