# 3EN INSPECTOR TEAM
**by: ROITH**

A Windows desktop inspection utility with a dark red/black UI.

## Current capabilities
- Consent confirmation before scanning.
- Windows process inventory and Microsoft Defender status checks.
- Review of recent executable/script files in selected user folders.
- SHA-256 hashes for keyword-matched candidates (hashes only; file contents are not uploaded).
- Search/filter, progress bar, JSON and CSV report export.
- Optional request for Microsoft Defender to perform its own quick scan.
- Local reports stored in Documents/3EN_Inspector_Team.

## Build a Windows EXE
1. Open the repository's **Actions** tab.
2. Run **Build 3EN Inspector Team EXE**, or push a change to `inspector_team.py`.
3. Open the successful workflow run.
4. Download the `3EN-Inspector-Team-Windows` artifact.

The artifact is a build output, not a signed installer. Windows SmartScreen may show a warning for unsigned builds.

## Important limitations
This tool performs transparent, consent-based checks. It does not silently collect files, take screenshots, or upload file contents. Keyword matches are heuristic leads, not proof of cheating or malware. This initial desktop version does not yet provide a live remote inspector dashboard or webhook delivery; those require a separately secured server endpoint and authenticated session flow.
