"""
3eN Inspect Team — transparent local inspection client.
Collects process metadata, 24-hour app activity, file metadata, and Windows Authenticode status.
A full-desktop screenshot is captured only after separate explicit user consent.
Run: python inspector_client.py
"""
import hashlib
import json
import os
import platform
import re
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime, timezone
from pathlib import Path

APP = "3eN Inspect Team"
try:
    from session_config import SESSION_CODE, DASHBOARD_URL
except ImportError:
    SESSION_CODE = ""
    DASHBOARD_URL = ""
SUSPICIOUS_TERMS = (
    "cheat", "cheatengine", "cheat engine", "injector", "trainer", "modmenu",
    "aimbot", "wallhack", "processhacker", "xenos", "extreme injector",
    "silent aim", "aimware", "redengine", "eulen", "skript", "lynx",
    "phantom", "rewasd", "macro recorder",
)
GAME_PROCESS_TERMS = {
    "FiveM": ("fivem.exe", "citizenfx", "gta5.exe", "gta process"),
    "Fortnite": ("fortniteclient", "easyanticheat", "epicgameslauncher"),
}

def classify_game_context(process_name, executable_path):
    text = (str(process_name or "") + " " + str(executable_path or "")).lower()
    return [game for game, terms in GAME_PROCESS_TERMS.items() if any(term in text for term in terms)]

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def capture_desktop_screenshot_base64(max_bytes=7_200_000):
    """Capture every connected desktop display only after the user explicitly opts in."""
    from io import BytesIO
    import base64
    from PIL import ImageGrab

    image = ImageGrab.grab(all_screens=True)
    image = image.convert("RGB")
    buffer = BytesIO()
    quality = 82
    while True:
        buffer.seek(0)
        buffer.truncate(0)
        image.save(buffer, format="JPEG", quality=quality, optimize=True, progressive=True)
        data = buffer.getvalue()
        if len(data) <= max_bytes:
            return base64.b64encode(data).decode("ascii")
        if quality > 48:
            quality -= 8
            continue
        width, height = image.size
        if max(width, height) <= 1600:
            raise RuntimeError("تعذر ضغط لقطة الشاشة إلى الحجم الآمن المسموح.")
        scale = 0.8
        image = image.resize((max(1, int(width * scale)), max(1, int(height * scale))))
        quality = 72


def utc_timestamp(value):
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def build_indicator_terms():
    return tuple(dict.fromkeys(SUSPICIOUS_TERMS + (
        "eulen", "menyo", "tiago", "tiago modz", "taigomodz", "falloutmenu",
        "cobramenu", "lux", "lux menu", "dopamine menu", "lua menu", "phantom",
        "monstermenu", "chiken's menu", "mysterious", "zentrix", "lambda", "lamda",
        "vmenu", "fivesense_v2", "swoopiexyz fivem", "swoopiexyz", "kekhack",
        "nitwit", "rely", "nove store", "redengine", "red engine", "mod menu.rar",
        "hack_fivem", "fivem mod menu", "mod gta", "modz gta", "fivem esp",
        "fivem wallhack", "fivem cheat no ban", "hack", "ai", "0x32",
        "sleezy spoofer", "aura spoofer", "escape service hack", "hazar",
        "fivemock", "loey", "duk_3", "ad movement", "filter key", "scod",
        "cr-fastrun", "loader.cfg", "loader", "loader.prod", "loader.global",
        "launcher", "injector", "lua injector", "lua executor", "gh injector",
        "gh enjector", "extreme injector", "winject", "asi plugin bypass",
        "cheat engine", "cheatengine", "cheat .rar", "ali_unban_method.pdf",
        "unknowncheats", "dumper", "decrypter", "bypass", "resource blocker",
        "memeproj.global", "loading.global", "rxexv3", "cff", "hjaldrgo",
        "ice breaker", "popstar", "lovex", "zc-firerate", "zc-firerate (alt version)",
        "zc-mp_f_freemode", "zc-explosiveammo", "zc-pedlight", "zc-electricammo",
        "zc-pedabilities", "zc-pedabilities v3", "zc-increasedrange",
        "zc-weaponmodifier", "zc-infiniteammo", "zc-damageboost",
        "zc-bulletpenetration", "no_recoil.rpf", "no_recoil", "ladders.meta",
        "remove_roll.rpf", "aml.lua", "fast_playboi_mods", "pedaccuracy.meta",
        "weaponcomponents.meta", "weaponanimation.meta", "bsk_skills",
        "bsk_skills.rpf", "quickenter", "quickenter.rpf"
    )))


INDICATOR_TERMS = build_indicator_terms()


def find_indicator_matches(name, path, indicators=None):
    indicators = indicators or INDICATOR_TERMS
    name_text = str(name or "").casefold()
    path_text = str(path or "").casefold()
    combined = name_text + " " + path_text
    matches = []
    basename = os.path.basename(str(path or name or "")).casefold()
    stem = os.path.splitext(basename)[0]
    exact_token_terms = {"lux", "hack", "ai", "loader", "launcher", "injector", "cff", "scod", "hazar", "loey"}
    for term in indicators:
        if term in exact_token_terms:
            if term == "ai":
                supplied_name = str(name or "").strip().casefold()
                matched = stem == "ai" or os.path.splitext(supplied_name)[0] == "ai"
            else:
                matched = bool(re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", combined))
            if matched:
                matches.append(term)
        elif term in combined:
            matches.append(term)
    return list(dict.fromkeys(matches))


def collect_files(progress, max_files=15000, max_scan_seconds=75):
    """Bounded metadata inventory for C:/D:. Never execute or open files/archives."""
    import time

    allowed_extensions = {".exe", ".dll", ".zip", ".rar"}
    excluded_dirs = {
        "windows", "$recycle.bin", "system volume information", "perflogs",
        "recovery", "config.msi", "winsxs", "servicing", "softwaredistribution",
        "node_modules", ".git", "__pycache__", "cache", "caches", "windowsapps",
        "windows defender", "package cache", "installer", "temp"
    }
    roots = [f"{drive}:\\" for drive in ("C", "D") if os.path.isdir(f"{drive}:\\")]
    candidates, seen = [], set()
    started = time.monotonic()
    last_progress = started
    stopped_early = False

    for root in roots:
        for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
            now = time.monotonic()
            if len(candidates) >= max_files or now - started >= max_scan_seconds:
                stopped_early = True
                break

            rel_parts = os.path.relpath(current, root).split(os.sep)
            if any(part.casefold() in excluded_dirs for part in rel_parts):
                dirs[:] = []
                continue

            dirs[:] = [
                d for d in dirs
                if d.casefold() not in excluded_dirs
                and not os.path.islink(os.path.join(current, d))
                and not d.casefold().startswith(("windows.", "$"))
            ]
            in_mods_ai = any(part.casefold() in {"mods", "ai"} for part in Path(current).parts)

            for name in names:
                path = os.path.join(current, name)
                extension = os.path.splitext(name)[1].casefold()
                matches = find_indicator_matches(name, current)
                # Keep the inventory strictly limited to the four declared file types.
                # Indicator-name matches and Mods/AI folder context must never expand the scope.
                if extension not in allowed_extensions:
                    continue
                try:
                    if os.path.islink(path) or not os.path.isfile(path):
                        continue
                    key = os.path.normcase(os.path.abspath(path))
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(("file", path, os.stat(path)))
                except OSError:
                    continue
                if len(candidates) >= max_files or time.monotonic() - started >= max_scan_seconds:
                    stopped_early = True
                    break

            now = time.monotonic()
            if now - last_progress >= 2:
                pct = 25 + int(min((now - started) / max_scan_seconds, 1.0) * 20)
                progress(pct, f"استكشاف الملفات... جُمِع {len(candidates):,} عنصر")
                last_progress = now
            if stopped_early:
                break
        if stopped_early:
            break

    rows = []
    total = max(len(candidates), 1)
    for i, (kind, path, st) in enumerate(candidates, 1):
        name = os.path.basename(path)
        matches = find_indicator_matches(name, path)
        context_flags = [ "Mods/AI folder context" ] if any(
            part.casefold() in {"mods", "ai"} for part in Path(path).parts
        ) else []
        too_large = st.st_size > 250 * 1024 * 1024
        created = utc_timestamp(st.st_ctime)
        modified = utc_timestamp(st.st_mtime)
        try:
            display_date = datetime.fromtimestamp(st.st_mtime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
            created_display = datetime.fromtimestamp(st.st_ctime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
        except (ValueError, OSError, OverflowError):
            display_date, created_display = modified, created

        digest = sha256_file(path) if kind == "file" and matches and not too_large else None
        rows.append({
            "artifact_type": kind, "file_name": name[:260], "path": path[:1500],
            "size_bytes": int(st.st_size), "created_at": created, "created_display": created_display,
            "modified_at": modified, "modified_display": display_date, "sha256": digest,
            "hash_skipped_large_file": too_large, "indicator_matches": list(dict.fromkeys(matches)),
            "context_flags": context_flags,
            "indicator_category": "مؤشرات حركة" if any(term in matches for term in ("ad movement", "filter key", "scod", "cr-fastrun")) else ("مؤشرات هاك/غش" if matches else "لا توجد مطابقة اسمية"),
            "assessment": "review" if matches else "metadata_only",
            "signature_status": "pending" if kind == "file" and os.path.splitext(name)[1].casefold() in {".exe", ".dll"} else "not_checked",
            "signature_label": "جارٍ التحقق" if kind == "file" and os.path.splitext(name)[1].casefold() in {".exe", ".dll"} else "غير موثق — لا يوجد توقيع رقمي قابل للتحقق لهذا النوع"
        })
        if i % 100 == 0 or i == total:
            progress(45 + int(i * 20 / total), f"تجهيز بيانات الملفات... {i:,}/{total:,}")

    rows.sort(key=lambda row: row.get("modified_at") or "", reverse=True)
    if stopped_early:
        progress(65, f"اكتمل الجزء المحدد زمنيًا: {len(rows):,} عنصر (حد الفحص {max_scan_seconds} ثانية)")
    return rows


def collect_fivem_artifacts(progress, max_files=8000, max_scan_seconds=35):
    """Collect metadata from common FiveM/GTA V locations; never execute or read file contents."""
    import time

    home = Path.home()
    local = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
    roaming = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    program_files_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    roots = [
        local / "FiveM" / "FiveM.app",
        roaming / "CitizenFX",
        home / "Documents" / "Rockstar Games" / "GTA V",
        program_files / "Rockstar Games" / "Grand Theft Auto V",
        program_files_x86 / "Rockstar Games" / "Grand Theft Auto V",
        program_files / "Steam" / "steamapps" / "common" / "Grand Theft Auto V",
        program_files_x86 / "Steam" / "steamapps" / "common" / "Grand Theft Auto V",
        program_files / "Epic Games" / "GTAV",
        program_files_x86 / "Epic Games" / "GTAV",
    ]
    allowed_extensions = {
        ".exe", ".dll", ".asi", ".lua", ".luac", ".json", ".cfg", ".ini",
        ".log", ".dat", ".bin", ".zip", ".rar", ".7z", ".rpf", ".meta", ".xml"
    }
    excluded_dirs = {
        "$recycle.bin", "system volume information", "windows", "winsxs",
        "node_modules", ".git", "__pycache__"
    }
    started = time.monotonic()
    candidates, seen = [], set()
    stopped_early = False
    existing_roots = [root for root in roots if root.is_dir()]

    for root in existing_roots:
        for current, dirs, names in os.walk(str(root), topdown=True, followlinks=False):
            if len(candidates) >= max_files or time.monotonic() - started >= max_scan_seconds:
                stopped_early = True
                break
            dirs[:] = [
                d for d in dirs
                if d.casefold() not in excluded_dirs
                and not os.path.islink(os.path.join(current, d))
            ]
            for name in names:
                ext = Path(name).suffix.casefold()
                if ext not in allowed_extensions:
                    continue
                path = os.path.join(current, name)
                try:
                    if os.path.islink(path) or not os.path.isfile(path):
                        continue
                    key = os.path.normcase(os.path.abspath(path))
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append((path, os.stat(path)))
                except OSError:
                    continue
                if len(candidates) >= max_files or time.monotonic() - started >= max_scan_seconds:
                    stopped_early = True
                    break
            if stopped_early:
                break
        if stopped_early:
            break

    rows = []
    total = max(len(candidates), 1)
    for index, (path, st) in enumerate(candidates, 1):
        name = os.path.basename(path)
        matches = find_indicator_matches(name, path)
        too_large = st.st_size > 250 * 1024 * 1024
        created = utc_timestamp(st.st_ctime)
        modified = utc_timestamp(st.st_mtime)
        try:
            modified_display = datetime.fromtimestamp(st.st_mtime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
            created_display = datetime.fromtimestamp(st.st_ctime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
        except (ValueError, OSError, OverflowError):
            modified_display, created_display = modified, created
        ext = Path(name).suffix.casefold()
        digest = sha256_file(path) if matches and not too_large else None
        rows.append({
            "artifact_type": "FiveM/GTA V file",
            "source": "FiveM/GTA V targeted locations",
            "file_name": name[:260], "path": path[:1500],
            "size_bytes": int(st.st_size), "created_at": created,
            "created_display": created_display, "modified_at": modified,
            "modified_display": modified_display, "sha256": digest,
            "hash_skipped_large_file": too_large,
            "indicator_matches": matches,
            "context_flags": ["FiveM/GTA V location"],
            "indicator_category": "مؤشرات هاك/غش" if matches else "لا توجد مطابقة اسمية",
            "assessment": "review" if matches else "metadata_only",
            "signature_status": "pending" if ext in {".exe", ".dll"} else "not_checked",
            "signature_label": "جارٍ التحقق" if ext in {".exe", ".dll"} else "لا ينطبق أو لم يتم التحقق"
        })
        if index % 100 == 0 or index == total:
            progress(45 + int(index * 20 / total), f"فحص مواقع FiveM وGTA V... {index:,}/{total:,}")

    if stopped_early:
        progress(65, f"انتهى الجزء المحدد زمنيًا من فحص FiveM: {len(rows):,} ملف")
    return rows



def collect_fivem_log_evidence(progress, max_files=250, max_file_bytes=2_000_000,
                               max_total_bytes=40_000_000, max_scan_seconds=25):
    """Inspect only selected FiveM/CitizenFX text logs; upload indicators and line numbers, never log text."""
    import time

    local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    roaming = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    roots = [
        local / "FiveM" / "FiveM.app" / "logs",
        local / "FiveM" / "FiveM.app" / "crashes",
        roaming / "CitizenFX",
    ]
    # Product-specific markers only. Generic words such as "hack", "menu", or
    # "injector" alone are intentionally excluded to reduce false positives.
    markers = (
        "eulen", "redengine", "red engine", "lynx", "lambda", "menyo",
        "tiago modz", "taigomodz", "swoopiexyz", "xenos", "extreme injector",
        "phantom menu", "lua executor", "lua injector", "cheat engine",
        "silent aim", "wallhack", "aimbot", "fivem esp", "falloutmenu",
        "cobramenu", "dopamine menu", "monstermenu", "fivesense_v2",
    )
    started = time.monotonic()
    candidates, seen = [], set()
    for root in roots:
        if not root.is_dir():
            continue
        for current, dirs, names in os.walk(str(root), topdown=True, followlinks=False):
            if time.monotonic() - started >= max_scan_seconds or len(candidates) >= max_files:
                break
            dirs[:] = [d for d in dirs if d.casefold() not in {
                "cache", "server-cache", "server-cache-priv", "crashes", "screenshots"
            } and not os.path.islink(os.path.join(current, d))]
            for name in names:
                if Path(name).suffix.casefold() not in {".log", ".txt"}:
                    continue
                path = os.path.join(current, name)
                try:
                    if os.path.islink(path) or not os.path.isfile(path):
                        continue
                    st = os.stat(path)
                    if st.st_size <= 0 or st.st_size > max_file_bytes:
                        continue
                    key = os.path.normcase(os.path.abspath(path))
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append((path, st))
                except OSError:
                    continue
        if time.monotonic() - started >= max_scan_seconds or len(candidates) >= max_files:
            break

    findings = []
    bytes_read = 0
    for index, (path, st) in enumerate(candidates, 1):
        if time.monotonic() - started >= max_scan_seconds or bytes_read >= max_total_bytes:
            break
        remaining = max_total_bytes - bytes_read
        read_limit = min(max_file_bytes, remaining)
        try:
            with open(path, "rb") as stream:
                raw = stream.read(read_limit + 1)
            if len(raw) > read_limit:
                raw = raw[:read_limit]
            bytes_read += len(raw)
            text = raw.decode("utf-8", errors="replace")
            matched_lines = {}
            for line_number, line in enumerate(text.splitlines(), 1):
                lowered = line.casefold()
                for marker_text in markers:
                    if marker_text in lowered:
                        matched_lines.setdefault(marker_text, []).append(line_number)
            if matched_lines:
                local_time = datetime.fromtimestamp(st.st_mtime).astimezone()
                findings.append({
                    "artifact_type": "FiveM/CitizenFX log indicator",
                    "source": "Targeted FiveM/CitizenFX text-log inspection",
                    "file_name": os.path.basename(path)[:260],
                    "path": path[:1500],
                    "size_bytes": int(st.st_size),
                    "modified_at": utc_timestamp(st.st_mtime),
                    "modified_display": local_time.strftime("%B %d, %Y %I:%M:%S %p"),
                    "indicator_matches": sorted(matched_lines.keys()),
                    "matched_line_numbers": {
                        key: values[:30] for key, values in matched_lines.items()
                    },
                    "matched_line_count": sum(len(values) for values in matched_lines.values()),
                    "log_contents_uploaded": False,
                    "context_flags": ["FiveM/CitizenFX log"],
                    "indicator_category": "مؤشرات داخل سجل اللعبة — تحتاج مراجعة",
                    "assessment": "review",
                    "evidence_confidence": "low",
                    "evidence_reason": "ظهرت كلمات مفتاحية مرتبطة بأدوات معروفة داخل سجل نصي؛ لم يتم رفع نص السجل ولا يُعد ذلك إثباتًا على وجود غش.",
                    "signature_status": "not_applicable",
                    "signature_label": "سجل نصي — لا ينطبق التوقيع الرقمي",
                })
        except (OSError, UnicodeError):
            continue
        if index % 20 == 0 or index == len(candidates):
            progress(65, f"تحليل سجلات FiveM النصية... {index}/{len(candidates)}")

    return findings


def collect_deleted_file_evidence(progress, max_entries=2000, max_scan_seconds=12):
    """Read bounded Windows Recycle Bin metadata for deleted executable/script/config artifacts only."""
    import struct
    import time

    started = time.monotonic()
    findings = []
    scanned = 0
    roots = [Path(f"{drive}:/$Recycle.Bin") for drive in ("C", "D")]
    interesting_extensions = {
        ".exe", ".dll", ".asi", ".lua", ".luac", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".jar", ".sys", ".scr", ".msi", ".zip", ".rar",
        ".7z", ".cfg", ".ini", ".json"
    }
    suspicious_terms = tuple(term.casefold() for term in SUSPICIOUS_TERMS)
    fivem_terms = ("fivem", "citizenfx", "gta v", "gtav", "grand theft auto")
    for root in roots:
        if not root.is_dir():
            continue
        try:
            sid_dirs = [p for p in root.iterdir() if p.is_dir() and not p.is_symlink()]
        except OSError:
            continue
        for sid_dir in sid_dirs:
            try:
                entries = list(sid_dir.iterdir())
            except OSError:
                continue
            for info_path in entries:
                if scanned >= max_entries or time.monotonic() - started >= max_scan_seconds:
                    progress(68, f"اكتمل فحص آثار المحذوفات ضمن الحدود: {len(findings)}")
                    return findings
                if not info_path.name.casefold().startswith("$i") or info_path.is_symlink():
                    continue
                scanned += 1
                try:
                    if not info_path.is_file() or info_path.stat().st_size > 65536:
                        continue
                    raw = info_path.read_bytes()
                    if len(raw) < 24:
                        continue
                    version, original_size, deleted_filetime = struct.unpack_from("<QQQ", raw, 0)
                    if version == 1:
                        path_offset = 24
                        original_path = raw[path_offset:].decode("utf-16le", errors="ignore").split("\x00", 1)[0]
                    elif version == 2 and len(raw) >= 28:
                        char_count = struct.unpack_from("<I", raw, 24)[0]
                        if char_count < 1 or char_count > 32760:
                            continue
                        path_offset = 28
                        original_path = raw[path_offset:path_offset + char_count * 2].decode("utf-16le", errors="ignore")
                    else:
                        continue
                    if not original_path:
                        continue
                    original_name = Path(original_path).name[:180]
                    extension = Path(original_name).suffix.casefold()
                    if extension not in interesting_extensions:
                        continue
                    lower_path = original_path.casefold()
                    matched = [term for term in suspicious_terms if term in lower_path]
                    game_context = "FiveM/GTA V" if any(term in lower_path for term in fivem_terms) else None
                    recycle_payload = sid_dir / ("$R" + info_path.name[2:])
                    try:
                        payload_present = recycle_payload.is_file()
                    except OSError:
                        payload_present = False
                    try:
                        deleted_at = datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp() + deleted_filetime / 10_000_000
                        deleted_at_iso = datetime.fromtimestamp(deleted_at, tz=timezone.utc).isoformat(timespec="seconds")
                    except (OverflowError, OSError, ValueError):
                        deleted_at_iso = None
                    # Keep only security-relevant metadata; do not report the original full path.
                    folder_hint = "FiveM/GTA V" if game_context else (
                        "Downloads" if "\\downloads\\" in lower_path else
                        "Desktop" if "\\desktop\\" in lower_path else "Other"
                    )
                    findings.append({
                        "file_name": original_name,
                        "file_path": f"Recycle Bin metadata / {folder_hint}",
                        "source": "Windows Recycle Bin ($I metadata)",
                        "kind": "deleted_file_metadata",
                        "deleted_at": deleted_at_iso,
                        "original_size": int(original_size),
                        "extension": extension,
                        "recycle_payload_present": payload_present,
                        "game_context": [game_context] if game_context else [],
                        "indicator_matches": matched,
                        "indicator_category": "مؤشرات اسمية تحتاج مراجعة" if matched else "ملف محذوف — بيانات وصفية فقط",
                        "assessment": "review" if matched or game_context else "metadata_only",
                        "evidence_confidence": "medium" if payload_present else "low",
                        "evidence_reason": "سجل $I في سلة المحذوفات يثبت وجود إدخال حذف؛ وجود ملف $R يعني أن محتوى الملف ما زال في السلة، وليس أنه خبيث.",
                        "signature_status": "not_checked",
                        "signature_label": "لم يتم التحقق من توقيع الملف المحذوف",
                    })
                except (OSError, PermissionError, UnicodeError, struct.error, ValueError):
                    continue
                if scanned % 100 == 0:
                    progress(68, f"فحص بيانات سلة المحذوفات... {scanned:,}")
    progress(68, f"اكتمل فحص بيانات سلة المحذوفات: {len(findings):,} عنصر")
    return findings


def collect_recent_apps(processes, progress):
    """Show apps started in the last 24h plus recent Windows Prefetch metadata."""
    import time

    cutoff = time.time() - 24 * 60 * 60
    recent = []
    seen = set()
    for proc in processes:
        try:
            started = datetime.fromisoformat(str(proc.get("process_started_at") or "").replace("Z", "+00:00"))
            started_recently = started.timestamp() >= cutoff
        except (ValueError, TypeError, OSError):
            started_recently = False
        # Include every process still running now; mark whether it started in the last 24 hours.
        key = (proc.get("pid"), proc.get("executable_path"))
        if key in seen:
            continue
        seen.add(key)
        recent.append({
            "app_name": proc.get("process_name") or proc.get("file_name") or "Unknown",
            "file_name": proc.get("file_name") or "Unknown",
            "path": proc.get("executable_path") or "غير متاح",
            "last_seen_at": proc.get("process_started_at"),
            "last_seen_display": proc.get("process_started_at"),
            "evidence_source": "عملية تعمل حاليًا — وقت بدء العملية",
            "time_accuracy": "exact_process_start",
            "started_within_24h": started_recently,
            "activity_window": "آخر 24 ساعة" if started_recently else "تعمل الآن — بدأت قبل آخر 24 ساعة",
            "indicator_matches": proc.get("indicator_matches", []),
            "indicator_category": proc.get("indicator_category", "لا توجد مطابقة اسمية"),
            "signature_status": proc.get("signature_status", "not_checked"),
            "signature_label": proc.get("signature_label", "لم يتم التحقق")
        })

    prefetch_roots = [r"C:\Windows\Prefetch"]
    for root in prefetch_roots:
        if not os.path.isdir(root):
            continue
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if not entry.is_file(follow_symlinks=False) or not entry.name.casefold().endswith(".pf"):
                        continue
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if st.st_mtime < cutoff:
                            continue
                        app_name = entry.name.split("-", 1)[0].removesuffix(".pf")
                        key = ("prefetch", entry.name.casefold())
                        if key in seen:
                            continue
                        seen.add(key)
                        local = datetime.fromtimestamp(st.st_mtime).astimezone()
                        prefetch_matches = find_indicator_matches(app_name, entry.name)
                        prefetch_category = "مؤشرات حركة" if any(term in prefetch_matches for term in ("ad movement", "filter key", "scod", "cr-fastrun")) else ("مؤشرات هاك/غش" if prefetch_matches else "لا توجد مطابقة اسمية")
                        recent.append({
                            "app_name": app_name, "file_name": entry.name,
                            "path": entry.path, "last_seen_at": utc_timestamp(st.st_mtime),
                            "last_seen_display": local.strftime("%B %d, %Y %I:%M:%S %p"),
                            "evidence_source": "Windows Prefetch (.pf) — قرينة تشغيل تقريبية",
                            "time_accuracy": "approximate_prefetch_timestamp",
                            "indicator_matches": prefetch_matches,
                            "indicator_category": prefetch_category,
                            "signature_status": "not_checked",
                            "signature_label": "بيانات سجل تشغيل، لا ينطبق عليها توقيع ملف التطبيق"
                        })
                    except OSError:
                        continue
        except OSError:
            pass
    recent.sort(key=lambda row: row.get("last_seen_at") or "", reverse=True)
    progress(90, f"اكتمل تجميع التطبيقات الحالية وسجل آخر 24 ساعة: {len(recent)}")
    return recent


def verify_authenticode_signatures(processes, artifacts, progress, max_checks=400):
    """Verify Windows Authenticode signatures in batches; unsigned/invalid files are unverified."""
    if platform.system().lower() != "windows":
        for row in list(processes) + list(artifacts):
            if row.get("signature_status") == "pending":
                row["signature_status"] = "not_checked"
                row["signature_label"] = "لم يتم التحقق — يلزم Windows"
        return

    path_rows = {}
    for row in list(processes) + list(artifacts):
        path = row.get("executable_path") or row.get("path")
        if not path or not os.path.isfile(path):
            continue
        if os.path.splitext(path)[1].casefold() not in {".exe", ".dll"}:
            continue
        if row.get("signature_status") == "pending" or "executable_path" in row:
            path_rows.setdefault(os.path.normcase(os.path.abspath(path)), []).append(row)
    paths = list(path_rows.keys())
    check_paths = paths[:max_checks]
    for path in paths[max_checks:]:
        for row in path_rows[path]:
            row["signature_status"] = "not_checked"
            row["signature_label"] = "لم يتم التحقق — تجاوز حد الأداء"

    if not check_paths:
        return

    import subprocess
    script = r"""
$ErrorActionPreference = 'Continue'
$utf8 = New-Object System.Text.UTF8Encoding
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$raw = [Console]::In.ReadToEnd()
$paths = @($raw | ConvertFrom-Json)
$results = @()
foreach ($p in $paths) {
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath ([string]$p)
    $publisher = ''
    $thumb = ''
    if ($sig.SignerCertificate) {
      $publisher = [string]$sig.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
      $thumb = [string]$sig.SignerCertificate.Thumbprint
    }
    $results += [pscustomobject]@{ path=[string]$p; status=[string]$sig.Status; publisher=$publisher; thumbprint=$thumb }
  } catch {
    $results += [pscustomobject]@{ path=[string]$p; status='Error'; publisher=''; thumbprint='' }
  }
}
ConvertTo-Json -InputObject @($results) -Compress -Depth 4
"""
    executable = "powershell.exe"
    checked = 0
    for offset in range(0, len(check_paths), 100):
        batch = check_paths[offset:offset + 100]
        try:
            result = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                input=json.dumps(batch), capture_output=True, text=True, timeout=35,
                encoding="utf-8", errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            if result.returncode != 0 or not result.stdout.strip():
                raise RuntimeError("PowerShell signature verification returned no result")
            parsed = json.loads(result.stdout.strip())
            if isinstance(parsed, dict):
                parsed = [parsed]
            by_path = {os.path.normcase(os.path.abspath(item.get("path", ""))): item for item in parsed if isinstance(item, dict)}
            for path in batch:
                item = by_path.get(path)
                rows_for_path = path_rows.get(path, [])
                if item and str(item.get("status", "")).casefold() == "valid":
                    label = "موثق رقمياً — " + (str(item.get("publisher") or "ناشر معتمد من Windows")[:160])
                    status = "verified"
                else:
                    label = "غير موثق — توقيع مفقود أو غير صالح"
                    status = "unverified"
                for row in rows_for_path:
                    row["signature_status"] = status
                    row["signature_label"] = label
                    row["signature_publisher"] = str(item.get("publisher") or "")[:160] if item else ""
                    row["signature_thumbprint"] = str(item.get("thumbprint") or "")[:80] if item else ""
            checked += len(batch)
            progress(65 + int(checked * 20 / max(len(check_paths), 1)), f"التحقق من مصدر البرامج... {checked}/{len(check_paths)}")
        except Exception:
            for path in batch:
                for row in path_rows.get(path, []):
                    row["signature_status"] = "not_checked"
                    row["signature_label"] = "تعذر التحقق من التوقيع"
    # Non-PE files and folders cannot be validated with Authenticode.
    for row in artifacts:
        if row.get("signature_status") == "pending":
            row["signature_status"] = "not_applicable"
            row["signature_label"] = "غير موثق — لا يوجد توقيع Authenticode لهذا النوع"


def collect_processes(progress):
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError("Missing dependency: install requirements with: pip install -r requirements.txt") from exc
    rows = []
    processes = list(psutil.process_iter(["pid", "name", "exe", "create_time"]))
    total = max(len(processes), 1)
    cutoff = datetime.now(timezone.utc).timestamp() - 24 * 60 * 60
    for i, proc in enumerate(processes, 1):
        try:
            info = proc.info
            name = str(info.get("name") or "Unknown")[:180]
            exe = str(info.get("exe") or "")[:1000]
            matches = find_indicator_matches(name, exe)
            exists = bool(exe and os.path.isfile(exe))
            digest = sha256_file(exe) if exists and matches else None
            file_created = file_modified = None
            if exists:
                try:
                    stat = os.stat(exe)
                    file_created = utc_timestamp(stat.st_ctime)
                    file_modified = utc_timestamp(stat.st_mtime)
                except OSError:
                    pass
            started_at = utc_timestamp(info.get("create_time"))
            try:
                started_recently = bool(info.get("create_time") and float(info["create_time"]) >= cutoff)
            except (TypeError, ValueError):
                started_recently = False
            rows.append({
                "pid": info.get("pid"), "process_name": name,
                "file_name": os.path.basename(exe) if exe else name,
                "executable_path": exe or None, "process_started_at": started_at,
                "started_within_24h": started_recently,
                "file_created_at": file_created, "file_modified_at": file_modified,
                "sha256": digest, "indicator_matches": matches,
                "indicator_category": "مؤشرات حركة" if any(term in matches for term in ("ad movement", "filter key", "scod", "cr-fastrun")) else ("مؤشرات هاك/غش" if matches else "لا توجد مطابقة اسمية"),
                "game_context": classify_game_context(name, exe),
                "signature_status": "pending" if exists and os.path.splitext(exe)[1].casefold() in {".exe", ".dll"} else "not_checked",
                "signature_label": "جارٍ التحقق" if exists and os.path.splitext(exe)[1].casefold() in {".exe", ".dll"} else "غير قابل للتحقق",
                "assessment": "review" if matches else "no_name_match",
            })
        except (psutil.Error, OSError):
            continue
        progress(int(i * 25 / total), f"جمع بيانات العمليات {i}/{total}")
    return rows


class InspectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("3EN Inspect Team")
        self.geometry("1080x790")
        try:
            icon_path = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "3en.ico")
            self.iconbitmap(icon_path)
        except Exception:
            pass
        self.minsize(900, 680)
        self.configure(bg="#090a10")
        self.report = None
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor="#20212c", background="#ff304f", bordercolor="#20212c")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=9)
        self._build()

    def _build(self):
        BG = "#080a10"
        PANEL = "#111521"
        PANEL_ALT = "#171c2a"
        RED = "#ff365c"
        RED_DARK = "#351521"
        MUTED = "#98a3b8"
        WHITE = "#f4f6fc"
        LINE = "#2b3244"
        GREEN = "#62e0b0"
        AMBER = "#ffbd69"

        self.configure(bg=BG)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor="#22283a", background=RED,
                        bordercolor="#22283a", lightcolor=RED, darkcolor=RED, thickness=11)
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=(16, 11),
                        background=PANEL_ALT, foreground=WHITE, bordercolor=LINE, relief="flat")
        style.map("TButton", background=[("active", "#3b2030"), ("disabled", "#171923")],
                  foreground=[("active", "white"), ("disabled", "#74798a")])

        # Hero header
        header = tk.Frame(self, bg=PANEL, padx=24, pady=19,
                          highlightbackground=LINE, highlightthickness=1)
        header.pack(fill="x", padx=16, pady=(16, 0))
        hero = tk.Frame(header, bg=PANEL)
        hero.pack(fill="x")
        logo = tk.Frame(hero, bg="#250812", padx=15, pady=10,
                        highlightbackground=RED, highlightthickness=2)
        logo.pack(side="left", padx=(0, 16))
        emblem = tk.Canvas(logo, width=112, height=54, bg="#250812",
                           highlightthickness=0, bd=0)
        emblem.pack()
        emblem.create_arc(7, 2, 48, 42, start=200, extent=140,
                          style="arc", outline="#ff4968", width=3)
        emblem.create_arc(7, 2, 48, 42, start=20, extent=140,
                          style="arc", outline="#ff4968", width=3)
        emblem.create_oval(20, 9, 35, 34, outline="#ff4968", width=2)
        emblem.create_oval(25, 12, 31, 31, fill="#ff365c", outline="")
        emblem.create_oval(27, 15, 29, 27, fill="#090a10", outline="")
        emblem.create_text(78, 25, text="3EN", fill="#ffffff",
                           font=("Segoe UI", 22, "bold"))
        tk.Label(logo, text="INSPECT TEAM", bg="#250812", fg="#ff4968",
                 font=("Segoe UI", 8, "bold")).pack()
        brand = tk.Frame(hero, bg=PANEL)
        brand.pack(side="left", fill="x", expand=True)
        tk.Label(brand, text="3EN  /  INSPECT TEAM", bg=PANEL, fg=WHITE,
                 font=("Segoe UI", 21, "bold")).pack(anchor="w")
        tk.Label(brand, text="CYBERSECURITY  •  DEVICE INSPECTION", bg=PANEL,
                 fg=RED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 0))
        tk.Label(brand, text="فحص واضح للعمليات والملفات التنفيذية — بموافقتك فقط",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 0))
        self.session_badge = tk.Label(hero, text="●  جاهز للفحص", bg="#142b28", fg=GREEN,
                                      font=("Segoe UI", 9, "bold"), padx=14, pady=9)
        self.session_badge.pack(side="right", anchor="center")

        body = tk.Frame(self, bg=BG, padx=24, pady=19)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        heading = tk.Frame(body, bg=BG)
        heading.pack(fill="x", pady=(0, 14))
        tk.Label(heading, text="فحص أمان الجهاز", bg=BG, fg=WHITE,
                 font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(heading, text="وافق على الفحص ثم ابدأ — ستظهر حالة التقدم هنا.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))

        # Keep metric variables for report processing without displaying extra cards.
        self.metric_processes = tk.StringVar(value="—")
        self.metric_flags = tk.StringVar(value="—")
        self.metric_state = tk.StringVar(value="READY")

        # Consent block
        consent_box = tk.Frame(body, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=17, pady=12)
        consent_box.pack(fill="x", pady=(0, 12))
        tk.Label(consent_box, text="01  /  الموافقة والصلاحية", bg=PANEL, fg="#ff8ca0",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.consent_processes = tk.BooleanVar(value=False)
        self.consent_files = tk.BooleanVar(value=False)
        self.consent_screenshot = tk.BooleanVar(value=False)
        tk.Checkbutton(consent_box,
            text="أوافق على الخيار الأول: مراجعة بيانات العمليات والتطبيقات التي استُخدمت خلال آخر 24 ساعة، مثل الاسم والمسار ووقت التشغيل ومؤشرات المطابقة.",
            variable=self.consent_processes, bg=PANEL, fg=WHITE, selectcolor=PANEL_ALT,
            activebackground=PANEL, activeforeground=WHITE, wraplength=900,
            font=("Segoe UI", 10), relief="flat", padx=0).pack(anchor="w", pady=(7, 0))
        tk.Checkbutton(consent_box,
            text="أوافق على الخيار الثاني: فحص بيانات الملفات في C: وD: والتحقق من التوقيعات الرقمية، وفحص سجلات FiveM/CitizenFX النصية المحددة بحثًا عن مؤشرات معروفة. يُرسل تقرير البيانات الوصفية ومواقع/أرقام أسطر المؤشرات فقط؛ لا يُرسل نص السجلات أو محتويات الملفات.",
            variable=self.consent_files, bg=PANEL, fg=WHITE, selectcolor=PANEL_ALT,
            activebackground=PANEL, activeforeground=WHITE, wraplength=900,
            font=("Segoe UI", 10), relief="flat", padx=0).pack(anchor="w", pady=(7, 0))
        tk.Checkbutton(consent_box,
            text="اختياري — أوافق صراحةً على التقاط صورة كاملة لكل شاشات سطح المكتب عند إرسال التقرير، وإرفاقها بلوحة التحكم ثم برسالة الديسكورد مع التقرير. لن تظهر معاينة، وستُحفظ الصورة ضمن التقرير حتى يرسلها المراجع. قد تتضمن الصورة نوافذ أو رسائل أو معلومات ظاهرة على الشاشة.",
            variable=self.consent_screenshot, bg=PANEL, fg=WHITE, selectcolor=PANEL_ALT,
            activebackground=PANEL, activeforeground=WHITE, wraplength=900,
            font=("Segoe UI", 10), relief="flat", padx=0).pack(anchor="w", pady=(7, 0))



        # Progress and controls
        scanbox = tk.Frame(body, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=17, pady=13)
        scanbox.pack(fill="x", pady=(0, 12))
        topstatus = tk.Frame(scanbox, bg=PANEL)
        topstatus.pack(fill="x")
        tk.Label(topstatus, text="02  /  تقدم الفحص", bg=PANEL, fg=WHITE,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        self.status = tk.StringVar(value="جاهز — وافق على الفحص ثم ابدأ.")
        tk.Label(topstatus, textvariable=self.status, bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="right")
        progress_row = tk.Frame(scanbox, bg=PANEL)
        progress_row.pack(fill="x", pady=(12, 0))
        self.progress = ttk.Progressbar(progress_row, maximum=100, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True)
        self.progress_percent = tk.Label(progress_row, text="0%", bg=PANEL, fg=RED,
                                          font=("Segoe UI", 11, "bold"), width=5)
        self.progress_percent.pack(side="right", padx=(12, 0))
        tk.Label(scanbox, text="LIVE SCAN PROGRESS  /  3EN SECURITY ENGINE",
                 bg=PANEL, fg="#69758c", font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(8, 0))

        controls = tk.Frame(body, bg=BG)
        controls.pack(fill="x", pady=(0, 12))
        self.start_button = ttk.Button(controls, text="▶   بدء الفحص", command=self.start)
        self.start_button.pack(side="left", padx=(0, 9))
        tk.Label(controls, text="يُرسل التقرير تلقائيًا بعد الفحص؛ التصنيف النهائي من لوحة التحكم.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=5)

        tk.Label(self, text="3eN INSPECT TEAM    •    by ROITH    •    فحص ظاهر وبموافقة المستخدم",
                 bg="#0d1018", fg="#7e899f", font=("Segoe UI", 8, "bold"), pady=9).pack(fill="x")
    def update_progress(self, value, text):
        def paint():
            value = max(0, min(100, int(value)))
            self.progress.configure(value=value)
            self.progress_percent.configure(text=f"{value}%")
            self.status.set(text)
        self.after(0, paint)

    def _close_then_offer_folder(self):
        # Close the UI without launching a second process or changing user files.
        self.destroy()
    def start(self):
        # The dashboard enforces one-time session use; the client does not
        # create local completion files or persist session state on the device.
        if not (self.consent_processes.get() and self.consent_files.get()):
            messagebox.showwarning(APP, "يجب الموافقة على الخيارين قبل بدء الفحص.")
            return

        # Session-specific builds contain the session code and dashboard URL.
        # Never prompt the scanned person to enter either value.
        self.active_session_code = str(SESSION_CODE or "").strip().upper()
        self.active_dashboard_url = str(DASHBOARD_URL or "").strip().rstrip("/")
        if not self.active_session_code or not self.active_dashboard_url.startswith("https://"):
            messagebox.showerror(APP, "هذا الملف غير مرتبط بجلسة فحص. اطلب من المسؤول إنشاء جلسة وتنزيل ملفها المخصص.")
            return
        self.metric_state.set("SCANNING")
        self.session_badge.configure(text="●  الفحص جارٍ", bg="#332616", fg="#ffbd69")
        self.start_button.configure(state="disabled")
        self.metric_processes.set("…")
        self.metric_flags.set("…")
        self.status.set("Inspection running…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            processes = collect_processes(self.update_progress)
            files = collect_files(self.update_progress)
            fivem_files = collect_fivem_artifacts(self.update_progress)
            fivem_log_findings = collect_fivem_log_evidence(self.update_progress)
            deleted_file_findings = collect_deleted_file_evidence(self.update_progress)
            # Keep targeted game evidence, log indicators, and deleted-file metadata in the unified inventory.
            for item in fivem_files:
                item.setdefault("source", "FiveM/GTA V targeted locations")
            files.extend(fivem_files)
            files.extend(fivem_log_findings)
            files.extend(deleted_file_findings)
            verify_authenticode_signatures(processes, files, self.update_progress)
            recent_apps = collect_recent_apps(processes, self.update_progress)
            matches = [p for p in processes if p["indicator_matches"]]
            file_matches = [item for item in files if item["indicator_matches"]]
            fivem_matches = [item for item in fivem_files if item["indicator_matches"]]
            self.report = {
                "product": APP,
                "signature": "3eN INSPECT TEAM",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "device_label": platform.node()[:100] or "Unknown",
                "platform": platform.platform()[:200],
                "scan_scope": "Bounded metadata inventory of C: and D: (up to 15,000 items or 75 seconds), excluding Windows/system folders; plus targeted FiveM/GTA V install, CitizenFX, and user Documents locations (up to 8,000 items or 35 seconds; EXE/DLL/ASI/LUA/LUAC/JSON/CFG/INI/LOG/DAT/BIN/ZIP/RAR/7Z/RPF/META/XML); selected FiveM/CitizenFX text logs are scanned with strict file/byte/time limits and only marker names and line numbers are reported, never log contents; Windows Recycle Bin $I metadata is checked on C: and D: for selected executable/script/config/archive file types, without reading or restoring deleted file contents; all currently running processes plus Windows Prefetch evidence from the last 24 hours; Authenticode verification for EXE/DLL; metadata only, archives are not opened, and file contents are never uploaded",
                "process_count": len(processes),
                "indicator_match_count": len(matches),
                "file_count": len(files),
                "file_artifact_count": len(files),
                "file_indicator_match_count": len(file_matches),
                "fivem_artifact_count": len(fivem_files),
                "fivem_indicator_match_count": len(fivem_matches) + sum(1 for item in fivem_log_findings if item.get("indicator_matches")),
                "fivem_log_files_with_indicators": len(fivem_log_findings),
                "fivem_log_line_matches": sum(item.get("matched_line_count", 0) for item in fivem_log_findings),
                "deleted_file_evidence_count": len(deleted_file_findings),
                "deleted_suspicious_file_count": sum(1 for item in deleted_file_findings if item.get("indicator_matches")),
                "deleted_fivem_file_count": sum(1 for item in deleted_file_findings if item.get("game_context")),
                "file_artifacts": files,
                "recent_apps_24h": recent_apps,
                "recent_apps_24h_count": len(recent_apps),
                "signature_verified_count": sum(1 for row in list(processes) + list(files) if row.get("signature_status") == "verified"),
                "signature_unverified_count": sum(1 for row in list(processes) + list(files) if row.get("signature_status") == "unverified"),
                "game_process_context": sorted({game for proc in processes for game in proc.get("game_context", [])}),
                "note": "Configured names and paths are indicators for manual review, not proof of cheating. The report includes a bounded general inventory plus a targeted metadata inventory of common FiveM/GTA V and CitizenFX locations and relevant file extensions. Selected FiveM/CitizenFX text logs are checked locally for specific known tool markers; only marker names and line numbers are retained, never log text. Windows Recycle Bin metadata is also checked for selected security-relevant file types; only filename, approximate deletion time, size, and a coarse folder category are retained, not the original full path or deleted contents. This does not detect every permanently deleted file and does not perform recovery. The recent activity section includes every process still running at scan time, marks processes started within the last 24 hours, and adds Windows Prefetch execution evidence from the last 24 hours where available; Prefetch timestamps are approximate and may be unavailable if disabled. File timestamps show last modification, not last execution; archives are not opened; only selected FiveM/CitizenFX text logs are read locally for specific known markers, and their text is never uploaded; file contents are never uploaded. Valid Authenticode signatures identify a verified publisher but do not prove a program is harmless. Coverage is bounded by time and item limits and cannot guarantee detection of every cheat. Dates are retained in UTC and local display format. A full-desktop screenshot is captured and retained with the report only when the separate screenshot-consent option is selected; otherwise no screenshot is taken. No files are modified and no processes are terminated.",
                "processes": processes,
            }
            self.update_progress(100, "اكتمل الفحص وتجهيز التقرير.")
            self.delivery_status = "pending"
            self.after(0, self._show_report)
        except Exception as exc:
            self.after(0, lambda: (messagebox.showerror(APP, str(exc)), self.start_button.configure(state="normal"), self.session_badge.configure(text="●  تعذر إكمال الفحص", bg="#351521", fg="#ff8093")))
            self.update_progress(0, "Scan failed. Check dependencies and permissions.")

    def _show_report(self):
        self.metric_processes.set(str(self.report["process_count"]))
        self.metric_flags.set(str(self.report["indicator_match_count"]))
        delivery = getattr(self, "delivery_status", "not_configured")
        self.start_button.configure(state="normal")
        if delivery == "sent":
            self.metric_state.set("SENT")
            self.session_badge.configure(text="●  اكتمل وأُرسل", bg="#142b28", fg="#62e0b0")
            self.status.set("اكتمل الفحص وتم إرسال التقرير إلى لوحة التحكم.")
        elif delivery.startswith("failed:"):
            self.metric_state.set("REVIEW")
            self.session_badge.configure(text="●  تعذر الإرسال", bg="#351521", fg="#ff8093")
            self.status.set("اكتمل الفحص، لكن تعذر إرسال التقرير. تحقق من الاتصال والجلسة.")
        else:
            self.metric_state.set("COMPLETE")
            self.session_badge.configure(text="●  بانتظار الإرسال", bg="#332616", fg="#ffbd69")
            self.status.set("اكتمل الفحص. جارٍ إرسال التقرير تلقائيًا إلى لوحة التحكم…")
            self.after(150, lambda: self.send_report(auto=True))

    def send_report(self, auto=False):
        if not self.report:
            messagebox.showwarning(APP, "ابدأ الفحص أولًا.")
            return
        # Keep the initial status as review; the reviewer makes the final decision in the dashboard.
        self.report["review_label"] = "review"
        self.report["review_label_ar"] = "بانتظار تصنيف المراجع في لوحة التحكم"
        self.status.set("جارٍ إرسال التقرير بعد موافقتك…")
        try:
            import urllib.request
            endpoint = self.active_dashboard_url.rstrip("/") + "/api/v1/session-report"
            if self.consent_screenshot.get():
                self.status.set("جارٍ التقاط سطح المكتب بالكامل بعد موافقتك…")
                self.report["desktop_screenshot_base64"] = capture_desktop_screenshot_base64()
                self.report["desktop_screenshot_captured_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            else:
                self.report.pop("desktop_screenshot_base64", None)
                self.report.pop("desktop_screenshot_captured_at", None)
            payload = {"session_code": self.active_session_code,
                       "computer_label": self.report["device_label"],
                       "summary": f"{self.report['review_label_ar']} — {self.report['indicator_match_count']} مؤشرات عمليات و{self.report.get('file_indicator_match_count', 0)} مؤشرات ملفات للمراجعة",
                       "report": self.report}
            req = urllib.request.Request(endpoint, data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=90) as response:
                result = json.loads(response.read().decode("utf-8"))
            self.report["dashboard_report_id"] = result.get("report_id")
            self.delivery_status = "sent"
            self.metric_state.set("SENT")
            self.session_badge.configure(text="●  تم الإرسال", bg="#142b28", fg="#62e0b0")
            self.status.set("تم إرسال التقرير تلقائيًا إلى لوحة التحكم.")
            self.start_button.configure(state="disabled")
            self.after(1200, self._close_then_offer_folder)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read(1200).decode("utf-8", errors="replace").strip()
            except Exception:
                detail = ""
            self.delivery_status = "failed: HTTP " + str(exc.code)
            self.session_badge.configure(text="●  تعذر الإرسال", bg="#351521", fg="#ff8093")
            self.status.set("رفض الخادم التقرير (HTTP " + str(exc.code) + "). " + (detail[:180] if detail else "تحقق من صلاحية الجلسة وحجم التقرير."))
        except Exception as exc:
            self.delivery_status = "failed: " + type(exc).__name__
            self.session_badge.configure(text="●  تعذر الإرسال", bg="#351521", fg="#ff8093")
            self.status.set("تعذر الإرسال: " + type(exc).__name__ + ". تحقق من الاتصال ثم أعد المحاولة.")

    def export_pdf(self):
        if not self.report:
            messagebox.showinfo(APP, "ابدأ الفحص أولاً.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                    filetypes=[("PDF report", "*.pdf")], initialfile="3eN-inspection-report.pdf")
        if not path:
            return
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name="RedTitle", parent=styles["Title"], textColor=colors.HexColor("#d92345")))
            doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm)
            story = [Paragraph("3eN INSPECT TEAM", styles["RedTitle"]), Paragraph("Security inspection report - by:ROITH", styles["Normal"]), Spacer(1, 8*mm)]
            summary = [["Device", str(self.report["device_label"])], ["Created (UTC)", str(self.report["created_at"])], ["Platform", str(self.report["platform"])], ["Processes reviewed", str(self.report["process_count"])], ["Name-based leads", str(self.report["indicator_match_count"])]]
            table = Table(summary, colWidths=[42*mm, 120*mm])
            table.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#fbe7eb")),("TEXTCOLOR",(0,0),(0,-1),colors.HexColor("#86152b")),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#dddddd")),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),7)]))
            story.extend([table, Spacer(1, 7*mm), Paragraph("Review findings", styles["Heading2"])])
            findings = [p for p in self.report["processes"] if p["indicator_matches"]]
            if not findings:
                story.append(Paragraph("No configured process-name indicators matched. This does not guarantee the device is clean.", styles["BodyText"]))
            else:
                data = [["PID", "Process", "Indicators", "SHA-256"]]
                for item in findings:
                    data.append([str(item.get("pid") or ""), str(item["process_name"])[:50], ", ".join(item["indicator_matches"]), str(item.get("sha256") or "unavailable")[:64]])
                t = Table(data, repeatRows=1, colWidths=[14*mm, 42*mm, 40*mm, 66*mm])
                t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#25111a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#cccccc")),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),5)]))
                story.append(t)
            story.extend([Spacer(1, 7*mm), Paragraph("Important: name-based indicators are leads for manual review, not proof of cheating. Scope: running process metadata and readable executable SHA-256 only.", styles["Italic"])])
            doc.build(story)
            messagebox.showinfo(APP, "تم تصدير تقرير PDF بنجاح.")
        except Exception as exc:
            messagebox.showerror(APP, "PDF export failed: " + str(exc))



if __name__ == "__main__":
    # PyInstaller --windowed builds need an explicit GUI entry point.
    try:
        app = InspectorApp()
        app.mainloop()
    except Exception as exc:
        import traceback
        error_text = traceback.format_exc()
        try:
            log_root = os.environ.get("APPDATA") or os.path.expanduser("~")
            log_dir = os.path.join(log_root, "3eN Inspect Team")
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "launch-error.log")
            with open(log_path, "w", encoding="utf-8") as log_file:
                log_file.write(error_text)
        except OSError:
            log_path = "تعذر حفظ سجل الخطأ"
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(APP, f"تعذر تشغيل البرنامج:\n{type(exc).__name__}: {exc}\n\nسجل التفاصيل: {log_path}")
            root.destroy()
        except Exception:
            pass
