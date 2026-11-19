"""
3eN Inspect Team — transparent local inspection client.
Collects process metadata, 24-hour app activity, file metadata, and Windows Authenticode status.
A full-desktop screenshot is captured only after the single explicit inspection consent.
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
from datetime import datetime, timezone, timedelta
from pathlib import Path

APP = "3EN INSPECT"


SAUDI_TZ = timezone(timedelta(hours=3), "AST")


def format_saudi_time(value, language="ar"):
    """Display ISO/UTC timestamps in Saudi Arabia time (UTC+3), independent of PC locale."""
    if not value:
        return "Unavailable" if language == "en" else "غير متاح"
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        stamp = parsed.astimezone(SAUDI_TZ).strftime("%d/%m/%Y %I:%M:%S %p")
        suffix = "(Saudi Arabia time, UTC+3)" if language == "en" else "(توقيت السعودية UTC+3)"
        return stamp + " " + suffix
    except (TypeError, ValueError, OverflowError):
        return str(value)
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
    # Keep only distinctive cheat/tool identifiers. Generic words such as
    # hack, loader, launcher, injector, bypass and phantom create false positives.
    return (
        "eulen", "redengine", "red engine", "lynx", "lambda menu",
        "menyo", "tiago modz", "taigomodz", "falloutmenu", "cobramenu",
        "dopamine menu", "monstermenu", "fivesense_v2", "swoopiexyz",
        "kekhack", "nove store", "sleezy spoofer", "aura spoofer",
        "fivem mod menu", "fivem esp", "fivem wallhack",
        "extreme injector", "winject", "cheat engine", "cheatengine",
        "unknowncheats", "resource blocker", "rxexv3", "hjaldrgo",
        "zc-firerate", "zc-mp_f_freemode", "zc-explosiveammo",
        "zc-pedlight", "zc-electricammo", "zc-pedabilities",
        "zc-increasedrange", "zc-weaponmodifier", "zc-infiniteammo",
        "zc-damageboost", "zc-bulletpenetration", "no_recoil",
        "securityhealthservice.exe", "processhacker", "xenos", "winject",
        "aimware", "phantom menu", "lua executor", "lua injector",
        "remove_roll.rpf", "fast_playboi_mods", "bsk_skills",
        "quickenter.rpf", "cr-fastrun", "fivemock",
    )


INDICATOR_TERMS = build_indicator_terms()

BINARY_INDICATOR_LABELS = {
    "virtualallocex": ("تخصيص ذاكرة داخل عملية أخرى", "Remote-process memory allocation"),
    "writeprocessmemory": ("كتابة بيانات في ذاكرة عملية أخرى", "Writing to another process memory"),
    "readprocessmemory": ("قراءة بيانات من ذاكرة عملية أخرى", "Reading another process memory"),
    "createremotethread": ("إنشاء مسار تنفيذ داخل عملية أخرى", "Creating a thread in another process"),
    "ntcreatethreadex": ("إنشاء مسار تنفيذ منخفض المستوى داخل عملية أخرى", "Low-level remote thread creation"),
    "queueuserapc": ("جدولة إجراء داخل مسار تنفيذ آخر", "Queueing an APC in another thread"),
    "setwindowshookex": ("تثبيت خطاف لمراقبة أحداث Windows", "Installing a Windows event hook"),
    "openprocess": ("فتح مقبض لعملية أخرى", "Opening another process handle"),
}

def classify_fivem_indicator_categories(values):
    """Map observed strings to review categories; categories are leads, never proof of cheating."""
    text = " ".join(str(value or "").casefold() for value in (values or []))
    categories = []
    groups = [
        ("AIM_ASSIST", ("aimbot", "silent aim", "silentaim", "triggerbot", "aimware")),
        ("ESP_WALLHACK", ("wallhack", "fivem esp", " esp", "chams", "entity esp")),
        ("MOVEMENT_MANIPULATION", ("noclip", "no clip", "fly hack", "flyhack", "freecam", "free cam", "teleport", "speedhack", "speed hack", "superjump", "super jump")),
        ("WEAPON_MANIPULATION", ("magic bullet", "magicbullet", "no recoil", "norecoil", "rapid fire", "rapidfire", "firerate", "infiniteammo", "infinite ammo", "explosiveammo", "weapon modifier")),
        ("INJECTOR_OR_LOADER", ("injector", "xenos", "winject", "extreme injector", "lua executor", "lua injector", "processhacker")),
        ("CHEAT_MENU", ("eulen", "redengine", "red engine", "lynx", "lambda menu", "menyo", "tiago modz", "taigomodz", "falloutmenu", "cobramenu", "dopamine menu", "monstermenu", "fivesense_v2", "phantom menu")),
        ("SPOOFER_OR_BYPASS", ("spoofer", "bypass", "hwid")),
    ]
    for label, needles in groups:
        if any(needle in text for needle in needles):
            categories.append(label)
    return categories


def localized_indicator_labels(values, language="ar"):
    labels = []
    for value in values or []:
        pair = BINARY_INDICATOR_LABELS.get(str(value or "").casefold())
        if pair:
            labels.append(f"{pair[0]} ({value})" if language == "ar" else f"{pair[1]} ({value})")
        else:
            labels.append(str(value))
    return labels

def add_localized_indicator_fields(report, language="ar"):
    translations = {
        "ملفات FiveM وGTA V": "FiveM / GTA V files",
        "سجلات FiveM وCitizenFX": "FiveM / CitizenFX logs",
        "سكربتات وإعدادات FiveM": "FiveM scripts and settings",
        "آثار ملفات محذوفة": "Deleted-file traces",
        "ملفات برامج المستخدم": "User application files",
        "مؤشرات هاك/غش": "Cheat indicators",
        "مؤشرات اسمية تحتاج مراجعة": "Name-based indicators — review required",
        "ملف محذوف — بيانات وصفية فقط": "Deleted file — metadata only",
        "مؤشرات حركة": "Movement indicators",
        "لا توجد مطابقة اسمية": "No name match",
        "غير متاح": "Unavailable",
        "لم يتم التحقق": "Not checked",
        "لم يتم التحقق من توقيع الملف المحذوف": "Deleted file signature not checked",
        "جارٍ التحقق": "Verification pending",
        "الملف موجود": "File exists",
        "الملف غير موجود": "File missing",
        "الملف غير موجود في مساره؛ قد يكون محذوفًا أو منقولًا": "File is missing from its path; it may have been deleted or moved",
        "اسم مطابق في سجل سلة المحذوفات": "Filename match in Recycle Bin record",
        "Windows Recent folder (.lnk shortcut metadata)": "Windows Recent folder (.lnk shortcut metadata)",
        "سجل $I في سلة المحذوفات يثبت وجود إدخال حذف؛ وجود ملف $R يعني أن محتوى الملف ما زال في السلة، وليس أنه خبيث.": "A Recycle Bin $I record confirms a deletion entry; a matching $R item means the content remains in the bin, not that it is malicious.",
        "مطابقة اسمية/مسارية فقط؛ يلزم التحقق من الملف والسياق قبل أي استنتاج.": "Name/path match only; verify the file and context before drawing conclusions."
    }
    for collection_name in ("processes", "file_artifacts", "recent_apps_24h", "recent_files"):
        for row in report.get(collection_name, []) or []:
            row["indicator_matches_display"] = localized_indicator_labels(
                row.get("indicator_matches", []), language
            )
            if language == "en":
                for field in ("scan_group", "indicator_category", "evidence_reason", "signature_label", "evidence_source", "activity_window", "target_status_ar"):
                    value = row.get(field)
                    if isinstance(value, str):
                        for ar, en in translations.items():
                            value = value.replace(ar, en)
                        row[field] = value
            if row.get("binary_indicator_type"):
                if language == "en":
                    row["indicator_category"] = "Binary-file indicators — review required"
                    row["evidence_reason"] = (
                        "Several strings associated with process memory access or remote thread creation "
                        "were found in the binary. Legitimate software may use these APIs; this alone "
                        "does not prove cheating or malicious behavior."
                    ) if row.get("binary_indicator_type") == "multiple_process_memory_api_strings" else (
                        "A string associated with a known tool name was found in the binary. "
                        "It may be an embedded reference and does not prove execution or cheating."
                    )
                else:
                    row["indicator_category"] = "مؤشرات داخل ملف ثنائي — تحتاج مراجعة"
                    row["evidence_reason"] = (
                        "عُثر على عدة سلاسل API مرتبطة بقراءة/كتابة ذاكرة العمليات أو إنشاء خيوط؛ "
                        "قد تستخدمها برامج مشروعة أيضًا."
                    ) if row.get("binary_indicator_type") == "multiple_process_memory_api_strings" else (
                        "عُثر على اسم/سلسلة مرتبطة بأداة معروفة داخل الملف الثنائي؛ "
                        "قد تكون سلسلة مضمّنة أو مرجعًا ولا تثبت التشغيل أو الغش."
                    )
    report["interface_language"] = language
    return report


def is_windows_system_path(path):
    """Return True for Windows OS, component-store, driver and protected app paths."""
    value = os.path.abspath(str(path or "")).replace("/", "\\").casefold()
    markers = (
        "\\windows\\", "\\programdata\\microsoft\\",
        "\\system volume information\\", "\\$recycle.bin\\",
        "\\windowsapps\\", "\\driverstore\\", "\\winsxs\\", "\\servicing\\",
        "\\system32\\", "\\syswow64\\", "\\windows defender\\",
        "\\program files\\windowsapps\\", "\\program files (x86)\\windowsapps\\",
        "\\microsoft shared\\", "\\assembly\\",
    )
    return any(marker in value for marker in markers) or value.endswith("\\windows")


def is_inspector_self_path(path):
    """Exclude only this inspector's own executable/source bundle from its report."""
    if not path:
        return False
    try:
        candidate = os.path.normcase(os.path.abspath(str(path)))
        own_files = {
            os.path.normcase(os.path.abspath(sys.executable)),
            os.path.normcase(os.path.abspath(__file__)),
        }
        if candidate in own_files:
            return True
        if getattr(sys, "frozen", False):
            bundle_root = os.path.dirname(os.path.abspath(sys.executable))
            internal_root = os.path.join(bundle_root, "_internal")
            if os.path.isdir(internal_root) and os.path.commonpath([candidate, bundle_root]) == bundle_root:
                return True
            extraction_root = getattr(sys, "_MEIPASS", "")
            if extraction_root and os.path.commonpath([candidate, os.path.abspath(extraction_root)]) == os.path.abspath(extraction_root):
                return True
    except (OSError, ValueError):
        return False
    return False


def find_indicator_matches(name, path, indicators=None):
    indicators = indicators or INDICATOR_TERMS
    if is_windows_system_path(path):
        return []
    combined = (str(name or "") + " " + str(path or "")).casefold()
    matches = []
    for term in indicators:
        # Distinctive names must be complete tokens, not incidental substrings.
        pattern = r"(?<![a-z0-9])" + re.escape(term.casefold()) + r"(?![a-z0-9])"
        if re.search(pattern, combined):
            matches.append(term)
    return list(dict.fromkeys(matches))


def finalize_evidence_quality(processes, artifacts, recent_apps, recent_files):
    """Normalize evidence, hide OS paths, and calculate conservative explainable triage scores."""
    # Never expose Windows OS binaries as user file/process findings.
    processes[:] = [
        row for row in processes
        if not is_windows_system_path(row.get("executable_path"))
    ]
    artifacts[:] = [
        row for row in artifacts
        if not is_windows_system_path(row.get("path"))
    ]
    recent_files[:] = [
        row for row in recent_files
        if not is_windows_system_path(row.get("target_path"))
    ]

    def score(row):
        matches = list(dict.fromkeys(
            str(x).strip().casefold() for x in row.get("indicator_matches", []) if str(x).strip()
        ))
        row["indicator_matches"] = matches
        if not matches:
            row["triage_score"] = 0
            row["triage_level"] = "none"
            row["evidence_confidence"] = "none"
            return
        kind = str(row.get("artifact_type") or "")
        binary_type = row.get("binary_indicator_type")
        if binary_type == "known_tool_string":
            value, confidence = 65, "medium"
        elif binary_type == "multiple_process_memory_api_strings":
            value, confidence = 25, "low"
        elif "log" in kind.casefold():
            value, confidence = 15, "low"
        elif "script" in kind.casefold() or "resource" in kind.casefold():
            value, confidence = (45, "medium") if len(matches) >= 2 else (25, "low")
        elif row.get("kind") == "deleted_file_metadata":
            value, confidence = 10, "low"
        else:
            value, confidence = 20, "low"
        row["triage_score"] = value
        row["triage_level"] = "high" if value >= 65 else ("medium" if value >= 35 else "low")
        row["evidence_confidence"] = row.get("evidence_confidence") or confidence
        row["evidence_reason"] = row.get("evidence_reason") or (
            "مطابقة اسمية/مسارية فقط؛ يلزم التحقق من الملف والسياق قبل أي استنتاج."
        )

    for row in processes:
        score(row)
    for row in artifacts:
        score(row)

    # Raise confidence only when the same exact file is corroborated by
    # independent evidence collectors (for example, process + inventory + binary).
    corroboration = {}
    for row in processes + artifacts:
        if not row.get("indicator_matches"):
            continue
        raw_path = row.get("executable_path") or row.get("path")
        if raw_path and os.path.isabs(str(raw_path)):
            key = os.path.normcase(os.path.abspath(str(raw_path)))
            corroboration.setdefault(key, set()).add(str(row.get("artifact_type") or row.get("source") or "evidence"))
    for row in processes + artifacts:
        raw_path = row.get("executable_path") or row.get("path")
        if not row.get("indicator_matches") or not raw_path or not os.path.isabs(str(raw_path)):
            continue
        key = os.path.normcase(os.path.abspath(str(raw_path)))
        if len(corroboration.get(key, set())) >= 2:
            row["triage_score"] = max(int(row.get("triage_score") or 0), 80)
            row["triage_level"] = "high"
            row["evidence_confidence"] = "high"
            row["evidence_reason"] = (str(row.get("evidence_reason") or "") +
                " وتوافقت معها قرينة مستقلة أخرى على الملف نفسه؛ يلزم تأكيد المفتش قبل التصنيف النهائي.")

    # Count unique paths, not every matched keyword or duplicate log line.
    unique_file_keys = set()
    unique_process_keys = set()
    for row in artifacts:
        if row.get("indicator_matches"):
            raw_path = row.get("path") or row.get("file_path") or row.get("file_name")
            key = os.path.normcase(os.path.abspath(str(raw_path))) if raw_path else None
            if key:
                unique_file_keys.add(key)
    for row in processes:
        if row.get("indicator_matches"):
            raw_path = row.get("executable_path") or row.get("file_name")
            key = os.path.normcase(os.path.abspath(str(raw_path))) if raw_path else None
            if key:
                unique_process_keys.add(key)
    return {
        "unique_indicator_file_count": len(unique_file_keys),
        "unique_indicator_process_count": len(unique_process_keys),
        "high_confidence_finding_count": sum(1 for row in processes + artifacts if row.get("triage_level") == "high"),
        "medium_confidence_finding_count": sum(1 for row in processes + artifacts if row.get("triage_level") == "medium"),
        "low_confidence_finding_count": sum(1 for row in processes + artifacts if row.get("triage_level") == "low"),
    }


def collect_files(progress, max_files=5000, max_scan_seconds=25):
    """Bounded inventory of user-facing app files only; Windows/system locations are never traversed."""
    import time

    home = Path.home()
    local = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
    roaming = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    program_files_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    # User folders plus common third-party application folders. Do not walk drive roots.
    roots = [
        home / "Downloads", home / "Desktop", home / "Documents",
        local / "Programs", roaming,
        program_files / "Google", program_files / "Epic Games",
        program_files / "Rockstar Games", program_files / "Steam",
        program_files_x86 / "Google", program_files_x86 / "Epic Games",
        program_files_x86 / "Rockstar Games", program_files_x86 / "Steam",
    ]
    allowed_extensions = {".exe", ".dll", ".zip", ".rar", ".7z"}
    excluded_dirs = {
        "windows", "system32", "syswow64", "winsxs", "servicing",
        "system volume information", "$recycle.bin", "perflogs", "recovery",
        "config.msi", "softwaredistribution", "windowsapps", "windows defender",
        "defender", "driverstore", "drivers", "installer", "package cache",
        "common files", "crashdumps", "cache", "caches", "code cache",
        "microsoft", "windows", "packages", "start menu", "application data",
        "gpuCache".casefold(), "temp", "tmp", "node_modules", ".git",
        "__pycache__", "cef", "browser",
    }
    excluded_path_markers = (
        "\\microsoft\\windows\\", "\\windows defender\\",
        "\\windowsapps\\", "\\system32\\", "\\syswow64\\",
        "\\winsxs\\", "\\driverstore\\", "\\programdata\\",
    )
    candidates, seen = [], set()
    started = time.monotonic()
    last_progress = started
    stopped_early = False

    for root in roots:
        if not root.is_dir():
            continue
        for current, dirs, names in os.walk(str(root), topdown=True, followlinks=False):
            now = time.monotonic()
            if len(candidates) >= max_files or now - started >= max_scan_seconds:
                stopped_early = True
                break
            current_lower = os.path.abspath(current).casefold()
            if any(marker in current_lower for marker in excluded_path_markers):
                dirs[:] = []
                continue
            dirs[:] = [
                d for d in dirs
                if d.casefold() not in excluded_dirs
                and not d.casefold().startswith(("windows.", "$"))
                and not os.path.islink(os.path.join(current, d))
            ]
            for name in names:
                extension = Path(name).suffix.casefold()
                if extension not in allowed_extensions:
                    continue
                path = os.path.join(current, name)
                if is_inspector_self_path(path):
                    continue
                path_lower = os.path.abspath(path).casefold()
                if any(marker in path_lower for marker in excluded_path_markers):
                    continue
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
            now = time.monotonic()
            if now - last_progress >= 2:
                pct = 25 + int(min((now - started) / max_scan_seconds, 1.0) * 15)
                progress(pct, f"فحص ملفات البرامج ومجلدات المستخدم فقط... {len(candidates):,} ملف")
                last_progress = now
            if stopped_early:
                break
        if stopped_early:
            break

    rows = []
    total = max(len(candidates), 1)
    for i, (path, st) in enumerate(candidates, 1):
        name = os.path.basename(path)
        matches = find_indicator_matches(name, path)
        too_large = st.st_size > 250 * 1024 * 1024
        created = utc_timestamp(st.st_ctime)
        modified = utc_timestamp(st.st_mtime)
        accessed = utc_timestamp(st.st_atime)
        try:
            modified_display = datetime.fromtimestamp(st.st_mtime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
            created_display = datetime.fromtimestamp(st.st_ctime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
            accessed_display = datetime.fromtimestamp(st.st_atime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
        except (ValueError, OSError, OverflowError):
            modified_display, created_display, accessed_display = modified, created, accessed
        digest = sha256_file(path) if matches and not too_large else None
        rows.append({
            "artifact_type": "User application file",
            "scan_group": "ملفات برامج المستخدم",
            "source": "User folders / selected third-party app locations",
            "file_name": name[:260], "path": path[:1500],
            "size_bytes": int(st.st_size), "created_at": created,
            "created_display": created_display, "accessed_at": accessed,
            "accessed_display": accessed_display, "modified_at": modified,
            "modified_display": modified_display, "sha256": digest,
            "hash_skipped_large_file": too_large,
            "indicator_matches": list(dict.fromkeys(matches)),
            "context_flags": ["User/application location"],
            "indicator_category": "مؤشرات هاك/غش" if matches else "لا توجد مطابقة اسمية",
            "assessment": "review" if matches else "metadata_only",
            "signature_status": "pending" if Path(name).suffix.casefold() in {".exe", ".dll"} else "not_checked",
            "signature_label": "جارٍ التحقق" if Path(name).suffix.casefold() in {".exe", ".dll"} else "لا ينطبق أو لم يتم التحقق"
        })
        if i % 100 == 0 or i == total:
            progress(40 + int(i * 15 / total), f"ترتيب ملفات البرامج... {i:,}/{total:,}")

    rows.sort(key=lambda row: row.get("accessed_at") or row.get("modified_at") or row.get("created_at") or "", reverse=True)
    if stopped_early:
        progress(55, f"اكتمل فحص ملفات المستخدم والبرامج ضمن الحدود: {len(rows):,} ملف")
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
        "$recycle.bin", "system volume information", "windows", "windows.old",
        "system32", "syswow64", "winsxs", "servicing", "driverstore",
        "windowsapps", "programdata", "node_modules", ".git", "__pycache__"
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
                if is_windows_system_path(path) or is_inspector_self_path(path):
                    continue
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
        accessed = utc_timestamp(st.st_atime)
        try:
            modified_display = datetime.fromtimestamp(st.st_mtime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
            created_display = datetime.fromtimestamp(st.st_ctime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
            accessed_display = datetime.fromtimestamp(st.st_atime).astimezone().strftime("%B %d, %Y %I:%M:%S %p")
        except (ValueError, OSError, OverflowError):
            modified_display, created_display, accessed_display = modified, created, accessed
        ext = Path(name).suffix.casefold()
        digest = sha256_file(path) if matches and not too_large else None
        rows.append({
            "artifact_type": "FiveM/GTA V file",
            "scan_group": "ملفات FiveM وGTA V",
            "source": "FiveM/GTA V targeted locations",
            "file_name": name[:260], "path": path[:1500],
            "size_bytes": int(st.st_size), "created_at": created,
            "created_display": created_display, "accessed_at": accessed,
            "accessed_display": accessed_display, "modified_at": modified,
            "modified_display": modified_display, "sha256": digest,
            "hash_skipped_large_file": too_large,
            "indicator_matches": matches,
            "fivem_indicator_categories": classify_fivem_indicator_categories(matches),
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
        "silent aim", "silentaim", "wallhack", "aimbot", "triggerbot", "fivem esp", "falloutmenu",
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
                    "scan_group": "سجلات FiveM وCitizenFX",
                    "source": "Targeted FiveM/CitizenFX text-log inspection",
                    "file_name": os.path.basename(path)[:260],
                    "path": path[:1500],
                    "size_bytes": int(st.st_size),
                    "modified_at": utc_timestamp(st.st_mtime),
                    "modified_display": local_time.strftime("%B %d, %Y %I:%M:%S %p"),
                    "indicator_matches": sorted(matched_lines.keys()),
                    "fivem_indicator_categories": classify_fivem_indicator_categories(matched_lines.keys()),
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



def collect_fivem_script_evidence(progress, max_files=1000, max_file_bytes=512_000,
                                  max_total_bytes=24_000_000, max_scan_seconds=20):
    """Locally inspect bounded FiveM resource/config text files; retain indicators and line numbers only."""
    import time

    local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    roaming = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    roots = [
        local / "FiveM" / "FiveM.app",
        roaming / "CitizenFX",
        Path.home() / "Documents" / "Rockstar Games" / "GTA V",
    ]
    text_extensions = {".lua", ".js", ".json", ".cfg", ".ini", ".xml", ".meta", ".txt"}
    excluded_dirs = {
        "cache", "server-cache", "server-cache-priv", "crashes", "screenshots",
        "logs", "node_modules", ".git", "__pycache__", "browser", "cef",
    }
    known_tool_markers = (
        "eulen", "redengine", "red engine", "lynx", "lambda menu", "menyo",
        "tiago modz", "taigomodz", "swoopiexyz", "xenos", "extreme injector",
        "phantom menu", "lua executor", "lua injector", "cheat engine",
        "falloutmenu", "cobramenu", "dopamine menu", "monstermenu", "fivesense_v2",
    )
    behavior_markers = (
        "aimbot", "silentaim", "silent aim", "wallhack", "triggerbot",
        "magicbullet", "magic bullet", "norecoil", "no recoil", "freecam", "free cam",
        "godmode", "god mode", "noclip", "no clip", "flyhack", "fly hack",
        "teleport", "speedhack", "speed hack", "superjump", "super jump",
        "rapidfire", "rapid fire", "vehicle godmode", "weapon modifier",
    )
    started = time.monotonic()
    candidates, seen = [], set()
    for root in roots:
        if not root.is_dir():
            continue
        for current, dirs, names in os.walk(str(root), topdown=True, followlinks=False):
            if time.monotonic() - started >= max_scan_seconds or len(candidates) >= max_files:
                break
            dirs[:] = [
                d for d in dirs
                if d.casefold() not in excluded_dirs
                and not os.path.islink(os.path.join(current, d))
            ]
            for name in names:
                if Path(name).suffix.casefold() not in text_extensions:
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

    findings, bytes_read = [], 0
    for index, (path, st) in enumerate(candidates, 1):
        if time.monotonic() - started >= max_scan_seconds or bytes_read >= max_total_bytes:
            break
        limit = min(max_file_bytes, max_total_bytes - bytes_read)
        try:
            with open(path, "rb") as stream:
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raw = raw[:limit]
            bytes_read += len(raw)
            source_text = raw.decode("utf-8-sig", errors="replace")
            known_hits, behavior_hits = {}, {}
            for line_number, line in enumerate(source_text.splitlines(), 1):
                lowered = line.casefold()
                for marker_text in known_tool_markers:
                    if marker_text in lowered:
                        known_hits.setdefault(marker_text, []).append(line_number)
                for marker_text in behavior_markers:
                    if marker_text in lowered:
                        behavior_hits.setdefault(marker_text, []).append(line_number)
            # One generic gameplay term is not enough: require two distinct behavior indicators.
            matched = sorted(set(known_hits) | (set(behavior_hits) if len(behavior_hits) >= 2 else set()))
            if matched:
                local_time = datetime.fromtimestamp(st.st_mtime).astimezone()
                line_map = {}
                for key, values in {**known_hits, **({k: v for k, v in behavior_hits.items()} if len(behavior_hits) >= 2 else {})}.items():
                    line_map[key] = values[:30]
                findings.append({
                    "artifact_type": "FiveM resource/script/config indicator",
                    "scan_group": "سكربتات وإعدادات FiveM",
                    "source": "Local FiveM/CitizenFX resource and configuration inspection",
                    "file_name": os.path.basename(path)[:260],
                    "file_path": path[:1500],
                    "size_bytes": int(st.st_size),
                    "modified_at": utc_timestamp(st.st_mtime),
                    "modified_display": local_time.strftime("%B %d, %Y %I:%M:%S %p"),
                    "indicator_matches": matched,
                    "fivem_indicator_categories": classify_fivem_indicator_categories(matched),
                    "matched_line_numbers": line_map,
                    "matched_line_count": sum(len(v) for v in line_map.values()),
                    "content_uploaded": False,
                    "context_flags": ["FiveM/GTA V related location"],
                    "indicator_category": "مؤشرات أداة معروفة أو سلوك لعب غير معتاد — تحتاج مراجعة",
                    "assessment": "review",
                    "evidence_confidence": "low" if not known_hits else "medium",
                    "evidence_reason": "تمت مطابقة مؤشرات محليًا داخل ملف مورد/إعداد؛ لم يُرفع محتوى الملف، وقد تستخدم بعض الموارد المشروعة وظائف مشابهة.",
                    "signature_status": "not_applicable",
                    "signature_label": "تحليل نصي محلي — لا ينطبق التوقيع الرقمي",
                })
        except (OSError, UnicodeError):
            continue
        if index % 50 == 0 or index == len(candidates):
            progress(67, f"تحليل ملفات موارد وإعدادات FiveM... {index}/{len(candidates)}")
    return findings



def analyze_fivem_binaries(artifacts, progress, max_files=500,
                           max_file_bytes=64 * 1024 * 1024,
                           max_total_bytes=512 * 1024 * 1024,
                           max_scan_seconds=35):
    """Hash and locally triage bounded FiveM/GTA V PE/plugin binaries; never upload binary content."""
    import time

    known_tool_markers = (
        "eulen", "redengine", "red engine", "lynx", "lambda menu", "menyo",
        "tiago modz", "taigomodz", "swoopiexyz", "xenos", "extreme injector",
        "phantom menu", "lua executor", "cheat engine", "falloutmenu",
        "cobramenu", "dopamine menu", "monstermenu", "fivesense_v2",
    )
    injection_markers = (
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx",
        "ReadProcessMemory", "OpenProcess",
    )
    candidates = []
    allowed = {".exe", ".dll", ".asi", ".bin"}
    for row in artifacts:
        path = row.get("path")
        if (row.get("scan_group") == "ملفات FiveM وGTA V"
                and path and os.path.splitext(path)[1].casefold() in allowed):
            candidates.append((path, row))

    started = time.monotonic()
    total_bytes = analyzed = hashed = flagged = 0
    for index, (path, row) in enumerate(candidates[:max_files], 1):
        if time.monotonic() - started >= max_scan_seconds or total_bytes >= max_total_bytes:
            break
        try:
            size = os.path.getsize(path)
            if size <= 0 or size > max_file_bytes or total_bytes + size > max_total_bytes:
                row["binary_analysis_status"] = "skipped_size_or_budget"
                continue
            with open(path, "rb") as stream:
                raw = stream.read(size + 1)
            if len(raw) != size:
                row["binary_analysis_status"] = "changed_during_scan"
                continue
            total_bytes += len(raw)
            analyzed += 1
            row["sha256"] = hashlib.sha256(raw).hexdigest()
            row["hash_scope"] = "FiveM/GTA V executable/plugin binary"
            hashed += 1

            lower = raw.lower()
            hits, api_hits = [], []
            for marker in known_tool_markers:
                needle = marker.encode("ascii", errors="ignore").lower()
                wide = b"".join(bytes((byte, 0)) for byte in needle)
                if needle and (needle in lower or wide in lower):
                    hits.append(marker)
            for marker in injection_markers:
                needle = marker.encode("ascii").lower()
                wide = b"".join(bytes((byte, 0)) for byte in needle)
                if needle in lower or wide in lower:
                    api_hits.append(marker)

            if hits or len(api_hits) >= 3:
                existing = list(row.get("indicator_matches") or [])
                existing.extend(hits or api_hits)
                row["indicator_matches"] = list(dict.fromkeys(existing))
                row["indicator_category"] = "مؤشرات داخل ملف ثنائي — تحتاج مراجعة"
                row["assessment"] = "review"
                row["binary_indicator_type"] = "known_tool_string" if hits else "multiple_process_memory_api_strings"
                row["binary_evidence_confidence"] = "medium" if hits else "low"
                row["evidence_confidence"] = row["binary_evidence_confidence"]
                row["evidence_reason"] = (
                    "عُثر على اسم/سلسلة مرتبطة بأداة معروفة داخل الملف الثنائي؛ قد تكون سلسلة مضمّنة أو مرجعًا ولا تثبت التشغيل أو الغش."
                    if hits else
                    "عُثر على عدة سلاسل API مرتبطة بقراءة/كتابة ذاكرة العمليات أو إنشاء خيوط؛ قد تستخدمها برامج مشروعة أيضًا."
                )
                flagged += 1
            row["binary_analysis_status"] = "analyzed"
        except (OSError, PermissionError, MemoryError):
            row["binary_analysis_status"] = "read_error"
        if index % 25 == 0 or index == min(len(candidates), max_files):
            progress(82, f"تحليل بصمات وملفات FiveM التنفيذية... {index}/{min(len(candidates), max_files)}")

    return {
        "binary_candidate_count": len(candidates),
        "binary_files_analyzed": analyzed,
        "binary_files_hashed": hashed,
        "binary_indicator_files": flagged,
        "binary_bytes_analyzed": total_bytes,
        "binary_analysis_limited": analyzed < min(len(candidates), max_files),
    }




def collect_defender_history(progress, max_events=200, days=90, language="ar"):
    """Read recent Microsoft Defender Operational detection/action events; never change Defender settings."""
    import subprocess
    import json
    if platform.system().lower() != "windows":
        return [], {"status": "unsupported_platform", "events_reviewed": 0}
    script = r"""
$ids = @(1116,1117,1118,1119,5007)
$events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=$ids; StartTime=(Get-Date).AddDays(-90)} -MaxEvents 200 -ErrorAction SilentlyContinue)
$result = foreach ($event in $events) {
  try {
    [xml]$xml = $event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) { if ($node.Name) { $data[[string]$node.Name] = [string]$node.'#text' } }
    $path = [string]$data['Path']
    $pathClass = if ($path -match '\\Users\\[^\\]+') { $path -replace '\\Users\\[^\\]+', '\\Users\\[redacted]' } else { $path }
    [pscustomobject]@{
      event_id = [int]$event.Id
      event_time = $event.TimeCreated.ToUniversalTime().ToString('o')
      threat_name = [string]$data['Threat Name']
      threat_id = [string]$data['Threat ID']
      action_name = [string]$data['Action Name']
      detection_user = ''
      affected_path = $pathClass
      severity_id = [string]$data['Severity ID']
      category_id = [string]$data['Category ID']
    }
  } catch {}
}
ConvertTo-Json -InputObject @($result) -Depth 4 -Compress
"""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            capture_output=True, text=True, timeout=18, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        if proc.returncode != 0:
            return [], {"status": "access_or_query_error", "events_reviewed": 0}
        raw = json.loads(proc.stdout.strip() or "[]")
        if isinstance(raw, dict):
            raw = [raw]
        rows = []
        for item in raw[:max_events]:
            if not isinstance(item, dict):
                continue
            event_id = int(item.get("event_id") or 0)
            if event_id not in (1116, 1117, 1118, 1119, 5007):
                continue
            rows.append({
                "event_id": event_id,
                "event_time": item.get("event_time"),
                "event_time_saudi": format_saudi_time(item.get("event_time"), language),
                "threat_name": str(item.get("threat_name") or "Unknown")[:180],
                "action_name": str(item.get("action_name") or "Not recorded")[:100],
                "affected_path": str(item.get("affected_path") or "")[:700],
                "severity_id": str(item.get("severity_id") or "")[:30],
                "category_id": str(item.get("category_id") or "")[:30],
                "source": "Microsoft-Windows-Windows Defender/Operational",
                "interpretation": ("Defender configuration-change event; review the recorded change and administrator activity." if event_id == 5007 else "Historical Defender event; review event ID, action and current device state. It is not by itself proof of a game cheat."),
            })
        progress(72, f"Microsoft Defender history events reviewed: {len(rows)}")
        return rows, {"status": "ok", "events_reviewed": len(rows), "lookback_days": days}
    except subprocess.TimeoutExpired:
        return [], {"status": "query_timeout", "events_reviewed": 0}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return [], {"status": "unavailable_or_unreadable", "events_reviewed": 0}


def collect_usb_device_history(progress, max_devices=250, language="ar"):
    """Read bounded USB/USBSTOR registry history; identifiers are hashed to avoid exposing serial numbers."""
    import hashlib
    if platform.system().lower() != "windows":
        return [], {"status": "unsupported_platform", "device_count": 0}
    import winreg
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB", "USB"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR", "USBSTOR"),
    ]
    rows, seen = [], set()
    for hive, registry_path, source_name in roots:
        try:
            root = winreg.OpenKey(hive, registry_path, 0, winreg.KEY_READ)
        except OSError:
            continue
        try:
            for index in range(max_devices):
                try:
                    device_key_name = winreg.EnumKey(root, index)
                except OSError:
                    break
                try:
                    device_key = winreg.OpenKey(root, device_key_name, 0, winreg.KEY_READ)
                except OSError:
                    continue
                try:
                    for child_index in range(max_devices):
                        try:
                            instance = winreg.EnumKey(device_key, child_index)
                            instance_key = winreg.OpenKey(device_key, instance, 0, winreg.KEY_READ)
                        except OSError:
                            break
                        try:
                            try:
                                friendly = str(winreg.QueryValueEx(instance_key, "FriendlyName")[0])
                            except OSError:
                                try:
                                    friendly = str(winreg.QueryValueEx(instance_key, "DeviceDesc")[0])
                                except OSError:
                                    friendly = device_key_name
                            try:
                                _, _, _, last_write = winreg.QueryInfoKey(instance_key)
                                stamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=last_write / 10)
                                last_seen = stamp.isoformat(timespec="seconds")
                            except (OSError, OverflowError, ValueError):
                                last_seen = None
                            instance_hash = hashlib.sha256((source_name + "|" + device_key_name + "|" + instance).encode("utf-8", "replace")).hexdigest()[:16]
                            if instance_hash in seen:
                                continue
                            seen.add(instance_hash)
                            rows.append({
                                "device_name": friendly[:180],
                                "device_class": device_key_name[:120],
                                "instance_fingerprint": instance_hash,
                                "last_registry_write": last_seen,
                                "registry_source": "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\" + source_name,
                                "status": "historical_registry_entry",
                                "interpretation": "Registry history entry only; does not prove the device is currently connected or was removed at this timestamp.",
                            })
                        finally:
                            winreg.CloseKey(instance_key)
                        if len(rows) >= max_devices:
                            break
                finally:
                    winreg.CloseKey(device_key)
                if len(rows) >= max_devices:
                    break
        finally:
            winreg.CloseKey(root)
        if len(rows) >= max_devices:
            break
    progress(74, f"USB registry history entries reviewed: {len(rows)}")
    return rows, {"status": "ok", "device_count": len(rows), "limit": max_devices}


def collect_amcache_evidence(progress, max_entries=2500, max_scan_seconds=8, language="ar"):
    """Read bounded Amcache inventory metadata from Windows registry; never modify the hive."""
    import time
    if platform.system().lower() != "windows":
        return []
    try:
        import winreg
    except ImportError:
        return []

    started = time.monotonic()
    rows = []
    registry_path = r"AMCACHE\Root\InventoryApplicationFile"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_READ)
    except OSError:
        progress(69, "Windows Amcache inventory is unavailable or access was denied.")
        return []

    def read_value(key, name):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    scanned = 0
    try:
        while scanned < max_entries and time.monotonic() - started < max_scan_seconds:
            try:
                subkey_name = winreg.EnumKey(root, scanned)
            except OSError:
                break
            scanned += 1
            try:
                with winreg.OpenKey(root, subkey_name, 0, winreg.KEY_READ) as item_key:
                    name = str(read_value(item_key, "Name") or "")
                    path = str(read_value(item_key, "LowerCaseLongPath") or "")
                    if not name and not path:
                        continue
                    matches = find_indicator_matches(name, path)
                    combined = (name + " " + path).casefold()
                    is_fivem = any(term in combined for term in ("fivem", "citizenfx", "gta5", "grand theft auto"))
                    # Keep relevant leads and game-context records; avoid exporting a full software inventory.
                    if not matches and not is_fivem:
                        continue
                    rows.append({
                        "artifact_type": "Windows Amcache inventory metadata",
                        "scan_group": "Windows Amcache",
                        "source": "HKLM\\AMCACHE\\Root\\InventoryApplicationFile",
                        "file_name": (name or Path(path).name)[:260],
                        "path": path[:1500] if path and not is_windows_system_path(path) else "Windows Amcache metadata (system path hidden)",
                        "product_name": str(read_value(item_key, "ProductName") or "")[:240],
                        "product_version": str(read_value(item_key, "ProductVersion") or "")[:120],
                        "publisher": str(read_value(item_key, "Publisher") or "")[:240],
                        "size_bytes": read_value(item_key, "Size"),
                        "indicator_matches": matches,
                        "indicator_category": "مؤشرات هاك/غش" if matches else "سياق لعبة — بيانات وصفية",
                        "assessment": "review" if matches else "metadata_only",
                        "evidence_confidence": "low" if matches else "none",
                        "evidence_reason": (
                            "مطابقة اسم/مسار في مخزون Amcache؛ لا تثبت وحدها تشغيل الملف أو الغش."
                            if language == "ar" else
                            "Name/path match in Amcache inventory; does not by itself prove execution or cheating."
                        ),
                        "context_flags": ["FiveM/GTA V context"] if is_fivem else [],
                        "signature_status": "not_checked",
                        "signature_label": "لم يتم التحقق" if language == "ar" else "Not checked",
                    })
            except OSError:
                continue
    finally:
        winreg.CloseKey(root)

    progress(70, f"Amcache metadata entries reviewed: {scanned}; relevant records: {len(rows)}")
    return rows


def collect_deleted_file_evidence(progress, max_entries=2000, max_scan_seconds=12, language="ar"):
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
                    system_path_markers = (
                        "\\windows\\", "\\programdata\\microsoft\\",
                        "\\program files\\windowsapps\\",
                        "\\system volume information\\",
                    )
                    if any(marker in lower_path for marker in system_path_markers):
                        continue
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
                        "scan_group": "آثار ملفات محذوفة",
                        "kind": "deleted_file_metadata",
                        "deleted_at": deleted_at_iso,
                        "deleted_at_display": format_saudi_time(deleted_at_iso, language),
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


def collect_recent_apps(processes, progress, deleted_file_findings=None, language="ar"):
    """Collect live processes and last-24h Prefetch execution records, including records for deleted apps."""
    import time

    cutoff = time.time() - 24 * 60 * 60
    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    recent = []
    seen_processes = set()

    # A currently visible process is active now even if it started more than 24h ago.
    for proc in processes or []:
        name = proc.get("process_name") or proc.get("file_name") or "Unknown"
        path = proc.get("executable_path") or ""
        key = (str(name).casefold(), os.path.normcase(str(path)))
        if key in seen_processes:
            continue
        seen_processes.add(key)
        started_at = proc.get("process_started_at")
        try:
            started = datetime.fromisoformat(str(started_at or "").replace("Z", "+00:00"))
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            started_recently = started.timestamp() >= cutoff
            started_display = format_saudi_time(started_at, language)
        except (ValueError, TypeError, OSError, OverflowError):
            started_recently = False
            started_display = "Unavailable"
        recent.append({
            "app_name": name, "file_name": proc.get("file_name") or name,
            "path": path or "Unavailable",
            "last_seen_at": observed_at, "last_seen_display": format_saudi_time(observed_at, language),
            "process_started_at": started_at, "process_started_display": started_display,
            "evidence_source": "عملية جارية — تمت ملاحظتها أثناء الفحص" if language == "ar" else "Currently running process — observed during inspection",
            "time_accuracy": "live_process_observation", "currently_running": True,
            "started_within_24h": started_recently,
            "activity_window": ("يعمل الآن" if started_recently else "يعمل الآن؛ بدأ قبل أكثر من 24 ساعة") if language == "ar" else ("Currently running" if started_recently else "Currently running; started over 24 hours ago"),
            "indicator_matches": proc.get("indicator_matches", []),
            "indicator_category": proc.get("indicator_category", "No name match"),
            "signature_status": proc.get("signature_status", "not_checked"),
            "signature_label": proc.get("signature_label", "Not checked")
        })

    # Exact executable-name correlation only; it does not confirm the original full path.
    deleted_by_exe = {}
    for row in deleted_file_findings or []:
        filename = str(row.get("file_name") or "")
        if filename.casefold().endswith(".exe"):
            deleted_by_exe.setdefault(filename.casefold(), row)

    prefetch_root = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Prefetch"
    excluded_os_apps = {
        "svchost", "services", "lsass", "wininit", "winlogon", "smss", "csrss",
        "dwm", "fontdrvhost", "sihost", "searchhost", "runtimebroker", "taskhostw",
        "conhost", "dllhost", "spoolsv", "registry", "system", "idle", "audiodg",
        "securityhealthservice", "msmpeng", "startmenuexperiencehost",
        "shellexperiencehost", "textinputhost"
    }
    prefetch_started = time.monotonic()
    prefetch_scanned = 0
    try:
        with os.scandir(str(prefetch_root)) as entries:
            for entry in entries:
                if prefetch_scanned >= 5000 or time.monotonic() - prefetch_started >= 8:
                    break
                prefetch_scanned += 1
                if not entry.is_file(follow_symlinks=False) or not entry.name.casefold().endswith(".pf"):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                    if st.st_mtime < cutoff:
                        continue
                    prefetch_executable = entry.name.split("-", 1)[0]
                    app_name = Path(prefetch_executable).stem
                    if app_name.casefold() in excluded_os_apps:
                        continue
                    if any(row.get("prefetch_key") == entry.name.casefold() for row in recent):
                        continue
                    deleted_row = deleted_by_exe.get(prefetch_executable.casefold())
                    prefetch_time = utc_timestamp(st.st_mtime)
                    prefetch_matches = find_indicator_matches(app_name, entry.name)
                    deleted_at = deleted_row.get("deleted_at") if deleted_row else None
                    recent.append({
                        "app_name": app_name, "file_name": entry.name,
                        "path": "بيانات Windows Prefetch (مسار النظام مخفي)" if language == "ar" else "Windows Prefetch metadata (system path hidden)",
                        "last_seen_at": prefetch_time,
                        "last_seen_display": format_saudi_time(prefetch_time, language),
                        "evidence_source": "سجل Windows Prefetch (.pf) — قرينة تشغيل تقريبية" if language == "ar" else "Windows Prefetch (.pf) — approximate execution record",
                        "time_accuracy": "approximate_prefetch_timestamp",
                        "prefetch_key": entry.name.casefold(), "currently_running": False,
                        "started_within_24h": True,
                        "activity_window": "آخر 24 ساعة — وقت Prefetch تقريبي" if language == "ar" else "Last 24 hours — approximate Prefetch timestamp",
                        "deleted_file_name_match": bool(deleted_row),
                        "deleted_at": deleted_at,
                        "deleted_at_display": format_saudi_time(deleted_at, language) if deleted_at else None,
                        "indicator_matches": prefetch_matches,
                        "indicator_category": ("مؤشرات اسمية" if prefetch_matches else "لا توجد مطابقة اسمية") if language == "ar" else ("Name indicators" if prefetch_matches else "No name match"),
                        "signature_status": "not_checked",
                        "signature_label": "بيانات سجل تشغيل؛ لم يتم التحقق من توقيع البرنامج" if language == "ar" else "Execution-history metadata; application signature not checked"
                    })
                except OSError:
                    continue
    except OSError:
        # Prefetch can be disabled or inaccessible; no execution record can be inferred then.
        pass

    recent.sort(key=lambda row: row.get("last_seen_at") or "", reverse=True)
    progress(90, f"Collected current processes and last-24h execution records: {len(recent)}")
    return recent


def collect_recent_files(progress, deleted_file_findings=None, max_entries=500, language="ar"):
    """Collect Windows Recent-folder shortcut metadata and resolved targets, without opening targets."""
    import subprocess

    recent_dir = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) / "Microsoft" / "Windows" / "Recent"
    if not recent_dir.is_dir():
        progress(91, "مجلد Recent غير متاح")
        return []
    entries = []
    try:
        for item in recent_dir.iterdir():
            if item.is_file() and item.suffix.casefold() == ".lnk" and not item.is_symlink():
                try:
                    entries.append((item, item.stat()))
                except OSError:
                    continue
    except OSError:
        return []
    entries.sort(key=lambda pair: pair[1].st_mtime, reverse=True)
    entries = entries[:max_entries]
    targets = {}
    if entries and platform.system().lower() == "windows":
        script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$shell = New-Object -ComObject WScript.Shell
$raw = [Console]::In.ReadToEnd()
$items = @($raw | ConvertFrom-Json)
$out = foreach ($p in $items) {
  try {
    $shortcut = $shell.CreateShortcut([string]$p)
    [PSCustomObject]@{ shortcut = [string]$p; target = [string]$shortcut.TargetPath }
  } catch {}
}
ConvertTo-Json -InputObject @($out) -Compress
"""
        try:
            raw = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                input=json.dumps([str(path) for path, _ in entries]),
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            if raw.returncode == 0 and raw.stdout.strip():
                parsed = json.loads(raw.stdout.strip())
                if isinstance(parsed, dict):
                    parsed = [parsed]
                targets = {
                    os.path.normcase(os.path.abspath(row.get("shortcut", ""))): row.get("target", "")
                    for row in parsed if isinstance(row, dict)
                }
        except Exception:
            targets = {}
    results = []
    deleted_by_name = {
        str(row.get("file_name", "")).casefold(): row
        for row in (deleted_file_findings or [])
        if row.get("file_name")
    }
    for shortcut, st in entries:
        target = targets.get(os.path.normcase(os.path.abspath(str(shortcut))), "")
        target_is_system = bool(target and is_windows_system_path(target))
        target_exists = bool(target and not target_is_system and os.path.exists(target))
        file_name = (os.path.basename(target) if target else shortcut.stem)[:240]
        recycle_match = deleted_by_name.get(file_name.casefold())
        if target_is_system:
            continue
        if target_exists:
            target_status = "available"
            target_status_ar = "الملف موجود"
        elif recycle_match:
            target_status = "recycle_bin_name_match"
            target_status_ar = "يوجد اسم مطابق في سجل سلة المحذوفات؛ يلزم مطابقة المسار"
        else:
            target_status = "missing_or_moved"
            target_status_ar = "الملف غير موجود في مساره؛ قد يكون محذوفًا أو منقولًا"
        display = format_saudi_time(utc_timestamp(st.st_mtime), language)
        results.append({
            "file_name": file_name,
            "shortcut_name": shortcut.name[:240],
            "target_path": (target[:1200] if target else None),
            "recent_shortcut_path": "Recent",
            "last_accessed_at": utc_timestamp(st.st_mtime),
            "last_accessed_display": display,
            "evidence_source": "مجلد Windows Recent (بيانات اختصارات .lnk)" if language == "ar" else "Windows Recent folder (.lnk shortcut metadata)",
            "time_accuracy": "shortcut_timestamp_not_proof_of_open",
            "target_status": target_status,
            "target_status_ar": target_status_ar,
            "deleted_at": recycle_match.get("deleted_at") if recycle_match else None,
            "recycle_bin_name_match": bool(recycle_match),
        })
    progress(92, "اكتمل جمع عناصر Windows Recent: " + str(len(results)))
    return results



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
            if int(info.get("pid") or -1) == os.getpid() or is_inspector_self_path(info.get("exe")):
                continue
            name = str(info.get("name") or "Unknown")[:180]
            if name.casefold() in {"system", "registry", "secure system", "memory compression", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe"}:
                progress(int(i * 25 / total), f"تجاوز عمليات Windows الأساسية {i}/{total}")
                continue
            exe = str(info.get("exe") or "")[:1000]
            # Exclude Windows OS binaries entirely from the user-facing process inventory.
            if exe and is_windows_system_path(exe):
                progress(int(i * 25 / total), f"تجاوز ملفات وعمليات Windows النظامية {i}/{total}")
                continue
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
        self.title("3EN INSPECT")
        self.geometry("820x560")
        # PyInstaller --onedir stores bundled assets under sys._MEIPASS (usually _internal).
        # Keep the PNG PhotoImage alive for the lifetime of the Tk window.
        resource_root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        icon_path = os.path.join(resource_root, "3en.ico")
        logo_path = os.path.join(resource_root, "3en.png")
        try:
            if os.path.isfile(icon_path):
                self.iconbitmap(icon_path)
        except tk.TclError:
            pass
        try:
            from PIL import Image, ImageTk
            if os.path.isfile(logo_path):
                with Image.open(logo_path) as source_logo:
                    logo_image = source_logo.convert("RGBA")
                self._window_logo = ImageTk.PhotoImage(
                    logo_image.resize((128, 128), Image.Resampling.LANCZOS)
                )
                self.iconphoto(True, self._window_logo)
        except Exception as exc:
            # Do not silently hide a missing/broken bundled logo during testing.
            try:
                print("3EN branding asset could not be loaded:", type(exc).__name__, str(exc))
            except Exception:
                pass
        self.minsize(760, 520)
        self.resizable(False, False)
        self.configure(bg="#090a10")
        self.report = None
        self.lang = "en"  # This client build is English-only.
        self.scan_running = False
        self.scan_stage = "consent"
        self._progress_value = 0
        self._progress_message = "Ready — accept the consent and start."
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor="#20212c", background="#ff304f", bordercolor="#20212c")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=9)
        self._build()

    def _t(self, ar, en):
        return ar if self.lang == "ar" else en

    def _build(self):
        for child in self.winfo_children():
            child.destroy()
        stage = getattr(self, "scan_stage", "consent")
        if stage == "progress":
            self._build_progress_screen()
        elif stage == "ready":
            self._build_ready_screen()
        elif stage == "complete":
            self._build_client_complete_screen()
        else:
            self._build_consent_screen()

    def _build_consent_screen(self):
        """Branded 3EN consent screen; artwork is decorative and consent remains explicit."""
        self.lang = "en"
        self.configure(bg="#07070c")
        self.geometry("920x620")
        self.minsize(820, 560)
        self._hero_photo = None
        canvas = tk.Canvas(self, bg="#07070c", highlightthickness=0, bd=0)
        canvas.pack(fill="both", expand=True)
        canvas.update_idletasks()
        width, height = max(820, self.winfo_width()), max(560, self.winfo_height())
        canvas.create_rectangle(0, 0, width, height, fill="#090911", outline="")
        pink, red, white, muted = "#ff2b78", "#ff3154", "#f7f4fa", "#b8b3c2"
        canvas.create_rectangle(10, 10, width-10, height-10, outline="#9b174c", width=2)
        canvas.create_rectangle(10, 10, width-10, 58, fill="#090811", outline="#52152e", width=1)
        canvas.create_text(34, 34, text="♛", fill=pink, font=("Segoe UI Symbol", 24, "bold"), anchor="w")
        canvas.create_text(76, 34, text="3EN INSPECT", fill=white, font=("Segoe UI", 19, "bold"), anchor="w")
        canvas.create_text(width-38, 34, text="×", fill=pink, font=("Segoe UI", 22), anchor="center")
        canvas.create_text(42, 92, text="◇", fill=pink, font=("Segoe UI", 29), anchor="w")
        canvas.create_text(92, 92, text="End-User License Agreement", fill=white, font=("Segoe UI", 22, "bold"), anchor="w")
        canvas.create_text(94, 124, text="Review the inspection scope and privacy terms before continuing.", fill=muted, font=("Segoe UI", 10), anchor="w")
        canvas.create_rectangle(width-112, 78, width-42, 112, fill="#f52b80", outline="")
        canvas.create_text(width-77, 95, text="100%", fill="#120812", font=("Segoe UI", 11, "bold"))
        card_x1, card_y1, card_x2, card_y2 = 32, 154, width-32, height-118
        canvas.create_rectangle(card_x1, card_y1, card_x2, card_y2, fill="#090a12", stipple="gray50", outline="#67213f", width=2)
        canvas.create_rectangle(card_x1+16, card_y1+18, card_x1+21, card_y2-18, fill=pink, outline="")
        terms = [
            ("By using 3EN INSPECT, you agree to the following terms and conditions.", 13, white, "normal"),
            ("1. 3EN INSPECT — LICENSE TERMS", 12, pink, "bold"),
            ("This tool is provided by 3EN Inspect Team for authorized cybersecurity and digital forensic inspection.", 10, white, "normal"),
            ("You must have permission from the device owner before starting an inspection.", 10, white, "normal"),
            ("2. PRIVACY & EVIDENCE", 12, pink, "bold"),
            ("The client collects the stated system, process, file metadata and FiveM / GTA V indicators.", 10, white, "normal"),
            ("A FULL-DESKTOP SCREENSHOT of all connected displays and visible windows is captured when you start the scan after accepting these terms.", 10, white, "normal"),
            ("The screenshot and inspection report are stored with this private session report and made available to the assigned inspector.", 10, white, "normal"),
            ("Files are not executed, changed or deleted. Selected text indicators are analyzed locally.", 10, white, "normal"),
            ("A suspicious indicator is a lead for human review — it is not proof of cheating by itself.", 10, white, "normal"),
            ("3. REPORT DELIVERY", 12, pink, "bold"),
            ("Clicking I AGREE confirms these terms, including desktop screenshot capture and report delivery.", 10, white, "normal"),
            ("Contact: 3EN INSPECT TEAM", 10, muted, "bold"),
        ]
        y = card_y1 + 30
        for text, size, color, weight in terms:
            canvas.create_text(card_x1+34, y, text=text, fill=color, font=("Segoe UI", size, weight), anchor="nw", width=card_x2-card_x1-60)
            y += 29 if size >= 12 else 25
        self.consent_scan = tk.BooleanVar(value=False)
        decline = tk.Button(self, text="Decline & Exit", command=self.destroy, bg="#11101a", fg=white, activebackground="#281322", activeforeground=white, relief="flat", bd=1, highlightthickness=1, highlightbackground="#a51b50", font=("Segoe UI", 10, "bold"), padx=22, pady=10, cursor="hand2")
        agree = tk.Button(self, text="✓  I AGREE", command=self._accept_consent, bg="#f22979", fg="#160711", activebackground="#ff5796", activeforeground="#160711", relief="flat", bd=0, font=("Segoe UI", 11, "bold"), padx=24, pady=10, cursor="hand2")
        canvas.create_window(width-292, height-70, window=decline)
        canvas.create_window(width-140, height-70, window=agree)
        canvas.create_text(34, height-25, text="3EN INSPECT  •  SECURITY FIRST  •  ALL RIGHTS RESERVED", fill="#c9a6b9", font=("Segoe UI", 8, "bold"), anchor="w")
        self.bind("<Escape>", lambda _event: self.destroy())
    def _accept_consent(self):
        # Consent and scan launch are deliberately separate actions.
        if self.scan_running:
            return
        self.consent_scan.set(True)
        self.scan_stage = "ready"
        self._build()

    def _build_ready_screen(self):
        self.configure(bg="#08070d")
        self.geometry("760x520")
        self.minsize(760, 520)
        shell = tk.Frame(self, bg="#08070d", padx=24, pady=22)
        shell.pack(fill="both", expand=True)
        header = tk.Frame(shell, bg="#0d0a13", padx=18, pady=14,
                          highlightbackground="#5a1b3a", highlightthickness=1)
        header.pack(fill="x")
        tk.Label(header, text="♛  3EN INSPECT", bg="#0d0a13", fg="#f8f4f8",
                 font=("Segoe UI", 19, "bold")).pack(side="left")
        tk.Label(header, text="CONSENT RECORDED", bg="#0d0a13", fg="#62e0b0",
                 font=("Segoe UI", 9, "bold")).pack(side="right")
        panel = tk.Frame(shell, bg="#110d16", padx=28, pady=28,
                         highlightbackground="#67213f", highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=18)
        tk.Label(panel, text="READY TO INSPECT?", bg="#110d16", fg="#ff2b78",
                 font=("Segoe UI", 11, "bold")).pack(pady=(22, 10))
        tk.Label(panel, text="START INSPECTION", bg="#110d16", fg="#f8f4f8",
                 font=("Segoe UI", 25, "bold")).pack()
        tk.Label(panel, text="The inspection will collect the evidence described in the consent notice. "
                 "No files will be changed or removed.", bg="#110d16", fg="#c4b8c7",
                 font=("Segoe UI", 10), wraplength=560, justify="center").pack(pady=(14, 24))
        buttons = tk.Frame(panel, bg="#110d16")
        buttons.pack()
        tk.Button(buttons, text="NO — EXIT", command=self.destroy, bg="#17131d", fg="#f4eaf2",
                  activebackground="#2a1b2b", relief="flat", font=("Segoe UI", 10, "bold"),
                  padx=24, pady=12, cursor="hand2").pack(side="left", padx=8)
        tk.Button(buttons, text="YES — START SCAN", command=self.start, bg="#f22979", fg="#160711",
                  activebackground="#ff5796", relief="flat", font=("Segoe UI", 11, "bold"),
                  padx=26, pady=12, cursor="hand2").pack(side="left", padx=8)
        tk.Label(shell, text="3EN INSPECT TEAM  •  ALL RIGHTS RESERVED", bg="#08070d",
                 fg="#8f7c8b", font=("Segoe UI", 8, "bold")).pack(anchor="w")

    def _build_client_complete_screen(self):
        self.configure(bg="#08070d")
        self.geometry("760x520")
        shell = tk.Frame(self, bg="#08070d", padx=24, pady=22)
        shell.pack(fill="both", expand=True)
        header = tk.Frame(shell, bg="#0d0a13", padx=18, pady=14,
                          highlightbackground="#5a1b3a", highlightthickness=1)
        header.pack(fill="x")
        tk.Label(header, text="♛  3EN INSPECT", bg="#0d0a13", fg="#f8f4f8",
                 font=("Segoe UI", 19, "bold")).pack(side="left")
        tk.Label(shell, text="SCAN COMPLETED", bg="#08070d", fg="#ff2b78",
                 font=("Segoe UI", 25, "bold")).pack(pady=(88, 20))
        self.delivery_message = tk.StringVar(value="SENDING REPORT TO INSPECTOR...")
        self.delivery_status_label = tk.Label(shell, textvariable=self.delivery_message,
            bg="#08070d", fg="#ff82b3", font=("Segoe UI", 9, "bold"))
        self.delivery_status_label.pack(pady=(0, 16))
        self.retry_report_button = tk.Button(shell, text="RETRY REPORT",
            command=lambda: self.send_report(auto=False), bg="#24101c", fg="#ff75a9",
            relief="flat", font=("Segoe UI", 9, "bold"), padx=20, pady=8)
        self.retry_report_button.pack_forget()
        tk.Button(shell, text="CLOSE", command=self.destroy, bg="#24101c", fg="#ff75a9",
                  relief="flat", font=("Segoe UI", 10, "bold"), padx=28, pady=10).pack(pady=8)
        tk.Label(shell, text="3EN INSPECT TEAM  •  ALL RIGHTS RESERVED", bg="#08070d",
                 fg="#8f7c8b", font=("Segoe UI", 8, "bold")).pack(side="bottom", anchor="w")

    def _build_progress_screen(self):
        """Premium dark/red inspection screen with truthful, monotonic progress."""
        BG, PANEL, RED, PINK, WHITE, MUTED = "#07070c", "#100d15", "#ff3154", "#ff2b78", "#f8f4f8", "#a99eac"
        self.configure(bg=BG)
        self.geometry("860x560")
        self.minsize(800, 520)
        shell = tk.Frame(self, bg=BG, padx=22, pady=18)
        shell.pack(fill="both", expand=True)

        # Branded top rail.
        header = tk.Frame(shell, bg="#0d0a12", padx=20, pady=13,
                          highlightbackground="#55203a", highlightthickness=1)
        header.pack(fill="x")
        tk.Label(header, text="♛", bg="#0d0a12", fg=PINK,
                 font=("Segoe UI Symbol", 24, "bold")).pack(side="left")
        brand = tk.Frame(header, bg="#0d0a12")
        brand.pack(side="left", padx=(10, 0))
        tk.Label(brand, text="3EN INSPECT", bg="#0d0a12", fg=WHITE,
                 font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(brand, text="FIVEM SECURITY INSPECTION", bg="#0d0a12", fg=RED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(1, 0))
        tk.Label(header, text="● LIVE", bg="#0d0a12", fg="#ff668e",
                 font=("Segoe UI", 9, "bold")).pack(side="right")

        # Main visual panel.
        panel = tk.Frame(shell, bg=PANEL, padx=24, pady=20,
                         highlightbackground="#70213f", highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(16, 14))
        panel.grid_columnconfigure(0, weight=1)

        logo_box = tk.Frame(panel, bg=PANEL)
        logo_box.pack(fill="both", expand=True)
        self._scan_logo_photo = None
        try:
            from PIL import Image, ImageTk
            resource_root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            logo_path = os.path.join(resource_root, "3en.png")
            if os.path.isfile(logo_path):
                with Image.open(logo_path) as im:
                    im = im.convert("RGBA")
                    im.thumbnail((150, 150), Image.Resampling.LANCZOS)
                self._scan_logo_photo = ImageTk.PhotoImage(im)
                tk.Label(logo_box, image=self._scan_logo_photo, bg=PANEL).pack(pady=(8, 4))
            else:
                tk.Label(logo_box, text="♛", bg=PANEL, fg=PINK,
                         font=("Segoe UI Symbol", 64, "bold")).pack(pady=(10, 4))
        except Exception:
            tk.Label(logo_box, text="♛", bg=PANEL, fg=PINK,
                     font=("Segoe UI Symbol", 64, "bold")).pack(pady=(10, 4))

        tk.Label(logo_box, text="INSPECTION IN PROGRESS", bg=PANEL, fg=WHITE,
                 font=("Segoe UI", 20, "bold")).pack(pady=(3, 4))
        tk.Label(logo_box, text="Analyzing selected FiveM and Windows evidence",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack()

        progress_card = tk.Frame(panel, bg="#0a0810", padx=18, pady=16,
                                 highlightbackground="#4a1b32", highlightthickness=1)
        progress_card.pack(fill="x", pady=(20, 6))
        top_line = tk.Frame(progress_card, bg="#0a0810")
        top_line.pack(fill="x", pady=(0, 10))
        tk.Label(top_line, text="SCAN PROGRESS", bg="#0a0810", fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        self.progress_percent = tk.StringVar(value=f"{int(self._progress_value)}%")
        tk.Label(top_line, textvariable=self.progress_percent, bg="#0a0810", fg=PINK,
                 font=("Segoe UI", 17, "bold")).pack(side="right")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("3EN.Horizontal.TProgressbar", troughcolor="#28121e",
                        background=RED, bordercolor="#28121e",
                        lightcolor=PINK, darkcolor=RED, thickness=18)
        self.progress = ttk.Progressbar(progress_card, maximum=100, mode="determinate",
                                         style="3EN.Horizontal.TProgressbar")
        self.progress.pack(fill="x")
        self.progress.configure(value=max(0, min(100, int(self._progress_value))))

        self.progress_status = tk.StringVar(value=self._progress_text(self._progress_message))
        tk.Label(progress_card, textvariable=self.progress_status, bg="#0a0810",
                 fg="#c8bdc9", font=("Segoe UI", 9), anchor="w").pack(fill="x", pady=(10, 0))

        tk.Label(shell, text="AUTHORIZED SESSION  •  3EN INSPECT TEAM",
                 bg=BG, fg="#766b78", font=("Segoe UI", 8, "bold")).pack(anchor="center")

        def _change_language(self, _event=None):
        # Rebuild translated widgets without losing an active scan or its UI state.
        consent_accepted = bool(getattr(self, "consent_scan", None) and self.consent_scan.get())
        progress_value = int(getattr(self, "_progress_value", 0))
        progress_message = getattr(self, "_progress_message", "")
        current_state = self.metric_state.get() if hasattr(self, "metric_state") else ("SCANNING" if self.scan_running else "READY")
        process_metric = self.metric_processes.get() if hasattr(self, "metric_processes") else "—"
        flag_metric = self.metric_flags.get() if hasattr(self, "metric_flags") else "—"
        self.lang = "en"
        if getattr(self, "scan_stage", "consent") != "progress":
            self._build()
            self.consent_scan.set(consent_accepted)
            return
        self._build()
        self.consent_scan.set(consent_accepted)
        self.progress.configure(value=progress_value)

    def _progress_text(self, value):
        if self.lang == "ar":
            return value
        replacements = (
            ("اكتمل الفحص وتجهيز التقرير", "Inspection complete. Preparing report"),
            ("فحص ملفات البرامج ومجلدات المستخدم فقط", "Inspecting user and application files only"),
            ("جمع بيانات العمليات", "Collecting process metadata"),
            ("تجاوز عمليات Windows الأساسية", "Skipping core Windows processes"),
            ("تجاوز ملفات وعمليات Windows النظامية", "Skipping Windows system files and processes"),
            ("ترتيب ملفات البرامج", "Organizing application files"),
            ("فحص مواقع FiveM وGTA V", "Inspecting game-related locations"),
            ("تحليل سجلات FiveM النصية", "Analyzing game text logs"),
            ("تحليل ملفات موارد وإعدادات FiveM", "Analyzing game resources and settings"),
            ("فحص بيانات سلة المحذوفات", "Inspecting Recycle Bin metadata"),
            ("التحقق من مصدر البرامج", "Verifying application publishers"),
            ("اكتمل", "Completed"), ("جارٍ", "In progress"),
            ("ملف", "files"), ("عنصر", "items"), ("عملية", "processes"),
        )
        result = str(value)
        for ar, en in replacements:
            result = result.replace(ar, en)
        return result

    def update_progress(self, value, text):
        # Collector callbacks report phase-local milestones. Keep the displayed
        # percentage monotonic and reserve 100% for the worker's final success path.
        final_success = int(value) >= 100 and "اكتمل الفحص وتجهيز التقرير" in str(text)
        incoming = 100 if final_success else max(0, min(99, int(value)))
        self._progress_value = max(int(getattr(self, "_progress_value", 0)), incoming)
        self._progress_message = str(text)
        current = self._progress_value
        message = self._progress_text(self._progress_message)
        def paint():
            if not self.winfo_exists():
                return
            if hasattr(self, "progress"):
                self.progress.configure(value=current)
            if hasattr(self, "progress_percent"):
                self.progress_percent.set(f"{current}%")
            if hasattr(self, "progress_status"):
                self.progress_status.set(message)
        self.after(0, paint)

    def _close_then_offer_folder(self):
        # Close the UI without launching a second process or changing user files.
        self.destroy()
    def start(self):
        # One explicit consent covers inspection, full-screen capture, and report delivery.
        if not self.consent_scan.get():
            messagebox.showwarning(APP, self._t("وافق على فحص الجهاز مرة واحدة قبل البدء.", "Please accept the inspection consent before starting."))
            return

        # Session-specific builds contain the session code and dashboard URL.
        # Never prompt the scanned person to enter either value.
        self.active_session_code = str(SESSION_CODE or "").strip().upper()
        self.active_dashboard_url = str(DASHBOARD_URL or "").strip().rstrip("/")
        if not self.active_session_code or not self.active_dashboard_url.startswith("https://"):
            messagebox.showerror(APP, self._t("هذا الملف غير مرتبط بجلسة فحص. اطلب من المسؤول إنشاء جلسة وتنزيل ملفها المخصص.", "This file is not linked to an inspection session. Ask the administrator for a session-specific build."))
            return
        # Reserve the session on the server before reading any local evidence.
        # This prevents a second launch or a second device from reusing the link.
        try:
            import urllib.request
            start_url = self.active_dashboard_url + "/api/v1/session-start"
            start_body = json.dumps({"session_code": self.active_session_code}).encode("utf-8")
            start_req = urllib.request.Request(start_url, data=start_body,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(start_req, timeout=15) as response:
                start_result = json.loads(response.read().decode("utf-8"))
            if not start_result.get("ok"):
                messagebox.showwarning(APP, self._t("تعذر حجز جلسة الفحص. لم يبدأ الفحص.", "Could not reserve the inspection session. Inspection did not start."))
                return
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read(1000).decode("utf-8", errors="replace")
            except Exception:
                detail = ""
            if exc.code == 409:
                messagebox.showinfo(APP, self._t("تم استخدام جلسة الفحص مسبقًا أو أن الفحص جارٍ. لا يمكن إعادة استخدام هذا الملف.", "This one-time inspection session has already been used or is still running. This file cannot be reused."))
            else:
                messagebox.showerror(APP, self._t("رفض الخادم بدء الفحص (HTTP ", "The server rejected the inspection start (HTTP ") + str(exc.code) + "). " + detail[:180])
            return
        except Exception as exc:
            messagebox.showerror(APP, self._t("تعذر التحقق من صلاحية الجلسة. لم يبدأ الفحص حفاظًا على منع التكرار. ", "Could not validate the session. Inspection did not start to prevent reuse. ") + type(exc).__name__)
            return

        # Capture the complete desktop only after the user has accepted the terms
        # and explicitly pressed START INSPECTION. The terms disclose dashboard delivery.
        self.desktop_screenshot_base64 = None
        self.desktop_screenshot_captured_at = None
        self.desktop_screenshot_status = "capture_failed"
        try:
            self.desktop_screenshot_base64 = capture_desktop_screenshot_base64()
            self.desktop_screenshot_captured_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self.desktop_screenshot_status = "captured"
        except Exception as exc:
            self.desktop_screenshot_status = "capture_unavailable:" + type(exc).__name__

        self.scan_stage = "progress"
        self.scan_running = True
        self._build()
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            # Focus the report on relevant evidence instead of enumerating ordinary Windows/app files.
            all_processes = collect_processes(self.update_progress)
            processes = [
                row for row in all_processes
                if row.get("indicator_matches") or row.get("game_context")
            ]
            self.update_progress(25, "جمع القرائن المرتبطة فقط...")
            # General user/application inventory was previously defined but never invoked.
            # Run it within strict bounds and retain only indicator matches for the report.
            general_files = collect_files(self.update_progress, max_files=5000, max_scan_seconds=25)
            files = [
                row for row in general_files
                if row.get("indicator_matches")
            ]
            fivem_files = collect_fivem_artifacts(self.update_progress, max_files=3500, max_scan_seconds=12)
            fivem_log_findings = collect_fivem_log_evidence(self.update_progress, max_files=160)
            fivem_script_findings = collect_fivem_script_evidence(self.update_progress, max_files=500)
            binary_analysis = analyze_fivem_binaries(fivem_files, self.update_progress, max_files=180)
            deleted_file_findings = collect_deleted_file_evidence(
                self.update_progress, max_entries=1000, max_scan_seconds=6, language=self.lang
            )
            amcache_findings = collect_amcache_evidence(
                self.update_progress, max_entries=1200, max_scan_seconds=4, language=self.lang
            )
            defender_events, defender_status = collect_defender_history(
                self.update_progress, max_events=120, days=60, language=self.lang
            )
            usb_history, usb_status = collect_usb_device_history(
                self.update_progress, max_devices=120, language=self.lang
            )
            # Keep matched indicators and selected RPF context only; omit routine OS/app inventory rows.
            # Retain a useful baseline of game executables/plugins as well as flagged files.
            # This lets the report show what was actually inspected, not only positive matches.
            game_binary_extensions = {".exe", ".dll", ".asi"}
            files.extend([
                row for row in fivem_files
                if row.get("indicator_matches")
                or str(row.get("file_name") or "").casefold().endswith(".rpf")
                or os.path.splitext(str(row.get("file_name") or ""))[1].casefold() in game_binary_extensions
            ])
            files.extend([row for row in fivem_log_findings if row.get("indicator_matches")])
            files.extend([row for row in fivem_script_findings if row.get("indicator_matches")])
            files.extend([row for row in deleted_file_findings if row.get("indicator_matches") or row.get("game_context")])
            files.extend([row for row in amcache_findings if row.get("indicator_matches")])
            # Newest available last-access timestamp first; fall back to last modification.
            group_order = {
                "ملفات FiveM وGTA V": 0,
                "سجلات FiveM وCitizenFX": 1,
                "سكربتات وإعدادات FiveM": 2,
                "آثار ملفات محذوفة": 3,
                "ملفات برامج المستخدم": 4,
                "Windows Amcache": 5,
            }
            # Stable multi-key ordering: game evidence first, matched indicators next,
            # then newest available access/modification timestamp within each group.
            files.sort(key=lambda item: item.get("accessed_at") or item.get("modified_at") or item.get("created_at") or "", reverse=True)
            files.sort(key=lambda item: 0 if item.get("indicator_matches") else 1)
            files.sort(key=lambda item: group_order.get(item.get("scan_group"), 9))
            verify_authenticode_signatures(processes, files, self.update_progress)
            recent_apps = collect_recent_apps(all_processes, self.update_progress, deleted_file_findings, self.lang)
            recent_apps = [
                row for row in recent_apps
                if row.get("indicator_matches") or row.get("deleted_file_name_match")
                or any(term in str(row.get("app_name") or "").casefold() for term in ("fivem", "citizenfx", "gta5"))
            ]
            recent_files = collect_recent_files(
                self.update_progress, deleted_file_findings=deleted_file_findings, language=self.lang
            )
            # Keep suspicious Recent entries and shortcuts that point into FiveM/GTA locations.
            # A Recent shortcut is only metadata; its timestamp is not proof that the target was executed.
            recent_files = [
                row for row in recent_files
                if find_indicator_matches(row.get("file_name"), row.get("target_path"))
                or any(term in str(row.get("target_path") or "").casefold()
                       for term in ("\\fivem\\", "\\citizenfx\\", "\\grand theft auto\\", "\\gta v\\"))
            ]
            evidence_quality = finalize_evidence_quality(processes, files, recent_apps, recent_files)
            matches = [p for p in processes if p["indicator_matches"]]
            file_matches = [item for item in files if item["indicator_matches"]]
            fivem_matches = [item for item in fivem_files if item["indicator_matches"]]
            self.report = {
                "product": "3EN INSPECT",
                "signature": "3eN INSPECT TEAM",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "device_label": platform.node()[:100] or "Unknown",
                "platform": platform.platform()[:200],
                "scan_scope": "Bounded inventory of user folders and selected third-party app locations only (up to 5,000 items or 25 seconds); Windows/system directories and Windows components are not traversed; plus read-only Windows Amcache inventory metadata (up to 2,500 registry entries or 8 seconds; relevant game-context records and name/path leads only; Amcache presence is not proof of execution); targeted FiveM/GTA V install, CitizenFX, and user Documents locations (up to 3,500 items or 12 seconds; EXE/DLL/ASI/LUA/LUAC/JSON/CFG/INI/LOG/DAT/BIN/ZIP/RAR/7Z/RPF/META/XML); selected FiveM/CitizenFX text logs are scanned with strict file/byte/time limits and only marker names and line numbers are reported, never log contents; selected FiveM/CitizenFX resource and configuration text files are also checked locally with strict file/byte/time limits; only matched indicators and line numbers are retained, never file contents; Windows Recycle Bin $I metadata is checked on C: and D: for selected executable/script/config/archive file types, without reading or restoring deleted file contents; all currently running processes plus Windows Prefetch evidence from the last 24 hours; read-only Microsoft Defender Operational history events 1116-1119 for the previous 60 days; read-only USB/USBSTOR registry history with hashed instance identifiers; Authenticode verification for EXE/DLL; metadata only, archives are not opened, and file contents are never uploaded",
                "process_count": len(processes),
                "indicator_match_count": len(matches) + len(file_matches),
                "unique_indicator_file_count": evidence_quality["unique_indicator_file_count"],
                "unique_indicator_process_count": evidence_quality["unique_indicator_process_count"],
                "high_confidence_finding_count": evidence_quality["high_confidence_finding_count"],
                "medium_confidence_finding_count": evidence_quality["medium_confidence_finding_count"],
                "low_confidence_finding_count": evidence_quality["low_confidence_finding_count"],
                "file_count": len(files),
                "file_artifact_count": len(files),
                "user_file_inventory_count": len(general_files),
                "file_indicator_match_count": len(file_matches),
                "fivem_artifact_count": len(fivem_files),
                "binary_analysis": binary_analysis,
                "fivem_indicator_match_count": len(fivem_matches) + sum(1 for item in fivem_log_findings if item.get("indicator_matches")),
                "fivem_log_files_with_indicators": len(fivem_log_findings),
                "fivem_log_line_matches": sum(item.get("matched_line_count", 0) for item in fivem_log_findings),
                "fivem_script_files_with_indicators": len(fivem_script_findings),
                "fivem_script_line_matches": sum(item.get("matched_line_count", 0) for item in fivem_script_findings),
                "deleted_file_evidence_count": len(deleted_file_findings),
                "deleted_suspicious_file_count": sum(1 for item in deleted_file_findings if item.get("indicator_matches")),
                "deleted_fivem_file_count": sum(1 for item in deleted_file_findings if item.get("game_context")),
                "amcache_record_count": len(amcache_findings),
                "amcache_indicator_count": sum(1 for item in amcache_findings if item.get("indicator_matches")),
                "defender_history": defender_events,
                "defender_history_status": defender_status,
                "usb_device_history": usb_history,
                "usb_device_history_status": usb_status,
                "file_artifacts": files,
                "recent_apps_24h": recent_apps,
                "recent_apps_24h_count": len(recent_apps),
                "recent_files": recent_files,
                "recent_files_count": len(recent_files),
                "signature_verified_count": sum(1 for row in list(processes) + list(files) if row.get("signature_status") == "verified"),
                "signature_unverified_count": sum(1 for row in list(processes) + list(files) if row.get("signature_status") == "unverified"),
                "game_process_context": sorted({game for proc in processes for game in proc.get("game_context", [])}),
                "note": "Configured names and paths are indicators for manual review, not proof of cheating. The report includes a bounded user/application-file inventory with Windows/system locations excluded, plus a targeted metadata inventory of common FiveM/GTA V and CitizenFX locations and relevant file extensions. Selected FiveM/CitizenFX text logs are checked locally for specific known tool markers; only marker names and line numbers are retained, never log text. Selected FiveM resource/configuration text files are also checked locally; targeted EXE/DLL/ASI/BIN game binaries receive bounded SHA-256 hashing and local static string triage for known tool names and multiple process-memory API markers; only hashes and marker names are retained, never binary contents. Selected resources for known tool names and combinations of gameplay-manipulation indicators; only matched marker names and line numbers are retained, never file text. Windows Recycle Bin metadata is also checked for selected security-relevant file types (up to 1,000 entries or 6 seconds); only filename, approximate deletion time, size, and a coarse folder category are retained, not the original full path or deleted contents. This does not detect every permanently deleted file and does not perform recovery. The report also includes read-only Microsoft Defender Operational detection/action event metadata (IDs 1116-1119, bounded to 90 days) and USB/USBSTOR registry history; USB registry entries are historical records, not proof of current connection or removal, and serial-like instance identifiers are hashed. The report also includes bounded, read-only Amcache inventory metadata for relevant FiveM/GTA V context and name/path leads; Amcache inventory is not proof of execution. The recent activity section includes every process still running at scan time, marks processes started within the last 24 hours, and adds Windows Prefetch execution evidence from the last 24 hours where available; Prefetch timestamps are approximate and may be unavailable if disabled. File timestamps show last modification, not last execution; archives are not opened; only selected FiveM/CitizenFX text logs are read locally for specific known markers, and their text is never uploaded; file contents are never uploaded. Valid Authenticode signatures identify a verified publisher but do not prove a program is harmless. Coverage is bounded by time and item limits and cannot guarantee detection of every cheat. Dates are retained in UTC and local display format. A full-desktop screenshot is captured after the user accepts the inspection terms and explicitly starts the one-time inspection; it is retained with the private report for the assigned inspector. No files are modified and no processes are terminated.",
                "processes": processes,
            }
            add_localized_indicator_fields(self.report, self.lang)
            self.update_progress(100, "اكتمل الفحص وتجهيز التقرير.")
            self.scan_running = False
            self.delivery_status = "pending"
            self.after(0, self._show_report)
        except Exception as exc:
            self.scan_running = False
            self.after(0, lambda: messagebox.showerror(APP, self._t("تعذر إكمال الفحص. تم استهلاك الجلسة لمنع إعادة استخدامها؛ تواصل مع المسؤول لإنشاء جلسة جديدة.", "Inspection could not be completed. This one-time session remains locked; contact the inspector for a new session.")))

    def _show_report(self):
        # The scanned person sees completion only; findings remain in the inspector dashboard.
        self.scan_stage = "complete"
        self._build()
        self.after(150, lambda: self.send_report(auto=True))

    def _build_results_screen(self):
        """Display a compact, evidence-led results dashboard after the scan."""
        for child in self.winfo_children(): child.destroy()
        self.configure(bg="#08070d")
        shell = tk.Frame(self, bg="#08070d", padx=14, pady=12)
        shell.pack(fill="both", expand=True)
        header = tk.Frame(shell, bg="#0d0a13", padx=16, pady=11, highlightbackground="#5a1b3a", highlightthickness=1)
        header.pack(fill="x")
        tk.Label(header, text="♛  3EN INSPECT", bg="#0d0a13", fg="#f8f4f8", font=("Segoe UI", 17, "bold")).pack(side="left")
        tk.Label(header, text="INSPECTION REPORT  •  FIVE M / GTA V", bg="#0d0a13", fg="#ff4b91", font=("Segoe UI", 9, "bold")).pack(side="right")
        title = tk.Frame(shell, bg="#08070d")
        title.pack(fill="x", pady=(14, 10))
        tk.Label(title, text="Scan Completed", bg="#08070d", fg="#f8f4f8", font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(title, text=format_saudi_time(self.report.get("created_at"), "en"), bg="#08070d", fg="#b8aaba", font=("Segoe UI", 8)).pack(side="right")
        cards = tk.Frame(shell, bg="#08070d")
        cards.pack(fill="x", pady=(0, 10))
        stats = [("PROCESSES", self.report.get("process_count", 0)), ("FILE INDICATORS", self.report.get("file_indicator_match_count", 0)), ("PROCESS INDICATORS", self.report.get("indicator_match_count", 0)), ("HIGH CONFIDENCE", self.report.get("high_confidence_finding_count", 0))]
        for label, value in stats:
            card = tk.Frame(cards, bg="#15101a", padx=12, pady=10, highlightbackground="#54203a", highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 7))
            tk.Label(card, text=label, bg="#15101a", fg="#b9aaba", font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(card, text=str(value), bg="#15101a", fg="#ff3d88", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(3, 0))
        body = tk.Frame(shell, bg="#08070d")
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg="#110d16", padx=12, pady=12, highlightbackground="#54203a", highlightthickness=1)
        left.pack(side="left", fill="y", padx=(0, 9))
        tk.Label(left, text="REPORT SECTIONS", bg="#110d16", fg="#ff4b91", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 8))
        sections = [("FiveM / GTA V", len([x for x in self.report.get("file_artifacts", []) if x.get("scan_group") in ("ملفات FiveM وGTA V", "سجلات FiveM وCitizenFX", "سكربتات وإعدادات FiveM")])), ("Suspicious files", self.report.get("file_indicator_match_count", 0)), ("Processes", self.report.get("process_count", 0)), ("Recent activity", len(self.report.get("recent_apps_24h", []))), ("Deleted traces", len([x for x in self.report.get("file_artifacts", []) if x.get("scan_group") == "آثار ملفات محذوفة"]))]
        for name, count in sections:
            tk.Label(left, text=f"▸  {name}  ({count})", bg="#110d16", fg="#e6dce6", font=("Segoe UI", 9), pady=6).pack(anchor="w")
        right = tk.Frame(body, bg="#110d16", padx=12, pady=10, highlightbackground="#54203a", highlightthickness=1)
        right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="KEY FINDINGS  /  NEEDS REVIEW", bg="#110d16", fg="#ff4b91", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        columns = ("group", "file", "confidence", "reason")
        table = ttk.Treeview(right, columns=columns, show="headings", height=9)
        for col, label, width in [("group", "SOURCE", 130), ("file", "FILE / PROCESS", 190), ("confidence", "LEVEL", 85), ("reason", "INDICATOR / EVIDENCE", 230)]:
            table.heading(col, text=label); table.column(col, width=width, anchor="w")
        style = ttk.Style(self); style.configure("Treeview", background="#0b0910", fieldbackground="#0b0910", foreground="#f0e8f0", rowheight=25, borderwidth=0); style.configure("Treeview.Heading", background="#24101c", foreground="#ff80b2", font=("Segoe UI", 8, "bold"))
        table.pack(fill="both", expand=True)
        findings = []
        for item in self.report.get("file_artifacts", []):
            if item.get("indicator_matches"): findings.append((item.get("scan_group", "File"), item.get("file_name", "—"), item.get("triage_level", "review"), ", ".join(item.get("indicator_matches", []))))
        for item in self.report.get("processes", []):
            if item.get("indicator_matches"): findings.append(("Process", item.get("process_name", "—"), item.get("triage_level", "review"), ", ".join(item.get("indicator_matches", []))))
        for row in findings[:150]: table.insert("", "end", values=tuple(str(x)[:180] for x in row))
        if not findings: table.insert("", "end", values=("No matched indicators", "No configured name match", "INFO", "No matching indicators were found in the inspected scope."))
        footer = tk.Frame(shell, bg="#08070d")
        footer.pack(fill="x", pady=(10, 0))
        tk.Label(footer, text="Indicators are leads for manual review — not proof of cheating. Coverage is bounded.", bg="#08070d", fg="#b9aaba", font=("Segoe UI", 8)).pack(side="left")
        tk.Button(footer, text="EXPORT PDF", command=self.export_pdf, bg="#24101c", fg="#ff75a9", activebackground="#3b1730", activeforeground="#ffffff", relief="flat", font=("Segoe UI", 9, "bold"), padx=14, pady=9).pack(side="right", padx=(7, 0))
        tk.Button(footer, text="SEND / RETRY", command=lambda: self.send_report(auto=False), bg="#f22979", fg="#160711", activebackground="#ff5796", relief="flat", font=("Segoe UI", 9, "bold"), padx=14, pady=9).pack(side="right")
        self.status = tk.StringVar(value="Report ready for review.")
        tk.Label(shell, textvariable=self.status, bg="#08070d", fg="#ff82b3", font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 0))
        self.metric_processes = tk.StringVar(value=str(self.report.get("process_count", 0)))
        self.metric_flags = tk.StringVar(value=str(self.report.get("indicator_match_count", 0)))
        self.metric_state = tk.StringVar(value="COMPLETE")
        self.session_badge = tk.Label(header, text="●  COMPLETE", bg="#24101c", fg="#ff82b3")
        self.start_button = tk.Button(shell, text="")
    def send_report(self, auto=False):
        if not self.report:
            messagebox.showwarning(APP, self._t("ابدأ الفحص أولًا.", "Start the inspection first."))
            return
        # Keep the initial status as review; the reviewer makes the final decision in the dashboard.
        self.report["review_label"] = "review"
        self.report["review_label_ar"] = "بانتظار تصنيف المراجع في لوحة التحكم"
        if hasattr(self, "status"):
            self.status.set(self._t("جارٍ إرسال التقرير بعد موافقتك…", "Sending the report with your consent…"))
        if hasattr(self, "delivery_message"):
            self.delivery_message.set("SENDING REPORT TO INSPECTOR...")
        try:
            import urllib.request
            endpoint = self.active_dashboard_url.rstrip("/") + "/api/v1/session-report"
            if hasattr(self, "status"):
                self.status.set(self._t("جارٍ إرسال التقرير إلى لوحة المسؤول…", "Sending report to the inspector dashboard…"))
            # Include the screenshot only when it was successfully captured after
            # explicit acceptance of the screenshot disclosure in the consent terms.
            if getattr(self, "desktop_screenshot_base64", None):
                self.report["desktop_screenshot_base64"] = self.desktop_screenshot_base64
                self.report["desktop_screenshot_captured_at"] = self.desktop_screenshot_captured_at
                self.report["desktop_screenshot_status"] = "captured"
            else:
                self.report["desktop_screenshot_status"] = getattr(self, "desktop_screenshot_status", "not_captured")
            summary_text = (
                f"{self.report['review_label_ar']} — {self.report['indicator_match_count']} مؤشرات عمليات "
                f"و{self.report.get('file_indicator_match_count', 0)} مؤشرات ملفات للمراجعة"
            ) if self.lang == "ar" else (
                f"Awaiting inspector review — {self.report['indicator_match_count']} process indicators "
                f"and {self.report.get('file_indicator_match_count', 0)} file indicators"
            )
            payload = {"session_code": self.active_session_code,
                       "computer_label": self.report["device_label"],
                       "summary": summary_text,
                       "report": self.report}
            req = urllib.request.Request(endpoint, data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=90) as response:
                result = json.loads(response.read().decode("utf-8"))
            self.report["dashboard_report_id"] = result.get("report_id")
            self.delivery_status = "sent"
            if hasattr(self, "status"):
                self.status.set(self._t("تم إرسال التقرير تلقائيًا إلى لوحة التحكم.", "The report was securely sent to the inspector dashboard."))
            if hasattr(self, "delivery_message"):
                self.delivery_message.set("REPORT SENT TO INSPECTOR")
            if hasattr(self, "retry_report_button"):
                self.retry_report_button.pack_forget()
            # The scanned person sees completion only; detailed findings stay in the dashboard.
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read(1200).decode("utf-8", errors="replace").strip()
            except Exception:
                detail = ""
            self.delivery_status = "failed: HTTP " + str(exc.code)
            if hasattr(self, "status"):
                self.status.set("تعذر إرسال التقرير (HTTP " + str(exc.code) + "). " + (detail[:180] if detail else "تحقق من الاتصال."))
            if hasattr(self, "delivery_message"):
                self.delivery_message.set("REPORT NOT SENT — CONTACT INSPECTOR")
            if hasattr(self, "retry_report_button"):
                self.retry_report_button.pack(pady=(0, 8))
        except Exception as exc:
            self.delivery_status = "failed: " + type(exc).__name__
            if hasattr(self, "status"):
                self.status.set("تعذر الإرسال: " + type(exc).__name__ + ". تحقق من الاتصال.")
            if hasattr(self, "delivery_message"):
                self.delivery_message.set("REPORT NOT SENT — CHECK CONNECTION")
            if hasattr(self, "retry_report_button"):
                self.retry_report_button.pack(pady=(0, 8))

    def export_pdf(self):
        if not self.report:
            messagebox.showinfo(APP, "ابدأ الفحص أولاً.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                    filetypes=[("PDF report", "*.pdf")], initialfile="3EN-Inspect-Full-Report.pdf")
        if not path:
            return
        try:
            from xml.sax.saxutils import escape
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

            report = self.report
            language = self.lang
            T = lambda ar, en: ar if language == "ar" else en
            pdf_font = "Helvetica"
            reshape_arabic = None
            if language == "ar":
                from reportlab.pdfbase import pdfmetrics
                from reportlab.pdfbase.ttfonts import TTFont
                font_candidates = [
                    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arial.ttf"),
                    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "tahoma.ttf"),
                    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                    "/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf",
                ]
                font_path = next((p for p in font_candidates if os.path.isfile(p)), None)
                if not font_path:
                    raise RuntimeError("Arabic PDF font not found. Install Arial, Tahoma, or DejaVu Sans.")
                pdfmetrics.registerFont(TTFont("3ENArabic", font_path))
                pdf_font = "3ENArabic"
                try:
                    import arabic_reshaper
                    from bidi.algorithm import get_display
                    reshape_arabic = lambda value: get_display(arabic_reshaper.reshape(str(value)))
                except ImportError:
                    raise RuntimeError("Arabic PDF support is missing. Install arabic-reshaper and python-bidi.")
            def pdf_text(value):
                value = str(value if value not in (None, "") else "—")
                if language == "en":
                    for ar, en in {
                        "ملفات FiveM وGTA V": "FiveM / GTA V files",
                        "سجلات FiveM وCitizenFX": "FiveM / CitizenFX logs",
                        "سكربتات وإعدادات FiveM": "FiveM scripts and settings",
                        "آثار ملفات محذوفة": "Deleted-file traces",
                        "ملفات برامج المستخدم": "User application files",
                        "مؤشرات هاك/غش": "Cheat indicators",
                        "مؤشرات اسمية تحتاج مراجعة": "Name-based indicators — review required",
                        "ملف محذوف — بيانات وصفية فقط": "Deleted file — metadata only",
                        "مؤشرات حركة": "Movement indicators",
                        "لا توجد مطابقة اسمية": "No name match",
                        "لم يتم التحقق": "Not checked",
                        "لم يتم التحقق من توقيع الملف المحذوف": "Deleted file signature not checked",
                        "مطابقة اسمية/مسارية فقط؛ يلزم التحقق من الملف والسياق قبل أي استنتاج.": "Name/path match only; verify the file and context before drawing conclusions."
                    }.items():
                        value = value.replace(ar, en)
                    return value
                return reshape_arabic(value) if reshape_arabic else value
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name="BrandTitle", parent=styles["Title"], textColor=colors.HexColor("#b51f3b"), fontSize=22, leading=27, spaceAfter=4, fontName=pdf_font, alignment=2 if language == "ar" else 0))
            styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading2"], textColor=colors.HexColor("#8f1830"), spaceBefore=10, spaceAfter=5, fontName=pdf_font, alignment=2 if language == "ar" else 0))
            styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7, leading=9, wordWrap="CJK", fontName=pdf_font, alignment=2 if language == "ar" else 0))
            styles.add(ParagraphStyle(name="MutedNote", parent=styles["BodyText"], textColor=colors.HexColor("#555555"), fontSize=8, leading=11, fontName=pdf_font, alignment=2 if language == "ar" else 0))
            styles["Heading2"].fontName = pdf_font
            styles["Heading2"].alignment = 2 if language == "ar" else 0
            styles["Title"].fontName = pdf_font
            doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=13*mm, leftMargin=13*mm, topMargin=15*mm, bottomMargin=15*mm)
            story = [
                Paragraph("3EN INSPECT", styles["BrandTitle"]),
                Paragraph(pdf_text(T("تقرير فحص أمني", "Security Inspection Report")), styles["Heading2"]),
                Paragraph(pdf_text(T("وقت إنشاء التقرير — توقيت السعودية: ", "Report generated — Saudi Arabia time: ") + format_saudi_time(report.get("created_at"), language)), styles["MutedNote"]),
                Spacer(1, 5*mm)
            ]

            processes = report.get("processes", [])
            artifacts = report.get("file_artifacts", [])
            recent_apps = report.get("recent_apps_24h", [])
            recent_files = report.get("recent_files", [])
            deleted = [x for x in artifacts if x.get("scan_group") == "آثار ملفات محذوفة"]
            game_evidence = [x for x in artifacts if x.get("scan_group") in {
                "ملفات FiveM وGTA V", "سجلات FiveM وCitizenFX", "سكربتات وإعدادات FiveM"
            }]
            flagged_processes = [x for x in processes if x.get("indicator_matches")]
            flagged_files = [x for x in artifacts if x.get("indicator_matches")]

            summary = [
                [T("الجهاز", "Device"), str(report.get("device_label", "Unknown"))],
                [T("نظام التشغيل", "Operating system"), str(report.get("platform", "Unknown"))[:150]],
                [T("العمليات الجارية", "Running processes"), str(len(processes))],
                [T("مؤشرات العمليات", "Process indicators"), str(len(flagged_processes))],
                [T("ملفات ذات مؤشرات فريدة", "Unique indicator files"), str(report.get("unique_indicator_file_count", len(flagged_files)))],
                [T("قرائن عالية الثقة ومتوافقة", "High-confidence corroborated findings"), str(report.get("high_confidence_finding_count", 0))],
                [T("قرائن متوسطة الثقة", "Medium-confidence findings"), str(report.get("medium_confidence_finding_count", 0))],
                [T("قرائن منخفضة الثقة (مراجعة يدوية)", "Low-confidence leads (manual review)"), str(report.get("low_confidence_finding_count", 0))],
                [T("عناصر FiveM / GTA V", "FiveM / GTA V artifacts"), str(len(game_evidence))],
                [T("ملفات لعبة تم حساب بصمتها", "Game binaries hashed"), str((report.get("binary_analysis") or {}).get("binary_files_hashed", 0))],
                [T("مؤشرات ثابتة داخل الملفات الثنائية", "Binary static indicator hits"), str((report.get("binary_analysis") or {}).get("binary_indicator_files", 0))],
                [T("ملفات بها مؤشرات", "Files with indicators"), str(len(flagged_files))],
                [T("سجلات ملفات محذوفة (سلة المحذوفات)", "Deleted-file records (Recycle Bin)"), str(len(deleted))],
                [T("برامج لها سجل تشغيل خلال 24 ساعة", "Apps with execution evidence in last 24 hours"), str(len(recent_apps))],
                [T("اختصارات Windows الحديثة", "Windows Recent shortcuts"), str(len(recent_files))]
            ]
            summary = [[pdf_text(a), pdf_text(b)] for a, b in summary]
            table = Table(summary, colWidths=[62*mm, 112*mm], hAlign="RIGHT" if language == "ar" else "LEFT")
            table.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#f8e6ea")),
                ("TEXTCOLOR",(0,0),(0,-1),colors.HexColor("#86152b")),
                ("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#d6d6d6")),
                ("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),6),
                ("FONTSIZE",(0,0),(-1,-1),8)
            ]))
            story.extend([Paragraph(pdf_text(T("الملخص التنفيذي", "Executive summary")), styles["SectionTitle"]), table])

            def cell(value, limit=500):
                return Paragraph(escape(pdf_text(str(value if value not in (None, "") else "—"))[:limit]), styles["SmallCell"])

            def add_section(title, rows, headers, widths, empty_note, cap=80):
                story.append(Paragraph(pdf_text(title), styles["SectionTitle"]))
                if not rows:
                    story.append(Paragraph(pdf_text(empty_note), styles["MutedNote"]))
                    return
                data = [[cell(h, 80) for h in headers]]
                for row in rows[:cap]:
                    data.append([cell(value) for value in row])
                t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
                t.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#25111a")),
                    ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                    ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cccccc")),
                    ("VALIGN",(0,0),(-1,-1),"TOP"),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#faf6f7")]),
                    ("FONTSIZE",(0,0),(-1,-1),7),("LEFTPADDING",(0,0),(-1,-1),4),
                    ("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),5),
                    ("BOTTOMPADDING",(0,0),(-1,-1),5)
                ]))
                story.append(t)
                if len(rows) > cap:
                    story.append(Paragraph(pdf_text(T("يعرض هذا القسم أول ", "Showing first ") + str(cap) + T(" من أصل ", " of ") + str(len(rows)) + T(" عنصرًا في هذا القسم. بقية البيانات محفوظة في التقرير الكامل بلوحة التحكم.", " entries in this section. Full structured evidence remains in the dashboard report.")), styles["MutedNote"]))

            story.append(Paragraph(pdf_text(T("نتائج FiveM / GTA V","FiveM / GTA V findings")), styles["SectionTitle"]))
            add_section(T("ملفات اللعبة والسجلات والموارد","Game files, logs and resource scripts"), [
                (x.get("scan_group"), x.get("file_name"), x.get("indicator_category"),
                 ", ".join(x.get("indicator_matches", [])),
                 "SHA-256: " + str(x.get("sha256") or "not calculated") +
                 " | Signature: " + str(x.get("signature_label") or "not checked") +
                 " | " + str(x.get("evidence_reason") or x.get("path") or ""))
                for x in game_evidence
            ], [T("مجموعة الدليل","Evidence group"), T("الملف","File"), T("التقييم","Assessment"), T("المؤشرات المطابقة","Matched indicators"), T("السياق / المسار","Context / path")],
            [30*mm, 34*mm, 30*mm, 35*mm, 45*mm],
            T("لم يتم جمع أدلة FiveM/GTA V من المواقع التي شملها الفحص.","No FiveM/GTA V evidence rows were collected in the scanned locations."))

            add_section(T("مؤشرات العمليات التي تحتاج مراجعة","Suspicious process leads"), [
                (x.get("process_name"), x.get("pid"), x.get("indicator_category"),
                 ", ".join(x.get("indicator_matches", [])), x.get("executable_path", ""))
                for x in flagged_processes
            ], [T("العملية","Process"), "PID", T("الفئة","Category"), T("المؤشرات","Indicators"), T("مسار التشغيل","Executable path")],
            [30*mm, 12*mm, 28*mm, 42*mm, 62*mm],
            T("لم تتطابق أسماء العمليات مع المؤشرات المحددة؛ وهذا لا يثبت خلو الجهاز من الغش.","No configured process-name indicators matched. This is not proof that no cheat is present."))

            add_section(T("ملفات ذات مؤشرات اسمية","Files with name-based indicators"), [
                (x.get("scan_group"), x.get("file_name"), ", ".join(x.get("indicator_matches", [])),
                 x.get("signature_label", ""), x.get("path", x.get("file_path", "")))
                for x in flagged_files
            ], [T("المجموعة","Group"), T("الملف","File"), T("المؤشرات","Indicators"), T("التوقيع","Signature"), T("المسار / المصدر","Path / source")],
            [27*mm, 32*mm, 38*mm, 30*mm, 47*mm],
            T("لم تتطابق أسماء الملفات مع المؤشرات المحددة.","No configured file-name indicators matched."))

            add_section(T("أدلة الملفات المحذوفة — سلة المحذوفات فقط","Deleted-file evidence — Recycle Bin only"), [
                (x.get("file_name"), x.get("extension"), format_saudi_time(x.get("deleted_at"), language),
                 T("نعم", "Yes") if x.get("recycle_payload_present") else T("لا", "No"),
                 x.get("evidence_reason", ""))
                for x in deleted
            ], [T("الملف المحذوف","Deleted file"), T("النوع","Type"), T("وقت الحذف — السعودية","Deletion time — Saudi Arabia"), T("المحتوى ما زال بالسلة","Payload in bin"), T("التفسير","Interpretation")],
            [32*mm, 18*mm, 35*mm, 22*mm, 67*mm],
            T("لم يتم العثور على سجلات حذف مطابقة في المواقع التي فُحصت.","No matching deleted-file metadata was found in the scanned Recycle Bin locations."), cap=max(80, len(deleted)))

            add_section(T("البرامج النشطة / سجلات التشغيل — آخر 24 ساعة","Apps active / execution evidence — last 24 hours"), [
                (x.get("app_name"), (x.get("last_seen_display") or "") + ((" · " + T("وقت بدء العملية: ", "Process start: ") + str(x.get("process_started_display"))) if x.get("currently_running") and x.get("process_started_display") else "") + ((" · " + T("وقت الحذف المسجل: ", "Recycle Bin deletion time: ") + format_saudi_time(x.get("deleted_at"), language)) if x.get("deleted_file_name_match") and x.get("deleted_at") else ""), x.get("evidence_source"),
                 T("يعمل الآن", "Currently running") if x.get("currently_running") else T("سجل تشغيل تقريبي", "Approximate execution record"),
                 ", ".join(x.get("indicator_matches", [])))
                for x in recent_apps
            ], [T("البرنامج","Application"), T("الوقت — السعودية","Time — Saudi Arabia"), T("مصدر الدليل","Evidence source"), T("الحالة","Status"), T("المؤشرات","Indicators")],
            [32*mm, 32*mm, 43*mm, 30*mm, 37*mm],
            T("لم تتوفر عمليات جارية أو سجلات Prefetch ضمن آخر 24 ساعة.","No current process or Prefetch entries were available."), cap=max(80, len(recent_apps)))

            add_section(T("مجلد Windows Recent — الاختصارات الحديثة","Windows Recent folder — recent shortcuts"), [
                (x.get("file_name"), x.get("last_accessed_display"),
                 x.get("target_path") or x.get("recent_shortcut_path"),
                 x.get("evidence_source", ""))
                for x in recent_files
            ], [T("الملف / الهدف","File / target"), T("وقت الاختصار — السعودية","Shortcut time — Saudi Arabia"), T("الهدف أو الاختصار","Resolved target or shortcut"), T("مصدر الدليل","Evidence source")],
            [35*mm, 34*mm, 70*mm, 35*mm],
            T("لا توجد اختصارات متاحة في مجلد Windows Recent.","No shortcut entries were available in the Windows Recent folder."), cap=max(80, len(recent_files)))

            story.extend([
                Spacer(1, 5*mm),
                Paragraph(pdf_text(T("نطاق الفحص والقيود","Scope and limitations")), styles["SectionTitle"]),
                Paragraph(pdf_text(T("هذا فحص موجّه ومحدود لمواقع FiveM وCitizenFX وGTA V الشائعة، ومجلدات مستخدم وبرامج محددة، والعمليات الجارية، وسجلات وملفات موارد مختارة، وبيانات Windows Prefetch وRecent وسلة المحذوفات. لا يفحص كل المواقع أو كل أنواع الغش ولا يضمن اكتشافها جميعًا.", "This is a targeted, bounded inspection of common FiveM, CitizenFX and GTA V locations, selected user/application folders, running processes, selected text logs and resource files, Windows Prefetch metadata, the Windows Recent shortcut folder, and Windows Recycle Bin metadata. It does not inspect every location or every possible cheat, and it cannot guarantee detection of all cheats.")), styles["MutedNote"]),
                Paragraph(pdf_text(T("وقت اختصار Recent لا يثبت وحده أن الملف فُتح. أوقات Prefetch قرائن تشغيل تقريبية وقد لا تتوفر. سجلات سلة المحذوفات تشمل العناصر التي ما زالت بياناتها موجودة فقط؛ لا تتم استعادة الملفات المحذوفة نهائيًا. لا يتم تشغيل الملفات أو تعديلها أو رفع محتواها. تُحلل ملفات السجلات والموارد محليًا، وتُحفظ أسماء المؤشرات وأرقام الأسطر فقط. المؤشرات تستلزم مراجعة بشرية ولا تثبت الغش، والتوقيع الرقمي الصحيح لا يضمن سلامة البرنامج.", "A Recent shortcut timestamp is not definitive proof that a file was opened. Prefetch timestamps are approximate execution evidence and may be unavailable. Recycle Bin records cover items still represented by Windows Recycle Bin metadata only; permanently deleted files are not recovered. Files are not executed, deleted, modified, or uploaded as content. Log/resource text is analyzed locally; only matched indicator names and line numbers are retained. Indicators are leads for human review, not proof of cheating. A valid digital signature does not guarantee software is safe.")), styles["MutedNote"]),
                Paragraph(pdf_text(T("3EN Inspect Team — الحقوق محفوظة","3EN Inspect Team — All rights reserved")), styles["MutedNote"])
            ])
            def draw_client_pdf_footer(canvas_obj, doc_obj):
                canvas_obj.saveState()
                canvas_obj.setFont(pdf_font, 8)
                canvas_obj.setFillColor(colors.HexColor("#777777"))
                canvas_obj.drawCentredString(A4[0] / 2, 8 * mm, "BY:ROITH")
                canvas_obj.restoreState()

            doc.build(story, onFirstPage=draw_client_pdf_footer, onLaterPages=draw_client_pdf_footer)
            messagebox.showinfo(APP, self._t("تم تصدير تقرير الفحص الكامل PDF بنجاح.", "The full inspection PDF report was exported successfully."))
        except Exception as exc:
            messagebox.showerror(APP, "PDF export failed: " + str(exc))



def set_windows_app_identity():
    """Give Windows a stable 3EN identity so the branded EXE icon is used on the taskbar."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("3EN.Inspect.Team")
    except Exception:
        # The window icon below remains the fallback if Windows rejects the AppUserModelID.
        pass


if __name__ == "__main__":
    # PyInstaller --windowed builds need an explicit GUI entry point.
    try:
        set_windows_app_identity()
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
