"""
3eN Inspect Team — transparent local inspection client.
Collects process metadata, 24-hour app activity, file metadata, and Windows Authenticode status.
An optional desktop screenshot is captured only after separate user consent.
Run: python inspector_client.py
"""
import base64
import hashlib
import io
import json
import os
import platform
import re
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
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


def collect_files(progress, max_files=50000):
    """Collect file/folder metadata from C:/D:. Never execute or open files/archives."""
    import time

    allowed_extensions = {".exe", ".dll", ".zip", ".rar", ".rpf", ".meta", ".lua", ".cfg", ".pdf"}
    primary_extensions = {".exe", ".dll", ".zip", ".rar"}
    excluded_dirs = {
        "windows", "$recycle.bin", "system volume information", "perflogs",
        "recovery", "config.msi", "winsxs", "servicing", "softwaredistribution",
        "node_modules", ".git", "__pycache__", "cache", "caches", "windowsapps"
    }
    roots = [f"{drive}:\\" for drive in ("C", "D") if os.path.isdir(f"{drive}:\\")]
    candidates, seen = [], set()
    started = time.monotonic()
    for root in roots:
        for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
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
            for dirname in dirs:
                folder = os.path.join(current, dirname)
                matches = find_indicator_matches(dirname, folder)
                context_flags = ["Mods/AI folder context"] if dirname.casefold() in {"mods", "ai"} else []
                if matches or context_flags:
                    key = os.path.normcase(os.path.abspath(folder))
                    if key not in seen:
                        seen.add(key)
                        try:
                            candidates.append(("folder", folder, os.stat(folder)))
                        except OSError:
                            pass
            for name in names:
                path = os.path.join(current, name)
                extension = os.path.splitext(name)[1].casefold()
                matches = find_indicator_matches(name, current)
                in_mods_ai = any(part.casefold() in {"mods", "ai"} for part in Path(current).parts)
                # Include any filename matching a supplied indicator, regardless of extension.
                # Inventory all file types inside Mods/AI folders as requested; metadata only.
                if extension not in allowed_extensions and not matches and not in_mods_ai:
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
                if len(candidates) >= max_files or time.monotonic() - started > 300:
                    break
            if len(candidates) >= max_files or time.monotonic() - started > 300:
                break
        if len(candidates) >= max_files or time.monotonic() - started > 300:
            break

    rows = []
    total = max(len(candidates), 1)
    for i, (kind, path, st) in enumerate(candidates, 1):
        name = os.path.basename(path)
        matches = find_indicator_matches(name, path)
        context_flags = ["Mods/AI folder context"] if any(part.casefold() in {"mods", "ai"} for part in Path(path).parts) else []
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
            progress(50 + int(i * 20 / total), f"فحص الملفات والمجلدات... {i}/{total}")
    rows.sort(key=lambda row: row.get("modified_at") or "", reverse=True)
    return rows


def collect_recent_apps(processes, progress):
    """Show apps started in the last 24h plus recent Windows Prefetch metadata."""
    import time

    cutoff = time.time() - 24 * 60 * 60
    recent = []
    seen = set()
    for proc in processes:
        try:
            started = datetime.fromisoformat(str(proc.get("process_started_at") or "").replace("Z", "+00:00"))
            if started.timestamp() < cutoff:
                continue
        except (ValueError, TypeError, OSError):
            continue
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
            "indicator_matches": proc.get("indicator_matches", []),
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
                        recent.append({
                            "app_name": app_name, "file_name": entry.name,
                            "path": entry.path, "last_seen_at": utc_timestamp(st.st_mtime),
                            "last_seen_display": local.strftime("%B %d, %Y %I:%M:%S %p"),
                            "evidence_source": "Windows Prefetch (.pf) — قرينة تشغيل تقريبية",
                            "time_accuracy": "approximate_prefetch_timestamp",
                            "indicator_matches": find_indicator_matches(app_name, entry.name),
                            "signature_status": "not_checked",
                            "signature_label": "بيانات سجل تشغيل، لا ينطبق عليها توقيع ملف التطبيق"
                        })
                    except OSError:
                        continue
        except OSError:
            pass
    recent.sort(key=lambda row: row.get("last_seen_at") or "", reverse=True)
    progress(75, f"اكتمل تجميع التطبيقات خلال آخر 24 ساعة: {len(recent)}")
    return recent


def verify_authenticode_signatures(processes, artifacts, progress, max_checks=2000):
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
    for offset in range(0, len(check_paths), 200):
        batch = check_paths[offset:offset + 200]
        try:
            result = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                input=json.dumps(batch), capture_output=True, text=True, timeout=55,
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
                    label = "موثق — " + (str(item.get("publisher") or "ناشر معتمد من Windows")[:160])
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
            progress(75 + int(checked * 10 / max(len(check_paths), 1)), f"التحقق من مصدر البرامج... {checked}/{len(check_paths)}")
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


def capture_desktop_screenshot():
    """Capture a resized JPEG only after separate user consent."""
    try:
        from PIL import ImageGrab
        image = ImageGrab.grab(all_screens=True)
        image.thumbnail((1600, 900))
        output = io.BytesIO()
        image.convert("RGB").save(output, format="JPEG", quality=55, optimize=True)
        data = output.getvalue()
        if len(data) > 5500000:
            raise RuntimeError("Screenshot is too large to upload.")
        return base64.b64encode(data).decode("ascii")
    except Exception as exc:
        raise RuntimeError("تعذر التقاط صورة سطح المكتب: " + type(exc).__name__) from exc


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
        progress(int(i * 100 / total), f"جمع بيانات العمليات {i}/{total}")
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
        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(consent_box,
            text="أوافق على فحص بيانات العمليات والتطبيقات المستخدمة خلال آخر 24 ساعة وبيانات الملفات في C: وD:، والتحقق من التوقيع الرقمي للبرامج، وإرسال الأسماء والمسارات والأحجام والتواريخ والبصمات وحالة التوثيق إلى لوحة التحكم. لا تُرسل محتويات الملفات.",
            variable=self.consent, bg=PANEL, fg=WHITE, selectcolor=PANEL_ALT,
            activebackground=PANEL, activeforeground=WHITE, wraplength=900,
            font=("Segoe UI", 10), relief="flat", padx=0).pack(anchor="w", pady=(7, 0))
        self.screenshot_consent = tk.BooleanVar(value=False)
        tk.Checkbutton(consent_box,
            text="أوافق بشكل منفصل على التقاط صورة كاملة لسطح المكتب وإرفاقها بالتقرير المرسل إلى لوحة التحكم. قد تظهر بالصورة نوافذ أو معلومات شخصية.",
            variable=self.screenshot_consent, bg=PANEL, fg=AMBER, selectcolor=PANEL_ALT,
            activebackground=PANEL, activeforeground=WHITE, wraplength=900,
            font=("Segoe UI", 10, "bold"), relief="flat", padx=0).pack(anchor="w", pady=(9, 0))


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

    def _completion_marker_path(self):
        # Per-user, per-session marker. The user can remove it to reset the session.
        root = os.environ.get("APPDATA") or os.path.expanduser("~")
        code_hash = hashlib.sha256(str(SESSION_CODE).encode("utf-8")).hexdigest()[:20]
        return os.path.join(root, "3eN Inspect Team", "completed-" + code_hash + ".json")

    def _close_then_offer_folder(self):
        # Close the UI without launching a second process or changing user files.
        self.destroy()

    def start(self):
        marker = self._completion_marker_path()
        if os.path.isfile(marker):
            messagebox.showinfo(APP, "تم الانتهاء من فحصك مسبقًا. لن تتم إعادة الفحص لهذه الجلسة.")
            self.destroy()
            return
        if not self.consent.get():
            messagebox.showwarning(APP, "Please confirm consent before starting.")
            return
        screenshot_notice = "\\nستُلتقط صورة لسطح المكتب وتُرسل مع التقرير." if self.screenshot_consent.get() else "\\nلن تُلتقط أي صورة."
        if not messagebox.askyesno(APP, "سيتم فحص العمليات والتطبيقات المستخدمة خلال آخر 24 ساعة، وملفات C: وD:، والتحقق من التوقيعات الرقمية للبرامج. ستُرسل الأسماء والمسارات والأحجام والتواريخ والبصمات وحالة التوثيق فقط، دون إرسال محتويات الملفات." + screenshot_notice + "\\nلن تُعدّل الملفات أو تُنهى العمليات. هل توافق على المتابعة؟"):
            return
        # Session-specific builds contain the session code and dashboard URL.
        # Never prompt the scanned person to enter either value.
        self.active_session_code = str(SESSION_CODE or "").strip().upper()
        self.active_dashboard_url = str(DASHBOARD_URL or "").strip().rstrip("/")
        self.include_desktop_screenshot = bool(self.screenshot_consent.get())
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
            verify_authenticode_signatures(processes, files, self.update_progress)
            recent_apps = collect_recent_apps(processes, self.update_progress)
            matches = [p for p in processes if p["indicator_matches"]]
            file_matches = [item for item in files if item["indicator_matches"]]
            desktop_screenshot = capture_desktop_screenshot() if self.include_desktop_screenshot else None
            self.report = {
                "product": APP,
                "signature": "3eN INSPECT TEAM",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "device_label": platform.node()[:100] or "Unknown",
                "platform": platform.platform()[:200],
                "scan_scope": "C: and D: drives excluding Windows/system folders; EXE/DLL/ZIP/RAR and matching RPF/META/LUA/CFG/PDF; recent app evidence from running processes and Windows Prefetch metadata within 24 hours; Authenticode verification for EXE/DLL; metadata only, archives are not opened, and file contents are never uploaded",
                "process_count": len(processes),
                "indicator_match_count": len(matches),
                "file_count": len(files),
                "file_artifact_count": len(files),
                "file_indicator_match_count": len(file_matches),
                "file_artifacts": files,
                "recent_apps_24h": recent_apps,
                "recent_apps_24h_count": len(recent_apps),
                "signature_verified_count": sum(1 for row in list(processes) + list(files) if row.get("signature_status") == "verified"),
                "signature_unverified_count": sum(1 for row in list(processes) + list(files) if row.get("signature_status") == "unverified"),
                "desktop_screenshot_base64": desktop_screenshot,
                "game_process_context": sorted({game for proc in processes for game in proc.get("game_context", [])}),
                "note": "Configured names are indicators for manual review, not proof of cheating. Recent apps include processes started within the last 24 hours and Windows Prefetch file timestamps, which are approximate evidence and may be unavailable if Prefetch is disabled. Valid Authenticode signatures identify a verified publisher but do not prove a program is harmless or cheat-free. Unsigned, invalid, unsupported, or unchecked files are labeled separately. File scan covers C: and D: excluding Windows/system folders; archives are not opened and file contents are never uploaded. Dates are retained in UTC and local display format. Desktop screenshot is included only after separate opt-in. No files are modified and no processes are terminated.",
                "processes": processes,
            }
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
            payload = {"session_code": self.active_session_code,
                       "computer_label": self.report["device_label"],
                       "summary": f"{self.report['review_label_ar']} — {self.report['indicator_match_count']} مؤشرات عمليات و{self.report.get('file_indicator_match_count', 0)} مؤشرات ملفات للمراجعة",
                       "report": self.report}
            req = urllib.request.Request(endpoint, data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=25) as response:
                result = json.loads(response.read().decode("utf-8"))
            self.report["dashboard_report_id"] = result.get("report_id")
            self.delivery_status = "sent"
            self.metric_state.set("SENT")
            self.session_badge.configure(text="●  تم الإرسال", bg="#142b28", fg="#62e0b0")
            self.status.set("تم إرسال التقرير تلقائيًا إلى لوحة التحكم.")
            marker = self._completion_marker_path()
            try:
                os.makedirs(os.path.dirname(marker), exist_ok=True)
                with open(marker, "w", encoding="utf-8") as marker_file:
                    json.dump({
                        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "session_code_hash": hashlib.sha256(str(SESSION_CODE).encode("utf-8")).hexdigest()
                    }, marker_file)
            except OSError:
                self.status.set("تم إرسال التقرير، لكن تعذر حفظ منع إعادة الفحص على هذا الجهاز.")
            self.start_button.configure(state="disabled")
            self.after(1200, self._close_then_offer_folder)
        except Exception as exc:
            self.delivery_status = "failed: " + type(exc).__name__
            self.session_badge.configure(text="●  تعذر الإرسال", bg="#351521", fg="#ff8093")
            self.status.set("تعذر الإرسال. تحقق من الاتصال والجلسة.")

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
    InspectorApp().mainloop()
