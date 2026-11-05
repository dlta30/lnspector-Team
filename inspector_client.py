"""
3eN Inspect Team — transparent local inspection client.
Scans process metadata and Downloads/Recent file metadata and hashes, excluding .txt files.
An optional desktop screenshot is captured only after separate user consent.
Run: python inspector_client.py
"""
import base64
import hashlib
import io
import json
import os
import platform
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from datetime import datetime, timezone

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


def collect_files(progress, max_files=50000):
    """Inventory EXE/DLL/ZIP/RAR and suspiciously named folders on C:/D:.
    Collect metadata only; never open archives or execute files.
    """
    import time

    allowed_extensions = {".exe", ".dll", ".zip", ".rar", ".rpf", ".meta", ".lua", ".cfg", ".pdf"}
    primary_extensions = {".exe", ".dll", ".zip", ".rar"}
    excluded_dirs = {
        "windows", "$recycle.bin", "system volume information", "perflogs",
        "recovery", "config.msi", "winsxs", "servicing", "softwaredistribution",
        "node_modules", ".git", "__pycache__", "cache", "caches", "windowsapps"
    }
    indicators = tuple(dict.fromkeys(SUSPICIOUS_TERMS + (
        "eulen", "menyo", "tiago", "tiago modz", "taigomodz", "falloutmenu",
        "cobramenu", "lux menu", "dopamine menu", "lua menu", "phantom",
        "monstermenu", "chiken's menu", "mysterious", "zentrix", "lambda",
        "lamda", "vmenu", "fivesense_v2", "swoopiexyz", "kekhack", "nitwit",
        "rely", "nove store", "redengine", "red engine", "hack_fivem",
        "fivem mod menu", "mod gta", "modz gta", "fivem esp", "fivem wallhack",
        "fivem cheat no ban", "sleezy spoofer", "aura spoofer",
        "escape service hack", "fivemock", "duk_3", "loader.cfg", "loader.prod",
        "loader.global", "launcher", "lua injector", "lua executor",
        "gh injector", "extreme injector", "winject", "asi plugin bypass",
        "cheat engine", "cheatengine", "unknowncheats", "dumper", "decrypter",
        "bypass", "resource blocker", "memeproj.global", "loading.global",
        "rxexv3", "hjaldrgo", "ice breaker", "popstar", "lovex",
        "zc-firerate", "zc-mp_f_freemode", "zc-explosiveammo", "zc-pedlight",
        "zc-electricammo", "zc-pedabilities", "zc-increasedrange",
        "zc-weaponmodifier", "cr-fastrun", "zc-infiniteammo", "zc-damageboost",
        "zc-bulletpenetration", "no_recoil", "ladders.meta", "aml.lua",
        "fast_playboi_mods", "pedaccuracy.meta", "weaponcomponents.meta",
        "weaponanimation.meta", "bsk_skills", "quickenter", "ad movement",
        "filter key", "scod", "ali_unban_method", "0x32", "hazar", "loey",
        "loader", "menyo", "falloutmenu", "cobramenu", "five sense", "fivesense",
        "mysterious", "monster menu", "red engine", "resource blocker",
        "no recoil", "quickenter", "ad movement"
    )))
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
            # Report only folders whose names themselves match a configured indicator.
            for dirname in dirs:
                matches = [term for term in indicators if term in dirname.casefold()]
                if dirname.casefold() in {"mods", "ai"}:
                    matches.append("Mods/AI folder context")
                if matches:
                    folder = os.path.join(current, dirname)
                    key = os.path.normcase(os.path.abspath(folder))
                    if key not in seen:
                        seen.add(key)
                        try:
                            st = os.stat(folder)
                            candidates.append(("folder", folder, st))
                        except OSError:
                            pass
            for name in names:
                path = os.path.join(current, name)
                extension = os.path.splitext(name)[1].casefold()
                if extension not in allowed_extensions:
                    continue
                path_context = (name + " " + current).casefold()
                preliminary_matches = [term for term in indicators if term in path_context]
                if any(part.casefold() in {"mods", "ai"} for part in Path(current).parts):
                    preliminary_matches.append("Mods/AI folder context")
                # Non-primary formats are included only when their names/paths match a known indicator.
                if extension not in primary_extensions and not preliminary_matches:
                    continue
                try:
                    if os.path.islink(path) or not os.path.isfile(path):
                        continue
                    key = os.path.normcase(os.path.abspath(path))
                    if key in seen:
                        continue
                    seen.add(key)
                    st = os.stat(path)
                    candidates.append(("file", path, st))
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
        matches = [term for term in indicators if term in (name + " " + path).casefold()]
        if kind == "folder" and os.path.basename(path).casefold() in {"mods", "ai"}:
            matches.append("Mods/AI folder context")
        elif kind == "file" and any(part.casefold() in {"mods", "ai"} for part in Path(path).parts):
            matches.append("Mods/AI folder context")
        too_large = st.st_size > 250 * 1024 * 1024
        created = utc_timestamp(st.st_ctime)
        modified = utc_timestamp(st.st_mtime)
        try:
            local_modified = datetime.fromtimestamp(st.st_mtime).astimezone()
            display_date = local_modified.strftime("%B %d, %Y %I:%M:%S %p")
            local_created = datetime.fromtimestamp(st.st_ctime).astimezone()
            created_display = local_created.strftime("%B %d, %Y %I:%M:%S %p")
        except (ValueError, OSError, OverflowError):
            display_date = modified
            created_display = created
        digest = sha256_file(path) if kind == "file" and matches and not too_large else None
        rows.append({
            "artifact_type": kind,
            "file_name": name[:260],
            "path": path[:1500],
            "size_bytes": int(st.st_size),
            "created_at": created,
            "created_display": created_display,
            "modified_at": modified,
            "modified_display": display_date,
            "sha256": digest,
            "hash_skipped_large_file": too_large,
            "indicator_matches": matches,
            "assessment": "review" if matches else "metadata_only",
        })
        if i % 100 == 0 or i == total:
            progress(50 + int(i * 25 / total), f"فحص ملفات C وD... {i}/{total}")
    rows.sort(key=lambda row: row.get("modified_at") or "", reverse=True)
    return rows

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
    for i, proc in enumerate(processes, 1):
        try:
            info = proc.info
            name = str(info.get("name") or "Unknown")[:180]
            exe = str(info.get("exe") or "")[:1000]
            matches = [term for term in SUSPICIOUS_TERMS if term in (name + " " + exe).lower()]
            exists = bool(exe and os.path.isfile(exe))
            digest = sha256_file(exe) if exists else None
            file_created = file_modified = None
            if exists:
                try:
                    stat = os.stat(exe)
                    file_created = utc_timestamp(stat.st_ctime)
                    file_modified = utc_timestamp(stat.st_mtime)
                except OSError:
                    pass
            rows.append({
                "pid": info.get("pid"),
                "process_name": name,
                "file_name": os.path.basename(exe) if exe else name,
                "executable_path": exe or None,
                "process_started_at": utc_timestamp(info.get("create_time")),
                "file_created_at": file_created,
                "file_modified_at": file_modified,
                "sha256": digest,
                "indicator_matches": matches,
                "game_context": classify_game_context(name, exe),
                "assessment": "review" if matches else "no_name_match",
            })
        except (psutil.Error, OSError):
            continue
        progress(int(i * 100 / total), f"Checking process metadata {i}/{total}")
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
            text="أوافق على فحص بيانات العمليات وبيانات وبصمات الملفات داخل Downloads وRecent باستثناء ملفات TXT، وإرسال أسماء الملفات ومساراتها وأحجامها وتواريخها وبصماتها إلى لوحة التحكم. لا تُرسل محتويات الملفات.",
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
        if not messagebox.askyesno(APP, "سيتم فحص بيانات العمليات والملفات داخل Downloads وRecent باستثناء ملفات TXT. ستُرسل أسماء الملفات ومساراتها وأحجامها وتواريخها وبصماتها، دون إرسال محتويات الملفات." + screenshot_notice + "\\nلن تُعدّل الملفات أو تُنهى العمليات. هل توافق على المتابعة؟"):
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
            matches = [p for p in processes if p["indicator_matches"]]
            file_matches = [item for item in files if item["indicator_matches"]]
            desktop_screenshot = capture_desktop_screenshot() if self.include_desktop_screenshot else None
            self.report = {
                "product": APP,
                "signature": "3eN INSPECT TEAM",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "device_label": platform.node()[:100] or "Unknown",
                "platform": platform.platform()[:200],
                "scan_scope": "C: and D: drives, excluding Windows/system folders; EXE, DLL, ZIP, RAR and indicator-matching folder names; metadata and selected SHA-256 only; archives are not opened and file contents are never uploaded",
                "process_count": len(processes),
                "indicator_match_count": len(matches),
                "file_count": len(files),
                "file_artifact_count": len(files),
                "file_indicator_match_count": len(file_matches),
                "file_artifacts": files,
                "desktop_screenshot_base64": desktop_screenshot,
                "game_process_context": sorted({game for proc in processes for game in proc.get("game_context", [])}),
                "note": "Name/path indicators are leads for manual review, not proof of cheating. File scan covers C: and D: while excluding Windows/system folders. It inventories EXE, DLL, ZIP, RAR and matching folder names; archives are not opened and file contents are never uploaded. Dates are retained in UTC and local display format. Desktop screenshot is included only after separate opt-in. No files are modified and no processes are terminated. Manual review is required.",
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
