import csv
import hashlib
import json
import os
import platform
import subprocess
import threading
import time
import secrets
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "3EN INSPECTOR TEAM"
BYLINE = "by: ROITH"
REPORT_DIR = Path.home() / "Documents" / "3EN_Inspector_Team"
CONFIG_PATH = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "3EN_Inspector_Team" / "config.json"
EXTENSIONS = {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".asi", ".lua"}
TERMS = ("cheat engine", "aimbot", "wallhack", "injector", "mapper", "mod menu", "trainer", "memory editor", "hwid spoofer")
MAX_FILES = 12000
MAX_SECONDS = 90

BG = "#090a0f"
PANEL = "#12141c"
PANEL2 = "#191c27"
RED = "#ff4057"
TEXT = "#f4f5f8"
MUTED = "#969daf"
BORDER = "#292d3a"


def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(config):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")


def password_digest(password, salt):
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 250000).hex()


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def run_powershell(command, timeout=20):
    if os.name != "nt":
        return ""
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout, errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), shell=False
        )
        return p.stdout.strip() if p.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def inspect_processes():
    rows = []
    raw = run_powershell(
        "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress",
        25
    )
    if not raw:
        return [{"category":"Processes","item":"Process inventory unavailable","path":"","severity":"info",
                 "details":"Windows process inventory could not be read. Try running on Windows; no conclusion can be drawn."}]
    try:
        processes = json.loads(raw)
        if isinstance(processes, dict):
            processes = [processes]
        for p in processes[:1500]:
            name = str(p.get("Name") or "(unknown)")
            path = str(p.get("ExecutablePath") or "")
            matches = [term for term in TERMS if term in (name + " " + path).casefold()]
            rows.append({
                "category":"Processes", "item":f"{name} (PID {p.get('ProcessId', '?')})",
                "path":path, "severity":"review" if matches else "info",
                "details":("Generic name/path keyword match: " + ", ".join(matches) +
                           ". This is only a lead for human review, not proof of cheating.") if matches
                          else "Process observed. Presence alone is not evidence of cheating."
            })
    except (ValueError, TypeError):
        rows.append({"category":"Processes","item":"Could not parse process inventory","path":"","severity":"info","details":"No reliable result available."})
    return rows


def inspect_recent_files(progress):
    rows, seen = [], set()
    roots = []
    for key in ("TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        val = os.environ.get(key)
        if val:
            roots.append(Path(val))
    start = time.monotonic()
    examined = 0
    for root in roots:
        if not root.exists():
            continue
        try:
            for base, dirs, files in os.walk(root, topdown=True):
                dirs[:] = [d for d in dirs if d.casefold() not in {
                    "node_modules", ".git", "cache", "caches", "packages", "winsxs"
                }]
                for filename in files:
                    if examined >= MAX_FILES or time.monotonic() - start > MAX_SECONDS:
                        return rows, examined
                    path = Path(base) / filename
                    if path.suffix.casefold() not in EXTENSIONS:
                        continue
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    # Recent 45 days only; does not read file contents.
                    if time.time() - stat.st_mtime > 45 * 86400:
                        continue
                    norm = str(path).casefold()
                    if norm in seen:
                        continue
                    seen.add(norm)
                    examined += 1
                    low = (filename + " " + str(path)).casefold()
                    matches = [term for term in TERMS if term in low]
                    digest = sha256_file(path) if matches else ""
                    rows.append({
                        "category":"Recent files", "item":filename, "path":str(path),
                        "severity":"review" if matches else "info",
                        "details":("Filename/path contains review keyword(s): " + ", ".join(matches) +
                                   ". Name-based heuristic only; verify file source and signature.") if matches
                                  else "Recent executable/script file. No generic keyword match; this is not a malware verdict.",
                        "modified_utc":datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                        "size_bytes":stat.st_size, "sha256":digest
                    })
                    if examined % 100 == 0:
                        progress(min(85, int(examined / MAX_FILES * 85)), f"يفحص الملفات المحددة... {examined}")
        except (OSError, PermissionError):
            continue
    return rows, examined


def inspect_defender():
    raw = run_powershell(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress",
        15
    )
    if not raw:
        return [{"category":"Windows Security","item":"Defender status unavailable","path":"","severity":"info",
                 "details":"Could not read Microsoft Defender status. This does not mean protection is disabled."}]
    try:
        data = json.loads(raw)
        off = [key for key in ("AntivirusEnabled", "RealTimeProtectionEnabled") if data.get(key) is False]
        return [{"category":"Windows Security","item":"Microsoft Defender","path":"","severity":"review" if off else "info",
                 "details":("Reported protection flags disabled: " + ", ".join(off) if off else "Reported protection flags enabled") +
                 "; last signature update: " + str(data.get("AntivirusSignatureLastUpdated", "unknown"))}]
    except (ValueError, TypeError):
        return []


class InspectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} | {BYLINE}")
        self.root.geometry("1180x790")
        self.root.minsize(950, 650)
        self.root.configure(bg=BG)
        self.results = []
        self.report = None
        self.report_path = None
        self.config = load_config()
        self.busy = False
        self._setup_style()
        self._build()

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, foreground=TEXT, fieldbackground=PANEL,
                        rowheight=29, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=PANEL2, foreground=TEXT,
                        relief="flat", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#4a1c27")], foreground=[("selected", TEXT)])
        style.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2, foreground=TEXT)

    def _build(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=22, pady=(18, 12))
        mark = tk.Label(header, text="3", bg="#2a0d16", fg=RED, font=("Segoe UI", 25, "bold"), width=3, height=2)
        mark.pack(side="left", padx=(0, 14))
        brand = tk.Frame(header, bg=BG); brand.pack(side="left", fill="y")
        tk.Label(brand, text="3EN INSPECTOR TEAM", bg=BG, fg=TEXT, font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(brand, text="by: ROITH  •  PLAYER INSPECTION OPERATIONS", bg=BG, fg=RED, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(3, 0))
        tk.Label(header, text="CONSENT-BASED LOCAL INSPECTION", bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="right", anchor="n", pady=8)

        control = tk.Frame(self.root, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        control.pack(fill="x", padx=22, pady=(0, 12))
        tk.Label(control, text="جلسة التفتيش", bg=PANEL, fg=TEXT, font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        tk.Label(control, text="اسم اللاعب", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", padx=14)
        self.player = tk.StringVar()
        tk.Entry(control, textvariable=self.player, bg=PANEL2, fg=TEXT, insertbackground=TEXT, relief="flat",
                 font=("Segoe UI", 11), width=28).grid(row=2, column=0, sticky="ew", padx=14, pady=(5, 12), ipady=7)
        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(control, text="أؤكد أن صاحب الجهاز وافق على تشغيل الفحص", variable=self.consent,
                       bg=PANEL, fg=TEXT, selectcolor=PANEL2, activebackground=PANEL, activeforeground=TEXT,
                       font=("Segoe UI", 9)).grid(row=1, column=1, columnspan=2, sticky="w", padx=14)
        self.defender = tk.BooleanVar(value=False)
        tk.Checkbutton(control, text="طلب فحص سريع من Microsoft Defender", variable=self.defender,
                       bg=PANEL, fg=MUTED, selectcolor=PANEL2, activebackground=PANEL, activeforeground=TEXT,
                       font=("Segoe UI", 9)).grid(row=2, column=1, columnspan=2, sticky="w", padx=14)
        self.scan_btn = tk.Button(control, text="▶  بدء التفتيش", command=self.start_scan, bg=RED, fg="white",
                                  activebackground="#e72e49", activeforeground="white", relief="flat",
                                  font=("Segoe UI", 10, "bold"), padx=18, pady=10, cursor="hand2")
        self.scan_btn.grid(row=1, column=3, rowspan=2, padx=18, pady=12)
        control.grid_columnconfigure(0, weight=1)

        stats = tk.Frame(self.root, bg=BG); stats.pack(fill="x", padx=18, pady=(0, 12))
        self.total_label = self._stat(stats, "نتائج الفحص", "0")
        self.review_label = self._stat(stats, "مؤشرات للمراجعة", "0")
        self.status_label = self._stat(stats, "حالة النظام", "READY")

        progress_frame = tk.Frame(self.root, bg=BG); progress_frame.pack(fill="x", padx=22, pady=(0, 12))
        self.status = tk.Label(progress_frame, text="جاهز — أدخل اسم اللاعب وابدأ بموافقته", bg=BG, fg=MUTED, anchor="w")
        self.status.pack(fill="x")
        self.progress = ttk.Progressbar(progress_frame, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(7, 0))

        tools = tk.Frame(self.root, bg=BG); tools.pack(fill="x", padx=22, pady=(0, 8))
        tk.Label(tools, text="نتائج الفحص", bg=BG, fg=TEXT, font=("Segoe UI", 12, "bold")).pack(side="left")
        self.search = tk.StringVar()
        search = tk.Entry(tools, textvariable=self.search, bg=PANEL2, fg=TEXT, insertbackground=TEXT, relief="flat", width=28)
        search.pack(side="right", ipady=5)
        search.insert(0, "")
        self.filter = tk.StringVar(value="الكل")
        ttk.Combobox(tools, textvariable=self.filter, values=("الكل", "تحتاج مراجعة", "معلومات فقط"), state="readonly", width=15).pack(side="right", padx=8)
        self.search.trace_add("write", lambda *_: self.render())
        self.filter.trace_add("write", lambda *_: self.render())

        table_wrap = tk.Frame(self.root, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        table_wrap.pack(fill="both", expand=True, padx=22, pady=(0, 12))
        cols = ("severity", "category", "item", "path", "details")
        self.tree = ttk.Treeview(table_wrap, columns=cols, show="headings")
        headers = {"severity":"الحالة", "category":"الفحص", "item":"العنصر", "path":"المسار", "details":"التفاصيل"}
        widths = {"severity":90, "category":130, "item":190, "path":280, "details":380}
        for col in cols:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=widths[col], minwidth=70, anchor="w")
        self.tree.tag_configure("review", foreground="#ff7b8b")
        self.tree.tag_configure("info", foreground="#c6cbd6")
        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew"); yscroll.grid(row=0, column=1, sticky="ns"); xscroll.grid(row=1, column=0, sticky="ew")
        table_wrap.grid_rowconfigure(0, weight=1); table_wrap.grid_columnconfigure(0, weight=1)

        footer = tk.Frame(self.root, bg=BG); footer.pack(fill="x", padx=22, pady=(0, 14))
        tk.Button(footer, text="تصدير تقرير JSON", command=self.export_json, bg=PANEL2, fg=TEXT, relief="flat", padx=12, pady=7).pack(side="right")
        tk.Button(footer, text="تصدير CSV", command=self.export_csv, bg=PANEL2, fg=TEXT, relief="flat", padx=12, pady=7).pack(side="right", padx=8)
        tk.Button(footer, text="إعدادات Webhook", command=self.webhook_settings, bg=PANEL2, fg=TEXT, relief="flat", padx=12, pady=7).pack(side="left", padx=(0, 8))
        tk.Button(footer, text="إرسال التقرير إلى Discord", command=self.send_discord, bg="#5865F2", fg="white", relief="flat", padx=12, pady=7).pack(side="left", padx=(0, 8))
        tk.Button(footer, text="فتح مجلد التقارير", command=self.open_reports, bg=PANEL2, fg=TEXT, relief="flat", padx=12, pady=7).pack(side="left")
        tk.Label(footer, text="الاشتباه ليس إثباتًا • افحص المصدر والتوقيع قبل اتخاذ قرار", bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(side="left", padx=12)

    def _stat(self, parent, title, value):
        frame = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(side="left", fill="x", expand=True, padx=4)
        tk.Label(frame, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(8, 1))
        val = tk.Label(frame, text=value, bg=PANEL, fg=RED, font=("Segoe UI", 17, "bold"))
        val.pack(anchor="w", padx=12, pady=(0, 8))
        return val

    def start_scan(self):
        if self.busy:
            return
        if not self.consent.get():
            messagebox.showwarning("الموافقة مطلوبة", "لا يبدأ الفحص إلا بعد موافقة صاحب الجهاز.")
            return
        player = self.player.get().strip()
        if not player:
            messagebox.showwarning("اسم اللاعب مطلوب", "اكتب اسم اللاعب أو صاحب الجهاز.")
            return
        if not messagebox.askyesno("تأكيد بدء الفحص", "سيتم فحص قائمة العمليات وحالة Defender والملفات التنفيذية الحديثة في مجلدات المستخدم المحددة. لن تُرفع ملفات أو لقطات شاشة. هل تريد المتابعة؟"):
            return
        self.busy = True
        self.scan_btn.configure(state="disabled", text="جارٍ الفحص...")
        self.progress.configure(value=0)
        self.status.configure(text="بدء الفحص المحلي...")
        threading.Thread(target=self.worker, args=(player, self.defender.get()), daemon=True).start()

    def worker(self, player, run_defender):
        results = []
        try:
            self.root.after(0, lambda: self.status.configure(text="فحص العمليات الجارية..."))
            results.extend(inspect_processes())
            self.root.after(0, lambda: self.progress.configure(value=15))
            results.extend(inspect_defender())
            if run_defender:
                self.root.after(0, lambda: self.status.configure(text="إرسال طلب فحص سريع إلى Microsoft Defender..."))
                output = run_powershell("Start-MpScan -ScanType QuickScan; 'REQUESTED'", 900)
                results.append({"category":"Microsoft Defender","item":"Quick scan request","path":"","severity":"info" if output else "review",
                                "details":"تم إرسال طلب الفحص إلى Defender." if output else "تعذر تأكيد قبول الطلب. راجع تطبيق Windows Security."})
            self.root.after(0, lambda: self.progress.configure(value=25))
            files, count = inspect_recent_files(lambda p, msg: self.root.after(0, lambda p=p,msg=msg: self.update_progress(p, msg)))
            results.extend(files)
            report = {
                "product":APP_NAME, "by":BYLINE, "version":"1.0.0",
                "player":player, "device":platform.node(), "platform":platform.platform(),
                "created_at":datetime.now(timezone.utc).isoformat(),
                "result_count":len(results), "review_count":sum(1 for x in results if x.get("severity")=="review"),
                "files_examined":count, "results":results,
                "privacy":"Local report. File contents and screenshots are not collected or uploaded.",
                "limitations":"Name/path heuristics can produce false positives and do not prove cheating or malware."
            }
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
            path = REPORT_DIR / ("3EN_Inspection_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json")
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            self.root.after(0, lambda: self.finish(report, path))
        except Exception as exc:
            self.root.after(0, lambda msg=str(exc): self.fail(msg))

    def update_progress(self, value, msg):
        self.progress.configure(value=value)
        self.status.configure(text=msg)

    def finish(self, report, path):
        self.report = report
        self.report_path = path
        self.results = report["results"]
        self.render()
        self.total_label.configure(text=str(report["result_count"]))
        self.review_label.configure(text=str(report["review_count"]))
        self.status_label.configure(text="COMPLETE")
        self.progress.configure(value=100)
        self.status.configure(text=f"اكتمل الفحص — حُفظ التقرير محليًا: {path}")
        self.scan_btn.configure(state="normal", text="↻  إعادة الفحص")
        self.busy = False

    def fail(self, message):
        self.busy = False
        self.scan_btn.configure(state="normal", text="▶  بدء التفتيش")
        self.status.configure(text="تعذر إكمال الفحص")
        messagebox.showerror("خطأ في الفحص", message)

    def render(self):
        if not hasattr(self, "tree"):
            return
        for item_id in self.tree.get_children():
            self.tree.delete(item_id)
        query = self.search.get().casefold().strip()
        selected = self.filter.get()
        for row in self.results:
            severity = row.get("severity", "info")
            if selected == "تحتاج مراجعة" and severity != "review":
                continue
            if selected == "معلومات فقط" and severity == "review":
                continue
            text = " ".join(str(row.get(k, "")) for k in ("category","item","path","details")).casefold()
            if query and query not in text:
                continue
            self.tree.insert("", "end", values=("مراجعة" if severity == "review" else "معلومات",
                row.get("category",""), row.get("item",""), row.get("path",""), row.get("details","")), tags=(severity,))

    def sort_by(self, col):
        rows = [(self.tree.set(i, col), i) for i in self.tree.get_children("")]
        rows.sort(key=lambda x: x[0].casefold())
        for index, (_, iid) in enumerate(rows):
            self.tree.move(iid, "", index)

    def export_json(self):
        if not self.report:
            messagebox.showinfo("لا يوجد تقرير", "شغّل الفحص أولًا.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".json", initialfile="3EN_Inspection.json", filetypes=[("JSON","*.json")])
        if dest:
            Path(dest).write_text(json.dumps(self.report, ensure_ascii=False, indent=2), encoding="utf-8")

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("لا توجد نتائج", "شغّل الفحص أولًا.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="3EN_Inspection.csv", filetypes=[("CSV","*.csv")])
        if not dest:
            return
        with open(dest, "w", newline="", encoding="utf-8-sig") as f:
            fields = ("category","item","path","severity","details","modified_utc","size_bytes","sha256")
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader(); writer.writerows(self.results)

    def webhook_settings(self):
        from tkinter import simpledialog
        value = simpledialog.askstring("إعدادات Webhook", "ألصق رابط Discord Webhook للروم المطلوب (احتفظ به سريًا):", initialvalue=self.config.get("discord_webhook", ""), parent=self.root)
        if value is None:
            return
        value = value.strip()
        if value and not value.startswith(("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/")):
            messagebox.showerror("رابط غير صحيح", "أدخل رابط Discord Webhook رسميًا.")
            return
        self.config["discord_webhook"] = value
        save_config(self.config)
        messagebox.showinfo("تم الحفظ", "حُفظ رابط Webhook محليًا.")

    def send_discord(self):
        if not self.report or not self.report_path or not self.report_path.exists():
            messagebox.showinfo("لا يوجد تقرير", "شغّل الفحص أولًا.")
            return
        webhook = self.config.get("discord_webhook", "")
        if not webhook:
            messagebox.showinfo("إعدادات مطلوبة", "أضف رابط Webhook أولًا.")
            return
        if not messagebox.askyesno("تأكيد الإرسال", "سيتم إرسال ملخص وملف JSON إلى روم Discord المحدد. هل وافق صاحب الجهاز على مشاركة التقرير؟"):
            return
        threading.Thread(target=self._send_discord_worker, args=(webhook, self.report_path, self.report), daemon=True).start()

    def _send_discord_worker(self, webhook, report_path, report):
        try:
            boundary = "----3EN" + secrets.token_hex(12)
            summary = json.dumps({"content": (
                "**3EN INSPECTOR TEAM**\\n"
                f"Player: {report.get('player', 'Unknown')}\\n"
                f"Device: {report.get('device', 'Unknown')}\\n"
                f"Results: {report.get('result_count', 0)} | Review leads: {report.get('review_count', 0)}\\n"
                "Note: indicators require human review; they are not proof."
            )}, ensure_ascii=False).encode("utf-8")
            parts = [
                f"--{boundary}\\r\\nContent-Disposition: form-data; name=\"payload_json\"\\r\\nContent-Type: application/json\\r\\n\\r\\n".encode(),
                summary, b"\\r\\n",
                f"--{boundary}\\r\\nContent-Disposition: form-data; name=\"files[0]\"; filename=\"{report_path.name}\"\\r\\nContent-Type: application/json\\r\\n\\r\\n".encode(),
                report_path.read_bytes(), b"\\r\\n", f"--{boundary}--\\r\\n".encode()
            ]
            req = urllib.request.Request(webhook, data=b"".join(parts), headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status not in (200, 204):
                    raise RuntimeError(f"HTTP {response.status}")
            self.root.after(0, lambda: messagebox.showinfo("تم الإرسال", "أُرسل ملخص الفحص وملف JSON إلى الروم المحدد."))
        except Exception as exc:
            msg = str(exc)
            self.root.after(0, lambda m=msg: messagebox.showerror("فشل الإرسال", "تعذر الإرسال. تحقق من Webhook والاتصال.\\n" + m))

    def open_reports(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(REPORT_DIR))
        else:
            messagebox.showinfo("مجلد التقارير", str(REPORT_DIR))


def password_gate(root):
    from tkinter import simpledialog
    config = load_config()
    saved = config.get("password_hash")
    if not saved:
        messagebox.showinfo("إنشاء كلمة مرور", "أول تشغيل: أنشئ كلمة مرور للأداة. احفظها؛ لا توجد استعادة تلقائية.")
        while True:
            p1 = simpledialog.askstring("كلمة المرور", "أنشئ كلمة مرور (8 أحرف على الأقل):", show="*", parent=root)
            if p1 is None:
                return False
            if len(p1) < 8:
                messagebox.showwarning("قصيرة جدًا", "استخدم 8 أحرف على الأقل.")
                continue
            p2 = simpledialog.askstring("تأكيد كلمة المرور", "أعد كتابة كلمة المرور:", show="*", parent=root)
            if p2 is None:
                return False
            if p1 != p2:
                messagebox.showerror("غير متطابقتين", "كلمتا المرور غير متطابقتين.")
                continue
            salt = secrets.token_hex(16)
            config["password_salt"] = salt
            config["password_hash"] = password_digest(p1, salt)
            save_config(config)
            return True
    for _ in range(3):
        p = simpledialog.askstring("3EN INSPECTOR TEAM", "أدخل كلمة المرور:", show="*", parent=root)
        if p is None:
            return False
        if secrets.compare_digest(password_digest(p, config.get("password_salt", "")), saved):
            return True
        messagebox.showerror("خطأ", "كلمة المرور غير صحيحة.")
    messagebox.showerror("مرفوض", "تجاوزت عدد المحاولات.")
    return False


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    if password_gate(root):
        root.deiconify()
        app = InspectorApp(root)
        root.mainloop()
    else:
        root.destroy()
