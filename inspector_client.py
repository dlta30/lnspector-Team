"""
3eN Inspector Team — transparent local inspection client.
Scans running process metadata only (name, executable path, SHA-256 where readable).
It does not read personal documents, browser data, credentials, or memory.
Run: python inspector_client.py
"""
import hashlib
import json
import os
import platform
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime, timezone

APP = "3eN Inspector Team"
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

def collect_startup_entries():
    """Collect startup entry names and command paths on Windows only; never execute anything."""
    entries = []
    if platform.system() != "Windows":
        return entries
    try:
        import winreg
        locations = (
            (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run 32-bit"),
        )
        for hive, key_path, label in locations:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for index in range(min(count, 250)):
                        try:
                            name, value, _kind = winreg.EnumValue(key, index)
                            entries.append({"source": label, "name": str(name)[:160], "command": str(value)[:1000]})
                        except OSError:
                            continue
            except OSError:
                continue
    except ImportError:
        pass
    return entries[:500]

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def collect_processes(progress):
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError("Missing dependency: install requirements with: pip install -r requirements.txt") from exc
    rows = []
    processes = list(psutil.process_iter(["pid", "name", "exe", "username"]))
    total = max(len(processes), 1)
    for i, proc in enumerate(processes, 1):
        try:
            info = proc.info
            name = str(info.get("name") or "Unknown")[:180]
            exe = str(info.get("exe") or "")[:1000]
            matches = [term for term in SUSPICIOUS_TERMS if term in (name + " " + exe).lower()]
            digest = sha256_file(exe) if exe and os.path.isfile(exe) else None
            rows.append({
                "pid": info.get("pid"),
                "process_name": name,
                "executable_path": exe or None,
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
        self.title(APP)
        self.geometry("940x700")
        self.minsize(820, 620)
        self.configure(bg="#090a10")
        self.report = None
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor="#20212c", background="#ff304f", bordercolor="#20212c")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=9)
        self._build()

    def _build(self):
        BG = "#08090f"
        PANEL = "#11131c"
        RED = "#ff304f"
        MUTED = "#939bad"
        WHITE = "#f5f6fb"
        self.configure(bg=BG)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TProgressbar", troughcolor="#252735", background=RED, bordercolor="#252735", lightcolor=RED, darkcolor=RED)
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=(13, 10), background="#242735", foreground=WHITE, bordercolor="#343747")
        style.map("TButton", background=[("active", "#343747")], foreground=[("active", "white")])
        header = tk.Frame(self, bg=PANEL, padx=26, pady=18)
        header.pack(fill="x")
        brandrow = tk.Frame(header, bg=PANEL)
        brandrow.pack(fill="x")
        tk.Label(brandrow, text="3", bg=RED, fg=WHITE, font=("Segoe UI", 22, "bold"), width=3, pady=5).pack(side="left", padx=(0, 12))
        brand = tk.Frame(brandrow, bg=PANEL)
        brand.pack(side="left", fill="x", expand=True)
        tk.Label(brand, text="3eN INSPECTOR TEAM", bg=PANEL, fg=WHITE, font=("Segoe UI", 19, "bold")).pack(anchor="w")
        tk.Label(brand, text="فحص أمني • إرسال تقرير بموافقتك", bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 0))
        tk.Label(brandrow, text="●  الجلسة جاهزة", bg="#25131b", fg="#ff7084", font=("Segoe UI", 9, "bold"), padx=12, pady=8).pack(side="right", anchor="center")
        body = tk.Frame(self, bg=BG, padx=24, pady=22)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="فحص أمان الجهاز", bg=BG, fg=WHITE, font=("Segoe UI", 21, "bold")).pack(anchor="w")
        tk.Label(body, text="يفحص البرنامج معلومات العمليات الظاهرة وبعض عناصر بدء التشغيل، ثم يرسل التقرير إلى لوحة الفحص بعد موافقتك.", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(5, 16))
        cards = tk.Frame(body, bg=BG)
        cards.pack(fill="x", pady=(0, 14))
        self.metric_processes = tk.StringVar(value="—")
        self.metric_flags = tk.StringVar(value="—")
        self.metric_state = tk.StringVar(value="READY")
        for title, var, accent in [("العناصر المفحوصة", self.metric_processes, RED), ("حالة التقرير", self.metric_flags, "#ffb454"), ("الحالة", self.metric_state, "#62d6a7")]:
            card = tk.Frame(cards, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=16, pady=14)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(card, textvariable=var, bg=PANEL, fg=accent, font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(8, 0))
        consent_box = tk.Frame(body, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=16, pady=14)
        consent_box.pack(fill="x", pady=(0, 13))
        tk.Label(consent_box, text="الموافقة على الفحص", bg=PANEL, fg="#ff7084", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(consent_box, text="أملك هذا الجهاز أو لدي إذن بفحصه، وأوافق على إرسال تقرير الفحص إلى المسؤول.", variable=self.consent, bg=PANEL, fg=WHITE, selectcolor="#242735", activebackground=PANEL, activeforeground=WHITE, wraplength=850, font=("Segoe UI", 10), relief="flat").pack(anchor="w", pady=(8, 0))
        scanbox = tk.Frame(body, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=16, pady=14)
        scanbox.pack(fill="x", pady=(0, 13))
        self.status = tk.StringVar(value="جاهز • وافق على الفحص ثم ابدأ.")
        topstatus = tk.Frame(scanbox, bg=PANEL)
        topstatus.pack(fill="x")
        tk.Label(topstatus, text="تقدم الفحص", bg=PANEL, fg=WHITE, font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Label(topstatus, textvariable=self.status, bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(side="right")
        self.progress = ttk.Progressbar(scanbox, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(12, 0))
        controls = tk.Frame(body, bg=BG)
        controls.pack(fill="x", pady=(0, 13))
        ttk.Button(controls, text="▶  بدء الفحص", command=self.start).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="↗  إرسال التقرير للمسؤول", command=self.submit).pack(side="left", padx=4)
        results = tk.Frame(body, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=14, pady=12)
        results.pack(fill="both", expand=True)
        tk.Label(results, text="سجل الفحص", bg=PANEL, fg=WHITE, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        self.output = tk.Text(results, bg="#0b0d14", fg="#dce0ec", insertbackground="white", relief="flat", font=("Consolas", 9), wrap="word", padx=13, pady=12, selectbackground="#7d1b31", borderwidth=0)
        self.output.pack(fill="both", expand=True)
        self.output.insert("end", "SYSTEM READY\n\nYour scan has not started yet.\n\nAfter completion, the detailed report is intended for the administrator dashboard.\n")
        self.output.insert("end", "• Confirm authorization and press START SCAN.\n")
        self.output.insert("end", "• Scope: running process metadata, readable executable hashes, and Windows startup entry names/commands.\n")
        self.output.insert("end", "• A flag is only a lead for administrator review, not proof of cheating.\n")
        tk.Label(self, text="3eN INSPECTOR TEAM     •     NO STEALTH COLLECTION", bg="#11131c", fg="#747d91", font=("Segoe UI", 8, "bold"), pady=10).pack(fill="x")

    def update_progress(self, value, text):
        self.after(0, lambda: (self.progress.configure(value=value), self.status.set(text)))

    def start(self):
        if not self.consent.get():
            messagebox.showwarning(APP, "Please confirm consent before starting.")
            return
        if not messagebox.askyesno(APP, "Start a visible scan of running process metadata on this device?"):
            return
        self.output.delete("1.0", "end")
        self.metric_state.set("SCANNING")
        self.metric_processes.set("…")
        self.metric_flags.set("…")
        self.status.set("Inspection running…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            processes = collect_processes(self.update_progress)
            matches = [p for p in processes if p["indicator_matches"]]
            startup_entries = collect_startup_entries()
            self.report = {
                "product": APP,
                "signature": "3eN INSPECTOR TEAM",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "device_label": platform.node()[:100] or "Unknown",
                "platform": platform.platform()[:200],
                "scan_scope": "running process metadata, readable executable SHA-256, and Windows startup entry names/commands",
                "process_count": len(processes),
                "indicator_match_count": len(matches),
                "startup_entry_count": len(startup_entries),
                "startup_entries": startup_entries,
                "game_process_context": sorted({game for proc in processes for game in proc.get("game_context", [])}),
                "note": "Name-based indicators are not proof of cheating. Manual review is required.",
                "processes": processes,
            }
            self.delivery_status = "not_configured"
            if DASHBOARD_URL and SESSION_CODE:
                try:
                    import urllib.request
                    endpoint = DASHBOARD_URL.rstrip("/") + "/api/v1/session-report"
                    payload = {"session_code": SESSION_CODE, "computer_label": self.report["device_label"],
                               "summary": f"{self.report['indicator_match_count']} name-based leads; {self.report.get('startup_entry_count', 0)} startup entries for review",
                               "report": self.report}
                    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
                    with urllib.request.urlopen(req, timeout=20) as response:
                        result = json.loads(response.read().decode("utf-8"))
                    self.delivery_status = "sent"
                    self.report["dashboard_report_id"] = result.get("report_id")
                except Exception as send_error:
                    self.delivery_status = "failed: " + type(send_error).__name__
            self.after(0, self._show_report)
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror(APP, str(exc)))
            self.update_progress(0, "Scan failed. Check dependencies and permissions.")

    def _show_report(self):
        self.metric_processes.set(str(self.report["process_count"]))
        self.metric_flags.set(str(self.report["indicator_match_count"]))
        self.metric_state.set("SENT" if getattr(self, "delivery_status", "") == "sent" else ("COMPLETE" if getattr(self, "delivery_status", "") == "not_configured" else "REVIEW"))
        self.output.insert("end", "SCAN COMPLETED\n\n")
        self.output.insert("end", f"Items checked: {self.report['process_count']}\n")
        self.output.insert("end", "Detailed findings are not displayed in this window.\n")
        self.output.insert("end", "Submit the report to the administrator dashboard for review.\n")
        delivery = getattr(self, "delivery_status", "not_configured")
        if delivery == "sent":
            self.output.insert("end", f"Report automatically submitted. Report ID: {self.report.get('dashboard_report_id')}\n")
            self.status.set("COMPLETE • Report sent to dashboard.")
        elif delivery.startswith("failed:"):
            self.output.insert("end", "Automatic submission failed: " + delivery + "\nUse the manual submit button to retry.\n")
            self.status.set("COMPLETE • Submission needs retry.")
        else:
            self.output.insert("end", "No session configuration found; report was not uploaded.\n")
            self.status.set("COMPLETE • No session configured.")

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
            story = [Paragraph("3eN INSPECTOR TEAM", styles["RedTitle"]), Paragraph("Security inspection report - by:ROITH", styles["Normal"]), Spacer(1, 8*mm)]
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

    def submit(self):
        if not self.report:
            messagebox.showinfo(APP, "ابدأ الفحص أولاً.")
            return
        dialog = tk.Toplevel(self)
        dialog.title("Submit approved report")
        dialog.configure(bg="#10121a")
        dialog.geometry("520x250")
        tk.Label(dialog, text="رابط لوحة التحكم (https://…)", bg="#10121a", fg="white").pack(anchor="w", padx=18, pady=(18, 0))
        url_entry = tk.Entry(dialog, bg="#08090e", fg="white", insertbackground="white")
        url_entry.pack(fill="x", padx=18, pady=5)
        if DASHBOARD_URL:
            url_entry.insert(0, DASHBOARD_URL)
            url_entry.configure(state="readonly")
        tk.Label(dialog, text="كود الجلسة لمرة واحدة", bg="#10121a", fg="white").pack(anchor="w", padx=18)
        code_entry = tk.Entry(dialog, bg="#08090e", fg="white", insertbackground="white")
        code_entry.pack(fill="x", padx=18, pady=5)
        if SESSION_CODE:
            code_entry.insert(0, SESSION_CODE)
            code_entry.configure(state="readonly")
        def send():
            import urllib.request
            import urllib.error
            base = url_entry.get().strip().rstrip("/")
            code = (SESSION_CODE or code_entry.get()).strip().upper()
            if not base.startswith("https://") or not code:
                messagebox.showwarning(APP, "Use an HTTPS dashboard URL and a session code.", parent=dialog)
                return
            if not messagebox.askyesno(APP, "Send the inspected process metadata to your inspector dashboard?", parent=dialog):
                return
            payload = {"session_code": code, "computer_label": self.report["device_label"],
                       "summary": f"{self.report['indicator_match_count']} name-based lead(s); {self.report.get('startup_entry_count', 0)} startup entries collected for manual review",
                       "report": self.report}
            request_data = urllib.request.Request(base + "/api/v1/session-report",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request_data, timeout=15) as response:
                    result = json.loads(response.read().decode("utf-8"))
                messagebox.showinfo(APP, f"Report submitted. Report ID: {result.get('report_id')}", parent=dialog)
                dialog.destroy()
            except Exception as exc:
                messagebox.showerror(APP, f"Could not submit report: {exc}", parent=dialog)
        ttk.Button(dialog, text="إرسال التقرير", command=send).pack(pady=14)

if __name__ == "__main__":
    InspectorApp().mainloop()
