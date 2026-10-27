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
    from session_config import SESSION_CODE
except ImportError:
    SESSION_CODE = ""
SUSPICIOUS_TERMS = (
    "cheat", "cheatengine", "injector", "trainer", "modmenu",
    "aimbot", "wallhack", "processhacker", "xenos", "extreme injector",
)

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
        self.geometry("900x650")
        self.minsize(760, 560)
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
        tk.Label(brandrow, text="◈", bg=PANEL, fg=RED, font=("Segoe UI Symbol", 27, "bold")).pack(side="left", padx=(0, 12))
        brand = tk.Frame(brandrow, bg=PANEL)
        brand.pack(side="left", fill="x", expand=True)
        tk.Label(brand, text="3eN INSPECTOR TEAM", bg=PANEL, fg=WHITE, font=("Segoe UI", 19, "bold")).pack(anchor="w")
        tk.Label(brand, text="SECURITY OPERATIONS  /  INSPECTION CLIENT", bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 0))
        tk.Label(brandrow, text="●  SESSION CLIENT", bg="#25131b", fg="#ff7084", font=("Segoe UI", 9, "bold"), padx=12, pady=8).pack(side="right", anchor="center")
        body = tk.Frame(self, bg=BG, padx=24, pady=22)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="DEVICE INSPECTION", bg=BG, fg=WHITE, font=("Segoe UI", 21, "bold")).pack(anchor="w")
        tk.Label(body, text="Visible process review • Consent required • Report export: PDF", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(5, 16))
        cards = tk.Frame(body, bg=BG)
        cards.pack(fill="x", pady=(0, 14))
        self.metric_processes = tk.StringVar(value="—")
        self.metric_flags = tk.StringVar(value="—")
        self.metric_state = tk.StringVar(value="READY")
        for title, var, accent in [("PROCESSES REVIEWED", self.metric_processes, RED), ("LEADS TO REVIEW", self.metric_flags, "#ffb454"), ("SCAN STATUS", self.metric_state, "#62d6a7")]:
            card = tk.Frame(cards, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=16, pady=14)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(card, textvariable=var, bg=PANEL, fg=accent, font=("Segoe UI", 18, "bold")).pack(anchor="w", pady=(8, 0))
        consent_box = tk.Frame(body, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=16, pady=14)
        consent_box.pack(fill="x", pady=(0, 13))
        tk.Label(consent_box, text="AUTHORIZATION", bg=PANEL, fg="#ff7084", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(consent_box, text="I own this device or have explicit permission to inspect it, and I consent to this scan.", variable=self.consent, bg=PANEL, fg=WHITE, selectcolor="#242735", activebackground=PANEL, activeforeground=WHITE, wraplength=850, font=("Segoe UI", 10), relief="flat").pack(anchor="w", pady=(8, 0))
        scanbox = tk.Frame(body, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=16, pady=14)
        scanbox.pack(fill="x", pady=(0, 13))
        self.status = tk.StringVar(value="Ready — no scan starts until you confirm and press Start inspection.")
        topstatus = tk.Frame(scanbox, bg=PANEL)
        topstatus.pack(fill="x")
        tk.Label(topstatus, text="INSPECTION PROGRESS", bg=PANEL, fg=WHITE, font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Label(topstatus, textvariable=self.status, bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(side="right")
        self.progress = ttk.Progressbar(scanbox, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(12, 0))
        controls = tk.Frame(body, bg=BG)
        controls.pack(fill="x", pady=(0, 13))
        ttk.Button(controls, text="▶  START INSPECTION", command=self.start).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="⇩  EXPORT PDF", command=self.export_pdf).pack(side="left", padx=4)
        ttk.Button(controls, text="↗  SEND TO DASHBOARD", command=self.submit).pack(side="left", padx=4)
        results = tk.Frame(body, bg=PANEL, highlightbackground="#292c3a", highlightthickness=1, padx=14, pady=12)
        results.pack(fill="both", expand=True)
        tk.Label(results, text="INSPECTION FINDINGS", bg=PANEL, fg=WHITE, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        self.output = tk.Text(results, bg="#0b0d14", fg="#dce0ec", insertbackground="white", relief="flat", font=("Consolas", 9), wrap="word", padx=13, pady=12, selectbackground="#7d1b31", borderwidth=0)
        self.output.pack(fill="both", expand=True)
        self.output.insert("end", "SYSTEM READY\n\n")
        self.output.insert("end", "• Press START INSPECTION after confirming authorization.\n")
        self.output.insert("end", "• The scan reviews process metadata and readable executable hashes only.\n")
        self.output.insert("end", "• A name-based indicator is not proof of cheating; review findings manually.\n")
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
            self.report = {
                "product": APP,
                "signature": "3eN INSPECTOR TEAM",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "device_label": platform.node()[:100] or "Unknown",
                "platform": platform.platform()[:200],
                "scan_scope": "running process metadata and readable executable SHA-256 only",
                "process_count": len(processes),
                "indicator_match_count": len(matches),
                "note": "Name-based indicators are not proof of cheating. Manual review is required.",
                "processes": processes,
            }
            self.after(0, self._show_report)
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror(APP, str(exc)))
            self.update_progress(0, "Scan failed. Check dependencies and permissions.")

    def _show_report(self):
        matches = [p for p in self.report["processes"] if p["indicator_matches"]]
        self.metric_processes.set(str(self.report["process_count"]))
        self.metric_flags.set(str(len(matches)))
        self.metric_state.set("COMPLETE")
        self.output.insert("end", f"Completed: {self.report['process_count']} process entries\n")
        self.output.insert("end", f"Name-based leads for review: {len(matches)}\n\n")
        if matches:
            for item in matches:
                self.output.insert("end", f"[REVIEW] {item['process_name']} (PID {item['pid']})\n")
                self.output.insert("end", f"  Indicators: {', '.join(item['indicator_matches'])}\n")
                self.output.insert("end", f"  Path: {item['executable_path'] or 'unavailable'}\n\n")
        else:
            self.output.insert("end", "No configured process-name indicators matched. This does not guarantee the device is clean.\n")
        self.status.set("Inspection complete — export or submit only after reviewing the results.")

    def export_pdf(self):
        if not self.report:
            messagebox.showinfo(APP, "Run an inspection first.")
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
            messagebox.showinfo(APP, "PDF report exported successfully.")
        except Exception as exc:
            messagebox.showerror(APP, "PDF export failed: " + str(exc))

    def submit(self):
        if not self.report:
            messagebox.showinfo(APP, "Run an inspection first.")
            return
        dialog = tk.Toplevel(self)
        dialog.title("Submit approved report")
        dialog.configure(bg="#10121a")
        dialog.geometry("520x250")
        tk.Label(dialog, text="Dashboard URL (https://…)", bg="#10121a", fg="white").pack(anchor="w", padx=18, pady=(18, 0))
        url_entry = tk.Entry(dialog, bg="#08090e", fg="white", insertbackground="white")
        url_entry.pack(fill="x", padx=18, pady=5)
        tk.Label(dialog, text="One-time session code", bg="#10121a", fg="white").pack(anchor="w", padx=18)
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
                       "summary": f"{self.report['indicator_match_count']} name-based lead(s) for manual review",
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
        ttk.Button(dialog, text="SEND REPORT", command=send).pack(pady=14)

if __name__ == "__main__":
    InspectorApp().mainloop()
