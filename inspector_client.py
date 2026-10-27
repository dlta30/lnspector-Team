"""
3eN Inspector Team — transparent local inspection client.
Scans running process metadata only (name, executable path, SHA-256 where readable).
It does not read personal documents, browser data, credentials, or memory.
Run: python inspector_client.py
"""
import csv
import hashlib
import json
import os
import platform
import re
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime, timezone

APP = "3eN Inspector Team"
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
        self.title(APP + " | by:ROITH")
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
        header = tk.Frame(self, bg="#11131c", padx=24, pady=20)
        header.pack(fill="x")
        tk.Label(header, text="◈  3eN INSPECTOR TEAM", bg="#11131c", fg="#ff405d",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(header, text="CONSENT-BASED SECURITY CHECK  •  by:ROITH", bg="#11131c",
                 fg="#9ca3b5", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(5, 0))
        body = tk.Frame(self, bg="#090a10", padx=24, pady=20)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="Device inspection", bg="#090a10", fg="#f5f6fb",
                 font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(body, text="This checks running process names and executable metadata only. A name match is a lead for review, not proof of cheating.",
                 bg="#090a10", fg="#aab0c0", wraplength=800, justify="left").pack(anchor="w", pady=(8, 16))
        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(body, text="I own this device or have explicit permission to inspect it, and I consent to this scan.",
                       variable=self.consent, bg="#090a10", fg="#f5f6fb", selectcolor="#171923",
                       activebackground="#090a10", activeforeground="#fff", wraplength=800,
                       font=("Segoe UI", 10)).pack(anchor="w", pady=5)
        self.progress = ttk.Progressbar(body, maximum=100, mode="determinate")
        self.progress.pack(fill="x", pady=(15, 6))
        self.status = tk.StringVar(value="Ready — nothing is scanned until you press Start inspection.")
        tk.Label(body, textvariable=self.status, bg="#090a10", fg="#ff8091",
                 font=("Segoe UI", 9)).pack(anchor="w")
        buttons = tk.Frame(body, bg="#090a10")
        buttons.pack(fill="x", pady=16)
        ttk.Button(buttons, text="START INSPECTION", command=self.start).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Export JSON", command=lambda: self.export("json")).pack(side="left", padx=4)
        ttk.Button(buttons, text="Export CSV", command=lambda: self.export("csv")).pack(side="left", padx=4)
        ttk.Button(buttons, text="Submit to dashboard", command=self.submit).pack(side="left", padx=4)
        self.output = tk.Text(body, bg="#10121a", fg="#dce0ec", insertbackground="white",
                              relief="flat", font=("Consolas", 9), wrap="word", padx=12, pady=12)
        self.output.pack(fill="both", expand=True, pady=(5, 0))
        self.output.insert("end", "Inspection results will appear here.\n")
        tk.Label(self, text="No stealth mode • No personal-document collection • Review every finding",
                 bg="#11131c", fg="#747d91", font=("Segoe UI", 9), pady=9).pack(fill="x")

    def update_progress(self, value, text):
        self.after(0, lambda: (self.progress.configure(value=value), self.status.set(text)))

    def start(self):
        if not self.consent.get():
            messagebox.showwarning(APP, "Please confirm consent before starting.")
            return
        if not messagebox.askyesno(APP, "Start a visible scan of running process metadata on this device?"):
            return
        self.output.delete("1.0", "end")
        self.status.set("Inspection running…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            processes = collect_processes(self.update_progress)
            matches = [p for p in processes if p["indicator_matches"]]
            self.report = {
                "product": APP,
                "signature": "by:ROITH",
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

    def export(self, kind):
        if not self.report:
            messagebox.showinfo(APP, "Run an inspection first.")
            return
        ext = "json" if kind == "json" else "csv"
        path = filedialog.asksaveasfilename(defaultextension="." + ext,
                    filetypes=[("JSON report", "*.json")] if ext == "json" else [("CSV process list", "*.csv")])
        if not path:
            return
        try:
            if ext == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.report, f, indent=2, ensure_ascii=False)
            else:
                with open(path, "w", newline="", encoding="utf-8-sig") as f:
                    fields = ["pid", "process_name", "executable_path", "sha256", "indicator_matches", "assessment"]
                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()
                    for row in self.report["processes"]:
                        row = dict(row)
                        row["indicator_matches"] = "; ".join(row["indicator_matches"])
                        writer.writerow({k: row.get(k) for k in fields})
            messagebox.showinfo(APP, "Report exported successfully.")
        except OSError as exc:
            messagebox.showerror(APP, str(exc))

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
        def send():
            import urllib.request
            import urllib.error
            base = url_entry.get().strip().rstrip("/")
            code = code_entry.get().strip().upper()
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
