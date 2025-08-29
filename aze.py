"""
Sesame Remote Monitor (with GUI password login)
- Reads host & user from YAML config
- Asks password once in GUI dialog
- Shows monitoring window with tabs:
  * Processes
  * Services
  * Disk usage
"""

import argparse
import csv
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

import paramiko
import yaml

# ---------------- Load config ----------------
def load_config(path, profile):
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if profile is None:
        profile = cfg.get("default_profile")
    prof = cfg.get("profiles", {}).get(profile)
    if not prof:
        raise ValueError(f"Profile '{profile}' not found in config")
    return prof

# ---------------- Formatters -----------------
def format_ps(output: str):
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=7)
        if len(parts) < 8:
            continue
        user, pid, _, _, stime, _, cpu, cmd = parts
        rows.append([user, pid, stime, cpu, cmd])
    return ["User", "PID", "Start", "CPU Time", "Command"], rows

def format_status(output: str):
    rows = []
    for line in output.splitlines():
        if not line.strip():
            continue
        i = line.rfind(" is ")
        if i != -1:
            rows.append([line[:i].strip(), line[i+4:].strip()])
    return ["Service", "Status"], rows

def format_df(output: str):
    lines = [ln for ln in output.splitlines() if ln.strip()]
    if not lines:
        return ["Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"], []
    headers = lines[0].split()
    rows = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            rows.append(parts[:5] + [" ".join(parts[5:])])
    std = ["Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"]
    if len(headers) != 6:
        headers = std
    return headers, rows

# ---------------- SSH runner -----------------
def ssh_run_all(prof, commands, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        prof["host"], port=prof.get("port",22),
        username=prof["user"], password=password, timeout=10
    )
    results = {}
    try:
        for section, cfg in commands.items():
            stdin, stdout, stderr = ssh.exec_command(cfg["cmd"])
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            text = out if out else err

            fmt = cfg.get("formatter")
            if fmt == "format_ps":
                headers, rows = format_ps(text)
            elif fmt == "format_status":
                headers, rows = format_status(text)
            elif fmt == "format_df":
                headers, rows = format_df(text)
            else:
                headers, rows = ["Output"], [[ln] for ln in text.splitlines()]
            results[section] = (headers, rows)
    finally:
        ssh.close()
    return results

def build_commands(prof):
    patt = "|".join(prof.get("process_patterns", []))
    process_cmd = (
        f'ps -ef | grep -Ei "{patt}" | grep -v grep'
        if patt else "echo 'No process patterns'"
    )
    services = prof.get("services", [])
    svc_cmd = (
        "for s in " + " ".join([f'"{s}"' for s in services]) + "; do\n"
        "  ps -ef | grep -v grep | grep -i \"$s\" > /dev/null && "
        "echo \"$s is RUNNING\" || echo \"$s is NOT RUNNING\";\n"
        "done"
    )
    mounts = prof.get("mount_points", [])
    df_cmd = "df -h " + " ".join(mounts) if mounts else "df -h"

    return {
        "Process Check": {"cmd": process_cmd, "formatter": "format_ps"},
        "Service Status": {"cmd": svc_cmd, "formatter": "format_status"},
        "Directory Listing": {"cmd": df_cmd, "formatter": "format_df"},
    }

# ---------------- GUI Login -----------------
def ask_password_gui(prof):
    root = tk.Tk()
    root.withdraw()
    while True:
        pwd = simpledialog.askstring(
            "Login",
            f"Enter password for {prof['user']}@{prof['host']}:",
            show="*"
        )
        if pwd is None:
            exit(0)
        try:
            # test login quickly
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(prof["host"], port=prof.get("port",22),
                        username=prof["user"], password=pwd, timeout=5)
            ssh.close()
            messagebox.showinfo("Login", "✅ Login Success")
            return pwd
        except Exception:
            messagebox.showerror("Login", "❌ Wrong password, try again.")

# ---------------- Main App ------------------
class App:
    def __init__(self, root, prof, password):
        self.prof = prof
        self.password = password
        self.commands = build_commands(prof)
        self.refresh_seconds = int(prof.get("refresh_seconds", 60))
        self.headers = {}
        self.trees = {}
        self.auto = True

        self._build_ui(root)
        self.refresh_now()
        self._schedule()

    def _build_ui(self, root):
        self.root = root
        root.title("Sesame Remote Monitor")

        bar = ttk.Frame(root); bar.pack(fill="x", padx=8, pady=6)
        self.status = ttk.Label(bar, text="Ready"); self.status.pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh_now).pack(side="right")
        self.toggle_btn = ttk.Button(bar, text="Pause Auto", command=self.toggle_auto)
        self.toggle_btn.pack(side="right", padx=5)
        ttk.Button(bar, text="Export CSV", command=self.export_csv).pack(side="right", padx=5)

        self.nb = ttk.Notebook(root); self.nb.pack(fill="both", expand=True, padx=8, pady=(0,8))
        for section in self.commands.keys():
            frame = ttk.Frame(self.nb)
            self.nb.add(frame, text=section)
            tree = ttk.Treeview(frame, show="headings")
            vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vs.set)
            tree.pack(fill="both", expand=True, side="left"); vs.pack(side="right", fill="y")
            tree.tag_configure("ok", foreground="#0a7f00")
            tree.tag_configure("warn", foreground="#a56c00")
            tree.tag_configure("bad", foreground="#b00020")
            self.trees[section] = tree

        ttk.Label(root,
            text=f"Host: {self.prof['host']} • User: {self.prof['user']} • Auto: {self.refresh_seconds}s"
        ).pack(anchor="e", padx=8, pady=(0,6))
        try: ttk.Style(root).theme_use("clam")
        except: pass
        root.geometry("1000x600")

    def _apply_headers(self, section, headers):
        tree = self.trees[section]
        if self.headers.get(section) == headers:
            return
        tree.delete(*tree.get_children())
        tree["columns"] = headers
        for h in headers:
            tree.heading(h, text=h)
            tree.column(h, width=140, anchor="w", stretch=True)
        self.headers[section] = headers

    def _insert_rows(self, section, headers, rows):
        tree = self.trees[section]; tree.delete(*tree.get_children())
        for r in rows:
            r = list(r) + [""]*(len(headers)-len(r))
            tags = ()
            if section == "Service Status":
                status = (r[1] or "").upper()
                if "RUNNING" in status: tags=("ok",)
                elif "NOT RUNNING" in status: tags=("bad",)
            if section == "Directory Listing":
                try:
                    use = r[4]
                    if use.endswith("%"):
                        p = int(use[:-1])
                        if p >= 90: tags=("bad",)
                        elif p >= 75: tags=("warn",)
                        else: tags=("ok",)
                except: pass
            tree.insert("", "end", values=r[:len(headers)], tags=tags)

    def refresh_now(self):
        self.status.config(text=f"Refreshing… {datetime.now():%H:%M:%S}")
        def worker():
            try:
                data = ssh_run_all(self.prof, self.commands, self.password)
                self.root.after(0, self._update, data)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("SSH Error", str(e)))
                self.status.config(text="Error")
        threading.Thread(target=worker, daemon=True).start()

    def _update(self, data):
        for sec,(h,rows) in data.items():
            self._apply_headers(sec,h)
            self._insert_rows(sec,h,rows)
        self.status.config(text=f"Last update: {datetime.now():%H:%M:%S}")

    def _schedule(self):
        if self.auto:
            self.root.after(self.refresh_seconds*1000, self._tick)

    def _tick(self):
        if self.auto:
            self.refresh_now()
            self._schedule()

    def toggle_auto(self):
        self.auto = not self.auto
        self.toggle_btn.config(text="Pause Auto" if self.auto else "Resume Auto")
        if self.auto: self._schedule()

    def export_csv(self):
        idx = self.nb.index(self.nb.select())
        sec = list(self.commands.keys())[idx]
        headers = self.headers.get(sec, [])
        tree = self.trees[sec]
        rows = [tree.item(i,"values") for i in tree.get_children()]
        if not rows:
            messagebox.showinfo("Export","Nothing to export"); return
        default = f"{sec.replace(' ','_')}_{datetime.now():%Y%m%d_%H%M%S}.csv"
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default)
        if not path: return
        with open(path,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(headers); w.writerows(rows)
        messagebox.showinfo("Export",f"Saved: {path}")

# ---------------- Main ----------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="sesame_monitor.yaml", help="YAML config")
    ap.add_argument("--profile", help="Profile in YAML")
    args = ap.parse_args()

    prof = load_config(args.config, args.profile)
    pwd = ask_password_gui(prof)

    root = tk.Tk()
    App(root, prof, pwd)
    root.mainloop()

if __name__=="__main__":
    main()
