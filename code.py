"""
Sesame Remote Sanity Checker (Config-driven)
GUI with tabs, auto-refresh, CSV export. Uses a YAML config.

Install:
  pip install paramiko tabulate pyyaml

Run:
  python sesame_monitor.py --config sesame_monitor.yaml [--profile prod]
"""

import argparse
import csv
import getpass
import os
import threading
from datetime import datetime

import paramiko
import yaml
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------- Utilities ----------------

def load_config(path, profile):
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if profile is None:
        profile = cfg.get("default_profile")
    if not profile:
        raise ValueError("No profile specified and no default_profile in config.")
    prof = cfg.get("profiles", {}).get(profile)
    if not prof:
        raise ValueError(f"Profile '{profile}' not found in config.")
    return prof

def build_commands(prof):
    """Build commands dict from config profile."""
    patt = prof.get("process_patterns", [])
    patt_escaped = "|".join(patt) if patt else ""
    process_cmd = (
        f'ps -ef | grep -Ei "{patt_escaped}" | grep -v grep'
        if patt_escaped else 'echo "No patterns configured"'
    )

    # services status loop
    services = prof.get("services", [])
    svc_cmd_lines = [
        'for s in ' + " ".join([f'"{s}"' for s in services]) + '; do',
        '  ps -ef | grep -v grep | grep -i "$s" > /dev/null &&',
        '    echo "$s is RUNNING" || echo "$s is NOT RUNNING";',
        'done'
    ]
    service_cmd = "\n".join(svc_cmd_lines)

    # df -h limited to mount points
    mounts = prof.get("mount_points", [])
    df_cmd = "df -h " + " ".join(mounts) if mounts else "df -h"

    return {
        "Process Check": {"cmd": process_cmd, "formatter": "format_ps"},
        "Service Status": {"cmd": service_cmd, "formatter": "format_status"},
        "Directory Listing": {"cmd": df_cmd, "formatter": "format_df"},
    }

# ---------------- Formatters ----------------

def format_ps(output: str):
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=7)
        if len(parts) < 8:
            parts = line.split()
            if len(parts) < 7:  # give up
                continue
            user, pid = parts[0], parts[1]
            stime, cpu_time = parts[-4], parts[-2]
            cmd = " ".join(parts[7:]) if len(parts) >= 8 else " ".join(parts[6:])
        else:
            user, pid = parts[0], parts[1]
            stime, cpu_time, cmd = parts[4], parts[6], parts[7]
        rows.append([user, pid, stime, cpu_time, cmd])
    return ["User", "PID", "Start", "CPU Time", "Command"], rows

def format_status(output: str):
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        i = line.rfind(" is ")
        if i != -1:
            rows.append([line[:i].strip(), line[i+4:].strip()])
        else:
            rows.append([line, ""])
    return ["Service", "Status"], rows

def format_df(output: str):
    lines = [ln for ln in output.splitlines() if ln.strip()]
    if not lines:
        return ["Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"], []
    headers = lines[0].split()
    rows = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            if len(parts) >= 5:
                rows.append(parts[:5] + [" ".join(parts[5:])])
            continue
        rows.append(parts[:5] + [" ".join(parts[5:])])
    std = ["Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"]
    if len(headers) != 6:
        headers = std
    return headers, rows

# ---------------- SSH core ------------------

def ssh_run_all(prof, commands):
    host = prof["host"]
    port = prof.get("port", 22)
    user = prof.get("user") or getpass.getuser()
    password = prof.get("password")
    key_file = prof.get("key_file")

    if not password and not key_file:
        password = getpass.getpass(f"Password for {user}@{host}: ")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if key_file:
        pkey = paramiko.RSAKey.from_private_key_file(key_file)
        ssh.connect(host, port=port, username=user, pkey=pkey, timeout=20)
    else:
        ssh.connect(host, port=port, username=user, password=password, timeout=20)

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

# ---------------- GUI -----------------------

class App:
    def __init__(self, root, prof):
        self.prof = prof
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
        root.title("Sesame Remote Sanity Checker")

        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=8, pady=6)
        self.status = ttk.Label(bar, text="Ready")
        self.status.pack(side="left")

        ttk.Button(bar, text="Refresh", command=self.refresh_now).pack(side="right", padx=(6,0))
        self.toggle_btn = ttk.Button(bar, text="Pause Auto-Refresh", command=self.toggle_auto)
        self.toggle_btn.pack(side="right", padx=(6,0))
        ttk.Button(bar, text="Export CSV", command=self.export_csv).pack(side="right")

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(0,8))

        for section in self.commands.keys():
            frame = ttk.Frame(self.nb)
            self.nb.add(frame, text=section)
            tree = ttk.Treeview(frame, show="headings")
            vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vs.set)
            tree.pack(fill="both", expand=True, side="left")
            vs.pack(side="right", fill="y")
            tree.tag_configure("ok", foreground="#0a7f00")
            tree.tag_configure("bad", foreground="#b00020")
            tree.tag_configure("warn", foreground="#a56c00")
            self.trees[section] = tree

        ttk.Label(
            root,
            text=f"Host: {self.prof['host']} • User: {self.prof.get('user','')} • Auto: {self.refresh_seconds}s"
        ).pack(anchor="e", padx=8, pady=(0,6))

        try:
            ttk.Style(root).theme_use("clam")
        except Exception:
            pass

        root.geometry("1100x650")

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
        tree = self.trees[section]
        tree.delete(*tree.get_children())
        for r in rows:
            r = list(r) + [""] * (len(headers) - len(r))
            tags = ()
            if section == "Service Status":
                st = (r[1] or "").upper()
                tags = ("ok",) if "RUNNING" in st else (("bad",) if "NOT RUNNING" in st else ())
            if section == "Directory Listing":
                try:
                    use = r[4]
                    if use.endswith("%"):
                        p = int(use[:-1])
                        tags = ("bad",) if p >= 90 else ("warn",) if p >= 75 else ("ok",)
                except Exception:
                    pass
            tree.insert("", "end", values=r[:len(headers)], tags=tags)

    def refresh_now(self):
        self.status.config(text=f"Refreshing… {datetime.now().strftime('%H:%M:%S')}")
        def work():
            try:
                data = ssh_run_all(self.prof, self.commands)
                self.root.after(0, self._update_tables, data)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("SSH Error", str(e)))
                self.status.config(text="Error")
        threading.Thread(target=work, daemon=True).start()

    def _update_tables(self, data):
        for section, (headers, rows) in data.items():
            self._apply_headers(section, headers)
            self._insert_rows(section, headers, rows)
        self.status.config(text=f"Last update: {datetime.now().strftime('%H:%M:%S')}")

    def _schedule(self):
        if self.auto:
            self.root.after(self.refresh_seconds * 1000, self._tick)

    def _tick(self):
        if self.auto:
            self.refresh_now()
            self._schedule()

    def toggle_auto(self):
        self.auto = not self.auto
        self.toggle_btn.config(text="Pause Auto-Refresh" if self.auto else "Resume Auto-Refresh")
        if self.auto:
            self._schedule()

    def export_csv(self):
        idx = self.nb.index(self.nb.select())
        section = list(self.commands.keys())[idx]
        headers = self.headers.get(section, [])
        tree = self.trees[section]
        rows = [tree.item(i, "values") for i in tree.get_children()]
        if not rows:
            messagebox.showinfo("Export", "Nothing to export on this tab.")
            return
        default = f"{section.replace(' ', '_').lower()}_{datetime.now():%Y%m%d_%H%M%S}.csv"
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default,
                                            filetypes=[("CSV","*.csv"),("All files","*.*")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers); w.writerows(rows)
        messagebox.showinfo("Export", f"Saved: {path}")

# ---------------- CLI -----------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to YAML config")
    ap.add_argument("--profile", help="Profile name in config")
    args = ap.parse_args()

    prof = load_config(args.config, args.profile)

    root = tk.Tk()
    App(root, prof)
    root.mainloop()

if __name__ == "__main__":
    main()
