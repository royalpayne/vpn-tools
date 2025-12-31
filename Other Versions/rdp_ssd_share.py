#!/usr/bin/env python3
# rdp_ssd_share.py — Share any SSD folder as removable disk over RDP (2025)

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import os
import json
import threading

try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False


class RDPSSDShare:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP – Share SSD Folder as Removable Disk")
        self.root.geometry("680x700")
        self.root.minsize(620, 600)
        self.root.configure(padx=20, pady=20)

        self.config_file = os.path.expanduser("~/.rdp_ssd_config.json")
        self.process = None

        self.create_widgets()
        self.load_config()

    def create_widgets(self):
        ttk.Label(self.root, text="RDP SSD Folder Sharer", font=("Segoe UI", 22, "bold")).pack(pady=(0, 25))

        # Server
        ttk.Label(self.root, text="RDP Server:").pack(anchor="w", pady=(10, 5))
        self.server = ttk.Entry(self.root, width=60)
        self.server.pack(fill="x", pady=(0, 15))

        # Credentials
        cred = ttk.LabelFrame(self.root, text=" Credentials ")
        cred.pack(fill="x", pady=10)
        ttk.Label(cred, text="Username:").grid(row=0, column=0, sticky="w", padx=15, pady=8)
        self.user = ttk.Entry(cred, width=35)
        self.user.grid(row=0, column=1, padx=15, pady=8, sticky="w")
        ttk.Label(cred, text="Password:").grid(row=1, column=0, sticky="w", padx=15, pady=(0, 8))
        self.passwd = ttk.Entry(cred, width=35, show="•")
        self.passwd.grid(row=1, column=1, padx=15, pady=(0, 8), sticky="w")

        ttk.Separator(self.root).pack(fill="x", pady=20)

        # SSD folder to share
        share = ttk.LabelFrame(self.root, text=" Share Folder from SSD as Removable Disk ")
        share.pack(fill="x", pady=10)

        pframe = ttk.Frame(share)
        pframe.pack(fill="x", padx=15, pady=10)
        ttk.Label(pframe, text="Local SSD folder to share:").pack(anchor="w")
        path_inner = ttk.Frame(pframe)
        path_inner.pack(fill="x", pady=5)
        self.path_entry = ttk.Entry(path_inner, width=50)
        self.path_entry.pack(side="left", expand=True, fill="x")
        self.path_entry.insert(0, "/mnt/ssd")  # ← default — change as you like
        ttk.Button(path_inner, text="Browse…", command=self.browse_path).pack(side="right", padx=(8, 0))

        ttk.Label(share, text="Name shown in Windows:").pack(anchor="w", padx=15, pady=(10, 5))
        self.name_entry = ttk.Entry(share, width=30)
        self.name_entry.insert(0, "SSD_Drive")
        self.name_entry.pack(padx=15, pady=(0, 15))

        # Display & Audio
        opts = ttk.LabelFrame(self.root, text=" Display & Audio ")
        opts.pack(fill="x", pady=15)
        self.fullscreen = tk.BooleanVar(value=False)
        self.multimon = tk.BooleanVar(value=True)
        self.sound = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Full screen", variable=self.fullscreen).pack(anchor="w", padx=20, pady=5)
        ttk.Checkbutton(opts, text="Span all monitors", variable=self.multimon).pack(anchor="w", padx=20, pady=5)
        ttk.Checkbutton(opts, text="Remote sound", variable=self.sound).pack(anchor="w", padx=20, pady=5)

        # Buttons
        buttons = ttk.Frame(self.root)
        buttons.pack(pady=30)
        self.connect_btn = ttk.Button(buttons, text="CONNECT RDP", style="Accent.TButton", command=self.connect)
        self.connect_btn.grid(row=0, column=0, padx=15)
        self.disconnect_btn = ttk.Button(buttons, text="DISCONNECT", command=self.disconnect, state="disabled")
        self.disconnect_btn.grid(row=0, column=1, padx=15)
        ttk.Button(buttons, text="Save Settings", command=self.save_config).grid(row=0, column=2, padx=15)

        self.status = ttk.Label(self.root, text="Ready – Pick SSD folder and connect", foreground="sea green", font=("", 12, "bold"))
        self.status.pack(pady=20)

    def browse_path(self):
        path = filedialog.askdirectory(initialdir="/mnt")
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def connect(self):
        server = self.server.get().strip()
        user   = self.user.get().strip()
        pwd    = self.passwd.get()
        path   = self.path_entry.get().strip()
        name   = self.name_entry.get().strip() or "SSD"

        if not all([server, user, path]):
            messagebox.showerror("Error", "Fill all fields")
            return
        if not os.path.isdir(path):
            messagebox.showerror("Error", f"Folder not found:\n{path}")
            return

        cmd = [
            "xfreerdp3",
            f"/v:{server}",
            f"/u:{user}",
            "/cert:ignore",
            "/sec:nla",
            "+clipboard",
            "/floatbar:sticky:off",
            f"/drive:{name},{path}"
        ]
        if pwd:
            cmd.append(f"/p:{pwd}")
        if self.fullscreen.get():
            cmd.append("/f")
        if self.multimon.get():
            cmd.append("/multimon")
        if self.sound.get():
            cmd += ["/sound:sys:pulse", "/microphone:sys:pulse"]

        self.status.config(text="Connecting...", foreground="orange")
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")
        threading.Thread(target=self.run_rdp, args=(cmd,), daemon=True).start()

    def run_rdp(self, cmd):
        try:
            self.process = subprocess.Popen(cmd)
            self.status.config(text=f"Connected – '{os.path.basename(self.path_entry.get())}' shared from SSD", foreground="sea green")
            self.process.wait()
        except FileNotFoundError:
            messagebox.showerror("Error", "xfreerdp3 not installed!")
        finally:
            self.status.config(text="Disconnected", foreground="red")
            self.connect_btn.config(state="normal")
            self.disconnect_btn.config(state="disabled")
            self.process = None

    def disconnect(self):
        if self.process:
            self.process.terminate()

    def save_config(self):
        config = {
            "server": self.server.get(),
            "user": self.user.get(),
            "path": self.path_entry.get(),
            "name": self.name_entry.get(),
            "fullscreen": self.fullscreen.get(),
            "multimon": self.multimon.get(),
            "sound": self.sound.get()
        }
        try:
            with open(self.config_file, "w") as f:
                json.dump(config, f, indent=2)
            if HAS_KEYRING and self.passwd.get():
                keyring.set_password("rdp_ssd", f"{self.user.get()}@{self.server.get()}", self.passwd.get())
            messagebox.showinfo("Saved", "Settings saved")
        except Exception as e:
            messagebox.showerror("Error", f"Save failed: {e}")

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    c = json.load(f)
                self.server.insert(0, c.get("server", ""))
                self.user.insert(0, c.get("user", ""))
                self.path_entry.insert(0, c.get("path", "/mnt/ssd"))
                self.name_entry.delete(0, tk.END); self.name_entry.insert(0, c.get("name", "SSD_Drive"))
                self.fullscreen.set(c.get("fullscreen", False))
                self.multimon.set(c.get("multimon", True))
                self.sound.set(c.get("sound", True))
                if HAS_KEYRING:
                    stored = keyring.get_password("rdp_ssd", f"{c.get('user','')}@{c.get('server','')}")
                    if stored: self.passwd.insert(0, stored)
            except: pass


if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Accent.TButton", foreground="white", background="#0078D4", font=("Segoe UI", 10, "bold"))
    app = RDPSSDShare(root)
    root.mainloop()
