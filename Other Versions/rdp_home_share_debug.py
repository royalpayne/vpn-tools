#!/usr/bin/env python3
# rdp_home_share_debug.py — with error logging

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import os

class RDPHomeShare:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP – Home Share (Debug)")
        self.root.geometry("620x620")
        self.process = None
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.root, text="RDP Home Folder Sharer", font=("Segoe UI", 22, "bold")).pack(pady=(0, 30))

        ttk.Label(self.root, text="Server:").pack(anchor="w", pady=(10, 5))
        self.server = ttk.Entry(self.root, width=55)
        self.server.pack(fill="x", pady=(0, 15))

        ttk.Label(self.root, text="Username:").pack(anchor="w")
        self.user = ttk.Entry(self.root, width=35)
        self.user.pack(pady=(0, 10))

        ttk.Label(self.root, text="Password:").pack(anchor="w")
        self.passwd = ttk.Entry(self.root, width=35, show="*")
        self.passwd.pack(pady=(0, 20))

        ttk.Label(self.root, text="Your /home/heath will be shared as 'Home' drive", foreground="blue").pack(pady=10)

        self.multimon = tk.BooleanVar(value=True)
        self.sound = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.root, text="Multi-monitor", variable=self.multimon).pack(anchor="w", pady=5)
        ttk.Checkbutton(self.root, text="Remote sound", variable=self.sound).pack(anchor="w", pady=5)

        btns = ttk.Frame(self.root)
        btns.pack(pady=30)
        self.connect_btn = ttk.Button(btns, text="CONNECT", command=self.connect)
        self.connect_btn.pack(side="left", padx=10)
        self.disconnect_btn = ttk.Button(btns, text="DISCONNECT", command=self.disconnect, state="disabled")
        self.disconnect_btn.pack(side="left", padx=10)

        self.status = ttk.Label(self.root, text="Ready", foreground="green", font=("", 11, "bold"))
        self.status.pack(pady=20)

    def connect(self):
        server = self.server.get().strip()
        user = self.user.get().strip()
        pwd = self.passwd.get()

        if not all([server, user]):
            messagebox.showerror("Error", "Server + username required")
            return

        cmd = [
            "xfreerdp3", f"/v:{server}", f"/u:{user}",
            "/cert:ignore", "/sec:nla", "+clipboard", "/drive:Home,$HOME"
        ]
        if pwd:
            cmd.append(f"/p:{pwd}")
        if self.multimon.get():
            cmd.append("/multimon")
        if self.sound.get():
            cmd.append("/sound:sys:pulse")

        self.status.config(text="Connecting...", foreground="orange")
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")

        def run():
            try:
                self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = self.process.communicate()
                if self.process.returncode != 0:
                    error_msg = err.decode('utf-8') if err else "Unknown error"
                    self.root.after(0, lambda: messagebox.showerror("Connection Failed", f"RDP failed:\n{error_msg}"))
                self.root.after(0, self.reset_ui)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Launch failed:\n{str(e)}"))
                self.root.after(0, self.reset_ui)

        threading.Thread(target=run, daemon=True).start()
        self.root.after(2000, lambda: self.status.config(text="Connected – Check for 'Home' drive in Windows!", foreground="green"))

    def reset_ui(self):
        self.status.config(text="Disconnected", foreground="red")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self.process = None

    def disconnect(self):
        if self.process:
            self.process.terminate()
            self.process = None
        self.reset_ui()

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Accent.TButton", foreground="white", background="#0078D4")
    app = RDPHomeShare(root)
    root.mainloop()
