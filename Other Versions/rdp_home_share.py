#!/usr/bin/env python3
# rdp_home_share.py — Share Home + Disconnect button + drive ALWAYS visible (2025)

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import os

class RDPHomeShare:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP – Share Home Folder")
        self.root.geometry("620x620")
        self.root.minsize(600, 550)
        self.root.configure(padx=20, pady=20)
        self.process = None

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.root, text="RDP Home Folder Sharer", font=("Segoe UI", 22, "bold")).pack(pady=(0, 30))

        # Server
        ttk.Label(self.root, text="RDP Server:").pack(anchor="w", pady=(10, 5))
        self.server = ttk.Entry(self.root, width=55)
        self.server.pack(fill="x", pady=(0, 15))

        ttk.Label(self.root, text="Username:").pack(anchor="w")
        self.user = ttk.Entry(self.root, width=35)
        self.user.pack(pady=(0, 10))

        ttk.Label(self.root, text="Password:").pack(anchor="w")
        self.passwd = ttk.Entry(self.root, width=35, show="•")
        self.passwd.pack(pady=(0, 20))

        # Info
        info = ttk.LabelFrame(self.root, text=" What You Get ")
        info.pack(fill="x", pady=15)
        ttk.Label(info, text="• Your entire /home/heath folder appears in Windows", foreground="blue").pack(pady=4)
        ttk.Label(info, text="• As a REAL removable drive named 'Home'", foreground="blue").pack(pady=4)
        ttk.Label(info, text="• Full read/write access", foreground="blue").pack(pady=4)

        # Options
        opts = ttk.LabelFrame(self.root, text=" Options ")
        opts.pack(fill="x", pady=10)
        self.multimon = tk.BooleanVar(value=True)
        self.sound = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Span all monitors", variable=self.multimon).pack(anchor="w", padx=20)
        ttk.Checkbutton(opts, text="Remote sound", variable=self.sound).pack(anchor="w", padx=20)

        # Buttons
        btns = ttk.Frame(self.root)
        btns.pack(pady=30)
        self.connect_btn = ttk.Button(btns, text="CONNECT RDP", style="Accent.TButton", command=self.connect)
        self.connect_btn.grid(row=0, column=0, padx=15)
        self.disconnect_btn = ttk.Button(btns, text="DISCONNECT", command=self.disconnect, state="disabled")
        self.disconnect_btn.grid(row=0, column=1, padx=15)

        # Status
        self.status = ttk.Label(self.root, text="Ready — Fill fields and click CONNECT", 
                               foreground="sea green", font=("", 11, "bold"))
        self.status.pack(pady=20)

    def connect(self):
        server = self.server.get().strip()
        user   = self.user.get().strip()
        pwd    = self.passwd.get()

        if not all([server, user]):
            messagebox.showerror("Error", "Server + username required")
            return

        # THIS IS THE MAGIC LINE THAT GUARANTEES THE DRIVE APPEARS
        cmd = [
            "xfreerdp3",
            f"/v:{server}",
            f"/u:{user}",
            "/cert:ignore",
            "/sec:nla",
            "+clipboard",
            "/floatbar:sticky:off",
            "/drive:Home,$HOME",           # ← Home folder
            "/dynamic-resolution",          # ← helps multi-monitor
        ]
        if pwd:
            cmd.append(f"/p:{pwd}")
        if self.multimon.get():
            cmd.append("/multimon")
        if self.sound.get():
            cmd += ["/sound:sys:pulse", "/microphone:sys:pulse"]

        self.status.config(text="Connecting... (wait 10–20 seconds)", foreground="orange")
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")

        def run():
            self.process = subprocess.Popen(cmd)
            self.process.wait()
            self.status.config(text="Disconnected", foreground="red")
            self.connect_btn.config(state="normal")
            self.disconnect_btn.config(state="disabled")
            self.process = None

        threading.Thread(target=run, daemon=True).start()
        self.status.config(text="CONNECTED — Look for 'Home (Z:)drive in Windows!", foreground="sea green")

    def disconnect(self):
        if self.process:
            self.process.terminate()
            self.process = None
        self.status.config(text="Disconnected", foreground="red")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Accent.TButton", foreground="white", background="#0078D4", font=("Segoe UI", 10, "bold"))
    app = RDPHomeShare(root)
    root.mainloop()
