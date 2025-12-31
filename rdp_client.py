#!/usr/bin/env python3
"""
RDP Client — Modern Remote Desktop Client for Linux
A polished, all-in-one RDP client with better UI/UX
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import os
import json
import threading
import queue
import re
from datetime import datetime

try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False


class RDPClient:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP Client")
        self.root.geometry("800x900")
        self.root.minsize(750, 800)

        self.config_file = os.path.expanduser("~/.rdp_client.json")
        self.process = None
        self.log_queue = queue.Queue()
        self.connection_start = None

        # Connection state
        self.is_connected = False
        self.is_connecting = False

        self.setup_styles()
        self.create_widgets()
        self.load_config()
        self.process_log_queue()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Custom button styles
        self.style.configure("Connect.TButton",
                           font=("Segoe UI", 11, "bold"),
                           padding=10)
        self.style.configure("Disconnect.TButton",
                           font=("Segoe UI", 11, "bold"),
                           padding=10)
        self.style.configure("Header.TLabel",
                           font=("Segoe UI", 20, "bold"))
        self.style.configure("Status.TLabel",
                           font=("Segoe UI", 11, "bold"))
        self.style.configure("Section.TLabelframe.Label",
                           font=("Segoe UI", 10, "bold"))

    def create_widgets(self):
        # Main container with padding
        main = ttk.Frame(self.root, padding=20)
        main.pack(fill="both", expand=True)

        # Header with status indicator
        header = ttk.Frame(main)
        header.pack(fill="x", pady=(0, 15))

        ttk.Label(header, text="RDP Client", style="Header.TLabel").pack(side="left")

        # Status indicator
        self.status_frame = ttk.Frame(header)
        self.status_frame.pack(side="right")

        self.status_dot = tk.Canvas(self.status_frame, width=16, height=16,
                                    highlightthickness=0, bg=self.root.cget('bg'))
        self.status_dot.pack(side="left", padx=(0, 8))
        self.status_circle = self.status_dot.create_oval(2, 2, 14, 14, fill="#888", outline="")

        self.status_label = ttk.Label(self.status_frame, text="Disconnected",
                                      style="Status.TLabel", foreground="#888")
        self.status_label.pack(side="left")

        # Notebook for tabs
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill="both", expand=True, pady=10)

        # Tab 1: Connection
        self.create_connection_tab()

        # Tab 2: Display & Audio
        self.create_display_tab()

        # Tab 3: Folder Sharing
        self.create_sharing_tab()

        # Tab 4: Advanced
        self.create_advanced_tab()

        # Bottom section: Buttons and Log
        bottom = ttk.Frame(main)
        bottom.pack(fill="both", expand=True, pady=10)

        # Action buttons
        btn_frame = ttk.Frame(bottom)
        btn_frame.pack(fill="x", pady=(0, 15))

        self.connect_btn = ttk.Button(btn_frame, text="Connect",
                                      style="Connect.TButton",
                                      command=self.connect)
        self.connect_btn.pack(side="left", padx=(0, 10))

        self.disconnect_btn = ttk.Button(btn_frame, text="Disconnect",
                                         style="Disconnect.TButton",
                                         command=self.disconnect,
                                         state="disabled")
        self.disconnect_btn.pack(side="left", padx=(0, 10))

        ttk.Button(btn_frame, text="Save Settings",
                  command=self.save_config).pack(side="left", padx=(0, 10))

        ttk.Button(btn_frame, text="Test Connection",
                  command=self.test_connection).pack(side="left")

        # Connection timer
        self.timer_label = ttk.Label(btn_frame, text="", foreground="#666")
        self.timer_label.pack(side="right")

        # Log area
        log_frame = ttk.LabelFrame(bottom, text=" Connection Log ", style="Section.TLabelframe")
        log_frame.pack(fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=8,
                                                   font=("Consolas", 9),
                                                   state="disabled",
                                                   wrap=tk.WORD)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Configure log colors
        self.log_text.tag_configure("info", foreground="#333")
        self.log_text.tag_configure("success", foreground="#27ae60")
        self.log_text.tag_configure("error", foreground="#e74c3c")
        self.log_text.tag_configure("warning", foreground="#f39c12")
        self.log_text.tag_configure("timestamp", foreground="#888")

    def create_connection_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="  Connection  ")

        # Server
        server_frame = ttk.LabelFrame(tab, text=" Server ", style="Section.TLabelframe")
        server_frame.pack(fill="x", pady=(0, 15))

        inner = ttk.Frame(server_frame)
        inner.pack(fill="x", padx=15, pady=15)

        ttk.Label(inner, text="Address:").grid(row=0, column=0, sticky="w", pady=5)
        self.server_entry = ttk.Entry(inner, width=40, font=("Consolas", 11))
        self.server_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(inner, text="Port:").grid(row=0, column=2, sticky="w", padx=(20, 0), pady=5)
        self.port_entry = ttk.Entry(inner, width=8, font=("Consolas", 11))
        self.port_entry.insert(0, "3389")
        self.port_entry.grid(row=0, column=3, sticky="w", padx=(10, 0), pady=5)

        inner.columnconfigure(1, weight=1)

        # Credentials
        cred_frame = ttk.LabelFrame(tab, text=" Credentials ", style="Section.TLabelframe")
        cred_frame.pack(fill="x", pady=(0, 15))

        cred_inner = ttk.Frame(cred_frame)
        cred_inner.pack(fill="x", padx=15, pady=15)

        ttk.Label(cred_inner, text="Username:").grid(row=0, column=0, sticky="w", pady=5)
        self.user_entry = ttk.Entry(cred_inner, width=30)
        self.user_entry.grid(row=0, column=1, sticky="w", padx=(10, 0), pady=5)

        ttk.Label(cred_inner, text="Domain:").grid(row=0, column=2, sticky="w", padx=(30, 0), pady=5)
        self.domain_entry = ttk.Entry(cred_inner, width=20)
        self.domain_entry.grid(row=0, column=3, sticky="w", padx=(10, 0), pady=5)

        ttk.Label(cred_inner, text="Password:").grid(row=1, column=0, sticky="w", pady=5)
        self.passwd_entry = ttk.Entry(cred_inner, width=30, show="*")
        self.passwd_entry.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=5)

        self.show_pass_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cred_inner, text="Show", variable=self.show_pass_var,
                       command=self.toggle_password).grid(row=1, column=2, sticky="w", padx=(10, 0))

        # Quick tips
        tips_frame = ttk.LabelFrame(tab, text=" Tips ", style="Section.TLabelframe")
        tips_frame.pack(fill="x")

        tips = """- Use IP address or hostname (e.g., 192.168.1.100 or workpc.domain.com)
- For domain accounts, enter domain separately or use DOMAIN\\username format
- Password is stored securely in system keyring when available"""

        ttk.Label(tips_frame, text=tips, foreground="#666",
                 font=("Segoe UI", 9)).pack(padx=15, pady=10, anchor="w")

    def create_display_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="  Display & Audio  ")

        # Display settings
        display_frame = ttk.LabelFrame(tab, text=" Display ", style="Section.TLabelframe")
        display_frame.pack(fill="x", pady=(0, 15))

        d_inner = ttk.Frame(display_frame)
        d_inner.pack(fill="x", padx=15, pady=15)

        self.fullscreen_var = tk.BooleanVar(value=False)
        self.multimon_var = tk.BooleanVar(value=True)
        self.dynamic_res_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(d_inner, text="Full screen mode",
                       variable=self.fullscreen_var).pack(anchor="w", pady=3)
        ttk.Checkbutton(d_inner, text="Use all monitors (multi-monitor)",
                       variable=self.multimon_var).pack(anchor="w", pady=3)
        ttk.Checkbutton(d_inner, text="Dynamic resolution (resize with window)",
                       variable=self.dynamic_res_var).pack(anchor="w", pady=3)

        # Resolution
        res_frame = ttk.Frame(d_inner)
        res_frame.pack(fill="x", pady=(10, 0))

        ttk.Label(res_frame, text="Custom resolution:").pack(side="left")
        self.width_entry = ttk.Entry(res_frame, width=6)
        self.width_entry.pack(side="left", padx=(10, 0))
        ttk.Label(res_frame, text="x").pack(side="left", padx=5)
        self.height_entry = ttk.Entry(res_frame, width=6)
        self.height_entry.pack(side="left")
        ttk.Label(res_frame, text="(leave empty for auto)",
                 foreground="#888").pack(side="left", padx=(10, 0))

        # Audio settings
        audio_frame = ttk.LabelFrame(tab, text=" Audio ", style="Section.TLabelframe")
        audio_frame.pack(fill="x", pady=(0, 15))

        a_inner = ttk.Frame(audio_frame)
        a_inner.pack(fill="x", padx=15, pady=15)

        self.sound_var = tk.BooleanVar(value=True)
        self.mic_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(a_inner, text="Play remote sound on this computer",
                       variable=self.sound_var).pack(anchor="w", pady=3)
        ttk.Checkbutton(a_inner, text="Enable microphone redirection",
                       variable=self.mic_var).pack(anchor="w", pady=3)

        # Performance preset
        perf_frame = ttk.LabelFrame(tab, text=" Performance ", style="Section.TLabelframe")
        perf_frame.pack(fill="x")

        p_inner = ttk.Frame(perf_frame)
        p_inner.pack(fill="x", padx=15, pady=15)

        ttk.Label(p_inner, text="Connection quality:").pack(side="left")
        self.quality_var = tk.StringVar(value="auto")
        quality_combo = ttk.Combobox(p_inner, textvariable=self.quality_var,
                                     values=["auto", "lan", "broadband", "modem"],
                                     state="readonly", width=15)
        quality_combo.pack(side="left", padx=(10, 0))

        quality_help = {
            "auto": "Automatically detect",
            "lan": "Best quality (LAN)",
            "broadband": "Balanced",
            "modem": "Low bandwidth"
        }
        self.quality_desc = ttk.Label(p_inner, text=quality_help["auto"], foreground="#888")
        self.quality_desc.pack(side="left", padx=(15, 0))

        def update_quality_desc(*args):
            self.quality_desc.config(text=quality_help.get(self.quality_var.get(), ""))
        quality_combo.bind("<<ComboboxSelected>>", update_quality_desc)

    def create_sharing_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="  Folder Sharing  ")

        # Enable/disable sharing
        self.share_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tab, text="Enable folder sharing",
                       variable=self.share_enabled_var,
                       command=self.toggle_sharing).pack(anchor="w", pady=(0, 15))

        # Folder selection
        self.share_frame = ttk.LabelFrame(tab, text=" Shared Folder ", style="Section.TLabelframe")
        self.share_frame.pack(fill="x", pady=(0, 15))

        s_inner = ttk.Frame(self.share_frame)
        s_inner.pack(fill="x", padx=15, pady=15)

        ttk.Label(s_inner, text="Local folder:").pack(anchor="w")

        path_frame = ttk.Frame(s_inner)
        path_frame.pack(fill="x", pady=5)

        self.path_entry = ttk.Entry(path_frame, font=("Consolas", 10))
        self.path_entry.insert(0, os.path.expanduser("~/Documents"))
        self.path_entry.pack(side="left", fill="x", expand=True)

        ttk.Button(path_frame, text="Browse...",
                  command=self.browse_folder).pack(side="right", padx=(10, 0))

        name_frame = ttk.Frame(s_inner)
        name_frame.pack(fill="x", pady=(10, 0))

        ttk.Label(name_frame, text="Share name (shown in Windows):").pack(side="left")
        self.share_name_entry = ttk.Entry(name_frame, width=20)
        self.share_name_entry.insert(0, "LinuxShare")
        self.share_name_entry.pack(side="left", padx=(10, 0))

        # Clipboard
        clip_frame = ttk.LabelFrame(tab, text=" Clipboard ", style="Section.TLabelframe")
        clip_frame.pack(fill="x")

        c_inner = ttk.Frame(clip_frame)
        c_inner.pack(fill="x", padx=15, pady=15)

        self.clipboard_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(c_inner, text="Enable clipboard sharing (copy/paste between computers)",
                       variable=self.clipboard_var).pack(anchor="w")

    def create_advanced_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text="  Advanced  ")

        # Security
        sec_frame = ttk.LabelFrame(tab, text=" Security ", style="Section.TLabelframe")
        sec_frame.pack(fill="x", pady=(0, 15))

        s_inner = ttk.Frame(sec_frame)
        s_inner.pack(fill="x", padx=15, pady=15)

        ttk.Label(s_inner, text="Security protocol:").pack(side="left")
        self.security_var = tk.StringVar(value="nla")
        sec_combo = ttk.Combobox(s_inner, textvariable=self.security_var,
                                values=["nla", "tls", "rdp", "any"],
                                state="readonly", width=12)
        sec_combo.pack(side="left", padx=(10, 0))

        self.ignore_cert_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(s_inner, text="Ignore certificate warnings",
                       variable=self.ignore_cert_var).pack(side="left", padx=(30, 0))

        # Gateway
        gw_frame = ttk.LabelFrame(tab, text=" RD Gateway (optional) ", style="Section.TLabelframe")
        gw_frame.pack(fill="x", pady=(0, 15))

        g_inner = ttk.Frame(gw_frame)
        g_inner.pack(fill="x", padx=15, pady=15)

        self.use_gateway_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(g_inner, text="Connect through RD Gateway",
                       variable=self.use_gateway_var,
                       command=self.toggle_gateway).grid(row=0, column=0, columnspan=4, sticky="w")

        ttk.Label(g_inner, text="Gateway:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.gateway_entry = ttk.Entry(g_inner, width=35, state="disabled")
        self.gateway_entry.grid(row=1, column=1, columnspan=3, sticky="w", padx=(10, 0), pady=(10, 0))

        # Extra arguments
        extra_frame = ttk.LabelFrame(tab, text=" Extra FreeRDP Arguments ", style="Section.TLabelframe")
        extra_frame.pack(fill="x")

        e_inner = ttk.Frame(extra_frame)
        e_inner.pack(fill="x", padx=15, pady=15)

        ttk.Label(e_inner, text="Additional command-line arguments:",
                 foreground="#666").pack(anchor="w")
        self.extra_args_entry = ttk.Entry(e_inner, font=("Consolas", 10))
        self.extra_args_entry.pack(fill="x", pady=(5, 0))

        ttk.Label(e_inner, text="Example: /gfx:avc420 /network:auto",
                 foreground="#888", font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 0))

    def toggle_password(self):
        if self.show_pass_var.get():
            self.passwd_entry.config(show="")
        else:
            self.passwd_entry.config(show="*")

    def toggle_sharing(self):
        state = "normal" if self.share_enabled_var.get() else "disabled"
        for child in self.share_frame.winfo_children():
            for widget in child.winfo_children():
                try:
                    widget.config(state=state)
                except:
                    pass

    def toggle_gateway(self):
        state = "normal" if self.use_gateway_var.get() else "disabled"
        self.gateway_entry.config(state=state)

    def browse_folder(self):
        path = filedialog.askdirectory(initialdir=os.path.expanduser("~"),
                                       title="Select folder to share")
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def log(self, message, level="info"):
        """Add message to log queue."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put((timestamp, message, level))

    def process_log_queue(self):
        """Process queued log messages."""
        try:
            while True:
                timestamp, message, level = self.log_queue.get_nowait()
                self.log_text.config(state="normal")
                self.log_text.insert("end", f"[{timestamp}] ", "timestamp")
                self.log_text.insert("end", f"{message}\n", level)
                self.log_text.see("end")
                self.log_text.config(state="disabled")
        except queue.Empty:
            pass
        self.root.after(100, self.process_log_queue)

    def update_status(self, text, color, dot_color=None):
        """Update connection status."""
        self.status_label.config(text=text, foreground=color)
        self.status_dot.itemconfig(self.status_circle, fill=dot_color or color)

    def update_timer(self):
        """Update connection timer."""
        if self.is_connected and self.connection_start:
            elapsed = datetime.now() - self.connection_start
            hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.timer_label.config(text=f"Connected: {hours:02d}:{minutes:02d}:{seconds:02d}")
            self.root.after(1000, self.update_timer)
        else:
            self.timer_label.config(text="")

    def build_command(self):
        """Build xfreerdp command from settings."""
        server = self.server_entry.get().strip()
        port = self.port_entry.get().strip()
        user = self.user_entry.get().strip()
        domain = self.domain_entry.get().strip()
        password = self.passwd_entry.get()

        if not server:
            raise ValueError("Server address is required")
        if not user:
            raise ValueError("Username is required")

        # Base command
        cmd = ["xfreerdp3"]

        # Server and port
        if port and port != "3389":
            cmd.append(f"/v:{server}:{port}")
        else:
            cmd.append(f"/v:{server}")

        # Credentials
        cmd.append(f"/u:{user}")
        if domain:
            cmd.append(f"/d:{domain}")
        if password:
            cmd.append(f"/p:{password}")

        # Security
        if self.ignore_cert_var.get():
            cmd.append("/cert:ignore")
        cmd.append(f"/sec:{self.security_var.get()}")

        # Display
        if self.fullscreen_var.get():
            cmd.append("/f")
        if self.multimon_var.get():
            cmd.append("/multimon")
        if self.dynamic_res_var.get():
            cmd.append("/dynamic-resolution")

        # Custom resolution
        width = self.width_entry.get().strip()
        height = self.height_entry.get().strip()
        if width and height:
            cmd.append(f"/size:{width}x{height}")

        # Audio
        if self.sound_var.get():
            cmd.append("/sound:sys:pulse")
        if self.mic_var.get():
            cmd.append("/microphone:sys:pulse")

        # Performance
        quality = self.quality_var.get()
        if quality != "auto":
            cmd.append(f"/network:{quality}")

        # Sharing
        if self.share_enabled_var.get():
            path = self.path_entry.get().strip()
            name = self.share_name_entry.get().strip() or "Share"
            if path and os.path.isdir(path):
                cmd.append(f"/drive:{name},{path}")

        if self.clipboard_var.get():
            cmd.append("+clipboard")

        # Floatbar
        cmd.append("/floatbar:sticky:off")

        # Gateway
        if self.use_gateway_var.get():
            gateway = self.gateway_entry.get().strip()
            if gateway:
                cmd.append(f"/g:{gateway}")

        # Extra arguments
        extra = self.extra_args_entry.get().strip()
        if extra:
            cmd.extend(extra.split())

        return cmd

    def connect(self):
        """Start RDP connection."""
        try:
            cmd = self.build_command()
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return

        # Verify folder exists if sharing enabled
        if self.share_enabled_var.get():
            path = self.path_entry.get().strip()
            if path and not os.path.isdir(path):
                messagebox.showerror("Error", f"Shared folder not found:\n{path}")
                return

        self.log(f"Connecting to {self.server_entry.get()}...", "info")
        self.log(f"Command: {' '.join(cmd[:5])}...", "info")

        self.is_connecting = True
        self.update_status("Connecting...", "#f39c12", "#f39c12")
        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")

        def run_connection():
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )

                # Mark as connected once process starts
                self.root.after(0, self.on_connected)

                # Read output
                for line in iter(self.process.stdout.readline, ''):
                    line = line.strip()
                    if line:
                        if "error" in line.lower() or "fail" in line.lower():
                            self.log(line, "error")
                        elif "warning" in line.lower():
                            self.log(line, "warning")
                        else:
                            self.log(line, "info")

                self.process.wait()

            except FileNotFoundError:
                self.root.after(0, lambda: self.log(
                    "xfreerdp3 not found! Install with: sudo apt install freerdp3-x11", "error"))
            except Exception as e:
                self.root.after(0, lambda: self.log(f"Error: {e}", "error"))
            finally:
                self.root.after(0, self.on_disconnected)

        threading.Thread(target=run_connection, daemon=True).start()

    def on_connected(self):
        """Called when connection is established."""
        self.is_connecting = False
        self.is_connected = True
        self.connection_start = datetime.now()
        self.update_status("Connected", "#27ae60", "#27ae60")
        self.log("Connection established", "success")
        self.update_timer()

    def on_disconnected(self):
        """Called when connection ends."""
        self.is_connecting = False
        self.is_connected = False
        self.process = None
        self.connection_start = None
        self.update_status("Disconnected", "#888", "#888")
        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self.log("Disconnected", "info")

    def disconnect(self):
        """Terminate RDP connection."""
        if self.process:
            self.log("Disconnecting...", "warning")
            self.process.terminate()

    def test_connection(self):
        """Test if server is reachable."""
        server = self.server_entry.get().strip()
        port = self.port_entry.get().strip() or "3389"

        if not server:
            messagebox.showerror("Error", "Enter a server address first")
            return

        self.log(f"Testing connection to {server}:{port}...", "info")

        def do_test():
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((server, int(port)))
                sock.close()

                if result == 0:
                    self.log(f"Success: {server}:{port} is reachable", "success")
                else:
                    self.log(f"Failed: Cannot reach {server}:{port}", "error")
            except socket.gaierror:
                self.log(f"Failed: Cannot resolve hostname {server}", "error")
            except Exception as e:
                self.log(f"Test failed: {e}", "error")

        threading.Thread(target=do_test, daemon=True).start()

    def save_config(self):
        """Save settings to file."""
        config = {
            "server": self.server_entry.get(),
            "port": self.port_entry.get(),
            "user": self.user_entry.get(),
            "domain": self.domain_entry.get(),
            "fullscreen": self.fullscreen_var.get(),
            "multimon": self.multimon_var.get(),
            "dynamic_resolution": self.dynamic_res_var.get(),
            "width": self.width_entry.get(),
            "height": self.height_entry.get(),
            "sound": self.sound_var.get(),
            "microphone": self.mic_var.get(),
            "quality": self.quality_var.get(),
            "share_enabled": self.share_enabled_var.get(),
            "share_path": self.path_entry.get(),
            "share_name": self.share_name_entry.get(),
            "clipboard": self.clipboard_var.get(),
            "security": self.security_var.get(),
            "ignore_cert": self.ignore_cert_var.get(),
            "use_gateway": self.use_gateway_var.get(),
            "gateway": self.gateway_entry.get(),
            "extra_args": self.extra_args_entry.get()
        }

        try:
            with open(self.config_file, "w") as f:
                json.dump(config, f, indent=2)

            # Save password securely
            if HAS_KEYRING and self.passwd_entry.get():
                key = f"{config['user']}@{config['server']}"
                keyring.set_password("rdp_client", key, self.passwd_entry.get())

            self.log("Settings saved", "success")
            messagebox.showinfo("Saved", "Settings saved successfully")
        except Exception as e:
            self.log(f"Failed to save: {e}", "error")
            messagebox.showerror("Error", f"Failed to save settings:\n{e}")

    def load_config(self):
        """Load settings from file."""
        if not os.path.exists(self.config_file):
            self.log("No saved configuration found", "info")
            return

        try:
            with open(self.config_file) as f:
                c = json.load(f)

            self.server_entry.insert(0, c.get("server", ""))
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, c.get("port", "3389"))
            self.user_entry.insert(0, c.get("user", ""))
            self.domain_entry.insert(0, c.get("domain", ""))

            self.fullscreen_var.set(c.get("fullscreen", False))
            self.multimon_var.set(c.get("multimon", True))
            self.dynamic_res_var.set(c.get("dynamic_resolution", True))
            self.width_entry.insert(0, c.get("width", ""))
            self.height_entry.insert(0, c.get("height", ""))

            self.sound_var.set(c.get("sound", True))
            self.mic_var.set(c.get("microphone", False))
            self.quality_var.set(c.get("quality", "auto"))

            self.share_enabled_var.set(c.get("share_enabled", True))
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, c.get("share_path", os.path.expanduser("~/Documents")))
            self.share_name_entry.delete(0, tk.END)
            self.share_name_entry.insert(0, c.get("share_name", "LinuxShare"))
            self.clipboard_var.set(c.get("clipboard", True))

            self.security_var.set(c.get("security", "nla"))
            self.ignore_cert_var.set(c.get("ignore_cert", True))
            self.use_gateway_var.set(c.get("use_gateway", False))
            if c.get("use_gateway"):
                self.gateway_entry.config(state="normal")
            self.gateway_entry.insert(0, c.get("gateway", ""))
            self.extra_args_entry.insert(0, c.get("extra_args", ""))

            # Load password from keyring
            if HAS_KEYRING:
                key = f"{c.get('user', '')}@{c.get('server', '')}"
                stored = keyring.get_password("rdp_client", key)
                if stored:
                    self.passwd_entry.insert(0, stored)

            self.log("Configuration loaded", "success")
        except Exception as e:
            self.log(f"Failed to load config: {e}", "warning")


def main():
    root = tk.Tk()

    # Set window icon if available
    try:
        root.iconname("RDP Client")
    except:
        pass

    app = RDPClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()