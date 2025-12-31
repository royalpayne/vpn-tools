#!/usr/bin/env python3
# rdp_server_manager.py — Manage incoming RDP connections via xrdp (2025)

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import os
import threading
import socket
import re

class RDPServerManager:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP Server Manager — Accept Incoming Connections")
        self.root.geometry("750x850")
        self.root.minsize(700, 750)
        self.root.configure(padx=20, pady=20)

        self.create_widgets()
        self.refresh_status()

    def create_widgets(self):
        ttk.Label(self.root, text="RDP Server Manager", font=("Segoe UI", 22, "bold")).pack(pady=(0, 10))
        ttk.Label(self.root, text="Allow remote connections to this computer", font=("Segoe UI", 11)).pack(pady=(0, 20))

        # Status Section
        status_frame = ttk.LabelFrame(self.root, text=" xrdp Server Status ")
        status_frame.pack(fill="x", pady=10)

        status_inner = ttk.Frame(status_frame)
        status_inner.pack(fill="x", padx=15, pady=15)

        self.status_indicator = tk.Canvas(status_inner, width=20, height=20, highlightthickness=0)
        self.status_indicator.pack(side="left", padx=(0, 10))
        self.status_circle = self.status_indicator.create_oval(2, 2, 18, 18, fill="gray", outline="")

        self.status_label = ttk.Label(status_inner, text="Checking...", font=("Segoe UI", 12, "bold"))
        self.status_label.pack(side="left")

        ttk.Button(status_inner, text="↻ Refresh", command=self.refresh_status).pack(side="right")

        # Installation Section
        install_frame = ttk.LabelFrame(self.root, text=" Installation ")
        install_frame.pack(fill="x", pady=10)

        self.install_status = ttk.Label(install_frame, text="Checking xrdp installation...", font=("Segoe UI", 10))
        self.install_status.pack(anchor="w", padx=15, pady=10)

        install_btn_frame = ttk.Frame(install_frame)
        install_btn_frame.pack(fill="x", padx=15, pady=(0, 15))
        self.install_btn = ttk.Button(install_btn_frame, text="Install xrdp", command=self.install_xrdp)
        self.install_btn.pack(side="left")
        ttk.Label(install_btn_frame, text="(requires sudo password)", foreground="gray").pack(side="left", padx=10)

        # Server Controls
        ctrl_frame = ttk.LabelFrame(self.root, text=" Server Controls ")
        ctrl_frame.pack(fill="x", pady=10)

        ctrl_inner = ttk.Frame(ctrl_frame)
        ctrl_inner.pack(fill="x", padx=15, pady=15)

        self.start_btn = ttk.Button(ctrl_inner, text="▶ Start Server", command=self.start_server, style="Accent.TButton")
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = ttk.Button(ctrl_inner, text="■ Stop Server", command=self.stop_server)
        self.stop_btn.pack(side="left", padx=5)
        self.enable_btn = ttk.Button(ctrl_inner, text="Enable on Boot", command=self.enable_autostart)
        self.enable_btn.pack(side="left", padx=5)
        self.disable_btn = ttk.Button(ctrl_inner, text="Disable on Boot", command=self.disable_autostart)
        self.disable_btn.pack(side="left", padx=5)

        # Network Information
        net_frame = ttk.LabelFrame(self.root, text=" Network Information — How to Connect ")
        net_frame.pack(fill="x", pady=10)

        self.net_info = ttk.Frame(net_frame)
        self.net_info.pack(fill="x", padx=15, pady=15)

        # Local IP
        ttk.Label(self.net_info, text="Local IP Address:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.local_ip_label = ttk.Label(self.net_info, text="Detecting...", font=("Consolas", 11))
        self.local_ip_label.grid(row=0, column=1, sticky="w", padx=10, pady=5)
        ttk.Button(self.net_info, text="Copy", command=lambda: self.copy_to_clipboard(self.local_ip_label.cget("text"))).grid(row=0, column=2, padx=5)

        # Port
        ttk.Label(self.net_info, text="RDP Port:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.port_label = ttk.Label(self.net_info, text="3389", font=("Consolas", 11))
        self.port_label.grid(row=1, column=1, sticky="w", padx=10, pady=5)

        # Public IP
        ttk.Label(self.net_info, text="Public IP Address:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w", pady=5)
        self.public_ip_label = ttk.Label(self.net_info, text="Detecting...", font=("Consolas", 11))
        self.public_ip_label.grid(row=2, column=1, sticky="w", padx=10, pady=5)
        ttk.Button(self.net_info, text="Copy", command=lambda: self.copy_to_clipboard(self.public_ip_label.cget("text"))).grid(row=2, column=2, padx=5)

        # Connection string
        ttk.Label(self.net_info, text="Connect from office:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w", pady=5)
        self.connect_str_label = ttk.Label(self.net_info, text="...", font=("Consolas", 11), foreground="blue")
        self.connect_str_label.grid(row=3, column=1, sticky="w", padx=10, pady=5)
        ttk.Button(self.net_info, text="Copy", command=lambda: self.copy_to_clipboard(self.connect_str_label.cget("text"))).grid(row=3, column=2, padx=5)

        # Firewall Section
        fw_frame = ttk.LabelFrame(self.root, text=" Firewall Configuration ")
        fw_frame.pack(fill="x", pady=10)

        fw_inner = ttk.Frame(fw_frame)
        fw_inner.pack(fill="x", padx=15, pady=15)

        self.fw_status = ttk.Label(fw_inner, text="Checking firewall...", font=("Segoe UI", 10))
        self.fw_status.pack(anchor="w")

        fw_btn_frame = ttk.Frame(fw_inner)
        fw_btn_frame.pack(fill="x", pady=10)
        ttk.Button(fw_btn_frame, text="Open Port 3389 (ufw)", command=self.open_firewall_ufw).pack(side="left", padx=5)
        ttk.Button(fw_btn_frame, text="Check Firewall Status", command=self.check_firewall).pack(side="left", padx=5)

        # Connection Guide
        guide_frame = ttk.LabelFrame(self.root, text=" How to Connect from Office ")
        guide_frame.pack(fill="both", expand=True, pady=10)

        guide_text = """To connect to this computer from your office:

1. SAME NETWORK / VPN:
   If your office and home are on the same VPN, use the Local IP address above.
   From Windows: Open Remote Desktop Connection → Enter the Local IP → Connect

2. OVER THE INTERNET (requires router configuration):
   a) Log into your home router (usually 192.168.1.1 or 192.168.0.1)
   b) Find "Port Forwarding" settings
   c) Add a rule: External Port 3389 → Internal IP (Local IP above) → Port 3389
   d) From office, connect using your Public IP address above

3. RECOMMENDED - SECURE OPTIONS:
   • Use a VPN (WireGuard, OpenVPN, Tailscale) between office and home
   • Use SSH tunneling: ssh -L 3389:localhost:3389 user@public-ip
     Then connect to localhost:3389 from office

4. SECURITY NOTES:
   • Exposing port 3389 directly to internet is risky
   • Consider using a non-standard port via router forwarding
   • Tailscale (free) is the easiest secure solution: tailscale.com
"""
        self.guide = scrolledtext.ScrolledText(guide_frame, wrap=tk.WORD, font=("Segoe UI", 10), height=10)
        self.guide.pack(fill="both", expand=True, padx=10, pady=10)
        self.guide.insert("1.0", guide_text)
        self.guide.config(state="disabled")

        # Detect IPs on startup
        threading.Thread(target=self.detect_ips, daemon=True).start()

    def run_cmd(self, cmd, sudo=False, capture=True):
        """Run a shell command, optionally with sudo."""
        try:
            if sudo:
                full_cmd = f"pkexec {cmd}"
            else:
                full_cmd = cmd
            result = subprocess.run(full_cmd, shell=True, capture_output=capture, text=True, timeout=30)
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def refresh_status(self):
        """Check xrdp installation and running status."""
        # Check if installed
        installed, _ = self.run_cmd("which xrdp")
        if installed:
            self.install_status.config(text="✓ xrdp is installed", foreground="green")
            self.install_btn.config(state="disabled")
        else:
            self.install_status.config(text="✗ xrdp is not installed", foreground="red")
            self.install_btn.config(state="normal")
            self.status_label.config(text="Not Installed")
            self.status_indicator.itemconfig(self.status_circle, fill="gray")
            return

        # Check if running
        running, output = self.run_cmd("systemctl is-active xrdp")
        if "active" in output.strip():
            self.status_label.config(text="Running")
            self.status_indicator.itemconfig(self.status_circle, fill="#2ecc71")
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
        else:
            self.status_label.config(text="Stopped")
            self.status_indicator.itemconfig(self.status_circle, fill="#e74c3c")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

        # Check autostart
        enabled, output = self.run_cmd("systemctl is-enabled xrdp")
        if "enabled" in output.strip():
            self.enable_btn.config(state="disabled")
            self.disable_btn.config(state="normal")
        else:
            self.enable_btn.config(state="normal")
            self.disable_btn.config(state="disabled")

        self.check_firewall()

    def install_xrdp(self):
        """Install xrdp package."""
        self.install_status.config(text="Installing xrdp... (check terminal for password prompt)", foreground="orange")
        self.root.update()

        def do_install():
            success, output = self.run_cmd("apt-get update && apt-get install -y xrdp", sudo=True)
            if success:
                # Add user to ssl-cert group for xrdp
                self.run_cmd(f"usermod -a -G ssl-cert {os.environ.get('USER', 'user')}", sudo=True)
                self.root.after(0, lambda: messagebox.showinfo("Success", "xrdp installed successfully!\nYou may need to log out and back in for group changes."))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Installation failed:\n{output}"))
            self.root.after(0, self.refresh_status)

        threading.Thread(target=do_install, daemon=True).start()

    def start_server(self):
        """Start xrdp service."""
        def do_start():
            success, output = self.run_cmd("systemctl start xrdp", sudo=True)
            if not success:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to start:\n{output}"))
            self.root.after(0, self.refresh_status)

        threading.Thread(target=do_start, daemon=True).start()

    def stop_server(self):
        """Stop xrdp service."""
        def do_stop():
            success, output = self.run_cmd("systemctl stop xrdp", sudo=True)
            if not success:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to stop:\n{output}"))
            self.root.after(0, self.refresh_status)

        threading.Thread(target=do_stop, daemon=True).start()

    def enable_autostart(self):
        """Enable xrdp on boot."""
        def do_enable():
            success, output = self.run_cmd("systemctl enable xrdp", sudo=True)
            if success:
                self.root.after(0, lambda: messagebox.showinfo("Success", "xrdp will start automatically on boot"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed:\n{output}"))
            self.root.after(0, self.refresh_status)

        threading.Thread(target=do_enable, daemon=True).start()

    def disable_autostart(self):
        """Disable xrdp on boot."""
        def do_disable():
            success, output = self.run_cmd("systemctl disable xrdp", sudo=True)
            self.root.after(0, self.refresh_status)

        threading.Thread(target=do_disable, daemon=True).start()

    def detect_ips(self):
        """Detect local and public IP addresses."""
        # Local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "Unable to detect"

        self.root.after(0, lambda: self.local_ip_label.config(text=local_ip))

        # Public IP
        try:
            result = subprocess.run(["curl", "-s", "https://api.ipify.org"], capture_output=True, text=True, timeout=10)
            public_ip = result.stdout.strip() if result.returncode == 0 else "Unable to detect"
        except:
            public_ip = "Unable to detect"

        self.root.after(0, lambda: self.public_ip_label.config(text=public_ip))
        self.root.after(0, lambda: self.connect_str_label.config(text=f"{public_ip}:3389"))

    def check_firewall(self):
        """Check firewall status for port 3389."""
        # Check if ufw is active
        success, output = self.run_cmd("ufw status")
        if "inactive" in output.lower():
            self.fw_status.config(text="UFW firewall is inactive (port should be accessible)", foreground="green")
        elif "3389" in output and "ALLOW" in output:
            self.fw_status.config(text="✓ Port 3389 is open in UFW firewall", foreground="green")
        elif "active" in output.lower():
            self.fw_status.config(text="⚠ UFW is active but port 3389 may not be open", foreground="orange")
        else:
            self.fw_status.config(text="Unable to determine firewall status", foreground="gray")

    def open_firewall_ufw(self):
        """Open port 3389 in UFW firewall."""
        def do_open():
            success, output = self.run_cmd("ufw allow 3389/tcp", sudo=True)
            if success:
                self.root.after(0, lambda: messagebox.showinfo("Success", "Port 3389 opened in UFW firewall"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed:\n{output}"))
            self.root.after(0, self.check_firewall)

        threading.Thread(target=do_open, daemon=True).start()

    def copy_to_clipboard(self, text):
        """Copy text to clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", f"Copied to clipboard:\n{text}")


if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Accent.TButton", foreground="white", background="#0078D4", font=("Segoe UI", 10, "bold"))
    app = RDPServerManager(root)
    root.mainloop()
