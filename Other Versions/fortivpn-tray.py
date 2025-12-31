#!/usr/bin/env python3
# fortivpn-tray.py — FINAL clean version (no password echo, no warnings)

import subprocess
import threading
from PIL import Image, ImageDraw
import pystray
import signal
import os
import sys

process = None

def create_image(color):
    img = Image.new('RGB', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((8, 8, 56, 56), fill=color)
    return img

connected_img    = create_image("#00ff00")
disconnected_img = create_image("#ff4444")

def connect(icon):
    global process
    if process and process.poll() is None:
        return

    def run():
        global process
        cmd = ["sudo", "-S", "openfortivpn", "12.38.215.141:12163", "--username=hpayne"]
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # Send password non-interactively and hidden
        process.communicate(input=b"Goldsmith197!\n")
        process = None
        icon.icon = disconnected_img
        icon.title = "FortiVPN – Disconnected"

    threading.Thread(target=run, daemon=True).start()
    icon.icon = connected_img
    icon.title = "FortiVPN – Connected"

def disconnect(icon):
    global process
    if process and process.poll() is None:
        process.terminate()
        process = None
    icon.icon = disconnected_img
    icon.title = "FortiVPN – Disconnected"

def quit_app(icon):
    disconnect(icon)
    icon.stop()
    os._exit(0)

menu = pystray.Menu(
    pystray.MenuItem("Connect", connect),
    pystray.MenuItem("Disconnect", disconnect),
    pystray.Menu.SEPARATOR,
    pystray.MenuItem("Quit", quit_app)
)

icon = pystray.Icon("FortiVPN", disconnected_img, "FortiVPN – Click to connect", menu)

# Clean shutdown
signal.signal(signal.SIGINT,  lambda s, f: quit_app(icon))
signal.signal(signal.SIGTERM, lambda s, f: quit_app(icon))

icon.run()
