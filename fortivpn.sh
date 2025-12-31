#!/bin/bash
# fortivpn — FortiGate VPN connection script using openfortivpn
#
# SETUP:
# 1. Install openfortivpn: sudo apt install openfortivpn
# 2. Edit this script with your VPN server details
# 3. Copy to /usr/local/bin/fortivpn: sudo cp fortivpn.sh /usr/local/bin/fortivpn
# 4. Make executable: sudo chmod +x /usr/local/bin/fortivpn

# ============ CONFIGURE THESE ============
VPN_SERVER="your.vpn.server.com"    # VPN server IP or hostname
VPN_PORT="10443"                     # VPN port (commonly 443 or 10443)
VPN_USER="your_username"             # Your VPN username
# =========================================

echo "Connecting to ${VPN_SERVER}:${VPN_PORT} as ${VPN_USER}..."
echo "You will be prompted for password → then MFA (Duo/etc) if configured"

sudo openfortivpn "${VPN_SERVER}:${VPN_PORT}" --username="${VPN_USER}"

# Final status
if ip route | grep -q ppp; then
    echo -e "\nSUCCESS: VPN IS UP!"
else
    echo -e "\nVPN disconnected or failed"
fi