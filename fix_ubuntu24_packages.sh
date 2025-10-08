#!/bin/bash

# Quick fix for Ubuntu 24.04 package conflicts
# This script resolves the ufw/iptables-persistent conflict

set -euo pipefail

echo "Fixing Ubuntu 24.04 package conflicts..."

# Remove any broken packages
apt autoremove -y
apt autoclean

# Install core packages first
apt update
apt install -y openvpn easy-rsa openssl curl

# Try to install ufw, if it fails, use iptables-persistent
if apt install -y ufw; then
    echo "UFW installed successfully"
    FIREWALL_TYPE="ufw"
else
    echo "UFW installation failed, installing iptables-persistent"
    apt install -y iptables-persistent
    FIREWALL_TYPE="iptables"
fi

echo "Package installation completed successfully!"
echo "Firewall type: $FIREWALL_TYPE"
echo ""
echo "You can now run the OpenVPN installer:"
echo "sudo ./install_openvpn_certpass.sh"
