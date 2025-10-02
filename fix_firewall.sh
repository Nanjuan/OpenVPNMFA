#!/bin/bash

# Fix UFW firewall settings to allow full internet access
# This script configures UFW to allow all necessary traffic

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Configuring UFW firewall for full internet access..."

# Reset UFW to default state
log "Resetting UFW to default state..."
ufw --force reset

# Set default policies to allow all traffic
log "Setting default policies to allow all traffic..."
ufw default allow incoming
ufw default allow outgoing

# Allow essential services
log "Allowing essential services..."
ufw allow ssh
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 53/udp
ufw allow 53/tcp

# Allow OpenVPN
log "Allowing OpenVPN..."
ufw allow 1194/udp

# Allow DNS
log "Allowing DNS..."
ufw allow out 53
ufw allow in 53

# Allow HTTP/HTTPS
log "Allowing HTTP/HTTPS..."
ufw allow out 80
ufw allow out 443
ufw allow in 80
ufw allow in 443

# Allow NTP (time synchronization)
log "Allowing NTP..."
ufw allow out 123/udp
ufw allow in 123/udp


# Allow all outbound traffic
log "Allowing all outbound traffic..."
ufw allow out on any

# Allow all inbound traffic (be careful with this in production)
log "Allowing all inbound traffic..."
ufw allow in on any

# Enable IP forwarding
log "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure NAT for VPN traffic
log "Configuring NAT for VPN traffic..."
cat > /etc/ufw/before.rules << 'EOF'
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]

# Allow traffic from OpenVPN client to the internet
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
-A POSTROUTING -s 10.8.0.0/8 -o ens3 -j MASQUERADE
-A POSTROUTING -s 10.8.0.0/8 -o enp0s3 -j MASQUERADE

# don't delete the 'COMMIT' line or these nat table rules won't be processed
COMMIT
EOF

# Enable UFW
log "Enabling UFW with new rules..."
ufw --force enable

# Check firewall status
log "Checking firewall status..."
ufw status verbose

# Restart OpenVPN service
log "Restarting OpenVPN service..."
systemctl restart openvpn@server.service

# Check OpenVPN status
log "Checking OpenVPN status..."
systemctl status openvpn@server.service

log "Firewall configuration completed!"
log "Full internet access is now allowed while maintaining OpenVPN functionality."
