#!/bin/bash

# Fix user certificate generation for Easy-RSA 3.x
# This script regenerates a user's certificate with the correct paths

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

if [ -z "$1" ]; then
    error "Usage: $0 <username>"
    exit 1
fi

USERNAME="$1"

log "Fixing certificate for user: $USERNAME"

# Navigate to Easy-RSA directory
cd /etc/openvpn/easy-rsa

# Generate client certificate using Easy-RSA 3.x
log "Generating client certificate for $USERNAME using Easy-RSA 3.x..."
./easyrsa build-client-full "$USERNAME" nopass

# Create client configuration with correct paths
log "Creating client configuration for $USERNAME..."
cat > "/etc/openvpn/client/${USERNAME}.ovpn" << CLIENT_EOF
client
dev tun
proto udp
remote $(curl -s ifconfig.me) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
comp-lzo
verb 3
auth-user-pass
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/easy-rsa/pki/issued/${USERNAME}.crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/pki/private/${USERNAME}.key)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
key-direction 1
CLIENT_EOF

# Set proper permissions
chmod 600 "/etc/openvpn/client/${USERNAME}.ovpn"
chown root:root "/etc/openvpn/client/${USERNAME}.ovpn"

log "Certificate and client configuration created successfully for $USERNAME"
log "Client configuration file: /etc/openvpn/client/${USERNAME}.ovpn"

# Display QR code for Google Authenticator
log "QR code for Google Authenticator setup:"
sudo -u "$USERNAME" google-authenticator -t -d -f -r 3 -R 30 -w 3 -q

log "User certificate fix completed!"
