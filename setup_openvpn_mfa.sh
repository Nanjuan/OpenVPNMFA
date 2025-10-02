#!/bin/bash

# OpenVPN Server Setup with MFA (Google Authenticator) on Ubuntu
# This script automates the complete setup of OpenVPN with PAM-based MFA
# Author: OpenVPN MFA Setup Script
# Version: 1.0

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Check Ubuntu version
if ! grep -q "Ubuntu" /etc/os-release; then
    error "This script is designed for Ubuntu. Please run on Ubuntu system."
fi

log "Starting OpenVPN with MFA setup..."

# Update system packages
log "Updating system packages..."
apt update && apt upgrade -y

# Install required packages
log "Installing required packages..."
apt install -y openvpn easy-rsa libpam-google-authenticator qrencode ufw

# Create OpenVPN directory structure
log "Creating OpenVPN directory structure..."
mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/client
mkdir -p /etc/openvpn/ccd
mkdir -p /var/log/openvpn

# Set up Easy-RSA
log "Setting up Easy-RSA..."
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# Configure Easy-RSA
log "Configuring Easy-RSA..."
cat > vars << EOF
export KEY_COUNTRY="US"
export KEY_PROVINCE="CA"
export KEY_CITY="SanFrancisco"
export KEY_ORG="OpenVPN"
export KEY_EMAIL="admin@example.com"
export KEY_OU="IT"
export KEY_NAME="OpenVPN-CA"
EOF

# Initialize PKI
log "Initializing PKI..."
source vars
./clean-all
./build-ca --batch

# Generate server certificate and key
log "Generating server certificate..."
./build-key-server --batch server

# Generate Diffie-Hellman parameters
log "Generating Diffie-Hellman parameters..."
./build-dh

# Generate TLS-auth key
log "Generating TLS-auth key..."
openvpn --genkey --secret ta.key

# Move certificates to proper locations
log "Moving certificates to proper locations..."
cp keys/ca.crt /etc/openvpn/
cp keys/server.crt /etc/openvpn/
cp keys/server.key /etc/openvpn/
cp keys/dh2048.pem /etc/openvpn/
cp ta.key /etc/openvpn/

# Set proper permissions
chmod 600 /etc/openvpn/server.key
chmod 600 /etc/openvpn/ta.key
chmod 644 /etc/openvpn/ca.crt
chmod 644 /etc/openvpn/server.crt
chmod 644 /etc/openvpn/dh2048.pem

# Create OpenVPN server configuration
log "Creating OpenVPN server configuration..."
cat > /etc/openvpn/server.conf << 'EOF'
# OpenVPN Server Configuration with MFA Support
port 1194
proto udp
dev tun

# Certificate and key files
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
tls-auth ta.key 0

# Network configuration
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# Push routes to client
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Client configuration directory
client-config-dir ccd

# Keepalive settings
keepalive 10 120

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Compression
comp-lzo

# Logging
log-append /var/log/openvpn/openvpn.log
verb 3

# User authentication
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn

# Additional security
remote-cert-tls client
tls-auth ta.key 0
key-direction 0

# Prevent DNS leaks
push "block-outside-dns"

# Disable weak protocols
tls-version-min 1.2
EOF

# Create PAM configuration for OpenVPN
log "Creating PAM configuration..."
cat > /etc/pam.d/openvpn << 'EOF'
# PAM configuration for OpenVPN with Google Authenticator
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
account required pam_unix.so
session required pam_unix.so
EOF

# Create user management script
log "Creating user management script..."
cat > /usr/local/bin/openvpn-user-mgmt.sh << 'EOF'
#!/bin/bash

# OpenVPN User Management Script with MFA Setup

case "$1" in
    add)
        if [ -z "$2" ]; then
            echo "Usage: $0 add <username>"
            exit 1
        fi
        USERNAME="$2"
        
        # Create user if doesn't exist
        if ! id "$USERNAME" &>/dev/null; then
            useradd -m -s /bin/bash "$USERNAME"
            echo "User $USERNAME created"
        fi
        
        # Set up Google Authenticator for user
        sudo -u "$USERNAME" google-authenticator -t -d -f -r 3 -R 30 -w 3
        
        # Generate client certificate
        cd /etc/openvpn/easy-rsa
        source vars
        ./build-key --batch "$USERNAME"
        
        # Create client configuration
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
$(cat /etc/openvpn/easy-rsa/keys/${USERNAME}.crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/keys/${USERNAME}.key)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
key-direction 1
CLIENT_EOF
        
        echo "Client configuration created: /etc/openvpn/client/${USERNAME}.ovpn"
        echo "QR code for Google Authenticator setup:"
        sudo -u "$USERNAME" google-authenticator -t -d -f -r 3 -R 30 -w 3 -q
        ;;
        
    revoke)
        if [ -z "$2" ]; then
            echo "Usage: $0 revoke <username>"
            exit 1
        fi
        USERNAME="$2"
        
        # Revoke certificate
        cd /etc/openvpn/easy-rsa
        source vars
        ./revoke-full "$USERNAME"
        
        # Remove client config
        rm -f "/etc/openvpn/client/${USERNAME}.ovpn"
        
        echo "Certificate revoked for user: $USERNAME"
        ;;
        
    list)
        echo "Active OpenVPN users:"
        ls -la /etc/openvpn/client/*.ovpn 2>/dev/null | awk '{print $9}' | sed 's|/etc/openvpn/client/||' | sed 's|.ovpn||'
        ;;
        
    *)
        echo "Usage: $0 {add|revoke|list} [username]"
        echo "  add <username>    - Add new user with MFA"
        echo "  revoke <username> - Revoke user certificate"
        echo "  list              - List active users"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/openvpn-user-mgmt.sh

# Configure firewall
log "Configuring firewall..."
ufw --force enable
ufw allow 1194/udp
ufw allow ssh
ufw allow 22/tcp

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

# don't delete the 'COMMIT' line or these nat table rules won't be processed
COMMIT
EOF

# Restart UFW to apply NAT rules
ufw --force reload

# Create systemd service for OpenVPN
log "Creating systemd service..."
cat > /etc/systemd/system/openvpn@server.service << 'EOF'
[Unit]
Description=OpenVPN connection to %i
After=network.target

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn/server
ExecStart=/usr/sbin/openvpn --config %i.conf --writepid /run/openvpn/%i.pid
PIDFile=/run/openvpn/%i.pid
KillMode=mixed
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Enable and start OpenVPN service
log "Enabling and starting OpenVPN service..."
systemctl daemon-reload
systemctl enable openvpn@server
systemctl start openvpn@server

# Create log rotation for OpenVPN
log "Setting up log rotation..."
cat > /etc/logrotate.d/openvpn << 'EOF'
/var/log/openvpn/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload openvpn@server
    endscript
}
EOF

# Create client setup instructions
log "Creating client setup instructions..."
cat > /etc/openvpn/client-setup-instructions.txt << 'EOF'
OpenVPN Client Setup Instructions
==================================

1. ANDROID SETUP:
   - Install "OpenVPN Connect" from Google Play Store
   - Transfer the .ovpn file to your Android device
   - Open the .ovpn file with OpenVPN Connect
   - Enter your username and password (password + MFA code)
   - Connect to the VPN

2. iOS SETUP:
   - Install "OpenVPN Connect" from App Store
   - Transfer the .ovpn file to your iOS device via email or cloud storage
   - Open the .ovpn file with OpenVPN Connect
   - Enter your username and password (password + MFA code)
   - Connect to the VPN

3. AUTHENTICATION:
   - Username: Your system username
   - Password: Your system password + 6-digit MFA code (no space)
   - Example: If your password is "mypass123" and MFA code is "123456"
     Enter: "mypass123123456"

4. SECURITY NOTES:
   - Keep your MFA device secure
   - Do not share your .ovpn file
   - Use strong passwords
   - Regularly update your MFA codes

5. TROUBLESHOOTING:
   - Check server logs: /var/log/openvpn/openvpn.log
   - Verify firewall settings
   - Ensure certificates are valid
   - Check PAM configuration
EOF

# Set up log directory permissions
mkdir -p /var/log/openvpn
chown root:root /var/log/openvpn
chmod 755 /var/log/openvpn

# Create initial admin user
log "Creating initial admin user..."
read -p "Enter admin username: " ADMIN_USER
if [ -n "$ADMIN_USER" ]; then
    /usr/local/bin/openvpn-user-mgmt.sh add "$ADMIN_USER"
fi

log "OpenVPN server setup completed successfully!"
log "Server IP: $(curl -s ifconfig.me)"
log "Port: 1194 (UDP)"
log "Client configs location: /etc/openvpn/client/"
log "Setup instructions: /etc/openvpn/client-setup-instructions.txt"
log "User management: /usr/local/bin/openvpn-user-mgmt.sh"

echo ""
echo "Next steps:"
echo "1. Add users: /usr/local/bin/openvpn-user-mgmt.sh add <username>"
echo "2. Distribute .ovpn files to clients"
echo "3. Test connection from mobile devices"
echo "4. Monitor logs: tail -f /var/log/openvpn/openvpn.log"

