#!/bin/bash

# Fix script for OpenVPN installation issues
# Run this if the main installation failed

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

log "Fixing OpenVPN installation..."

# Detect Ubuntu version for compatibility
UBUNTU_VERSION=$(lsb_release -rs)
UBUNTU_CODENAME=$(lsb_release -cs)
log "Detected Ubuntu $UBUNTU_VERSION ($UBUNTU_CODENAME)"

# Install OpenVPN from Ubuntu repositories (more reliable)
log "Installing OpenVPN from Ubuntu repositories..."
apt update
apt install -y openvpn easy-rsa ufw iptables-persistent fail2ban unattended-upgrades

# Verify versions
OPENVPN_VERSION=$(openvpn --version | head -n1 | awk '{print $2}')
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
log "OpenVPN version: $OPENVPN_VERSION"
log "OpenSSL version: $OPENSSL_VERSION"

# Check if OpenVPN is installed
if command -v openvpn &> /dev/null; then
    log "OpenVPN installed successfully"
    openvpn --version
else
    error "OpenVPN installation failed"
    exit 1
fi

# Continue with the rest of the setup
log "Continuing with OpenVPN configuration..."

# Setup EasyRSA
OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_NAME="server"

log "Setting up EasyRSA Certificate Authority..."
rm -rf $EASYRSA_DIR
cp -r /usr/share/easy-rsa $EASYRSA_DIR
cd $EASYRSA_DIR
./easyrsa init-pki
./easyrsa --batch --req-cn="OpenVPN-CA" build-ca nopass
./easyrsa gen-dh
openvpn --genkey --secret pki/ta.key
./easyrsa --batch --req-cn="OpenVPN-Server" build-server-full $SERVER_NAME nopass

# Configure OpenVPN server
log "Configuring OpenVPN server..."
cat > $OPENVPN_DIR/$SERVER_NAME.conf << EOF
# OpenVPN Server Configuration
port 1194
proto udp
dev tun

# Certificate and key files
ca $EASYRSA_DIR/pki/ca.crt
cert $EASYRSA_DIR/pki/issued/$SERVER_NAME.crt
key $EASYRSA_DIR/pki/private/$SERVER_NAME.key
dh $EASYRSA_DIR/pki/dh.pem
tls-crypt $EASYRSA_DIR/pki/ta.key

# Network topology
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# Client configuration
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Security settings
cipher AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384

# Perfect Forward Secrecy
tls-crypt $EASYRSA_DIR/pki/ta.key

# Additional security
remote-cert-tls client
tls-auth $EASYRSA_DIR/pki/ta.key 0
key-direction 0

# Compression
comp-lzo

# Logging
log-append /var/log/openvpn/openvpn.log
verb 3
mute 20

# Status file
status /var/log/openvpn/openvpn-status.log
status-version 2

# Client timeout settings
keepalive 10 120

# Security enhancements
explicit-exit-notify 1
tls-server
tls-version-min 1.2
EOF

# Create directories
mkdir -p /var/log/openvpn
mkdir -p /etc/openvpn/clients
mkdir -p /etc/openvpn/backup
chown openvpn:openvpn /var/log/openvpn /etc/openvpn/clients /etc/openvpn/backup

# Configure firewall
log "Configuring firewall..."
ufw --force enable
ufw allow ssh
ufw allow 1194/udp

# Configure IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure NAT for VPN traffic
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $(ip route | grep default | awk '{print $5}') -j MASQUERADE
iptables-save > /etc/iptables/rules.v4

# Enable and start OpenVPN service
systemctl enable openvpn@$SERVER_NAME
systemctl start openvpn@$SERVER_NAME

# Create management script
cat > /usr/local/bin/openvpn-manage << 'EOF'
#!/bin/bash

# OpenVPN Management Script
set -euo pipefail

OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
SERVER_NAME="server"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

show_usage() {
    echo "OpenVPN Management Script"
    echo ""
    echo "Usage: $0 [command] [username]"
    echo ""
    echo "Commands:"
    echo "  add <username>     - Add a new VPN user"
    echo "  remove <username>  - Remove a VPN user"
    echo "  renew <username>   - Renew user certificate"
    echo "  list               - List all users"
    echo "  status             - Show server status"
    echo "  restart            - Restart OpenVPN service"
    echo ""
}

add_user() {
    local username=$1
    if [[ -z "$username" ]]; then
        error "Username is required"
        return 1
    fi
    
    if [[ -f "$EASYRSA_DIR/pki/issued/$username.crt" ]]; then
        warning "User $username already exists"
        return 1
    fi
    
    log "Adding user: $username"
    cd $EASYRSA_DIR
    ./easyrsa --batch --req-cn="$username" build-client-full "$username" nopass
    
    # Generate client configuration
    local server_ip=$(curl -s ifconfig.me)
    cat > "$CLIENT_DIR/$username.ovpn" << CLIENT_EOF
client
dev tun
proto udp
remote $server_ip 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA512
verb 3
mute 20

<ca>
$(cat $EASYRSA_DIR/pki/ca.crt)
</ca>

<cert>
$(cat $EASYRSA_DIR/pki/issued/$username.crt)
</cert>

<key>
$(cat $EASYRSA_DIR/pki/private/$username.key)
</key>

<tls-crypt>
$(cat $EASYRSA_DIR/pki/ta.key)
</tls-crypt>
CLIENT_EOF

    chmod 600 "$CLIENT_DIR/$username.ovpn"
    log "User $username added successfully"
    info "Client configuration: $CLIENT_DIR/$username.ovpn"
}

remove_user() {
    local username=$1
    if [[ -z "$username" ]]; then
        error "Username is required"
        return 1
    fi
    
    if [[ ! -f "$EASYRSA_DIR/pki/issued/$username.crt" ]]; then
        warning "User $username does not exist"
        return 1
    fi
    
    log "Removing user: $username"
    cd $EASYRSA_DIR
    ./easyrsa revoke "$username"
    ./easyrsa gen-crl
    cp pki/crl.pem $OPENVPN_DIR/
    rm -f "$CLIENT_DIR/$username.ovpn"
    systemctl restart openvpn@$SERVER_NAME
    log "User $username removed successfully"
}

renew_user() {
    local username=$1
    if [[ -z "$username" ]]; then
        error "Username is required"
        return 1
    fi
    
    if [[ ! -f "$EASYRSA_DIR/pki/issued/$username.crt" ]]; then
        warning "User $username does not exist"
        return 1
    fi
    
    log "Renewing certificate for user: $username"
    cd $EASYRSA_DIR
    ./easyrsa revoke "$username"
    ./easyrsa --batch --req-cn="$username" build-client-full "$username" nopass
    ./easyrsa gen-crl
    cp pki/crl.pem $OPENVPN_DIR/
    systemctl restart openvpn@$SERVER_NAME
    log "Certificate renewed for user: $username"
}

list_users() {
    log "VPN Users:"
    cd $EASYRSA_DIR
    if [[ -d "pki/issued" ]]; then
        ls -1 pki/issued/*.crt 2>/dev/null | sed 's/.*\///' | sed 's/\.crt$//' | grep -v "$SERVER_NAME" || echo "No users found"
    else
        echo "No users found"
    fi
}

show_status() {
    log "OpenVPN Server Status:"
    systemctl status openvpn@$SERVER_NAME --no-pager
    echo ""
    log "Connected clients:"
    if [[ -f "/var/log/openvpn/openvpn-status.log" ]]; then
        cat /var/log/openvpn/openvpn-status.log | grep "CLIENT_LIST" | wc -l
    else
        echo "0"
    fi
}

# Main script logic
case "${1:-}" in
    add)
        add_user "$2"
        ;;
    remove)
        remove_user "$2"
        ;;
    renew)
        renew_user "$2"
        ;;
    list)
        list_users
        ;;
    status)
        show_status
        ;;
    restart)
        systemctl restart openvpn@$SERVER_NAME
        log "OpenVPN service restarted"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/openvpn-manage

log "OpenVPN installation and configuration completed successfully!"
info "Server IP: $(curl -s ifconfig.me)"
info "VPN Port: 1194"
info "Management command: openvpn-manage"

warning "Next steps:"
warning "1. Add your first user: sudo openvpn-manage add <username>"
warning "2. Download client config: sudo cp /etc/openvpn/clients/<username>.ovpn /tmp/"
warning "3. Transfer to your local machine: scp user@server:/tmp/<username>.ovpn ~/"
