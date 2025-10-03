#!/usr/bin/env bash

set -euo pipefail
umask 027

# OpenVPN Server Setup with MFA - Production Ready
# Best practices implementation with modern security standards

SCRIPT_NAME=$(basename "$0")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Configuration variables
OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
LOG_DIR="/var/log/openvpn"
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
VPN_NETWORK="10.8.0.0"
VPN_NETMASK="255.255.255.0"
VPN_PORT="1194"
VPN_PROTO="udp"
ECDH_CURVE="prime256v1"

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Update system packages
update_system() {
    log "Updating system packages..."
    apt update && apt upgrade -y
    success "System packages updated"
}

# Install required packages
install_packages() {
    log "Installing required packages..."
    apt install -y \
        openvpn \
        easy-rsa \
        libpam-google-authenticator \
        qrencode \
        oathtool \
        curl \
        wget \
        unzip \
        net-tools \
        iptables-persistent \
        netfilter-persistent
    success "Required packages installed"
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    mkdir -p "$OPENVPN_DIR"
    mkdir -p "$CLIENT_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$EASYRSA_DIR"
    
    # Set proper permissions
    chmod 750 "$OPENVPN_DIR"
    chmod 750 "$CLIENT_DIR"
    chmod 750 "$LOG_DIR"
    chmod 750 "$EASYRSA_DIR"
    
    success "Directory structure created"
}

# Setup Easy-RSA v3
setup_easyrsa() {
    log "Setting up Easy-RSA v3..."
    
    # Copy Easy-RSA from system location
    cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR/"
    cd "$EASYRSA_DIR"
    
    # Configure Easy-RSA with modern settings
    cat > vars << EOF
set_var EASYRSA_ALGO "ec"
set_var EASYRSA_CURVE "${ECDH_CURVE}"
set_var EASYRSA_BATCH "1"
set_var EASYRSA_REQ_COUNTRY "US"
set_var EASYRSA_REQ_PROVINCE "California"
set_var EASYRSA_REQ_CITY "San Francisco"
set_var EASYRSA_REQ_ORG "OpenVPN-CA"
set_var EASYRSA_REQ_EMAIL "admin@openvpn.local"
set_var EASYRSA_REQ_OU "IT Department"
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 825
set_var EASYRSA_CRL_DAYS 60
EOF
    
    # Initialize PKI
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa build-server-full server nopass
    ./easyrsa gen-dh
    openvpn --genkey secret ta.key
    
    # Generate CRL (Certificate Revocation List)
    log "Generating Certificate Revocation List..."
    ./easyrsa gen-crl
    chmod 644 pki/crl.pem
    
    # Verify CRL was created
    if [ ! -f "pki/crl.pem" ]; then
        error "Failed to create CRL file"
        exit 1
    fi
    
    success "Easy-RSA setup completed with CRL"
}

# Generate server configuration with modern security
generate_server_config() {
    log "Generating OpenVPN server configuration..."
    
    cat > "$OPENVPN_DIR/server.conf" << EOF
# OpenVPN Server Configuration - Production Ready
# Port and Protocol
port $VPN_PORT
proto $VPN_PROTO
dev tun
topology subnet

# Network configuration
server $VPN_NETWORK $VPN_NETMASK
ifconfig-pool-persist $OPENVPN_DIR/ipp.txt

# Client configuration
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "route $VPN_NETWORK $VPN_NETMASK"

# Security settings - Modern standards
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC

# Certificate files
ca $OPENVPN_DIR/ca.crt
cert $OPENVPN_DIR/server.crt
key $OPENVPN_DIR/server.key
dh $OPENVPN_DIR/dh.pem
tls-crypt $OPENVPN_DIR/ta.key

# Authentication via PAM
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so openvpn
verify-client-cert require
username-as-common-name
script-security 2

# CRL verification
crl-verify $EASYRSA_DIR/pki/crl.pem

# Logging
log $LOG_DIR/openvpn.log
log-append $LOG_DIR/openvpn.log
status $LOG_DIR/openvpn-status.log
status-version 2
verb 3

# Performance
keepalive 10 120
persist-key
persist-tun

# Security
user nobody
group nogroup
writepid /run/openvpn/server.pid

# Client limits
max-clients 100

# Additional security
explicit-exit-notify 1
EOF
    
    success "Server configuration generated"
}

# Create PAM configuration for Google Authenticator
create_pam_config() {
    log "Creating PAM configuration..."
    
    cat > /etc/pam.d/openvpn << 'EOF'
auth requisite pam_google_authenticator.so nullok
auth required pam_unix.so
account required pam_unix.so
EOF
    
    chmod 644 /etc/pam.d/openvpn
    success "PAM configuration created"
}

# Copy certificates
copy_certificates() {
    log "Copying certificates..."
    cp "$EASYRSA_DIR/pki/ca.crt" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/pki/issued/server.crt" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/pki/private/server.key" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/pki/dh.pem" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/ta.key" "$OPENVPN_DIR/"
    
    # Verify CRL exists before copying
    if [ ! -f "$EASYRSA_DIR/pki/crl.pem" ]; then
        error "CRL file not found. Regenerating..."
        cd "$EASYRSA_DIR"
        ./easyrsa gen-crl
        chmod 644 pki/crl.pem
    fi
    
    # Set proper permissions
    chmod 600 "$OPENVPN_DIR"/*.key
    chmod 644 "$OPENVPN_DIR"/*.crt
    chmod 644 "$OPENVPN_DIR"/*.pem
    chmod 600 "$OPENVPN_DIR"/ta.key
    
    # Verify all required files exist
    local required_files=("$OPENVPN_DIR/ca.crt" "$OPENVPN_DIR/server.crt" "$OPENVPN_DIR/server.key" "$OPENVPN_DIR/dh.pem" "$OPENVPN_DIR/ta.key" "$EASYRSA_DIR/pki/crl.pem")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            error "Required file missing: $file"
            exit 1
        fi
    done
    
    success "Certificates copied and permissions set"
}

# Enable IP forwarding
enable_ip_forwarding() {
    log "Enabling IP forwarding..."
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    sysctl -p
    success "IP forwarding enabled"
}

# Configure NAT
configure_nat() {
    log "Configuring NAT..."
    
    # Get the default interface
    WAN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # Add NAT rule
    iptables -t nat -A POSTROUTING -s $VPN_NETWORK/24 -o $WAN_INTERFACE -j MASQUERADE
    
    # Save iptables rules
    netfilter-persistent save
    
    success "NAT configured"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    cat > /etc/systemd/system/openvpn@server.service << EOF
[Unit]
Description=OpenVPN connection to %i
Documentation=man:openvpn(8)
After=network-online.target
Wants=network-online.target
PartOf=openvpn.service
ReloadPropagatedFrom=openvpn.service

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=$OPENVPN_DIR
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/%i.conf --writepid /run/openvpn/%i.pid
PIDFile=/run/openvpn/%i.pid
KillMode=mixed
Restart=always
RestartSec=5
TimeoutStartSec=0
LimitNOFILE=1048576
LimitNPROC=1048576
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    success "Systemd service created"
}

# Create user management script
create_user_management() {
    log "Creating user management script..."
    
    cat > /usr/local/bin/openvpn-user-mgmt << 'EOF'
#!/bin/bash

# OpenVPN User Management Script
# Usage: openvpn-user-mgmt [add|remove|list|renew] [username]

set -e

OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
VPN_PORT="1194"
VPN_PROTO="udp"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

show_usage() {
    echo "Usage: $0 [add|remove|list|renew] [username]"
    echo ""
    echo "Commands:"
    echo "  add <username>    - Add a new OpenVPN user"
    echo "  remove <username> - Remove an OpenVPN user"
    echo "  list             - List all OpenVPN users"
    echo "  renew <username> - Renew user certificate"
    echo ""
    echo "Examples:"
    echo "  $0 add john"
    echo "  $0 remove john"
    echo "  $0 list"
    echo "  $0 renew john"
}

add_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
        exit 1
    fi
    
    log "Adding user: $username"
    
    # Create Linux user
    if ! id "$username" &>/dev/null; then
        useradd -m -s /bin/bash "$username"
        success "Linux user created: $username"
    else
        warning "Linux user already exists: $username"
    fi
    
    # Set password
    echo "Enter password for $username:"
    read -s password
    echo "$username:$password" | chpasswd
    success "Password set for $username"
    
    # Setup Google Authenticator
    log "Setting up Google Authenticator for $username"
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3
    
    # Generate client certificate
    cd "$EASYRSA_DIR"
    ./easyrsa build-client-full "$username" nopass
    
    # Generate CRL
    ./easyrsa gen-crl
    
    # Create client configuration
    cat > "$CLIENT_DIR/$username.ovpn" << CLIENT_EOF
client
dev tun
proto $VPN_PROTO
remote $SERVER_IP $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
verb 3
auth-user-pass

<ca>
$(cat $OPENVPN_DIR/ca.crt)
</ca>

<cert>
$(cat $EASYRSA_DIR/pki/issued/$username.crt)
</cert>

<key>
$(cat $EASYRSA_DIR/pki/private/$username.key)
</key>

<tls-crypt>
$(cat $OPENVPN_DIR/ta.key)
</tls-crypt>
CLIENT_EOF
    
    chmod 600 "$CLIENT_DIR/$username.ovpn"
    success "Client configuration created: $CLIENT_DIR/$username.ovpn"
    
    # Show QR code
    log "QR Code for Google Authenticator setup:"
    qrencode -t ANSIUTF8 < "/home/$username/.google_authenticator"
    
    success "User $username added successfully"
}

remove_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
        exit 1
    fi
    
    log "Removing user: $username"
    
    # Revoke certificate
    cd "$EASYRSA_DIR"
    ./easyrsa revoke "$username"
    ./easyrsa gen-crl
    
    # Remove client configuration
    rm -f "$CLIENT_DIR/$username.ovpn"
    
    # Remove Linux user
    userdel -r "$username" 2>/dev/null || true
    
    success "User $username removed successfully"
}

list_users() {
    log "Listing OpenVPN users..."
    
    echo "OpenVPN Users:"
    echo "=============="
    
    for user in "$CLIENT_DIR"/*.ovpn; do
        if [ -f "$user" ]; then
            username=$(basename "$user" .ovpn)
            if id "$username" &>/dev/null; then
                echo "✅ $username (Active)"
            else
                echo "❌ $username (User not found)"
            fi
        fi
    done
}

renew_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
        exit 1
    fi
    
    log "Renewing certificate for user: $username"
    
    # Revoke old certificate
    cd "$EASYRSA_DIR"
    ./easyrsa revoke "$username"
    
    # Generate new certificate
    ./easyrsa build-client-full "$username" nopass
    
    # Generate CRL
    ./easyrsa gen-crl
    
    # Update client configuration
    cat > "$CLIENT_DIR/$username.ovpn" << CLIENT_EOF
client
dev tun
proto $VPN_PROTO
remote $SERVER_IP $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
verb 3
auth-user-pass

<ca>
$(cat $OPENVPN_DIR/ca.crt)
</ca>

<cert>
$(cat $EASYRSA_DIR/pki/issued/$username.crt)
</cert>

<key>
$(cat $EASYRSA_DIR/pki/private/$username.key)
</key>

<tls-crypt>
$(cat $OPENVPN_DIR/ta.key)
</tls-crypt>
CLIENT_EOF
    
    chmod 600 "$CLIENT_DIR/$username.ovpn"
    success "Certificate renewed for $username"
}

# Main script logic
case "$1" in
    add)
        add_user "$2"
        ;;
    remove)
        remove_user "$2"
        ;;
    list)
        list_users
        ;;
    renew)
        renew_user "$2"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/openvpn-user-mgmt
    success "User management script created"
}

# Start and enable services
start_services() {
    log "Starting OpenVPN service..."
    
    # Create ipp.txt file
    touch "$OPENVPN_DIR/ipp.txt"
    chmod 644 "$OPENVPN_DIR/ipp.txt"
    
    # Test configuration before starting service
    log "Testing OpenVPN configuration..."
    if ! openvpn --config "$OPENVPN_DIR/server.conf" --test-crypto; then
        error "OpenVPN configuration test failed"
        exit 1
    fi
    
    # Start OpenVPN
    systemctl enable openvpn@server.service
    systemctl start openvpn@server.service
    
    sleep 3
    
    if systemctl is-active --quiet openvpn@server.service; then
        success "OpenVPN service started successfully"
    else
        error "Failed to start OpenVPN service"
        systemctl status openvpn@server.service
        log "Checking OpenVPN logs for errors:"
        tail -20 /var/log/openvpn/openvpn.log 2>/dev/null || true
        exit 1
    fi
}

# Display final information
show_final_info() {
    log "OpenVPN server setup completed!"
    echo ""
    echo "🔧 Server Information:"
    echo "====================="
    echo "Server IP: $SERVER_IP"
    echo "VPN Port: $VPN_PORT"
    echo "VPN Protocol: $VPN_PROTO"
    echo "VPN Network: $VPN_NETWORK/$VPN_NETMASK"
    echo ""
    echo "📁 Important Files:"
    echo "==================="
    echo "Server Config: $OPENVPN_DIR/server.conf"
    echo "Client Configs: $CLIENT_DIR/"
    echo "Logs: $LOG_DIR/"
    echo "Certificates: $EASYRSA_DIR/pki/"
    echo ""
    echo "🛠️  Management Commands:"
    echo "======================="
    echo "Add user:     openvpn-user-mgmt add <username>"
    echo "Remove user:  openvpn-user-mgmt remove <username>"
    echo "List users:   openvpn-user-mgmt list"
    echo "Renew cert:   openvpn-user-mgmt renew <username>"
    echo ""
    echo "📊 Service Commands:"
    echo "==================="
    echo "Status:       systemctl status openvpn@server.service"
    echo "Restart:      systemctl restart openvpn@server.service"
    echo "Logs:         tail -f $LOG_DIR/openvpn.log"
    echo ""
    echo "🔒 Security Notes:"
    echo "=================="
    echo "1. Configure your external firewall to allow port $VPN_PORT/$VPN_PROTO"
    echo "2. Consider setting up fail2ban for additional security"
    echo "3. Regularly update certificates using the renew command"
    echo "4. Monitor logs for suspicious activity"
    echo ""
    echo "✅ Setup complete! You can now add users with: openvpn-user-mgmt add <username>"
}

# Main execution
main() {
    log "Starting OpenVPN server setup..."
    
    check_root
    update_system
    install_packages
    create_directories
    setup_easyrsa
    generate_server_config
    create_pam_config
    copy_certificates
    create_systemd_service
    enable_ip_forwarding
    configure_nat
    create_user_management
    start_services
    show_final_info
}

# Run main function
main "$@"