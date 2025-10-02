#!/bin/bash

# OpenVPN Server Setup with MFA - Production Ready
# This script sets up a secure OpenVPN server with Google Authenticator MFA
# Best practices implementation with modern security standards

set -e

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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
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
        net-tools
    success "Required packages installed"
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    mkdir -p "$OPENVPN_DIR"
    mkdir -p "$CLIENT_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$EASYRSA_DIR"
    success "Directory structure created"
}

# Setup Easy-RSA
setup_easyrsa() {
    log "Setting up Easy-RSA..."
    
    # Remove existing easy-rsa if it exists
    rm -rf "$EASYRSA_DIR"
    
    # Create new easy-rsa directory
    make-cadir "$EASYRSA_DIR"
    cd "$EASYRSA_DIR"
    
    # Configure Easy-RSA
    cat > vars << EOF
set_var EASYRSA_REQ_COUNTRY     "US"
set_var EASYRSA_REQ_PROVINCE    "California"
set_var EASYRSA_REQ_CITY        "San Francisco"
set_var EASYRSA_REQ_ORG         "OpenVPN-CA"
set_var EASYRSA_REQ_EMAIL       "admin@openvpn.local"
set_var EASYRSA_REQ_OU          "IT Department"
set_var EASYRSA_KEY_SIZE        2048
set_var EASYRSA_CA_EXPIRE       3650
set_var EASYRSA_CERT_EXPIRE     3650
set_var EASYRSA_CRL_DAYS       60
set_var EASYRSA_CERT_RENEW    30
EOF
    
    # Initialize PKI
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa build-server-full server nopass
    ./easyrsa gen-dh
    openvpn --genkey --secret ta.key
    
    success "Easy-RSA setup completed"
}

# Generate server configuration
generate_server_config() {
    log "Generating OpenVPN server configuration..."
    
    cat > "$OPENVPN_DIR/server.conf" << EOF
# OpenVPN Server Configuration - Production Ready
# Port and Protocol
port $VPN_PORT
proto $VPN_PROTO
dev tun

# Certificate files
ca $OPENVPN_DIR/ca.crt
cert $OPENVPN_DIR/server.crt
key $OPENVPN_DIR/server.key
dh $OPENVPN_DIR/dh.pem
tls-auth $OPENVPN_DIR/ta.key 0

# Network configuration
server $VPN_NETWORK $VPN_NETMASK
ifconfig-pool-persist $OPENVPN_DIR/ipp.txt

# Client configuration
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "route $VPN_NETWORK $VPN_NETMASK"
push "topology subnet"
push "ping 10"
push "ping-restart 120"

# Security settings - Modern standards
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Authentication
auth-user-pass-verify $OPENVPN_DIR/auth-script.sh via-env
script-security 3

# Logging
log $LOG_DIR/openvpn.log
verb 3
status $LOG_DIR/openvpn-status.log
status-version 2

# Performance
keepalive 10 120
comp-lzo
persist-key
persist-tun

# Security
user nobody
group nogroup
writepid /run/openvpn/server.pid

# Client limits
max-clients 100
duplicate-cn

# Additional security
explicit-exit-notify 1
EOF
    
    success "Server configuration generated"
}

# Create authentication script
create_auth_script() {
    log "Creating authentication script..."
    
    cat > "$OPENVPN_DIR/auth-script.sh" << 'EOF'
#!/bin/bash
set -e

# Get credentials from environment
USERNAME="$username"
PASSWORD="$password"

# Log authentication attempt
echo "$(date): Auth attempt for user: $USERNAME" >> /var/log/openvpn/auth.log

# Check if user exists
if ! id "$USERNAME" &>/dev/null; then
    echo "$(date): User $USERNAME does not exist" >> /var/log/openvpn/auth.log
    exit 1
fi

# Check if MFA is configured
if [ ! -f "/home/$USERNAME/.google_authenticator" ]; then
    echo "$(date): MFA not configured for user $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Extract MFA code (last 6 digits) and password
MFA_CODE="${PASSWORD: -6}"
USER_PASSWORD="${PASSWORD%??????}"

echo "$(date): Testing auth for $USERNAME (pass: ${#USER_PASSWORD} chars, MFA: $MFA_CODE)" >> /var/log/openvpn/auth.log

# Test password authentication
if ! echo "$USER_PASSWORD" | su - "$USERNAME" -c "true" 2>/dev/null; then
    echo "$(date): Password auth failed for $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Get secret key
SECRET=$(head -1 "/home/$USERNAME/.google_authenticator")
if [ -z "$SECRET" ]; then
    echo "$(date): No secret found for user $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Test MFA code using oathtool
if command -v oathtool &> /dev/null; then
    # Try current time window
    EXPECTED_CODE=$(oathtool --totp -b "$SECRET")
    if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
        echo "$(date): Auth successful for $USERNAME" >> /var/log/openvpn/auth.log
        exit 0
    fi
    
    # Try with time offset for clock drift
    for i in -1 0 1; do
        EXPECTED_CODE=$(oathtool --totp -b "$SECRET" --time-offset=$i)
        if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
            echo "$(date): Auth successful for $USERNAME (offset $i)" >> /var/log/openvpn/auth.log
            exit 0
        fi
    done
fi

echo "$(date): MFA auth failed for $USERNAME" >> /var/log/openvpn/auth.log
exit 1
EOF
    
    chmod +x "$OPENVPN_DIR/auth-script.sh"
    chown root:root "$OPENVPN_DIR/auth-script.sh"
    
    success "Authentication script created"
}

# Copy certificates
copy_certificates() {
    log "Copying certificates..."
    cp "$EASYRSA_DIR/pki/ca.crt" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/pki/issued/server.crt" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/pki/private/server.key" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/pki/dh.pem" "$OPENVPN_DIR/"
    cp "$EASYRSA_DIR/ta.key" "$OPENVPN_DIR/"
    
    # Set proper permissions
    chmod 600 "$OPENVPN_DIR"/*.key
    chmod 644 "$OPENVPN_DIR"/*.crt
    chmod 644 "$OPENVPN_DIR"/*.pem
    chmod 600 "$OPENVPN_DIR"/ta.key
    
    success "Certificates copied and permissions set"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    cat > /etc/systemd/system/openvpn@server.service << EOF
[Unit]
Description=OpenVPN connection to %i
Documentation=man:openvpn(8)
Documentation=https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
After=network-online.target
Wants=network-online.target
PartOf=openvpn.service
ReloadPropagatedFrom=openvpn.service

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=$OPENVPN_DIR
ExecStart=/usr/sbin/openvpn --config %i.conf --writepid /run/openvpn/%i.pid
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

# Enable IP forwarding
enable_ip_forwarding() {
    log "Enabling IP forwarding..."
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    sysctl -p
    success "IP forwarding enabled"
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
    
    # Create client configuration
    cat > "$CLIENT_DIR/$username.ovpn" << CLIENT_EOF
client
dev tun
proto udp
remote $SERVER_IP $VPN_PORT
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
$(cat $OPENVPN_DIR/ca.crt)
</ca>

<cert>
$(cat $EASYRSA_DIR/pki/issued/$username.crt)
</cert>

<key>
$(cat $EASYRSA_DIR/pki/private/$username.key)
</key>

<tls-auth>
$(cat $OPENVPN_DIR/ta.key)
</tls-auth>
key-direction 1
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
    
    # Update client configuration
    cat > "$CLIENT_DIR/$username.ovpn" << CLIENT_EOF
client
dev tun
proto udp
remote $SERVER_IP $VPN_PORT
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
$(cat $OPENVPN_DIR/ca.crt)
</ca>

<cert>
$(cat $EASYRSA_DIR/pki/issued/$username.crt)
</cert>

<key>
$(cat $EASYRSA_DIR/pki/private/$username.key)
</key>

<tls-auth>
$(cat $OPENVPN_DIR/ta.key)
</tls-auth>
key-direction 1
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
    
    # Start OpenVPN
    systemctl enable openvpn@server.service
    systemctl start openvpn@server.service
    
    sleep 3
    
    if systemctl is-active --quiet openvpn@server.service; then
        success "OpenVPN service started successfully"
    else
        error "Failed to start OpenVPN service"
        systemctl status openvpn@server.service
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
    echo "Auth logs:    tail -f $LOG_DIR/auth.log"
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
    create_auth_script
    copy_certificates
    create_systemd_service
    enable_ip_forwarding
    create_user_management
    start_services
    show_final_info
}

# Run main function
main "$@"
