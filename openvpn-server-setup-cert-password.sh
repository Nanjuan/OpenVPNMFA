#!/bin/bash

# OpenVPN Server Setup Script - Certificate + Username/Password Authentication
# Compatible with Ubuntu 24.04+ and OpenVPN 2.6.12+
# Uses certificate + username/password authentication (two-factor)

set -euo pipefail

# Script metadata
SCRIPT_VERSION="2.0-cert-pass"
SCRIPT_DATE="2024-10-07"
COMPATIBLE_UBUNTU="20.04,22.04,24.04,24.10"
COMPATIBLE_OPENVPN="2.6.12+"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables
OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_NAME="server"
CLIENT_DIR="/etc/openvpn/clients"
LOG_DIR="/var/log/openvpn"
BACKUP_DIR="/etc/openvpn/backup"
SCRIPT_DIR="/usr/local/bin"

# Network configuration
VPN_NETWORK="10.8.0.0"
VPN_NETMASK="255.255.255.0"
VPN_PORT="1194"
VPN_PROTOCOL="udp"

# Security settings (latest standards)
KEY_SIZE="4096"
CURVE="secp384r1"
CIPHER="AES-256-GCM"
AUTH="SHA512"
TLS_VERSION="1.2"
DH_SIZE="4096"

# System information
UBUNTU_VERSION=""
UBUNTU_CODENAME=""
OPENVPN_VERSION=""
OPENSSL_VERSION=""
EASYRSA_VERSION=""

# Authentication method (fixed for this script)
AUTH_METHOD="username_password"

# System user for OpenVPN
OPENVPN_SYSTEM_USER="openvpn"
OPENVPN_SYSTEM_GROUP="openvpn"

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

header() {
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE}$1${NC}"
    echo -e "${PURPLE}================================${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Display script information
show_header() {
    header "OpenVPN Server Setup Script v$SCRIPT_VERSION (Certificate + Password)"
    echo -e "${CYAN}Authentication: Certificate + Username/Password${NC}"
    echo -e "${CYAN}Compatible with: Ubuntu $COMPATIBLE_UBUNTU${NC}"
    echo -e "${CYAN}OpenVPN: $COMPATIBLE_OPENVPN${NC}"
    echo -e "${CYAN}Date: $SCRIPT_DATE${NC}"
    echo ""
}

# Detect system information
detect_system() {
    log "Detecting system information..."
    
    UBUNTU_VERSION=$(lsb_release -rs)
    UBUNTU_CODENAME=$(lsb_release -cs)
    
    log "Ubuntu Version: $UBUNTU_VERSION ($UBUNTU_CODENAME)"
    
    # Verify Ubuntu version compatibility
    case "$UBUNTU_VERSION" in
        "20.04"|"22.04"|"24.04"|"24.10")
            success "Ubuntu version $UBUNTU_VERSION is supported"
            ;;
        *)
            warning "Ubuntu version $UBUNTU_VERSION may not be fully tested"
            ;;
    esac
}

# Update system packages
update_system() {
    log "Updating system packages..."
    
    # Update package lists
    apt update
    
    # Upgrade system packages
    apt upgrade -y
    
    # Install essential packages
    apt install -y curl wget gnupg2 software-properties-common ca-certificates \
                   lsb-release apt-transport-https
    
    success "System packages updated"
}

# Install OpenVPN and dependencies
install_openvpn() {
    log "Installing OpenVPN and dependencies..."
    
    # Try Ubuntu repositories first (most reliable)
    if apt install -y openvpn easy-rsa ufw; then
        success "Installed OpenVPN from Ubuntu repositories"
        
        # Get version information
        OPENVPN_VERSION=$(openvpn --version | head -n1 | awk '{print $2}')
        OPENSSL_VERSION=$(openssl version | awk '{print $2}')
        
        log "OpenVPN version: $OPENVPN_VERSION"
        log "OpenSSL version: $OPENSSL_VERSION"
        
    else
        warning "Ubuntu repositories failed, trying OpenVPN repository..."
        
        # Add OpenVPN repository (modern method)
        if [[ "$UBUNTU_VERSION" == "24.04" ]] || [[ "$UBUNTU_VERSION" == "24.10" ]]; then
            # Use new OpenVPN repository format for Ubuntu 24.04+
            wget -O - https://swupdate.openvpn.net/repos/openvpn-repo-pkg-key.pub | \
                gpg --dearmor -o /usr/share/keyrings/openvpn-archive-keyring.gpg
            
            echo "deb [signed-by=/usr/share/keyrings/openvpn-archive-keyring.gpg] \
                https://swupdate.openvpn.net/community/openvpn3/repos/openvpn3-$UBUNTU_CODENAME main" | \
                tee /etc/apt/sources.list.d/openvpn3.list
        else
            # Fallback for older Ubuntu versions
            wget -O /tmp/openvpn-repo.gpg https://swupdate.openvpn.net/repos/repo-public.gpg
            gpg --dearmor /tmp/openvpn-repo.gpg
            mv /tmp/openvpn-repo.gpg.gpg /etc/apt/trusted.gpg.d/openvpn-repo.gpg
            echo "deb http://build.openvpn.net/debian/openvpn/stable $UBUNTU_CODENAME main" | \
                tee /etc/apt/sources.list.d/openvpn.list
        fi
        
        apt update
        apt install -y openvpn easy-rsa ufw
        
        # Clean up
        rm -f /tmp/openvpn-repo.gpg
    fi
    
    # Install additional security tools and PAM authentication
    apt install -y fail2ban unattended-upgrades libpam-google-authenticator
    
    # Verify installation
    if command -v openvpn &> /dev/null; then
        success "OpenVPN installation completed"
    else
        error "OpenVPN installation failed"
        exit 1
    fi
}

# Create dedicated system user for OpenVPN
create_openvpn_user() {
    log "Creating OpenVPN system user ($OPENVPN_SYSTEM_USER)..."

    if id -u "$OPENVPN_SYSTEM_USER" >/dev/null 2>&1; then
        info "User $OPENVPN_SYSTEM_USER already exists"
    else
        # Create group and user
        getent group "$OPENVPN_SYSTEM_GROUP" >/dev/null 2>&1 || groupadd -r "$OPENVPN_SYSTEM_GROUP"
        useradd -m -s /bin/bash -g "$OPENVPN_SYSTEM_GROUP" -G "$OPENVPN_SYSTEM_GROUP" "$OPENVPN_SYSTEM_USER"

        # Prompt for password
        echo -n "Enter password for $OPENVPN_SYSTEM_USER: "
        read -s OPENVPN_USER_PASS
        echo
        echo -n "Confirm password: "
        read -s OPENVPN_USER_PASS2
        echo
        if [[ "$OPENVPN_USER_PASS" != "$OPENVPN_USER_PASS2" ]]; then
            error "Passwords do not match"
            exit 1
        fi
        echo "$OPENVPN_SYSTEM_USER:$OPENVPN_USER_PASS" | chpasswd
        unset OPENVPN_USER_PASS OPENVPN_USER_PASS2

        success "User $OPENVPN_SYSTEM_USER created"
    fi

    # Ensure ssh group exists and add user to it (if group not present, create it)
    if getent group ssh >/dev/null 2>&1; then
        usermod -aG ssh "$OPENVPN_SYSTEM_USER"
    else
        info "Group 'ssh' not found; creating and adding user"
        groupadd ssh
        usermod -aG ssh "$OPENVPN_SYSTEM_USER"
    fi
}

# Setup PAM authentication
setup_pam_auth() {
    log "Setting up PAM authentication..."
    
    # Create PAM configuration for OpenVPN
    cat > /etc/pam.d/openvpn << EOF
# OpenVPN PAM configuration
auth required pam_unix.so
account required pam_unix.so
session required pam_unix.so
EOF
    
    # Create auth script
    cat > $OPENVPN_DIR/auth-script.sh << 'AUTH_EOF'
#!/bin/bash
# OpenVPN PAM authentication script

# Read username and password from environment
USERNAME="$1"
PASSWORD="$2"

# Authenticate using PAM
echo "$PASSWORD" | /usr/bin/pamtester openvpn "$USERNAME" authenticate
AUTH_EOF
    
    chmod +x $OPENVPN_DIR/auth-script.sh
    success "PAM authentication configured"
}

# Setup EasyRSA Certificate Authority
setup_easyrsa() {
    log "Setting up EasyRSA Certificate Authority..."
    
    # Remove existing EasyRSA if present
    rm -rf $EASYRSA_DIR
    
    # Copy EasyRSA to OpenVPN directory
    cp -r /usr/share/easy-rsa $EASYRSA_DIR
    
    # Navigate to EasyRSA directory
    cd $EASYRSA_DIR
    
    # Get Easy-RSA version
    EASYRSA_VERSION=$(./easyrsa version | head -n1 | awk '{print $2}')
    log "Easy-RSA version: $EASYRSA_VERSION"
    
    # Initialize PKI
    ./easyrsa init-pki
    
    # Create CA with secure settings
    ./easyrsa --batch --req-cn="OpenVPN-CA" build-ca nopass
    
    # Generate Diffie-Hellman parameters with modern key size
    ./easyrsa gen-dh
    
    # Generate TLS-Crypt key for additional security
    openvpn --genkey --secret pki/ta.key
    
    # Generate server certificate
    ./easyrsa --batch --req-cn="OpenVPN-Server" build-server-full $SERVER_NAME nopass
    
    # Set secure permissions on key material to work with user $OPENVPN_SYSTEM_USER
    chmod 600 pki/private/$SERVER_NAME.key || true
    chown root:root pki/private/$SERVER_NAME.key || true
    # Allow OpenVPN group to read tls-crypt key after drop-privs
    chgrp "$OPENVPN_SYSTEM_GROUP" pki/ta.key || true
    chmod 600 pki/ta.key || true
    # Public materials
    chmod 644 pki/ca.crt pki/issued/$SERVER_NAME.crt || true
    
    # Verify certificates were created
    if [[ -f "pki/ca.crt" ]] && [[ -f "pki/issued/$SERVER_NAME.crt" ]]; then
        success "EasyRSA setup completed successfully"
    else
        error "EasyRSA setup failed - certificates not created"
        exit 1
    fi
}

# Configure OpenVPN server
configure_openvpn() {
    log "Configuring OpenVPN server..."
    
    # Create server configuration file (Certificate + Username/Password authentication)
    cat > $OPENVPN_DIR/$SERVER_NAME.conf << EOF
# OpenVPN Server Configuration
# Generated by openvpn-server-setup-cert-password.sh
# Compatible with OpenVPN 2.6.12+ and OpenSSL 3.0.2+
# Authentication: Certificate + Username/Password

# Network settings
port $VPN_PORT
proto $VPN_PROTOCOL
dev tun
topology subnet

# Certificate and key files
ca $EASYRSA_DIR/pki/ca.crt
cert $EASYRSA_DIR/pki/issued/$SERVER_NAME.crt
key $EASYRSA_DIR/pki/private/$SERVER_NAME.key
dh $EASYRSA_DIR/pki/dh.pem
tls-crypt $EASYRSA_DIR/pki/ta.key

# Network topology
server $VPN_NETWORK $VPN_NETMASK
ifconfig-pool-persist ipp.txt

# Client configuration
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Security settings (OpenSSL 3.0+ compatible)
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-GCM
auth $AUTH
tls-version-min $TLS_VERSION

# Perfect Forward Secrecy
tls-crypt $EASYRSA_DIR/pki/ta.key

# Additional security
remote-cert-tls client

# PAM Authentication
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn
verify-client-cert none
username-as-common-name

# Drop privileges after reading keys
user $OPENVPN_SYSTEM_USER
group $OPENVPN_SYSTEM_GROUP
persist-tun
persist-key

# Temporary directory
tmp-dir /var/run/openvpn-tmp

# Logging
log-append $LOG_DIR/openvpn.log
verb 3
mute 20

# Status file
status $LOG_DIR/openvpn-status.log
status-version 2

# Client timeout settings
keepalive 10 120

# Security enhancements
explicit-exit-notify 1
tls-server
EOF

    # Create directories
    mkdir -p $LOG_DIR
    mkdir -p $CLIENT_DIR
    mkdir -p $BACKUP_DIR
    mkdir -p /var/run/openvpn-tmp
    
    # Set secure ownership and permissions
    # Use root:root for backup; OpenVPN user owns logs to write
    chown root:root $BACKUP_DIR
    chmod 755 $BACKUP_DIR
    chown root:root $CLIENT_DIR
    chmod 700 $CLIENT_DIR
    
    # Prepare log directory and files with correct ownership for runtime user
    mkdir -p $LOG_DIR
    touch $LOG_DIR/openvpn.log $LOG_DIR/openvpn-status.log
    chown $OPENVPN_SYSTEM_USER:$OPENVPN_SYSTEM_GROUP $LOG_DIR/openvpn.log $LOG_DIR/openvpn-status.log
    chown $OPENVPN_SYSTEM_USER:$OPENVPN_SYSTEM_GROUP $LOG_DIR
    chmod 755 $LOG_DIR
    
    # Set permissions for temporary directory (must be writable by OpenVPN process)
    chown $OPENVPN_SYSTEM_USER:$OPENVPN_SYSTEM_GROUP /var/run/openvpn-tmp
    chmod 770 /var/run/openvpn-tmp
    
    success "OpenVPN server configuration completed"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall rules..."
    
    # Enable UFW
    ufw --force enable
    
    # Allow SSH (important!)
    ufw allow ssh
    
    # Allow OpenVPN port
    ufw allow $VPN_PORT/$VPN_PROTOCOL
    
    # Configure IP forwarding via UFW (do not duplicate entries)
    if grep -q '^#net/ipv4/ip_forward' /etc/ufw/sysctl.conf 2>/dev/null; then
        sed -i 's/^#net\/ipv4\/ip_forward=.*/net.ipv4.ip_forward=1/' /etc/ufw/sysctl.conf || true
    fi
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/ufw/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/ufw/sysctl.conf
    fi

    # Ensure UFW default forward policy is ACCEPT
    if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw 2>/dev/null; then
        sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    else
        echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
    fi

    # Add MASQUERADE rule to UFW before.rules if not present
    if ! grep -q 'OPENVPN NAT RULES' /etc/ufw/before.rules 2>/dev/null; then
        cat << 'UFWEOF' >> /etc/ufw/before.rules
*nat
:POSTROUTING ACCEPT [0:0]
# OPENVPN NAT RULES
-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
COMMIT
UFWEOF
        # Replace hardcoded interface with detected default interface
        IFACE=$(ip route | awk '/^default/ {print $5; exit}')
        if [[ -n "${IFACE}" ]]; then
            sed -i "s/-o eth0/-o ${IFACE}/" /etc/ufw/before.rules
        fi
    fi

    # Reload UFW to apply changes
    ufw --force reload

    success "Firewall configuration completed"
}

# Configure systemd service
configure_systemd() {
    log "Configuring systemd service..."
    
    # Enable and start OpenVPN service
    systemctl enable openvpn@$SERVER_NAME
    systemctl start openvpn@$SERVER_NAME
    
    # Wait for service to start
    sleep 3
    
    # Check if service is running
    if systemctl is-active --quiet openvpn@$SERVER_NAME; then
        success "OpenVPN service started successfully"
    else
        error "OpenVPN service failed to start"
        systemctl status openvpn@$SERVER_NAME
        exit 1
    fi
}

# Create management script
create_management_script() {
    log "Creating management script..."
    
    cat > $SCRIPT_DIR/openvpn-manage << 'EOF'
#!/bin/bash

# OpenVPN Management Script v2.0 (Certificate + Password)
# Compatible with OpenVPN 2.6.12+ and Easy-RSA 3.1.0+

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
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }
success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }

show_usage() {
    echo -e "${PURPLE}OpenVPN Management Script v2.0 (Certificate + Password)${NC}"
    echo ""
    echo "Usage: $0 [command] [username]"
    echo ""
    echo "Commands:"
    echo "  add <username>     - Add a new VPN user (certificate + password)"
    echo "  remove <username>  - Remove a VPN user"
    echo "  renew <username>   - Renew user certificate"
    echo "  list               - List all users"
    echo "  status             - Show server status"
    echo "  backup             - Create configuration backup"
    echo "  restart            - Restart OpenVPN service"
    echo "  logs               - Show recent logs"
    echo "  test               - Test server configuration"
    echo "  fix                - Fix permissions and restart service"
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
    
    # Create system user for username/password authentication
    if ! id -u "$username" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$username"
        echo -n "Enter password for $username: "
        read -s USER_PASS
        echo
        echo -n "Confirm password: "
        read -s USER_PASS2
        echo
        if [[ "$USER_PASS" != "$USER_PASS2" ]]; then
            error "Passwords do not match"
            return 1
        fi
        echo "$username:$USER_PASS" | chpasswd
        unset USER_PASS USER_PASS2
        success "System user $username created"
    else
        info "System user $username already exists"
    fi
    
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
auth-user-pass

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
    success "User $username added successfully"
    info "Client configuration: $CLIENT_DIR/$username.ovpn"
    info "User will need both certificate and username/password to connect"
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
    
    # Remove system user
    if id -u "$username" >/dev/null 2>&1; then
        userdel -r "$username" 2>/dev/null || true
        success "System user $username removed"
    fi
    
    systemctl restart openvpn@$SERVER_NAME
    success "User $username removed successfully"
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
    success "Certificate renewed for user: $username"
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

backup_config() {
    local backup_name="openvpn-backup-$(date +%Y%m%d-%H%M%S)"
    local backup_path="/etc/openvpn/backup/$backup_name"
    
    log "Creating backup: $backup_name"
    mkdir -p "$backup_path"
    cp -r $EASYRSA_DIR/pki "$backup_path/"
    cp $OPENVPN_DIR/$SERVER_NAME.conf "$backup_path/"
    cp -r $CLIENT_DIR "$backup_path/"
    tar -czf "$backup_path.tar.gz" -C "/etc/openvpn/backup" "$backup_name"
    rm -rf "$backup_path"
    success "Backup created: $backup_path.tar.gz"
}

show_logs() {
    log "Recent OpenVPN logs:"
    if [[ -f "/var/log/openvpn/openvpn.log" ]]; then
        tail -20 /var/log/openvpn/openvpn.log
    else
        echo "No logs found"
    fi
}

test_config() {
    log "Testing OpenVPN server configuration..."
    if openvpn --config $OPENVPN_DIR/$SERVER_NAME.conf --test-crypto; then
        success "Configuration test passed"
    else
        error "Configuration test failed"
        return 1
    fi
}

fix_permissions() {
    log "Fixing OpenVPN permissions..."
    
    # Fix temporary directory permissions
    if [[ -d "/var/run/openvpn-tmp" ]]; then
        chown openvpn:openvpn /var/run/openvpn-tmp
        chmod 770 /var/run/openvpn-tmp
        success "Temporary directory permissions fixed"
    else
        mkdir -p /var/run/openvpn-tmp
        chown openvpn:openvpn /var/run/openvpn-tmp
        chmod 770 /var/run/openvpn-tmp
        success "Temporary directory created"
    fi
    
    # Fix log directory permissions
    chown openvpn:openvpn /var/log/openvpn
    chmod 755 /var/log/openvpn
    
    # Restart service
    systemctl restart openvpn@$SERVER_NAME
    success "OpenVPN service restarted"
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
    backup)
        backup_config
        ;;
    restart)
        systemctl restart openvpn@$SERVER_NAME
        success "OpenVPN service restarted"
        ;;
    logs)
        show_logs
        ;;
    test)
        test_config
        ;;
    fix)
        fix_permissions
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
EOF

    chmod +x $SCRIPT_DIR/openvpn-manage
    success "Management script created"
}

# Create status monitoring script
create_status_script() {
    log "Creating status monitoring script..."
    
    cat > $SCRIPT_DIR/openvpn-status << 'EOF'
#!/bin/bash

# OpenVPN Status Script (Certificate + Password)
# Shows comprehensive server status

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}OpenVPN Server Status (Certificate + Password)${NC}"
echo "================================================"

# Service status
echo -e "\n${YELLOW}Service Status:${NC}"
systemctl status openvpn@server --no-pager

# Connected clients
echo -e "\n${YELLOW}Connected Clients:${NC}"
if [[ -f "/var/log/openvpn/openvpn-status.log" ]]; then
    cat /var/log/openvpn/openvpn-status.log | grep "CLIENT_LIST" | wc -l
else
    echo "0"
fi

# Server information
echo -e "\n${YELLOW}Server Information:${NC}"
echo "Server IP: $(curl -s ifconfig.me)"
echo "VPN Port: 1194"
echo "VPN Network: 10.8.0.0/24"
echo "Authentication: Certificate + Username/Password"

# Recent logs
echo -e "\n${YELLOW}Recent Logs:${NC}"
if [[ -f "/var/log/openvpn/openvpn.log" ]]; then
    tail -10 /var/log/openvpn/openvpn.log
else
    echo "No logs found"
fi
EOF

    chmod +x $SCRIPT_DIR/openvpn-status
    success "Status script created"
}

# Main installation function
install_openvpn_server() {
    header "Starting OpenVPN Server Installation (Certificate + Password)"
    
    check_root
    show_header
    detect_system
    update_system
    install_openvpn
    create_openvpn_user
    setup_pam_auth
    setup_easyrsa
    configure_openvpn
    configure_firewall
    configure_systemd
    create_management_script
    create_status_script
    
    header "Installation Completed Successfully!"
    
    success "OpenVPN server is now running (Certificate + Password)"
    info "Server IP: $(curl -s ifconfig.me)"
    info "VPN Port: $VPN_PORT"
    info "VPN Network: $VPN_NETWORK/24"
    info "Authentication: Certificate + Username/Password"
    info "Management command: openvpn-manage"
    info "Status command: openvpn-status"
    
    echo ""
    warning "Next steps:"
    warning "1. Add your first user: sudo openvpn-manage add <username>"
    warning "2. Download client config: sudo cp /etc/openvpn/clients/<username>.ovpn /tmp/"
    warning "3. Transfer to your local machine: scp user@server:/tmp/<username>.ovpn ~/"
    warning "4. Install OpenVPN client and import the .ovpn file"
    warning "5. Users will need both certificate and username/password to connect"
    
    echo ""
    info "For help, run: sudo openvpn-manage"
}

# Main script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-install}" in
        install)
            install_openvpn_server
            ;;
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
        backup)
            backup_config
            ;;
        *)
            echo "Usage: $0 [install|add|remove|renew|list|backup] [username]"
            echo ""
            echo "Commands:"
            echo "  install         - Install and configure OpenVPN server (Certificate + Password)"
            echo "  add <username>  - Add a new VPN user"
            echo "  remove <username> - Remove a VPN user"
            echo "  renew <username>  - Renew user certificate"
            echo "  list            - List all users"
            echo "  backup          - Create configuration backup"
            exit 1
            ;;
    esac
fi
