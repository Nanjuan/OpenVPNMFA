#!/bin/bash

# OpenVPN Certificate-Only Installer with Encrypted Private Keys
# Supports Ubuntu 20.04/22.04/24.04, Debian 11/12, and RHEL-like systems
# Author: Production-ready installer for certificate-based authentication

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_PORT=1194
DEFAULT_PROTO="udp"
DEFAULT_NET="10.8.0.0"
DEFAULT_MASK="255.255.255.0"
DEFAULT_ORG="MyVPN"
DEFAULT_COUNTRY="US"
DEFAULT_STATE="CA"
DEFAULT_CITY="San Francisco"

# Global variables
PUBLIC_IP=""
PORT="$DEFAULT_PORT"
PROTO="$DEFAULT_PROTO"
NET="$DEFAULT_NET"
MASK="$DEFAULT_MASK"
ORG="$DEFAULT_ORG"
COUNTRY="$DEFAULT_COUNTRY"
STATE="$DEFAULT_STATE"
CITY="$DEFAULT_CITY"
INTERACTIVE=false
OS_TYPE=""
PKG_MANAGER=""
FIREWALL_TYPE=""

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

# Detect OS and package manager
detect_os() {
    log_info "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu)
                OS_TYPE="ubuntu"
                PKG_MANAGER="apt"
                ;;
            debian)
                OS_TYPE="debian"
                PKG_MANAGER="apt"
                ;;
            rhel|centos|almalinux|rocky|fedora)
                OS_TYPE="rhel"
                if command -v dnf &> /dev/null; then
                    PKG_MANAGER="dnf"
                else
                    PKG_MANAGER="yum"
                fi
                ;;
            *)
                error_exit "Unsupported operating system: $ID"
                ;;
        esac
    else
        error_exit "Cannot detect operating system"
    fi
    
    log_success "Detected OS: $OS_TYPE with package manager: $PKG_MANAGER"
}

# Detect public IP
detect_public_ip() {
    if [[ -z "$PUBLIC_IP" ]]; then
        log_info "Detecting public IP address..."
        PUBLIC_IP=$(curl -s --connect-timeout 10 https://ipv4.icanhazip.com/ 2>/dev/null || \
                   curl -s --connect-timeout 10 https://api.ipify.org 2>/dev/null || \
                   curl -s --connect-timeout 10 https://checkip.amazonaws.com 2>/dev/null || \
                   echo "")
        
        if [[ -z "$PUBLIC_IP" ]]; then
            if [[ "$INTERACTIVE" == true ]]; then
                read -p "Enter your public IP address or DNS name: " PUBLIC_IP
            else
                error_exit "Cannot detect public IP. Use --public-ip flag or run interactively."
            fi
        else
            log_success "Detected public IP: $PUBLIC_IP"
        fi
    fi
}

# Install packages
install_packages() {
    log_info "Installing required packages..."
    
    case "$OS_TYPE" in
        ubuntu|debian)
            apt update
            apt install -y openvpn easy-rsa openssl iptables-persistent ufw curl
            ;;
        rhel)
            # Install EPEL if not present
            if ! rpm -q epel-release &> /dev/null; then
                if command -v dnf &> /dev/null; then
                    dnf install -y epel-release
                else
                    yum install -y epel-release
                fi
            fi
            
            if command -v dnf &> /dev/null; then
                dnf install -y openvpn easy-rsa openssl iptables-services firewalld curl
            else
                yum install -y openvpn easy-rsa openssl iptables-services firewalld curl
            fi
            ;;
    esac
    
    log_success "Packages installed successfully"
}

# Setup directories
setup_directories() {
    log_info "Creating OpenVPN directories..."
    
    mkdir -p /etc/openvpn/easy-rsa
    mkdir -p /etc/openvpn/clients
    mkdir -p /var/log/openvpn
    
    # Set proper permissions
    chmod 700 /etc/openvpn/easy-rsa
    chmod 700 /etc/openvpn/clients
    chmod 755 /var/log/openvpn
    
    log_success "Directories created"
}

# Initialize Easy-RSA PKI
init_pki() {
    log_info "Initializing Easy-RSA PKI..."
    
    cd /etc/openvpn/easy-rsa
    
    # Initialize PKI if not already done
    if [[ ! -d pki ]]; then
        ./easyrsa init-pki
    fi
    
    # Create vars file
    cat > vars << EOF
set_var EASYRSA_REQ_COUNTRY    "$COUNTRY"
set_var EASYRSA_REQ_PROVINCE   "$STATE"
set_var EASYRSA_REQ_CITY       "$CITY"
set_var EASYRSA_REQ_ORG        "$ORG"
set_var EASYRSA_REQ_EMAIL      "admin@$ORG.local"
set_var EASYRSA_REQ_OU         "$ORG"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    3650
set_var EASYRSA_CRL_DAYS       30
EOF
    
    # Build CA
    if [[ ! -f pki/ca.crt ]]; then
        ./easyrsa build-ca nopass
    fi
    
    # Build server certificate
    if [[ ! -f pki/issued/server.crt ]]; then
        ./easyrsa build-server-full server nopass
    fi
    
    # Generate DH parameters
    if [[ ! -f pki/dh.pem ]]; then
        ./easyrsa gen-dh
    fi
    
    # Generate TLS-Crypt key
    if [[ ! -f pki/ta.key ]]; then
        openvpn --genkey --secret pki/ta.key
    fi
    
    # Set proper permissions
    chmod 600 pki/ca.crt pki/private/ca.key
    chmod 600 pki/issued/server.crt pki/private/server.key
    chmod 600 pki/dh.pem pki/ta.key
    
    log_success "PKI initialized and certificates generated"
}

# Create server configuration
create_server_config() {
    log_info "Creating server configuration..."
    
    cat > /etc/openvpn/server.conf << EOF
# OpenVPN Server Configuration - Certificate Only
port $PORT
proto $PROTO
dev tun

# Network settings
server $NET $MASK
ifconfig-pool-persist ipp.txt

# Client routing
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"

# Certificate files
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-crypt /etc/openvpn/easy-rsa/pki/ta.key

# Security settings
tls-version-min 1.2
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
remote-cert-tls client
verify-client-cert require

# Network topology
topology subnet

# Keepalive
keepalive 10 120

# User/Group
user nobody
group nogroup

# Persistence
persist-key
persist-tun

# Exit notification for UDP
explicit-exit-notify 1

# Logging
status /var/log/openvpn/status.log
log-append /var/log/openvpn/server.log
verb 3

# CRL
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem
EOF
    
    log_success "Server configuration created"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    sysctl -p
    
    case "$OS_TYPE" in
        ubuntu|debian)
            # Check if UFW is available
            if command -v ufw &> /dev/null; then
                FIREWALL_TYPE="ufw"
                ufw --force enable
                ufw allow $PORT/$PROTO
                ufw allow OpenSSH
                
                # Add NAT rule for VPN traffic
                cat >> /etc/ufw/before.rules << EOF

# OpenVPN NAT rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $NET/$MASK -o $(ip route | grep default | awk '{print $5}' | head -1) -j MASQUERADE
COMMIT
EOF
                
                ufw reload
            else
                # Use iptables directly
                FIREWALL_TYPE="iptables"
                iptables -A INPUT -p $PROTO --dport $PORT -j ACCEPT
                iptables -t nat -A POSTROUTING -s $NET/$MASK -o $(ip route | grep default | awk '{print $5}' | head -1) -j MASQUERADE
                
                # Save iptables rules
                if command -v iptables-save &> /dev/null; then
                    iptables-save > /etc/iptables/rules.v4
                fi
            fi
            ;;
        rhel)
            # Check if firewalld is available
            if systemctl is-active firewalld &> /dev/null; then
                FIREWALL_TYPE="firewalld"
                systemctl enable firewalld
                systemctl start firewalld
                firewall-cmd --permanent --add-port=$PORT/$PROTO
                firewall-cmd --permanent --add-masquerade
                firewall-cmd --reload
            else
                # Use iptables
                FIREWALL_TYPE="iptables"
                systemctl enable iptables
                systemctl start iptables
                iptables -A INPUT -p $PROTO --dport $PORT -j ACCEPT
                iptables -t nat -A POSTROUTING -s $NET/$MASK -o $(ip route | grep default | awk '{print $5}' | head -1) -j MASQUERADE
                service iptables save
            fi
            ;;
    esac
    
    log_success "Firewall configured using $FIREWALL_TYPE"
}

# Start OpenVPN service
start_service() {
    log_info "Starting OpenVPN service..."
    
    systemctl enable openvpn-server@server
    systemctl start openvpn-server@server
    
    # Wait a moment and check status
    sleep 2
    if systemctl is-active --quiet openvpn-server@server; then
        log_success "OpenVPN service started successfully"
    else
        log_error "Failed to start OpenVPN service"
        systemctl status openvpn-server@server
        error_exit "OpenVPN service failed to start"
    fi
}

# Validation checks
validate_installation() {
    log_info "Validating installation..."
    
    # Check OpenVPN version
    OPENVPN_VERSION=$(openvpn --version | head -1 | awk '{print $2}')
    log_success "OpenVPN version: $OPENVPN_VERSION"
    
    # Check service status
    if systemctl is-active --quiet openvpn-server@server; then
        log_success "OpenVPN service is running"
    else
        log_error "OpenVPN service is not running"
        return 1
    fi
    
    # Check IP forwarding
    if [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]]; then
        log_success "IP forwarding is enabled"
    else
        log_warning "IP forwarding is not enabled"
    fi
    
    # Check firewall
    case "$FIREWALL_TYPE" in
        ufw)
            if ufw status | grep -q "$PORT/$PROTO"; then
                log_success "Firewall rule for port $PORT/$PROTO is active"
            fi
            ;;
        firewalld)
            if firewall-cmd --list-ports | grep -q "$PORT/$PROTO"; then
                log_success "Firewall rule for port $PORT/$PROTO is active"
            fi
            ;;
        iptables)
            if iptables -L | grep -q "$PORT"; then
                log_success "Firewall rule for port $PORT is active"
            fi
            ;;
    esac
    
    log_success "Installation validation completed"
}

# Client management functions
add_client() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        error_exit "Username is required for add-client command"
    fi
    
    log_info "Adding client: $username"
    
    cd /etc/openvpn/easy-rsa
    
    # Create client certificate
    ./easyrsa build-client-full "$username" nopass
    
    # Create client directory
    mkdir -p "/etc/openvpn/clients/$username"
    
    # Encrypt the private key with a passphrase
    log_info "Encrypting private key for $username..."
    openssl rsa -aes256 -in "pki/private/$username.key" -out "/etc/openvpn/clients/$username/$username.key"
    
    # Create unified .ovpn file
    cat > "/etc/openvpn/clients/$username/$username.ovpn" << EOF
client
dev tun
proto $PROTO
remote $PUBLIC_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3

<ca>
$(cat pki/ca.crt)
</ca>

<cert>
$(cat pki/issued/$username.crt)
</cert>

<key>
$(cat /etc/openvpn/clients/$username/$username.key)
</key>

<tls-crypt>
$(cat pki/ta.key)
</tls-crypt>
EOF
    
    # Create separate PEM files for reference
    cp pki/ca.crt "/etc/openvpn/clients/$username/ca.crt"
    cp pki/issued/$username.crt "/etc/openvpn/clients/$username/$username.crt"
    
    # Set proper permissions
    chmod 600 "/etc/openvpn/clients/$username/$username.key"
    chmod 600 "/etc/openvpn/clients/$username/$username.ovpn"
    chmod 644 "/etc/openvpn/clients/$username/ca.crt"
    chmod 644 "/etc/openvpn/clients/$username/$username.crt"
    
    # Create tar bundle
    cd "/etc/openvpn/clients/$username"
    tar -czf "$username-bundle.tar.gz" "$username.ovpn" ca.crt "$username.crt" "$username.key"
    chmod 600 "$username-bundle.tar.gz"
    
    log_success "Client $username added successfully"
    log_info "Client files created in: /etc/openvpn/clients/$username/"
    log_info "Bundle created: /etc/openvpn/clients/$username/$username-bundle.tar.gz"
    log_warning "The private key is encrypted and will prompt for passphrase on connect"
}

revoke_client() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        error_exit "Username is required for revoke-client command"
    fi
    
    log_info "Revoking client: $username"
    
    cd /etc/openvpn/easy-rsa
    
    # Revoke certificate
    ./easyrsa revoke "$username"
    
    # Generate new CRL
    ./easyrsa gen-crl
    
    # Copy CRL to OpenVPN directory
    cp pki/crl.pem /etc/openvpn/
    chmod 644 /etc/openvpn/crl.pem
    
    # Reload OpenVPN
    systemctl reload openvpn-server@server
    
    # Archive client files
    if [[ -d "/etc/openvpn/clients/$username" ]]; then
        mv "/etc/openvpn/clients/$username" "/etc/openvpn/clients/revoked-$username-$(date +%Y%m%d)"
        log_info "Client files archived to: /etc/openvpn/clients/revoked-$username-$(date +%Y%m%d)"
    fi
    
    log_success "Client $username revoked successfully"
}

list_clients() {
    log_info "Listing clients..."
    
    cd /etc/openvpn/easy-rsa
    
    echo -e "\n${BLUE}Issued Certificates:${NC}"
    if [[ -d pki/issued ]]; then
        for cert in pki/issued/*.crt; do
            if [[ -f "$cert" ]]; then
                filename=$(basename "$cert" .crt)
                if [[ "$filename" != "server" ]]; then
                    expiry=$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)
                    echo "  $filename (expires: $expiry)"
                fi
            fi
        done
    fi
    
    echo -e "\n${BLUE}Revoked Certificates:${NC}"
    if [[ -f pki/index.txt ]]; then
        grep "^R" pki/index.txt | while read line; do
            cert_name=$(echo "$line" | awk '{print $5}')
            revoke_date=$(echo "$line" | awk '{print $2}')
            echo "  $cert_name (revoked: $revoke_date)"
        done
    fi
    
    echo -e "\n${BLUE}Active Client Directories:${NC}"
    if [[ -d /etc/openvpn/clients ]]; then
        ls -la /etc/openvpn/clients/ | grep "^d" | awk '{print "  " $9}' | grep -v "^\.$\|^\.\.$"
    fi
}

# Interactive setup
interactive_setup() {
    echo -e "${BLUE}OpenVPN Certificate-Only Installer${NC}"
    echo "This installer will set up OpenVPN with certificate-based authentication."
    echo "Each client will have an encrypted private key requiring a passphrase."
    echo ""
    
    read -p "Enter your public IP address or DNS name: " PUBLIC_IP
    read -p "Enter VPN port [$DEFAULT_PORT]: " input_port
    PORT="${input_port:-$DEFAULT_PORT}"
    
    read -p "Enter protocol (udp/tcp) [$DEFAULT_PROTO]: " input_proto
    PROTO="${input_proto:-$DEFAULT_PROTO}"
    
    read -p "Enter organization name [$DEFAULT_ORG]: " input_org
    ORG="${input_org:-$DEFAULT_ORG}"
    
    read -p "Enter country code [$DEFAULT_COUNTRY]: " input_country
    COUNTRY="${input_country:-$DEFAULT_COUNTRY}"
    
    read -p "Enter state [$DEFAULT_STATE]: " input_state
    STATE="${input_state:-$DEFAULT_STATE}"
    
    read -p "Enter city [$DEFAULT_CITY]: " input_city
    CITY="${input_city:-$DEFAULT_CITY}"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [COMMAND]

OPTIONS:
    --public-ip <IP>     Public IP address or DNS name (required)
    --port <port>        VPN port (default: $DEFAULT_PORT)
    --proto <udp|tcp>    Protocol (default: $DEFAULT_PROTO)
    --net <network>      VPN network (default: $DEFAULT_NET)
    --mask <mask>        VPN netmask (default: $DEFAULT_MASK)
    --org <name>         Organization name (default: $DEFAULT_ORG)
    --country <code>     Country code (default: $DEFAULT_COUNTRY)
    --state <state>      State (default: $DEFAULT_STATE)
    --city <city>        City (default: $DEFAULT_CITY)
    --help               Show this help

COMMANDS:
    add-client <user>    Add a new client
    revoke-client <user> Revoke a client
    list-clients         List all clients

If no options are provided, interactive mode will be used.

Examples:
    $0 --public-ip 1.2.3.4
    $0 add-client alice
    $0 revoke-client alice
    $0 list-clients
EOF
}

# Main installation function
main_install() {
    log_info "Starting OpenVPN certificate-only installation..."
    
    check_root
    detect_os
    detect_public_ip
    install_packages
    setup_directories
    init_pki
    create_server_config
    configure_firewall
    start_service
    validate_installation
    
    log_success "OpenVPN installation completed successfully!"
    
    echo -e "\n${GREEN}NEXT STEPS:${NC}"
    echo "1. Add your first client:"
    echo "   sudo $0 add-client alice"
    echo ""
    echo "2. Client files will be created in: /etc/openvpn/clients/alice/"
    echo "3. Send the .ovpn file or bundle to your client"
    echo "4. Client will be prompted for private key passphrase on connect"
    echo ""
    echo "Server configuration: /etc/openvpn/server.conf"
    echo "Client management: /etc/openvpn/clients/"
    echo "Logs: /var/log/openvpn/"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --public-ip)
                PUBLIC_IP="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --proto)
                PROTO="$2"
                shift 2
                ;;
            --net)
                NET="$2"
                shift 2
                ;;
            --mask)
                MASK="$2"
                shift 2
                ;;
            --org)
                ORG="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --city)
                CITY="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            add-client)
                if [[ -z "${2:-}" ]]; then
                    error_exit "Username required for add-client command"
                fi
                add_client "$2"
                exit 0
                ;;
            revoke-client)
                if [[ -z "${2:-}" ]]; then
                    error_exit "Username required for revoke-client command"
                fi
                revoke_client "$2"
                exit 0
                ;;
            list-clients)
                list_clients
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
}

# Main script logic
main() {
    # If no arguments, run interactive mode
    if [[ $# -eq 0 ]]; then
        INTERACTIVE=true
        interactive_setup
    else
        parse_args "$@"
    fi
    
    # Run main installation
    main_install
}

# Run main function with all arguments
main "$@"
