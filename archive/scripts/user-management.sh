#!/bin/bash

# OpenVPN User Management Script with MFA Setup
# This script provides comprehensive user management for OpenVPN with Google Authenticator

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

# Function to add a new user
add_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "Adding user: $username"
    
    # Create user if doesn't exist
    if ! id "$username" &>/dev/null; then
        useradd -m -s /bin/bash "$username"
        log "User $username created"
    else
        log "User $username already exists"
    fi
    
    # Set up Google Authenticator for user
    log "Setting up Google Authenticator for $username..."
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3
    
    # Generate client certificate
    log "Generating client certificate for $username..."
    cd /etc/openvpn/easy-rsa
    source vars
    ./build-key --batch "$username"
    
    # Create client configuration
    log "Creating client configuration for $username..."
    cat > "/etc/openvpn/client/${username}.ovpn" << CLIENT_EOF
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
$(cat /etc/openvpn/easy-rsa/keys/${username}.crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/keys/${username}.key)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
key-direction 1
CLIENT_EOF
    
    # Set proper permissions
    chmod 600 "/etc/openvpn/client/${username}.ovpn"
    chown root:root "/etc/openvpn/client/${username}.ovpn"
    
    log "Client configuration created: /etc/openvpn/client/${username}.ovpn"
    
    # Display QR code for Google Authenticator setup
    log "QR code for Google Authenticator setup:"
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3 -q
    
    log "User $username added successfully!"
    log "Client configuration file: /etc/openvpn/client/${username}.ovpn"
    log "Please distribute this file securely to the user"
}

# Function to revoke a user
revoke_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "Revoking user: $username"
    
    # Revoke certificate
    cd /etc/openvpn/easy-rsa
    source vars
    ./revoke-full "$username"
    
    # Remove client config
    rm -f "/etc/openvpn/client/${username}.ovpn"
    
    # Remove user's Google Authenticator configuration
    rm -f "/home/${username}/.google_authenticator"
    
    log "Certificate revoked for user: $username"
    log "Client configuration removed"
    log "Google Authenticator configuration removed"
}

# Function to list active users
list_users() {
    log "Active OpenVPN users:"
    if [ -d "/etc/openvpn/client" ]; then
        ls -la /etc/openvpn/client/*.ovpn 2>/dev/null | awk '{print $9}' | sed 's|/etc/openvpn/client/||' | sed 's|.ovpn||' | while read user; do
            if [ -n "$user" ]; then
                echo "  - $user"
            fi
        done
    else
        warn "No client configurations found"
    fi
}

# Function to show user status
show_user_status() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "Status for user: $username"
    
    # Check if user exists
    if id "$username" &>/dev/null; then
        echo "  User account: EXISTS"
    else
        echo "  User account: NOT FOUND"
        return
    fi
    
    # Check if client config exists
    if [ -f "/etc/openvpn/client/${username}.ovpn" ]; then
        echo "  Client config: EXISTS"
    else
        echo "  Client config: NOT FOUND"
    fi
    
    # Check if Google Authenticator is configured
    if [ -f "/home/${username}/.google_authenticator" ]; then
        echo "  Google Authenticator: CONFIGURED"
    else
        echo "  Google Authenticator: NOT CONFIGURED"
    fi
    
    # Check if certificate exists
    if [ -f "/etc/openvpn/easy-rsa/keys/${username}.crt" ]; then
        echo "  Certificate: EXISTS"
    else
        echo "  Certificate: NOT FOUND"
    fi
}

# Function to reset user MFA
reset_user_mfa() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "Resetting MFA for user: $username"
    
    # Remove existing Google Authenticator configuration
    rm -f "/home/${username}/.google_authenticator"
    
    # Set up new Google Authenticator
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3
    
    log "MFA reset for user: $username"
    log "New QR code generated"
}

# Function to backup user configurations
backup_users() {
    local backup_dir="/etc/openvpn/backups/$(date +%Y%m%d_%H%M%S)"
    
    log "Creating backup in: $backup_dir"
    
    mkdir -p "$backup_dir"
    
    # Backup client configurations
    if [ -d "/etc/openvpn/client" ]; then
        cp -r /etc/openvpn/client "$backup_dir/"
        log "Client configurations backed up"
    fi
    
    # Backup certificates
    if [ -d "/etc/openvpn/easy-rsa/keys" ]; then
        cp -r /etc/openvpn/easy-rsa/keys "$backup_dir/"
        log "Certificates backed up"
    fi
    
    # Backup CA
    if [ -f "/etc/openvpn/ca.crt" ]; then
        cp /etc/openvpn/ca.crt "$backup_dir/"
        log "CA certificate backed up"
    fi
    
    log "Backup completed: $backup_dir"
}

# Function to restore user configurations
restore_users() {
    local backup_dir="$1"
    
    if [ -z "$backup_dir" ]; then
        error "Backup directory is required"
    fi
    
    if [ ! -d "$backup_dir" ]; then
        error "Backup directory not found: $backup_dir"
    fi
    
    log "Restoring from backup: $backup_dir"
    
    # Restore client configurations
    if [ -d "$backup_dir/client" ]; then
        cp -r "$backup_dir/client"/* /etc/openvpn/client/
        log "Client configurations restored"
    fi
    
    # Restore certificates
    if [ -d "$backup_dir/keys" ]; then
        cp -r "$backup_dir/keys"/* /etc/openvpn/easy-rsa/keys/
        log "Certificates restored"
    fi
    
    # Restore CA
    if [ -f "$backup_dir/ca.crt" ]; then
        cp "$backup_dir/ca.crt" /etc/openvpn/
        log "CA certificate restored"
    fi
    
    log "Restore completed"
}

# Function to show help
show_help() {
    echo "OpenVPN User Management Script"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  add <username>           - Add new user with MFA"
    echo "  revoke <username>        - Revoke user certificate"
    echo "  list                     - List active users"
    echo "  status <username>        - Show user status"
    echo "  reset-mfa <username>     - Reset user MFA"
    echo "  backup                   - Backup user configurations"
    echo "  restore <backup_dir>     - Restore from backup"
    echo "  help                     - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 add john"
    echo "  $0 revoke john"
    echo "  $0 list"
    echo "  $0 status john"
    echo "  $0 reset-mfa john"
    echo "  $0 backup"
    echo "  $0 restore /etc/openvpn/backups/20240101_120000"
}

# Main script logic
case "$1" in
    add)
        add_user "$2"
        ;;
    revoke)
        revoke_user "$2"
        ;;
    list)
        list_users
        ;;
    status)
        show_user_status "$2"
        ;;
    reset-mfa)
        reset_user_mfa "$2"
        ;;
    backup)
        backup_users
        ;;
    restore)
        restore_users "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        error "Invalid command. Use '$0 help' for usage information."
        ;;
esac

