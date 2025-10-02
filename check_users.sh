#!/bin/bash

# OpenVPN Users Check Script
# This script shows comprehensive information about OpenVPN users

set -e

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "OpenVPN Users Check"
echo ""

info "=== 1. OpenVPN Client Configurations ==="
if [ -d "/etc/openvpn/client" ]; then
    log "Client configuration files:"
    ls -la /etc/openvpn/client/*.ovpn 2>/dev/null | while read line; do
        if [ -n "$line" ]; then
            filename=$(echo "$line" | awk '{print $9}')
            username=$(basename "$filename" .ovpn)
            size=$(echo "$line" | awk '{print $5}')
            date=$(echo "$line" | awk '{print $6, $7, $8}')
            echo "  - $username (${size} bytes, $date)"
        fi
    done
else
    warn "No client configuration directory found"
fi

echo ""
info "=== 2. Users with MFA Configured ==="
MFA_USERS=()
for user in $(ls /home/ 2>/dev/null); do
    if [ -f "/home/$user/.google_authenticator" ]; then
        MFA_USERS+=("$user")
        echo "  ✅ $user - MFA configured"
    fi
done

if [ ${#MFA_USERS[@]} -eq 0 ]; then
    warn "No users with MFA configured found"
fi

echo ""
info "=== 3. Linux Users ==="
log "System users with shell access:"
cat /etc/passwd | grep -E "(bash|sh)$" | while read line; do
    username=$(echo "$line" | cut -d: -f1)
    home_dir=$(echo "$line" | cut -d: -f6)
    shell=$(echo "$line" | cut -d: -f7)
    echo "  - $username (home: $home_dir, shell: $shell)"
done

echo ""
info "=== 4. OpenVPN Service Status ==="
if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service is running"
    
    # Check for active connections
    if [ -f "/var/log/openvpn/openvpn-status.log" ]; then
        log "Active connections:"
        grep -E "CLIENT_LIST|ROUTING_TABLE" /var/log/openvpn/openvpn-status.log 2>/dev/null || echo "  No active connections"
    else
        warn "No status file found"
    fi
else
    error "❌ OpenVPN service is not running"
fi

echo ""
info "=== 5. Certificate Information ==="
if [ -d "/etc/openvpn/easy-rsa" ]; then
    log "Certificate directory exists"
    
    # Check Easy-RSA version
    if [ -f "/etc/openvpn/easy-rsa/easyrsa" ]; then
        version=$(/etc/openvpn/easy-rsa/easyrsa version 2>/dev/null | head -1 || echo "Unknown")
        log "Easy-RSA version: $version"
    fi
    
    # Check for user certificates
    if [ -d "/etc/openvpn/easy-rsa/pki/issued" ]; then
        log "User certificates:"
        ls /etc/openvpn/easy-rsa/pki/issued/*.crt 2>/dev/null | while read cert; do
            username=$(basename "$cert" .crt)
            if [ "$username" != "server" ]; then
                echo "  - $username"
            fi
        done
    elif [ -d "/etc/openvpn/easy-rsa/keys" ]; then
        log "User certificates (Easy-RSA 2.x):"
        ls /etc/openvpn/easy-rsa/keys/*.crt 2>/dev/null | while read cert; do
            username=$(basename "$cert" .crt)
            if [ "$username" != "server" ]; then
                echo "  - $username"
            fi
        done
    fi
else
    warn "Easy-RSA directory not found"
fi

echo ""
info "=== 6. Summary ==="
echo "OpenVPN Users Summary:"
echo "======================"

# Count client configs
CLIENT_COUNT=$(ls /etc/openvpn/client/*.ovpn 2>/dev/null | wc -l)
echo "Client configurations: $CLIENT_COUNT"

# Count MFA users
MFA_COUNT=${#MFA_USERS[@]}
echo "Users with MFA: $MFA_COUNT"

# Count certificates
if [ -d "/etc/openvpn/easy-rsa/pki/issued" ]; then
    CERT_COUNT=$(ls /etc/openvpn/easy-rsa/pki/issued/*.crt 2>/dev/null | grep -v server.crt | wc -l)
elif [ -d "/etc/openvpn/easy-rsa/keys" ]; then
    CERT_COUNT=$(ls /etc/openvpn/easy-rsa/keys/*.crt 2>/dev/null | grep -v server.crt | wc -l)
else
    CERT_COUNT=0
fi
echo "User certificates: $CERT_COUNT"

echo ""
log "OpenVPN users check completed!"
