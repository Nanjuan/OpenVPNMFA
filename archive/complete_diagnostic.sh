#!/bin/bash

# Complete OpenVPN MFA Diagnostic Script
# This script thoroughly checks all configuration components

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

log "Complete OpenVPN MFA Diagnostic"
echo "================================="
echo ""

# Function to test PAM authentication directly
test_pam_direct() {
    local username="$1"
    local password_mfa="$2"
    
    log "Testing PAM authentication directly..."
    
    # Create a test script that mimics OpenVPN's authentication
    cat > /tmp/pam_test.sh << EOF
#!/bin/bash
export USER="$username"
echo "$password_mfa" | /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn
EOF
    
    chmod +x /tmp/pam_test.sh
    /tmp/pam_test.sh 2>&1
    local result=$?
    rm -f /tmp/pam_test.sh
    
    return $result
}

info "=== 1. SYSTEM OVERVIEW ==="
echo "OS: $(lsb_release -d | cut -f2)"
echo "Kernel: $(uname -r)"
echo "Date/Time: $(date)"
echo "Timezone: $(timedatectl show --property=Timezone --value)"
echo ""

info "=== 2. OPENVPN SERVICE STATUS ==="
if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service is running"
    systemctl status openvpn@server.service --no-pager -l
else
    error "❌ OpenVPN service is not running"
    systemctl status openvpn@server.service --no-pager -l
fi
echo ""

info "=== 3. OPENVPN CONFIGURATION ==="
if [ -f "/etc/openvpn/server.conf" ]; then
    log "✅ OpenVPN config exists"
    echo "Key configuration lines:"
    grep -E "(plugin|auth-user-pass|port|proto)" /etc/openvpn/server.conf
else
    error "❌ OpenVPN config not found"
fi
echo ""

info "=== 4. PAM CONFIGURATION ==="
if [ -f "/etc/pam.d/openvpn" ]; then
    log "✅ PAM config exists"
    echo "Content:"
    cat /etc/pam.d/openvpn
else
    error "❌ PAM config not found"
fi
echo ""

info "=== 5. PAM MODULES ==="
if [ -f "/lib/x86_64-linux-gnu/security/pam_google_authenticator.so" ]; then
    log "✅ PAM Google Authenticator module exists"
    ls -la /lib/x86_64-linux-gnu/security/pam_google_authenticator.so
else
    error "❌ PAM Google Authenticator module not found"
fi

if [ -f "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so" ]; then
    log "✅ OpenVPN PAM plugin exists"
    ls -la /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so
else
    error "❌ OpenVPN PAM plugin not found"
fi
echo ""

info "=== 6. CERTIFICATES ==="
log "Checking certificate files..."
for cert in ca.crt server.crt server.key dh2048.pem ta.key; do
    if [ -f "/etc/openvpn/$cert" ]; then
        log "✅ $cert exists"
    else
        error "❌ $cert not found"
    fi
done
echo ""

info "=== 7. USER CONFIGURATION ==="
if [ -n "$1" ]; then
    USERNAME="$1"
    log "Checking user: $USERNAME"
    
    # Check if user exists
    if id "$USERNAME" &>/dev/null; then
        log "✅ User $USERNAME exists"
        echo "User info: $(id $USERNAME)"
    else
        error "❌ User $USERNAME does not exist"
    fi
    
    # Check MFA configuration
    if [ -f "/home/$USERNAME/.google_authenticator" ]; then
        log "✅ MFA configured for $USERNAME"
        echo "Secret key: $(head -1 /home/$USERNAME/.google_authenticator)"
    else
        error "❌ MFA not configured for $USERNAME"
    fi
    
    # Check client config
    if [ -f "/etc/openvpn/client/$USERNAME.ovpn" ]; then
        log "✅ Client config exists for $USERNAME"
    else
        error "❌ Client config not found for $USERNAME"
    fi
    
    # Check certificate
    if [ -f "/etc/openvpn/easy-rsa/pki/issued/$USERNAME.crt" ]; then
        log "✅ Certificate exists for $USERNAME"
    elif [ -f "/etc/openvpn/easy-rsa/keys/$USERNAME.crt" ]; then
        log "✅ Certificate exists for $USERNAME (Easy-RSA 2.x)"
    else
        error "❌ Certificate not found for $USERNAME"
    fi
else
    warn "No username provided for user-specific checks"
fi
echo ""

info "=== 8. NETWORK CONFIGURATION ==="
log "Checking network settings..."
echo "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "OpenVPN port status:"
netstat -tulpn | grep 1194 || echo "Port 1194 not listening"
echo ""

info "=== 9. FIREWALL STATUS ==="
if command -v ufw &> /dev/null; then
    log "UFW status:"
    ufw status verbose
else
    warn "UFW not installed or not available"
fi
echo ""

info "=== 10. LOG ANALYSIS ==="
log "Recent OpenVPN logs:"
if [ -f "/var/log/openvpn/openvpn.log" ]; then
    tail -20 /var/log/openvpn/openvpn.log
else
    warn "No OpenVPN log file found"
fi
echo ""

info "=== 11. PAM AUTHENTICATION TEST ==="
if [ -n "$1" ]; then
    USERNAME="$1"
    log "Testing PAM authentication for $USERNAME"
    echo "Enter password + MFA code (no space):"
    read -s password_mfa
    echo ""
    
    if [ -n "$password_mfa" ]; then
        log "Testing authentication..."
        if test_pam_direct "$USERNAME" "$password_mfa"; then
            log "✅ PAM authentication successful!"
        else
            error "❌ PAM authentication failed!"
            echo ""
            echo "Troubleshooting steps:"
            echo "1. Check if password is correct"
            echo "2. Check if MFA code is current (30-second window)"
            echo "3. Check time synchronization between server and authenticator app"
            echo "4. Verify Google Authenticator is properly configured"
        fi
    else
        warn "No password+MFA provided for test"
    fi
else
    warn "No username provided for authentication test"
fi
echo ""

info "=== 12. RECOMMENDATIONS ==="
log "Configuration recommendations:"
echo "1. Ensure time synchronization is working:"
echo "   sudo apt install ntp -y && sudo systemctl enable ntp"
echo ""
echo "2. Check PAM configuration syntax:"
echo "   pam-auth-update --package --force"
echo ""
echo "3. Restart OpenVPN service:"
echo "   sudo systemctl restart openvpn@server.service"
echo ""
echo "4. Test with fresh MFA code from authenticator app"
echo ""

log "Complete diagnostic finished!"
