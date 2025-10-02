#!/bin/bash

# Fix PAM Plugin Permissions Script
# This script fixes the permission issues with the OpenVPN PAM plugin

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

log "Fixing PAM Plugin Permissions"
echo "============================="
echo ""

info "=== 1. Checking Current Permissions ==="
log "OpenVPN PAM plugin permissions:"
ls -la /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so

log "PAM Google Authenticator module permissions:"
ls -la /lib/x86_64-linux-gnu/security/pam_google_authenticator.so
echo ""

info "=== 2. Fixing Permissions ==="
log "Setting correct permissions for OpenVPN PAM plugin..."
chmod +x /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so

log "Setting correct permissions for PAM Google Authenticator module..."
chmod +x /lib/x86_64-linux-gnu/security/pam_google_authenticator.so

log "Setting correct ownership..."
chown root:root /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so
chown root:root /lib/x86_64-linux-gnu/security/pam_google_authenticator.so
echo ""

info "=== 3. Verifying Permissions ==="
log "Updated OpenVPN PAM plugin permissions:"
ls -la /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so

log "Updated PAM Google Authenticator module permissions:"
ls -la /lib/x86_64-linux-gnu/security/pam_google_authenticator.so
echo ""

info "=== 4. Testing PAM Plugin ==="
log "Testing PAM plugin execution..."
if /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so --help &>/dev/null; then
    log "✅ PAM plugin is now executable"
else
    warn "PAM plugin test failed, but this might be normal for --help"
fi
echo ""

info "=== 5. Restarting OpenVPN Service ==="
log "Restarting OpenVPN service to apply changes..."
systemctl restart openvpn@server.service

if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service restarted successfully"
else
    error "❌ OpenVPN service failed to restart"
    systemctl status openvpn@server.service --no-pager -l
fi
echo ""

info "=== 6. Testing PAM Authentication ==="
log "Testing PAM authentication with a test user..."
echo "This will test if the PAM plugin can now execute properly."

# Create a simple test
cat > /tmp/pam_test_fixed.sh << 'EOF'
#!/bin/bash
export USER="$1"
echo "Testing PAM plugin execution for user: $USER"
if /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn 2>&1; then
    echo "PAM plugin executed successfully"
else
    echo "PAM plugin execution failed"
fi
EOF

chmod +x /tmp/pam_test_fixed.sh

if [ -n "$1" ]; then
    log "Testing with user: $1"
    /tmp/pam_test_fixed.sh "$1"
else
    log "No user specified for test"
fi

rm -f /tmp/pam_test_fixed.sh
echo ""

info "=== 7. Additional Recommendations ==="
log "Additional steps to ensure PAM authentication works:"
echo "1. Install time synchronization:"
echo "   sudo apt install ntp -y && sudo systemctl enable ntp"
echo ""
echo "2. Update PAM configuration:"
echo "   sudo pam-auth-update --package --force"
echo ""
echo "3. Test with a real user:"
echo "   sudo ./validate_mfa.sh <username>"
echo ""

log "PAM permissions fix completed!"
