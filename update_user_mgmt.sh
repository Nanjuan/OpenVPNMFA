#!/bin/bash

# Update user management script on server
# This script replaces the old user management script with the Easy-RSA 3.x compatible version

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Updating user management script for Easy-RSA 3.x compatibility..."

# Create the updated user management script
cat > /usr/local/bin/openvpn-user-mgmt.sh << 'EOF'
#!/bin/bash

# OpenVPN User Management Script with MFA Setup
# Updated for Easy-RSA 3.x compatibility

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
        
        # Check Easy-RSA version and use appropriate commands
        if ./easyrsa version | grep -q "3\."; then
            echo "Using Easy-RSA 3.x commands..."
            ./easyrsa build-client-full "$USERNAME" nopass
        else
            echo "Using Easy-RSA 2.x commands..."
            source vars
            if [ -f "./build-key" ]; then
                ./build-key --batch "$USERNAME"
            else
                ./easyrsa build-client-full "$USERNAME" nopass
            fi
        fi
        
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
$(if ./easyrsa version | grep -q "3\."; then cat /etc/openvpn/easy-rsa/pki/issued/${USERNAME}.crt; else cat /etc/openvpn/easy-rsa/keys/${USERNAME}.crt; fi)
</cert>
<key>
$(if ./easyrsa version | grep -q "3\."; then cat /etc/openvpn/easy-rsa/pki/private/${USERNAME}.key; else cat /etc/openvpn/easy-rsa/keys/${USERNAME}.key; fi)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
key-direction 1
CLIENT_EOF
        
        # Set proper permissions
        chmod 600 "/etc/openvpn/client/${USERNAME}.ovpn"
        chown root:root "/etc/openvpn/client/${USERNAME}.ovpn"
        
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
        
        # Check Easy-RSA version and use appropriate commands
        if ./easyrsa version | grep -q "3\."; then
            echo "Using Easy-RSA 3.x commands..."
            ./easyrsa revoke "$USERNAME"
        else
            echo "Using Easy-RSA 2.x commands..."
            source vars
            if [ -f "./revoke-full" ]; then
                ./revoke-full "$USERNAME"
            else
                ./easyrsa revoke "$USERNAME"
            fi
        fi
        
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

# Make the script executable
chmod +x /usr/local/bin/openvpn-user-mgmt.sh

log "User management script updated successfully!"
log "Now you can use: sudo /usr/local/bin/openvpn-user-mgmt.sh add <username>"
