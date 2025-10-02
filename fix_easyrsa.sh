#!/bin/bash

# Fix Easy-RSA version compatibility issues
# This script handles differences between Easy-RSA versions

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
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

log "Fixing Easy-RSA compatibility issues..."

# Navigate to Easy-RSA directory
cd /etc/openvpn/easy-rsa

# Source the vars file
source vars

# Check Easy-RSA version and create compatibility scripts
log "Checking Easy-RSA version..."

# Create compatibility scripts for older Easy-RSA versions
if [ ! -f "./clean-all" ] && [ -f "./easyrsa" ]; then
    log "Creating compatibility scripts for newer Easy-RSA version..."
    
    # Create clean-all script
    cat > clean-all << 'EOF'
#!/bin/bash
# Compatibility script for newer Easy-RSA versions
./easyrsa clean
EOF
    chmod +x clean-all
    
    # Create build-ca script
    cat > build-ca << 'EOF'
#!/bin/bash
# Compatibility script for newer Easy-RSA versions
./easyrsa build-ca nopass
EOF
    chmod +x build-ca
    
    # Create build-key-server script
    cat > build-key-server << 'EOF'
#!/bin/bash
# Compatibility script for newer Easy-RSA versions
./easyrsa build-server-full server nopass
EOF
    chmod +x build-key-server
    
    # Create build-dh script
    cat > build-dh << 'EOF'
#!/bin/bash
# Compatibility script for newer Easy-RSA versions
./easyrsa gen-dh
EOF
    chmod +x build-dh
    
    # Create build-key script
    cat > build-key << 'EOF'
#!/bin/bash
# Compatibility script for newer Easy-RSA versions
./easyrsa build-client-full "$1" nopass
EOF
    chmod +x build-key
    
    # Create revoke-full script
    cat > revoke-full << 'EOF'
#!/bin/bash
# Compatibility script for newer Easy-RSA versions
./easyrsa revoke "$1"
EOF
    chmod +x revoke-full
    
    log "Compatibility scripts created successfully!"
fi

# Now run the PKI initialization
log "Initializing PKI with compatibility fixes..."

# Clean the PKI
if [ -f "./clean-all" ]; then
    ./clean-all
elif [ -f "./clean" ]; then
    ./clean
else
    ./easyrsa clean
fi

# Build CA
if [ -f "./build-ca" ]; then
    ./build-ca --batch
else
    ./easyrsa build-ca nopass
fi

# Build server certificate
if [ -f "./build-key-server" ]; then
    ./build-key-server --batch server
else
    ./easyrsa build-server-full server nopass
fi

# Generate DH parameters
if [ -f "./build-dh" ]; then
    ./build-dh
else
    ./easyrsa gen-dh
fi

log "Easy-RSA compatibility fix completed!"
log "You can now continue with the OpenVPN setup."
