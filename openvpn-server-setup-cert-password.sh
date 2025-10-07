#!/bin/bash
#
# OpenVPN Server Setup - Username/Password Only (no client certs)
# Ubuntu 20.04/22.04/24.04/24.10 + OpenVPN 2.6.x
# Installs OpenVPN, creates server TLS keys, enables PAM (pam_unix) auth,
# writes /etc/openvpn/server/server.conf, configures UFW+NAT,
# and provides a management script to add/remove users + export .ovpn.
#
set -euo pipefail

# --- Metadata ---------------------------------------------------------------
SCRIPT_VERSION="3.0-userpass"
SCRIPT_DATE="2025-10-07"

# --- Colors -----------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'
log(){ echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}"; }
warn(){ echo -e "${YELLOW}[WARN] $*${NC}"; }
err(){ echo -e "${RED}[ERROR] $*${NC}" >&2; }

# --- Config (edit if needed) ------------------------------------------------
OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="/etc/openvpn/server"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
LOG_DIR="/var/log/openvpn"
RUN_DIR="/var/run/openvpn-tmp"

SERVER_NAME="server"
VPN_NETWORK="10.8.0.0"
VPN_NETMASK="255.255.255.0"
VPN_PORT="1194"
VPN_PROTO="udp"

DATA_CIPHERS="AES-256-GCM:AES-128-GCM"
AUTH_DIGEST="SHA512"           # Control-channel HMAC (data-channel uses AEAD)
TLS_VERSION_MIN="1.2"

OPENVPN_USER="openvpn"         # system account (non-login)
OPENVPN_GROUP="openvpn"

# --- Root check -------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then err "Run as root."; exit 1; fi

# --- Header -----------------------------------------------------------------
echo -e "${PURPLE}==========================================${NC}"
echo -e "${PURPLE}OpenVPN User/Pass Setup v$SCRIPT_VERSION ($SCRIPT_DATE)${NC}"
echo -e "${PURPLE}==========================================${NC}"

# --- Detect system ----------------------------------------------------------
if command -v lsb_release >/dev/null 2>&1; then
  UBUNTU_VERSION="$(lsb_release -rs)"
  UBUNTU_CODENAME="$(lsb_release -cs)"
else
  UBUNTU_VERSION="unknown"; UBUNTU_CODENAME="unknown"
fi
log "Ubuntu: $UBUNTU_VERSION ($UBUNTU_CODENAME)"

# --- Update & install packages ---------------------------------------------
log "Updating and installing packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
apt-get install -y openvpn easy-rsa ufw curl ca-certificates lsb-release

# --- Create service user (non-login) ---------------------------------------
log "Ensuring service user '$OPENVPN_USER' exists (no login)..."
if ! id -u "$OPENVPN_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --user-group "$OPENVPN_USER"
  log "Created system user '$OPENVPN_USER'."
else
  log "User '$OPENVPN_USER' already exists."
fi

# --- Detect PAM plugin path -------------------------------------------------
detect_pam_plugin() {
  local paths=(
    "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so"
    "/usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so"
    "/usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so"
    "/usr/lib/openvpn/plugins/auth-pam.so"
  )
  for p in "${paths[@]}"; do [[ -f "$p" ]] && { echo "$p"; return; } done
  # fallback to the most common on Ubuntu
  echo "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so"
}
PAM_PLUGIN="$(detect_pam_plugin)"
log "PAM plugin: $PAM_PLUGIN"

# --- EasyRSA: build CA + server cert/keys ----------------------------------
log "Setting up Easy-RSA PKI for the server TLS..."
rm -rf "$EASYRSA_DIR"
mkdir -p "$EASYRSA_DIR"
cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"/
cd "$EASYRSA_DIR"

./easyrsa init-pki
# Non-interactive CA and server cert (nopass for unattended service key)
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 ./easyrsa build-server-full "$SERVER_NAME" nopass
EASYRSA_BATCH=1 ./easyrsa gen-dh
openvpn --genkey --secret pki/ta.key

# tighten perms
chmod 600 "pki/private/$SERVER_NAME.key" || true
chmod 600 "pki/ta.key" || true
chmod 644 pki/ca.crt "pki/issued/$SERVER_NAME.crt" || true

# --- Directories & permissions ---------------------------------------------
log "Creating runtime/log/client directories..."
mkdir -p "$SERVER_DIR" "$CLIENT_DIR" "$LOG_DIR" "$RUN_DIR"
touch "$LOG_DIR/openvpn.log" "$LOG_DIR/openvpn-status.log" "$OPENVPN_DIR/ipp.txt"
chown -R "$OPENVPN_USER:$OPENVPN_GROUP" "$LOG_DIR" "$RUN_DIR"
chown "$OPENVPN_USER:$OPENVPN_GROUP" "$OPENVPN_DIR/ipp.txt"
chmod 755 "$LOG_DIR"
chmod 770 "$RUN_DIR"

# --- PAM configuration (password auth) -------------------------------------
log "Writing /etc/pam.d/openvpn (pam_unix password auth)..."
cat > /etc/pam.d/openvpn <<'PAM'
# OpenVPN PAM configuration - local UNIX passwords
auth    required        pam_unix.so
account required        pam_unix.so
PAM

# --- Server configuration ---------------------------------------------------
log "Writing server config to $SERVER_DIR/$SERVER_NAME.conf ..."
cat > "$SERVER_DIR/$SERVER_NAME.conf" <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun
topology subnet

# Server TLS (clients do not present certs; server still needs its cert)
ca $EASYRSA_DIR/pki/ca.crt
cert $EASYRSA_DIR/pki/issued/$SERVER_NAME.crt
key $EASYRSA_DIR/pki/private/$SERVER_NAME.key
dh $EASYRSA_DIR/pki/dh.pem
tls-crypt $EASYRSA_DIR/pki/ta.key
tls-version-min $TLS_VERSION_MIN

# Username/Password via PAM (no client cert required)
plugin $PAM_PLUGIN openvpn
verify-client-cert none
username-as-common-name

# Network
server $VPN_NETWORK $VPN_NETMASK
ifconfig-pool-persist $OPENVPN_DIR/ipp.txt

# Push default route + DNS
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Crypto
data-ciphers $DATA_CIPHERS
data-ciphers-fallback AES-256-GCM
auth $AUTH_DIGEST

# Drop privileges after reading keys
user $OPENVPN_USER
group $OPENVPN_GROUP
persist-tun
persist-key
tmp-dir $RUN_DIR

# Logging
log-append $LOG_DIR/openvpn.log
status $LOG_DIR/openvpn-status.log
status-version 2
verb 3
mute 20

# Keepalive & UDP notice
keepalive 10 120
explicit-exit-notify 1
tls-server
EOF

# --- UFW & NAT --------------------------------------------------------------
log "Configuring UFW and NAT..."
ufw --force enable || true
ufw allow ssh || true
ufw allow "$VPN_PORT/$VPN_PROTO" || true

# IP forwarding
sed -i 's/^#\?net\.ipv4\.ip_forward.*/net.ipv4.ip_forward=1/' /etc/ufw/sysctl.conf || true
grep -q '^net.ipv4.ip_forward=1' /etc/ufw/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/ufw/sysctl.conf

# Default forward policy
if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw 2>/dev/null; then
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
else
  echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
fi

# NAT (idempotent): insert OPENVPN NAT RULES once, with the detected egress iface
IFACE="$(ip route | awk '/^default/ {print $5; exit}')"
grep -q 'OPENVPN NAT RULES' /etc/ufw/before.rules 2>/dev/null || cat <<'UFWNAT' >> /etc/ufw/before.rules
*nat
:POSTROUTING ACCEPT [0:0]
# OPENVPN NAT RULES
-A POSTROUTING -s 10.8.0.0/24 -o IFACE_REPLACE -j MASQUERADE
COMMIT
UFWNAT
[[ -n "$IFACE" ]] && sed -i "s/IFACE_REPLACE/$IFACE/" /etc/ufw/before.rules
ufw --force reload

# --- Enable & start service -------------------------------------------------
log "Enabling and starting openvpn-server@$SERVER_NAME ..."
systemctl enable --now "openvpn-server@$SERVER_NAME"
sleep 2
systemctl is-active --quiet "openvpn-server@$SERVER_NAME" && log "OpenVPN is running." || { err "OpenVPN failed to start."; systemctl status "openvpn-server@$SERVER_NAME" --no-pager; exit 1; }

# --- Management helper ------------------------------------------------------
log "Installing management helper at /usr/local/bin/openvpn-manage ..."
cat > /usr/local/bin/openvpn-manage <<'MAN'
#!/bin/bash
# OpenVPN Management - User/Pass mode (no client certs)
set -euo pipefail

OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="/etc/openvpn/server"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
SERVER_NAME="server"
UNIT="openvpn-server@${SERVER_NAME}"
OPENVPN_SYSTEM_USER="openvpn"
OPENVPN_SYSTEM_GROUP="openvpn"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GREEN}[$(date +'%H:%M:%S')] $*${NC}"; }
err(){ echo -e "${RED}[ERROR] $*${NC}" >&2; }
warn(){ echo -e "${YELLOW}[WARN] $*${NC}"; }

usage(){
  echo "Usage: $0 <command> [args]"
  echo "  add <username>       - Create VPN user (Linux account, no shell) and export <username>.ovpn"
  echo "  passwd <username>    - Reset VPN user password"
  echo "  remove <username>    - Remove VPN user and its .ovpn"
  echo "  list                 - List exported client profiles"
  echo "  status               - Service status + connected clients count"
  echo "  restart              - Restart OpenVPN"
  echo "  logs                 - Tail server log"
  echo "  fixperms             - Fix log/run perms"
}

server_ip(){ curl -fsS ifconfig.me || hostname -I | awk '{print $1}'; }

mk_profile(){
  local username="$1"
  local sip="$(server_ip)"
  cat > "$CLIENT_DIR/${username}.ovpn" <<PROF
client
dev tun
proto udp
remote ${sip} 1194
resolv-retry infinite
nobind
persist-key
persist-tun

# Match server crypto
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA512
verb 3
mute 20

# Username/Password prompt
auth-user-pass
auth-nocache
remote-cert-tls server

<ca>
$(cat "$EASYRSA_DIR/pki/ca.crt")
</ca>
<tls-crypt>
$(cat "$EASYRSA_DIR/pki/ta.key")
</tls-crypt>
PROF
  chmod 600 "$CLIENT_DIR/${username}.ovpn"
  log "Client profile: $CLIENT_DIR/${username}.ovpn"
}

add_user(){
  local u="${1:-}"; [[ -z "$u" ]] && { err "Username required"; exit 1; }
  # Create a local account with no shell; set password interactively
  if id -u "$u" >/dev/null 2>&1; then
    warn "User '$u' already exists (skipping create)."
  else
    useradd --create-home --shell /usr/sbin/nologin "$u"
    log "Set password for '$u' (used for VPN auth via PAM)..."
  fi
  passwd "$u"
  mkdir -p "$CLIENT_DIR"
  mk_profile "$u"
  log "User '$u' ready. Distribute ${CLIENT_DIR}/${u}.ovpn and the user’s VPN credentials."
}

passwd_user(){
  local u="${1:-}"; [[ -z "$u" ]] && { err "Username required"; exit 1; }
  id -u "$u" >/dev/null 2>&1 || { err "User '$u' not found"; exit 1; }
  passwd "$u"
}

remove_user(){
  local u="${1:-}"; [[ -z "$u" ]] && { err "Username required"; exit 1; }
  if id -u "$u" >/dev/null 2>&1; then
    userdel -r "$u" 2>/dev/null || true
    log "Removed system user '$u'."
  else
    warn "System user '$u' not found."
  fi
  rm -f "$CLIENT_DIR/${u}.ovpn"
  log "Removed client profile for '$u' (if existed)."
  systemctl restart "$UNIT"
}

list_profiles(){
  ls -1 "$CLIENT_DIR"/*.ovpn 2>/dev/null || echo "No client profiles."
}

status_srv(){
  systemctl status "$UNIT" --no-pager || true
  echo
  echo -n "Connected clients: "
  if [[ -f "/var/log/openvpn/openvpn-status.log" ]]; then
    grep -c "^CLIENT_LIST" /var/log/openvpn/openvpn-status.log || echo 0
  else
    echo 0
  fi
}

fixperms(){
  mkdir -p /var/log/openvpn /var/run/openvpn-tmp
  chown -R "$OPENVPN_SYSTEM_USER:$OPENVPN_SYSTEM_GROUP" /var/log/openvpn /var/run/openvpn-tmp
  chmod 755 /var/log/openvpn
  chmod 770 /var/run/openvpn-tmp
  touch /var/log/openvpn/openvpn.log /var/log/openvpn/openvpn-status.log
  chown "$OPENVPN_SYSTEM_USER:$OPENVPN_SYSTEM_GROUP" /var/log/openvpn/openvpn.log /var/log/openvpn/openvpn-status.log
  log "Permissions fixed."
  systemctl restart "$UNIT"
}

case "${1:-}" in
  add)       shift; add_user "${1:-}";;
  passwd)    shift; passwd_user "${1:-}";;
  remove)    shift; remove_user "${1:-}";;
  list)      list_profiles;;
  status)    status_srv;;
  restart)   systemctl restart "$UNIT"; log "Restarted.";;
  logs)      exec tail -n 50 -F /var/log/openvpn/openvpn.log;;
  fixperms)  fixperms;;
  *)         usage; exit 1;;
esac
MAN
chmod +x /usr/local/bin/openvpn-manage

# --- Status helper ----------------------------------------------------------
cat > /usr/local/bin/openvpn-status <<'STAT'
#!/bin/bash
set -euo pipefail
echo "=== OpenVPN Server Status ==="
systemctl status openvpn-server@server --no-pager || true
echo
if [[ -f /var/log/openvpn/openvpn-status.log ]]; then
  echo -n "Connected clients: "
  grep -c "^CLIENT_LIST" /var/log/openvpn/openvpn-status.log || echo 0
else
  echo "Connected clients: 0"
fi
echo
echo "Recent log:"
if [[ -f /var/log/openvpn/openvpn.log ]]; then
  tail -n 20 /var/log/openvpn/openvpn.log
else
  echo "(no log yet)"
fi
STAT
chmod +x /usr/local/bin/openvpn-status

# --- Final info -------------------------------------------------------------
IP_NOW="$(curl -fsS ifconfig.me || true)"
echo
log "Installation complete."
echo -e "${CYAN}Server IP:${NC} ${IP_NOW:-unknown}"
echo -e "${CYAN}Port/Proto:${NC} $VPN_PORT/$VPN_PROTO"
echo -e "${CYAN}Auth:${NC} Username & Password (PAM)"
echo -e "${CYAN}Config path:${NC} $SERVER_DIR/$SERVER_NAME.conf"
echo -e "${CYAN}Manage users:${NC} openvpn-manage add <username> | passwd <username> | remove <username> | list"
echo -e "${CYAN}Quick status:${NC} openvpn-status"
echo
warn "Next:"
echo "  1) Create a VPN user:  sudo openvpn-manage add alice"
echo "  2) Fetch profile:      sudo cat /etc/openvpn/clients/alice.ovpn"
echo "  3) Import into OpenVPN client; enter username/password when prompted."
