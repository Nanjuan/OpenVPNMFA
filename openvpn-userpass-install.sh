#!/bin/bash
#
# OpenVPN Server Setup - Username/Password only (no client certs)
# Ubuntu 20.04/22.04/24.04/24.10 + OpenVPN 2.6.x
#
# - PAM (pam_unix) auth (system accounts)
# - tmp-dir is /run/openvpn-server/tmp (systemd creates + allows writes)
# - UFW + NAT (idempotent)
# - Management: openvpn-manage / openvpn-status
# - Server log verbosity: verb 6
#
set -euo pipefail

SCRIPT_VERSION="4.0-userpass"
SCRIPT_DATE="2025-10-07"

# ---------- UI ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log(){ echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}"; }
warn(){ echo -e "${YELLOW}[WARN] $*${NC}"; }
err(){ echo -e "${RED}[ERROR] $*${NC}" >&2; }
trap 'err "Install failed on line $LINENO"' ERR

# ---------- Config ----------
OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="/etc/openvpn/server"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
LOG_DIR="/var/log/openvpn"

SERVER_NAME="server"
VPN_NETWORK="10.8.0.0"
VPN_NETMASK="255.255.255.0"
VPN_PORT="1194"
VPN_PROTO="udp"

DATA_CIPHERS="AES-256-GCM:AES-128-GCM"
AUTH_DIGEST="SHA512"
TLS_VERSION_MIN="1.2"

OPENVPN_USER="openvpn"
OPENVPN_GROUP="openvpn"

# ---------- Helpers ----------
detect_pam_plugin() {
  local p
  for p in \
    /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so \
    /usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so \
    /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so \
    /usr/lib/openvpn/plugins/auth-pam.so; do
    [[ -f "$p" ]] && { echo "$p"; return; }
  done
  echo "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so"
}

default_iface(){ ip -4 route list default | awk '{print $5; exit}'; }

ensure_nat_block() {
  # idempotently add a NAT section with MASQUERADE on the detected interface
  local br="/etc/ufw/before.rules"
  local bkp="/etc/ufw/before.rules.bak.$(date +%s)"
  local iface="${1:-$(default_iface)}"; [[ -n "$iface" ]] || iface="eth0"

  if grep -q 'OPENVPN NAT RULES' "$br" 2>/dev/null; then
    sed -i "s/^\(-A POSTROUTING -s 10\.8\.0\.0\/24 -o \).* -j MASQUERADE/\1${iface} -j MASQUERADE/" "$br"
    return 0
  fi

  cp -a "$br" "$bkp"

  awk '
    BEGIN { skip=0 }
    /# OPENVPN NAT RULES/ { skip=1 }
    skip && /^COMMIT$/ { skip=0; next }
    !skip { print }
  ' "$bkp" > "${br}.tmp"

  awk -v iface="$iface" '
    BEGIN { inserted=0 }
    /^\*filter$/ && !inserted {
      print "*nat"
      print ":POSTROUTING ACCEPT [0:0]"
      print "# OPENVPN NAT RULES"
      print "-A POSTROUTING -s 10.8.0.0/24 -o " iface " -j MASQUERADE"
      print "COMMIT"
      inserted=1
    }
    { print }
  ' "${br}.tmp" > "$br"

  rm -f "${br}.tmp"
}

server_ip(){ curl -fsS ifconfig.me || hostname -I | awk '{print $1}'; }

# ---------- Pre-check ----------
[[ $EUID -eq 0 ]] || { err "Run as root"; exit 1; }
log "OpenVPN User/Pass Setup v${SCRIPT_VERSION} (${SCRIPT_DATE})"

# ---------- Packages ----------
log "Updating packages and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y openvpn easy-rsa ufw curl ca-certificates lsb-release

# ---------- Service account ----------
log "Ensuring service user '${OPENVPN_USER}' exists..."
getent passwd "$OPENVPN_USER" >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin --user-group "$OPENVPN_USER"
getent group "$OPENVPN_GROUP" >/dev/null || groupadd --system "$OPENVPN_GROUP"

# ---------- Easy-RSA PKI (server TLS only) ----------
log "Setting up Easy-RSA PKI for server..."
rm -rf "$EASYRSA_DIR"
mkdir -p "$EASYRSA_DIR"
cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"/
pushd "$EASYRSA_DIR" >/dev/null
./easyrsa init-pki
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 ./easyrsa build-server-full "$SERVER_NAME" nopass
EASYRSA_BATCH=1 ./easyrsa gen-dh
openvpn --genkey secret pki/ta.key
chmod 600 "pki/private/${SERVER_NAME}.key" "pki/ta.key" || true
chmod 644 "pki/ca.crt" "pki/issued/${SERVER_NAME}.crt" || true
popd >/dev/null

# ---------- Directories & permissions ----------
log "Creating directories and setting permissions..."
mkdir -p "$SERVER_DIR" "$CLIENT_DIR" "$LOG_DIR"
touch "$LOG_DIR/openvpn.log" "$LOG_DIR/openvpn-status.log" "$OPENVPN_DIR/ipp.txt"
chown -R "$OPENVPN_USER:$OPENVPN_GROUP" "$LOG_DIR"
chmod 0755 "$LOG_DIR"
chown "$OPENVPN_USER:$OPENVPN_GROUP" "$OPENVPN_DIR/ipp.txt"

# ---------- PAM (password auth only) ----------
log "Writing /etc/pam.d/openvpn ..."
cat >/etc/pam.d/openvpn <<'PAM'
# OpenVPN PAM configuration - local UNIX passwords
auth    required        pam_unix.so
account required        pam_unix.so
PAM

# ---------- Server configuration ----------
PAM_PLUGIN="$(detect_pam_plugin)"
log "Using PAM plugin: $PAM_PLUGIN"
log "Writing server config to $SERVER_DIR/${SERVER_NAME}.conf ..."
cat >"$SERVER_DIR/${SERVER_NAME}.conf" <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun
topology subnet

# Server TLS (clients do NOT present certs)
ca $EASYRSA_DIR/pki/ca.crt
cert $EASYRSA_DIR/pki/issued/$SERVER_NAME.crt
key $EASYRSA_DIR/pki/private/$SERVER_NAME.key
dh $EASYRSA_DIR/pki/dh.pem
tls-crypt $EASYRSA_DIR/pki/ta.key
tls-version-min $TLS_VERSION_MIN

# Username/Password only via PAM
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

# Modern crypto
data-ciphers $DATA_CIPHERS
data-ciphers-fallback AES-256-GCM
auth $AUTH_DIGEST

# Privilege drop (OpenVPN starts as root to read keys, then drops here)
user $OPENVPN_USER
group $OPENVPN_GROUP
persist-tun
persist-key

# Temp directory for PAM deferred-auth files (systemd allows this path)
tmp-dir /run/openvpn-server/tmp

# Logging
log-append $LOG_DIR/openvpn.log
verb 6
mute 20

# Keepalive & UDP niceties
keepalive 10 120
explicit-exit-notify 1
tls-server
EOF

# ---------- Systemd drop-in (runtime dir + sandbox write paths) ----------
log "Creating systemd override..."
mkdir -p /etc/systemd/system/openvpn-server@.service.d
cat >/etc/systemd/system/openvpn-server@.service.d/override.conf <<'EOF'
[Service]
# Create /run/openvpn-server at start (owned by root, mode below)
RuntimeDirectory=openvpn-server
RuntimeDirectoryMode=0755

# Create temp subdir for PAM plugin with correct owner/mode, atomically
ExecStartPre=/usr/bin/install -d -m 0770 -o openvpn -g openvpn /run/openvpn-server/tmp

# Allow writes to these paths inside the service sandbox
ReadWritePaths=/run/openvpn-server /var/log/openvpn /etc/openvpn
EOF

systemctl daemon-reload

# ---------- UFW + NAT ----------
log "Configuring UFW and NAT..."
ufw --force enable || true
ufw allow OpenSSH || ufw allow ssh || true
ufw allow "$VPN_PORT/$VPN_PROTO" || true

# IP forwarding & policy
sed -i 's/^#\?net\.ipv4\.ip_forward.*/net.ipv4.ip_forward=1/' /etc/ufw/sysctl.conf || true
grep -q '^net.ipv4.ip_forward=1' /etc/ufw/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/ufw/sysctl.conf
if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw 2>/dev/null; then
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
else
  echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
fi

IFACE="$(default_iface)"; [[ -n "$IFACE" ]] || IFACE="eth0"
ensure_nat_block "$IFACE"
ufw --force reload || { err "UFW reload failed"; exit 1; }

# ---------- Enable & start service ----------
log "Starting openvpn-server@${SERVER_NAME} ..."
systemctl enable --now "openvpn-server@${SERVER_NAME}"
sleep 2
if ! systemctl is-active --quiet "openvpn-server@${SERVER_NAME}"; then
  systemctl status "openvpn-server@${SERVER_NAME}" --no-pager || true
  journalctl -u "openvpn-server@${SERVER_NAME}" -n 120 --no-pager || true
  err "OpenVPN service failed to start."
  exit 1
fi

# ---------- Management helper ----------
log "Installing /usr/local/bin/openvpn-manage ..."
cat >/usr/local/bin/openvpn-manage <<'MAN'
#!/bin/bash
# OpenVPN Management - Username/Password mode (no client certs)
set -euo pipefail
OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="/etc/openvpn/server"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
SERVER_NAME="server"
UNIT="openvpn-server@${SERVER_NAME}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log(){ echo -e "${GREEN}[$(date +'%H:%M:%S')] $*${NC}"; }
warn(){ echo -e "${YELLOW}[WARN] $*${NC}"; }
err(){ echo -e "${RED}[ERROR] $*${NC}" >&2; }

usage(){
  echo "Usage: $0 <command> [args]"
  echo "  add <username>     - Create VPN user (local account, nologin) and export <username>.ovpn"
  echo "  passwd <username>  - Reset VPN user password"
  echo "  remove <username>  - Remove VPN user and .ovpn"
  echo "  list               - List client profiles"
  echo "  status             - Service status + connected clients count"
  echo "  restart            - Restart service"
  echo "  logs               - Tail server log"
  echo "  fixperms           - Fix log/runtime perms and restart"
}

server_ip(){ curl -fsS ifconfig.me || hostname -I | awk '{print $1}'; }

mk_profile(){
  local u="$1"; local sip="$(server_ip)"
  mkdir -p "$CLIENT_DIR"
  cat > "$CLIENT_DIR/${u}.ovpn" <<PROF
client
setenv CLIENT_CERT 0
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
  chmod 600 "$CLIENT_DIR/${u}.ovpn"
  log "Client profile written: $CLIENT_DIR/${u}.ovpn"
}

add_user(){
  local u="${1:-}"; [[ -n "$u" ]] || { err "Username required"; exit 1; }
  if id -u "$u" >/dev/null 2>&1; then
    warn "User '$u' exists; resetting password."
  else
    useradd --no-create-home --shell /usr/sbin/nologin "$u"
  fi
  passwd "$u"
  mk_profile "$u"
  log "User '$u' is ready. Distribute ${CLIENT_DIR}/${u}.ovpn to the user."
}

passwd_user(){
  local u="${1:-}"; [[ -n "$u" ]] || { err "Username required"; exit 1; }
  id -u "$u" >/dev/null 2>&1 || { err "User '$u' not found"; exit 1; }
  passwd "$u"
}

remove_user(){
  local u="${1:-}"; [[ -n "$u" ]] || { err "Username required"; exit 1; }
  if id -u "$u" >/dev/null 2>&1; then userdel --remove "$u" 2>/dev/null || true; fi
  rm -f "$CLIENT_DIR/${u}.ovpn"
  systemctl restart "$UNIT"
  log "Removed '$u' and restarted VPN."
}

list_profiles(){ ls -1 "$CLIENT_DIR"/*.ovpn 2>/dev/null || echo "No client profiles."; }

status_srv(){
  systemctl status "$UNIT" --no-pager || true
  echo
  echo -n "Connected clients: "
  if [[ -f /run/openvpn-server/status-server.log ]]; then
    grep -c "^CLIENT_LIST" /run/openvpn-server/status-server.log || echo 0
  else
    echo 0
  fi
}

logs(){ exec tail -n 100 -F /var/log/openvpn/openvpn.log; }

fixperms(){
  mkdir -p /var/log/openvpn /run/openvpn-server/tmp
  chown -R openvpn:openvpn /var/log/openvpn
  chmod 0755 /var/log/openvpn
  # Runtime dir is created by systemd, but ensure tmp exists & owned by openvpn
  install -d -m 0770 -o openvpn -g openvpn /run/openvpn-server/tmp
  systemctl restart "$UNIT"
  log "Permissions fixed and service restarted."
}

case "${1:-}" in
  add) shift; add_user "${1:-}";;
  passwd) shift; passwd_user "${1:-}";;
  remove) shift; remove_user "${1:-}";;
  list) list_profiles;;
  status) status_srv;;
  restart) systemctl restart "$UNIT"; log "Restarted.";;
  logs) logs;;
  fixperms) fixperms;;
  *) usage; exit 1;;
esac
MAN
chmod +x /usr/local/bin/openvpn-manage

# ---------- Quick status helper ----------
cat >/usr/local/bin/openvpn-status <<'STAT'
#!/bin/bash
set -euo pipefail
echo "=== OpenVPN Server Status ==="
systemctl status openvpn-server@server --no-pager || true
echo
if [[ -f /run/openvpn-server/status-server.log ]]; then
  echo -n "Connected clients: "
  grep -c "^CLIENT_LIST" /run/openvpn-server/status-server.log || echo 0
else
  echo "Connected clients: 0"
fi
echo
echo "Recent log:"
[[ -f /var/log/openvpn/openvpn.log ]] && tail -n 20 /var/log/openvpn/openvpn.log || echo "(no log yet)"
STAT
chmod +x /usr/local/bin/openvpn-status

# ---------- Done ----------
PUB_IP="$(server_ip || true)"
echo
log "Installation complete."
echo -e "${CYAN}Server IP:${NC} ${PUB_IP:-unknown}"
echo -e "${CYAN}Port/Proto:${NC} ${VPN_PORT}/${VPN_PROTO}"
echo -e "${CYAN}Auth:${NC} Username & Password (PAM)"
echo -e "${CYAN}Server config:${NC} ${SERVER_DIR}/${SERVER_NAME}.conf"
echo -e "${CYAN}Manage users:${NC} openvpn-manage add <user> | passwd <user> | remove <user> | list | status | logs"
echo -e "${CYAN}Quick status:${NC} openvpn-status"
echo
warn "Next: create a user ->  sudo openvpn-manage add alice  ; then import /etc/openvpn/clients/alice.ovpn into your client."
