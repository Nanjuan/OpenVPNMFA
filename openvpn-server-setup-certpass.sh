#!/usr/bin/env bash
# openvpn-cert-pass-installer.sh
# OpenVPN server with certificate-only auth and passphrase-protected keys (no PAM)
# Ubuntu/Debian and RHEL/Rocky/Alma supported. Requires systemd.
#
# Author: Nestor Torres
# Created: October 2025
# Version: 1
set -euo pipefail

# ---------------------- Constants ----------------------
INSTANCE_NAME="server"  # fixed systemd instance and config filename (server.conf)

# ---------------------- Helpers ----------------------
die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "$(id -u )" -eq 0 ] || die "Run as root."; }

detect_pkg(){
  if command -v apt-get >/dev/null 2>&1; then PKG="apt"; return; fi
  if command -v dnf >/dev/null 2>&1; then PKG="dnf"; return; fi
  if command -v yum >/dev/null 2>&1; then PKG="yum"; return; fi
  die "Unsupported distro: need apt, dnf, or yum."
}

pkg_install(){
  case "$PKG" in
    apt)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn easy-rsa curl
      ;;
    dnf)
      dnf install -y openvpn easy-rsa curl || dnf install -y openvpn easy-rsa-3 curl
      ;;
    yum)
      yum install -y epel-release || true
      yum install -y openvpn easy-rsa curl || yum install -y easy-rsa-3 curl
      ;;
  esac
}

prompt_default(){
  local prompt="$1" default="$2" var
  read -r -p "$prompt [$default]: " var
  echo "${var:-$default}"
}

ensure_dirs(){
  mkdir -p /etc/openvpn/server /etc/openvpn/tmp "$OUTPUT_DIR"
  chmod 700 "$OUTPUT_DIR"
}

# Safe IP forward enabling (works even if /etc/sysctl.conf is missing)
enable_ip_forward(){
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  mkdir -p /etc/sysctl.d
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-openvpn-ipforward.conf
  if [ -f /etc/sysctl.conf ]; then
    if grep -q '^\s*net\.ipv4\.ip_forward' /etc/sysctl.conf; then
      sed -ri 's|^\s*#?\s*net\.ipv4\.ip_forward\s*=.*|net.ipv4.ip_forward=1|' /etc/sysctl.conf || true
    else
      printf '\nnet.ipv4.ip_forward=1\n' >> /etc/sysctl.conf || true
    fi
  fi
  sysctl --system >/dev/null 2>&1 || true
}

ensure_easyrsa(){
  if [ ! -d "$EASYRSA_DIR" ]; then
    mkdir -p "$EASYRSA_DIR"
    if [ -d /usr/share/easy-rsa ]; then
      cp -a /usr/share/easy-rsa/* "$EASYRSA_DIR"/
    fi
  fi
  if [ ! -x "$EASYRSA_DIR/easyrsa" ] && command -v easyrsa >/dev/null 2>&1; then
    ln -sf "$(command -v easyrsa)" "$EASYRSA_DIR/easyrsa"
  fi
  [ -x "$EASYRSA_DIR/easyrsa" ] || die "Could not find Easy-RSA executable."
}

init_pki(){
  cd "$EASYRSA_DIR"
  [ -d "$PKI_DIR" ] || ./easyrsa init-pki
}

build_ca(){
  cd "$EASYRSA_DIR"
  if [ ! -f "$PKI_DIR/private/ca.key" ]; then
        echo
    echo ">>> Building the Certificate Authority (CA)"
    echo "ABOUT THIS PASSWORD (CA KEY):"
    echo " - You (the admin) will set a passphrase that protects the CA private key (ca.key)."
    echo " - This CA passphrase is used only when YOU issue or revoke certificates (admin operations)."
    echo " - OpenVPN server and clients do NOT need this at runtime."
    echo " - Store it safely (ideally offline). If lost, you cannot issue/revoke certs from this CA."
    echo
    ./easyrsa build-ca
  fi
}

build_server(){
  cd "$EASYRSA_DIR"
  if [ ! -f "$PKI_DIR/issued/${SERVER_NAME}.crt" ]; then
    echo
    echo ">>> Building the SERVER certificate and encrypted private key"
    echo "ABOUT THIS PASSWORD (SERVER KEY):"
    echo " - You will set a passphrase that encrypts the server private key (${SERVER_NAME}.key)."
    echo " - OpenVPN needs this passphrase every time the service starts (e.g., on reboot or restart)."
    echo " - In the next step, the script will ask you for THIS SAME passphrase again to save it"
    echo "   into: /etc/openvpn/server/server.pass (root-only, 600) so systemd can auto-start OpenVPN."
    echo " - If you choose NOT to save it, the systemd service cannot prompt and will fail to start"
    echo "   unless you run OpenVPN in the foreground and type the passphrase manually."
    echo
    ./easyrsa build-server-full "$SERVER_NAME"
  fi
  [ -f "$PKI_DIR/dh.pem" ] || ./easyrsa gen-dh
  if [ ! -f "$CRL_FILE" ]; then
    ./easyrsa gen-crl
  else
    ./easyrsa gen-crl || true
  fi
  if [ ! -f "$TA_KEY" ]; then
    openvpn --genkey secret "$TA_KEY"
    chmod 600 "$TA_KEY"
  fi
  install -m 0644 "$CRL_FILE" /etc/openvpn/server/crl.pem
}

write_server_conf(){
  local port="$1" proto="$2"
  cat > "$SERVER_CONF" <<EOF
# OpenVPN Server Configuration (PAM-free, cert-only with passphrase-protected keys)
port $port
proto $proto
dev tun
topology subnet

ca $PKI_DIR/ca.crt
cert $PKI_DIR/issued/${SERVER_NAME}.crt
key $PKI_DIR/private/${SERVER_NAME}.key
dh $PKI_DIR/dh.pem
tls-crypt $TA_KEY
crl-verify /etc/openvpn/server/crl.pem

server $OVPN_NET $OVPN_MASK
ifconfig-pool-persist ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $OVPN_DNS_1"
push "dhcp-option DNS $OVPN_DNS_2"

keepalive 10 120
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun

# If the server key is encrypted (recommended), use askpass
askpass $ASKPASS_FILE

explicit-exit-notify 1
verb 3
EOF
}

set_askpass(){
  echo
  echo
  echo ">>> Configure askpass for systemd (server key unlock at boot)"
  echo "ABOUT THIS STEP:"
  echo " - Enter the SAME passphrase you just set for the SERVER private key."
  echo " - It will be stored at: $ASKPASS_FILE (root-only, chmod 600)."
  echo " - This allows 'systemctl start openvpn-server@server' to unlock the server key automatically."
  echo " - Example use: after a reboot or 'systemctl restart openvpn-server@server', systemd reads this file"
  echo "   to supply the passphrase non-interactively."
  echo " - If you leave it blank, the 'askpass' line is removed and the service will NOT auto-start."
  echo
  read -r -s -p "Server key passphrase: " spass; echo
  if [ -n "$spass" ]; then
    mkdir -p "$(dirname "$ASKPASS_FILE")"
    printf '%s\n' "$spass" > "$ASKPASS_FILE"
    chmod 600 "$ASKPASS_FILE"
  else
    sed -i '/^askpass /d' "$SERVER_CONF"
    echo "No askpass set; service start will fail if it cannot prompt. You can start in foreground manually."
  fi
}

start_service(){
  systemctl enable "openvpn-server@${INSTANCE_NAME}" >/dev/null 2>&1 || true
  systemctl daemon-reload
  systemctl restart "openvpn-server@${INSTANCE_NAME}"
  sleep 1
  systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true
}

is_service_running(){
  systemctl is-active --quiet "openvpn-server@${INSTANCE_NAME}"
}

# ---------- Settings discovery for client generation ----------
detect_public_ip(){
  curl -s ifconfig.me || curl -s icanhazip.com || hostname -I | awk '{print $1}'
}

get_server_port(){
  [ -f "$SERVER_CONF" ] || { echo "1194"; return; }
  awk '/^port[[:space:]]+/ {print $2; found=1} END{if(!found) print "1194"}' "$SERVER_CONF"
}

get_server_proto(){
  [ -f "$SERVER_CONF" ] || { echo "udp"; return; }
  awk '/^proto[[:space:]]+/ {print $2; found=1} END{if(!found) print "udp"}' "$SERVER_CONF"
}

# ---------- Client management ----------
make_client(){
  local cn="$1"
  cd "$EASYRSA_DIR"
  if [ -f "$PKI_DIR/issued/${cn}.crt" ]; then
    echo "Client ${cn} already exists."
  else
    echo
    echo ">>> Creating client certificate and encrypted private key for: $cn"
    echo "ABOUT THIS PASSWORD (CLIENT KEY for $cn):"
    echo " - You will set a passphrase that encrypts $cn's private key (${cn}.key)."
    echo " - The USER ($cn) will be prompted for this passphrase whenever they connect"
    echo "   using their .ovpn profile in the OpenVPN app (desktop or mobile)."
    echo " - The server does NOT know this passphrase; if it’s forgotten, you’ll need to"
    echo "   issue a new client certificate/key for the user."
    echo
    ./easyrsa build-client-full "$cn"
  fi
}

inline_ovpn(){
  local cn="$1" remote_ip="$2" port="$3" proto="$4"
  local out="$OUTPUT_DIR/${cn}.ovpn"
  cat > "$out" <<EOF
client
dev tun
proto $proto
remote $remote_ip $port
resolv-retry infinite
nobind
persist-key
persist-tun

remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
$(cat "$PKI_DIR/ca.crt")
</ca>

<cert>
$(openssl x509 -in "$PKI_DIR/issued/${cn}.crt")
</cert>

<key>
$(cat "$PKI_DIR/private/${cn}.key")
</key>

<tls-crypt>
$(cat "$TA_KEY")
</tls-crypt>
EOF
  chmod 600 "$out"
  echo "Generated: $out"
}

rebuild_crl(){
  cd "$EASYRSA_DIR"
  ./easyrsa gen-crl
  install -m 0644 "$CRL_FILE" /etc/openvpn/server/crl.pem
  systemctl restart "openvpn-server@${INSTANCE_NAME}"
}

revoke_client(){
  local cn="$1"
  cd "$EASYRSA_DIR"
  ./easyrsa revoke "$cn" || true
  rebuild_crl
  echo "Revoked $cn and refreshed CRL."
}

list_clients(){
  if [ -f "$PKI_DIR/index.txt" ]; then
    echo "Status  Expiry(UTC)          Serial            CN"
    awk '/^V|^R/{
      status=$1=="V"?"VALID":"REVOKED";
      split($NF, a, "/CN="); cn=a[length(a)];
      printf "%-7s %-20s %-16s %s\n", status, $2, $4, cn
    }' "$PKI_DIR/index.txt" | sort
  else
    echo "No PKI index found."
  fi
}

show_menu(){
  cat <<'MENU'

===== OpenVPN Cert+Passphrase Manager =====
1) Add new client (encrypted key, inline .ovpn)
2) Revoke client
3) List clients
4) Restart OpenVPN service
5) Show service status
6) Exit
MENU
}

# ---------------------- Fixed locations ----------------------
ASKPASS_FILE="/etc/openvpn/server/${INSTANCE_NAME}.pass"
SERVER_CONF="/etc/openvpn/server/${INSTANCE_NAME}.conf"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
PKI_DIR="$EASYRSA_DIR/pki"
TA_KEY="/etc/openvpn/ta.key"
CRL_FILE="$PKI_DIR/crl.pem"
OUTPUT_DIR="/root/openvpn-clients"

# ---------------------- Main ----------------------
need_root

# If OpenVPN service is already running, skip install and go straight to manager
if is_service_running; then
  echo "Detected running OpenVPN service: openvpn-server@${INSTANCE_NAME}"
  echo "Skipping installation and entering manager..."
  while true; do
    show_menu
    read -r -p "Select: " choice
    case "$choice" in
      1)
        read -r -p "Client name (CN) username: " CN
        [ -z "$CN" ] && { echo "No CN provided."; continue; }
        make_client "$CN"
        RIP="$(detect_public_ip)"
        RPORT="$(get_server_port)"
        RPROTO="$(get_server_proto)"
        inline_ovpn "$CN" "$RIP" "$RPORT" "$RPROTO"
        ;;
      2)
        read -r -p "Client name (CN) username to revoke: " CN
        [ -z "$CN" ] && { echo "No CN provided."; continue; }
        revoke_client "$CN"
        ;;
      3) list_clients ;;
      4) systemctl restart "openvpn-server@${INSTANCE_NAME}"; systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true ;;
      5) systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true ;;
      6) echo "Done."; exit 0 ;;
      *) echo "Invalid choice." ;;
    esac
  done
fi

# Not running: proceed with installation
detect_pkg
pkg_install

# -------- CONFIG PROMPTS (interactive) --------
PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || hostname -I | awk '{print $1}')
OVPN_PORT_DEFAULT="1194"
OVPN_PROTO_DEFAULT="udp"
OVPN_NET_DEFAULT="10.8.0.0"
OVPN_MASK_DEFAULT="255.255.255.0"
OVPN_DNS_1_DEFAULT="1.1.1.1"
OVPN_DNS_2_DEFAULT="8.8.8.8"
SERVER_NAME_DEFAULT="server"

echo "===== OpenVPN Setup ====="
read -r -p "Public IP or DNS for clients [$PUBLIC_IP]: " PROFILE_REMOTE_IP
PROFILE_REMOTE_IP="${PROFILE_REMOTE_IP:-$PUBLIC_IP}"

read -r -p "OpenVPN port [$OVPN_PORT_DEFAULT]: " OVPN_PORT
OVPN_PORT="${OVPN_PORT:-$OVPN_PORT_DEFAULT}"

read -r -p "OpenVPN protocol (udp/tcp) [$OVPN_PROTO_DEFAULT]: " OVPN_PROTO
OVPN_PROTO="${OVPN_PROTO:-$OVPN_PROTO_DEFAULT}"

read -r -p "VPN network [$OVPN_NET_DEFAULT]: " OVPN_NET
OVPN_NET="${OVPN_NET:-$OVPN_NET_DEFAULT}"

read -r -p "VPN netmask [$OVPN_MASK_DEFAULT]: " OVPN_MASK
OVPN_MASK="${OVPN_MASK:-$OVPN_MASK_DEFAULT}"

read -r -p "Primary DNS [$OVPN_DNS_1_DEFAULT]: " OVPN_DNS_1
OVPN_DNS_1="${OVPN_DNS_1:-$OVPN_DNS_1_DEFAULT}"

read -r -p "Secondary DNS [$OVPN_DNS_2_DEFAULT]: " OVPN_DNS_2
OVPN_DNS_2="${OVPN_DNS_2:-$OVPN_DNS_2_DEFAULT}"

read -r -p "Server certificate name (CN) [$SERVER_NAME_DEFAULT]: " SERVER_NAME
SERVER_NAME="${SERVER_NAME:-$SERVER_NAME_DEFAULT}"

# -------- Proceed with setup --------
ensure_dirs
enable_ip_forward
ensure_easyrsa
init_pki
build_ca
build_server
write_server_conf "$OVPN_PORT" "$OVPN_PROTO"
set_askpass
start_service

echo
echo "Base setup complete."
echo "Clients authenticate with certificates; each private key is encrypted and will prompt for a passphrase at connection."
echo "Client profiles (.ovpn) will be written to: $OUTPUT_DIR"
echo

# -------- Management loop --------
while true; do
  show_menu
  read -r -p "Select: " choice
  case "$choice" in
    1)
      read -r -p "Client name (CN) username: " CN
      [ -z "$CN" ] && { echo "No CN provided."; continue; }
      make_client "$CN"
      RIP="$(detect_public_ip)"
      RPORT="$(get_server_port)"
      RPROTO="$(get_server_proto)"
      inline_ovpn "$CN" "$RIP" "$RPORT" "$RPROTO"
      ;;
    2)
      read -r -p "Client name (CN) username to revoke: " CN
      [ -z "$CN" ] && { echo "No CN provided."; continue; }
      revoke_client "$CN"
      ;;
    3) list_clients ;;
    4) systemctl restart "openvpn-server@${INSTANCE_NAME}"; systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true ;;
    5) systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true ;;
    6) echo "Done."; exit 0 ;;
    *) echo "Invalid choice." ;;
  esac
done
