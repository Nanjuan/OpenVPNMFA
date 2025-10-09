#!/usr/bin/env bash
# openvpn-cert-pass-installer.sh
# OpenVPN server with certificate-only auth and passphrase-protected keys (no PAM)
# Ubuntu/Debian and RHEL/Rocky/Alma supported. Requires systemd.
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
    echo ">>> Building CA (you will be prompted for a CA key passphrase)"
    ./easyrsa build-ca
  fi
}

build_server(){
  cd "$EASYRSA_DIR"
  if [ ! -f "$PKI_DIR/issued/${SERVER_NAME}.crt" ]; then
    echo
    echo ">>> Building server cert/key (you will be prompted for a SERVER key passphrase)"
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
  echo "The server's private key is encrypted. OpenVPN under systemd needs an askpass file."
  echo "Enter the SERVER KEY passphrase (stored root-only at $ASKPASS_FILE)."
  echo "If you prefer to type it manually every boot, leave empty and we will remove 'askpass'."
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

make_client(){
  local cn="$1"
  cd "$EASYRSA_DIR"
  if [ -f "$PKI_DIR/issued/${cn}.crt" ]; then
    echo "Client ${cn} already exists."
  else
    echo
    echo ">>> Creating client '$cn' (you will be prompted for a CLIENT key passphrase)"
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

# ---------------------- Main ----------------------
need_root
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

# -------- Fixed locations (use INSTANCE_NAME for service/config) --------
ASKPASS_FILE="/etc/openvpn/server/${INSTANCE_NAME}.pass"
SERVER_CONF="/etc/openvpn/server/${INSTANCE_NAME}.conf"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
PKI_DIR="$EASYRSA_DIR/pki"
TA_KEY="/etc/openvpn/ta.key"
CRL_FILE="$PKI_DIR/crl.pem"
OUTPUT_DIR="/root/openvpn-clients"

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
      read -r -p "Client name (CN): " CN
      [ -z "$CN" ] && { echo "No CN provided."; continue; }
      make_client "$CN"
      inline_ovpn "$CN" "$PROFILE_REMOTE_IP" "$OVPN_PORT" "$OVPN_PROTO"
      ;;
    2)
      read -r -p "Client name (CN) to revoke: " CN
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
