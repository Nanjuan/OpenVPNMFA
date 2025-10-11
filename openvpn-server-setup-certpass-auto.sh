#!/usr/bin/env bash
# openvpn-server-setup-certpass-auto.sh
# OpenVPN server with certificate-only auth and passphrase-protected keys (no PAM)
# Ubuntu/Debian and RHEL/Rocky/Alma supported. Requires systemd.
#
# Author: Nestor Torres
# Created: October 2025
# Version: 2 (adds robust non-interactive passphrase handling)
set -euo pipefail

# ---------------------- Constants ----------------------
INSTANCE_NAME="server"  # fixed systemd instance and config filename (server.conf)

# ---------------------- Defaults for prompts ----------------------
PUBLIC_IP_DEFAULT="$(curl -s ifconfig.me || curl -s icanhazip.com || hostname -I | awk '{print $1}' || true)"
OVPN_PORT_DEFAULT="1194"
OVPN_PROTO_DEFAULT="udp"
OVPN_NET_DEFAULT="10.8.0.0"
OVPN_MASK_DEFAULT="255.255.255.0"
OVPN_DNS_1_DEFAULT="1.1.1.1"
OVPN_DNS_2_DEFAULT="8.8.8.8"
SERVER_NAME_DEFAULT="server"

# ---------------------- Helpers ----------------------
die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "$(id -u )" -eq 0 ] || die "Run as root."; }

# ---------------------- CLI: help/daemon/flags ----------------------
usage() {
  cat <<'EOF'
Usage:
  openvpn-server-setup-certpass-auto.sh [options]

General:
  -h, --help              Show this help and exit
  -d, --daemon            Non-interactive install (no prompts). All required flags
                          below must be supplied; otherwise the script exits.

Install parameters (map 1:1 to interactive prompts):
  --remote VALUE          Public IP or DNS for clients (e.g., vpn.example.com)
  --port VALUE            OpenVPN port (e.g., 1194)
  --proto VALUE           OpenVPN protocol ("udp" or "tcp")
  --vpn-net VALUE         VPN network (e.g., 10.8.0.0)
  --vpn-mask VALUE        VPN netmask (e.g., 255.255.255.0)
  --dns1 VALUE            Primary DNS (e.g., 1.1.1.1)
  --dns2 VALUE            Secondary DNS (e.g., 8.8.8.8)
  --server-name VALUE     Server certificate CN (e.g., "server")

Secrets (required in --daemon, entered once in interactive):
  --ca-pass VALUE         Passphrase to encrypt the CA private key
  --server-pass VALUE     Passphrase to encrypt the SERVER private key AND to write
                          into the askpass file for systemd auto-unlock

Examples:
  # Interactive (prompts as before)
  sudo ./openvpn-server-setup-certpass-auto.sh

  # Non-interactive (daemon mode) with auto-unlock on boot
  sudo ./openvpn-server-setup-certpass-auto.sh -d \
    --remote vpn.example.com --port 1194 --proto udp \
    --vpn-net 10.8.0.0 --vpn-mask 255.255.255.0 \
    --dns1 1.1.1.1 --dns2 8.8.8.8 --server-name server \
    --ca-pass "CA-Strong-Secret" \
    --server-pass "Server-Strong-Secret"
EOF
}

DAEMON_MODE=false
# Flags (empty == not provided)
PROFILE_REMOTE_IP_FLAG=""; OVPN_PORT_FLAG=""; OVPN_PROTO_FLAG=""
OVPN_NET_FLAG=""; OVPN_MASK_FLAG=""; OVPN_DNS_1_FLAG=""; OVPN_DNS_2_FLAG=""
SERVER_NAME_FLAG=""
CA_PASS_FLAG=""; SERVER_PASS_FLAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -d|--daemon) DAEMON_MODE=true; shift ;;
    --remote) PROFILE_REMOTE_IP_FLAG="${2:?--remote requires a value}"; shift 2 ;;
    --port)   OVPN_PORT_FLAG="${2:?--port requires a value}"; shift 2 ;;
    --proto)  OVPN_PROTO_FLAG="${2:?--proto requires a value}"; shift 2 ;;
    --vpn-net)  OVPN_NET_FLAG="${2:?--vpn-net requires a value}"; shift 2 ;;
    --vpn-mask) OVPN_MASK_FLAG="${2:?--vpn-mask requires a value}"; shift 2 ;;
    --dns1)   OVPN_DNS_1_FLAG="${2:?--dns1 requires a value}"; shift 2 ;;
    --dns2)   OVPN_DNS_2_FLAG="${2:?--dns2 requires a value}"; shift 2 ;;
    --server-name) SERVER_NAME_FLAG="${2:?--server-name requires a value}"; shift 2 ;;
    --ca-pass)    CA_PASS_FLAG="${2:?--ca-pass requires a value}"; shift 2 ;;
    --server-pass) SERVER_PASS_FLAG="${2:?--server-pass requires a value}"; shift 2 ;;
    --) shift; break ;;
    -*) echo "Unknown option: $1"; usage; exit 1 ;;
    *) break ;;
  esac
done

require_flag() { local n="$1" v="$2"; [[ -n "$v" ]] || die "Missing required parameter in --daemon mode: $n"; }

# ---------------------- Existing helpers (unchanged core) ----------------------
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

prompt_default(){ local p="$1" d="$2" v; read -r -p "$p [$d]: " v; echo "${v:-$d}"; }

ensure_dirs(){ mkdir -p /etc/openvpn/server /etc/openvpn/tmp "$OUTPUT_DIR"; chmod 700 "$OUTPUT_DIR"; }

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

init_pki(){ cd "$EASYRSA_DIR"; [ -d "$PKI_DIR" ] || ./easyrsa init-pki; }

# ---------- Robust non-interactive helpers ----------
supports_passout() { ./easyrsa --help 2>/dev/null | grep -q -- '--passout' || return 1; }
ensure_expect() {
  command -v expect >/dev/null 2>&1 && return 0
  case "$PKG" in
    apt)  DEBIAN_FRONTEND=noninteractive apt-get update -y; DEBIAN_FRONTEND=noninteractive apt-get install -y expect ;;
    dnf)  dnf install -y expect ;;
    yum)  yum install -y expect ;;
    *) die "Expect required but package manager unsupported." ;;
  esac
}

build_ca(){
  cd "$EASYRSA_DIR"
  if [ ! -f "$PKI_DIR/private/ca.key" ]; then
    echo
    echo ">>> Building the Certificate Authority (CA) with a PASSPHRASE"
    echo " - The CA private key will be encrypted."
    local capass=""
    if $DAEMON_MODE; then
      capass="${CA_PASS_FLAG}"
    else
      read -r -s -p "Enter CA key passphrase: " capass; echo
      [ -n "$capass" ] || die "CA key passphrase cannot be empty."
    fi
    # 1) Try CLI --passout (preferred)
    if supports_passout; then
      if ./easyrsa --batch --req-cn="OpenVPN-CA" --passout="pass:${capass}" build-ca; then
        return
      fi
      echo "WARN: --passout path failed; trying env..." >&2
    fi
    # 2) Try env-based passout
    if EASYRSA_BATCH=1 EASYRSA_REQ_CN="OpenVPN-CA" EASYRSA_PASSOUT="pass:${capass}" ./easyrsa build-ca; then
      return
    fi
    echo "WARN: env path failed; falling back to expect..." >&2
    # 3) Expect fallback (drive prompts)
    ensure_expect
    expect -c " \
      set timeout -1; \
      set capass \"$capass\"; \
      spawn ./easyrsa build-ca; \
      expect { \
        -re {(?i)Enter New CA Key Passphrase:} { send -- \"$capass\r\"; exp_continue } \
        -re {(?i)Re-Enter New CA Key Passphrase:} { send -- \"$capass\r\"; exp_continue } \
        -re {(?i)Common Name.*:} { send -- \"OpenVPN-CA\r\"; exp_continue } \
        eof \
      }"
  fi
}

build_server(){
  cd "$EASYRSA_DIR"
  if [ ! -f "$PKI_DIR/issued/${SERVER_NAME}.crt" ]; then
    echo
    echo ">>> Building the SERVER certificate with an encrypted private key"
    local spass=""
    if $DAEMON_MODE; then
      spass="$SERVER_PASS_FLAG"
    else
      read -r -s -p "Enter SERVER key passphrase: " SERVER_KEY_PASSPHRASE; echo
      [ -n "$SERVER_KEY_PASSPHRASE" ] || die "Server key passphrase cannot be empty."
      spass="$SERVER_KEY_PASSPHRASE"
    fi
    # 1) Try CLI --passout
    if supports_passout; then
      if ./easyrsa --batch --req-cn="${SERVER_NAME}" --passout="pass:${spass}" build-server-full "$SERVER_NAME"; then
        :
      else
        echo "WARN: --passout failed; trying env..." >&2
        EASYRSA_BATCH=1 EASYRSA_REQ_CN="${SERVER_NAME}" EASYRSA_PASSOUT="pass:${spass}" ./easyrsa build-server-full "$SERVER_NAME" || {
          echo "WARN: env failed; falling back to expect..." >&2
          ensure_expect
          expect -c " \
            set timeout -1; \
            set spass \"$spass\"; \
            spawn ./easyrsa build-server-full \"$SERVER_NAME\"; \
            expect { \
              -re {(?i)Enter PEM pass phrase:} { send -- \"$spass\r\"; exp_continue } \
              -re {(?i)Verifying - Enter PEM pass phrase:} { send -- \"$spass\r\"; exp_continue } \
              -re {(?i)Common Name.*:} { send -- \"$SERVER_NAME\r\"; exp_continue } \
              eof \
            }"
        }
      fi
    else
      # Older easy-rsa without --passout
      EASYRSA_BATCH=1 EASYRSA_REQ_CN="${SERVER_NAME}" EASYRSA_PASSOUT="pass:${spass}" ./easyrsa build-server-full "$SERVER_NAME" || {
        ensure_expect
        expect -c " \
          set timeout -1; \
          set spass \"$spass\"; \
          spawn ./easyrsa build-server-full \"$SERVER_NAME\"; \
          expect { \
            -re {(?i)Enter PEM pass phrase:} { send -- \"$spass\r\"; exp_continue } \
            -re {(?i)Verifying - Enter PEM pass phrase:} { send -- \"$spass\r\"; exp_continue } \
            -re {(?i)Common Name.*:} { send -- \"$SERVER_NAME\r\"; exp_continue } \
            eof \
          }"
      }
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

    # Save passphrase for askpass (used again)
    SERVER_PASSPHRASE_RUNTIME="$spass"
  fi
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
  echo ">>> Configure askpass for systemd (server key unlock at boot)"
  mkdir -p "$(dirname "$ASKPASS_FILE")"
  local spass=""
  if $DAEMON_MODE; then
    spass="$SERVER_PASS_FLAG"
  else
    # reuse previously entered pass if present, fallback to prompt
    if [[ -n "${SERVER_PASSPHRASE_RUNTIME:-}" ]]; then
      spass="$SERVER_PASSPHRASE_RUNTIME"
    else
      read -r -s -p "Re-enter SERVER key passphrase for askpass: " tmp; echo
      spass="$tmp"
    fi
  fi

  if [ -n "$spass" ]; then
    printf '%s\n' "$spass" > "$ASKPASS_FILE"
    chmod 600 "$ASKPASS_FILE"
  else
    sed -i '/^askpass /d' "$SERVER_CONF"
    echo "No server passphrase available; askpass removed. Service may not auto-start."
  fi
}

start_service(){
  systemctl enable "openvpn-server@${INSTANCE_NAME}" >/dev/null 2>&1 || true
  systemctl daemon-reload
  systemctl restart "openvpn-server@${INSTANCE_NAME}"
  sleep 1
  systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true
}

is_service_running(){ systemctl is-active --quiet "openvpn-server@${INSTANCE_NAME}"; }

# ---------- Settings discovery for client generation ----------
detect_public_ip(){ curl -s ifconfig.me || curl -s icanhazip.com || hostname -I | awk '{print $1}'; }
get_server_port(){ [ -f "$SERVER_CONF" ] || { echo "1194"; return; }; awk '/^port[[:space:]]+/ {print $2; f=1} END{if(!f) print "1194"}' "$SERVER_CONF"; }
get_server_proto(){ [ -f "$SERVER_CONF" ] || { echo "udp"; return; }; awk '/^proto[[:space:]]+/ {print $2; f=1} END{if(!f) print "udp"}' "$SERVER_CONF"; }

# ---------- Client management ----------
make_client(){
  local cn="$1"
  cd "$EASYRSA_DIR"
  if [ -f "$PKI_DIR/issued/${cn}.crt" ]; then
    echo "Client ${cn} already exists."
  else
    echo
    echo ">>> Creating client certificate and encrypted private key for: $cn"
    ./easyrsa build-client-full "$cn"   # interactive passphrase entry (by design)
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

rebuild_crl(){ cd "$EASYRSA_DIR"; ./easyrsa gen-crl; install -m 0644 "$CRL_FILE" /etc/openvpn/server/crl.pem; systemctl restart "openvpn-server@${INSTANCE_NAME}"; }
revoke_client(){ local cn="$1"; cd "$EASYRSA_DIR"; ./easyrsa revoke "$cn" || true; rebuild_crl; echo "Revoked $cn and refreshed CRL."; }

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

# -------- CONFIG PROMPTS (interactive) or FLAGS (daemon) --------
if $DAEMON_MODE; then
  require_flag "--remote"      "$PROFILE_REMOTE_IP_FLAG"
  require_flag "--port"        "$OVPN_PORT_FLAG"
  require_flag "--proto"       "$OVPN_PROTO_FLAG"
  require_flag "--vpn-net"     "$OVPN_NET_FLAG"
  require_flag "--vpn-mask"    "$OVPN_MASK_FLAG"
  require_flag "--dns1"        "$OVPN_DNS_1_FLAG"
  require_flag "--dns2"        "$OVPN_DNS_2_FLAG"
  require_flag "--server-name" "$SERVER_NAME_FLAG"
  require_flag "--ca-pass"     "$CA_PASS_FLAG"
  require_flag "--server-pass" "$SERVER_PASS_FLAG"

  PROFILE_REMOTE_IP="$PROFILE_REMOTE_IP_FLAG"
  OVPN_PORT="$OVPN_PORT_FLAG"
  OVPN_PROTO="$OVPN_PROTO_FLAG"
  OVPN_NET="$OVPN_NET_FLAG"
  OVPN_MASK="$OVPN_MASK_FLAG"
  OVPN_DNS_1="$OVPN_DNS_1_FLAG"
  OVPN_DNS_2="$OVPN_DNS_2_FLAG"
  SERVER_NAME="$SERVER_NAME_FLAG"
else
  echo "===== OpenVPN Setup ====="
  PROFILE_REMOTE_IP="$(prompt_default "Public IP or DNS for clients" "${PUBLIC_IP_DEFAULT:-$(hostname -I | awk '{print $1}')}" )"
  OVPN_PORT="$(prompt_default "OpenVPN port" "$OVPN_PORT_DEFAULT")"
  OVPN_PROTO="$(prompt_default "OpenVPN protocol (udp/tcp)" "$OVPN_PROTO_DEFAULT")"
  OVPN_NET="$(prompt_default "VPN network" "$OVPN_NET_DEFAULT")"
  OVPN_MASK="$(prompt_default "VPN netmask" "$OVPN_MASK_DEFAULT")"
  OVPN_DNS_1="$(prompt_default "Primary DNS" "$OVPN_DNS_1_DEFAULT")"
  OVPN_DNS_2="$(prompt_default "Secondary DNS" "$OVPN_DNS_2_DEFAULT")"
  SERVER_NAME="$(prompt_default "Server certificate name (CN)" "$SERVER_NAME_DEFAULT")"
fi

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
