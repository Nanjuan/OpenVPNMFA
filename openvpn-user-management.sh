#!/usr/bin/env bash
# openvpn-user-manager.sh
# Manage OpenVPN users AFTER install: add, revoke, list, optional file removal.
# Works with both "cert-only" and "cert+passphrase" installers in this suite.

set -euo pipefail

# ---------------------- Constants/Paths ----------------------
INSTANCE_NAME="server"
SERVER_CONF="/etc/openvpn/server/${INSTANCE_NAME}.conf"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
PKI_DIR="${EASYRSA_DIR}/pki"
TA_CANDIDATES=(
  "/etc/openvpn/ta.key"
  "${PKI_DIR}/ta.key"
)
CLIENT_OUT_DIRS=(
  "/etc/openvpn/clients"
  "/root/openvpn-clients"
)

AUTH="SHA256"            # matches passphrase installer; clients still work with SHA512 from cert-only server
                         # (server-side 'auth' is authoritative; client 'auth' can be equal or omitted)
DEFAULT_AUTH="${AUTH}"

# ---------------------- UI / Colors -------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
die(){ echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
ok(){ echo -e "${GREEN}OK:${NC} $*"; }
info(){ echo -e "${BLUE}INFO:${NC} $*"; }
warn(){ echo -e "${YELLOW}WARN:${NC} $*"; }

need_root(){ [ "$(id -u)" -eq 0 ] || die "Run as root."; }
have(){ command -v "$1" >/dev/null 2>&1; }

pause(){ read -r -p "Press Enter to continue..." _; }

# ---------------------- (ADDED) CLI -------------------------
usage() {
  cat <<'EOF'
Usage:
  openvpn-user-manager.sh [options]

General:
  -h, --help                Show this help and exit
  -d, --daemon              Non-interactive mode (no prompts). Requires --action.

Actions (daemon mode):
  --action add --cn NAME [--nopass | --key-pass PASS] [--remote HOST] [--port N] [--proto udp|tcp]
  --action revoke --cn NAME
  --action remove-files --cn NAME      # deletes cert/key/profile files (does NOT un-revoke)
  --action list
  --action status

Notes:
- In interactive mode, you get a menu.
- "Add user" can make a passphrase-protected key (you'll be prompted) or a nopass key.
- "Revoke user" updates CRL and restarts the OpenVPN service.
- After revocation, you'll be OFFERED to purge files (never automatic).

EOF
}

DAEMON=false
ACTION=""
CN_FLAG=""
NOPASS=false
KEY_PASS_FLAG=""
REMOTE_FLAG=""
PORT_FLAG=""
PROTO_FLAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -d|--daemon) DAEMON=true; shift ;;
    --action) ACTION="${2:-}"; shift 2 ;;
    --cn) CN_FLAG="${2:-}"; shift 2 ;;
    --nopass) NOPASS=true; shift ;;
    --key-pass) KEY_PASS_FLAG="${2:-}"; shift 2 ;;
    --remote) REMOTE_FLAG="${2:-}"; shift 2 ;;
    --port) PORT_FLAG="${2:-}"; shift 2 ;;
    --proto) PROTO_FLAG="${2:-}"; shift 2 ;;
    --) shift; break ;;
    -*) die "Unknown option: $1" ;;
    *) break ;;
  esac
done

require(){ local n="$1" v="${2:-}"; [[ -n "$v" ]] || die "Missing required parameter: $n"; }

# ---------------------- Helpers ---------------------------
detect_pki(){ [[ -d "$PKI_DIR" && -f "$PKI_DIR/index.txt" ]] || die "PKI not found at $PKI_DIR"; }
find_ta(){
  local t
  for t in "${TA_CANDIDATES[@]}"; do
    [[ -s "$t" ]] && { echo "$t"; return; }
  done
  die "Could not locate ta.key (looked in: ${TA_CANDIDATES[*]})"
}
clients_dir(){
  local d
  for d in "${CLIENT_OUT_DIRS[@]}"; do
    [[ -d "$d" ]] && { echo "$d"; return; }
  done
  # default to first candidate
  echo "${CLIENT_OUT_DIRS[0]}"
}
detect_public_ip(){
  have curl && (curl -s ifconfig.me || curl -s icanhazip.com) || hostname -I | awk '{print $1}'
}
get_server_port(){
  [[ -f "$SERVER_CONF" ]] || { echo "1194"; return; }
  awk '/^port[[:space:]]+/ {print $2; f=1} END{if(!f) print "1194"}' "$SERVER_CONF"
}
get_server_proto(){
  [[ -f "$SERVER_CONF" ]] || { echo "udp"; return; }
  awk '/^proto[[:space:]]+/ {print $2; f=1} END{if(!f) print "udp"}' "$SERVER_CONF"
}

list_users(){
  detect_pki
  if [[ -f "$PKI_DIR/index.txt" ]]; then
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

make_client(){
  detect_pki
  local cn="$1" keymode="$2" pass="${3:-}"
  pushd "$EASYRSA_DIR" >/dev/null
  if [[ -f "$PKI_DIR/issued/${cn}.crt" ]]; then
    warn "Client ${cn} already exists."
  else
    echo ">>> Creating client certificate for: $cn"
    if [[ "$keymode" == "nopass" ]]; then
      EASYRSA_BATCH=1 ./easyrsa build-client-full "$cn" nopass
    else
      if [[ -n "$pass" ]]; then
        EASYRSA_BATCH=1 EASYRSA_PASSOUT="pass:${pass}" ./easyrsa build-client-full "$cn"
      else
        ./easyrsa build-client-full "$cn"
      fi
    fi
  fi
  popd >/dev/null
}

inline_ovpn(){
  detect_pki
  local cn="$1" remote_ip="$2" port="$3" proto="$4"
  local ca="${PKI_DIR}/ca.crt"
  local cert="${PKI_DIR}/issued/${cn}.crt"
  local key="${PKI_DIR}/private/${cn}.key"
  local ta="$(find_ta)"
  local outdir; outdir="$(clients_dir)"; mkdir -p "$outdir"
  local out="${outdir}/${cn}.ovpn"

  [[ -s "$cert" && -s "$key" ]] || die "Missing client cert/key for ${cn}"

  cat > "$out" <<EOF
client
dev tun
proto ${proto}
remote ${remote_ip} ${port}
resolv-retry infinite
nobind
persist-key
persist-tun

remote-cert-tls server
cipher AES-256-GCM
auth ${DEFAULT_AUTH}
verb 3

<ca>
$(cat "$ca")
</ca>

<cert>
$(openssl x509 -in "$cert")
</cert>

<key>
$(cat "$key")
</key>

<tls-crypt>
$(cat "$ta")
</tls-crypt>
EOF
  chmod 600 "$out"
  ok "Profile written: $out"
}

rebuild_crl_and_restart(){
  detect_pki
  pushd "$EASYRSA_DIR" >/dev/null
  ./easyrsa gen-crl
  install -m 0644 "$PKI_DIR/crl.pem" "/etc/openvpn/server/crl.pem"
  systemctl restart "openvpn-server@${INSTANCE_NAME}" || true
  popd >/dev/null
}

revoke_user(){
  detect_pki
  local cn="$1"
  pushd "$EASYRSA_DIR" >/dev/null
  ./easyrsa revoke "$cn" || true
  popd >/dev/null
  rebuild_crl_and_restart
  ok "Revoked ${cn} and refreshed CRL."
}

remove_user_files(){
  detect_pki
  local cn="$1"
  local removed=0
  local f
  for f in \
    "$PKI_DIR/private/${cn}.key" \
    "$PKI_DIR/issued/${cn}.crt" \
    "$PKI_DIR/reqs/${cn}.req" ; do
    [[ -f "$f" ]] && { rm -f "$f"; removed=1; info "Deleted $f"; }
  done
  # try both output dirs
  local outdir
  for outdir in "${CLIENT_OUT_DIRS[@]}"; do
    [[ -f "${outdir}/${cn}.ovpn" ]] && { rm -f "${outdir}/${cn}.ovpn"; removed=1; info "Deleted ${outdir}/${cn}.ovpn"; }
  done
  [[ "$removed" -eq 1 ]] && ok "Files removed for ${cn}" || warn "No files found for ${cn}"
}

service_status(){
  systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true
}

# ---------------------- TUI ------------------------------
menu(){
  cat <<'MENU'

=========== OpenVPN User Manager ===========
1) Add user (create client cert/key and .ovpn)
2) Revoke user (invalidate cert + refresh CRL)
3) List users (VALID/REVOKED)
4) Remove user files (cert/key/.ovpn)  [optional]
5) Show OpenVPN service status
6) Exit
===========================================
MENU
}

interactive_add(){
  read -r -p "Client name (CN): " CN
  [[ -z "$CN" ]] && { warn "Empty CN"; return; }
  read -r -p "Create encrypted client key? [Y/n]: " yn; yn="${yn:-Y}"
  local mode pass=""
  if [[ "$yn" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
    mode="pass"
    echo "You'll be prompted by Easy-RSA to set the passphrase."
  else
    mode="nopass"
  fi
  make_client "$CN" "$mode" ""
  local rip port proto
  rip="$(detect_public_ip)"
  port="$(get_server_port)"
  proto="$(get_server_proto)"
  read -r -p "Remote IP/DNS for profile [$rip]: " tmp; rip="${tmp:-$rip}"
  read -r -p "Port [$port]: " tmp; port="${tmp:-$port}"
  read -r -p "Proto (udp/tcp) [$proto]: " tmp; proto="${tmp:-$proto}"
  inline_ovpn "$CN" "$rip" "$port" "$proto"
}

interactive_revoke(){
  read -r -p "Client name (CN) to revoke: " CN
  [[ -z "$CN" ]] && { warn "Empty CN"; return; }
  revoke_user "$CN"
  echo
  read -r -p "Also remove this user's files now? [y/N]: " yn
  if [[ "$yn" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
    remove_user_files "$CN"
  else
    info "Files were left on disk. You can remove them later from menu option 4."
  fi
}

interactive_remove_files(){
  read -r -p "Client name (CN) whose files to remove: " CN
  [[ -z "$CN" ]] && { warn "Empty CN"; return; }
  remove_user_files "$CN"
}

# ---------------------- MAIN (interactive) ---------------
need_root

if ! $DAEMON; then
  while true; do
    menu
    read -r -p "Select: " choice
    case "$choice" in
      1) interactive_add; pause ;;
      2) interactive_revoke; pause ;;
      3) list_users; pause ;;
      4) interactive_remove_files; pause ;;
      5) service_status; pause ;;
      6) echo "Bye."; exit 0 ;;
      *) echo "Invalid choice." ;;
    esac
  done
  exit 0
fi

# ---------------------- MAIN (daemon) --------------------
case "$ACTION" in
  add)
    require "--cn" "$CN_FLAG"
    # key mode
    mode="nopass"
    if $NOPASS; then mode="nopass"
    elif [[ -n "$KEY_PASS_FLAG" ]]; then mode="pass"
    else die "Provide either --nopass or --key-pass for daemon add."
    fi
    make_client "$CN_FLAG" "$mode" "${KEY_PASS_FLAG:-}"
    # remote/port/proto fill
    rip="${REMOTE_FLAG:-$(detect_public_ip)}"
    port="${PORT_FLAG:-$(get_server_port)}"
    proto="${PROTO_FLAG:-$(get_server_proto)}"
    inline_ovpn "$CN_FLAG" "$rip" "$port" "$proto"
    ;;
  revoke)
    require "--cn" "$CN_FLAG"
    revoke_user "$CN_FLAG"
    ;;
  remove-files)
    require "--cn" "$CN_FLAG"
    remove_user_files "$CN_FLAG"
    ;;
  list) list_users ;;
  status) service_status ;;
  *) usage; die "Unknown or missing --action" ;;
esac
