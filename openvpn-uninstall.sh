#!/usr/bin/env bash
# openvpn-uninstall-manager.sh
# Interactive uninstaller for:
#   1) openvpn-cert-only-setup.sh
#   2) openvpn-cert-pass-installer.sh
#   3) BOTH
#   4) networking-setup.sh  (forwarding, NAT, persistence, autostart)
#
# Supports Debian/Ubuntu (apt) and RHEL/Rocky/Alma (dnf/yum).
set -euo pipefail

# ---------------------- Constants/Paths ----------------------
INSTANCE_NAME="server"  # systemd instance and config filename (server.conf)
OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="$OPENVPN_DIR/server"
EASYRSA_DIR="$OPENVPN_DIR/easy-rsa"
CLIENT_DIR="$OPENVPN_DIR/clients"
LOG_DIR="/var/log/openvpn"
OUTPUT_DIR="/root/openvpn-clients"

ASKPASS_FILE="$SERVER_DIR/${INSTANCE_NAME}.pass"     # Script 2
CRL_FILE="$SERVER_DIR/crl.pem"                       # Script 2
TA_KEY_SCRIPT2="$OPENVPN_DIR/ta.key"                 # Script 2
TMP_SCRIPT1="/var/run/openvpn-tmp"                   # Script 1
TMP_SCRIPT2="$OPENVPN_DIR/tmp"                       # Script 2
POOL_FILE="$SERVER_DIR/ipp.txt"                      # runtime

SYSCTL_DROPIN="/etc/sysctl.d/99-openvpn-ipforward.conf"  # Script 2 / networking-setup.sh
SYSCTL_CONF="/etc/sysctl.conf"

# Persistence paths and services used by networking-setup.sh
IPTABLES_RULES_V4="/etc/iptables/rules.v4"
IPTABLES_RULES_V6="/etc/iptables/rules.v6"
IPTABLES_RESTORE_UNIT="/etc/systemd/system/iptables-restore.service"
RHEL_RULES_V4="/etc/sysconfig/iptables"
RHEL_RULES_V6="/etc/sysconfig/ip6tables"

# ---------------------- Colors/Output -----------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log(){  echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}"; }
info(){ echo -e "${BLUE}[INFO] $*${NC}"; }
warn(){ echo -e "${YELLOW}[WARN] $*${NC}"; }
err(){  echo -e "${RED}[ERROR] $*${NC}" >&2; }

die(){ err "$*"; exit 1; }
need_root(){ [ "$(id -u)" -eq 0 ] || die "Run as root."; }

# ---------------------- Global Options (toggle in UI) -------
PURGE_PACKAGES=false
REMOVE_USER=false
REMOVE_NETWORKING_PKGS=false

# ---------------------- Helpers -----------------------------
prompt_yn(){
  local q="$1" d="${2:-y}" ans
  read -r -p "$q [${d^^}/$([ "$d" = y ] && echo n || echo y)]: " ans
  ans="${ans:-$d}"
  [[ "$ans" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]
}

detect_pkg(){
  if command -v apt-get >/dev/null 2>&1; then PKG="apt"; return; fi
  if command -v dnf      >/dev/null 2>&1; then PKG="dnf"; return; fi
  if command -v yum      >/dev/null 2>&1; then PKG="yum"; return; fi
  PKG=""; warn "No supported package manager detected (apt/dnf/yum)."
}

stop_disable_services(){
  info "Stopping and disabling OpenVPN services..."
  systemctl stop "openvpn-server@${INSTANCE_NAME}" 2>/dev/null || true
  systemctl disable "openvpn-server@${INSTANCE_NAME}" 2>/dev/null || true
  systemctl stop "openvpn@${INSTANCE_NAME}" 2>/dev/null || true
  systemctl disable "openvpn@${INSTANCE_NAME}" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
}

mask2cidr() {
  local x bits=0 IFS=.
  for x in $1; do
    case "$x" in
      255) bits=$((bits+8));;
      254) bits=$((bits+7));;
      252) bits=$((bits+6));;
      248) bits=$((bits+5));;
      240) bits=$((bits+4));;
      224) bits=$((bits+3));;
      192) bits=$((bits+2));;
      128) bits=$((bits+1));;
      0)   bits=$((bits+0));;
      *) return 1;;
    esac
  done
  echo "$bits"
}

collect_vpn_cidrs(){
  # Parse all OpenVPN server confs for "server <net> <mask>" -> net/cidr
  local conf cidr net mask bits
  while IFS= read -r -d '' conf; do
    while read -r _ net mask _; do
      bits=$(mask2cidr "$mask" || true)
      [ -n "${bits:-}" ] && echo "${net}/${bits}"
    done < <(awk '/^server[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $0}' "$conf")
  done < <(find "$OPENVPN_DIR" -type f -name "*.conf" -print0 2>/dev/null || true)
}

default_iface(){
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

# ---------------------- iptables rule cleanup ----------------
delete_rule_line(){
  # Convert "-A CHAIN ..." to "-D CHAIN ..." and delete
  local table="$1" line="$2"
  local del="${line/-A /-D }"
  iptables -t "$table" $del 2>/dev/null || true
}

delete_nat_forward_rules_for_cidr(){
  local cidr="$1"
  have_cmd iptables || { warn "iptables not found; skipping live rule cleanup for $cidr"; return; }

  info "Removing iptables rules for VPN CIDR: $cidr"

  # nat POSTROUTING MASQUERADE for this cidr (any iface)
  while IFS= read -r line; do
    delete_rule_line "nat" "$line"
  done < <(iptables -t nat -S POSTROUTING | grep -E -- "^-A POSTROUTING .* -s[[:space:]]+$cidr([[:space:]]|$).* -j[[:space:]]+MASQUERADE" || true)

  # FORWARD allow rules for this cidr (src -> any iface)
  while IFS= read -r line; do
    delete_rule_line "filter" "$line"
  done < <(iptables -S FORWARD | grep -E -- "^-A FORWARD .* -s[[:space:]]+$cidr([[:space:]]|$).* -j[[:space:]]+ACCEPT" || true)

  # FORWARD established back to this cidr (WAN -> VPN)
  while IFS= read -r line; do
    delete_rule_line "filter" "$line"
  done < <(iptables -S FORWARD | grep -E -- "^-A FORWARD .* -d[[:space:]]+$cidr([[:space:]]|$).* -m state --state ESTABLISHED,RELATED .* -j[[:space:]]+ACCEPT" || true)
}

prompt_delete_remaining_masq(){
  have_cmd iptables || return 0
  echo
  echo "Remaining MASQUERADE rules (if any):"
  iptables -t nat -S POSTROUTING | grep -E "^-A POSTROUTING .* -j[[:space:]]+MASQUERADE" || echo "(none)"
  echo
  if prompt_yn "Delete ALL remaining MASQUERADE rules? (SAFE only if this host is NATing exclusively for OpenVPN)" n; then
    while IFS= read -r line; do
      delete_rule_line "nat" "$line"
    done < <(iptables -t nat -S POSTROUTING | grep -E "^-A POSTROUTING .* -j[[:space:]]+MASQUERADE" || true)
  fi
}

# ---------------------- Persistence & sysctl cleanup --------
revert_sysctl_ipfwd(){
  info "Reverting IPv4 forwarding configuration..."
  rm -f "$SYSCTL_DROPIN" 2>/dev/null || true
  # Remove explicit "net.ipv4.ip_forward=1" line if present
  if [ -f "$SYSCTL_CONF" ]; then
    sed -i.bak '/^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$/d' "$SYSCTL_CONF" 2>/dev/null || true
  fi
  sysctl --system >/dev/null 2>&1 || true
}

remove_network_persistence(){
  log "Removing firewall persistence and helper units..."
  # netfilter-persistent
  if have_cmd netfilter-persistent; then
    netfilter-persistent flush 2>/dev/null || true
    systemctl disable netfilter-persistent 2>/dev/null || true
    systemctl stop netfilter-persistent 2>/dev/null || true
  fi

  # iptables-restore custom unit
  if [ -f "$IPTABLES_RESTORE_UNIT" ]; then
    systemctl stop iptables-restore.service 2>/dev/null || true
    systemctl disable iptables-restore.service 2>/dev/null || true
    rm -f "$IPTABLES_RESTORE_UNIT" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  fi

  # rules files (Debian-style)
  rm -f "$IPTABLES_RULES_V4" "$IPTABLES_RULES_V6" 2>/dev/null || true
  rmdir /etc/iptables 2>/dev/null || true

  # RHEL iptables-services files
  if [ -f "$RHEL_RULES_V4" ] || [ -f "$RHEL_RULES_V6" ]; then
    systemctl stop iptables 2>/dev/null || true
    systemctl disable iptables 2>/dev/null || true
    rm -f "$RHEL_RULES_V4" "$RHEL_RULES_V6" 2>/dev/null || true
  fi

  # UFW OpenVPN rule (best-effort)
  if have_cmd ufw; then
    ufw status numbered 2>/dev/null | grep -q '1194/udp' && yes | ufw delete allow 1194/udp || true
  fi
}

purge_packages_if_requested(){
  $PURGE_PACKAGES || { info "Package purge: SKIPPED"; return; }
  log "Purging OpenVPN-related packages..."
  systemctl stop openvpn 2>/dev/null || true

  detect_pkg
  case "$PKG" in
    apt)
      apt-get purge -y openvpn easy-rsa libpam-google-authenticator 2>/dev/null || true
      $REMOVE_NETWORKING_PKGS && apt-get purge -y iptables-persistent netfilter-persistent 2>/dev/null || true
      apt-get autoremove -y 2>/dev/null || true
      apt-get update -y 2>/dev/null || true
      ;;
    dnf)
      dnf remove -y openvpn easy-rsa || true
      $REMOVE_NETWORKING_PKGS && dnf remove -y iptables-services || true
      ;;
    yum)
      yum remove -y openvpn easy-rsa || true
      $REMOVE_NETWORKING_PKGS && yum remove -y iptables-services || true
      ;;
    *)
      warn "No supported package manager found for purge."
      ;;
  esac
}

remove_user_if_requested(){
  $REMOVE_USER || { info "User removal: SKIPPED"; return; }
  if id -u openvpn >/dev/null 2>&1; then
    info "Removing user 'openvpn'..."
    userdel -r openvpn 2>/dev/null || true
  fi
  if getent group openvpn >/dev/null 2>&1; then
    info "Removing group 'openvpn'..."
    groupdel openvpn 2>/dev/null || true
  fi
}

# ---------------------- OpenVPN footprints ------------------
remove_common_files(){
  info "Removing common OpenVPN files and directories..."
  rm -f "$OPENVPN_DIR/${INSTANCE_NAME}.conf" 2>/dev/null || true
  rm -f "$SERVER_DIR/${INSTANCE_NAME}.conf" 2>/dev/null || true
  rm -f "$POOL_FILE" 2>/dev/null || true
  rm -rf "$EASYRSA_DIR" 2>/dev/null || true
  rm -rf "$CLIENT_DIR" "$LOG_DIR" "$TMP_SCRIPT1" 2>/dev/null || true
  rmdir "$SERVER_DIR" 2>/dev/null || true
  rmdir "$OPENVPN_DIR" 2>/dev/null || true
}

remove_script1_footprint(){
  log "Removing artifacts from: openvpn-cert-only-setup.sh"
  rm -rf "$TMP_SCRIPT1" 2>/dev/null || true
  remove_common_files
}

remove_script2_footprint(){
  log "Removing artifacts from: openvpn-cert-pass-installer.sh"
  rm -f "$ASKPASS_FILE" "$CRL_FILE" "$TA_KEY_SCRIPT2" 2>/dev/null || true
  rm -rf "$TMP_SCRIPT2" 2>/dev/null || true
  remove_common_files
  revert_sysctl_ipfwd
}

# ---------------------- networking-setup.sh removal ---------
remove_networking_setup(){
  log "Removing artifacts from: networking-setup.sh"

  # 1) Revert sysctl ip_forward & drop-ins
  revert_sysctl_ipfwd

  # 2) Derive known VPN CIDRs from any server.conf found and delete their rules
  declare -A seen=()
  while read -r cidr; do
    [ -n "$cidr" ] || continue
    [[ -n "${seen[$cidr]:-}" ]] && continue
    seen["$cidr"]=1
    delete_nat_forward_rules_for_cidr "$cidr"
  done < <(collect_vpn_cidrs || true)

  # 3) Offer to delete any remaining MASQUERADE rules (covers custom CIDRs added via "Add new route")
  prompt_delete_remaining_masq

  # 4) Remove persistence (netfilter-persistent, iptables-restore.service, iptables-services files)
  remove_network_persistence

  # 5) Ensure OpenVPN autostart is not forced by networking script
  systemctl disable "openvpn-server@${INSTANCE_NAME}" 2>/dev/null || true
}

# ---------------------- Detection --------------------------
detect_install_type(){
  # Returns one of: "script1" "script2" "both" "networking" "unknown"
  local s1 s2 net
  [ -d "$TMP_SCRIPT1" ] && s1=1
  [ -f "$ASKPASS_FILE" ] && s2=1
  [ -f "$TA_KEY_SCRIPT2" ] && s2=1
  [ -f "$SYSCTL_DROPIN" ] && net=1
  [ -f "$IPTABLES_RESTORE_UNIT" ] && net=1
  [ -f "$RHEL_RULES_V4" ] && net=1
  [ -f "$IPTABLES_RULES_V4" ] && net=1

  if [[ "$s1" == "1" && "$s2" == "1" ]]; then echo "both"; return; fi
  if [[ "$s1" == "1" ]]; then echo "script1"; return; fi
  if [[ "$s2" == "1" ]]; then echo "script2"; return; fi
  if [[ "$net" == "1" ]]; then echo "networking"; return; fi

  # Fallback to config hints
  if [ -f "$SERVER_DIR/${INSTANCE_NAME}.conf" ]; then
    if grep -qE '^\s*askpass\s+' "$SERVER_DIR/${INSTANCE_NAME}.conf" 2>/dev/null; then
      echo "script2"; return
    fi
    if grep -qE '^\s*tmp-dir\s+/var/run/openvpn-tmp' "$SERVER_DIR/${INSTANCE_NAME}.conf" 2>/dev/null; then
      echo "script1"; return
    fi
  fi
  echo "unknown"
}

# ---------------------- UI -------------------------------
show_header(){
  echo
  echo "===== OpenVPN Uninstall Manager ====="
  echo
  echo "1) Uninstall 'openvpn-cert-only-setup.sh' (Cert-only, no networking)"
  echo "2) Uninstall 'openvpn-cert-pass-installer.sh' (Cert + passphrase, IP forwarding)"
  echo "3) Uninstall BOTH"
  echo "4) Uninstall 'networking-setup.sh' (forwarding, NAT, persistence)"
  echo "5) Toggle options"
  echo "6) Detect and suggest"
  echo "7) Exit"
  echo
  echo "Options: purge-packages=${PURGE_PACKAGES}, remove-user=${REMOVE_USER}, purge-networking-pkgs=${REMOVE_NETWORKING_PKGS}"
  echo
}

toggle_options_menu(){
  while true; do
    echo
    echo "----- Toggle Options -----"
    echo "1) Toggle purge OpenVPN packages       (current: $PURGE_PACKAGES)"
    echo "2) Toggle remove 'openvpn' user        (current: $REMOVE_USER)"
    echo "3) Toggle purge networking packages    (current: $REMOVE_NETWORKING_PKGS)"
    echo "4) Back"
    read -r -p "Select: " o
    case "$o" in
      1) PURGE_PACKAGES=$([ "$PURGE_PACKAGES" = true ] && echo false || echo true) ;;
      2) REMOVE_USER=$([ "$REMOVE_USER" = true ] && echo false || echo true) ;;
      3) REMOVE_NETWORKING_PKGS=$([ "$REMOVE_NETWORKING_PKGS" = true ] && echo false || echo true) ;;
      4) break ;;
      *) echo "Invalid choice." ;;
    esac
  done
}

confirm_and_run(){
  read -r -p "Type YES to confirm uninstall: " c
  [[ "$c" == "YES" ]] || { echo "Cancelled."; return; }

  stop_disable_services

  case "$1" in
    script1)
      remove_script1_footprint
      ;;
    script2)
      remove_script2_footprint
      ;;
    both)
      remove_script2_footprint
      remove_script1_footprint
      ;;
    networking)
      remove_networking_setup
      ;;
    *)
      warn "Unknown selection; no action."
      ;;
  esac

  purge_packages_if_requested
  remove_user_if_requested

  log "Uninstall task completed."
}

# ---------------------- Main Loop -------------------------
need_root
while true; do
  show_header
  read -r -p "Select: " choice
  case "$choice" in
    1)
      echo; echo "You chose: Uninstall 'openvpn-cert-only-setup.sh'"
      confirm_and_run "script1"
      ;;
    2)
      echo; echo "You chose: Uninstall 'openvpn-cert-pass-installer.sh'"
      confirm_and_run "script2"
      ;;
    3)
      echo; echo "You chose: Uninstall BOTH"
      confirm_and_run "both"
      ;;
    4)
      echo; echo "You chose: Uninstall 'networking-setup.sh'"
      confirm_and_run "networking"
      ;;
    5)
      toggle_options_menu
      ;;
    6)
      det="$(detect_install_type)"
      echo; echo "Detection result: $det"
      case "$det" in
        script1) echo "Suggestion: choose option 1";;
        script2) echo "Suggestion: choose option 2";;
        both)    echo "Suggestion: choose option 3";;
        networking) echo "Suggestion: choose option 4";;
        *)       echo "No clear fingerprint found. Choose the option(s) you know were used, or run BOTH + NETWORKING.";;

      esac
      ;;
    7)
      echo "Bye."
      exit 0
      ;;
    *)
      echo "Invalid choice."
      ;;
  esac
done
