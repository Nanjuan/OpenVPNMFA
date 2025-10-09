#!/usr/bin/env bash
# openvpn-uninstall-manager.sh
# Interactive uninstaller for:
#   1) openvpn-cert-only-setup.sh   (Certificate-only, NO networking changes)
#   2) openvpn-cert-pass-installer.sh (Certificate + passphrase keys, enables IP forwarding)
#
# Supports Debian/Ubuntu (apt) and RHEL/Rocky/Alma (dnf/yum).
# Provides options to purge packages, remove the 'openvpn' user, and clean networking persistence.
set -euo pipefail

# ---------------------- Constants/Paths ----------------------
INSTANCE_NAME="server"  # systemd instance and config filename
OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="$OPENVPN_DIR/server"
EASYRSA_DIR="$OPENVPN_DIR/easy-rsa"
CLIENT_DIR="$OPENVPN_DIR/clients"
LOG_DIR="/var/log/openvpn"
OUTPUT_DIR="/root/openvpn-clients"

ASKPASS_FILE="$SERVER_DIR/${INSTANCE_NAME}.pass"     # Script: openvpn-cert-pass-installer.sh
CRL_FILE="$SERVER_DIR/crl.pem"                       # Installed by Script 2
TA_KEY_SCRIPT2="$OPENVPN_DIR/ta.key"                 # Script 2 location
TMP_SCRIPT1="/var/run/openvpn-tmp"                   # Script 1 tmp dir
TMP_SCRIPT2="$OPENVPN_DIR/tmp"                       # Script 2 tmp dir
POOL_FILE="$SERVER_DIR/ipp.txt"                      # Created by OpenVPN at runtime

SYSCTL_DROPIN="/etc/sysctl.d/99-openvpn-ipforward.conf"  # Script 2
SYSCTL_CONF="/etc/sysctl.conf"

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
REMOVE_NETWORKING=false

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

# ---------------------- Removal Blocks ----------------------
remove_common_files(){
  info "Removing common OpenVPN files and directories..."
  # Server configs (either location/style)
  rm -f "$OPENVPN_DIR/${INSTANCE_NAME}.conf" 2>/dev/null || true
  rm -f "$SERVER_DIR/${INSTANCE_NAME}.conf" 2>/dev/null || true
  rm -f "$POOL_FILE" 2>/dev/null || true

  # PKI (covers Script 1 ta.key inside pki)
  rm -rf "$EASYRSA_DIR" 2>/dev/null || true

  # Clients, logs, tmp dirs
  rm -rf "$CLIENT_DIR" "$LOG_DIR" "$TMP_SCRIPT1" 2>/dev/null || true
  # try to remove empty server dir afterward
  rmdir "$SERVER_DIR" 2>/dev/null || true
  rmdir "$OPENVPN_DIR" 2>/dev/null || true
}

remove_script1_footprint(){
  log "Removing artifacts from: openvpn-cert-only-setup.sh"
  # Specific tmp dir used by Script 1
  rm -rf "$TMP_SCRIPT1" 2>/dev/null || true
  # Common bits
  remove_common_files
}

remove_script2_footprint(){
  log "Removing artifacts from: openvpn-cert-pass-installer.sh"
  # Askpass + CRL + Script 2 TA key + tmp dir
  rm -f "$ASKPASS_FILE" 2>/dev/null || true
  rm -f "$CRL_FILE" 2>/dev/null || true
  rm -f "$TA_KEY_SCRIPT2" 2>/dev/null || true
  rm -rf "$TMP_SCRIPT2" 2>/dev/null || true
  # Common bits
  remove_common_files
  # Revert IP forwarding changes
  info "Reverting IP forwarding configuration (Script 2)..."
  rm -f "$SYSCTL_DROPIN" 2>/dev/null || true
  if [ -f "$SYSCTL_CONF" ]; then
    sed -i.bak '/^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$/d' "$SYSCTL_CONF" 2>/dev/null || true
  fi
  sysctl --system >/dev/null 2>&1 || true
}

remove_networking_persistence(){
  log "Removing networking persistence (if present)..."
  # UFW rule for OpenVPN
  if command -v ufw >/dev/null 2>&1; then
    ufw status numbered 2>/dev/null | grep -q '1194/udp' && yes | ufw delete allow 1194/udp || true
  fi
  # iptables persistence service/files
  rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 2>/dev/null || true
  if [ -f /etc/systemd/system/iptables-restore.service ]; then
    systemctl stop iptables-restore.service 2>/dev/null || true
    systemctl disable iptables-restore.service 2>/dev/null || true
    rm -f /etc/systemd/system/iptables-restore.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  fi
  rmdir /etc/iptables 2>/dev/null || true
}

purge_packages_if_requested(){
  $PURGE_PACKAGES || { info "Package purge: SKIPPED"; return; }
  log "Purging OpenVPN-related packages..."
  systemctl stop openvpn 2>/dev/null || true

  detect_pkg
  case "$PKG" in
    apt)
      apt-get purge -y openvpn easy-rsa libpam-google-authenticator 2>/dev/null || true
      $REMOVE_NETWORKING && apt-get purge -y iptables-persistent netfilter-persistent 2>/dev/null || true
      apt-get autoremove -y 2>/dev/null || true
      apt-get update -y 2>/dev/null || true
      ;;
    dnf)
      dnf remove -y openvpn easy-rsa || true
      ;;
    yum)
      yum remove -y openvpn easy-rsa || true
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

# ---------------------- Detection --------------------------
detect_install_type(){
  # Returns one of: "script1" "script2" "both" "unknown"
  local s1 s2
  # Script 1 signals
  [ -d "$TMP_SCRIPT1" ] && s1=1
  # Script 2 signals
  [ -f "$ASKPASS_FILE" ] && s2=1
  [ -f "$TA_KEY_SCRIPT2" ] && s2=1
  [ -f "$SYSCTL_DROPIN" ] && s2=1
  [ -d "$TMP_SCRIPT2" ] && s2=1

  if [[ "$s1" == "1" && "$s2" == "1" ]]; then echo "both"; return; fi
  if [[ "$s1" == "1" ]]; then echo "script1"; return; fi
  if [[ "$s2" == "1" ]]; then echo "script2"; return; fi

  # If nothing obvious, try to guess from server.conf contents
  if [ -f "$SERVER_DIR/${INSTANCE_NAME}.conf" ]; then
    if grep -qE '^\s*askpass\s+' "$SERVER_DIR/${INSTANCE_NAME}.conf" 2>/dev/null; then
      echo "script2"; return
    fi
    # Script 1 set tmp-dir /var/run/openvpn-tmp
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
  echo "3) Uninstall BOTH (safe superset)"
  echo "4) Toggle options"
  echo "5) Detect and suggest"
  echo "6) Exit"
  echo
  echo "Options: purge-packages=${PURGE_PACKAGES}, remove-user=${REMOVE_USER}, remove-networking=${REMOVE_NETWORKING}"
  echo
}

toggle_options_menu(){
  while true; do
    echo
    echo "----- Toggle Options -----"
    echo "1) Toggle purge packages        (current: $PURGE_PACKAGES)"
    echo "2) Toggle remove 'openvpn' user (current: $REMOVE_USER)"
    echo "3) Toggle remove networking     (current: $REMOVE_NETWORKING)"
    echo "4) Back"
    read -r -p "Select: " o
    case "$o" in
      1) PURGE_PACKAGES=$([ "$PURGE_PACKAGES" = true ] && echo false || echo true) ;;
      2) REMOVE_USER=$([ "$REMOVE_USER" = true ] && echo false || echo true) ;;
      3) REMOVE_NETWORKING=$([ "$REMOVE_NETWORKING" = true ] && echo false || echo true) ;;
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
      # Run Script 2 first (reverts sysctl), then Script 1 cleanup and common
      remove_script2_footprint
      remove_script1_footprint
      ;;
    *)
      warn "Unknown selection; performing conservative BOTH removal."
      remove_script2_footprint
      remove_script1_footprint
      ;;
  esac

  $REMOVE_NETWORKING && remove_networking_persistence
  purge_packages_if_requested
  remove_user_if_requested

  log "OpenVPN uninstall completed."
}

# ---------------------- Main Loop -------------------------
need_root
while true; do
  show_header
  read -r -p "Select: " choice
  case "$choice" in
    1)
      echo
      echo "You chose: Uninstall 'openvpn-cert-only-setup.sh'"
      confirm_and_run "script1"
      ;;
    2)
      echo
      echo "You chose: Uninstall 'openvpn-cert-pass-installer.sh'"
      confirm_and_run "script2"
      ;;
    3)
      echo
      echo "You chose: Uninstall BOTH"
      confirm_and_run "both"
      ;;
    4)
      toggle_options_menu
      ;;
    5)
      det="$(detect_install_type)"
      echo
      echo "Detection result: $det"
      case "$det" in
        script1) echo "Suggestion: choose option 1";;
        script2) echo "Suggestion: choose option 2";;
        both)    echo "Suggestion: choose option 3";;
        *)       echo "No clear fingerprint found. If unsure, choose option 3 (BOTH).";;
      esac
      ;;
    6)
      echo "Bye."
      exit 0
      ;;
    *)
      echo "Invalid choice."
      ;;
  esac
done
