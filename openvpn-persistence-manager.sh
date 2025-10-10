#!/usr/bin/env bash
# openvpn-persistence-manager.sh
# Check and enforce (or remove) persistence across reboots for:
#  - OpenVPN autostart (openvpn-server@server)
#  - Unattended server-key unlock (askpass)  [optional]
#  - IPv4 forwarding (sysctl)
#  - NAT & FORWARD iptables rules + persistence
#  - (Optional) UFW 1194/udp rule
#
# Works on Debian/Ubuntu (apt) and RHEL/Rocky/Alma (dnf/yum).
# Run as root.

set -euo pipefail

# ---------------------- Constants ----------------------
INSTANCE_NAME="server"
OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="${OPENVPN_DIR}/server"
SERVER_CONF="${SERVER_DIR}/${INSTANCE_NAME}.conf"
ASKPASS_FILE="${SERVER_DIR}/${INSTANCE_NAME}.pass"
SYSCTL_DROPIN="/etc/sysctl.d/99-openvpn-ipforward.conf"
SYSCTL_CONF="/etc/sysctl.conf"

IPTABLES_RULES_V4="/etc/iptables/rules.v4"
IPTABLES_RULES_V6="/etc/iptables/rules.v6"
IPTABLES_RESTORE_UNIT="/etc/systemd/system/iptables-restore.service"
RHEL_RULES_V4="/etc/sysconfig/iptables"
RHEL_RULES_V6="/etc/sysconfig/ip6tables"

# ---------------------- UI / Colors ---------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok(){   echo -e "${GREEN}[OK]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){  echo -e "${RED}[ERR]${NC} $*" >&2; }
info(){ echo -e "${BLUE}[INFO]${NC} $*"; }

need_root(){ [ "$(id -u)" -eq 0 ] || { err "Run as root"; exit 1; }; }
have(){ command -v "$1" >/dev/null 2>&1; }

state(){ # pretty state label: on/off/na
  case "${1:-}" in
    on)  echo -e "${GREEN}ENABLED${NC}";;
    off) echo -e "${RED}DISABLED${NC}";;
    *)   echo -e "${YELLOW}N/A${NC}";;
  esac
}

press_enter(){ read -r -p "Press Enter to continue..." _; }

# ---------------------- Helpers ------------------------
default_iface(){ ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'; }

mask2cidr(){
  local m=$1 bits=0 x IFS=.
  for x in $m; do
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
  # Read all openvpn server confs and output "x.x.x.x/nn" lines
  local conf net mask bits
  while IFS= read -r -d '' conf; do
    while read -r _ net mask _; do
      bits=$(mask2cidr "$mask" || true)
      [ -n "${bits:-}" ] && echo "${net}/${bits}"
    done < <(awk '/^server[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $0}' "$conf")
  done < <(find "$OPENVPN_DIR" -type f -name "*.conf" -print0 2>/dev/null || true)
}

prompt_yn(){
  local prompt="$1" def="${2:-y}" ans
  read -r -p "$prompt [${def^^}/$([ "$def" = y ] && echo n || echo y)]: " ans
  ans="${ans:-$def}"
  [[ "$ans" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]
}

# ---------------------- DETECTORS -----------------------
det_autostart(){
  systemctl is-enabled "openvpn-server@${INSTANCE_NAME}" >/dev/null 2>&1 && echo on || echo off
}

det_unattended(){
  # Unattended if askpass line present AND file exists (non-empty)
  if [[ -f "$SERVER_CONF" ]] && grep -qE '^\s*askpass\s+' "$SERVER_CONF"; then
    [[ -s "$ASKPASS_FILE" ]] && echo on || echo off
  else
    echo off
  fi
}

det_ip_forward_persist(){
  # persisted if drop-in exists OR sysctl.conf sets 1
  if [[ -f "$SYSCTL_DROPIN" ]] || ( [[ -f "$SYSCTL_CONF" ]] && grep -q '^\s*net\.ipv4\.ip_forward\s*=\s*1' "$SYSCTL_CONF" ); then
    echo on
  else
    echo off
  fi
}

det_nat_rules_present_for(){
  local cidr="$1"
  have iptables || { echo off; return; }
  if iptables -t nat -S POSTROUTING 2>/dev/null | grep -Eq -- "-A POSTROUTING .* -s[[:space:]]+$cidr([[:space:]]|$).* -j[[:space:]]+MASQUERADE"; then
    echo on
  else
    echo off
  fi
}

det_persist_engine(){
  # netfilter-persistent (Deb), iptables-services (RHEL), or systemd restore unit
  if have netfilter-persistent; then echo "netfilter-persistent"; return; fi
  if [[ -f "$RHEL_RULES_V4" || -f "$RHEL_RULES_V6" ]]; then echo "iptables-services"; return; fi
  if [[ -f "$IPTABLES_RESTORE_UNIT" || -f "$IPTABLES_RULES_V4" ]]; then echo "systemd-restore"; return; fi
  echo "none"
}

det_nat_persist(){
  local engine; engine=$(det_persist_engine)
  [[ "$engine" == "none" ]] && { echo off; return; }
  echo on
}

det_ufw_1194(){
  have ufw || { echo off; return; }
  ufw status numbered 2>/dev/null | grep -q '1194/udp' && echo on || echo off
}

# ---------------------- ENFORCERS -----------------------
ensure_autostart(){
  systemctl enable "openvpn-server@${INSTANCE_NAME}" && ok "Enabled autostart for openvpn-server@${INSTANCE_NAME}"
}

remove_autostart(){
  systemctl disable "openvpn-server@${INSTANCE_NAME}" && ok "Disabled autostart for openvpn-server@${INSTANCE_NAME}"
}

ensure_unattended(){
  if [[ ! -f "$SERVER_CONF" ]]; then
    err "Server config not found at $SERVER_CONF"; return 1
  fi
  if ! grep -qE '^\s*askpass\s+' "$SERVER_CONF"; then
    echo "askpass $ASKPASS_FILE" | tee -a "$SERVER_CONF" >/dev/null
  fi
  echo
  echo "Enter the server key passphrase to store in ${ASKPASS_FILE} (will be chmod 600)."
  read -r -s -p "Passphrase: " sp; echo
  [[ -n "$sp" ]] || { err "Empty passphrase; aborting."; return 1; }
  printf '%s\n' "$sp" > "$ASKPASS_FILE"
  chmod 600 "$ASKPASS_FILE"
  ok "Configured unattended start (askpass)."
}

remove_unattended(){
  [[ -f "$SERVER_CONF" ]] && sed -i '/^\s*askpass\s\+/d' "$SERVER_CONF" || true
  rm -f "$ASKPASS_FILE" || true
  ok "Removed unattended start (askpass)."
}

ensure_ip_forward(){
  echo 'net.ipv4.ip_forward=1' > "$SYSCTL_DROPIN"
  sysctl --system >/dev/null 2>&1 || true
  ok "IPv4 forwarding persistence enabled."
}

remove_ip_forward(){
  rm -f "$SYSCTL_DROPIN" || true
  if [[ -f "$SYSCTL_CONF" ]]; then
    sed -i '/^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$/d' "$SYSCTL_CONF" || true
  fi
  sysctl --system >/dev/null 2>&1 || true
  ok "IPv4 forwarding persistence removed."
}

ensure_nat_for(){
  local cidr="$1" wan="$2"
  have iptables || { err "iptables not found"; return 1; }
  [[ -n "$cidr" && -n "$wan" ]] || { err "CIDR or WAN iface missing"; return 1; }

  # Add rules if missing
  iptables -t nat -C POSTROUTING -s "$cidr" -o "$wan" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$cidr" -o "$wan" -j MASQUERADE
  iptables -C FORWARD -s "$cidr" -o "$wan" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "$cidr" -o "$wan" -j ACCEPT
  iptables -C FORWARD -d "$cidr" -m state --state ESTABLISHED,RELATED -i "$wan" -j ACCEPT 2>/dev/null || iptables -A FORWARD -d "$cidr" -m state --state ESTABLISHED,RELATED -i "$wan" -j ACCEPT
  ok "NAT/FORWARD rules ensured for $cidr via $wan"
}

remove_nat_for(){
  local cidr="$1" wan="$2"
  have iptables || return 0
  # Delete if present (any iface if $wan empty)
  if [[ -n "$wan" ]]; then
    iptables -t nat -C POSTROUTING -s "$cidr" -o "$wan" -j MASQUERADE 2>/dev/null && iptables -t nat -D POSTROUTING -s "$cidr" -o "$wan" -j MASQUERADE || true
    iptables -C FORWARD -s "$cidr" -o "$wan" -j ACCEPT 2>/dev/null && iptables -D FORWARD -s "$cidr" -o "$wan" -j ACCEPT || true
    iptables -C FORWARD -d "$cidr" -m state --state ESTABLISHED,RELATED -i "$wan" -j ACCEPT 2>/dev/null && iptables -D FORWARD -d "$cidr" -m state --state ESTABLISHED,RELATED -i "$wan" -j ACCEPT || true
  else
    # try without iface qualifier
    iptables -t nat -S POSTROUTING | grep -E -- "^-A POSTROUTING .* -s[[:space:]]+$cidr([[:space:]]|$).* -j[[:space:]]+MASQUERADE" | sed 's/^-A /-D /' | while read -r l; do iptables -t nat $l || true; done
    iptables -S FORWARD       | grep -E -- "^-A FORWARD .* -s[[:space:]]+$cidr([[:space:]]|$).* -j[[:space:]]+ACCEPT" | sed 's/^-A /-D /' | while read -r l; do iptables $l || true; done
    iptables -S FORWARD       | grep -E -- "^-A FORWARD .* -d[[:space:]]+$cidr([[:space:]]|$).* --state ESTABLISHED,RELATED .* -j[[:space:]]+ACCEPT" | sed 's/^-A /-D /' | while read -r l; do iptables $l || true; done
  fi
  ok "NAT/FORWARD rules removed for $cidr"
}

ensure_nat_persistence(){
  # Prefer netfilter-persistent on Debian/Ubuntu; fallback to systemd unit
  if have netfilter-persistent; then
    netfilter-persistent save || true
    ok "Saved iptables via netfilter-persistent."
    return
  fi
  # RHEL iptables-services
  if systemctl list-unit-files | grep -q '^iptables\.service'; then
    systemctl enable iptables || true
    service iptables save || true
    ok "Saved iptables via iptables-services."
    return
  fi
  # Fallback: systemd restore unit + rules.v4
  mkdir -p /etc/iptables
  have iptables-save && iptables-save > "$IPTABLES_RULES_V4"
  if [[ ! -f "$IPTABLES_RESTORE_UNIT" ]]; then
    cat > "$IPTABLES_RESTORE_UNIT" <<'UNIT'
[Unit]
Description=Restore iptables rules
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable iptables-restore.service
  fi
  ok "Configured iptables persistence via systemd restore unit."
}

remove_nat_persistence(){
  # Try all mechanisms
  if have netfilter-persistent; then
    netfilter-persistent flush || true
    systemctl disable netfilter-persistent 2>/dev/null || true
    systemctl stop netfilter-persistent 2>/dev/null || true
  fi
  if systemctl list-unit-files | grep -q '^iptables\.service'; then
    systemctl disable iptables 2>/dev/null || true
    systemctl stop iptables 2>/dev/null || true
    rm -f "$RHEL_RULES_V4" "$RHEL_RULES_V6" || true
  fi
  if [[ -f "$IPTABLES_RESTORE_UNIT" ]]; then
    systemctl disable iptables-restore.service 2>/dev/null || true
    systemctl stop iptables-restore.service 2>/dev/null || true
    rm -f "$IPTABLES_RESTORE_UNIT" || true
    systemctl daemon-reload || true
  fi
  rm -f "$IPTABLES_RULES_V4" "$IPTABLES_RULES_V6" || true
  rmdir /etc/iptables 2>/dev/null || true
  ok "Removed iptables persistence mechanisms."
}

ensure_ufw_rule(){
  have ufw || { warn "UFW not installed"; return 0; }
  ufw status numbered 2>/dev/null | grep -q '1194/udp' || yes | ufw allow 1194/udp
  ok "Ensured UFW rule 1194/udp."
}

remove_ufw_rule(){
  have ufw || return 0
  ufw status numbered 2>/dev/null | grep -q '1194/udp' && yes | ufw delete allow 1194/udp || true
  ok "Removed UFW rule 1194/udp."
}

# ---------------------- SUMMARY -------------------------
print_summary(){
  echo
  echo "===== Persistence Summary ====="
  echo "OpenVPN autostart     : $(state "$(det_autostart)")"
  echo "Unattended (askpass)  : $(state "$(det_unattended)")"
  echo "IPv4 forwarding persist: $(state "$(det_ip_forward_persist)")"
  local cidrs; cidrs="$(collect_vpn_cidrs | sort -u || true)"
  if [[ -z "$cidrs" ]]; then
    echo "VPN CIDRs (from conf) : (none found, default may be 10.8.0.0/24)"
  else
    echo "VPN CIDRs (from conf) :"
    while read -r c; do
      [[ -z "$c" ]] && continue
      echo "  - $c : NAT $(state "$(det_nat_rules_present_for "$c")")"
    done <<< "$cidrs"
  fi
  echo "iptables persistence  : $(state "$(det_nat_persist)") [$(det_persist_engine)]"
  echo "UFW 1194/udp          : $(state "$(det_ufw_1194)")"
  echo "================================"
  echo
}

# ---------------------- MENU ACTIONS --------------------
ensure_all(){
  # 1) Autostart
  [[ "$(det_autostart)" = on ]] || ensure_autostart

  # 2) Unattended (optional)
  if [[ "$(det_unattended)" = off ]]; then
    if prompt_yn "Configure unattended server-key unlock (askpass) now?" n; then
      ensure_unattended
    else
      warn "Skipping unattended start."
    fi
  fi

  # 3) IPv4 forwarding
  [[ "$(det_ip_forward_persist)" = on ]] || ensure_ip_forward

  # 4) NAT rules per CIDR + persistence
  local cidrs; cidrs="$(collect_vpn_cidrs | sort -u || true)"
  if [[ -z "$cidrs" ]]; then
    if prompt_yn "No VPN CIDR found. Use default 10.8.0.0/24?" y; then
      cidrs="10.8.0.0/24"
    fi
  fi
  local wan; wan="$(default_iface)"; [[ -z "$wan" ]] && wan="eth0"
  for c in $cidrs; do
    [[ "$(det_nat_rules_present_for "$c")" = on ]] || ensure_nat_for "$c" "$wan"
  done
  [[ "$(det_nat_persist)" = on ]] || ensure_nat_persistence

  # 5) UFW rule (optional)
  if [[ "$(det_ufw_1194)" = off ]]; then
    have ufw && prompt_yn "Add UFW rule 1194/udp?" y && ensure_ufw_rule || true
  fi

  ok "All selected persistence items ensured."
}

remove_all(){
  # Ask confirmation
  echo "This will remove IPv4 forwarding persistence, iptables NAT persistence, and optional unattended askpass/autostart."
  prompt_yn "Proceed?" n || { warn "Aborted."; return; }

  # NAT persistence first
  remove_nat_persistence

  # Remove NAT rules for any detected CIDRs
  local cidrs; cidrs="$(collect_vpn_cidrs | sort -u || true)"
  local wan; wan="$(default_iface)"
  for c in $cidrs; do remove_nat_for "$c" "$wan"; done

  # IPv4 forwarding
  [[ "$(det_ip_forward_persist)" = on ]] && remove_ip_forward

  # Unattended askpass (optional)
  [[ "$(det_unattended)" = on ]] && remove_unattended

  # Autostart (optional)
  if [[ "$(det_autostart)" = on ]] && prompt_yn "Disable OpenVPN autostart?" y; then
    remove_autostart
  fi

  # UFW (optional)
  if [[ "$(det_ufw_1194)" = on ]] && prompt_yn "Remove UFW 1194/udp rule?" y; then
    remove_ufw_rule
  fi

  ok "Selected persistence items removed."
}

granular_menu(){
  while true; do
    print_summary
    cat <<MENU
Granular actions:
  1) Enable autostart           2) Disable autostart
  3) Enable unattended askpass  4) Remove unattended askpass
  5) Enable IPv4 forwarding     6) Remove IPv4 forwarding
  7) Ensure NAT+persist         8) Remove NAT+persist
  9) Add UFW 1194/udp          10) Remove UFW 1194/udp
  0) Back
MENU
    read -r -p "Select: " g
    case "$g" in
      1) ensure_autostart;;
      2) remove_autostart;;
      3) ensure_unattended;;
      4) remove_unattended;;
      5) ensure_ip_forward;;
      6) remove_ip_forward;;
      7)
         local cidrs wan
         cidrs="$(collect_vpn_cidrs | sort -u || true)"
         [[ -z "$cidrs" ]] && { read -r -p "Enter VPN CIDR (e.g., 10.8.0.0/24): " cidrs; }
         wan="$(default_iface)"; [[ -z "$wan" ]] && read -r -p "WAN iface (e.g., eth0): " wan
         for c in $cidrs; do ensure_nat_for "$c" "$wan"; done
         ensure_nat_persistence
         ;;
      8)
         local cidrs wan
         cidrs="$(collect_vpn_cidrs | sort -u || true)"
         wan="$(default_iface)"
         for c in $cidrs; do remove_nat_for "$c" "$wan"; done
         remove_nat_persistence
         ;;
      9) ensure_ufw_rule;;
      10) remove_ufw_rule;;
      0) break;;
      *) echo "Invalid choice.";;
    esac
    press_enter
  done
}

# ---------------------- MAIN MENU ----------------------
need_root
while true; do
  print_summary
  cat <<MENU
===== OpenVPN Persistence Manager =====
1) Ensure all persistence items
2) Remove all persistence items
3) Granular actions
4) Exit
MENU
  read -r -p "Select: " choice
  case "$choice" in
    1) ensure_all; press_enter;;
    2) remove_all; press_enter;;
    3) granular_menu;;
    4) echo "Bye."; exit 0;;
    *) echo "Invalid choice.";;
  esac
done
