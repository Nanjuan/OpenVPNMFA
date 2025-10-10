#!/usr/bin/env bash
# networking-setup.sh
# Network-only helper for OpenVPN: forwarding, NAT, persistence, autostart, and config inspection.
# Works on Ubuntu/Debian and RHEL-like systems. Requires root.
#
# Author: Nestor Torres
# Created: October 2025
# Version: 1

set -euo pipefail

INSTANCE_NAME="server"                              # fixed OpenVPN instance
SERVER_CONF="/etc/openvpn/server/${INSTANCE_NAME}.conf"

die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "$(id -u)" -eq 0 ] || die "Run as root."; }
has_cmd(){ command -v "$1" >/dev/null 2>&1; }

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
      *) die "Invalid netmask: $1";;
    esac
  done
  echo "$bits"
}

detect_public_iface() {
  if has_cmd ip; then
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
  fi
}

detect_vpn_cidr_from_conf() {
  local conf="$1"
  if [[ -f "$conf" ]]; then
    local line
    line=$(awk '/^server[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print; exit}' "$conf")
    if [[ -n "$line" ]]; then
      local _ net mask
      read -r _ net mask <<<"$line"
      echo "${net}/$(mask2cidr "$mask")"
      return
    fi
  fi
  echo ""
}

enable_ip_forward() {
  echo "[*] Enabling IPv4 forwarding..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  mkdir -p /etc/sysctl.d
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-openvpn-ipforward.conf
  sysctl --system >/dev/null 2>&1 || true
}

ensure_persist_tools() {
  if has_cmd apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent || true
  elif has_cmd dnf; then
    dnf install -y iptables-services || true
  elif has_cmd yum; then
    yum install -y iptables-services || true
  fi
}

add_nat_rules() {
  local vpn_cidr="$1" wan="$2"

  [[ -z "$wan" ]] && die "No public interface detected/provided."
  [[ -z "$vpn_cidr" ]] && die "No VPN CIDR provided."

  echo "[*] Applying iptables rules: VPN ${vpn_cidr} -> WAN ${wan}"

  # NAT (POSTROUTING)
  if ! iptables -t nat -C POSTROUTING -s "$vpn_cidr" -o "$wan" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$vpn_cidr" -o "$wan" -j MASQUERADE
  fi

  # FORWARD allow from VPN to WAN
  if ! iptables -C FORWARD -s "$vpn_cidr" -o "$wan" -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -s "$vpn_cidr" -o "$wan" -j ACCEPT
  fi

  # FORWARD allow established back from WAN to VPN
  if ! iptables -C FORWARD -d "$vpn_cidr" -m state --state ESTABLISHED,RELATED -i "$wan" -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -d "$vpn_cidr" -m state --state ESTABLISHED,RELATED -i "$wan" -j ACCEPT
  fi
}

persist_rules() {
  echo "[*] Persisting firewall rules..."
  if has_cmd netfilter-persistent; then
    netfilter-persistent save || true
    echo "[*] Saved with netfilter-persistent."
    return
  fi
  if has_cmd service && service iptables save >/dev/null 2>&1; then
    service iptables save
    echo "[*] Saved with iptables-services."
    return
  fi
  # Fallback: write rules.v4 and auto-restore at boot
  mkdir -p /etc/iptables
  if has_cmd iptables-save; then
    iptables-save > /etc/iptables/rules.v4
    if [[ ! -f /etc/systemd/system/iptables-restore.service ]]; then
      cat >/etc/systemd/system/iptables-restore.service <<'UNIT'
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
    echo "[*] Saved to /etc/iptables/rules.v4 and enabled restore service."
  else
    echo "[!] iptables-save not found; rules may not persist on reboot."
  fi
}

configure_autostart() {
  echo "[*] Enabling OpenVPN autostart for '${INSTANCE_NAME}'..."
  systemctl enable "openvpn-server@${INSTANCE_NAME}"
  echo "[*] Done. It will start automatically on reboot."
}

full_network_setup() {
  echo ">>> Full NETWORK setup selected."
  enable_ip_forward
  ensure_persist_tools

  local vpn_cidr; vpn_cidr="$(detect_vpn_cidr_from_conf "$SERVER_CONF")"
  [[ -z "$vpn_cidr" ]] && vpn_cidr="10.8.0.0/24"

  local wan; wan="$(detect_public_iface)"
  [[ -z "$wan" ]] && wan="eth0"

  echo "[*] Detected VPN subnet: $vpn_cidr"
  echo "[*] Detected WAN iface : $wan"

  add_nat_rules "$vpn_cidr" "$wan"
  persist_rules

  echo
  echo "==== Network setup complete ===="
  echo "VPN subnet : $vpn_cidr"
  echo "WAN iface  : $wan"
  echo "Test from a VPN client: ping 8.8.8.8 ; curl ifconfig.me"
  echo
}

add_new_route() {
  enable_ip_forward
  ensure_persist_tools

  local default_vpn_cidr; default_vpn_cidr="$(detect_vpn_cidr_from_conf "$SERVER_CONF")"
  [[ -z "$default_vpn_cidr" ]] && default_vpn_cidr="10.8.0.0/24"

  local default_iface; default_iface="$(detect_public_iface)"
  [[ -z "$default_iface" ]] && default_iface="eth0"

  read -r -p "VPN subnet in CIDR (e.g., 10.8.0.0/24) [$default_vpn_cidr]: " VPN_CIDR
  VPN_CIDR="${VPN_CIDR:-$default_vpn_cidr}"

  read -r -p "Public (WAN) interface [$default_iface]: " WAN_IFACE
  WAN_IFACE="${WAN_IFACE:-$default_iface}"

  add_nat_rules "$VPN_CIDR" "$WAN_IFACE"
  persist_rules

  echo
  echo "==== Route added and persisted ===="
  echo "VPN subnet : $VPN_CIDR"
  echo "WAN iface  : $WAN_IFACE"
  echo "Test from a VPN client: ping 8.8.8.8 ; curl ifconfig.me"
  echo
}

show_status() {
  echo "OpenVPN service status:"
  systemctl --no-pager --full status "openvpn-server@${INSTANCE_NAME}" || true
}

show_current_config() {
  echo "========== Current Network Configuration =========="
  # IPv4 forwarding (live)
  local fwd_live; fwd_live="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "n/a")"
  # IPv4 forwarding (persisted)
  local fwd_persist="not found"
  if grep -Rqs '^\s*net\.ipv4\.ip_forward\s*=\s*1' /etc/sysctl.d /etc/sysctl.conf 2>/dev/null; then
    fwd_persist="1 (persisted)"
  fi
  echo "IPv4 forwarding (live): ${fwd_live}"
  echo "IPv4 forwarding (persist): ${fwd_persist}"

  # WAN interface & IP
  local wan; wan="$(detect_public_iface)"
  local wan_ip="n/a"
  if [[ -n "${wan}" && -n "$(command -v ip || true)" ]]; then
    wan_ip="$(ip -4 -o addr show dev "$wan" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd, -)"
  fi
  echo "WAN interface         : ${wan:-<none>}"
  echo "WAN IPv4 address(es)  : ${wan_ip}"

  # VPN subnet
  local vpn_cidr; vpn_cidr="$(detect_vpn_cidr_from_conf "$SERVER_CONF")"
  [[ -z "$vpn_cidr" ]] && vpn_cidr="(not found; default may be 10.8.0.0/24)"
  echo "VPN subnet (from conf): ${vpn_cidr}"

  # iptables rules relevant to VPN
  echo
  echo "--- iptables NAT (POSTROUTING) MASQUERADE matching VPN ---"
  if has_cmd iptables; then
    if [[ "$vpn_cidr" == \(not* ]] || [[ -z "$vpn_cidr" ]]; then
      iptables -t nat -S POSTROUTING | sed 's/^/- /'
    else
      iptables -t nat -S POSTROUTING | awk -v v="$vpn_cidr" '/^-A POSTROUTING/ {print}' | sed 's/^/- /'
      if ! iptables -t nat -S POSTROUTING | awk -v v="$vpn_cidr" '/^-A POSTROUTING/ {print}' | grep -q .; then
        echo "(no exact match for ${vpn_cidr}; full table below)"
        iptables -t nat -S POSTROUTING | sed 's/^/  /'
      fi
    fi
  else
    echo "(iptables not found)"
  fi

  echo
  echo "--- iptables FORWARD rules relevant to VPN ---"
  if has_cmd iptables; then
    if [[ "$vpn_cidr" == \(not* ]] || [[ -z "$vpn_cidr" ]]; then
      iptables -S FORWARD | sed 's/^/- /'
    else
      iptables -S FORWARD | awk -v v="$vpn_cidr" '
        /-A FORWARD/ && ($0 ~ v || $0 ~ "ESTABLISHED,RELATED") {print}
      ' | sed 's/^/- /'
      if ! iptables -S FORWARD | awk -v v="$vpn_cidr" '/-A FORWARD/ && ($0 ~ v || $0 ~ "ESTABLISHED,RELATED") {found=1} END{exit !found}'; then
        echo "(no VPN-specific FORWARD rules found; full chain below)"
        iptables -S FORWARD | sed 's/^/  /'
      fi
    fi
  else
    echo "(iptables not found)"
  fi

  # Persistence tools status
  echo
  echo "--- Persistence & Services ---"
  if has_cmd netfilter-persistent; then
    if systemctl is-enabled netfilter-persistent >/dev/null 2>&1; then
      echo "netfilter-persistent: enabled"
    else
      echo "netfilter-persistent: installed (not enabled)"
    fi
  fi
  if has_cmd service && service iptables status >/dev/null 2>&1; then
    echo "iptables-services     : installed"
  fi
  if [[ -f /etc/systemd/system/iptables-restore.service ]]; then
    if systemctl is-enabled iptables-restore.service >/dev/null 2>&1; then
      echo "iptables-restore unit : enabled"
    else
      echo "iptables-restore unit : present (not enabled)"
    fi
  fi
  if systemctl is-enabled "openvpn-server@${INSTANCE_NAME}" >/dev/null 2>&1; then
    echo "OpenVPN autostart     : enabled"
  else
    echo "OpenVPN autostart     : not enabled"
  fi

  echo "=========================================================="
  echo
}

menu() {
  cat <<'MENU'

============= OpenVPN Networking Menu =============
1) Full network setup (forwarding + NAT + persist)
2) Add new route (additional VPN CIDR / WAN iface)
3) Enable OpenVPN autostart on reboot
4) Show OpenVPN service status
5) Show current network configuration
6) Exit
===================================================
MENU
}

# -------------------- Main --------------------
need_root
while true; do
  menu
  read -r -p "Select: " choice
  case "$choice" in
    1) full_network_setup ;;
    2) add_new_route ;;
    3) configure_autostart ;;
    4) show_status ;;
    5) show_current_config ;;
    6) echo "Bye."; exit 0 ;;
    *) echo "Invalid choice." ;;
  esac
done
