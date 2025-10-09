#!/usr/bin/env bash
# networking-setup.sh
# Network-only helper for OpenVPN: forwarding, NAT, persistence, autostart, and config inspection.
# Works on Ubuntu/Debian and RHEL-like systems. Requires root.

set -euo pipefail

INSTANCE_NAME="server"                              # fixed OpenVPN instance
SERVER_CONF="/etc/openvpn/server/${INSTANCE_NAME}.conf"

die(){ echo "ERROR: $*" >&2; exit 1; }
need_root(){ [ "$(id -u)" -eq 0 ] || die "Run as root."; }
has_cmd(){ command -v "$1" >/dev/null 2>&1; }

mask2cidr() {
  local x bits=0 IFS=.
  for x in $1; do
    case $x in
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
  has_cmd ip && ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

detect_vpn_cidr_from_conf() {
  local conf="$1"
  if [[ -f "$conf" ]]; then
    local line; line=$(awk '/^server[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print; exit}' "$conf")
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
  if ! iptabl
