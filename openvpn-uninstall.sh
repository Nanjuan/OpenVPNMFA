#!/bin/bash

# OpenVPN Uninstall Script for v2 Installation
# Safely reverts changes made by openvpn-server-setup-v2.sh
# Supports config-only removal (default) and full package purge with --purge-packages

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
err() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root"
        exit 1
    fi
}

# Defaults
PURGE_PACKAGES=false
REMOVE_USER=false
DRY_RUN=false

OPENVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="/etc/openvpn/clients"
LOG_DIR="/var/log/openvpn"
BACKUP_DIR="/etc/openvpn/backup"
SCRIPT_DIR="/usr/local/bin"
SERVER_NAME="server"
VPN_NETWORK="10.8.0.0/24"

DEFAULT_IFACE() {
    ip route | awk '/^default/ {print $5; exit}' || true
}

delete_iptables_rule() {
    local iface="$1"
    # Delete MASQUERADE rule if it exists; ignore errors if not present
    iptables -t nat -C POSTROUTING -s "$VPN_NETWORK" -o "$iface" -j MASQUERADE 2>/dev/null && \
        iptables -t nat -D POSTROUTING -s "$VPN_NETWORK" -o "$iface" -j MASQUERADE || true
}

restore_sysctl() {
    # Remove the exact line added by installer; don't break other content
    if grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf 2>/dev/null; then
        sed -i.bak '/^net.ipv4.ip_forward=1$/d' /etc/sysctl.conf || true
        sysctl -p >/dev/null 2>&1 || true
        log "Reverted net.ipv4.ip_forward=1 in /etc/sysctl.conf"
    else
        info "No explicit net.ipv4.ip_forward=1 entry to remove"
    fi
}

remove_ufw_rules() {
    # Remove OpenVPN port rule if present
    ufw status numbered 2>/dev/null | grep -q '1194/udp' && \
        yes | ufw delete allow 1194/udp || true
}

remove_systemd_service() {
    systemctl disable openvpn@"$SERVER_NAME" 2>/dev/null || true
    systemctl stop openvpn@"$SERVER_NAME" 2>/dev/null || true
}

remove_files_and_dirs() {
    # Server config
    rm -f "$OPENVPN_DIR/$SERVER_NAME.conf" 2>/dev/null || true
    # PKI and EasyRSA
    rm -rf "$EASYRSA_DIR" 2>/dev/null || true
    # Clients and backups
    rm -rf "$CLIENT_DIR" 2>/dev/null || true
    rm -rf "$BACKUP_DIR" 2>/dev/null || true
    # Logs
    rm -rf "$LOG_DIR" 2>/dev/null || true
    # Helper scripts
    rm -f "$SCRIPT_DIR/openvpn-manage" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/openvpn-status" 2>/dev/null || true
}

remove_repos_and_keys() {
    # OpenVPN repo files possibly created by v2
    rm -f /etc/apt/sources.list.d/openvpn3.list 2>/dev/null || true
    rm -f /etc/apt/sources.list.d/openvpn.list 2>/dev/null || true
    rm -f /usr/share/keyrings/openvpn-archive-keyring.gpg 2>/dev/null || true
    rm -f /etc/apt/trusted.gpg.d/openvpn-repo.gpg 2>/dev/null || true
}

purge_packages_if_requested() {
    if [[ "$PURGE_PACKAGES" == true ]]; then
        info "Purging OpenVPN-related packages..."
        apt purge -y openvpn easy-rsa 2>/dev/null || true
        # Optionally purge iptables-persistent rules created by us
        # Do not purge ufw, fail2ban, unattended-upgrades by default as they may be system-wide
        apt autoremove -y 2>/dev/null || true
        apt update -y 2>/dev/null || true
    fi
}

usage() {
    cat <<USAGE
OpenVPN v2 Uninstall Script

Usage: sudo ./openvpn-uninstall-v2.sh [--purge-packages] [--remove-user] [--dry-run]

Options:
  --purge-packages  Additionally remove openvpn and easy-rsa packages
  --remove-user     Remove the dedicated openvpn user and its home
  --dry-run         Show what would be done without making changes
  -h, --help        Show this help
USAGE
}

parse_args() {
    while [[ ${1:-} ]]; do
        case "$1" in
            --purge-packages)
                PURGE_PACKAGES=true
                ;;
            --dry-run)
                DRY_RUN=true
                ;;
            --remove-user)
                REMOVE_USER=true
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

summarize_plan() {
    echo ""
    echo "Planned actions:"
    echo "- Stop and disable systemd service openvpn@${SERVER_NAME}"
    echo "- Remove server config, PKI, clients, backups, logs"
    echo "- Remove helper scripts from ${SCRIPT_DIR}"
    echo "- Remove UFW rule 1194/udp if present"
    echo "- Delete iptables MASQUERADE rule for ${VPN_NETWORK}"
    echo "- Revert net.ipv4.ip_forward sysctl change"
    echo "- Remove OpenVPN repo list and key (if present)"
    if [[ "$PURGE_PACKAGES" == true ]]; then
        echo "- Purge packages: openvpn, easy-rsa"
    else
        echo "- Keep packages installed (use --purge-packages to remove)"
    fi
    if [[ "$REMOVE_USER" == true ]]; then
        echo "- Remove user 'openvpn' and its home directory"
    fi
}

main() {
    require_root
    parse_args "$@"

    log "Starting OpenVPN v2 uninstall"
    summarize_plan

    if [[ "$DRY_RUN" == true ]]; then
        warn "Dry run mode: no changes will be made"
        exit 0
    fi

    # Stop services first
    remove_systemd_service

    # Remove firewall rules
    remove_ufw_rules || true

    # Delete NAT rule
    IFACE=$(DEFAULT_IFACE)
    if [[ -n "${IFACE}" ]]; then
        delete_iptables_rule "$IFACE"
    else
        warn "Could not detect default interface; skipping iptables MASQUERADE removal"
    fi

    # Revert sysctl
    restore_sysctl

    # Remove files and directories
    remove_files_and_dirs

    # Remove repositories and keys
    remove_repos_and_keys

    # Optionally purge packages
    purge_packages_if_requested

    # Optionally remove dedicated user
    if [[ "$REMOVE_USER" == true ]]; then
        if id -u openvpn >/dev/null 2>&1; then
            info "Removing user 'openvpn'..."
            userdel -r openvpn 2>/dev/null || true
        fi
        if getent group openvpn >/dev/null 2>&1; then
            info "Removing group 'openvpn'..."
            groupdel openvpn 2>/dev/null || true
        fi
    fi

    log "OpenVPN v2 uninstall completed"
}

main "$@"


