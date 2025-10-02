#!/usr/bin/env bash

set -euo pipefail

umask 027

SCRIPT_NAME=$(basename "$0")

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    local level="$1"
    shift
    printf '[%s] [%s] %s\n' "$(timestamp)" "$level" "$*"
}

log_info() {
    log INFO "$@"
}

log_warn() {
    log WARN "$@"
}

log_error() {
    log ERROR "$@"
}

log_success() {
    log SUCCESS "$@"
}

on_error() {
    local exit_code=$?
    log_error "Unexpected failure (exit code ${exit_code}) on or near line $1"
    exit "$exit_code"
}

trap 'on_error $LINENO' ERR
trap 'log_warn "Interrupted"; exit 1' INT TERM

normalize_bool() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON)
            echo "true"
            ;;
        0|false|FALSE|no|NO|off|OFF|"")
            echo "false"
            ;;
        *)
            log_warn "Unknown boolean value '${1}'; defaulting to false"
            echo "false"
            ;;
    esac
}

cidr_to_netmask() {
    local cidr="$1"
    if ! [[ "$cidr" =~ ^[0-9]{1,2}$ ]]; then
        log_error "Invalid CIDR prefix: ${cidr}"
        exit 1
    fi
    if (( cidr < 0 || cidr > 32 )); then
        log_error "CIDR prefix must be between 0 and 32"
        exit 1
    fi
    if (( cidr == 0 )); then
        echo "0.0.0.0"
        return
    fi
    local mask=$((0xFFFFFFFF << (32 - cidr) & 0xFFFFFFFF))
    printf '%d.%d.%d.%d' \
        $(((mask >> 24) & 0xFF)) \
        $(((mask >> 16) & 0xFF)) \
        $(((mask >> 8) & 0xFF)) \
        $((mask & 0xFF))
}

backup_path() {
    local path="$1"
    local timestamp_suffix
    timestamp_suffix=$(date '+%Y%m%d%H%M%S')
    echo "${path}.bak.${timestamp_suffix}"
}

backup_file() {
    local path="$1"
    if [ -e "$path" ]; then
        local backup
        backup=$(backup_path "$path")
        log_info "Backing up $path to $backup"
        cp -a "$path" "$backup"
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
EASYRSA_DIR=${EASYRSA_DIR:-/etc/openvpn/easy-rsa}
CLIENT_DIR=${CLIENT_DIR:-/etc/openvpn/clients}
LOG_DIR=${LOG_DIR:-/var/log/openvpn}
PAM_FILE="/etc/pam.d/openvpn"
SERVER_ENV_FILE="${OPENVPN_DIR}/openvpn-server.env"
CLIENT_TEMPLATE="${OPENVPN_DIR}/client-common.ovpn"
LOGROTATE_FILE="/etc/logrotate.d/openvpn"
SYSCTL_CONF="/etc/sysctl.conf"
FRESH_INSTALL=$(normalize_bool "${FRESH_INSTALL:-false}")
ENABLE_DUPLICATE_CN=$(normalize_bool "${ENABLE_DUPLICATE_CN:-false}")
VPN_NETWORK_CIDR="${VPN_NETWORK:-10.8.0.0/24}"
VPN_PROTO="${VPN_PROTO:-udp}"
VPN_PORT="${VPN_PORT:-1194}"
ECDH_CURVE="${ECDH_CURVE:-prime256v1}"
WAN_INTERFACE="${WAN_IFACE:-}"
SERVER_FQDN_OR_IP="${SERVER_FQDN_OR_IP:-}"

if [[ ! "$VPN_NETWORK_CIDR" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3})/([0-9]{1,2})$ ]]; then
    log_error "VPN_NETWORK must be in CIDR notation (e.g. 10.8.0.0/24)"
    exit 1
fi
VPN_NETWORK_ADDRESS="${BASH_REMATCH[1]}"
VPN_CIDR_BITS="${BASH_REMATCH[3]}"
VPN_NETMASK=$(cidr_to_netmask "$VPN_CIDR_BITS")
VPN_NETWORK_RANGE="${VPN_NETWORK_ADDRESS}/${VPN_CIDR_BITS}"

case "$VPN_PROTO" in
    udp|udp4|udp6|tcp|tcp4|tcp6)
        ;;
    *)
        log_error "Unsupported VPN_PROTO value '${VPN_PROTO}'. Supported: udp, udp4, udp6, tcp, tcp4, tcp6"
        exit 1
        ;;
esac

PAM_PLUGIN_PATH=""

apt_install_packages() {
    log_info "Refreshing apt package index"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    local packages=(
        openvpn
        easy-rsa
        libpam-google-authenticator
        qrencode
        oathtool
        curl
        iptables-persistent
        netfilter-persistent
        python3
    )
    log_info "Installing required packages: ${packages[*]}"
    apt-get install -y "${packages[@]}"
}

setup_directories() {
    log_info "Preparing OpenVPN directories"
    install -d -m 750 "$OPENVPN_DIR"
    install -d -m 750 "$CLIENT_DIR"
    install -d -m 750 "$LOG_DIR"
    install -d -m 755 "$OPENVPN_DIR/ccd"
    install -d -m 750 "$EASYRSA_DIR"

    touch "$LOG_DIR/openvpn.log" "$LOG_DIR/openvpn-status.log"
    chmod 640 "$LOG_DIR"/*.log 2>/dev/null || true
    chown root:adm "$LOG_DIR"/*.log 2>/dev/null || true

    touch "$OPENVPN_DIR/ipp.txt"
    chown nobody:nogroup "$OPENVPN_DIR/ipp.txt" 2>/dev/null || true
    chmod 644 "$OPENVPN_DIR/ipp.txt"
}

prepare_easy_rsa() {
    if [[ "$FRESH_INSTALL" == "true" && -d "$EASYRSA_DIR" ]]; then
        backup_file "$EASYRSA_DIR"
        rm -rf "$EASYRSA_DIR"
        install -d -m 750 "$EASYRSA_DIR"
    fi

    if [ ! -f "$EASYRSA_DIR/easyrsa" ]; then
        log_info "Seeding Easy-RSA skeleton"
        install -d -m 750 "$EASYRSA_DIR"
        cp -r /usr/share/easy-rsa/. "$EASYRSA_DIR/"
    fi

    write_easyrsa_vars
}

write_easyrsa_vars() {
    local vars_file="$EASYRSA_DIR/vars"
    backup_file "$vars_file"
    cat > "$vars_file" <<EOF
set_var EASYRSA_ALGO "ec"
set_var EASYRSA_CURVE "${ECDH_CURVE}"
set_var EASYRSA_BATCH "1"
set_var EASYRSA_REQ_COUNTRY "${EASYRSA_REQ_COUNTRY:-US}"
set_var EASYRSA_REQ_PROVINCE "${EASYRSA_REQ_PROVINCE:-California}"
set_var EASYRSA_REQ_CITY "${EASYRSA_REQ_CITY:-San Francisco}"
set_var EASYRSA_REQ_ORG "${EASYRSA_REQ_ORG:-OpenVPN}"
set_var EASYRSA_REQ_OU "${EASYRSA_REQ_OU:-Operations}"
set_var EASYRSA_REQ_EMAIL "${EASYRSA_REQ_EMAIL:-admin@example.local}"
set_var EASYRSA_CA_EXPIRE "${EASYRSA_CA_EXPIRE:-3650}"
set_var EASYRSA_CERT_EXPIRE "${EASYRSA_CERT_EXPIRE:-825}"
set_var EASYRSA_CRL_DAYS "${EASYRSA_CRL_DAYS:-60}"
set_var EASYRSA_PKI "$EASYRSA_DIR/pki"
EOF
    chmod 600 "$vars_file"
}

initialize_pki_and_keys() {
    pushd "$EASYRSA_DIR" >/dev/null
    export EASYRSA_BATCH=1

    if [ ! -d "pki" ]; then
        log_info "Initializing Easy-RSA PKI"
        ./easyrsa init-pki
    fi

    if [ ! -f "pki/ca.crt" ]; then
        log_info "Generating Certificate Authority"
        ./easyrsa build-ca nopass
    fi

    if [ ! -f "pki/issued/server.crt" ]; then
        log_info "Generating server certificate"
        ./easyrsa build-server-full server nopass
    fi

    if [ ! -f "ta.key" ]; then
        log_info "Generating tls-crypt key"
        openvpn --genkey --secret ta.key
    fi

    log_info "Generating certificate revocation list"
    ./easyrsa gen-crl
    chmod 644 "pki/crl.pem"

    popd >/dev/null
}

deploy_server_files() {
    log_info "Deploying server certificates and keys"
    install -m 600 -D "$EASYRSA_DIR/pki/private/server.key" "$OPENVPN_DIR/server.key"
    install -m 644 -D "$EASYRSA_DIR/pki/issued/server.crt" "$OPENVPN_DIR/server.crt"
    install -m 644 -D "$EASYRSA_DIR/pki/ca.crt" "$OPENVPN_DIR/ca.crt"
    install -m 600 -D "$EASYRSA_DIR/ta.key" "$OPENVPN_DIR/ta.key"
    install -m 644 -D "$EASYRSA_DIR/pki/crl.pem" "$EASYRSA_DIR/pki/crl.pem"
}

write_pam_config() {
    log_info "Writing PAM configuration"
    backup_file "$PAM_FILE"
    cat > "$PAM_FILE" <<'EOF'
auth requisite pam_google_authenticator.so nullok
auth required pam_unix.so
account required pam_unix.so
EOF
    chmod 644 "$PAM_FILE"
}

write_server_config() {
    local config="$OPENVPN_DIR/server.conf"
    log_info "Rendering OpenVPN server configuration to ${config}"
    backup_file "$config"

    cat > "$config" <<EOF
port ${VPN_PORT}
proto ${VPN_PROTO}
dev tun
topology subnet
server ${VPN_NETWORK_ADDRESS} ${VPN_NETMASK}
ifconfig-pool-persist ${OPENVPN_DIR}/ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "route ${VPN_NETWORK_ADDRESS} ${VPN_NETMASK}"

keepalive 10 120
persist-key
persist-tun
dh none
ecdh-curve ${ECDH_CURVE}

verify-client-cert require
username-as-common-name
plugin ${PAM_PLUGIN_PATH} openvpn
script-security 2
crl-verify ${EASYRSA_DIR}/pki/crl.pem

ca ${OPENVPN_DIR}/ca.crt
cert ${OPENVPN_DIR}/server.crt
key ${OPENVPN_DIR}/server.key
tls-crypt ${OPENVPN_DIR}/ta.key

data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
auth SHA256
tls-version-min 1.2
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256

user nobody
group nogroup

log /var/log/openvpn/openvpn.log
log-append /var/log/openvpn/openvpn.log
status /var/log/openvpn/openvpn-status.log
status-version 2
verb 3
EOF

    if [[ "$VPN_PROTO" == udp* ]]; then
        echo "explicit-exit-notify 1" >> "$config"
    fi

    if [[ "$ENABLE_DUPLICATE_CN" == "true" ]]; then
        echo "duplicate-cn" >> "$config"
    fi

    chmod 600 "$config"
}

write_client_template() {
    log_info "Creating client configuration template at ${CLIENT_TEMPLATE}"
    backup_file "$CLIENT_TEMPLATE"
    cat > "$CLIENT_TEMPLATE" <<EOF
client
dev tun
proto ${VPN_PROTO}
remote ${SERVER_FQDN_OR_IP} ${VPN_PORT}
remote-cert-tls server
resolv-retry infinite
nobind
persist-key
persist-tun
auth SHA256
auth-user-pass
setenv CLIENT_CERT 0
verb 3
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
tls-version-min 1.2
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
EOF

    if [[ "$VPN_PROTO" == udp* ]]; then
        echo "explicit-exit-notify 1" >> "$CLIENT_TEMPLATE"
    fi

    cat >> "$CLIENT_TEMPLATE" <<'EOF'
# Inline certificates and keys are appended by openvpn-user-mgmt.
EOF

    chmod 640 "$CLIENT_TEMPLATE"
}

write_logrotate_snippet() {
    log_info "Configuring logrotate for OpenVPN logs"
    backup_file "$LOGROTATE_FILE"
    cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/openvpn/*.log {
    weekly
    rotate 12
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        systemctl kill -s SIGUSR2 openvpn@server.service 2>/dev/null || true
    endscript
}
EOF
    chmod 644 "$LOGROTATE_FILE"
}

detect_public_endpoint() {
    local endpoint=""
    if command -v curl >/dev/null 2>&1; then
        endpoint=$(curl -4 -m 6 -fsS https://ifconfig.co 2>/dev/null || true)
        endpoint=${endpoint//$'\n'/}
    fi
    if [[ -z "$endpoint" ]]; then
        endpoint=$(hostname -f 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
    fi
    if [[ -z "$endpoint" ]]; then
        log_warn "Unable to detect public IP/FQDN automatically; defaulting to 127.0.0.1"
        endpoint="127.0.0.1"
    fi
    echo "$endpoint"
}

PAM_PLUGIN_SEARCH_PATHS=(
    /usr/lib/openvpn/openvpn-plugin-auth-pam.so
    /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so
    /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so
)

detect_pam_plugin() {
    local candidate
    for candidate in "${PAM_PLUGIN_SEARCH_PATHS[@]}"; do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return
        fi
    done
    log_error "OpenVPN PAM plugin not found. Ensure openvpn package installed."
    exit 1
}

detect_wan_interface() {
    if [[ -n "$WAN_INTERFACE" ]]; then
        echo "$WAN_INTERFACE"
        return
    fi

    if command -v ip >/dev/null 2>&1; then
        local iface
        iface=$(ip -4 route list default | awk '/default/ {for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i+1); exit}}')
        if [[ -n "$iface" ]]; then
            echo "$iface"
            return
        fi
    fi

    if command -v route >/dev/null 2>&1; then
        local iface
        iface=$(route -n get default 2>/dev/null | awk '/interface/ {print $2}')
        if [[ -n "$iface" ]]; then
            echo "$iface"
            return
        fi
    fi

    log_error "Unable to determine WAN interface automatically; set WAN_IFACE environment variable."
    exit 1
}

configure_sysctl() {
    log_info "Enabling IPv4 forwarding"
    if grep -q '^\s*net\.ipv4\.ip_forward' "$SYSCTL_CONF"; then
        sed -i 's/^\s*net\.ipv4\.ip_forward.*/net.ipv4.ip_forward = 1/' "$SYSCTL_CONF"
    else
        echo 'net.ipv4.ip_forward = 1' >> "$SYSCTL_CONF"
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

configure_nat() {
    WAN_INTERFACE=$(detect_wan_interface)
    log_info "Configuring NAT via iptables on ${WAN_INTERFACE}"

    if ! iptables -t nat -C POSTROUTING -s "$VPN_NETWORK_RANGE" -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$VPN_NETWORK_RANGE" -o "$WAN_INTERFACE" -j MASQUERADE
    else
        log_info "MASQUERADE rule already present"
    fi

    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    systemctl start netfilter-persistent >/dev/null 2>&1 || true
    netfilter-persistent save >/dev/null

    log_success "NAT rule persisted via netfilter-persistent"
}

add_ufw_nat_rule() {
    local wan="$1"
    local before_rules="/etc/ufw/before.rules"
    local rule="-A POSTROUTING -s ${VPN_NETWORK_RANGE} -o ${wan} -j MASQUERADE"

    if [ ! -f "$before_rules" ]; then
        return
    fi

    if grep -qF "$rule" "$before_rules"; then
        return
    fi

    backup_file "$before_rules"
    awk -v insert_rule="$rule" '
        /^\*nat/ {print; nat=1; next}
        /^COMMIT/ && nat {print insert_rule; nat=0; print; next}
        {print}
    ' "$before_rules" > "${before_rules}.tmp"
    mv "${before_rules}.tmp" "$before_rules"
}

configure_ufw() {
    if ! command -v ufw >/dev/null 2>&1; then
        return
    fi

    if ! ufw status | grep -q 'Status: active'; then
        log_info "UFW is inactive; skipping firewall adjustments"
        return
    fi

    log_info "Configuring UFW for OpenVPN"

    if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
        sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    else
        echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
    fi

    add_ufw_nat_rule "$WAN_INTERFACE"

    ufw allow "${VPN_PORT}/${VPN_PROTO}" || true
    ufw allow in on tun0 to any || true
    ufw route allow in on tun0 out on "$WAN_INTERFACE" || true
    ufw route allow in on "$WAN_INTERFACE" out on tun0 || true
    ufw reload

    log_success "UFW rules updated"
}

write_env_file() {
    log_info "Persisting environment metadata to ${SERVER_ENV_FILE}"
    cat > "$SERVER_ENV_FILE" <<EOF
SERVER_FQDN_OR_IP="${SERVER_FQDN_OR_IP}"
VPN_PORT="${VPN_PORT}"
VPN_PROTO="${VPN_PROTO}"
VPN_NETWORK="${VPN_NETWORK_RANGE}"
OPENVPN_DIR="${OPENVPN_DIR}"
EASYRSA_DIR="${EASYRSA_DIR}"
CLIENT_DIR="${CLIENT_DIR}"
CLIENT_TEMPLATE="${CLIENT_TEMPLATE}"
ECDH_CURVE="${ECDH_CURVE}"
WAN_INTERFACE="${WAN_INTERFACE}"
EOF
    chmod 600 "$SERVER_ENV_FILE"
}

write_user_mgmt_script() {
    local script_path="/usr/local/bin/openvpn-user-mgmt"
    log_info "Installing user management helper at ${script_path}"
    backup_file "$script_path"
    cat > "$script_path" <<'"EOF"'
#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_NAME=$(basename "$0")

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    local level="$1"
    shift
    printf '[%s] [%s] %s\n' "$(timestamp)" "$level" "$*"
}

log_info() {
    log INFO "$@"
}

log_warn() {
    log WARN "$@"
}

log_error() {
    log ERROR "$@"
}

error_exit() {
    log_error "$1"
    exit 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This command must be run as root"
    fi
}

require_root

SERVER_ENV_FILE="/etc/openvpn/openvpn-server.env"
if [ -f "$SERVER_ENV_FILE" ]; then
    # shellcheck disable=SC1091
    source "$SERVER_ENV_FILE"
else
    error_exit "Server environment file $SERVER_ENV_FILE not found. Run the setup script first."
fi

OPENVPN_DIR="${OPENVPN_DIR:-/etc/openvpn}"
EASYRSA_DIR="${EASYRSA_DIR:-/etc/openvpn/easy-rsa}"
CLIENT_DIR="${CLIENT_DIR:-/etc/openvpn/clients}"
CLIENT_TEMPLATE="${CLIENT_TEMPLATE:-/etc/openvpn/client-common.ovpn}"
VPN_PROTO="${VPN_PROTO:-udp}"
VPN_PORT="${VPN_PORT:-1194}"
SERVER_FQDN_OR_IP="${SERVER_FQDN_OR_IP:-localhost}"

mkdir -p "$CLIENT_DIR"

usage() {
    cat <<USAGE
Usage: $SCRIPT_NAME <add|remove|renew|list> [username] [options]

Commands:
  add <username>              Create user, password, TOTP, certificate, and client profile
  remove <username> [--delete-system-user]
                              Revoke certificate, update CRL, delete client profile, optional system user removal
  renew <username>            Revoke and reissue certificate, update profile
  list                        Show existing client profiles
USAGE
}

read_passphrase() {
    local username="$1"
    local password
    local confirm
    read -s -p "Enter password for ${username}: " password
    echo
    read -s -p "Confirm password: " confirm
    echo
    if [[ "$password" != "$confirm" ]]; then
        error_exit "Passwords do not match"
    fi
    if [[ ${#password} -lt 8 ]]; then
        log_warn "Password shorter than 8 characters"
    fi
    echo "$password"
}

refresh_crl() {
    pushd "$EASYRSA_DIR" >/dev/null
    EASYRSA_BATCH=1 ./easyrsa gen-crl >/dev/null
    chmod 644 pki/crl.pem
    popd >/dev/null
    systemctl kill -s SIGHUP openvpn@server.service >/dev/null 2>&1 || true
}

generate_client_profile() {
    local username="$1"
    local tmp_file
    tmp_file=$(mktemp)

    if [ -f "$CLIENT_TEMPLATE" ]; then
        cp "$CLIENT_TEMPLATE" "$tmp_file"
    else
        cat > "$tmp_file" <<EOF
client
dev tun
proto ${VPN_PROTO}
remote ${SERVER_FQDN_OR_IP} ${VPN_PORT}
remote-cert-tls server
resolv-retry infinite
nobind
persist-key
persist-tun
auth SHA256
auth-user-pass
setenv CLIENT_CERT 0
verb 3
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
tls-version-min 1.2
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
EOF
        if [[ "$VPN_PROTO" == udp* ]]; then
            echo "explicit-exit-notify 1" >> "$tmp_file"
        fi
    fi

    if [[ "$VPN_PROTO" == udp* ]] && ! grep -q '^explicit-exit-notify' "$tmp_file"; then
        echo "explicit-exit-notify 1" >> "$tmp_file"
    fi

    {
        echo
        echo "<tls-crypt>"
        cat "${OPENVPN_DIR}/ta.key"
        echo "</tls-crypt>"
        echo
        echo "<ca>"
        cat "${EASYRSA_DIR}/pki/ca.crt"
        echo "</ca>"
        echo
        echo "<cert>"
        cat "${EASYRSA_DIR}/pki/issued/${username}.crt"
        echo "</cert>"
        echo
        echo "<key>"
        cat "${EASYRSA_DIR}/pki/private/${username}.key"
        echo "</key>"
    } >> "$tmp_file"

    install -m 600 -T "$tmp_file" "${CLIENT_DIR}/${username}.ovpn"
}

print_qr() {
    local username="$1"
    local secret="$2"
    local otpauth="otpauth://totp/OpenVPN:${username}?secret=${secret}&issuer=OpenVPN"
    log_info "Scan this QR code with your authenticator app:" 
    qrencode -t ANSIUTF8 "$otpauth"
}

add_user() {
    local username="$1"
    if [[ -z "$username" ]]; then
        error_exit "Username is required"
    fi

    if ! id "$username" >/dev/null 2>&1; then
        log_info "Creating system user ${username}"
        useradd -m -s /usr/sbin/nologin "$username"
    else
        log_warn "System user ${username} already exists"
    fi

    local password
    password=$(read_passphrase "$username")
    echo "${username}:${password}" | chpasswd

    local user_home
    user_home=$(getent passwd "$username" | cut -d: -f6)
    sudo -u "$username" -H HOME="$user_home" google-authenticator -t -d -f -r 3 -R 30 -w 3 >/dev/null

    local secret
    secret=$(sudo -u "$username" -H head -n1 "$user_home/.google_authenticator" | cut -d' ' -f1)
    if [[ -z "$secret" ]]; then
        error_exit "Failed to read Google Authenticator secret"
    fi

    print_qr "$username" "$secret"

    pushd "$EASYRSA_DIR" >/dev/null
    if [ -f "pki/issued/${username}.crt" ]; then
        log_warn "Existing certificate for ${username} found; revoking before reissuing"
        EASYRSA_BATCH=1 ./easyrsa revoke "$username" >/dev/null || true
    fi
    EASYRSA_BATCH=1 ./easyrsa build-client-full "$username" nopass >/dev/null
    popd >/dev/null

    refresh_crl
    generate_client_profile "$username"

    log_success "User ${username} created. Client profile: ${CLIENT_DIR}/${username}.ovpn"
}

remove_user() {
    local username="$1"
    local delete_flag="$2"
    if [[ -z "$username" ]]; then
        error_exit "Username is required"
    fi

    pushd "$EASYRSA_DIR" >/dev/null
    EASYRSA_BATCH=1 ./easyrsa revoke "$username" >/dev/null || log_warn "Certificate for ${username} not found during revocation"
    popd >/dev/null
    refresh_crl

    rm -f "${CLIENT_DIR}/${username}.ovpn"

    if [[ "$delete_flag" == "true" ]]; then
        userdel -r "$username" >/dev/null 2>&1 || log_warn "Failed to delete system user ${username}"
    fi

    log_success "User ${username} removed"
}

renew_user() {
    local username="$1"
    if [[ -z "$username" ]]; then
        error_exit "Username is required"
    fi

    pushd "$EASYRSA_DIR" >/dev/null
    EASYRSA_BATCH=1 ./easyrsa revoke "$username" >/dev/null || log_warn "Existing certificate not found; issuing new certificate"
    EASYRSA_BATCH=1 ./easyrsa build-client-full "$username" nopass >/dev/null
    popd >/dev/null

    refresh_crl
    generate_client_profile "$username"

    log_success "Certificate reissued for ${username}"
}

list_users() {
    log_info "Client profiles in ${CLIENT_DIR}:"
    if compgen -G "${CLIENT_DIR}/*.ovpn" >/dev/null; then
        for cfg in "${CLIENT_DIR}"/*.ovpn; do
            printf '  %s\n' "$(basename "$cfg" .ovpn)"
        done
    else
        echo "  (none)"
    fi
}

command="$1"
shift || true

case "$command" in
    add)
        add_user "${1:-}" ;;
    remove)
        delete_flag="false"
        if [[ "${2:-}" == "--delete-system-user" ]]; then
            delete_flag="true"
        fi
        remove_user "${1:-}" "$delete_flag" ;;
    renew)
        renew_user "${1:-}" ;;
    list)
        list_users ;;
    *)
        usage
        exit 1 ;;
esac
"EOF"
    chmod 750 "$script_path"
}

create_custom_unit() {
    local unit_path="/etc/systemd/system/openvpn@server.service"
    if systemctl list-unit-files | grep -q '^openvpn@\.service'; then
        return
    fi

    log_warn "Distribution-provided openvpn@.service unit not found; installing managed unit"
    backup_file "$unit_path"
    cat > "$unit_path" <<'EOF'
[Unit]
Description=OpenVPN service for %i
Documentation=man:openvpn(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/openvpn
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/%i.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

ensure_systemd_service() {
    if ! systemctl list-unit-files | grep -q '^openvpn@\.service'; then
        create_custom_unit
    fi
    log_info "Enabling and starting openvpn@server.service"
    systemctl enable openvpn@server.service >/dev/null
    systemctl restart openvpn@server.service
    sleep 2
    if systemctl is-active --quiet openvpn@server.service; then
        log_success "OpenVPN service is active"
    else
        systemctl status openvpn@server.service --no-pager || true
        log_error "OpenVPN service failed to start"
        exit 1
    fi
}

print_summary() {
    cat <<EOF

OpenVPN setup complete.

Connection details:
  Endpoint   : ${SERVER_FQDN_OR_IP}:${VPN_PORT} (${VPN_PROTO})
  VPN network: ${VPN_NETWORK_RANGE}

Key assets:
  Server config : ${OPENVPN_DIR}/server.conf
  Client template: ${CLIENT_TEMPLATE}
  PKI directory : ${EASYRSA_DIR}/pki
  CRL file      : ${EASYRSA_DIR}/pki/crl.pem
  Logs          : ${LOG_DIR}

User management:
  Add user   : openvpn-user-mgmt add <username>
  Remove user: openvpn-user-mgmt remove <username> [--delete-system-user]
  List users : openvpn-user-mgmt list
  Renew cert : openvpn-user-mgmt renew <username>

Reminder: ensure UDP/TCP port ${VPN_PORT} is permitted on upstream firewalls.

EOF
}

main() {
    require_root
    log_info "Beginning OpenVPN with MFA setup"
    apt_install_packages

    if [[ -z "$SERVER_FQDN_OR_IP" ]]; then
        SERVER_FQDN_OR_IP=$(detect_public_endpoint)
        log_info "Detected server endpoint: ${SERVER_FQDN_OR_IP}"
    fi

    PAM_PLUGIN_PATH=$(detect_pam_plugin)

    setup_directories
    prepare_easy_rsa
    initialize_pki_and_keys
    deploy_server_files
    write_pam_config
    write_server_config
    write_client_template
    write_logrotate_snippet
    configure_sysctl
    configure_nat
    configure_ufw
    write_env_file
    write_user_mgmt_script
    ensure_systemd_service
    print_summary
}

main "$@"
