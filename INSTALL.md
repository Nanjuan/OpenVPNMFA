# OpenVPN Server v2.0 Quick Installation Guide

## Prerequisites

- Ubuntu 20.04+ (24.04 LTS recommended)
- Root or sudo access
- Internet connection
- At least 1GB RAM and 10GB disk space

## Quick Start

### 1. Download and Install

```bash
# Download the v2.0 script
wget https://raw.githubusercontent.com/your-repo/openvpn-server-setup-v2.sh
chmod +x openvpn-server-setup-v2.sh

# Run installation (will prompt for openvpn user password)
sudo ./openvpn-server-setup-v2.sh
```

### 2. Add Your First User

```bash
# Add a VPN user
sudo openvpn-manage add myuser

# The client configuration will be created at:
# /etc/openvpn/clients/myuser.ovpn
```

### 3. Download Client Configuration

```bash
# Copy the .ovpn file to your local machine
sudo cp /etc/openvpn/clients/myuser.ovpn ~/
sudo chown $USER:$USER ~/myuser.ovpn
```

### 4. Install OpenVPN Client

#### Windows
- Download OpenVPN GUI from https://openvpn.net/
- Import the `.ovpn` file
- Connect

#### macOS
- Install Tunnelblick from https://tunnelblick.net/
- Import the `.ovpn` file
- Connect

#### Linux
```bash
sudo apt install openvpn
sudo openvpn --config myuser.ovpn
```

#### Mobile
- Install "OpenVPN Connect" app
- Import the `.ovpn` file
- Connect

## Post-Installation

### Check Status
```bash
sudo openvpn-manage status
```

### View Logs
```bash
sudo tail -f /var/log/openvpn/openvpn.log
```

### Add More Users
```bash
sudo openvpn-manage add another_user
```

## Security Notes

- The server uses strong encryption (AES-256-GCM)
- Certificates are 4096-bit RSA
- TLS 1.2+ is enforced
- Perfect Forward Secrecy is enabled

## Troubleshooting

### Can't Connect?
1. Check if service is running: `sudo systemctl status openvpn@server`
2. Check firewall: `sudo ufw status`
3. Check logs: `sudo tail -f /var/log/openvpn/openvpn.log`

### Certificate Issues?
1. Verify user exists: `sudo openvpn-manage list`
2. Renew certificate: `sudo openvpn-manage renew username`

## Management Commands

```bash
# List all users
sudo openvpn-manage list

# Add user
sudo openvpn-manage add username

# Remove user
sudo openvpn-manage remove username

# Renew user certificate
sudo openvpn-manage renew username

# Check server status
sudo openvpn-manage status

# Create backup
sudo openvpn-manage backup

# Restart service
sudo openvpn-manage restart
```

## File Locations

- Server config: `/etc/openvpn/server.conf`
- Client configs: `/etc/openvpn/clients/`
- Logs: `/var/log/openvpn/`
- Certificates: `/etc/openvpn/easy-rsa/pki/`
- Backups: `/etc/openvpn/backup/`

## Next Steps

1. Test the VPN connection
2. Add additional users as needed
3. Set up regular backups
4. Monitor logs for security
5. Consider setting up monitoring/alerting

For detailed documentation, see `README.md`.
