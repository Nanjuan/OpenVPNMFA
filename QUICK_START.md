# OpenVPN Quick Start - Remote Server

## One-Line Installation

```bash
curl -sSL https://raw.githubusercontent.com/your-repo/openvpn-server-setup.sh | sudo bash
```

## Manual Installation

```bash
# 1. Download and run
wget https://raw.githubusercontent.com/your-repo/openvpn-server-setup.sh
chmod +x openvpn-server-setup.sh
sudo ./openvpn-server-setup.sh

# 2. Add your first user
sudo openvpn-manage add myuser

# 3. Download client config
sudo cp /etc/openvpn/clients/myuser.ovpn /tmp/
sudo chown $USER:$USER /tmp/myuser.ovpn

# 4. Download to your local machine
scp user@your-server-ip:/tmp/myuser.ovpn ~/myuser.ovpn
```

## Quick Commands

```bash
# Add user
sudo openvpn-manage add username

# Remove user  
sudo openvpn-manage remove username

# List users
sudo openvpn-manage list

# Check status
sudo openvpn-manage status

# Create backup
sudo openvpn-manage backup

# Restart service
sudo openvpn-manage restart
```

## File Locations

- **Server Config**: `/etc/openvpn/server.conf`
- **Client Configs**: `/etc/openvpn/clients/`
- **Logs**: `/var/log/openvpn/`
- **Management**: `openvpn-manage`

## Troubleshooting

```bash
# Check service
sudo systemctl status openvpn@server

# View logs
sudo tail -f /var/log/openvpn/openvpn.log

# Test config
sudo openvpn --config /etc/openvpn/server.conf --test-crypto

# Check firewall
sudo ufw status
```

## Security Notes

- Uses AES-256-GCM encryption
- 4096-bit certificates
- TLS 1.2+ required
- Perfect Forward Secrecy enabled
- Port 1194/UDP

## Client Setup

1. **Windows**: OpenVPN GUI + import .ovpn file
2. **macOS**: Tunnelblick + import .ovpn file  
3. **Linux**: `sudo openvpn --config file.ovpn`
4. **Mobile**: OpenVPN Connect app + import .ovpn file
