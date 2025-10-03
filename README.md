# OpenVPN Server Setup Script

A comprehensive OpenVPN installation and management script for Ubuntu with best security practices and user management functionality.

## Features

- **Secure Installation**: Implements industry best practices for OpenVPN security
- **EasyRSA Integration**: Automated certificate authority setup
- **User Management**: Add, remove, and renew VPN users easily
- **Firewall Configuration**: Automatic UFW and iptables setup
- **Client Configuration**: Automatic generation of client .ovpn files
- **Backup System**: Built-in configuration backup functionality
- **Monitoring**: Logging and status monitoring capabilities

## Security Features

- **Strong Encryption**: AES-256-GCM cipher with SHA512 authentication
- **Perfect Forward Secrecy**: TLS-Crypt implementation
- **Certificate Revocation**: CRL (Certificate Revocation List) support
- **TLS 1.2+**: Minimum TLS version enforcement
- **Strong DH Parameters**: 4096-bit Diffie-Hellman parameters
- **ECDSA Support**: secp384r1 curve for enhanced security

## Installation

### Prerequisites

- Ubuntu 18.04+ (tested on Ubuntu 20.04 and 22.04)
- Root or sudo access
- Internet connection

### Quick Installation

```bash
# Download and run the installation script
wget https://raw.githubusercontent.com/your-repo/openvpn-server-setup.sh
chmod +x openvpn-server-setup.sh
sudo ./openvpn-server-setup.sh
```

### Manual Installation

```bash
# Clone or download the script
git clone https://github.com/your-repo/OpenVPNMFA.git
cd OpenVPNMFA

# Make executable and run
chmod +x openvpn-server-setup.sh
sudo ./openvpn-server-setup.sh
```

## Usage

### Initial Setup

1. **Install OpenVPN Server**:
   ```bash
   sudo ./openvpn-server-setup.sh install
   ```

2. **Add your first user**:
   ```bash
   sudo openvpn-manage add username
   ```

3. **Download client configuration**:
   ```bash
   # The .ovpn file will be created in /etc/openvpn/clients/
   sudo cp /etc/openvpn/clients/username.ovpn ~/
   ```

### User Management

The script includes a management tool at `/usr/local/bin/openvpn-manage`:

#### Add a new user
```bash
sudo openvpn-manage add john_doe
```

#### Remove a user
```bash
sudo openvpn-manage remove john_doe
```

#### Renew user certificate
```bash
sudo openvpn-manage renew john_doe
```

#### List all users
```bash
sudo openvpn-manage list
```

#### Check server status
```bash
sudo openvpn-manage status
```

#### Create backup
```bash
sudo openvpn-manage backup
```

#### Restart service
```bash
sudo openvpn-manage restart
```

## Configuration Details

### Network Settings
- **VPN Network**: 10.8.0.0/24
- **Port**: 1194 (UDP)
- **Protocol**: UDP
- **DNS**: Google DNS (8.8.8.8, 8.8.4.4)

### Security Configuration
- **Cipher**: AES-256-GCM
- **Authentication**: SHA512
- **TLS Version**: 1.2+
- **Key Size**: 4096 bits
- **DH Parameters**: 4096 bits
- **TLS-Crypt**: Enabled for additional security

### File Locations
- **Server Config**: `/etc/openvpn/server.conf`
- **Certificates**: `/etc/openvpn/easy-rsa/pki/`
- **Client Configs**: `/etc/openvpn/clients/`
- **Logs**: `/var/log/openvpn/`
- **Backups**: `/etc/openvpn/backup/`

## Client Setup

### Download Client Configuration
After adding a user, download the `.ovpn` file:

```bash
# Copy the client configuration to your local machine
sudo cp /etc/openvpn/clients/username.ovpn /home/user/
sudo chown user:user /home/user/username.ovpn
```

### Client Installation

#### Windows
1. Download OpenVPN GUI from https://openvpn.net/
2. Install and import the `.ovpn` file
3. Connect to the VPN

#### macOS
1. Install Tunnelblick from https://tunnelblick.net/
2. Import the `.ovpn` file
3. Connect to the VPN

#### Linux
1. Install OpenVPN client:
   ```bash
   sudo apt install openvpn
   ```
2. Connect using the configuration:
   ```bash
   sudo openvpn --config username.ovpn
   ```

#### Mobile (Android/iOS)
1. Install OpenVPN Connect app
2. Import the `.ovpn` file
3. Connect to the VPN

## Firewall Configuration

The script automatically configures:
- UFW firewall rules
- IP forwarding
- NAT masquerading for VPN traffic
- Port 1194/UDP access

### Manual Firewall Rules
If you need to add custom rules:

```bash
# Allow specific ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS

# Allow VPN port
sudo ufw allow 1194/udp  # OpenVPN
```

## Monitoring and Troubleshooting

### Check Server Status
```bash
sudo systemctl status openvpn@server
sudo openvpn-manage status
```

### View Logs
```bash
# Server logs
sudo tail -f /var/log/openvpn/openvpn.log

# Status logs
sudo tail -f /var/log/openvpn/openvpn-status.log
```

### Common Issues

#### 1. Connection Refused
- Check if OpenVPN service is running: `sudo systemctl status openvpn@server`
- Verify firewall rules: `sudo ufw status`
- Check if port 1194 is open: `sudo netstat -tulpn | grep 1194`

#### 2. Certificate Issues
- Verify certificates exist: `ls -la /etc/openvpn/easy-rsa/pki/issued/`
- Check certificate validity: `openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/username.crt -text -noout`

#### 3. Client Cannot Connect
- Verify client configuration file
- Check server IP address in client config
- Ensure client has internet access

## Backup and Recovery

### Create Backup
```bash
sudo openvpn-manage backup
```

### Restore from Backup
```bash
# Extract backup
sudo tar -xzf /etc/openvpn/backup/openvpn-backup-YYYYMMDD-HHMMSS.tar.gz -C /tmp/

# Restore PKI
sudo cp -r /tmp/openvpn-backup-YYYYMMDD-HHMMSS/pki/* /etc/openvpn/easy-rsa/pki/

# Restore server config
sudo cp /tmp/openvpn-backup-YYYYMMDD-HHMMSS/server.conf /etc/openvpn/

# Restart service
sudo systemctl restart openvpn@server
```

## Security Best Practices

1. **Regular Updates**: Keep the system and OpenVPN updated
2. **Certificate Rotation**: Renew certificates annually
3. **Monitor Logs**: Regularly check for suspicious activity
4. **Backup Certificates**: Keep secure backups of CA and certificates
5. **Firewall Rules**: Regularly audit firewall configuration
6. **User Management**: Remove unused user accounts promptly

## Advanced Configuration

### Custom Server Configuration
Edit `/etc/openvpn/server.conf` for custom settings:

```bash
sudo nano /etc/openvpn/server.conf
sudo systemctl restart openvpn@server
```

### Multiple Server Instances
To run multiple OpenVPN servers:

```bash
# Copy server configuration
sudo cp /etc/openvpn/server.conf /etc/openvpn/server2.conf

# Edit port and network settings
sudo nano /etc/openvpn/server2.conf

# Enable and start second server
sudo systemctl enable openvpn@server2
sudo systemctl start openvpn@server2
```

## Troubleshooting

### Debug Mode
Enable verbose logging by editing the server configuration:

```bash
sudo nano /etc/openvpn/server.conf
# Change verb 3 to verb 6 for more detailed logs
sudo systemctl restart openvpn@server
```

### Test Configuration
```bash
# Test server configuration
sudo openvpn --config /etc/openvpn/server.conf --test-crypto

# Test client configuration
sudo openvpn --config /path/to/client.ovpn --test-crypto
```

## Support

For issues and questions:
1. Check the logs: `/var/log/openvpn/`
2. Verify configuration: `sudo openvpn --config /etc/openvpn/server.conf --test-crypto`
3. Check system status: `sudo systemctl status openvpn@server`

## License

This script is provided as-is for educational and production use. Please review and test thoroughly before deploying in production environments.

## Changelog

- **v1.0**: Initial release with basic OpenVPN setup
- **v1.1**: Added user management functionality
- **v1.2**: Enhanced security configuration
- **v1.3**: Added backup and monitoring features
