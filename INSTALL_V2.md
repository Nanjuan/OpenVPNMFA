# OpenVPN Server Setup v2.0 - Installation Guide

## 🚀 Quick Installation

### One-Line Installation
```bash
curl -sSL https://raw.githubusercontent.com/your-repo/openvpn-server-setup-v2.sh | sudo bash
```

### Manual Installation
```bash
# Download and run
wget https://raw.githubusercontent.com/your-repo/openvpn-server-setup-v2.sh
chmod +x openvpn-server-setup-v2.sh
sudo ./openvpn-server-setup-v2.sh
```

## 📋 What's New in v2.0

### ✅ Latest Version Compatibility
- **Ubuntu 24.04 LTS** (Noble Numbat) - Fully tested
- **Ubuntu 24.10** (Oracular Oriole) - Fully tested
- **OpenVPN 2.6.12+** - Latest stable version
- **Easy-RSA 3.1.0+** - Modern certificate management
- **OpenSSL 3.0.2+** - Enhanced security

### 🔧 Enhanced Features
- **Automatic version detection** - Adapts to your system
- **Modern GPG key management** - No more apt-key errors
- **Enhanced security settings** - OpenSSL 3.0+ compatible
- **Improved error handling** - Better diagnostics
- **Comprehensive logging** - Detailed status information

### 🛡️ Security Improvements
- **AES-256-GCM encryption** - Latest standard
- **SHA512 authentication** - Strongest available
- **TLS 1.2+ enforcement** - Minimum secure version
- **4096-bit certificates** - Maximum security
- **Perfect Forward Secrecy** - TLS-Crypt implementation

## 📊 System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+ (24.04 LTS recommended)
- **RAM**: 1GB (2GB+ recommended)
- **Storage**: 10GB+ free space
- **Network**: Public IP with port 1194/UDP accessible
- **Access**: SSH with sudo privileges

### Recommended Specifications
- **OS**: Ubuntu 24.04 LTS
- **RAM**: 2GB+
- **Storage**: 20GB+ SSD
- **CPU**: 2+ cores
- **Network**: 100Mbps+ connection

## 🔧 Installation Process

### Step 1: Download Script
```bash
wget https://raw.githubusercontent.com/your-repo/openvpn-server-setup-v2.sh
chmod +x openvpn-server-setup-v2.sh
```

### Step 2: Run Installation
```bash
sudo ./openvpn-server-setup-v2.sh
```

### Step 3: Monitor Progress
The script will:
- ✅ Detect your Ubuntu version
- ✅ Update system packages
- ✅ Install OpenVPN and dependencies
- ✅ Set up Easy-RSA certificate authority
- ✅ Configure OpenVPN server
- ✅ Set up firewall rules
- ✅ Start OpenVPN service
- ✅ Create management tools

### Step 4: Add Your First User
```bash
sudo openvpn-manage add myuser
```

### Step 5: Download Client Configuration
```bash
# Copy client config to accessible location
sudo cp /etc/openvpn/clients/myuser.ovpn /tmp/
sudo chown $USER:$USER /tmp/myuser.ovpn

# Download to your local machine
scp user@your-server-ip:/tmp/myuser.ovpn ~/myuser.ovpn
```

## 🎛️ Management Commands

### User Management
```bash
# Add user
sudo openvpn-manage add username

# Remove user
sudo openvpn-manage remove username

# Renew user certificate
sudo openvpn-manage renew username

# List all users
sudo openvpn-manage list
```

### Server Management
```bash
# Check server status
sudo openvpn-manage status

# View recent logs
sudo openvpn-manage logs

# Test configuration
sudo openvpn-manage test

# Restart service
sudo openvpn-manage restart

# Create backup
sudo openvpn-manage backup
```

### Quick Status Check
```bash
# Comprehensive status
sudo openvpn-status
```

## 🔒 Security Features

### Encryption Standards
- **Cipher**: AES-256-GCM (latest standard)
- **Authentication**: SHA512 (strongest available)
- **TLS Version**: 1.2+ (minimum secure)
- **Key Size**: 4096-bit RSA (maximum security)
- **DH Parameters**: 4096-bit (perfect forward secrecy)

### Certificate Management
- **Easy-RSA 3.1.0+** - Modern certificate generation
- **OpenSSL 3.0+** - Enhanced security policies
- **CRL Support** - Certificate revocation lists
- **TLS-Crypt** - Additional security layer

### Network Security
- **UFW Firewall** - Uncomplicated firewall
- **iptables NAT** - Network address translation
- **IP Forwarding** - VPN traffic routing
- **Port Security** - Minimal open ports

## 📁 File Locations

### Configuration Files
- **Server Config**: `/etc/openvpn/server.conf`
- **Certificates**: `/etc/openvpn/easy-rsa/pki/`
- **Client Configs**: `/etc/openvpn/clients/`
- **Logs**: `/var/log/openvpn/`
- **Backups**: `/etc/openvpn/backup/`

### Management Scripts
- **Main Management**: `/usr/local/bin/openvpn-manage`
- **Status Check**: `/usr/local/bin/openvpn-status`

## 🔧 Troubleshooting

### Common Issues

#### 1. Installation Fails
```bash
# Check system requirements
lsb_release -a
free -h
df -h

# Verify internet connection
ping -c 3 8.8.8.8
```

#### 2. Service Won't Start
```bash
# Check service status
sudo systemctl status openvpn@server

# View detailed logs
sudo journalctl -u openvpn@server -f

# Test configuration
sudo openvpn --config /etc/openvpn/server.conf --test-crypto
```

#### 3. Client Can't Connect
```bash
# Check firewall
sudo ufw status

# Verify port is open
sudo netstat -tulpn | grep 1194

# Check server logs
sudo tail -f /var/log/openvpn/openvpn.log
```

### Debug Mode
```bash
# Enable verbose logging
sudo nano /etc/openvpn/server.conf
# Change 'verb 3' to 'verb 6'

# Restart and monitor
sudo systemctl restart openvpn@server
sudo tail -f /var/log/openvpn/openvpn.log
```

## 📊 Monitoring and Maintenance

### Regular Maintenance
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Check certificate expiration
sudo openssl x509 -in /etc/openvpn/easy-rsa/pki/ca.crt -noout -dates

# Monitor logs
sudo tail -f /var/log/openvpn/openvpn.log

# Check connected clients
sudo openvpn-manage status
```

### Backup and Recovery
```bash
# Create backup
sudo openvpn-manage backup

# List backups
ls -la /etc/openvpn/backup/

# Restore from backup
sudo tar -xzf /etc/openvpn/backup/openvpn-backup-YYYYMMDD-HHMMSS.tar.gz -C /tmp/
sudo cp -r /tmp/openvpn-backup-*/pki/* /etc/openvpn/easy-rsa/pki/
sudo systemctl restart openvpn@server
```

## 🎯 Best Practices

### Security
1. **Regular Updates** - Keep system and OpenVPN updated
2. **Certificate Rotation** - Renew certificates annually
3. **Access Control** - Use strong authentication
4. **Monitoring** - Set up log monitoring and alerting
5. **Backups** - Regular configuration backups

### Performance
1. **Resource Monitoring** - Monitor CPU, RAM, and network usage
2. **Log Rotation** - Configure log rotation to prevent disk full
3. **Connection Limits** - Set appropriate connection limits
4. **Bandwidth Management** - Monitor and manage bandwidth usage

### Maintenance
1. **Regular Backups** - Automated backup schedule
2. **Log Analysis** - Regular log review for issues
3. **Certificate Management** - Monitor certificate expiration
4. **Security Updates** - Apply security patches promptly

## 📞 Support

### Getting Help
1. **Check Logs**: `/var/log/openvpn/openvpn.log`
2. **Test Configuration**: `sudo openvpn-manage test`
3. **View Status**: `sudo openvpn-manage status`
4. **Check Service**: `sudo systemctl status openvpn@server`

### Emergency Procedures
1. **Service Down**: `sudo systemctl restart openvpn@server`
2. **Configuration Issues**: `sudo openvpn-manage test`
3. **Certificate Problems**: Check `/etc/openvpn/easy-rsa/pki/`
4. **Network Issues**: Verify firewall and routing

## 🎉 Success!

Once installation is complete, you'll have:
- ✅ Secure OpenVPN server running
- ✅ User management system
- ✅ Client configuration generation
- ✅ Monitoring and status tools
- ✅ Backup and recovery system
- ✅ Comprehensive documentation

Your OpenVPN server is now ready for production use with the latest security standards and best practices!
