# Remote Server Deployment Guide

## Pre-Deployment Checklist

### Server Requirements
- **OS**: Ubuntu 18.04+ (20.04 LTS recommended)
- **RAM**: Minimum 1GB (2GB+ recommended)
- **Storage**: 10GB+ free space
- **Network**: Public IP address with port 1194/UDP accessible
- **Access**: SSH access with sudo privileges

### Security Considerations
- Ensure SSH is properly secured (key-based authentication recommended)
- Consider using a non-standard SSH port
- Have a backup connection method (console access)
- Document your server's public IP address

## Deployment Methods

### Method 1: Direct Upload (Recommended)

1. **Upload the script to your server**:
   ```bash
   # From your local machine
   scp openvpn-server-setup.sh user@your-server-ip:/home/user/
   ```

2. **SSH into your server**:
   ```bash
   ssh user@your-server-ip
   ```

3. **Make executable and run**:
   ```bash
   sudo chmod +x openvpn-server-setup.sh
   sudo ./openvpn-server-setup.sh
   ```

### Method 2: Git Clone

1. **SSH into your server**:
   ```bash
   ssh user@your-server-ip
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/OpenVPNMFA.git
   cd OpenVPNMFA
   ```

3. **Run installation**:
   ```bash
   sudo chmod +x openvpn-server-setup.sh
   sudo ./openvpn-server-setup.sh
   ```

### Method 3: Direct Download

1. **SSH into your server**:
   ```bash
   ssh user@your-server-ip
   ```

2. **Download and run**:
   ```bash
   wget https://raw.githubusercontent.com/your-repo/openvpn-server-setup.sh
   chmod +x openvpn-server-setup.sh
   sudo ./openvpn-server-setup.sh
   ```

## Step-by-Step Remote Installation

### 1. Connect to Your Server
```bash
ssh user@your-server-ip
```

### 2. Update System (Important!)
```bash
sudo apt update && sudo apt upgrade -y
```

### 3. Download and Run Script
```bash
# Download the script
wget https://raw.githubusercontent.com/your-repo/openvpn-server-setup.sh
chmod +x openvpn-server-setup.sh

# Run the installation
sudo ./openvpn-server-setup.sh
```

### 4. Monitor Installation
The script will:
- Update system packages
- Install OpenVPN and dependencies
- Set up EasyRSA certificate authority
- Configure OpenVPN server
- Set up firewall rules
- Start OpenVPN service

### 5. Add Your First User
```bash
sudo openvpn-manage add admin
```

### 6. Download Client Configuration
```bash
# Copy to your local machine
sudo cp /etc/openvpn/clients/admin.ovpn /tmp/
sudo chown $USER:$USER /tmp/admin.ovpn

# Download to your local machine
scp user@your-server-ip:/tmp/admin.ovpn ~/admin.ovpn
```

## Post-Installation Verification

### 1. Check Service Status
```bash
sudo systemctl status openvpn@server
```

### 2. Verify Firewall
```bash
sudo ufw status
```

### 3. Check OpenVPN Port
```bash
sudo netstat -tulpn | grep 1194
```

### 4. Test Configuration
```bash
sudo openvpn --config /etc/openvpn/server.conf --test-crypto
```

## Security Hardening for Remote Servers

### 1. SSH Security
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config

# Recommended settings:
# Port 2222  # Change from default 22
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes

# Restart SSH
sudo systemctl restart ssh
```

### 2. Firewall Rules
```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp  # SSH (if changed)
sudo ufw allow 1194/udp  # OpenVPN
sudo ufw allow 80/tcp    # HTTP (if needed)
sudo ufw allow 443/tcp   # HTTPS (if needed)
```

### 3. Fail2Ban Configuration
```bash
# Install fail2ban
sudo apt install fail2ban

# Configure for SSH and OpenVPN
sudo nano /etc/fail2ban/jail.local
```

Add this configuration:
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log

[openvpn]
enabled = true
port = 1194
filter = openvpn
logpath = /var/log/openvpn/openvpn.log
```

## Client Configuration Download

### Method 1: SCP Download
```bash
# From your local machine
scp user@your-server-ip:/etc/openvpn/clients/username.ovpn ~/
```

### Method 2: HTTP Download (Temporary)
```bash
# On the server, create a temporary web server
cd /etc/openvpn/clients
python3 -m http.server 8080

# Download from your browser: http://your-server-ip:8080/username.ovpn
# Remember to stop the web server after download!
```

### Method 3: Email Configuration
```bash
# Send configuration via email (be careful with security!)
sudo apt install mailutils
echo "OpenVPN Configuration" | mail -s "VPN Config" -A /etc/openvpn/clients/username.ovpn your-email@domain.com
```

## Troubleshooting Remote Installation

### Common Issues

#### 1. Connection Refused
```bash
# Check if OpenVPN is running
sudo systemctl status openvpn@server

# Check firewall
sudo ufw status

# Check if port is open
sudo netstat -tulpn | grep 1194
```

#### 2. Certificate Issues
```bash
# Verify certificates
ls -la /etc/openvpn/easy-rsa/pki/issued/

# Check certificate validity
openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/username.crt -text -noout
```

#### 3. Network Issues
```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Check NAT rules
sudo iptables -t nat -L
```

### Debug Mode
```bash
# Enable verbose logging
sudo nano /etc/openvpn/server.conf
# Change 'verb 3' to 'verb 6'

# Restart and check logs
sudo systemctl restart openvpn@server
sudo tail -f /var/log/openvpn/openvpn.log
```

## Backup and Recovery

### Create Backup
```bash
sudo openvpn-manage backup
```

### Download Backup
```bash
# From your local machine
scp user@your-server-ip:/etc/openvpn/backup/openvpn-backup-*.tar.gz ~/
```

### Restore Backup
```bash
# Upload backup to server
scp ~/openvpn-backup-*.tar.gz user@your-server-ip:/tmp/

# On server, restore
sudo tar -xzf /tmp/openvpn-backup-*.tar.gz -C /etc/openvpn/backup/
sudo cp -r /etc/openvpn/backup/openvpn-backup-*/pki/* /etc/openvpn/easy-rsa/pki/
sudo systemctl restart openvpn@server
```

## Monitoring and Maintenance

### Log Monitoring
```bash
# Real-time log monitoring
sudo tail -f /var/log/openvpn/openvpn.log

# Check for errors
sudo grep -i error /var/log/openvpn/openvpn.log
```

### Performance Monitoring
```bash
# Check connected clients
sudo openvpn-manage status

# Monitor bandwidth
sudo iftop -i tun0
```

### Regular Maintenance
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Check certificate expiration
sudo openssl x509 -in /etc/openvpn/easy-rsa/pki/ca.crt -noout -dates

# Rotate logs
sudo logrotate -f /etc/logrotate.d/openvpn
```

## Security Best Practices

1. **Regular Updates**: Keep system and OpenVPN updated
2. **Certificate Management**: Rotate certificates annually
3. **Access Control**: Use strong authentication
4. **Monitoring**: Set up log monitoring and alerting
5. **Backups**: Regular configuration backups
6. **Firewall**: Minimal necessary ports only
7. **SSH Security**: Key-based authentication only

## Emergency Procedures

### If You Lose SSH Access
1. Use console access (VPS provider console)
2. Check firewall rules
3. Verify SSH service status
4. Review system logs

### If OpenVPN Stops Working
1. Check service status: `sudo systemctl status openvpn@server`
2. Review logs: `sudo tail -f /var/log/openvpn/openvpn.log`
3. Test configuration: `sudo openvpn --config /etc/openvpn/server.conf --test-crypto`
4. Restart service: `sudo systemctl restart openvpn@server`

## Support and Documentation

- **Server Logs**: `/var/log/openvpn/`
- **Configuration**: `/etc/openvpn/server.conf`
- **Client Configs**: `/etc/openvpn/clients/`
- **Certificates**: `/etc/openvpn/easy-rsa/pki/`
- **Management**: `sudo openvpn-manage [command]`
