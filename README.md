# OpenVPN Server with MFA - Production Ready

A comprehensive, production-ready OpenVPN server setup with Google Authenticator MFA integration.

## 🚀 Features

- **Modern Security**: AES-256-GCM encryption, TLS 1.2+, strong ciphers
- **MFA Integration**: Google Authenticator TOTP support
- **User Management**: Easy user addition, removal, and certificate renewal
- **Production Ready**: Systemd service, proper logging, error handling
- **No Firewall**: External firewall configuration (you handle firewall rules)
- **Best Practices**: Secure defaults, proper file permissions, comprehensive logging

## 📋 Prerequisites

- Ubuntu 20.04+ or Debian 11+
- Root access
- External firewall (script doesn't configure UFW)
- Internet connection for package installation

## 🛠️ Installation

1. **Clone and setup**:
   ```bash
   git clone <your-repo>
   cd OpenVPNMFA
   chmod +x openvpn-server-setup.sh
   ```

2. **Run the installation**:
   ```bash
   sudo ./openvpn-server-setup.sh
   ```

3. **Add your first user**:
   ```bash
   sudo openvpn-user-mgmt add <username>
   ```

## 📁 Directory Structure

```
/etc/openvpn/
├── server.conf          # Server configuration
├── auth-script.sh       # Authentication script
├── ca.crt               # Certificate Authority
├── server.crt           # Server certificate
├── server.key           # Server private key
├── dh.pem               # Diffie-Hellman parameters
├── ta.key               # TLS-auth key
├── ipp.txt              # IP pool persistence
└── easy-rsa/            # Easy-RSA directory
    └── pki/             # PKI certificates

/etc/openvpn/clients/     # Client configuration files
/var/log/openvpn/        # Log files
```

## 👥 User Management

### Add a new user:
```bash
sudo openvpn-user-mgmt add john
```

### Remove a user:
```bash
sudo openvpn-user-mgmt remove john
```

### List all users:
```bash
sudo openvpn-user-mgmt list
```

### Renew user certificate:
```bash
sudo openvpn-user-mgmt renew john
```

## 🔧 Service Management

### Check service status:
```bash
sudo systemctl status openvpn@server.service
```

### Restart service:
```bash
sudo systemctl restart openvpn@server.service
```

### View logs:
```bash
# OpenVPN logs
sudo tail -f /var/log/openvpn/openvpn.log

# Authentication logs
sudo tail -f /var/log/openvpn/auth.log
```

## 🔒 Security Features

- **Encryption**: AES-256-GCM with SHA256 authentication
- **TLS**: Minimum TLS 1.2 with strong cipher suites
- **MFA**: Google Authenticator TOTP integration
- **Certificates**: 2048-bit RSA certificates
- **Network**: Subnet topology (modern, recommended)
- **Logging**: Comprehensive audit trail

## 📱 Client Setup

1. **Download client config**: Located in `/etc/openvpn/clients/<username>.ovpn`
2. **Install OpenVPN client** on your device
3. **Import the .ovpn file**
4. **Connect using**:
   - Username: `<username>`
   - Password: `<password><mfa_code>` (no space between password and MFA code)

## 🌐 Network Configuration

- **Server IP**: Automatically detected
- **VPN Port**: 1194 (UDP)
- **VPN Network**: 10.8.0.0/24
- **Client IPs**: 10.8.0.4-10.8.0.254

## 🔧 Firewall Configuration

The script doesn't configure UFW. You need to configure your external firewall to allow:

- **Inbound**: UDP port 1194 from anywhere
- **Outbound**: All traffic (for VPN routing)

Example UFW rules (if you want to use UFW):
```bash
sudo ufw allow 1194/udp
sudo ufw allow out on tun0
```

## 📊 Monitoring

### Check connected clients:
```bash
sudo cat /var/log/openvpn/openvpn-status.log
```

### Monitor authentication:
```bash
sudo tail -f /var/log/openvpn/auth.log
```

### Check service health:
```bash
sudo systemctl status openvpn@server.service
```

## 🚨 Troubleshooting

### Service won't start:
```bash
sudo journalctl -u openvpn@server.service -f
```

### Authentication issues:
```bash
sudo tail -f /var/log/openvpn/auth.log
```

### Network connectivity:
```bash
# Check if port is listening
sudo netstat -tuln | grep 1194

# Check TUN interface
ip link show tun0
```

## 📝 Configuration Files

- **Server Config**: `/etc/openvpn/server.conf`
- **Auth Script**: `/etc/openvpn/auth-script.sh`
- **User Management**: `/usr/local/bin/openvpn-user-mgmt`

## 🔄 Certificate Management

- **CA Certificate**: 10-year validity
- **Server Certificate**: 10-year validity
- **Client Certificates**: 10-year validity
- **Certificate Renewal**: Use `openvpn-user-mgmt renew <username>`

## 📚 Additional Resources

- [OpenVPN Documentation](https://openvpn.net/community-resources/)
- [Google Authenticator](https://github.com/google/google-authenticator)
- [Easy-RSA Documentation](https://github.com/OpenVPN/easy-rsa)

## 🆘 Support

For issues or questions:
1. Check the logs: `/var/log/openvpn/`
2. Verify service status: `systemctl status openvpn@server.service`
3. Test authentication: Check auth logs
4. Verify network connectivity: Check firewall rules

## 📄 License

This project is open source. Use at your own risk in production environments.

---

**Note**: This setup is designed for production use with proper security practices. Always test in a safe environment first.
