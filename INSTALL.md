# Quick Installation Guide

## 🚀 One-Command Setup

```bash
# Make executable and run
chmod +x openvpn-server-setup.sh
sudo ./openvpn-server-setup.sh
```

## 👤 Add Your First User

```bash
# Add a user (will prompt for password and setup MFA)
sudo openvpn-user-mgmt add john
```

## 📱 Client Setup

1. **Download client config**: `/etc/openvpn/clients/john.ovpn`
2. **Install OpenVPN client** on your device
3. **Import the .ovpn file**
4. **Connect with**:
   - Username: `john`
   - Password: `yourpassword123456` (password + MFA code, no space)

## 🔧 Firewall (External)

Configure your firewall to allow:
- **UDP port 1194** (inbound)
- **All traffic** on tun0 interface (outbound)

## ✅ Verify Installation

```bash
# Check service status
sudo systemctl status openvpn@server.service

# Check if port is listening
sudo netstat -tuln | grep 1194

# View logs
sudo tail -f /var/log/openvpn/openvpn.log
```

## 🆘 Quick Troubleshooting

**Service won't start?**
```bash
sudo journalctl -u openvpn@server.service -f
```

**Authentication issues?**
```bash
sudo tail -f /var/log/openvpn/auth.log
```

**Can't connect?**
- Check firewall rules
- Verify port 1194 is open
- Check client configuration

---

That's it! Your OpenVPN server with MFA is ready to use! 🎉
