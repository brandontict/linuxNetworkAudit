# Kali Linux Network Security Audit Script

![Kali Linux](https://img.shields.io/badge/Kali%20Linux-557C94?style=flat&logo=kalilinux&logoColor=white)
![Bash](https://img.shields.io/badge/bash-4EAA25?style=flat&logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.0-green.svg)

A comprehensive network security audit script designed specifically for Kali Linux penetration testing environments. This script performs automated security checks to ensure your pentesting laptop isn't inadvertently exposing services or vulnerable to attacks.

## 🎯 Features

### Network Security Analysis
- **Port Scanning**: Identifies all listening TCP/UDP ports with associated processes
- **Connection Monitoring**: Tracks established connections and connection states  
- **Interface Analysis**: Detects promiscuous mode and VPN interfaces
- **Firewall Assessment**: Comprehensive firewall status (iptables, UFW, firewalld)

### System Security Checks  
- **Service Auditing**: Monitors running services and daemons
- **Process Analysis**: Detects suspicious processes and unusual execution paths
- **Configuration Review**: Examines network parameters and DNS settings
- **Kali-Specific Checks**: Tailored for Kali Linux pentesting environment

### Visual Output
- **Color-coded Results**: Red (critical), Yellow (warning), Green (good), Blue (info)
- **ASCII Art Header**: Professional presentation
- **Organized Sections**: Easy-to-scan categorized output
- **Security Recommendations**: Actionable advice for hardening

## 🚀 Quick Start

### Prerequisites
- Kali Linux (tested on 2023.x and later)
- Bash shell
- Root privileges (for comprehensive checks)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/kali-network-audit.git
cd kali-network-audit

# Make the script executable
chmod +x kali_net_audit.sh

# Run the audit
sudo ./kali_net_audit.sh
```

### One-liner Installation
```bash
wget https://raw.githubusercontent.com/yourusername/kali-network-audit/main/kali_net_audit.sh && chmod +x kali_net_audit.sh && sudo ./kali_net_audit.sh
```

## 📋 Usage

### Basic Usage
```bash
# Run with full privileges (recommended)
sudo ./kali_net_audit.sh

# Run as regular user (limited functionality)
./kali_net_audit.sh
```

### Sample Output

```
    ██╗  ██╗ █████╗ ██╗     ██╗    ███╗   ██╗███████╗████████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗
    ██║ ██╔╝██╔══██╗██║     ██║    ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
    █████╔╝ ███████║██║     ██║    ██╔██╗ ██║█████╗     ██║       ███████║██║   ██║██║  ██║██║   ██║   
    ██╔═██╗ ██╔══██║██║     ██║    ██║╚██╗██║██╔══╝     ██║       ██╔══██║██║   ██║██║  ██║██║   ██║   
    ██║  ██╗██║  ██║███████╗██║    ██║ ╚████║███████╗   ██║       ██║  ██║╚██████╔╝██████╔╝██║   ██║   
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝    ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   

Network Security Audit Script - Wed Sep 17 15:30:45 CDT 2025
[✓] Running as root - full access mode

========================================
SYSTEM INFORMATION
========================================
Hostname: kali-laptop
Kernel: 6.1.0-kali7-amd64
Distro: Kali GNU/Linux Rolling
Uptime: up 2 hours, 15 minutes
Load Average:  0.08, 0.12, 0.09
[✓] Confirmed Kali Linux system

========================================
LISTENING PORTS & SERVICES  
========================================
[i] Checking for listening TCP ports...
TCP Listening Ports:
[PRIVILEGED] tcp   LISTEN 0      128                0.0.0.0:22             0.0.0.0:*    users:(("sshd",pid=1492,fd=3))
[USER] tcp   LISTEN 0      50               *:1716            *:*    users:(("kdeconnectd",pid=2756,fd=7))
```

## 🔧 What Gets Checked

### Network Security
- [x] Listening TCP/UDP ports
- [x] Established connections
- [x] Network interface status
- [x] Promiscuous mode detection
- [x] VPN tunnel interfaces
- [x] Routing table analysis
- [x] DNS configuration

### Firewall & Access Control
- [x] iptables rules and policies
- [x] UFW (Uncomplicated Firewall) status
- [x] firewalld configuration
- [x] Network security parameters

### System Services
- [x] SystemD service status
- [x] Failed service detection
- [x] Web server checks (Apache, Nginx)
- [x] Database server monitoring
- [x] SSH service analysis

### Kali Linux Specific
- [x] Default Kali services status
- [x] Metasploit database check
- [x] Pentesting tool process detection
- [x] Security recommendations

### Process & Security Analysis
- [x] Suspicious process locations
- [x] Hidden process detection
- [x] Network connection mapping
- [x] System update status

## ⚠️ Security Recommendations

The script provides tailored recommendations including:
- SSH hardening strategies
- Firewall policy improvements  
- Service management best practices
- Update and maintenance reminders
- Kali Linux specific security guidance

## 🛡️ Common Issues & Solutions

### Permission Denied Errors
```bash
# Ensure script is executable
chmod +x kali_net_audit.sh

# Run with appropriate privileges
sudo ./kali_net_audit.sh
```

### Missing Dependencies
Most tools are included in Kali Linux by default. If you encounter missing commands:
```bash
# Update package list
sudo apt update

# Install common network tools
sudo apt install net-tools iproute2 lsof
```

### Firewall Warnings
If you see "NO FIREWALL PROTECTION DETECTED":
```bash
# Enable UFW
sudo ufw enable

# Or configure iptables
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT
```

## 🔍 Interpreting Results

### Color Coding
- 🔴 **RED**: Critical security issues requiring immediate attention
- 🟡 **YELLOW**: Warnings that should be reviewed
- 🟢 **GREEN**: Good security practices detected
- 🔵 **BLUE**: Informational messages

### Common Findings
- **SSH Running**: Normal for remote access but ensure it's secured
- **KDE Connect**: Legitimate but consider firewall rules
- **No Firewall**: High priority - enable protection
- **Multiple Connections**: Monitor for unusual activity

## 📚 Additional Tools

After running this audit, consider these complementary security tools:

```bash
# Comprehensive system audit
sudo lynis audit system

# Rootkit scanner  
sudo rkhunter --check

# Network mapper (scan yourself)
nmap -sS localhost

# Process monitor
sudo netstat -tulnp

# Real-time network monitoring
sudo ss -tuln4 | watch -n 1
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Additional security checks
- Bug fixes
- Performance improvements  
- Documentation updates
- Kali Linux tool integrations

### Development Guidelines
1. Maintain existing color coding scheme
2. Add comments for complex logic
3. Test on multiple Kali versions
4. Update documentation for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Disclaimer

This tool is intended for educational purposes and authorized penetration testing only. Users are responsible for complying with applicable laws and obtaining proper authorization before using this tool on any systems they do not own or have explicit permission to test.

**Use responsibly and ethically.**

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/kali-network-audit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/kali-network-audit/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/kali-network-audit/wiki)

## 🏷️ Version History

- **v1.0**: Initial release with comprehensive network security auditing
- **Future**: Planning integration with popular Kali tools and export features

---

**Made with ❤️ for the cybersecurity community**

*"Security is not a product, but a process." - Bruce Schneier*