![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)

# 🔒 Security Agent - Autonomous PC Security Tool

An AI-powered security agent that automatically audits and fixes vulnerabilities on your PC. No more manual security checks - let the agent handle it!

## 📋 Table of Contents
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📋 Security Checks](#-security-checks)
- [📊 Report Example](#-report-example)
- [🛠️ Advanced Usage](#️-advanced-usage)
- [📁 Project Structure](#-project-structure)
- [🔒 Security Features](#-security-features)
- [🐛 Troubleshooting](#-troubleshooting)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## ✨ Features

- 🛡️ **20+ Security Checks** - Comprehensive system audit
- 🔧 **Auto-Fix** - Automatically fixes common vulnerabilities
- 📊 **Detailed Reports** - TXT, JSON, and HTML formats
- 🚨 **Real-time Monitoring** - Continuous security monitoring
- 🌐 **DNS Protection** - Blocks DNS leaks automatically
- 🔌 **WebRTC Block** - Prevents IP leaks through WebRTC
- 🕐 **Timezone Spoofing** - Hides your real location
- 📝 **Complete Logging** - Track all security events

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Zarafeen/Lisbon.git
cd Lisbon

# Install dependencies
pip install -r requirements.txt

# Run security audit
python src/agent.py --audit

# Auto-fix vulnerabilities
python src/agent.py --fix

# Start continuous monitoring
python src/agent.py --monitor

Windows PowerShell (Run as Administrator)

```powershell
# Quick audit
python src/agent.py --audit --report

# Fix all issues
python src/agent.py --fix

# Monitor system
python src/agent.py --monitor
```

📋 Security Checks Performed

Category Checks
System Security Windows Updates, Firewall Status, Antivirus Status
Network Security DNS Security, WebRTC Leaks, Open Ports
Privacy Telemetry, Browser Security, Timezone Spoofing
Access Control Password Policy, User Accounts, Permissions
Malware Prevention Suspicious Processes, Autostart Items, Scheduled Tasks
Data Protection Disk Encryption, Network Shares, Registry Security

📊 Report Example

```
╔══════════════════════════════════════════════════════════════╗
║                 SECURITY AGENT REPORT                         ║
╚══════════════════════════════════════════════════════════════╝

Generated: 2026-03-31 10:30:00
System: Windows 11
Risk Score: 25/100
Vulnerabilities Found: 3

VULNERABILITIES:
  [MEDIUM] DNS Security
      → Using ISP DNS servers
  [LOW] Telemetry
      → Telemetry sending data to Microsoft
  [MEDIUM] Browser Security
      → Browser security not fully configured

FIXES APPLIED:
  ✓ Set secure DNS (1.1.1.1) and blocked DNS leaks
  ✓ Disabled Windows telemetry
  ✓ Applied browser hardening
```

🛠️ Advanced Usage

Custom Configuration

Edit config/settings.yaml to customize:

```yaml
agent:
  auto_fix: true
  report_format: "html"  # txt, json, html

audit:
  enabled_checks:
    - firewall_status
    - dns_security
    - webrtc_leaks

monitor:
  interval_seconds: 300  # Check every 5 minutes
  alert_on_critical: true
```

Schedule Regular Audits

Windows Task Scheduler:

```powershell
# Create scheduled task for daily audit at 3 AM
$action = New-ScheduledTaskAction -Execute "python" -Argument "C:\path\to\security-agent\src\agent.py --audit --report"
$trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"
Register-ScheduledTask -TaskName "SecurityAudit" -Action $action -Trigger $trigger
```

📁 Project Structure

```
security-agent/
├── README.md              # This file
├── requirements.txt       # Python dependencies
├── setup.py              # Installation setup
├── .gitignore            # Git ignore rules
├── LICENSE               # MIT License
├── config/
│   ├── settings.yaml     # Configuration settings
│   └── rules.json        # Security rules
├── src/
│   ├── __init__.py       # Package init
│   ├── agent.py          # Main agent
│   ├── auditor.py        # Security audit
│   ├── fixer.py          # Auto-fix
│   ├── reporter.py       # Report generation
│   ├── monitor.py        # Continuous monitoring
│   └── utils.py          # Utilities
├── scripts/
│   ├── run_agent.py      # Quick launcher
│   ├── install.ps1       # Windows install
│   └── install.sh        # Linux install
├── tests/                # Unit tests
├── reports/              # Generated reports
└── logs/                 # Log files
```

🔒 Security Features

DNS Leak Protection

· Blocks all DNS queries outside VPN
· Forces encrypted DNS (DNS over HTTPS)
· Prevents ISP tracking

WebRTC Block

· Blocks STUN/TURN ports
· Prevents local IP leaks
· Works with any browser

Anti-Fingerprinting

· Timezone spoofing
· Language spoofing
· Browser fingerprint protection

Privacy Hardening

· Disables telemetry
· Blocks tracking
· Cleans browser data

📝 Requirements

· Python 3.8+ - Download
· Windows 10/11 (Linux/macOS support coming)
· Administrator privileges for fixes
· Git for cloning (optional)

🐛 Troubleshooting

"Permission denied" errors

Run as Administrator (Windows) or with sudo (Linux)

"Module not found" errors

```bash
pip install -r requirements.txt
```

DNS blocking not working

```bash
# Check firewall rules
netsh advfirewall firewall show rule name="BlockDNS_UDP"
```

WebRTC still leaking

Visit https://browserleaks.com/webrtc to verify blocking

🤝 Contributing

1. Fork the repository
2. Create feature branch (git checkout -b feature/AmazingFeature)
3. Commit changes (git commit -m 'Add AmazingFeature')
4. Push to branch (git push origin feature/AmazingFeature)
5. Open Pull Request

📄 License

Distributed under the MIT License. See LICENSE for more information.

👤 Author

Zarafeen

· GitHub: @Zarafeen

⭐ Show Your Support

Give a ⭐️ if this project helped you!

📧 Contact

For issues or questions, open an issue on GitHub.

---

Built with 🛡️ for security enthusiasts

---

# Web dashboard (optional)
flask==2.3.0
jinja2==3.1.2

# Utilities
python-dateutil==2.8.2

# Windows-specific
wmi==1.5.1
pywin32==306

# Development
pytest==7.4.0
black==23.7.0
```
