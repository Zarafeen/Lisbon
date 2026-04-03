![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

# Lisbon

Lisbon is a Windows-focused security auditing and remediation tool. It audits common local security issues, applies selected fixes, generates reports, and includes optional monitoring and advanced protection modules.

## Overview

Lisbon is designed as a local, scriptable security assistant for a personal Windows machine. It combines:

- security auditing
- automated fixes for supported findings
- report generation
- continuous monitoring
- optional advanced protection features such as malware scanning, behavioral analysis, and network monitoring

## Current Capabilities

- Audit configurable Windows security checks
- Apply automatic remediation for supported issues
- Generate reports in `txt`, `json`, or `html`
- Run a continuous monitoring loop
- Start real-time protection for file and process monitoring
- Scan directories for suspicious files using YARA and hash checks
- Analyze running processes for behavioral anomalies
- Check installed software for simple vulnerability/version issues

## Important Safety Notes

- Lisbon is still a beta tool and should be used carefully on a real machine.
- Malware scanning is heuristic-based and can produce false positives.
- Auto-quarantine is intentionally conservative and is meant for stronger detections only.
- Trusted Microsoft application folders are excluded by default from malware scanning to reduce noise.
- Do not treat every detection as confirmed malware without review.

## Quick Start

```bash
git clone https://github.com/Zarafeen/Lisbon.git
cd Lisbon
pip install -r requirements.txt
python src/agent.py --audit --report
```

Windows PowerShell examples:

```powershell
python src/agent.py --audit --report
python src/agent.py --fix
python src/agent.py --monitor
python scripts/run_agent.py
```

## CLI Commands

```bash
python src/agent.py --audit
python src/agent.py --audit --report
python src/agent.py --fix
python src/agent.py --monitor
python src/agent.py --rtp
python src/agent.py --malware-scan
python src/agent.py --vuln-scan
python src/agent.py --behavior
python src/agent.py --network-monitor
```

Interactive launcher:

```bash
python scripts/run_agent.py
```

## Configuration

This repository currently stores configuration in `cofigs/`.

Main config files:

- `cofigs/settings.yaml`
- `cofigs/rules.json`
- `cofigs/malware_rules.yar`

### Malware Scanning Settings

The malware scanner supports configurable quarantine behavior and default exclusions.

```yaml
advanced_protection:
  malware_scanning:
    enabled: true
    auto_quarantine: true
    quarantine_min_confidence: "high"
    scan_schedule: "weekly"
    yara_rules: "config/malware_rules.yar"
    exclude_paths:
      - "\\AppData\\Local\\Microsoft\\Edge\\User Data\\"
      - "\\AppData\\Local\\Microsoft\\Office\\"
      - "\\AppData\\Local\\Microsoft\\TeamsMeetingAdd-in\\"
```

What this means:

- auto-quarantine can be enabled
- quarantine only happens for stronger detections
- noisy Microsoft vendor folders are skipped by default

## 🔧 DNS Protection

For encrypted, reliable DNS on Windows, install Cloudflare WARP:
1. Download from https://one.one.one.one/
2. Install and turn WARP ON
3. Lisbon sets secure DNS (1.1.1.1) on active Wi-Fi/Ethernet adapters, and the secure DNS list includes WARP loopback endpoints (127.0.2.2, 127.0.2.3).

### Real-Time Protection Safe Processes

Real-Time Protection now keeps a small allowlist of common browsers so they are not killed by default. You can extend it in `cofigs/settings.yaml`:

```yaml
advanced_protection:
  real_time:
    safe_processes:
      - "opera.exe"
      - "chrome.exe"
      - "msedge.exe"
      - "firefox.exe"
```

## Recommended Scan Targets

Safer first-scan locations:

- `C:\Users\USER\Downloads`
- `C:\Users\USER\AppData\Local\Temp`
- specific unknown browser extension directories

Avoid broad full-profile scans until you have reviewed your rules and exclusions.

## Project Structure

```text
Lisbon/
|-- README.md
|-- requirements.txt
|-- setup.py
|-- LICENSE
|-- cofigs/
|   |-- settings.yaml
|   |-- rules.json
|   `-- malware_rules.yar
|-- scripts/
|   `-- run_agent.py
`-- src/
    |-- __init__.py
    |-- agent.py
    |-- auditor.py
    |-- fixer.py
    |-- reporter.py
    |-- monitor.py
    |-- advanced_protection.py
    |-- sanitizer.py
    |-- threat_logger.py
    `-- utils.py
```

## Main Modules

- `agent.py`: top-level CLI and orchestration
- `auditor.py`: audit checks and vulnerability collection
- `fixer.py`: supported auto-remediation actions
- `reporter.py`: report generation and retention cleanup
- `monitor.py`: continuous monitoring loop
- `advanced_protection.py`: malware scanning, behavioral analysis, and real-time protection
- `sanitizer.py`: input and path validation helpers
- `utils.py`: config loading, logging, shell helpers, and system utilities

## Development Notes

- The package entrypoint is `src.__init__`.
- The default config directory is `cofigs/`, matching the current repository layout.
- Advanced features depend on optional packages such as `yara-python`, `watchdog`, `scapy`, and `scikit-learn`.
- Network monitoring may show platform-specific warnings if packet capture support is unavailable.

## Basic Validation

```bash
python -m py_compile src\__init__.py src\agent.py src\auditor.py src\advanced_protection.py src\utils.py setup.py
```

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

## Community

- Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security policy: [SECURITY.md](SECURITY.md)
