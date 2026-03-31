![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

# Lisbon

Lisbon is a Windows-focused security auditing and remediation tool. It audits common local security issues, applies selected fixes, generates reports, and offers optional monitoring and advanced protection modules.

## Features

- Configurable security audit checks
- Automatic remediation for supported findings
- Report generation in `txt`, `json`, and `html`
- Continuous monitoring loop
- Optional advanced modules for:
  - real-time file and process monitoring
  - malware scanning
  - network monitoring
  - software vulnerability checks
  - behavioral anomaly detection

## Scope

- Primary target: Windows 10/11
- Python 3.8+
- Administrator privileges recommended for most fix operations
- Best treated as a personal/local beta tool until it has stronger test coverage

## Quick Start

```bash
git clone https://github.com/Zarafeen/Lisbon.git
cd Lisbon
pip install -r requirements.txt
python src/agent.py --audit --report
```

Windows PowerShell:

```powershell
python src/agent.py --audit --report
python src/agent.py --fix
python src/agent.py --monitor
```

## CLI Usage

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

Quick launcher:

```bash
python scripts/run_agent.py
```

## Configuration

The repository currently stores configuration in `cofigs/`.

Key files:

- `cofigs/settings.yaml`
- `cofigs/rules.json`
- `cofigs/malware_rules.yar`

Example:

```yaml
agent:
  auto_fix: true

monitor:
  interval_seconds: 300
  alert_on_critical: true

reporting:
  report_format: "html"
```

## Project Structure

```text
Lisbon/
├── README.md
├── requirements.txt
├── setup.py
├── LICENSE
├── cofigs/
│   ├── settings.yaml
│   ├── rules.json
│   └── malware_rules.yar
├── scripts/
│   └── run_agent.py
└── src/
    ├── __init__.py
    ├── agent.py
    ├── auditor.py
    ├── fixer.py
    ├── reporter.py
    ├── monitor.py
    ├── advanced_protection.py
    ├── sanitizer.py
    ├── threat_logger.py
    └── utils.py
```

## Main Modules

- `agent.py`: CLI entrypoint and orchestration
- `auditor.py`: security checks
- `fixer.py`: automatic remediation
- `reporter.py`: report generation and retention cleanup
- `monitor.py`: scheduled monitoring loop
- `advanced_protection.py`: optional real-time and scanning features
- `sanitizer.py`: input and path validation helpers
- `utils.py`: config loading, logging, and system helpers

## Notes

- Some advanced features depend on optional packages such as `yara-python`, `watchdog`, `scapy`, and `scikit-learn`.
- Real-time monitoring and remediation features can change local system state.
- The current config directory name is `cofigs/` because that is how the repository is presently structured.

## Development

```bash
pip install -r requirements.txt
python -m py_compile src\__init__.py src\agent.py src\auditor.py src\advanced_protection.py src\utils.py setup.py
```

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
