"""Security Auditor - Checks for system vulnerabilities"""

import os
import socket
import re
from pathlib import Path
from typing import Dict, List, Any

from src.utils import SystemInfo, Logger


class SecurityAuditor:
    """Audits system for security vulnerabilities"""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger("auditor").get_logger()
        self.system = SystemInfo()
        self.vulnerabilities = []
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Run all enabled security checks"""
        self.logger.info("Running security audits...")
        
        enabled_checks = self.config.get('audit.enabled_checks', [])
        
        # Define all check methods
        checks = {
            'windows_updates': self.check_windows_updates,
            'firewall_status': self.check_firewall_status,
            'antivirus_status': self.check_antivirus_status,
            'dns_security': self.check_dns_security,
            'webrtc_leaks': self.check_webrtc_leaks,
            'telemetry': self.check_telemetry,
            'open_ports': self.check_open_ports,
            'suspicious_processes': self.check_suspicious_processes,
            'password_policy': self.check_password_policy,
            'disk_encryption': self.check_disk_encryption,
            'browser_security': self.check_browser_security,
        }
        
        for check_name in enabled_checks:
            if check_name in checks:
                try:
                    result = checks[check_name]()
                    if result.get('vulnerable', False):
                        self.vulnerabilities.append(result)
                        self.logger.warning(f"Vulnerability found: {result['name']}")
                except Exception as e:
                    self.logger.error(f"Check {check_name} failed: {e}")
        
        return self.vulnerabilities
    
    def check_windows_updates(self) -> Dict[str, Any]:
        """Check Windows update status"""
        if self.system.get_os() != "Windows":
            return {"name": "Windows Updates", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell(
            "Get-WindowsUpdate -IsInstalled -ErrorAction SilentlyContinue | Select-Object -First 1"
        )
        
        vulnerable = not result or "No updates" in result
        
        return {
            "name": "Windows Updates",
            "vulnerable": vulnerable,
            "details": "Updates may be missing" if vulnerable else "Updates installed",
            "severity": "CRITICAL" if vulnerable else "LOW",
            "fix_available": True,
            "check_name": "windows_updates"
        }
    
    def check_firewall_status(self) -> Dict[str, Any]:
        """Check firewall status"""
        if self.system.get_os() != "Windows":
            return {"name": "Firewall Status", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell(
            "Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $False} | Select-Object Name"
        )
        
        vulnerable = bool(result)
        
        return {
            "name": "Firewall Status",
            "vulnerable": vulnerable,
            "details": "Firewall disabled on some profiles" if vulnerable else "Firewall enabled",
            "severity": "HIGH" if vulnerable else "LOW",
            "fix_available": True,
            "check_name": "firewall_status"
        }
    
    def check_antivirus_status(self) -> Dict[str, Any]:
        """Check antivirus status"""
        if self.system.get_os() != "Windows":
            return {"name": "Antivirus", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled"
        )
        
        vulnerable = "False" in result or not result
        
        return {
            "name": "Antivirus Status",
            "vulnerable": vulnerable,
            "details": "Antivirus disabled" if vulnerable else "Antivirus enabled",
            "severity": "CRITICAL" if vulnerable else "LOW",
            "fix_available": True,
            "check_name": "antivirus_status"
        }
    
    def check_dns_security(self) -> Dict[str, Any]:
        """Check DNS configuration"""
        if self.system.get_os() != "Windows":
            return {"name": "DNS Security", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"
        )
        
        dns_servers = [s for s in result.split('\n') if s.strip()]
        secure_dns = self.config.get_rule('secure_dns_servers', [])
        
        using_secure = any(server in secure_dns for server in dns_servers)
        vulnerable = not using_secure
        
        return {
            "name": "DNS Security",
            "vulnerable": vulnerable,
            "details": f"DNS Servers: {', '.join(dns_servers)}" if dns_servers else "No DNS configured",
            "severity": "MEDIUM" if vulnerable else "LOW",
            "fix_available": True,
            "check_name": "dns_security"
        }
    
    def check_webrtc_leaks(self) -> Dict[str, Any]:
        """Check WebRTC protection"""
        if self.system.get_os() != "Windows":
            return {"name": "WebRTC", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell(
            "Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*WebRTC*'} | Select-Object Enabled"
        )
        
        vulnerable = "True" not in result
        
        return {
            "name": "WebRTC Protection",
            "vulnerable": vulnerable,
            "details": "WebRTC ports not blocked" if vulnerable else "WebRTC blocked",
            "severity": "MEDIUM" if vulnerable else "LOW",
            "fix_available": True,
            "check_name": "webrtc_leaks"
        }
    
    def check_telemetry(self) -> Dict[str, Any]:
        """Check Windows telemetry"""
        if self.system.get_os() != "Windows":
            return {"name": "Telemetry", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue"
        )
        
        vulnerable = "0" not in result
        
        return {
            "name": "Telemetry",
            "vulnerable": vulnerable,
            "details": "Telemetry sending data" if vulnerable else "Telemetry disabled",
            "severity": "LOW",
            "fix_available": True,
            "check_name": "telemetry"
        }
    
    def check_open_ports(self) -> Dict[str, Any]:
        """Check for vulnerable open ports"""
        vulnerable_ports = []
        ports_to_check = self.config.get_rule('vulnerable_ports', [21, 23, 25, 445, 3389])
        
        for port in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                vulnerable_ports.append(port)
            sock.close()
        
        return {
            "name": "Open Ports",
            "vulnerable": len(vulnerable_ports) > 0,
            "details": f"Open ports: {vulnerable_ports}" if vulnerable_ports else "No vulnerable ports",
            "severity": "HIGH" if vulnerable_ports else "LOW",
            "fix_available": True,
            "check_name": "open_ports"
        }
    
    def check_suspicious_processes(self) -> Dict[str, Any]:
        """Check for suspicious processes"""
        suspicious = self.config.get_rule('suspicious_processes', [])
        found_processes = []
        
        for proc in suspicious:
            result = self.system.run_powershell(
                f"Get-Process -Name *{proc}* -ErrorAction SilentlyContinue | Select-Object Name"
            )
            if result and proc not in found_processes:
                found_processes.append(proc)
        
        return {
            "name": "Suspicious Processes",
            "vulnerable": len(found_processes) > 0,
            "details": f"Found: {', '.join(found_processes)}" if found_processes else "No suspicious processes",
            "severity": "HIGH" if found_processes else "LOW",
            "fix_available": True,
            "check_name": "suspicious_processes"
        }
    
    def check_password_policy(self) -> Dict[str, Any]:
        """Check password policy"""
        if self.system.get_os() != "Windows":
            return {"name": "Password Policy", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell("net accounts")
        
        match = re.search(r'Minimum password length\s+(\d+)', result)
        min_length = int(match.group(1)) if match else 0
        
        vulnerable = min_length < 8
        
        return {
            "name": "Password Policy",
            "vulnerable": vulnerable,
            "details": f"Minimum length: {min_length}",
            "severity": "MEDIUM" if vulnerable else "LOW",
            "fix_available": True,
            "check_name": "password_policy"
        }
    
    def check_disk_encryption(self) -> Dict[str, Any]:
        """Check disk encryption"""
        if self.system.get_os() != "Windows":
            return {"name": "Disk Encryption", "vulnerable": False, "details": "Not applicable"}
        
        result = self.system.run_powershell("manage-bde -status C:")
        
        vulnerable = "Protection Off" in result or "Percentage Encrypted: 0%" in result
        
        return {
            "name": "Disk Encryption",
            "vulnerable": vulnerable,
            "details": "BitLocker is OFF" if vulnerable else "BitLocker is ON",
            "severity": "HIGH" if vulnerable else "LOW",
            "fix_available": True,
            "check_name": "disk_encryption"
        }
    
    def check_browser_security(self) -> Dict[str, Any]:
        """Check browser security settings"""
        firefox_profiles = Path(os.environ.get('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles'
        
        configured = firefox_profiles.exists()
        
        return {
            "name": "Browser Security",
            "vulnerable": not configured,
            "details": "Browser security not configured" if not configured else "Browser configured",
            "severity": "MEDIUM" if not configured else "LOW",
            "fix_available": True,
            "check_name": "browser_security"
        }
