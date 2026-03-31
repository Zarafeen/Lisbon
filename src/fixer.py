"""Security Fixer - Automatically fixes vulnerabilities"""

import os
from pathlib import Path
from typing import Dict, Any, List

from src.utils import SystemInfo, Logger


class SecurityFixer:
    """Automatically fixes security vulnerabilities"""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger("fixer").get_logger()
        self.system = SystemInfo()
        self.fixes_applied = []
    
    def fix_all(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fix all vulnerabilities that have available fixes"""
        self.logger.info(f"Attempting to fix {len(vulnerabilities)} vulnerabilities...")
        
        for vuln in vulnerabilities:
            if vuln.get('fix_available', False):
                fix_method = getattr(self, f"fix_{vuln['check_name']}", None)
                if fix_method:
                    try:
                        result = fix_method()
                        if result.get('fixed', False):
                            self.fixes_applied.append(result)
                            self.logger.info(f"Fixed: {result['description']}")
                    except Exception as e:
                        self.logger.error(f"Fix failed for {vuln['name']}: {e}")
        
        return self.fixes_applied
    
    def fix_firewall_status(self) -> Dict[str, Any]:
        """Enable Windows Firewall"""
        try:
            self.system.run_powershell("Set-NetFirewallProfile -All -Enabled True")
            return {"fixed": True, "description": "Enabled Windows Firewall on all profiles"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not enable firewall: {e}"}
    
    def fix_antivirus_status(self) -> Dict[str, Any]:
        """Enable Windows Defender"""
        try:
            self.system.run_powershell("Set-MpPreference -DisableRealtimeMonitoring $false")
            return {"fixed": True, "description": "Enabled Windows Defender real-time protection"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not enable antivirus: {e}"}
    
    def fix_dns_security(self) -> Dict[str, Any]:
        """Configure secure DNS"""
        try:
            # Set Cloudflare DNS
            self.system.run_powershell("netsh interface ip set dns name='Wi-Fi' static 1.1.1.1")
            self.system.run_powershell("netsh interface ip set dns name='Ethernet' static 1.1.1.1")
            
            # Block DNS leaks
            self.system.run_powershell(
                "netsh advfirewall firewall add rule name='BlockDNS_UDP' dir=out protocol=udp remoteport=53 action=block"
            )
            self.system.run_powershell(
                "netsh advfirewall firewall add rule name='BlockDNS_TCP' dir=out protocol=tcp remoteport=53 action=block"
            )
            
            return {"fixed": True, "description": "Set secure DNS (1.1.1.1) and blocked DNS leaks"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not configure DNS: {e}"}
    
    def fix_webrtc_leaks(self) -> Dict[str, Any]:
        """Block WebRTC ports"""
        try:
            self.system.run_powershell(
                "netsh advfirewall firewall add rule name='BlockWebRTC' dir=out protocol=udp remoteport=3478-3481,16384-16387,10000-20000 action=block"
            )
            return {"fixed": True, "description": "Blocked WebRTC ports"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not block WebRTC: {e}"}
    
    def fix_telemetry(self) -> Dict[str, Any]:
        """Disable Windows telemetry"""
        try:
            self.system.run_powershell(
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0"
            )
            return {"fixed": True, "description": "Disabled Windows telemetry"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not disable telemetry: {e}"}
    
    def fix_open_ports(self) -> Dict[str, Any]:
        """Block vulnerable open ports"""
        try:
            ports_to_block = [21, 23, 25, 445, 1433, 3306, 3389, 5900]
            blocked = []
            for port in ports_to_block:
                self.system.run_powershell(
                    f"netsh advfirewall firewall add rule name='Block_Port_{port}' dir=in protocol=tcp localport={port} action=block"
                )
                blocked.append(str(port))
            return {"fixed": True, "description": f"Blocked ports: {', '.join(blocked)}"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not block ports: {e}"}
    
    def fix_suspicious_processes(self) -> Dict[str, Any]:
        """Stop suspicious processes"""
        try:
            suspicious = ['vnc', 'remote', 'teamviewer', 'anydesk', 'tightvnc', 'radmin', 'logmein']
            stopped = []
            for proc in suspicious:
                # Check if process exists
                check_result = self.system.run_powershell(
                    f"Get-Process -Name *{proc}* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
                )
                if check_result and check_result != "Error:" and "No" not in check_result and check_result.strip():
                    # Process exists, stop it
                    self.system.run_powershell(
                        f"Stop-Process -Name *{proc}* -Force -ErrorAction SilentlyContinue"
                    )
                    stopped.append(proc)
                    self.logger.info(f"Stopped process: {proc}")
            
            if stopped:
                return {"fixed": True, "description": f"Stopped processes: {', '.join(stopped)}"}
            else:
                return {"fixed": False, "description": "No suspicious processes found"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not stop processes: {e}"}
    
    def fix_password_policy(self) -> Dict[str, Any]:
        """Enforce strong password policy"""
        try:
            self.system.run_powershell("net accounts /minpwlen:8 /maxpwage:90 /minpwage:1 /uniquepw:5")
            return {"fixed": True, "description": "Set minimum password length to 8 characters, max age 90 days"}
        except Exception as e:
            return {"fixed": False, "description": f"Could not update password policy: {e}"}
    
    def fix_disk_encryption(self) -> Dict[str, Any]:
        """Enable BitLocker (requires user intervention)"""
        # BitLocker requires user interaction, so we just notify
        return {"fixed": False, "description": "BitLocker requires manual setup. Open 'Manage BitLocker' and enable encryption"}
    
    def fix_browser_security(self) -> Dict[str, Any]:
        """Apply browser hardening"""
        fixes = []
        
        # Firefox hardening
        firefox_profiles = Path(os.environ.get('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles'
        if firefox_profiles.exists():
            user_js_content = '''// Security Agent Auto-Config
user_pref("media.peerconnection.enabled", false);
user_pref("privacy.resistFingerprinting", true);
user_pref("network.trr.mode", 3);
user_pref("network.trr.uri", "https://cloudflare-dns.com/dns-query");
user_pref("geo.enabled", false);
user_pref("browser.send_pings", false);
user_pref("webgl.disabled", true);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
'''
            for profile in firefox_profiles.glob('*.default'):
                user_js_file = profile / 'user.js'
                user_js_file.write_text(user_js_content)
                fixes.append(f"Firefox hardened: {profile.name}")
                self.logger.info(f"Applied Firefox hardening to {profile.name}")
        
        # Chrome/Brave/Edge hardening (registry keys for Windows)
        if self.system.get_os() == "Windows":
            try:
                # Disable WebRTC in Chrome/Edge
                chrome_policies = r"HKLM:\SOFTWARE\Policies\Google\Chrome"
                self.system.run_powershell(
                    f"New-Item -Path '{chrome_policies}' -Force -ErrorAction SilentlyContinue"
                )
                self.system.run_powershell(
                    f"Set-ItemProperty -Path '{chrome_policies}' -Name 'WebRtcLocalhostIpHandling' -Value '2' -Type DWord"
                )
                fixes.append("Chrome/Edge WebRTC disabled")
            except:
                pass
        
        return {"fixed": len(fixes) > 0, "description": f"Applied: {', '.join(fixes)}" if fixes else "No browser fixes applied"}
