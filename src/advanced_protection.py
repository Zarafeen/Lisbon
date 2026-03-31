"""
Advanced Security Features - Real-time Protection, Malware Detection, Network Monitoring
"""

import os
import sys
import time
import threading
import hashlib
import json
import pickle
from pathlib import Path
from datetime import datetime
import psutil
import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import netifaces
import requests
from cryptography.fernet import Fernet

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import sklearn
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from src.utils import SystemInfo, Logger


class RealTimeProtection:
    """Real-time file system and process monitoring"""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger("rtp").get_logger()
        self.system = SystemInfo()
        self.observer = None
        self.suspicious_events = []
        self.file_activity = {}
        
        # Critical directories to monitor
        self.critical_dirs = [
            Path(os.environ.get('USERPROFILE', '')) / 'Desktop',
            Path(os.environ.get('USERPROFILE', '')) / 'Documents',
            Path(os.environ.get('USERPROFILE', '')) / 'Downloads',
            Path(os.environ.get('USERPROFILE', '')) / 'Pictures',
            Path(os.environ.get('APPDATA', '')),
        ]
        
        # Known ransomware extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypt', '.ransom',
            '.ezz', '.micro', '.wallet', '.locky'
        ]
        
    def start_monitoring(self):
        """Start real-time file system monitoring"""
        self.logger.info("Starting Real-Time Protection...")
        
        # Start file system monitor
        event_handler = FileMonitorHandler(self)
        self.observer = Observer()
        
        for directory in self.critical_dirs:
            if directory.exists():
                self.observer.schedule(event_handler, str(directory), recursive=True)
                self.logger.info(f"Monitoring: {directory}")
        
        self.observer.start()
        
        # Start process monitor thread
        process_thread = threading.Thread(target=self._monitor_processes)
        process_thread.daemon = True
        process_thread.start()
        
        self.logger.info("Real-Time Protection Active")
        
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.logger.info("Real-Time Protection Stopped")
    
    def _monitor_processes(self):
        """Monitor running processes for malicious activity"""
        known_malicious = [
            'ransomware', 'crypt', 'encrypt', 'locker',
            'wannacry', 'notpetya', 'badrabbit'
        ]
        
        while True:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                        cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                        
                        # Check for malicious patterns
                        for malicious in known_malicious:
                            if malicious in proc_name or malicious in cmdline:
                                self.logger.warning(f"⚠️ Suspicious process detected: {proc_name}")
                                self._alert_threat(f"Suspicious process: {proc_name}", proc)
                                proc.kill()
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                        
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"Process monitor error: {e}")
    
    def _alert_threat(self, message, process=None):
        """Alert about detected threat"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "process": process.info if process else None
        }
        self.suspicious_events.append(alert)
        self.logger.error(f"🚨 THREAT DETECTED: {message}")
        
        # Save to threat log
        with open("threat_log.json", "a") as f:
            json.dump(alert, f)
            f.write("\n")


class FileMonitorHandler(FileSystemEventHandler):
    """Handle file system events for ransomware detection"""
    
    def __init__(self, rtp):
        self.rtp = rtp
        self.file_count = {}
        self.last_alert_time = {}
        
    def on_modified(self, event):
        if not event.is_directory:
            self._check_ransomware_pattern(event.src_path)
            
    def on_created(self, event):
        if not event.is_directory:
            self._check_malicious_extension(event.src_path)
            
    def _check_ransomware_pattern(self, file_path):
        """Check for ransomware-like file modifications"""
        try:
            # Track file modifications per directory
            directory = os.path.dirname(file_path)
            current_time = time.time()
            
            if directory not in self.file_count:
                self.file_count[directory] = []
                self.last_alert_time[directory] = 0
            
            # Clean old entries (last 60 seconds)
            self.file_count[directory] = [
                t for t in self.file_count[directory] 
                if current_time - t < 60
            ]
            self.file_count[directory].append(current_time)
            
            # If > 100 files modified in 60 seconds, possible ransomware
            if len(self.file_count[directory]) > 100:
                if current_time - self.last_alert_time.get(directory, 0) > 300:
                    self.rtp.logger.warning(f"🚨 Ransomware pattern detected in: {directory}")
                    self.rtp._alert_threat(f"Possible ransomware in {directory}")
                    self.last_alert_time[directory] = current_time
                    
        except Exception as e:
            pass
            
    def _check_malicious_extension(self, file_path):
        """Check for malicious file extensions"""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.rtp.ransomware_extensions:
            self.rtp.logger.warning(f"⚠️ Malicious file created: {file_path}")
            self.rtp._alert_threat(f"Malicious file detected: {file_path}")
            # Try to quarantine
            try:
                os.rename(file_path, file_path + ".quarantined")
            except:
                pass


class MalwareScanner:
    """Advanced malware detection using YARA rules and signatures"""
    
    def __init__(self):
        self.logger = Logger("scanner").get_logger()
        self.yara_rules = self._load_yara_rules()
        self.malware_signatures = self._load_signatures()
        
    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        rules = {}
        
        # Create basic YARA rules
        basic_rules = """
        rule Suspicious_PE_Characteristics {
            strings:
                $mz = "MZ" ascii
                $pe = "PE" ascii
                $upx = "UPX" ascii
            condition:
                $mz at 0 and $pe at 0x3c and $upx
        }
        
        rule PowerShell_Encoded_Command {
            strings:
                $ps1 = "-enc" ascii
                $ps2 = "-EncodedCommand" ascii
                $ps3 = "-e" ascii
            condition:
                ($ps1 or $ps2 or $ps3) and filesize < 10KB
        }
        
        rule Malware_Indicator_Hashes {
            strings:
                $hash1 = {6C 6F 63 6B 79}  // "locky"
                $hash2 = {77 61 6E 6E 61 63 72 79}  // "wannacry"
            condition:
                any of them
        }
        """
        
        try:
            rules = yara.compile(source=basic_rules)
        except Exception as e:
            self.logger.warning(f"Could not compile YARA rules: {e}")
            
        return rules
    
    def _load_signatures(self):
        """Load malware signatures from online sources"""
        signatures = []
        
        try:
            # Load from MalwareBazaar (example)
            response = requests.get(
                "https://mb-api.abuse.ch/api/v1/",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    for entry in data['data'][:100]:  # First 100 signatures
                        if 'sha256_hash' in entry:
                            signatures.append(entry['sha256_hash'])
        except:
            self.logger.warning("Could not load online signatures")
            
        return signatures
    
    def scan_file(self, file_path):
        """Scan a single file for malware"""
        results = {
            "file": file_path,
            "malicious": False,
            "detections": [],
            "hash": None
        }
        
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_data = f.read()
                sha256 = hashlib.sha256(file_data).hexdigest()
                results["hash"] = sha256
                
                # Check against known malware hashes
                if sha256 in self.malware_signatures:
                    results["malicious"] = True
                    results["detections"].append("Known malware hash")
                
                # Scan with YARA
                if self.yara_rules:
                    matches = self.yara_rules.match(data=file_data)
                    if matches:
                        results["malicious"] = True
                        for match in matches:
                            results["detections"].append(f"YARA rule: {match.rule}")
                            
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
            
        if results["malicious"]:
            self.logger.warning(f"🚨 Malware detected: {file_path}")
            
        return results
    
    def scan_directory(self, directory):
        """Scan entire directory for malware"""
        self.logger.info(f"Scanning directory: {directory}")
        threats = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) < 100 * 1024 * 1024:  # < 100MB
                    result = self.scan_file(file_path)
                    if result["malicious"]:
                        threats.append(result)
                        
        return threats


class NetworkMonitor:
    """Network traffic analysis and attack detection"""
    
    def __init__(self):
        self.logger = Logger("network").get_logger()
        self.packet_count = 0
        self.suspicious_ips = set()
        
    def start_capture(self):
        """Start network packet capture"""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available - network monitoring disabled")
            return
            
        self.logger.info("Starting network traffic analysis...")
        
        def packet_handler(packet):
            self.packet_count += 1
            
            # Check for ARP spoofing
            if packet.haslayer(scapy.ARP):
                self._check_arp_spoofing(packet)
                
            # Check for port scanning
            if packet.haslayer(scapy.TCP):
                self._check_port_scan(packet)
                
            # Check for suspicious destinations
            if packet.haslayer(scapy.IP):
                self._check_suspicious_ips(packet)
                
        # Start capture in background thread
        capture_thread = threading.Thread(
            target=scapy.sniff,
            kwargs={'prn': packet_handler, 'store': False}
        )
        capture_thread.daemon = True
        capture_thread.start()
        
    def _check_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            if packet[scapy.ARP].op == 2:  # ARP reply
                # Check for conflicting MAC addresses
                # This is simplified - real implementation would track MAC-IP pairs
                pass
        except:
            pass
            
    def _check_port_scan(self, packet):
        """Detect port scanning attempts"""
        # Simplified detection - track connection attempts
        pass
        
    def _check_suspicious_ips(self, packet):
        """Check for connections to known malicious IPs"""
        suspicious_networks = [
            "185.130.5",  # Example malicious network
            "94.102.49",
        ]
        
        ip = packet[scapy.IP].dst
        for network in suspicious_networks:
            if ip.startswith(network):
                self.suspicious_ips.add(ip)
                self.logger.warning(f"⚠️ Connection to suspicious IP: {ip}")


class VulnerabilityScanner:
    """CVE vulnerability scanning for installed software"""
    
    def __init__(self):
        self.logger = Logger("vuln").get_logger()
        self.cve_cache = {}
        
    def scan_software(self):
        """Scan installed software for vulnerabilities"""
        self.logger.info("Scanning for vulnerable software...")
        vulnerabilities = []
        
        if SystemInfo.get_os() == "Windows":
            # Get installed software via registry
            import winreg
            
            keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for key_path in keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                
                                # Check for vulnerabilities
                                vulns = self._check_cve(name, version)
                                if vulns:
                                    vulnerabilities.append({
                                        "software": name,
                                        "version": version,
                                        "vulnerabilities": vulns
                                    })
                            except:
                                pass
                                
                            i += 1
                        except WindowsError:
                            break
                except:
                    pass
                    
        return vulnerabilities
    
    def _check_cve(self, software, version):
        """Check CVE database for known vulnerabilities"""
        # Simplified - would query NVD API in real implementation
        high_risk_software = {
            "chrome": "120",
            "firefox": "115",
            "java": "8",
            "adobe": "24"
        }
        
        vulns = []
        software_lower = software.lower()
        
        for risky, safe_version in high_risk_software.items():
            if risky in software_lower:
                if version < safe_version:
                    vulns.append(f"CVE-2024-XXXX - Outdated {risky} detected")
                    
        return vulns


class BehavioralAnalyzer:
    """ML-based behavioral analysis for anomaly detection"""
    
    def __init__(self):
        self.logger = Logger("behavior").get_logger()
        self.model = None
        self.process_features = []
        
        if ML_AVAILABLE:
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.logger.info("Behavioral analysis model loaded")
        else:
            self.logger.warning("ML libraries not available - behavioral analysis limited")
    
    def collect_process_features(self):
        """Collect features for running processes"""
        features = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                features.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cpu': proc.info['cpu_percent'] or 0,
                    'memory': proc.info['memory_percent'] or 0,
                    'threads': proc.num_threads() if hasattr(proc, 'num_threads') else 0
                })
            except:
                pass
                
        return features
    
    def detect_anomalies(self):
        """Detect anomalous process behavior"""
        features = self.collect_process_features()
        
        if not features or not self.model:
            return []
            
        # Prepare data for ML
        data = [[f['cpu'], f['memory'], f['threads']] for f in features]
        
        if len(data) > 10:
            self.model.fit(data)
            predictions = self.model.predict(data)
            
            anomalies = []
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomaly detected
                    anomalies.append(features[i])
                    self.logger.warning(f"⚠️ Anomalous process detected: {features[i]['name']}")
                    
            return anomalies
            
        return []
