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
from typing import List, Dict, Any, Optional
import psutil
import requests

# Optional imports with fallbacks
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None

try:
    import sklearn
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    IsolationForest = None

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
        self.running = True
        
        # Critical directories to monitor
        user_profile = os.environ.get('USERPROFILE', '')
        self.critical_dirs = [
            Path(user_profile) / 'Desktop' if user_profile else None,
            Path(user_profile) / 'Documents' if user_profile else None,
            Path(user_profile) / 'Downloads' if user_profile else None,
            Path(user_profile) / 'Pictures' if user_profile else None,
            Path(os.environ.get('APPDATA', '')) if os.environ.get('APPDATA') else None,
        ]
        self.critical_dirs = [d for d in self.critical_dirs if d and d.exists()]
        
        # Known ransomware extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypt', '.ransom',
            '.ezz', '.micro', '.wallet', '.locky', '.crypto',
            '.enc', '.lock', '.ransomware'
        ]
        
    def start_monitoring(self):
        """Start real-time file system monitoring"""
        if not WATCHDOG_AVAILABLE:
            self.logger.warning("Watchdog not installed - file monitoring disabled")
            return
            
        self.logger.info("Starting Real-Time Protection...")
        
        # Start file system monitor
        event_handler = FileMonitorHandler(self)
        self.observer = Observer()
        
        for directory in self.critical_dirs:
            if directory and directory.exists():
                self.observer.schedule(event_handler, str(directory), recursive=True)
                self.logger.info(f"Monitoring: {directory}")
        
        if self.critical_dirs:
            self.observer.start()
            self.logger.info("File system monitoring active")
        else:
            self.logger.warning("No directories to monitor")
        
        # Start process monitor thread
        process_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        process_thread.start()
        self.logger.info("Process monitoring active")
        self.logger.info("Real-Time Protection Active")
        
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.logger.info("Real-Time Protection Stopped")
    
    def _monitor_processes(self):
        """Monitor running processes for malicious activity"""
        known_malicious = [
            'ransomware', 'crypt', 'encrypt', 'locker',
            'wannacry', 'notpetya', 'badrabbit', 'mimikatz',
            'powershell -enc', 'powershell -e'
        ]
        
        while self.running:
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
                                try:
                                    proc.kill()
                                    self.logger.info(f"Killed suspicious process: {proc_name}")
                                except:
                                    pass
                                
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
        try:
            with open("threat_log.json", "a") as f:
                json.dump(alert, f)
                f.write("\n")
        except:
            pass


class FileMonitorHandler(FileSystemEventHandler):
    """Handle file system events for ransomware detection"""
    
    def __init__(self, rtp):
        super().__init__()
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
                quarantined_path = file_path + ".quarantined"
                os.rename(file_path, quarantined_path)
                self.rtp.logger.info(f"Quarantined: {file_path}")
            except Exception as e:
                self.rtp.logger.error(f"Could not quarantine: {e}")


class MalwareScanner:
    """Advanced malware detection using YARA rules and signatures"""
    
    def __init__(self):
        self.logger = Logger("scanner").get_logger()
        self.yara_rules = self._load_yara_rules()
        self.malware_signatures = self._load_signatures()
        
    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        if not YARA_AVAILABLE:
            self.logger.warning("YARA not installed - malware detection limited")
            return None
            
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
                $ps4 = "IEX" ascii
                $ps5 = "Invoke-Expression" ascii
            condition:
                ($ps1 or $ps2 or $ps3) and ($ps4 or $ps5) and filesize < 50KB
        }
        
        rule Malware_Indicator_Strings {
            strings:
                $locky = "locky" nocase
                $wannacry = "wannacry" nocase
                $ransom = "ransom" nocase
                $encrypt = "encrypt" nocase
            condition:
                any of them
        }
        """
        
        try:
            rules = yara.compile(source=basic_rules)
            self.logger.info("YARA rules loaded successfully")
            return rules
        except Exception as e:
            self.logger.warning(f"Could not compile YARA rules: {e}")
            return None
    
    def _load_signatures(self):
        """Load malware signatures from online sources"""
        signatures = set()  # Use set for faster lookup
        
        try:
            # Try to load from local file first
            sig_file = Path("config/malware_hashes.txt")
            if sig_file.exists():
                with open(sig_file, 'r') as f:
                    for line in f:
                        signatures.add(line.strip().lower())
                self.logger.info(f"Loaded {len(signatures)} signatures from local file")
        except:
            pass
            
        # Optionally load from online (commented out to avoid delays)
        # try:
        #     response = requests.get("https://raw.githubusercontent.com/...", timeout=5)
        #     if response.status_code == 200:
        #         for line in response.text.split('\n'):
        #             signatures.add(line.strip().lower())
        # except:
        #     pass
            
        return signatures
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a single file for malware"""
        results = {
            "file": file_path,
            "malicious": False,
            "detections": [],
            "hash": None
        }
        
        try:
            # Check if file exists and is readable
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                return results
                
            # Skip very large files
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # > 100MB
                return results
                
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
    
    def scan_directory(self, directory: str) -> List[Dict[str, Any]]:
        """Scan entire directory for malware"""
        self.logger.info(f"Scanning directory: {directory}")
        threats = []
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory does not exist: {directory}")
            return threats
            
        for root, dirs, files in os.walk(directory):
            # Skip system directories
            if 'Windows' in root or 'System32' in root:
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if os.path.getsize(file_path) < 100 * 1024 * 1024:  # < 100MB
                        result = self.scan_file(file_path)
                        if result["malicious"]:
                            threats.append(result)
                except:
                    pass
                        
        self.logger.info(f"Scan complete. Found {len(threats)} threats")
        return threats


class NetworkMonitor:
    """Network traffic analysis and attack detection"""
    
    def __init__(self):
        self.logger = Logger("network").get_logger()
        self.packet_count = 0
        self.suspicious_ips = set()
        self.running = True
        self.capture_thread = None
        
    def start_capture(self):
        """Start network packet capture"""
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available - network monitoring disabled")
            return
            
        self.logger.info("Starting network traffic analysis...")
        
        def packet_handler(packet):
            self.packet_count += 1
            if self.packet_count % 1000 == 0:
                self.logger.debug(f"Packets captured: {self.packet_count}")
            
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
        self.capture_thread = threading.Thread(
            target=scapy.sniff,
            kwargs={'prn': packet_handler, 'store': False, 'timeout': 1},
            daemon=True
        )
        self.capture_thread.start()
        self.logger.info("Network monitoring active")
        
    def stop_capture(self):
        """Stop network capture"""
        self.running = False
        self.logger.info("Network monitoring stopped")
        
    def _check_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            if packet[scapy.ARP].op == 2:  # ARP reply
                # Simplified detection - would track MAC-IP pairs in production
                pass
        except:
            pass
            
    def _check_port_scan(self, packet):
        """Detect port scanning attempts"""
        # Simplified detection
        pass
        
    def _check_suspicious_ips(self, packet):
        """Check for connections to known malicious IPs"""
        suspicious_networks = [
            "185.130.5",   # Example malicious network
            "94.102.49",   # Example malicious network
            "45.33.32",    # Example malicious network
        ]
        
        ip = packet[scapy.IP].dst
        for network in suspicious_networks:
            if ip.startswith(network):
                if ip not in self.suspicious_ips:
                    self.suspicious_ips.add(ip)
                    self.logger.warning(f"⚠️ Connection to suspicious IP: {ip}")


class VulnerabilityScanner:
    """CVE vulnerability scanning for installed software"""
    
    def __init__(self):
        self.logger = Logger("vuln").get_logger()
        self.cve_cache = {}
        
    def scan_software(self) -> List[Dict[str, Any]]:
        """Scan installed software for vulnerabilities"""
        self.logger.info("Scanning for vulnerable software...")
        vulnerabilities = []
        
        if SystemInfo.get_os() != "Windows":
            self.logger.warning("Vulnerability scanner only supports Windows")
            return vulnerabilities
            
        try:
            import winreg
        except ImportError:
            self.logger.warning("winreg not available")
            return vulnerabilities
            
        keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        scanned_software = set()
        
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
                            
                            # Skip duplicates
                            if name in scanned_software:
                                i += 1
                                continue
                            scanned_software.add(name)
                            
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
            except Exception as e:
                self.logger.debug(f"Could not read registry key {key_path}: {e}")
                
        self.logger.info(f"Found {len(vulnerabilities)} vulnerable applications")
        return vulnerabilities
    
    def _check_cve(self, software: str, version: str) -> List[str]:
        """Check CVE database for known vulnerabilities"""
        # Map software to minimum safe versions
        safe_versions = {
            "chrome": (120, 0),      # Chrome 120+
            "firefox": (115, 0),     # Firefox 115+
            "java": (11, 0),         # Java 11+
            "adobe": (24, 0),        # Adobe 24+
            "python": (3, 9),        # Python 3.9+
            "node": (18, 0),         # Node.js 18+
        }
        
        vulns = []
        software_lower = software.lower()
        
        for risky, (major, minor) in safe_versions.items():
            if risky in software_lower:
                try:
                    # Parse version number
                    import re
                    version_match = re.search(r'(\d+)\.(\d+)', version)
                    if version_match:
                        ver_major = int(version_match.group(1))
                        ver_minor = int(version_match.group(2))
                        
                        if ver_major < major or (ver_major == major and ver_minor < minor):
                            vulns.append(f"CVE - Outdated {risky} ({version} < {major}.{minor})")
                except:
                    vulns.append(f"CVE - Possibly outdated {risky} ({version})")
                    
        return vulns


class BehavioralAnalyzer:
    """ML-based behavioral analysis for anomaly detection"""
    
    def __init__(self):
        self.logger = Logger("behavior").get_logger()
        self.model = None
        self.model_trained = False
        self.process_features = []
        
        if ML_AVAILABLE and IsolationForest:
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.logger.info("Behavioral analysis model initialized")
        else:
            self.logger.warning("ML libraries not available - behavioral analysis limited")
    
    def collect_process_features(self) -> List[Dict[str, Any]]:
        """Collect features for running processes"""
        features = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                # Get CPU and memory info
                cpu = proc.info['cpu_percent'] or 0
                memory = proc.info['memory_percent'] or 0
                
                # Get thread count
                try:
                    threads = proc.num_threads()
                except:
                    threads = 0
                    
                # Get handle count (Windows)
                handles = 0
                if SystemInfo.get_os() == "Windows":
                    try:
                        handles = proc.num_handles()
                    except:
                        pass
                
                features.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'] or 'unknown',
                    'cpu': cpu,
                    'memory': memory,
                    'threads': threads,
                    'handles': handles
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        return features
    
    def train_model(self, features: List[Dict[str, Any]]):
        """Train the anomaly detection model"""
        if not self.model or len(features) < 10:
            return
            
        # Prepare data for ML
        data = [[f['cpu'], f['memory'], f['threads'], f.get('handles', 0)] for f in features]
        
        try:
            self.model.fit(data)
            self.model_trained = True
            self.logger.info("Behavioral model trained successfully")
        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalous process behavior"""
        features = self.collect_process_features()
        
        if not features:
            return []
            
        # Train model if not trained and we have enough data
        if not self.model_trained and len(features) >= 10:
            self.train_model(features)
            
        if not self.model_trained or not self.model:
            return []
            
        # Prepare data for ML
        data = [[f['cpu'], f['memory'], f['threads'], f.get('handles', 0)] for f in features]
        
        try:
            predictions = self.model.predict(data)
            
            anomalies = []
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomaly detected
                    anomalies.append(features[i])
                    self.logger.warning(f"⚠️ Anomalous process detected: {features[i]['name']} "
                                       f"(CPU: {features[i]['cpu']:.1f}%, Memory: {features[i]['memory']:.1f}%)")
                    
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return []
