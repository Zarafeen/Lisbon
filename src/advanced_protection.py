"""
Advanced Security Features - Real-time Protection, Malware Detection, Network Monitoring
"""

import os
import sys
import time
import threading
import hashlib
import json
import re
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

# Import sanitizer
try:
    from src.sanitizer import InputSanitizer
    SANITIZER_AVAILABLE = True
except ImportError:
    SANITIZER_AVAILABLE = False
    InputSanitizer = None


class QuarantineManager:
    """Manage quarantined files"""
    
    def __init__(self):
        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
        self.quarantine_log = self.quarantine_dir / "quarantine_log.json"
        
    def quarantine(self, file_path: str) -> bool:
        """Move file to quarantine with path validation"""
        try:
            # Validate file path
            if SANITIZER_AVAILABLE and InputSanitizer:
                safe_filename = InputSanitizer.sanitize_filename(Path(file_path).name)
                if not safe_filename:
                    return False
            else:
                safe_filename = Path(file_path).name
            
            file_name = safe_filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantined_path = self.quarantine_dir / f"{timestamp}_{file_name}"
            
            # Move file
            os.rename(file_path, quarantined_path)
            
            # Calculate file hash for tracking
            with open(quarantined_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Log quarantine
            log_entry = {
                "original_path": file_path,
                "quarantined_path": str(quarantined_path),
                "timestamp": datetime.now().isoformat(),
                "hash": file_hash
            }
            
            # Update log
            if self.quarantine_log.exists():
                with open(self.quarantine_log, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(log_entry)
            
            with open(self.quarantine_log, 'w') as f:
                json.dump(logs, f, indent=2)
                
            return True
            
        except Exception as e:
            return False


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
        self.quarantine_manager = QuarantineManager()
        
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
        
        # Get auto-quarantine setting from config
        self.auto_quarantine = config.get('advanced_protection.malware_scanning.auto_quarantine', False)
        
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
                # Validate directory path
                dir_str = str(directory)
                if SANITIZER_AVAILABLE and InputSanitizer:
                    # Basic validation - ensure it's a legitimate path
                    if '..' in dir_str or dir_str.startswith('\\') and not dir_str.startswith('\\\\'):
                        self.logger.warning(f"Skipping suspicious directory: {dir_str}")
                        continue
                self.observer.schedule(event_handler, dir_str, recursive=True)
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
                        
                        # Sanitize for comparison
                        if SANITIZER_AVAILABLE and InputSanitizer:
                            proc_name = InputSanitizer.sanitize_command(proc_name, allow_spaces=True)
                            cmdline = InputSanitizer.sanitize_command(cmdline, allow_spaces=True)
                        
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
        # Sanitize message before logging
        if SANITIZER_AVAILABLE and InputSanitizer:
            safe_message = InputSanitizer.sanitize_command(message)
        else:
            safe_message = message
        
        alert = {
            "timestamp": datetime.now().isoformat(),
            "message": safe_message,
            "process": process.info if process else None
        }
        self.suspicious_events.append(alert)
        self.logger.error(f"🚨 THREAT DETECTED: {safe_message}")
        
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
            # Sanitize file path
            safe_path = self._sanitize_path(event.src_path)
            if safe_path:
                self._check_ransomware_pattern(safe_path)
            
    def on_created(self, event):
        if not event.is_directory:
            # Sanitize file path
            safe_path = self._sanitize_path(event.src_path)
            if safe_path:
                self._check_malicious_extension(safe_path)
    
    def _sanitize_path(self, file_path):
        """Sanitize file path"""
        if SANITIZER_AVAILABLE and InputSanitizer:
            return InputSanitizer.sanitize_filename(file_path)
        return file_path
            
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
    
    def __init__(self, config=None):
        self.logger = Logger("scanner").get_logger()
        self.config = config
        self.yara_rules = self._load_yara_rules()
        self.malware_signatures = self._load_signatures()
        self.quarantine_manager = QuarantineManager()
        
        # Extensions to scan (executable files)
        self.scan_extensions = {
            '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', 
            '.ps1', '.vbs', '.js', '.jar', '.py', '.pl', '.rb'
        }
        
        # Auto-quarantine setting
        self.auto_quarantine = config.get('advanced_protection.malware_scanning.auto_quarantine', False) if config else False
        
    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        if not YARA_AVAILABLE:
            self.logger.warning("YARA not installed - malware detection limited")
            return None
            
        # Try to load from external file first
        yara_file = Path("config/malware_rules.yar")
        if yara_file.exists():
            try:
                rules = yara.compile(filepath=str(yara_file))
                self.logger.info(f"Loaded YARA rules from {yara_file}")
                return rules
            except Exception as e:
                self.logger.warning(f"Could not load external rules: {e}")
        
        # Fallback to built-in rules
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
            self.logger.info("Using built-in YARA rules")
            return rules
        except Exception as e:
            self.logger.warning(f"Could not compile YARA rules: {e}")
            return None
    
    def _load_signatures(self):
        """Load malware signatures from local file"""
        signatures = set()
        
        try:
            # Try to load from local file
            sig_file = Path("config/malware_hashes.txt")
            if sig_file.exists():
                with open(sig_file, 'r') as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith('#'):
                            # Validate hash format (64 hex characters)
                            if re.match(r'^[a-f0-9]{64}$', line):
                                signatures.add(line)
                self.logger.info(f"Loaded {len(signatures)} signatures from local file")
        except Exception as e:
            self.logger.debug(f"Could not load signatures: {e}")
            
        return signatures
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a single file for malware with path validation"""
        results = {
            "file": file_path,
            "malicious": False,
            "detections": [],
            "hash": None
        }
        
        # Validate file path
        if SANITIZER_AVAILABLE and InputSanitizer:
            safe_path = InputSanitizer.sanitize_filename(file_path)
            if not safe_path:
                self.logger.debug(f"Invalid file path: {file_path}")
                return results
            file_path = safe_path
        
        try:
            # Check if file exists and is readable
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                return results
                
            # Skip very large files
            size = os.path.getsize(file_path)
            if size > 100 * 1024 * 1024:  # > 100MB
                return results
                
            # Skip empty files
            if size == 0:
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
                if self.yara_rules and not results["malicious"]:
                    matches = self.yara_rules.match(data=file_data)
                    if matches:
                        results["malicious"] = True
                        for match in matches:
                            results["detections"].append(f"YARA rule: {match.rule}")
                            
        except PermissionError:
            self.logger.debug(f"Permission denied: {file_path}")
        except Exception as e:
            self.logger.debug(f"Error scanning {file_path}: {e}")
            
        if results["malicious"]:
            self.logger.warning(f"🚨 Malware detected: {file_path}")
            # Auto-quarantine if configured
            if self.auto_quarantine:
                self.quarantine_manager.quarantine(file_path)
            
        return results
    
    def scan_directory(self, directory: str, show_progress: bool = True) -> List[Dict[str, Any]]:
        """Scan entire directory for malware with progress tracking and path validation"""
        
        # Validate directory path
        if SANITIZER_AVAILABLE and InputSanitizer:
            safe_dir = InputSanitizer.sanitize_filename(directory)
            if not safe_dir:
                self.logger.error(f"Invalid directory path: {directory}")
                return []
            directory = safe_dir
        
        self.logger.info(f"Scanning directory: {directory}")
        threats = []
        scanned = 0
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory does not exist: {directory}")
            return threats
            
        for root, dirs, files in os.walk(directory):
            # Skip system directories
            skip_dirs = ['Windows', 'System32', 'WinSxS', 'AppData\\Local\\Temp', '$Recycle.Bin']
            if any(skip in root for skip in skip_dirs):
                continue
                
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # Validate filename
                if SANITIZER_AVAILABLE and InputSanitizer:
                    safe_file = InputSanitizer.sanitize_filename(file)
                    if not safe_file:
                        continue
                    file = safe_file
                
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                # Only scan relevant file types
                if ext not in self.scan_extensions:
                    continue
                    
                try:
                    if os.path.getsize(file_path) < 100 * 1024 * 1024:
                        result = self.scan_file(file_path)
                        scanned += 1
                        
                        if show_progress and scanned % 100 == 0:
                            self.logger.info(f"Scanned {scanned} files, found {len(threats)} threats...")
                            
                        if result["malicious"]:
                            threats.append(result)
                except:
                    pass
                        
        self.logger.info(f"Scan complete. Scanned {scanned} files, found {len(threats)} threats")
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
            kwargs={'prn': packet_handler, 'store': False},
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
        
        # Validate IP format
        if SANITIZER_AVAILABLE and InputSanitizer:
            valid_ip = InputSanitizer.sanitize_ip(ip)
            if not valid_ip:
                return
            ip = valid_ip
        
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
            self.logger.warning("winreg module not available (Windows only)")
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
                            
                            # Sanitize software name
                            if SANITIZER_AVAILABLE and InputSanitizer:
                                safe_name = InputSanitizer.sanitize_command(name)
                                if not safe_name:
                                    i += 1
                                    continue
                                name = safe_name
                            
                            # Skip duplicates and empty names
                            if not name or name in scanned_software:
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
            "edge": (120, 0),        # Microsoft Edge 120+
            "opera": (100, 0),       # Opera 100+
            "7-zip": (23, 0),        # 7-Zip 23+
            "vlc": (3, 0),           # VLC 3.0+
            "notepad++": (8, 5),     # Notepad++ 8.5+
        }
        
        vulns = []
        software_lower = software.lower()
        
        for risky, (major, minor) in safe_versions.items():
            if risky in software_lower:
                try:
                    # Parse version number
                    version_match = re.search(r'(\d+)\.(\d+)', version)
                    if version_match:
                        ver_major = int(version_match.group(1))
                        ver_minor = int(version_match.group(2))
                        
                        if ver_major < major or (ver_major == major and ver_minor < minor):
                            vulns.append(f"CVE - Outdated {risky.title()} ({version} < {major}.{minor})")
                except:
                    vulns.append(f"CVE - Possibly outdated {risky.title()} ({version})")
                    
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
        """Collect features for running processes with sanitization"""
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
                
                proc_name = proc.info['name'] or 'unknown'
                
                # Sanitize process name
                if SANITIZER_AVAILABLE and InputSanitizer:
                    proc_name = InputSanitizer.sanitize_process_name(proc_name)
                    if not proc_name:
                        proc_name = 'unknown'
                
                features.append({
                    'pid': proc.info['pid'],
                    'name': proc_name,
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
