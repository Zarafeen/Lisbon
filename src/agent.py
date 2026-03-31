"""Main Security Agent - Orchestrates all security operations"""

import argparse
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils import ConfigLoader, SystemInfo, print_banner, print_progress
from src.auditor import SecurityAuditor
from src.fixer import SecurityFixer
from src.reporter import SecurityReporter
from src.monitor import SecurityMonitor

# Import advanced protection modules (with error handling for missing dependencies)
try:
    from src.advanced_protection import (
        RealTimeProtection,
        MalwareScanner,
        NetworkMonitor,
        VulnerabilityScanner,
        BehavioralAnalyzer
    )
    ADVANCED_AVAILABLE = True
except ImportError:
    ADVANCED_AVAILABLE = False
    print_progress("Advanced protection modules not available", "warning")


DEFAULT_CONFIG_DIR = "cofigs"


class SecurityAgent:
    """Main security agent orchestrator"""
    
    def __init__(self, config_dir: str = DEFAULT_CONFIG_DIR):
        self.config_dir = Path(config_dir)
        self.config_loader = ConfigLoader(str(self.config_dir))
        self.system = SystemInfo()
        
        # Initialize components
        self.auditor = SecurityAuditor(self.config_loader)
        self.fixer = SecurityFixer(self.config_loader)
        self.reporter = SecurityReporter(self.config_loader)
        self.monitor = None
        
        # Initialize advanced protection modules (if available)
        self.rtp = None
        self.malware_scanner = None
        self.network_monitor = None
        self.vuln_scanner = None
        self.behavior_analyzer = None
        
        if ADVANCED_AVAILABLE:
            try:
                self.malware_scanner = MalwareScanner(self.config_loader)
                self.network_monitor = NetworkMonitor()
                self.vuln_scanner = VulnerabilityScanner()
                self.behavior_analyzer = BehavioralAnalyzer()
            except Exception as e:
                print_progress(f"Could not initialize advanced modules: {e}", "warning")
        
        print_banner()
        print_progress(f"System: {self.system.get_os()} - {self.system.get_hostname()}", "info")
        
        if not self.system.is_admin():
            print_progress("⚠️  Not running as administrator! Some features may not work.", "warning")
    
    def run_audit(self, save_report: bool = True) -> dict:
        """Run security audit"""
        print_progress("Starting security audit...", "info")
        
        # Run all checks
        vulnerabilities = self.auditor.run_all_checks()
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Prepare results
        results = {
            "timestamp": __import__('datetime').datetime.now().isoformat(),
            "system": self.system.get_os(),
            "hostname": self.system.get_hostname(),
            "username": self.system.get_username(),
            "is_admin": self.system.is_admin(),
            "risk_score": risk_score,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
        
        # Print summary
        print_progress(f"Audit complete. Found {len(vulnerabilities)} vulnerabilities", "success")
        print_progress(f"Risk Score: {risk_score}/100", "info")
        
        # Show top vulnerabilities
        if vulnerabilities:
            print_progress("Top vulnerabilities:", "warning")
            for v in vulnerabilities[:5]:
                print(f"  - [{v.get('severity', 'UNKNOWN')}] {v.get('name', 'Unknown')}")
        
        # Save report
        if save_report:
            report = self.reporter.generate_report(results)
            report_file = self.reporter.save_report(report)
            print_progress(f"Report saved to: {report_file}", "success")
        
        return results
    
    def run_fix(self, vulnerabilities: list = None) -> list:
        """Run auto-fix on vulnerabilities"""
        if vulnerabilities is None:
            print_progress("Running audit before fixes...", "info")
            vulnerabilities = self.auditor.run_all_checks()
        
        if not vulnerabilities:
            print_progress("No vulnerabilities found!", "success")
            return []
        
        print_progress(f"Attempting to fix {len(vulnerabilities)} vulnerabilities...", "info")
        fixes = self.fixer.fix_all(vulnerabilities)
        
        print_progress(f"Applied {len(fixes)} fixes", "success")
        
        for fix in fixes:
            if fix.get('fixed'):
                print(f"  ✓ {fix.get('description', 'Fix applied')}")
        
        return fixes
    
    def run_monitor(self):
        """Start continuous monitoring"""
        print_progress("Starting continuous monitoring...", "info")
        print_progress("Press Ctrl+C to stop", "info")
        
        self.monitor = SecurityMonitor(
            self.config_loader,
            self.auditor,
            self.fixer,
            self.reporter
        )
        
        try:
            self.monitor.start()
        except KeyboardInterrupt:
            print_progress("Monitoring stopped by user", "info")
            self.monitor.stop()
    
    def start_real_time_protection(self):
        """Start real-time protection"""
        if not ADVANCED_AVAILABLE:
            print_progress("Advanced protection not available", "error")
            return
        
        print_progress("Starting Real-Time Protection...", "info")
        try:
            self.rtp = RealTimeProtection(self.config_loader)
            self.rtp.start_monitoring()
            print_progress("Real-Time Protection Active", "success")
        except Exception as e:
            print_progress(f"Failed to start real-time protection: {e}", "error")
    
    def stop_real_time_protection(self):
        """Stop real-time protection"""
        if self.rtp:
            self.rtp.stop_monitoring()
            print_progress("Real-Time Protection Stopped", "info")
    
    def scan_for_malware(self, path=None):
        """Scan for malware"""
        if not ADVANCED_AVAILABLE or not self.malware_scanner:
            print_progress("Malware scanner not available", "error")
            return []
        
        if not path:
            path = os.environ.get('USERPROFILE', 'C:\\')
        
        print_progress(f"Scanning for malware: {path}", "info")
        threats = self.malware_scanner.scan_directory(path)
        
        if threats:
            print_progress(f"Found {len(threats)} threats!", "error")
            for threat in threats:
                print(f"  🚨 {threat['file']}")
                for detection in threat['detections']:
                    print(f"     → {detection}")
        else:
            print_progress("No malware found", "success")
        
        return threats
    
    def scan_vulnerabilities(self):
        """Scan for software vulnerabilities"""
        if not ADVANCED_AVAILABLE or not self.vuln_scanner:
            print_progress("Vulnerability scanner not available", "error")
            return []
        
        print_progress("Scanning for vulnerabilities...", "info")
        vulns = self.vuln_scanner.scan_software()
        
        if vulns:
            print_progress(f"Found {len(vulns)} vulnerable applications", "warning")
            for vuln in vulns:
                print(f"  ⚠️ {vuln['software']} {vuln['version']}")
                for cve in vuln['vulnerabilities']:
                    print(f"     → {cve}")
        else:
            print_progress("No vulnerabilities found", "success")
        
        return vulns
    
    def analyze_behavior(self):
        """Analyze system behavior for anomalies"""
        if not ADVANCED_AVAILABLE or not self.behavior_analyzer:
            print_progress("Behavioral analyzer not available", "error")
            return []
        
        print_progress("Analyzing system behavior...", "info")
        anomalies = self.behavior_analyzer.detect_anomalies()
        
        if anomalies:
            print_progress(f"Found {len(anomalies)} anomalous processes", "warning")
            for anomaly in anomalies:
                print(f"  ⚠️ {anomaly['name']} (CPU: {anomaly['cpu']}%, Memory: {anomaly['memory']}%)")
        else:
            print_progress("No behavioral anomalies detected", "success")
        
        return anomalies
    
    def start_network_monitoring(self):
        """Start network traffic monitoring"""
        if not ADVANCED_AVAILABLE or not self.network_monitor:
            print_progress("Network monitor not available", "error")
            return
        
        print_progress("Starting network monitoring...", "info")
        try:
            self.network_monitor.start_capture()
            print_progress("Network monitoring active", "success")
        except Exception as e:
            print_progress(f"Failed to start network monitoring: {e}", "error")
    
    def _calculate_risk_score(self, vulnerabilities: list) -> int:
        """Calculate risk score from vulnerabilities"""
        weights = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1
        }
        
        total = sum(weights.get(v.get('severity', 'LOW'), 1) for v in vulnerabilities)
        return min(100, total * 2)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Security Agent - Autonomous PC Security Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/agent.py --audit           # Run security audit
  python src/agent.py --audit --report  # Audit with report
  python src/agent.py --fix             # Auto-fix vulnerabilities
  python src/agent.py --monitor         # Start continuous monitoring
  python src/agent.py --rtp             # Start real-time protection
  python src/agent.py --malware-scan    # Scan for malware
  python src/agent.py --vuln-scan       # Scan for vulnerabilities
        """
    )
    
    parser.add_argument('--audit', action='store_true', help='Run security audit')
    parser.add_argument('--fix', action='store_true', help='Auto-fix vulnerabilities')
    parser.add_argument('--monitor', action='store_true', help='Start continuous monitoring')
    parser.add_argument('--report', action='store_true', help='Generate report (with audit)')
    parser.add_argument('--config', default=DEFAULT_CONFIG_DIR, help='Config directory path')
    
    # Advanced features
    parser.add_argument('--rtp', action='store_true', help='Start real-time protection')
    parser.add_argument('--malware-scan', action='store_true', help='Scan for malware')
    parser.add_argument('--vuln-scan', action='store_true', help='Scan for vulnerabilities')
    parser.add_argument('--behavior', action='store_true', help='Analyze system behavior')
    parser.add_argument('--network-monitor', action='store_true', help='Start network monitoring')
    
    args = parser.parse_args()
    
    # Create agent
    agent = SecurityAgent(config_dir=args.config)
    
    # Run requested actions
    if args.audit:
        agent.run_audit(save_report=args.report)
    elif args.fix:
        agent.run_fix()
    elif args.monitor:
        agent.run_monitor()
    elif args.rtp:
        try:
            agent.start_real_time_protection()
            input("Press Enter to stop...\n")
            agent.stop_real_time_protection()
        except KeyboardInterrupt:
            agent.stop_real_time_protection()
    elif args.malware_scan:
        agent.scan_for_malware()
    elif args.vuln_scan:
        agent.scan_vulnerabilities()
    elif args.behavior:
        agent.analyze_behavior()
    elif args.network_monitor:
        try:
            agent.start_network_monitoring()
            input("Press Enter to stop...\n")
        except KeyboardInterrupt:
            pass
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
