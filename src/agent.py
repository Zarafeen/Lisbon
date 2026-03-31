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


class SecurityAgent:
    """Main security agent orchestrator"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_loader = ConfigLoader(str(self.config_dir))
        self.system = SystemInfo()
        
        # Initialize components
        self.auditor = SecurityAuditor(self.config_loader)
        self.fixer = SecurityFixer(self.config_loader)
        self.reporter = SecurityReporter(self.config_loader)
        self.monitor = None
        
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
        """
    )
    
    parser.add_argument('--audit', action='store_true', help='Run security audit')
    parser.add_argument('--fix', action='store_true', help='Auto-fix vulnerabilities')
    parser.add_argument('--monitor', action='store_true', help='Start continuous monitoring')
    parser.add_argument('--report', action='store_true', help='Generate report (with audit)')
    parser.add_argument('--config', default='config', help='Config directory path')
    
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
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
