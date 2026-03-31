"""Security Monitor - Continuous monitoring"""

import time
import threading
import datetime
from typing import Dict, Any, Callable
import schedule

from src.utils import Logger


class SecurityMonitor:
    """Continuous security monitoring"""
    
    def __init__(self, config, auditor, fixer, reporter):
        self.config = config
        self.auditor = auditor
        self.fixer = fixer
        self.reporter = reporter
        self.logger = Logger("monitor").get_logger()
        self.running = False
        self.monitor_thread = None
    
    def start(self):
        """Start continuous monitoring"""
        interval = self.config.get('monitor.interval_seconds', 300)
        self.running = True
        
        self.logger.info(f"Starting monitoring (interval: {interval}s)")
        
        # Run initial check
        self._monitor_cycle()
        
        # Schedule regular checks
        schedule.every(interval).seconds.do(self._monitor_cycle)
        
        self.monitor_thread = threading.Thread(target=self._run_scheduler)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.logger.info("Monitoring stopped")
    
    def _run_scheduler(self):
        """Run scheduler loop"""
        while self.running:
            schedule.run_pending()
            time.sleep(1)
    
    def _monitor_cycle(self):
        """Run one monitoring cycle"""
        try:
            self.logger.info("Running monitoring cycle...")
            
            # Run audit
            vulnerabilities = self.auditor.run_all_checks()
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(vulnerabilities)
            
            # Auto-fix if configured
            if self.config.get('fix.auto_apply', True) and vulnerabilities:
                fixes = self.fixer.fix_all(vulnerabilities)
                if fixes:
                    self.logger.info(f"Applied {len(fixes)} fixes")
            
            # Save report
            if self.config.get('reporting.save_reports', True):
                results = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "system": self.auditor.system.get_os(),
                    "risk_score": risk_score,
                    "total_vulnerabilities": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities
                }
                report = self.reporter.generate_report(results)
                self.reporter.save_report(report)
            
            self.logger.info(f"Cycle complete. Risk score: {risk_score}/100")
            
        except Exception as e:
            self.logger.error(f"Monitor cycle failed: {e}")
    
    def _calculate_risk_score(self, vulnerabilities: list) -> int:
        """Calculate risk score"""
        weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        total = sum(weights.get(v.get('severity', 'LOW'), 1) for v in vulnerabilities)
        return min(100, total * 2)
