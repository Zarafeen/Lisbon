"""Security Monitor - Continuous monitoring"""

import time
import threading
import datetime
from typing import Dict, Any, Callable, List

# Try to import schedule
try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False
    schedule = None  # Placeholder

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
        self.alert_callbacks = []
        self.last_alert_time = 0
        self.alert_cooldown = 300  # 5 minutes
        self.last_risk_score = 0
    
    def start(self):
        """Start continuous monitoring"""
        interval = self.config.get('monitor.interval_seconds', 300)
        self.running = True
        
        self.logger.info(f"Starting monitoring (interval: {interval}s)")
        
        # Run initial check
        self._monitor_cycle()
        
        # Schedule regular checks
        if SCHEDULE_AVAILABLE:
            schedule.every(interval).seconds.do(self._monitor_cycle)
            self.monitor_thread = threading.Thread(target=self._run_scheduler)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.logger.info("Monitoring scheduler started")
        else:
            self.logger.warning("Schedule library not installed, using simple loop")
            self.monitor_thread = threading.Thread(target=self._simple_loop, args=(interval,))
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.logger.info("Monitoring stopped")
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for alerts"""
        self.alert_callbacks.append(callback)
        self.logger.info(f"Registered alert callback: {callback.__name__}")
    
    def _run_scheduler(self):
        """Run scheduler loop"""
        self.logger.debug("Scheduler thread started")
        while self.running:
            schedule.run_pending()
            time.sleep(1)
        self.logger.debug("Scheduler thread stopped")
    
    def _simple_loop(self, interval):
        """Simple monitoring loop without schedule library"""
        self.logger.debug(f"Simple loop started (interval: {interval}s)")
        while self.running:
            time.sleep(interval)
            if self.running:
                self._monitor_cycle()
        self.logger.debug("Simple loop stopped")
    
    def _monitor_cycle(self):
        """Run one monitoring cycle"""
        try:
            self.logger.debug("Running monitoring cycle...")
            
            # Run audit
            vulnerabilities = self.auditor.run_all_checks()
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(vulnerabilities)
            self.last_risk_score = risk_score
            
            # Check for critical issues and send alerts
            if self.config.get('monitor.alert_on_critical', True):
                self._send_alerts(vulnerabilities, risk_score)
            
            # Auto-fix if configured
            if self.config.get('fix.auto_apply', True) and vulnerabilities:
                fixes = self.fixer.fix_all(vulnerabilities)
                if fixes:
                    self.logger.info(f"Applied {len(fixes)} fixes during monitoring")
            
            # Save report
            if self.config.get('reporting.save_reports', True):
                results = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "system": self.auditor.system.get_os(),
                    "hostname": self.auditor.system.get_hostname(),
                    "risk_score": risk_score,
                    "total_vulnerabilities": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities
                }
                report = self.reporter.generate_report(results)
                self.reporter.save_report(report)
            
            # Log summary
            if vulnerabilities:
                self.logger.info(f"Cycle complete. Found {len(vulnerabilities)} issues, Risk: {risk_score}/100")
            else:
                self.logger.debug(f"Cycle complete. System clean, Risk: {risk_score}/100")
            
        except Exception as e:
            self.logger.error(f"Monitor cycle failed: {e}")
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate risk score"""
        weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        total = sum(weights.get(v.get('severity', 'LOW'), 1) for v in vulnerabilities)
        return min(100, total * 2)
    
    def _send_alerts(self, vulnerabilities: List[Dict], risk_score: int):
        """Send alerts for critical issues with cooldown"""
        current_time = time.time()
        
        # Check cooldown
        if current_time - self.last_alert_time < self.alert_cooldown:
            return
        
        # Check for critical issues
        critical_issues = [v for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']]
        
        if critical_issues or risk_score > 70:
            self.last_alert_time = current_time
            self.logger.warning(f"🚨 ALERT! Risk score: {risk_score}/100, Critical issues: {len(critical_issues)}")
            
            for issue in critical_issues[:5]:  # Log first 5
                self.logger.warning(f"  - {issue.get('name')}: {issue.get('details')}")
            
            # Call registered callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(critical_issues, risk_score)
                except Exception as e:
                    self.logger.error(f"Alert callback failed: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            "running": self.running,
            "last_risk_score": self.last_risk_score,
            "alert_callbacks": len(self.alert_callbacks),
            "schedule_available": SCHEDULE_AVAILABLE,
            "timestamp": datetime.datetime.now().isoformat()
                }
