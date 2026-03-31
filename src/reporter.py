"""Security Reporter - Generates security reports"""

import json
import datetime
from pathlib import Path
from typing import Dict, Any, List

from src.utils import Logger


class SecurityReporter:
    """Generate security reports in various formats"""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger("reporter").get_logger()
        self.report_dir = Path(config.get('reporting.report_directory', './reports'))
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_report(self, audit_results: Dict[str, Any], fixes: List = None) -> str:
        """Generate report in configured format"""
        report_format = self.config.get('reporting.report_format', 'txt')
        
        if report_format == 'txt':
            return self._generate_txt_report(audit_results, fixes)
        elif report_format == 'json':
            return self._generate_json_report(audit_results, fixes)
        else:
            return self._generate_txt_report(audit_results, fixes)
    
    def _generate_txt_report(self, audit_results: Dict, fixes: List = None) -> str:
        """Generate text format report"""
        timestamp = audit_results.get('timestamp', datetime.datetime.now().isoformat())
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         SECURITY AGENT REPORT                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

Generated: {timestamp}
System: {audit_results.get('system', 'Unknown')}
Hostname: {audit_results.get('hostname', 'Unknown')}
User: {audit_results.get('username', 'Unknown')}
Admin: {'Yes' if audit_results.get('is_admin') else 'No'}

Risk Score: {audit_results.get('risk_score', 0)}/100
Vulnerabilities Found: {audit_results.get('total_vulnerabilities', 0)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VULNERABILITIES:
"""
        
        for vuln in audit_results.get('vulnerabilities', []):
            report += f"""
  [{vuln.get('severity', 'UNKNOWN')}] {vuln.get('name', 'Unknown')}
      → {vuln.get('details', 'No details')}
"""
        
        if fixes:
            report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FIXES APPLIED:
"""
            for fix in fixes:
                report += f"  ✓ {fix.get('description', 'Fix applied')}\n"
        
        report += """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECOMMENDATIONS:
"""
        
        if audit_results.get('vulnerabilities'):
            report += """
  • Run with --fix to automatically resolve issues
  • Review and apply remaining fixes manually
  • Schedule regular security audits
  • Keep system and software updated
"""
        else:
            report += """
  ✓ System appears secure!
  • Continue regular maintenance
  • Run weekly audits for ongoing security
"""
        
        return report
    
    def _generate_json_report(self, audit_results: Dict, fixes: List = None) -> str:
        """Generate JSON format report"""
        report_data = {
            "timestamp": audit_results.get('timestamp'),
            "system": audit_results.get('system'),
            "hostname": audit_results.get('hostname'),
            "risk_score": audit_results.get('risk_score'),
            "total_vulnerabilities": audit_results.get('total_vulnerabilities'),
            "vulnerabilities": audit_results.get('vulnerabilities', []),
            "fixes_applied": fixes if fixes else []
        }
        return json.dumps(report_data, indent=2, default=str)
    
    def save_report(self, report: str, filename: str = None) -> Path:
        """Save report to file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_format = self.config.get('reporting.report_format', 'txt')
            filename = f"security_report_{timestamp}.{report_format}"
        
        report_path = self.report_dir / filename
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.logger.info(f"Report saved to {report_path}")
        return report_path
