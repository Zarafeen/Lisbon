"""Security Reporter - Generates security reports"""

import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.utils import Logger


class SecurityReporter:
    """Generate security reports in various formats"""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger("reporter").get_logger()
        self.report_dir = Path(config.get('reporting.report_directory', './reports'))
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_report(self, audit_results: Dict[str, Any], fixes: Optional[List] = None) -> str:
        """Generate report in configured format"""
        report_format = self.config.get('reporting.report_format', 'txt')
        
        if report_format == 'txt':
            return self._generate_txt_report(audit_results, fixes)
        elif report_format == 'json':
            return self._generate_json_report(audit_results, fixes)
        elif report_format == 'html':
            return self._generate_html_report(audit_results, fixes)
        else:
            return self._generate_txt_report(audit_results, fixes)
    
    def _generate_txt_report(self, audit_results: Dict, fixes: Optional[List] = None) -> str:
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
    
    def _generate_json_report(self, audit_results: Dict, fixes: Optional[List] = None) -> str:
        """Generate JSON format report"""
        report_data = {
            "timestamp": audit_results.get('timestamp'),
            "system": audit_results.get('system'),
            "hostname": audit_results.get('hostname'),
            "username": audit_results.get('username'),
            "is_admin": audit_results.get('is_admin'),
            "risk_score": audit_results.get('risk_score'),
            "total_vulnerabilities": audit_results.get('total_vulnerabilities'),
            "vulnerabilities": audit_results.get('vulnerabilities', []),
            "fixes_applied": fixes if fixes else []
        }
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_html_report(self, audit_results: Dict, fixes: Optional[List] = None) -> str:
        """Generate HTML format report"""
        timestamp = audit_results.get('timestamp', datetime.datetime.now().isoformat())
        risk_score = audit_results.get('risk_score', 0)
        
        # Determine risk class
        if risk_score >= 70:
            risk_class = "critical"
        elif risk_score >= 50:
            risk_class = "high"
        elif risk_score >= 30:
            risk_class = "medium"
        else:
            risk_class = "low"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Agent Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 20px; }}
        .risk-score {{ font-size: 24px; padding: 10px; border-radius: 5px; margin: 10px 0; text-align: center; font-weight: bold; }}
        .risk-critical {{ background: #ff4444; color: white; }}
        .risk-high {{ background: #ff8800; color: white; }}
        .risk-medium {{ background: #ffcc00; color: #333; }}
        .risk-low {{ background: #44ff44; color: #333; }}
        .vulnerability {{ border-left: 4px solid #ff4444; margin: 10px 0; padding: 10px; background: #fff0f0; border-radius: 4px; }}
        .fix {{ border-left: 4px solid #44ff44; margin: 10px 0; padding: 10px; background: #f0fff0; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; }}
        .timestamp {{ color: #666; font-size: 12px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #ff4444; color: white; }}
        .badge-high {{ background: #ff8800; color: white; }}
        .badge-medium {{ background: #ffcc00; }}
        .badge-low {{ background: #44ff44; }}
        footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Agent Report</h1>
        <div class="timestamp">Generated: {timestamp}</div>
        <div class="timestamp">System: {audit_results.get('system', 'Unknown')} | Host: {audit_results.get('hostname', 'Unknown')}</div>
        <div class="timestamp">User: {audit_results.get('username', 'Unknown')} | Admin: {'Yes' if audit_results.get('is_admin') else 'No'}</div>
        
        <div class="risk-score risk-{risk_class}">
            Risk Score: {risk_score}/100
        </div>
        
        <h2>📊 Summary</h2>
        <table>
            <tr><th>Total Vulnerabilities</th><td>{audit_results.get('total_vulnerabilities', 0)}</td></tr>
            <tr><th>Fixes Applied</th><td>{len(fixes) if fixes else 0}</td></tr>
        </table>
        
        <h2>⚠️ Vulnerabilities</h2>"""
        
        for vuln in audit_results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'UNKNOWN').lower()
            html += f"""
        <div class="vulnerability">
            <span class="badge badge-{severity}">[{vuln.get('severity', 'UNKNOWN')}]</span>
            <strong>{vuln.get('name', 'Unknown')}</strong><br>
            {vuln.get('details', 'No details')}
        </div>"""
        
        if fixes:
            html += """
        <h2>🔧 Fixes Applied</h2>"""
            for fix in fixes:
                html += f"""
        <div class="fix">
            ✓ {fix.get('description', 'Fix applied')}
        </div>"""
        
        if not audit_results.get('vulnerabilities'):
            html += """
        <div style="text-align: center; padding: 40px; background: #e8f5e9; border-radius: 10px;">
            🎉 No vulnerabilities found! System is secure.
        </div>"""
        
        html += """
        <h2>📝 Recommendations</h2>
        <ul>"""
        
        if audit_results.get('vulnerabilities'):
            html += """
            <li>Run with --fix to automatically resolve issues</li>
            <li>Review and apply remaining fixes manually</li>
            <li>Schedule regular security audits</li>
            <li>Keep system and software updated</li>"""
        else:
            html += """
            <li>✓ System appears secure!</li>
            <li>Continue regular maintenance</li>
            <li>Run weekly audits for ongoing security</li>"""
        
        html += """
        </ul>
        <footer>
            Built with 🛡️ Security Agent | Report generated automatically
        </footer>
    </div>
</body>
</html>"""
        return html
    
    def save_report(self, report: str, filename: Optional[str] = None) -> Path:
        """Save report to file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_format = self.config.get('reporting.report_format', 'txt')
            filename = f"security_report_{timestamp}.{report_format}"
        
        report_path = self.report_dir / filename
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.logger.info(f"Report saved to {report_path}")
        
        # Clean up old reports
        self._cleanup_old_reports()
        
        return report_path
    
    def _cleanup_old_reports(self):
        """Delete reports older than retention days"""
        retention_days = self.config.get('reporting.retention_days', 30)
        if retention_days <= 0:
            return
        
        cutoff = datetime.datetime.now() - datetime.timedelta(days=retention_days)
        
        for report_file in self.report_dir.glob("security_report_*"):
            try:
                file_time = datetime.datetime.fromtimestamp(report_file.stat().st_mtime)
                if file_time < cutoff:
                    report_file.unlink()
                    self.logger.info(f"Deleted old report: {report_file.name}")
            except Exception as e:
                self.logger.error(f"Could not delete {report_file.name}: {e}")
