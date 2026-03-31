"""Threat logging and reporting system"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

class ThreatLogger:
    """Log and track security threats"""
    
    def __init__(self, db_path="threats.db"):
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for threat tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                severity TEXT,
                description TEXT,
                file_path TEXT,
                process_name TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def log_threat(self, threat_type, severity, description, **kwargs):
        """Log a detected threat"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threats (timestamp, type, severity, description, file_path, process_name, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            threat_type,
            severity,
            description,
            kwargs.get('file_path', ''),
            kwargs.get('process_name', ''),
            json.dumps(kwargs.get('details', {}))
        ))
        
        conn.commit()
        conn.close()
        
        # Also log to file
        with open("threat_log.json", "a") as f:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "type": threat_type,
                "severity": severity,
                "description": description,
                **kwargs
            }
            json.dump(log_entry, f)
            f.write("\n")
