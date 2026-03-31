"""Utility functions for Security Agent"""

import os
import sys
import logging
import platform
import subprocess
import json
import yaml
import requests  # ADDED: Missing import
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Try to import colorama for Windows color support
try:
    import colorama
    colorama.init()
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False


class Logger:
    """Custom logger for Security Agent"""
    
    def __init__(self, name: str, log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        
        # File handler
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
    
    def get_logger(self):
        return self.logger


class ConfigLoader:
    """Load and manage configuration"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.settings = {}
        self.rules = {}
        self.load_all()
    
    def load_all(self) -> Dict[str, Any]:
        """Load all configuration files"""
        # Load settings.yaml
        settings_path = self.config_dir / "settings.yaml"
        if settings_path.exists():
            with open(settings_path, 'r', encoding='utf-8') as f:
                self.settings = yaml.safe_load(f) or {}
        
        # Load rules.json
        rules_path = self.config_dir / "rules.json"
        if rules_path.exists():
            with open(rules_path, 'r', encoding='utf-8') as f:
                self.rules = json.load(f) or {}
        
        return {
            "settings": self.settings,
            "rules": self.rules
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key"""
        keys = key.split('.')
        value = self.settings
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def get_rule(self, key: str, default: Any = None) -> Any:
        """Get rule value by key"""
        return self.rules.get(key, default)


class SystemInfo:
    """System information utilities"""
    
    @staticmethod
    def get_os() -> str:
        """Get operating system name"""
        return platform.system()
    
    @staticmethod
    def get_os_version() -> str:
        """Get OS version"""
        return platform.version()
    
    @staticmethod
    def get_hostname() -> str:
        """Get computer hostname"""
        return platform.node()
    
    @staticmethod
    def get_username() -> str:
        """Get current username"""
        return os.environ.get('USERNAME', os.environ.get('USER', 'unknown'))
    
    @staticmethod
    def is_admin() -> bool:
        """Check if running with administrator privileges"""
        if platform.system() == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0
    
    @staticmethod
    def run_powershell(command: str, timeout: int = 30) -> str:
        """Run PowerShell command and return output"""
        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "Timeout"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def run_cmd(command: str, timeout: int = 30) -> str:
        """Run CMD command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "Timeout"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def get_ip() -> str:
        """Get public IP address"""
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text.strip()
        except:
            return "Unable to determine"


def print_banner():
    """Print Security Agent banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🔒 SECURITY AGENT                         ║
║            Autonomous PC Security & Protection               ║
║                         v1.0.0                               ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_progress(message: str, status: str = "info"):
    """Print formatted progress message with color support"""
    colors = {
        "info": "\033[94m",     # Blue
        "success": "\033[92m",  # Green
        "warning": "\033[93m",  # Yellow
        "error": "\033[91m",    # Red
        "reset": "\033[0m"
    }
    
    # Check if we can use colors
    use_colors = False
    if sys.platform != "win32":  # Linux/Mac always support colors
        use_colors = True
    elif COLOR_SUPPORT:  # Windows with colorama
        use_colors = True
    
    if not use_colors:
        print(f"[{status.upper()}] {message}")
    else:
        print(f"{colors.get(status, colors['info'])}[{status.upper()}]{colors['reset']} {message}")
