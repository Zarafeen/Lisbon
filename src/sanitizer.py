"""
Input Sanitization Module - Prevents injection attacks
"""

import re
import os
from pathlib import Path
from typing import Optional, List, Any


class InputSanitizer:
    """Sanitize all user inputs to prevent injection attacks"""
    
    # Dangerous characters for shell commands
    SHELL_DANGEROUS_CHARS = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r', '\t', '{', '}', '[', ']']
    
    # Dangerous PowerShell patterns
    PS_DANGEROUS_PATTERNS = [
        r'Invoke-Expression',
        r'IEX\s*\(',
        r'\.\s*\(\s*[\'"\w]',
        r'Start-Process',
        r'Add-Type',
        r'\[System\.Reflection\.Assembly\]',
        r'DownloadString',
        r'WebClient',
        r'Net\.WebClient',
    ]
    
    # Dangerous command patterns
    CMD_DANGEROUS_PATTERNS = [
        r'&&',
        r'\|\|',
        r'>',
        r'>>',
        r'<',
        r'\|',
        r'%\w+%',
    ]
    
    @classmethod
    def sanitize_command(cls, text: str, allow_spaces: bool = True) -> str:
        """
        Sanitize text for use in shell commands
        
        Args:
            text: Input string to sanitize
            allow_spaces: Whether to preserve spaces
            
        Returns:
            Sanitized string safe for command execution
        """
        if not text:
            return ""
        
        # Remove dangerous characters
        for char in cls.SHELL_DANGEROUS_CHARS:
            text = text.replace(char, '')
        
        # Remove dangerous patterns
        for pattern in cls.CMD_DANGEROUS_PATTERNS:
            text = re.sub(pattern, '', text)
        
        # Remove multiple spaces if not allowed
        if not allow_spaces:
            text = re.sub(r'\s+', '', text)
        
        # Trim whitespace
        text = text.strip()
        
        return text
    
    @classmethod
    def sanitize_powershell(cls, text: str) -> str:
        """
        Sanitize text for PowerShell commands
        
        Args:
            text: Input string to sanitize
            
        Returns:
            Sanitized string safe for PowerShell
        """
        if not text:
            return ""
        
        # First apply basic command sanitization
        text = cls.sanitize_command(text)
        
        # Remove PowerShell-specific dangerous patterns
        for pattern in cls.PS_DANGEROUS_PATTERNS:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        # Escape single quotes
        text = text.replace("'", "''")
        
        # Remove PowerShell variables
        text = re.sub(r'\$[\w]+', '', text)
        
        return text
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> Optional[str]:
        """
        Sanitize filename to prevent path traversal
        
        Args:
            filename: Filename to sanitize
            
        Returns:
            Sanitized filename or None if invalid
        """
        if not filename:
            return None
        
        # Remove path separators
        filename = filename.replace('/', '_').replace('\\', '_')
        
        # Remove directory traversal attempts
        filename = filename.replace('..', '')
        
        # Remove dangerous characters
        dangerous = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'"]
        for char in dangerous:
            filename = filename.replace(char, '')
        
        # Remove null bytes
        filename = filename.replace('\x00', '')
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
        
        # Ensure not empty
        if not filename or filename.strip() == '':
            return None
        
        return filename.strip()
    
    @classmethod
    def sanitize_path(cls, base_path: str, user_path: str) -> Optional[str]:
        """
        Validate and sanitize a file path to prevent directory traversal
        
        Args:
            base_path: The base directory to restrict to
            user_path: User-provided path to validate
            
        Returns:
            Sanitized absolute path or None if invalid
        """
        if not user_path:
            return None
        
        # Normalize base path
        base = os.path.realpath(os.path.abspath(base_path))
        
        # Try to resolve the user path relative to base
        try:
            # Remove dangerous patterns
            safe_path = cls.sanitize_filename(user_path)
            if not safe_path:
                return None
            
            # Join with base
            full_path = os.path.join(base, safe_path)
            real_path = os.path.realpath(os.path.abspath(full_path))
            
            # Check if path is within base directory
            if real_path.startswith(base):
                return real_path
            else:
                return None
                
        except Exception:
            return None
    
    @classmethod
    def sanitize_process_name(cls, name: str) -> Optional[str]:
        """
        Sanitize process name for safe lookup
        
        Args:
            name: Process name to sanitize
            
        Returns:
            Sanitized process name
        """
        if not name:
            return None
        
        # Remove path separators
        name = name.replace('/', '').replace('\\', '')
        
        # Keep only alphanumeric, dot, underscore, hyphen
        name = re.sub(r'[^a-zA-Z0-9._-]', '', name)
        
        # Remove extension if present (we'll add .exe later)
        if name.lower().endswith('.exe'):
            name = name[:-4]
        
        # Limit length
        if len(name) > 100:
            name = name[:100]
        
        return name if name else None
    
    @classmethod
    def sanitize_port(cls, port: Any) -> Optional[int]:
        """
        Validate and sanitize port number
        
        Args:
            port: Port number to validate
            
        Returns:
            Valid port number or None
        """
        try:
            port_int = int(port)
            if 1 <= port_int <= 65535:
                return port_int
            return None
        except (ValueError, TypeError):
            return None
    
    @classmethod
    def sanitize_ip(cls, ip: str) -> Optional[str]:
        """
        Validate IP address format
        
        Args:
            ip: IP address to validate
            
        Returns:
            Valid IP address or None
        """
        if not ip:
            return None
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        # Simple validation (doesn't check each octet range)
        if re.match(ipv4_pattern, ip):
            # Check each octet
            octets = ip.split('.')
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    return None
            return ip
        
        # Could add IPv6 validation here if needed
        return None
    
    @classmethod
    def sanitize_regex(cls, pattern: str) -> Optional[str]:
        """
        Sanitize regex pattern to prevent ReDoS attacks
        
        Args:
            pattern: Regex pattern to sanitize
            
        Returns:
            Sanitized pattern or None
        """
        if not pattern:
            return None
        
        # Remove catastrophic backtracking patterns
        dangerous_patterns = [
            r'\(\.\*\)\+',
            r'\(\.\+\?\)\*',
            r'\(\w\+\|\w\+\)\+',
        ]
        
        for dangerous in dangerous_patterns:
            if re.search(dangerous, pattern):
                return None
        
        # Limit length
        if len(pattern) > 1000:
            pattern = pattern[:1000]
        
        return pattern
    
    @classmethod
    def sanitize_url(cls, url: str) -> Optional[str]:
        """
        Validate and sanitize URL
        
        Args:
            url: URL to validate
            
        Returns:
            Valid URL or None
        """
        if not url:
            return None
        
        # Basic URL validation
        url_pattern = r'^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(:[0-9]{1,5})?(/.*)?$'
        
        if re.match(url_pattern, url, re.IGNORECASE):
            # Remove potential script injection
            url = re.sub(r'<script.*?>.*?</script>', '', url, flags=re.IGNORECASE)
            return url
        
        return None
    
    @classmethod
    def validate_all(cls, **kwargs) -> dict:
        """
        Validate multiple inputs at once
        
        Args:
            **kwargs: Key-value pairs to validate
            
        Returns:
            Dictionary with validation results
        """
        results = {}
        
        validators = {
            'command': cls.sanitize_command,
            'ps_command': cls.sanitize_powershell,
            'filename': cls.sanitize_filename,
            'process': cls.sanitize_process_name,
            'port': cls.sanitize_port,
            'ip': cls.sanitize_ip,
            'url': cls.sanitize_url,
        }
        
        for key, value in kwargs.items():
            for type_name, validator in validators.items():
                if type_name in key.lower():
                    results[key] = validator(value)
                    break
            else:
                # Default sanitization
                results[key] = cls.sanitize_command(str(value))
        
        return results


class SafeCommandExecutor:
    """
    Safe command execution wrapper
    """
    
    def __init__(self, system_info):
        self.system = system_info
        self.sanitizer = InputSanitizer
    
    def run_powershell_safe(self, command: str, timeout: int = 30) -> str:
        """
        Execute PowerShell command safely
        
        Args:
            command: PowerShell command to execute
            timeout: Timeout in seconds
            
        Returns:
            Command output
        """
        # Sanitize the command
        safe_command = self.sanitizer.sanitize_powershell(command)
        
        if not safe_command:
            return "Error: Command sanitization failed"
        
        # Log what we're executing (for debugging)
        # Do NOT log sensitive data
        
        # Execute
        return self.system.run_powershell(safe_command, timeout)
    
    def run_cmd_safe(self, command: str, timeout: int = 30) -> str:
        """
        Execute CMD command safely
        
        Args:
            command: CMD command to execute
            timeout: Timeout in seconds
            
        Returns:
            Command output
        """
        # Sanitize the command
        safe_command = self.sanitizer.sanitize_command(command)
        
        if not safe_command:
            return "Error: Command sanitization failed"
        
        # Execute
        return self.system.run_cmd(safe_command, timeout)
