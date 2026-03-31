"""Setup configuration for Security Agent"""

from setuptools import setup, find_packages
import os

# Read the long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements from requirements.txt (optional, but keeps consistency)
def read_requirements():
    """Read requirements from requirements.txt"""
    requirements = []
    req_file = "requirements.txt"
    if os.path.exists(req_file):
        with open(req_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Handle comments and empty lines
                    if not line.startswith("#"):
                        requirements.append(line)
    return requirements

setup(
    name="security-agent",
    version="1.0.0",
    author="Zarafeen",
    author_email="zarafeen@example.com",  # Consider using a real email
    description="Autonomous Security Agent for PC security auditing and remediation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Zarafeen/Lisbon",  # Fixed URL
    project_urls={
        "Bug Tracker": "https://github.com/Zarafeen/Lisbon/issues",
        "Documentation": "https://github.com/Zarafeen/Lisbon/wiki",
        "Source Code": "https://github.com/Zarafeen/Lisbon",
    },
    packages=find_packages(include=["src", "src.*"]),
    include_package_data=True,
    package_data={
        "src": ["*.py"],
        "config": ["*.yaml", "*.json", "*.yar"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[
        'requests>=2.31.0',
        'pyyaml>=6.0',
        'psutil>=5.9.5',
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'schedule>=1.2.0',
        'watchdog>=3.0.0',      # Real-time file monitoring
        'yara-python>=4.3.0',   # Malware detection
        'cryptography>=41.0.0', # Encryption utilities
        'netifaces>=0.11.0',    # Network interface detection
        'python-dateutil>=2.8.0',
    ],
    extras_require={
        'network': [
            'scapy>=2.5.0',      # Network packet analysis
        ],
        'ml': [
            'scikit-learn>=1.3.0',  # ML-based behavioral analysis
            'numpy>=1.24.0',        # ML dependency
            'pandas>=2.1.0',        # ML dependency
        ],
        'web': [
            'flask>=2.3.0',      # Web dashboard
            'jinja2>=3.1.0',     # HTML reports
        ],
        'windows': [
            'wmi>=1.5.1',        # Windows Management
            'pywin32>=306',      # Windows API
        ],
        'full': [
            'scapy>=2.5.0',
            'scikit-learn>=1.3.0',
            'numpy>=1.24.0',
            'pandas>=2.1.0',
            'flask>=2.3.0',
            'jinja2>=3.1.0',
            'wmi>=1.5.1',
            'pywin32>=306',
        ],
    },
    entry_points={
        'console_scripts': [
            'security-agent=src.agent:main',
            'security-audit=src.agent:main',
            'security-monitor=src.agent:main',
        ],
    },
    keywords="security, audit, vulnerability, malware, ransomware, protection, monitoring",
    zip_safe=False,
)
