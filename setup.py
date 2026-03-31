"""Setup configuration for Security Agent"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="security-agent",
    version="1.0.0",
    author="Zarafeen",
    author_email="your.email@example.com",
    description="Autonomous Security Agent for PC security auditing and remediation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Zarafeen/security-agent",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        'requests>=2.31.0',
        'pyyaml>=6.0',
        'psutil>=5.9.5',
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
        'schedule>=1.2.0',
    ],
    entry_points={
        'console_scripts': [
            'security-agent=src.agent:main',
        ],
    },
)
