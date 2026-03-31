#!/usr/bin/env python
"""Quick launcher for Security Agent"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def main():
    print("🔒 Security Agent Launcher")
    print("=" * 50)
    print("\nOptions:")
    print("  1. Quick Security Audit")
    print("  2. Full Security Fix")
    print("  3. Continuous Monitoring")
    print("  4. Generate Report")
    print("  5. Exit")
    
    choice = input("\nSelect option (1-5): ").strip()
    
    from src.agent import SecurityAgent
    agent = SecurityAgent()
    
    if choice == "1":
        agent.run_audit(save_report=True)
    elif choice == "2":
        agent.run_fix()
    elif choice == "3":
        agent.run_monitor()
    elif choice == "4":
        results = agent.run_audit(save_report=True)
        print(f"\nReport saved to ./reports/")
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()
