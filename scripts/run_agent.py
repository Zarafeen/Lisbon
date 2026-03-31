#!/usr/bin/env python
"""Quick launcher for Security Agent with Advanced Features"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def main():
    print("🔒 Security Agent - Advanced Edition")
    print("=" * 60)
    print("\nOptions:")
    print("  1. Quick Security Audit")
    print("  2. Full Security Fix")
    print("  3. Continuous Monitoring")
    print("  4. REAL-TIME PROTECTION (NEW!)")
    print("  5. MALWARE SCAN (NEW!)")
    print("  6. VULNERABILITY SCAN (NEW!)")
    print("  7. NETWORK MONITOR (NEW!)")
    print("  8. BEHAVIORAL ANALYSIS (NEW!)")
    print("  9. FULL SECURITY SUITE (All Features)")
    print("  10. Exit")
    
    choice = input("\nSelect option (1-10): ").strip()
    
    from src.agent import SecurityAgent
    agent = SecurityAgent()
    
    if choice == "1":
        agent.run_audit(save_report=True)
        
    elif choice == "2":
        agent.run_fix()
        
    elif choice == "3":
        agent.run_monitor()
        
    elif choice == "4":
        print("\n🔒 Starting Real-Time Protection...")
        print("This will monitor file system and processes for threats")
        print("Press Ctrl+C to stop\n")
        try:
            agent.start_real_time_protection()
            input("Press Enter to stop...\n")
            agent.stop_real_time_protection()
        except KeyboardInterrupt:
            agent.stop_real_time_protection()
            
    elif choice == "5":
        path = input("Enter path to scan (default: User Profile): ").strip()
        if not path:
            path = None
        threats = agent.scan_for_malware(path)
        
    elif choice == "6":
        vulns = agent.scan_vulnerabilities()
        
    elif choice == "7":
        print("\n🌐 Starting Network Monitoring...")
        print("Analyzing network traffic for threats")
        print("Press Ctrl+C to stop\n")
        try:
            agent.start_network_monitoring()
            input("Press Enter to stop...\n")
        except KeyboardInterrupt:
            print("\nMonitoring stopped")
            
    elif choice == "8":
        anomalies = agent.analyze_behavior()
        
    elif choice == "9":
        print("\n🛡️ FULL SECURITY SUITE ACTIVATED")
        print("=" * 60)
        
        # Run all features
        agent.run_audit(save_report=True)
        print("\n" + "="*60)
        
        agent.scan_for_malware()
        print("\n" + "="*60)
        
        agent.scan_vulnerabilities()
        print("\n" + "="*60)
        
        agent.analyze_behavior()
        print("\n" + "="*60)
        
        print("\n🚨 Starting Real-Time Protection...")
        try:
            agent.start_real_time_protection()
            print("\nPress Ctrl+C to stop all protection...")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            agent.stop_real_time_protection()
            print("\n✅ All protection stopped")
            
    else:
        print("Exiting...")

if __name__ == "__main__":
    import time
    main()
