"""
Simple Network Intrusion Detection System (NIDS)
CodeAlpha Cybersecurity Internship - Task 4
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
import datetime
import time

class NetworkIDS:
    def __init__(self):
        # Store connection attempts
        self.connection_attempts = defaultdict(int)
        self.port_scans = defaultdict(set)
        self.suspicious_ips = set()
        self.alert_log = []
        
        # Thresholds
        self.MAX_CONNECTIONS = 50
        self.MAX_PORTS = 20
        self.SUSPICIOUS_PORTS = [22, 23, 25, 135, 139, 445, 3389, 1433, 3306]
        
        print("=" * 60)
        print("NETWORK INTRUSION DETECTION SYSTEM")
        print("=" * 60)
        print("Monitoring for:")
        print("  - Port scans")
        print("  - Suspicious ports (SSH, Telnet, SMB, RDP)")
        print("  - SYN floods")
        print("  - ICMP floods")
        print("=" * 60)
        print("Press Ctrl+C to stop")
        print("=" * 60)
    
    def get_timestamp(self):
        """Get current timestamp"""
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def log_alert(self, message):
        """Log an alert"""
        timestamp = self.get_timestamp()
        alert = f"[{timestamp}] {message}"
        self.alert_log.append(alert)
        print(f"\n🚨 {alert}")
    
    def detect_port_scan(self, src_ip, dst_port):
        """Detect if someone is scanning ports"""
        self.port_scans[src_ip].add(dst_port)
        
        if len(self.port_scans[src_ip]) > self.MAX_PORTS:
            self.suspicious_ips.add(src_ip)
            self.log_alert(f"PORT SCAN detected from {src_ip}")
            self.log_alert(f"  Scanned {len(self.port_scans[src_ip])} different ports")
            return True
        return False
    
    def detect_suspicious_port(self, dst_port):
        """Check if traffic is going to suspicious ports"""
        return dst_port in self.SUSPICIOUS_PORTS
    
    def analyze_packet(self, packet):
        """Analyze each packet for suspicious activity"""
        if IP not in packet:
            return
        
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        
        # Check if it's a TCP packet
        if TCP in packet:
            tcp = packet[TCP]
            dst_port = tcp.dport
            src_port = tcp.sport
            
            # Detect port scanning (many different ports)
            if self.detect_port_scan(src_ip, dst_port):
                return
            
            # Alert on suspicious ports
            if self.detect_suspicious_port(dst_port):
                self.suspicious_ips.add(src_ip)
                port_names = {
                    22: "SSH", 23: "Telnet", 25: "SMTP",
                    135: "RPC", 139: "NetBIOS", 445: "SMB",
                    3389: "RDP", 1433: "MSSQL", 3306: "MySQL"
                }
                service = port_names.get(dst_port, f"Port {dst_port}")
                self.log_alert(f"Suspicious connection: {src_ip} → {dst_ip}:{dst_port} ({service})")
            
            # Detect SYN flood
            if tcp.flags == "S":
                self.connection_attempts[src_ip] += 1
                if self.connection_attempts[src_ip] > self.MAX_CONNECTIONS:
                    self.suspicious_ips.add(src_ip)
                    self.log_alert(f"SYN FLOOD detected from {src_ip}")
                    self.log_alert(f"  {self.connection_attempts[src_ip]} SYN packets sent")
        
        # Check for ICMP floods
        if ICMP in packet:
            self.connection_attempts[src_ip] += 1
            if self.connection_attempts[src_ip] > self.MAX_CONNECTIONS:
                self.suspicious_ips.add(src_ip)
                self.log_alert(f"ICMP FLOOD detected from {src_ip}")
                self.log_alert(f"  {self.connection_attempts[src_ip]} ICMP packets sent")
    
    def start_monitoring(self, count=0, timeout=60):
        """Start monitoring network traffic"""
        print(f"\n[+] Monitoring started at {self.get_timestamp()}")
        print(f"[+] Packet limit: {count if count > 0 else 'Unlimited'}")
        print(f"[+] Timeout: {timeout if timeout else 'None'}")
        print("-" * 60)
        
        try:
            scapy.sniff(
                count=count,
                prn=self.analyze_packet,
                store=False,
                timeout=timeout
            )
        except KeyboardInterrupt:
            print("\n\n[+] Stopped by user")
        except Exception as e:
            print(f"\n[!] Error: {e}")
        finally:
            self.print_summary()
    
    def print_summary(self):
        """Print a summary of alerts"""
        print("\n" + "=" * 60)
        print("NIDS SUMMARY REPORT")
        print("=" * 60)
        
        print(f"\n📊 Total Alerts: {len(self.alert_log)}")
        
        if self.suspicious_ips:
            print(f"\n🚨 Suspicious IPs Detected ({len(self.suspicious_ips)}):")
            for ip in self.suspicious_ips:
                print(f"  - {ip}")
        else:
            print("\n✅ No suspicious IPs detected")
        
        if self.port_scans:
            print("\n📡 Port Scan Activity:")
            for ip, ports in self.port_scans.items():
                if len(ports) > 10:
                    print(f"  - {ip}: scanned {len(ports)} ports")
        
        if self.alert_log:
            print("\n📝 Alert Log:")
            for alert in self.alert_log[-10:]:  # Show last 10 alerts
                print(f"  {alert}")
        
        print("\n" + "=" * 60)
    
    def save_report(self, filename="nids_report.txt"):
        """Save alerts to a file"""
        if self.alert_log:
            with open(filename, "w") as f:
                f.write("NIDS ALERT REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {self.get_timestamp()}\n")
                f.write(f"Total Alerts: {len(self.alert_log)}\n")
                f.write("=" * 50 + "\n\n")
                for alert in self.alert_log:
                    f.write(alert + "\n")
            print(f"\n[+] Report saved to {filename}")

def main():
    print("Network Intrusion Detection System (NIDS)")
    print("CodeAlpha Cybersecurity Internship - Task 4")
    print()
    
    print("Select monitoring mode:")
    print("1. Quick scan (30 seconds)")
    print("2. Standard scan (60 seconds)")
    print("3. Continuous scan (Ctrl+C to stop)")
    print("4. Custom (enter your own duration)")
    
    choice = input("\nEnter choice (1-4): ")
    
    nids = NetworkIDS()
    
    if choice == "1":
        nids.start_monitoring(timeout=30)
    elif choice == "2":
        nids.start_monitoring(timeout=60)
    elif choice == "3":
        nids.start_monitoring()
    elif choice == "4":
        seconds = int(input("Enter seconds to monitor: "))
        nids.start_monitoring(timeout=seconds)
    else:
        print("Invalid choice")
    
    # Ask to save report
    if nids.alert_log:
        save = input("\nSave alert report to file? (y/n): ")
        if save.lower() == 'y':
            nids.save_report()

if __name__ == "__main__":
    main()