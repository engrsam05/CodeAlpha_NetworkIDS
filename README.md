## CodeAlpha Cybersecurity Internship - Task 4

### Project Description

This project is a simple Network Intrusion Detection System (NIDS) developed using Python and Scapy. It monitors live network traffic and detects suspicious activities such as port scans, SYN flood attacks, ICMP flood attacks, and connections to commonly targeted ports.

## Features

- Real-time packet monitoring
- Port scan detection
- Detection of suspicious ports (SSH, Telnet, SMTP, SMB, RDP, MSSQL, MySQL)
- SYN flood detection
- ICMP flood detection
- Alert logging with timestamps
- Summary report generation
- Option to save alert reports

## Technologies Used

- Python
- Scapy
- Collections
- Datetime

## Project Structure
CodeAlpha_NetworkIDS/
├── simple_nids.py
└── README.md

text

## How to Run

1. Install Scapy

```bash
pip install scapy
Run the program

bash
python simple_nids.py
Choose one of the available monitoring modes:

Quick Scan (30 seconds)

Standard Scan (60 seconds)

Continuous Monitoring

Custom Duration

Detection Capabilities
The system detects:

Port scanning attempts

SYN flood attacks

ICMP flood attacks

Connections to suspicious ports

Repeated connection attempts from the same source

Sample Alerts
text
[2026-07-06 10:30:15] PORT SCAN detected from 192.168.1.10
[2026-07-06 10:31:02] SYN FLOOD detected from 192.168.1.20
[2026-07-06 10:31:15] Suspicious connection: 192.168.1.15 → 192.168.1.5:22 (SSH)
Author
ADESIYAN ADEOLA SAMUEL

CodeAlpha Cybersecurity Intern

July 2026