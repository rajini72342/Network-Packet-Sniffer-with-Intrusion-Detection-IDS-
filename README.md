# Network-Packet-Sniffer-with-Intrusion-Detection-IDS-
A Mini Wireshark-style packet sniffer built using Python and Scapy with integrated Intrusion Detection System (IDS) capabilities.

This project captures live network traffic and detects suspicious activities such as:

Port Scanning

ARP Spoofing

Suspicious Backdoor Ports

ICMP Flooding

High Traffic Anomalies

HTTP Packet Monitoring

🛠 Technologies Used

Python 3

Scapy

Colorama

Npcap (Windows)

📌 Features
🔎 Packet Analysis

TCP, UDP, ICMP, ARP detection

Source & Destination tracking

Real-time packet counter

Timestamp support

🚨 Intrusion Detection

Port Scan Detection (multi-port attempts)

Suspicious Ports Monitoring (4444, 1337, 6666, 9999)

ARP Spoofing Detection

ICMP Flood detection

Traffic anomaly detection

Suspicion scoring engine

📁 Logging System

Optional log file generation

Alert recording

Risk scoring output

⚙ Installation (Windows 10/11)
1️⃣ Install Dependencies
pip install scapy colorama
2️⃣ Install Npcap

Download from: https://npcap.com

(Enable WinPcap compatibility mode)

▶ Usage

Run basic sniffer:

python sniffer_v3.py

With timestamp:

python sniffer_v3.py --timestamp

Capture specific packet count:

python sniffer_v3.py --count 50

Enable logging:

python sniffer_v3.py --log
📊 Example Alerts
🚨 Suspicious Port Access: 4444
🚨 Possible Port Scan from 192.168.1.5
🚨 Possible ARP Spoofing Detected
⚠ HIGH RISK HOST: 192.168.1.5 | Score: 8

🎯 Learning Outcomes
Deep understanding of TCP/IP protocol stack

Hands-on packet inspection

Real-time traffic monitoring

Basic IDS rule development

Network attack behavior detection logic


