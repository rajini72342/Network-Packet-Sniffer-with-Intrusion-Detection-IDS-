from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
from colorama import Fore, init
import argparse
import datetime
from collections import defaultdict

init(autoreset=True)

# ---------------- CLI Arguments ---------------- #

parser = argparse.ArgumentParser(description="Advanced Packet Sniffer + IDS v3")
parser.add_argument("--timestamp", action="store_true", help="Show timestamp")
parser.add_argument("--count", type=int, default=0, help="Number of packets")
parser.add_argument("--log", action="store_true", help="Save logs to file")
args = parser.parse_args()

# ---------------- Storage ---------------- #

packet_count = 0
ip_counter = defaultdict(int)
port_scan_tracker = defaultdict(set)
arp_table = {}
suspicion_score = defaultdict(int)

SUSPICIOUS_PORTS = [4444, 1337, 6666, 9999]

log_file = "sniffer_logs.txt"

# ---------------- Logging ---------------- #

def write_log(message):
    if args.log:
        with open(log_file, "a") as f:
            f.write(message + "\n")

# ---------------- Packet Processing ---------------- #

def process_packet(packet):
    global packet_count
    packet_count += 1

    time_now = datetime.datetime.now().strftime("%H:%M:%S")

    header = f"\nPacket #{packet_count}"
    print(Fore.WHITE + header)
    write_log(header)

    if args.timestamp:
        print(Fore.CYAN + f"[{time_now}]")
        write_log(f"[{time_now}]")

    # ---------------- ARP Detection ---------------- #
    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        print(Fore.YELLOW + f"[ARP] {src_ip} → MAC: {src_mac}")
        write_log(f"[ARP] {src_ip} → MAC: {src_mac}")

        if src_ip in arp_table and arp_table[src_ip] != src_mac:
            alert = f"🚨 ALERT: Possible ARP Spoofing Detected for {src_ip}"
            print(Fore.RED + alert)
            write_log(alert)
            suspicion_score[src_ip] += 5

        arp_table[src_ip] = src_mac
        return

    # ---------------- IP Layer ---------------- #
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    ip_counter[src] += 1

    # ---------------- TCP ---------------- #
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport

        msg = f"[TCP] {src}:{sport} → {dst}:{dport}"
        print(Fore.GREEN + msg)
        write_log(msg)

        # Suspicious Port
        if dport in SUSPICIOUS_PORTS:
            alert = f"🚨 Suspicious Port Access: {dport}"
            print(Fore.RED + alert)
            write_log(alert)
            suspicion_score[src] += 3

        # Port Scan Detection
        port_scan_tracker[src].add(dport)
        if len(port_scan_tracker[src]) > 15:
            alert = f"🚨 Possible Port Scan from {src}"
            print(Fore.RED + alert)
            write_log(alert)
            suspicion_score[src] += 4

        # HTTP Detection
        if packet.haslayer(Raw) and dport == 80:
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                if "HTTP" in payload:
                    print(Fore.BLUE + "🌐 HTTP Request Captured")
                    write_log("HTTP Request Captured")
            except:
                pass

    # ---------------- UDP ---------------- #
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        msg = f"[UDP] {src}:{sport} → {dst}:{dport}"
        print(Fore.MAGENTA + msg)
        write_log(msg)

    # ---------------- ICMP ---------------- #
    elif packet.haslayer(ICMP):
        msg = f"[ICMP] {src} → {dst}"
        print(Fore.BLUE + msg)
        write_log(msg)
        suspicion_score[src] += 1

    # ---------------- High Traffic ---------------- #
    if ip_counter[src] > 100:
        alert = f"🚨 High Traffic Volume from {src}"
        print(Fore.RED + alert)
        write_log(alert)
        suspicion_score[src] += 5

    # ---------------- Suspicion Score Output ---------------- #
    if suspicion_score[src] >= 7:
        alert = f"⚠ HIGH RISK HOST: {src} | Score: {suspicion_score[src]}"
        print(Fore.RED + alert)
        write_log(alert)

# ---------------- Start Sniffing ---------------- #

print(Fore.RED + "Advanced Mini Wireshark + IDS v3 Started (Ctrl+C to stop)\n")

sniff(prn=process_packet, count=args.count)