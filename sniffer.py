from scapy.all import sniff
from collections import Counter
from datetime import datetime
import csv
import argparse
import matplotlib.pyplot as plt

# -----------------------------
# Argument Parser (CLI Support)
# -----------------------------
parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
parser.add_argument("--count", type=int, default=50, help="Number of packets to capture")
parser.add_argument("--filter", type=str, default="ip", help="Packet filter (e.g., tcp, udp)")
args = parser.parse_args()

# -----------------------------
# Global Data Stores
# -----------------------------
protocol_count = Counter()
ip_counter = Counter()
packet_logs = []

# Suspicious + Blacklist
suspicious_ports = [21, 22, 23, 3389]
blacklist_ips = ["192.168.1.100"]

IP_THRESHOLD = 10

# -----------------------------
# Packet Processing
# -----------------------------
def process_packet(packet):
    if packet.haslayer("IP"):
        ip = packet["IP"]
        src, dst = ip.src, ip.dst
        timestamp = datetime.now().strftime('%H:%M:%S')

        ip_counter[src] += 1

        log = {
            "time": timestamp,
            "src": src,
            "dst": dst,
            "protocol": "",
            "sport": "",
            "dport": ""
        }

        print(f"\n[{timestamp}] {src} → {dst}")

        # TCP
        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            protocol_count["TCP"] += 1
            log.update({"protocol": "TCP", "sport": tcp.sport, "dport": tcp.dport})

            print(f"TCP | Ports: {tcp.sport} → {tcp.dport}")

            if tcp.dport in suspicious_ports:
                print("⚠️ Suspicious Port!")

        # UDP
        elif packet.haslayer("UDP"):
            udp = packet["UDP"]
            protocol_count["UDP"] += 1
            log.update({"protocol": "UDP", "sport": udp.sport, "dport": udp.dport})

            print(f"UDP | Ports: {udp.sport} → {udp.dport}")

        # ICMP
        elif packet.haslayer("ICMP"):
            protocol_count["ICMP"] += 1
            log["protocol"] = "ICMP"
            print("ICMP Packet")

        # Blacklist detection
        if src in blacklist_ips:
            print("🚨 BLACKLISTED IP DETECTED")

        # High traffic anomaly
        if ip_counter[src] > IP_THRESHOLD:
            print("⚠️ High Traffic Detected from:", src)

        packet_logs.append(log)


# -----------------------------
# Save Logs
# -----------------------------
def save_logs():
    with open("network_logs.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["time", "src", "dst", "protocol", "sport", "dport"])
        writer.writeheader()
        writer.writerows(packet_logs)


# -----------------------------
# Summary + Visualization
# -----------------------------
def show_summary():
    print("\n========== SUMMARY ==========")

    for proto, count in protocol_count.items():
        print(f"{proto}: {count}")

    print("\nTop IPs:")
    for ip, count in ip_counter.most_common(5):
        print(f"{ip}: {count}")

    print("============================")

    # Graph
    if protocol_count:
        plt.figure()
        plt.bar(protocol_count.keys(), protocol_count.values())
        plt.title("Protocol Distribution")
        plt.xlabel("Protocol")
        plt.ylabel("Packet Count")
        plt.show()


# -----------------------------
# Main
# -----------------------------
print(f"Starting Sniffer | Filter: {args.filter} | Count: {args.count}\n")

try:
    sniff(filter=args.filter, prn=process_packet, count=args.count)
finally:
    save_logs()
    show_summary()
    print("\nLogs saved → network_logs.csv")