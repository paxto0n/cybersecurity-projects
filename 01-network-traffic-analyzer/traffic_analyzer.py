from scapy.all import AsyncSniffer, IP, UDP, TCP
from collections import defaultdict
import time

session_protocol_counts = defaultdict(int)
session_talker_bytes = defaultdict(int)
session_total_bytes = 0
session_packet_count = 0
session_alerts = []

interval_stats = {
    "packet_count": 0,
    "discovery_count": 0,
    "protocol_counts": defaultdict(int),
    "talker_bytes": defaultdict(int),
    "talker_packets": defaultdict(int),
    "talker_ports": defaultdict(set),
}

DISCOVERY_PORTS = {5353: "mDNS", 1900: "SSDP", 67: "DHCP", 68: "DHCP"}
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

PORT_SCAN_THRESHOLD = 15

# Rolling baseline for spike detection
recent_interval_totals = []
BASELINE_WINDOW = 15
SPIKE_MULTIPLIER = 4
SPIKE_MIN_FLOOR = 250

def is_discovery_traffic(pkt):
    if UDP in pkt:
        return pkt[UDP].sport in DISCOVERY_PORTS or pkt[UDP].dport in DISCOVERY_PORTS
    return False

def process_packet(pkt):
    global session_total_bytes, session_packet_count

    if IP in pkt:
        proto_num = pkt[IP].proto
        proto_name = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")
        pkt_len = len(pkt)
        src_ip = pkt[IP].src

        if is_discovery_traffic(pkt):
            interval_stats["discovery_count"] += 1
            session_protocol_counts["DISCOVERY"] += 1
        else:
            interval_stats["protocol_counts"][proto_name] += 1
            interval_stats["talker_bytes"][src_ip] += pkt_len
            interval_stats["talker_packets"][src_ip] += 1
            session_protocol_counts[proto_name] += 1
            session_talker_bytes[src_ip] += pkt_len

            if TCP in pkt:
                interval_stats["talker_ports"][src_ip].add(pkt[TCP].dport)
            elif UDP in pkt:
                interval_stats["talker_ports"][src_ip].add(pkt[UDP].dport)

        interval_stats["packet_count"] += 1
        session_packet_count += 1
        session_total_bytes += pkt_len

def check_suspicious_activity():
    alerts = []

    for ip, ports in interval_stats["talker_ports"].items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append(f"[ALERT] Possible port scan from {ip}: {len(ports)} distinct ports in 2s")

    if recent_interval_totals:
        baseline_avg = sum(recent_interval_totals) / len(recent_interval_totals)
    else:
        baseline_avg = 0

    for ip, count in interval_stats["talker_packets"].items():
        if count >= SPIKE_MIN_FLOOR and (baseline_avg == 0 or count >= baseline_avg * SPIKE_MULTIPLIER):
            alerts.append(f"[ALERT] Traffic spike from {ip}: {count} packets in 2s (baseline avg: {baseline_avg:.0f})")

    total_this_interval = sum(interval_stats["talker_packets"].values())
    recent_interval_totals.append(total_this_interval)
    if len(recent_interval_totals) > BASELINE_WINDOW:
        recent_interval_totals.pop(0)

    return alerts

def print_interval_stats():
    print("\n--- Last 2 seconds ---")
    print(f"Packets: {interval_stats['packet_count']}  (discovery/background: {interval_stats['discovery_count']})")

    if interval_stats["protocol_counts"]:
        print("Protocols:")
        for proto, count in sorted(interval_stats["protocol_counts"].items(), key=lambda x: -x[1]):
            print(f"  {proto}: {count}")

    if interval_stats["talker_bytes"]:
        print("Top talkers:")
        for ip, b in sorted(interval_stats["talker_bytes"].items(), key=lambda x: -x[1])[:5]:
            print(f"  {ip}: {b/1024:.2f} KB")

    alerts = check_suspicious_activity()
    if alerts:
        print("\n*** SUSPICIOUS ACTIVITY DETECTED ***")
        for a in alerts:
            print(a)
            session_alerts.append(a)

    interval_stats["packet_count"] = 0
    interval_stats["discovery_count"] = 0
    interval_stats["protocol_counts"] = defaultdict(int)
    interval_stats["talker_bytes"] = defaultdict(int)
    interval_stats["talker_packets"] = defaultdict(int)
    interval_stats["talker_ports"] = defaultdict(set)

def print_session_summary():
    print("\n" + "="*50)
    print("SESSION SUMMARY")
    print(f"Total packets: {session_packet_count}")
    print(f"Total traffic: {session_total_bytes/1024:.2f} KB")
    print("\nProtocol breakdown:")
    for proto, count in sorted(session_protocol_counts.items(), key=lambda x: -x[1]):
        print(f"  {proto}: {count}")
    print("\nTop talkers (excludes discovery traffic):")
    for ip, b in sorted(session_talker_bytes.items(), key=lambda x: -x[1])[:5]:
        print(f"  {ip}: {b/1024:.2f} KB")

    if session_alerts:
        print(f"\nTotal alerts this session: {len(session_alerts)}")
        for a in session_alerts:
            print(f"  {a}")
    else:
        print("\nNo suspicious activity detected this session.")
    print("="*50)

print("Starting capture on eth0... (Ctrl+C to stop)\n")

sniffer = AsyncSniffer(iface="eth0", prn=process_packet, store=False)
sniffer.start()

try:
    while True:
        time.sleep(2)
        print_interval_stats()
except KeyboardInterrupt:
    sniffer.stop()
    print("\nCapture stopped.")
    print_session_summary()
