from scapy.all import AsyncSniffer, IP, UDP, TCP, ARP, Raw
from collections import defaultdict
from datetime import datetime
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

recent_interval_totals = []
BASELINE_WINDOW = 15
SPIKE_MULTIPLIER = 4
SPIKE_MIN_FLOOR = 250

ALERT_LOG_PATH = "ids_alerts.log"

# --- Signature-based detection ---
PAYLOAD_SIGNATURES = [
    (b"' OR 1=1", "Possible SQL injection attempt in payload"),
    (b"' OR '1'='1", "Possible SQL injection attempt in payload"),
    (b"<script>", "Possible XSS payload in traffic"),
    (b"/etc/passwd", "Possible local file inclusion / path traversal attempt"),
    (b"UNION SELECT", "Possible SQL injection (UNION-based) attempt"),
    (b"cmd.exe", "Possible Windows command injection attempt"),
    (b"/bin/sh", "Possible Unix shell injection attempt"),
    (b"\x90\x90\x90\x90", "Possible NOP sled (shellcode indicator)"),
]

# --- ARP spoofing detection ---
arp_table = {}


def log_alert(message):
    """Writes an alert to both console and a persistent log file with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    session_alerts.append(full_message)
    with open(ALERT_LOG_PATH, "a") as f:
        f.write(full_message + "\n")
    return full_message


def is_discovery_traffic(pkt):
    if UDP in pkt:
        return pkt[UDP].sport in DISCOVERY_PORTS or pkt[UDP].dport in DISCOVERY_PORTS
    return False


def check_payload_signatures(pkt):
    if not pkt.haslayer(Raw):
        return []

    payload = bytes(pkt[Raw].load)
    src_ip = pkt[IP].src if IP in pkt else "unknown"

    matches = []
    for signature, description in PAYLOAD_SIGNATURES:
        if signature in payload:
            matches.append(f"[SIGNATURE] {description} from {src_ip}")

    return matches


def check_arp_spoofing(pkt):
    if ARP not in pkt or pkt[ARP].op != 2:
        return None

    sender_ip = pkt[ARP].psrc
    sender_mac = pkt[ARP].hwsrc

    if sender_ip in arp_table and arp_table[sender_ip] != sender_mac:
        old_mac = arp_table[sender_ip]
        arp_table[sender_ip] = sender_mac
        return (f"[SIGNATURE] Possible ARP spoofing: {sender_ip} changed from "
                f"MAC {old_mac} to {sender_mac}")

    arp_table[sender_ip] = sender_mac
    return None


def process_packet(pkt):
    global session_total_bytes, session_packet_count

    arp_alert = check_arp_spoofing(pkt)
    if arp_alert:
        print(f"\n*** {log_alert(arp_alert)} ***")

    if IP in pkt:
        proto_num = pkt[IP].proto
        proto_name = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")
        pkt_len = len(pkt)
        src_ip = pkt[IP].src

        signature_matches = check_payload_signatures(pkt)
        for match in signature_matches:
            print(f"\n*** {log_alert(match)} ***")

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
            alerts.append(f"[ANOMALY] Possible port scan from {ip}: {len(ports)} distinct ports in 2s")

    if recent_interval_totals:
        baseline_avg = sum(recent_interval_totals) / len(recent_interval_totals)
    else:
        baseline_avg = 0

    for ip, count in interval_stats["talker_packets"].items():
        if count >= SPIKE_MIN_FLOOR and (baseline_avg == 0 or count >= baseline_avg * SPIKE_MULTIPLIER):
            alerts.append(f"[ANOMALY] Traffic spike from {ip}: {count} packets in 2s (baseline avg: {baseline_avg:.0f})")

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
            log_alert(a)

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
        print(f"\nFull alert log saved to: {ALERT_LOG_PATH}")
    else:
        print("\nNo suspicious activity detected this session.")
    print("="*50)


def run_ids(iface="eth0"):
    """Starts live IDS capture on the given interface. Blocks until Ctrl+C."""
    print(f"Starting IDS capture on {iface}... (Ctrl+C to stop)")
    print(f"Alerts will be logged to: {ALERT_LOG_PATH}\n")

    sniffer = AsyncSniffer(iface=iface, prn=process_packet, store=False)
    sniffer.start()

    try:
        while True:
            time.sleep(2)
            print_interval_stats()
    except KeyboardInterrupt:
        sniffer.stop()
        print("\nCapture stopped.")
        print_session_summary()


if __name__ == "__main__":
    run_ids()
