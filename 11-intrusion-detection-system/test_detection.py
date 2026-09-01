"""
Direct unit tests for the IDS detection logic, bypassing live packet
capture entirely. This validates check_payload_signatures() and
check_arp_spoofing() against manually constructed packets — the
capture engine itself (AsyncSniffer on eth0) was already validated
in Project #1 against a real external nmap scan.
"""
from scapy.all import IP, UDP, TCP, ARP, Ether, Raw
import sys
sys.path.insert(0, "/home/paxt0n/ids_tool")

from ids import check_payload_signatures, check_arp_spoofing, arp_table

print("=== Testing signature-based payload detection ===\n")

test_packets = [
    IP(src="10.0.0.5") / TCP() / Raw(load=b"email=admin' OR 1=1--&password=x"),
    IP(src="10.0.0.6") / TCP() / Raw(load=b"<script>alert('xss')</script>"),
    IP(src="10.0.0.7") / TCP() / Raw(load=b"cat /etc/passwd"),
    IP(src="10.0.0.8") / TCP() / Raw(load=b"perfectly normal harmless traffic"),
]

for pkt in test_packets:
    matches = check_payload_signatures(pkt)
    src = pkt[IP].src
    if matches:
        for m in matches:
            print(f"[DETECTED] {m}")
    else:
        print(f"[CLEAN] No signature match for traffic from {src}")

print("\n=== Testing ARP spoofing detection ===\n")

arp1 = Ether() / ARP(op=2, psrc="192.168.64.50", hwsrc="aa:aa:aa:aa:aa:aa")
result1 = check_arp_spoofing(arp1)
print(f"First sighting of 192.168.64.50: {result1 or 'no alert (expected — first time seeing this IP)'}")

arp2 = Ether() / ARP(op=2, psrc="192.168.64.50", hwsrc="bb:bb:bb:bb:bb:bb")
result2 = check_arp_spoofing(arp2)
print(f"Same IP, different MAC: {result2 or 'NO ALERT (unexpected — this should have fired!)'}")

print("\nDone.")
