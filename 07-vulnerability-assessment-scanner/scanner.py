import socket
import sys
import os
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
]

TOP_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500,
                 514, 520, 631, 1900, 4500, 5353]

MAX_THREADS = 200
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}


def grab_banner(target, port, timeout=1.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        if port in HTTP_PORTS:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if banner:
            first_line = banner.splitlines()[0]
            return first_line[:100]
        return None
    except (socket.timeout, socket.error, UnicodeDecodeError):
        return None


def tcp_connect_scan(target, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def udp_scan(target, port, timeout=1.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        if port == 53:
            payload = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                       b"\x07example\x03com\x00\x00\x01\x00\x01")
        else:
            payload = b"\x00"

        sock.sendto(payload, (target, port))

        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return "open"
        except socket.timeout:
            sock.close()
            return "open|filtered"

    except ConnectionResetError:
        return "closed"
    except socket.error:
        return "closed"


def syn_scan_port(target, port, timeout=1.5):
    """
    Half-open SYN scan using scapy. Sends SYN, checks the reply,
    then sends RST to tear down without completing the handshake
    (this is what makes it 'stealthier' than a full connect scan).
    Requires root — raw sockets.
    """
    from scapy.all import IP, TCP, sr1, RandShort

    src_port = RandShort()
    pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
    response = sr1(pkt, timeout=timeout, verbose=0)

    if response is None:
        return "filtered"  # no reply — likely dropped by a firewall

    if response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK
            # send RST to close the half-open connection cleanly
            rst_pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R")
            sr1(rst_pkt, timeout=timeout, verbose=0)
            return "open"
        elif flags == 0x14:  # RST-ACK
            return "closed"

    return "filtered"


def syn_scan(target, ports, timeout=1.5):
    """
    Sequential by design — scapy's sr1 doesn't thread safely without
    more setup (e.g. AsyncSniffer + manual packet correlation), and
    for a stealth scan mode, going a bit slower is an acceptable tradeoff.
    """
    print(f"\n[SYN] Scanning {target}  (requires root)")
    print(f"Ports to check: {len(ports)}")
    print("-" * 60)

    results = {}
    start_time = time.time()

    for port in ports:
        state = syn_scan_port(target, port, timeout)
        if state != "filtered":
            print(f"Port {port:5d}  {state.upper()}")
            results[port] = state

    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"SYN scan complete in {elapsed:.2f}s. {len(results)} port(s) not filtered.")
    if results:
        print(f"Results: {results}")
    return results


def parse_ports(args, default_list):
    if args.all:
        return list(range(1, 65536))

    if args.ports:
        ports = set()
        for part in args.ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    n = args.top_ports if args.top_ports else 20
    return default_list[:n]


def scan_target_tcp(target, ports, max_threads=MAX_THREADS, grab_banners=True):
    print(f"\n[TCP] Scanning {target}")
    print(f"Ports to check: {len(ports)}")
    print("-" * 60)

    open_ports = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(tcp_connect_scan, target, port): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    banner = grab_banner(target, port) if grab_banners else None
                    if banner:
                        print(f"Port {port:5d}  OPEN   {banner}")
                    else:
                        print(f"Port {port:5d}  OPEN")
                    open_ports.append(port)
            except Exception as e:
                print(f"Port {port:5d}  ERROR ({e})")

    elapsed = time.time() - start_time
    open_ports.sort()
    print("-" * 60)
    print(f"TCP scan complete in {elapsed:.2f}s. {len(open_ports)} open port(s) found.")
    if open_ports:
        print(f"Open ports: {open_ports}")
    return open_ports


def scan_target_udp(target, ports, max_threads=MAX_THREADS):
    print(f"\n[UDP] Scanning {target}")
    print(f"Ports to check: {len(ports)}")
    print("-" * 60)

    results = {}
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(udp_scan, target, port): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                state = future.result()
                if state != "closed":
                    print(f"Port {port:5d}  {state.upper()}")
                    results[port] = state
            except Exception as e:
                print(f"Port {port:5d}  ERROR ({e})")

    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"UDP scan complete in {elapsed:.2f}s. {len(results)} port(s) open or open|filtered.")
    if results:
        print(f"Results: {results}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-mode Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--top-ports", type=int, metavar="N",
                         help="Scan the top N most common ports (default 20)")
    parser.add_argument("--ports", type=str,
                         help="Custom port list/range, e.g. 1-1000 or 22,80,443")
    parser.add_argument("--all", action="store_true",
                         help="Scan all 65535 ports")
    parser.add_argument("--no-banners", action="store_true",
                         help="Skip banner grabbing (faster, TCP only)")
    parser.add_argument("--udp", action="store_true",
                         help="Run a UDP scan instead of TCP")
    parser.add_argument("--syn", action="store_true",
                         help="Run a stealth SYN scan instead of TCP connect (requires root)")

    args = parser.parse_args()

    if args.syn and os.geteuid() != 0:
        print("SYN scan requires root privileges. Try: sudo python3 scanner.py ... --syn")
        sys.exit(1)

    if args.udp:
        ports = parse_ports(args, TOP_UDP_PORTS)
        scan_target_udp(args.target, ports)
    elif args.syn:
        ports = parse_ports(args, TOP_PORTS)
        syn_scan(args.target, ports)
    else:
        ports = parse_ports(args, TOP_PORTS)
        scan_target_tcp(args.target, ports, grab_banners=not args.no_banners)

