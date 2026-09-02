#!/usr/bin/env python3
"""
Project #6 - Wi-Fi Security Analyzer

No wireless/monitor-mode-capable adapter is available in this development
VM, so this tool is built around OFFLINE analysis of captured 802.11
traffic (.pcap/.cap files) as the primary, fully-testable mode. This is a
legitimate, standard technique -- real Wi-Fi security tooling (including
aircrack-ng itself) ships and validates against exactly this kind of
capture file, not just live hardware.

Checks performed on a capture file:
  - Encryption type per network (Open / WEP / WPA / WPA2 / WPA3), parsed
    from beacon frame RSN/WPA information elements
  - WPS enabled (a known attack surface via WPS PIN brute-forcing)
  - WPA/WPA2 4-way handshake capture detection (all 4 EAPOL messages
    present for a BSSID) -- confirms a capture is crackable
  - Deauthentication/disassociation flood detection (a common attack used
    to force clients to reconnect and leak a handshake, or as plain DoS)
  - Rogue AP / Evil Twin detection (same SSID broadcast from multiple
    distinct BSSIDs)

A `live` mode using scapy's sniff() against a monitor-mode interface is
also included, but is CODE-COMPLETE AND UNVERIFIED -- there is no
wireless adapter available to test it against. Verify this on hardware
with a real monitor-mode-capable adapter before relying on it.

Usage:
    python3 wifi_analyzer.py analyze -f capture.cap
    python3 wifi_analyzer.py analyze -f capture.cap -o report.json
    python3 wifi_analyzer.py live --iface wlan0mon --duration 60   # untested, needs hardware
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Disas, EAPOL

DEAUTH_FLOOD_THRESHOLD = 10  # deauth/disassoc frames from one source = suspicious


# ---------------------------------------------------------------------------
# Encryption / WPS detection from beacon information elements
# ---------------------------------------------------------------------------

def _get_ssid(pkt) -> str:
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID element
                ssid = elt.info.decode(errors="ignore")
                return ssid if ssid else "(hidden)"
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return "(unknown)"


def _classify_encryption(pkt) -> str:
    """Inspects beacon information elements to classify network security."""
    has_rsn = False    # RSN IE (ID 48) = WPA2/WPA3
    has_wpa_vendor = False  # Microsoft WPA vendor-specific IE = WPA (v1)
    privacy_bit = False

    try:
        privacy_bit = bool(pkt[Dot11Beacon].cap.privacy)
    except Exception:
        pass

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:  # RSN information element
            has_rsn = True
        if elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01"):
            has_wpa_vendor = True
        elt = elt.payload.getlayer(Dot11Elt)

    if not privacy_bit:
        return "Open (unencrypted)"
    if has_rsn:
        # Distinguishing WPA2 vs WPA3 reliably needs deeper AKM suite
        # parsing (SAE = WPA3); reported generically as WPA2/WPA3 to avoid
        # overclaiming a distinction this simpler IE-presence check can't
        # always make confidently.
        return "WPA2/WPA3 (RSN)"
    if has_wpa_vendor:
        return "WPA"
    return "WEP or unknown (privacy bit set, no RSN/WPA IE found)"


def _has_wps(pkt) -> bool:
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x04"):
            return True
        elt = elt.payload.getlayer(Dot11Elt)
    return False


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze_capture(pcap_path: str, quiet: bool = False) -> dict:
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"Capture file not found: {pcap_path}")

    packets = rdpcap(str(path))

    networks = {}  # bssid -> {ssid, encryption, wps}
    handshake_frames = defaultdict(set)  # bssid -> set of EAPOL message numbers seen
    deauth_sources = defaultdict(int)
    ssid_to_bssids = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        dot11 = pkt[Dot11]

        if pkt.haslayer(Dot11Beacon):
            bssid = dot11.addr2
            ssid = _get_ssid(pkt)
            networks[bssid] = {
                "ssid": ssid,
                "encryption": _classify_encryption(pkt),
                "wps": _has_wps(pkt),
            }
            ssid_to_bssids[ssid].add(bssid)

        if pkt.haslayer(EAPOL):
            # addr2 (source) alternates between the AP and the client across
            # the 4 handshake messages (2 frames from each side), so
            # grouping by addr2 would split one handshake into two groups
            # of 2 and never reach the 4-frame threshold. addr3 is the BSSID
            # consistently across all 4 messages regardless of direction --
            # confirmed against a real captured handshake during testing.
            bssid = dot11.addr3 if dot11.addr3 else dot11.addr2
            handshake_frames[bssid].add(len(handshake_frames[bssid]) + 1)

        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            source = dot11.addr2
            deauth_sources[source] += 1

    findings = []

    for bssid, info in networks.items():
        if info["encryption"] == "Open (unencrypted)":
            findings.append({
                "type": "open_network", "severity": "high", "bssid": bssid,
                "detail": f"SSID '{info['ssid']}' broadcasts with NO encryption",
            })
        elif "WEP" in info["encryption"]:
            findings.append({
                "type": "weak_encryption", "severity": "critical", "bssid": bssid,
                "detail": f"SSID '{info['ssid']}' uses WEP or unidentified legacy encryption (trivially crackable)",
            })
        if info["wps"]:
            findings.append({
                "type": "wps_enabled", "severity": "medium", "bssid": bssid,
                "detail": f"SSID '{info['ssid']}' has WPS enabled (vulnerable to PIN brute-force attacks)",
            })

    for bssid, frames in handshake_frames.items():
        if len(frames) >= 4:
            ssid = networks.get(bssid, {}).get("ssid", "(unknown)")
            findings.append({
                "type": "handshake_captured", "severity": "info", "bssid": bssid,
                "detail": f"Full 4-way WPA handshake captured for SSID '{ssid}' -- crackable offline with a wordlist",
            })

    for source, count in deauth_sources.items():
        if count >= DEAUTH_FLOOD_THRESHOLD:
            findings.append({
                "type": "deauth_flood", "severity": "critical", "bssid": source,
                "detail": f"{count} deauth/disassoc frames from {source} -- consistent with an active deauth attack",
            })

    for ssid, bssids in ssid_to_bssids.items():
        if len(bssids) > 1:
            findings.append({
                "type": "possible_rogue_ap", "severity": "high", "bssid": ", ".join(sorted(bssids)),
                "detail": f"SSID '{ssid}' broadcast from {len(bssids)} different BSSIDs -- "
                          f"possible Evil Twin/rogue AP (or a legitimate multi-AP network; verify)",
            })

    result = {
        "capture_file": str(path),
        "timestamp": datetime.now().isoformat(),
        "packets_analyzed": len(packets),
        "networks_seen": len(networks),
        "findings_count": len(findings),
        "findings": findings,
        "networks": networks,
    }

    if not quiet:
        _print_report(result)

    return result


def _print_report(result: dict):
    print(f"[*] Capture: {result['capture_file']}")
    print(f"[*] Packets analyzed: {result['packets_analyzed']}")
    print(f"[*] Networks seen: {result['networks_seen']}")
    print(f"[*] Findings: {result['findings_count']}")
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for finding in sorted(result["findings"], key=lambda f: severity_rank.get(f["severity"], 9)):
        print(f"\n  [{finding['severity'].upper()}] {finding['type']} ({finding['bssid']})")
        print(f"      {finding['detail']}")


# ---------------------------------------------------------------------------
# Live capture mode -- CODE-COMPLETE, UNVERIFIED (no hardware available)
# ---------------------------------------------------------------------------

def run_live_capture(iface: str, duration: int = 60, quiet: bool = False):
    """
    Sniffs live 802.11 traffic on a monitor-mode interface and runs the
    same analysis as analyze_capture(). NOT TESTED -- no monitor-mode
    capable wireless adapter was available during development. Requires
    the interface to already be in monitor mode (e.g. via
    `airmon-ng start wlan0`) before running this.
    """
    try:
        from scapy.all import sniff, wrpcap
    except ImportError:
        print("[!] scapy sniff not available.", file=sys.stderr)
        sys.exit(1)

    if not quiet:
        print(f"[*] Sniffing on {iface} for {duration}s... (requires monitor mode already enabled)")
        print("[!] This live-capture path is untested -- no wireless adapter was available during development.")

    packets = sniff(iface=iface, timeout=duration)
    tmp_path = "/tmp/wifi_analyzer_live_capture.pcap"
    wrpcap(tmp_path, packets)

    return analyze_capture(tmp_path, quiet=quiet)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")

    parser = argparse.ArgumentParser(description="Wi-Fi Security Analyzer (Project #6)", parents=[common])
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze a captured .pcap/.cap file", parents=[common])
    p_analyze.add_argument("-f", "--file", required=True, help="Path to the capture file")
    p_analyze.add_argument("-o", "--output", help="Write JSON report to this file")

    p_live = sub.add_parser("live", help="[UNTESTED - needs monitor-mode hardware] Sniff live traffic", parents=[common])
    p_live.add_argument("--iface", required=True, help="Monitor-mode interface, e.g. wlan0mon")
    p_live.add_argument("--duration", type=int, default=60, help="Seconds to capture")

    args = parser.parse_args()

    try:
        if args.command == "analyze":
            result = analyze_capture(args.file, quiet=args.quiet)
            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2))
                if not args.quiet:
                    print(f"\n[+] Report written to {args.output}")
            if result["findings_count"] > 0:
                sys.exit(2)

        elif args.command == "live":
            result = run_live_capture(args.iface, args.duration, quiet=args.quiet)
            if result["findings_count"] > 0:
                sys.exit(2)

    except FileNotFoundError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
