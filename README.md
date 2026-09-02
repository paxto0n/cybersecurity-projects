# Cybersecurity Projects

A collection of practical cybersecurity tools built as part of a self-directed final-year-style project curriculum. Each folder is a standalone project with its own source file(s).

Built and tested on Kali Linux (UTM VM on macOS).

## Getting Started

Clone the repo onto your machine:

```bash
git clone https://github.com/paxto0n/cybersecurity-projects.git
cd cybersecurity-projects
```

Each project folder is self-contained. To run one:

```bash
cd 08-encryption-decryption-tool
python3 crypto_tool.py --help
```

Most projects here were built with Python 3.13 on Kali and use `pip install <package> --break-system-packages` since Kali's system Python is externally managed. Projects #3 and #16 are Flask web apps run as a server; the rest are command-line tools.

---

## Projects

### 01 — Network Traffic Analysis Tool
Scapy-based packet capture and traffic analysis: protocol counting, per-host byte/packet talkers, and discovery-protocol detection (mDNS/SSDP/DHCP).

```bash
cd 01-network-traffic-analyzer
pip install scapy --break-system-packages
sudo python3 traffic_analyzer.py   # run -h to confirm current flags; needs root for raw packet capture
```

### 02 — Malware Detection System
YARA-rule-based static malware detection with signatures for process injection, keylogging, and dropper behavior, plus a watch-folder mode for automatic scanning and quarantine of newly created files.

```bash
cd 02-malware-detection-system
pip install yara-python pefile watchdog --break-system-packages
python3 malware_scanner.py   # run -h to confirm current flags
```
To rebuild the test binary used to validate the YARA rules (Windows executable, needs a Windows cross-compiler like `mingw-w64` on Kali):
```bash
x86_64-w64-mingw32-gcc test_sample.c -o test_sample.exe
python3 yara_test.py
```

### 03 — Phishing Detection Website
Flask app analyzing URLs for phishing indicators: structural analysis, brand impersonation via Levenshtein distance, SSL certificate validation, and WHOIS domain-age checks.

```bash
cd 03-phishing-detection-website
pip install flask tldextract python-whois --break-system-packages
python3 app.py
# visit http://127.0.0.1:5000
```

### 04 — Port Scanner
TCP connect, UDP, and SYN/stealth scanning with banner grabbing and threading.

```bash
cd 04-port-scanner
pip install scapy --break-system-packages
sudo python3 scanner.py -t <target-ip> -p 1-1000
```

### 05 — Password Strength Checker
Entropy scoring, rockyou.txt breach-list check, HIBP k-anonymity API lookup, and crack-time estimates.

```bash
cd 05-password-strength-checker
pip install requests --break-system-packages
python3 checker.py
```

### 06 — Wi-Fi Security Analyzer
Offline analysis of captured 802.11 traffic (.pcap/.cap files): encryption classification (Open/WEP/WPA/WPA2/WPA3), WPS detection, 4-way handshake capture detection, deauth-flood detection, and rogue AP / Evil Twin detection. Built around offline pcap analysis since no monitor-mode-capable wireless adapter is available in this VM; a `live` capture mode is included but is code-complete and unverified against real hardware.

```bash
cd 06-wifi-security-analyzer
pip install scapy --break-system-packages
python3 wifi_analyzer.py analyze -f capture.cap
python3 wifi_analyzer.py live --iface wlan0mon --duration 60   # untested, needs a monitor-mode adapter
```

### 07 — Vulnerability Assessment Scanner
Integrates `searchsploit` and the NVD API with banner-based service/version detection (imports Project #4's scanner for the port-scanning layer).

```bash
cd 07-vulnerability-assessment-scanner
pip install requests --break-system-packages
sudo python3 scanner.py -t <target-ip>
```

### 08 — Encryption & Decryption Tool
AES-256-CBC file encryption with PBKDF2 key derivation, RSA-2048 keypair generation, hybrid RSA+AES encryption, and SHA-256 hashing.

```bash
cd 08-encryption-decryption-tool
pip install pycryptodome --break-system-packages
python3 crypto_tool.py encrypt -i file.txt -o file.txt.enc
python3 crypto_tool.py decrypt -i file.txt.enc -o file.txt
python3 crypto_tool.py genkeys --name mykey
python3 crypto_tool.py hash -i file.txt
```

### 09 — Log Monitoring System
Real-time log monitoring via `journalctl -f` (Kali uses systemd), pattern-based classification with severity tags, and brute-force detection with a time-window threshold.

```bash
cd 09-log-monitoring-system
python3 log_monitor.py
```

### 10 — Web Application Vulnerability Scanner
Security headers, cookie flag checks, SSL, directory enumeration, and SQLi/XSS probing (GET and JSON POST).

```bash
cd 10-webapp-vulnerability-scanner
pip install requests beautifulsoup4 --break-system-packages
python3 webapp_scanner.py -u http://target-url
```

### 11 — Intrusion Detection System (IDS)
Extends Project #1's traffic analyzer with payload signature matching and ARP spoofing detection, logging alerts to `ids_alerts.log`.

```bash
cd 11-intrusion-detection-system
pip install scapy --break-system-packages
sudo python3 ids.py
python3 test_detection.py   # unit tests, no live capture needed
```

### 12 — Steganography Tool
LSB image steganography (PNG only) with an optional AES encryption layer (via Project #8's crypto_tool) and chi-square steganalysis for detecting hidden data.

```bash
cd 12-steganography-tool
pip install pillow numpy scipy --break-system-packages
python3 stego_tool.py encode -i cover.png -o stego.png -m "secret message"
python3 stego_tool.py decode -i stego.png
python3 stego_tool.py capacity -i cover.png
python3 stego_tool.py detect -i stego.png
```

### 13 — USB Malware Detection Tool
Scans mounted volumes for `autorun.inf`, disguised double-extension executables (e.g. `photo.jpg.exe`), and known-bad SHA-256 file hashes; includes a live `watch` mode for real USB insertion via udev.

```bash
cd 13-usb-malware-detection
pip install pyudev --break-system-packages   # only needed for 'watch' mode
python3 usb_malware_detector.py scan -p /media/usb
python3 usb_malware_detector.py watch   # requires real USB hardware
```

### 14 — Cloud Security Monitoring Tool
AWS misconfiguration scanner covering S3 (public buckets, missing encryption/versioning), IAM (wildcard admin policies, stale keys, missing MFA), and EC2 (exposed security groups). Includes a `moto`-based offline self-test suite — no AWS account needed to verify it works.

```bash
cd 14-cloud-security-monitoring
pip install boto3 moto --break-system-packages
python3 selftest.py   # verify detection logic offline, no AWS account needed
python3 cloud_security_monitor.py scan --region us-east-1   # once you have a real AWS account configured
```

### 15 — SQL Injection Detection Tool
Four detection techniques — error-based, boolean-based blind, time-based blind, and union-based (column-count discovery via ORDER BY, confirmed without extracting real data).

```bash
cd 15-sql-injection-detector
pip install requests --break-system-packages
python3 sql_injection_detector.py scan -u "http://target/search?q=test"
python3 sql_injection_detector.py scan -u "http://target/login" -X POST \
  -d '{"username": "admin", "password": "x"}' --json
```

### 16 — Access Control System
Flask-based RBAC (Role-Based Access Control) system. Role is always read server-side from the database via the session, never trusted from client input — verified with a real cookie-tampering test against the live server. Includes audit logging of every access attempt and password strength enforcement via Project #5.

```bash
cd 16-access-control-system
pip install flask --break-system-packages
python3 access_control.py seed-admin --db mydb.db --username admin1 --password 'YourStrongPass!2026'
python3 access_control.py serve --db mydb.db --port 5060
python3 selftest.py   # 25-assertion test suite via Flask's test client
```

### 17 — Data Leakage Prevention Tool
Scans files/directories for sensitive data: credit card numbers (Luhn-validated to cut false positives), SSNs, AWS keys, private key material, and generic API tokens. Findings are always redacted in output. Includes a real-time `watch` mode.

```bash
cd 17-data-leakage-prevention
pip install watchdog --break-system-packages
python3 dlp_scanner.py scan -p /path/to/scan
python3 dlp_scanner.py watch -p /path/to/watch
```

### 18 — Mobile Application Security Testing
Static analysis of Android APK files via `androguard` (pure Python, no Android SDK/emulator needed): manifest misconfigurations (debuggable, allowBackup, exported components, cleartext traffic), dangerous permissions, and hardcoded secrets/weak crypto scanned from the app's decompiled string pool (reuses Project #17's DLP detection patterns).

```bash
cd 18-mobile-app-security-testing
pip install androguard --break-system-packages
python3 mobile_security_scanner.py scan -f app.apk
```

### 19 — SIEM System
Centralizes and correlates security events across this portfolio. Ingests the shared JSON report schema produced by Projects #13, #14, #15, #17, and #18 directly, normalizes findings into a unified event model, runs burst correlation (multiple high-severity events from one source in a short window), and serves a Flask dashboard API.

```bash
cd 19-siem-system
pip install flask --break-system-packages
python3 siem.py ingest-json -f ../17-data-leakage-prevention/report.json -s dlp_scanner
python3 siem.py stats
python3 siem.py correlate --window-minutes 10 --threshold 2
python3 siem.py serve --port 5070
```

### 20 — Cyber Range Simulation Environment
Orchestrates intentionally-vulnerable Docker containers as practice targets, each paired with specific tools from this portfolio. Includes real per-scenario flag verification — e.g. the `sqli-lab` scenario's flag is only captured by actually performing a working SQL injection auth bypass, verified end-to-end against a live container with Project #15's own SQL Injection Detector.

```bash
cd 20-cyber-range-simulation
pip install requests --break-system-packages
python3 cyber_range.py list
python3 cyber_range.py up sqli-lab
python3 cyber_range.py check-flag sqli-lab --host 127.0.0.1 --port 5000
python3 cyber_range.py down sqli-lab
```

---

## Status

All 20 projects complete. Notes on scope/verification limits, documented rather than hidden:

- **#1 and #2** were built before this repo's git workflow was established; their exact CLI flags weren't independently re-verified in this session — run `-h`/`--help` to confirm current options.
- **#6** is built around offline pcap analysis (verified against a real aircrack-ng WPA handshake test capture) since no monitor-mode-capable wireless adapter was available; its `live` capture mode is code-complete but unverified against real hardware.
- **#13**'s live udev `watch` mode and **#20**'s `weak-ssh-lab` scenario are code-complete but need real hardware/further testing beyond what was verified here.
