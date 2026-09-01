# Cybersecurity Projects

A collection of practical cybersecurity tools built as part of a self-directed final-year-style project curriculum. Each folder is a standalone project.

## Projects

| # | Project | Description |
|---|---------|-------------|
| 03 | [Phishing Detection Website](./03-phishing-detection-website) | Flask app analyzing URLs for phishing indicators (structural analysis, brand impersonation via Levenshtein distance, SSL/WHOIS checks) |
| 04 | [Port Scanner](./04-port-scanner) | TCP connect, UDP, and SYN/stealth scanning with banner grabbing and threading |
| 05 | [Password Strength Checker](./05-password-strength-checker) | Entropy scoring, breach-database checks, HIBP k-anonymity API, crack-time estimates |
| 07 | [Vulnerability Assessment Scanner](./07-vulnerability-assessment-scanner) | Integrates searchsploit and the NVD API with banner-based service/version detection |
| 08 | [Encryption & Decryption Tool](./08-encryption-decryption-tool) | AES-256-CBC file encryption, RSA-2048 keypairs, hybrid encryption, SHA-256 hashing |
| 09 | [Log Monitoring System](./09-log-monitoring-system) | journald-based real-time log monitoring with brute-force detection |
| 10 | [Web Application Vulnerability Scanner](./10-webapp-vulnerability-scanner) | Security headers, SSL, directory enumeration, SQLi/XSS probing |
| 11 | [Intrusion Detection System](./11-intrusion-detection-system) | Payload signature matching and ARP spoofing detection |
| 12 | [Steganography Tool](./12-steganography-tool) | LSB image steganography with optional AES encryption layer and chi-square steganalysis |
| 13 | [USB Malware Detection Tool](./13-usb-malware-detection) | Scans mounted volumes for autorun.inf, disguised executables, and known-bad file hashes |
| 14 | [Cloud Security Monitoring Tool](./14-cloud-security-monitoring) | AWS misconfiguration scanner (S3, IAM, EC2) with a moto-based offline self-test suite |

## Environment

Built and tested on Kali Linux (UTM VM on macOS).

## Status

Work in progress — more projects to follow.
