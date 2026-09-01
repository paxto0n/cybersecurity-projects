import sys
import re
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone

import tldextract

try:
    import whois
except ImportError:
    whois = None


KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase", "instagram",
    "whatsapp", "linkedin", "twitter", "outlook", "office365", "dropbox",
]

SUSPICIOUS_TLDS = {
    ".zip", ".review", ".country", ".kim", ".cricket", ".science",
    ".work", ".party", ".gq", ".tk", ".ml", ".ga", ".cf", ".top", ".xyz",
}


def levenshtein(a, b):
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def analyze_structure(url):
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        findings.append(("IP address used instead of domain name", "high"))

    if "@" in url:
        findings.append(("Contains '@' symbol (can mask the real destination)", "high"))

    subdomain_count = hostname.count(".")
    if subdomain_count >= 4:
        findings.append((f"Unusually high number of subdomains ({subdomain_count})", "medium"))

    if len(url) > 100:
        findings.append((f"Unusually long URL ({len(url)} characters)", "low"))

    ext = tldextract.extract(url)
    if ext.domain.count("-") >= 2:
        findings.append(("Multiple hyphens in domain name", "medium"))

    tld = "." + ext.suffix.split(".")[-1] if ext.suffix else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append((f"Uses a TLD commonly associated with abuse ({tld})", "medium"))

    return findings, ext


def check_brand_impersonation(ext):
    findings = []
    domain = ext.domain.lower()

    for brand in KNOWN_BRANDS:
        if domain == brand:
            continue
        distance = levenshtein(domain, brand)
        if 0 < distance <= 2:
            findings.append((f"Domain closely resembles '{brand}' (edit distance: {distance})", "high"))
        elif brand in domain and domain != brand:
            findings.append((f"Domain contains brand name '{brand}' but isn't the real domain", "high"))

    return findings


def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
        return True, None
    except Exception as e:
        return False, str(e)


def check_domain_age(hostname):
    if whois is None:
        return None, "python-whois not installed"
    try:
        w = whois.whois(hostname)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None, "No creation date in WHOIS record"
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        return age_days, None
    except Exception as e:
        return None, str(e)


def _run_all_checks(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    all_findings = []

    structural_findings, ext = analyze_structure(url)
    all_findings.extend(structural_findings)

    brand_findings = check_brand_impersonation(ext)
    all_findings.extend(brand_findings)

    ssl_ok, ssl_error = check_ssl(hostname)
    if not ssl_ok:
        all_findings.append((f"No valid SSL certificate ({ssl_error})", "medium"))

    age_days, age_error = check_domain_age(hostname)
    if age_days is not None:
        if age_days < 30:
            all_findings.append((f"Domain registered very recently ({age_days} days ago)", "high"))
        elif age_days < 180:
            all_findings.append((f"Domain registered relatively recently ({age_days} days ago)", "medium"))

    severity_weight = {"high": 3, "medium": 2, "low": 1}
    risk_score = sum(severity_weight.get(sev, 1) for _, sev in all_findings)

    if risk_score >= 6:
        verdict = "HIGH RISK - likely phishing"
        verdict_class = "high"
    elif risk_score >= 3:
        verdict = "MODERATE RISK - worth investigating"
        verdict_class = "moderate"
    else:
        verdict = "LOW RISK"
        verdict_class = "low"

    return {
        "url": url,
        "hostname": hostname,
        "domain": f"{ext.domain}.{ext.suffix}",
        "domain_age_days": age_days,
        "domain_age_error": age_error,
        "ssl_valid": ssl_ok,
        "ssl_error": ssl_error,
        "findings": all_findings,
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_class": verdict_class,
    }


def analyze_url(url):
    """CLI version — prints results."""
    print(f"\n{'='*60}")
    print(f"Analyzing: {url}")
    print(f"{'='*60}")

    result = _run_all_checks(url)

    print(f"\nDomain: {result['domain']}")
    if result["domain_age_days"] is not None:
        print(f"Domain age: {result['domain_age_days']} days")
    elif result["domain_age_error"]:
        print(f"Domain age: could not determine ({result['domain_age_error']})")

    print(f"SSL certificate: {'valid' if result['ssl_valid'] else 'INVALID/MISSING'}")

    if result["findings"]:
        print(f"\nFindings ({len(result['findings'])}):")
        for desc, severity in result["findings"]:
            print(f"  [{severity.upper()}] {desc}")
    else:
        print("\nNo suspicious indicators found.")

    print(f"\n--- VERDICT ---")
    print(f"Risk score: {result['risk_score']}")
    print(f"Result: {result['verdict']}")
    print(f"{'='*60}\n")


def analyze_url_for_web(url):
    """Web version — returns structured data for Flask to render."""
    return _run_all_checks(url)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detector.py <url1> [url2] ...")
        sys.exit(1)

    for url in sys.argv[1:]:
        analyze_url(url)
