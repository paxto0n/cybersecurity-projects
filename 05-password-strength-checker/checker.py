import sys
import re
import math
import hashlib
import subprocess
import urllib.request
import urllib.error

SEQUENTIAL_RUNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]

ROCKYOU_PATH = "/usr/share/wordlists/rockyou.txt"
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

# guesses per second, illustrative reference points
CRACK_RATES = {
    "Online attack (rate-limited login)": 100,
    "Offline, slow hash (bcrypt/scrypt)": 10_000,
    "Offline, fast hash (unsalted MD5/SHA1, GPU rig)": 10_000_000_000,
}


def check_length(password):
    length = len(password)
    if length < 8:
        return length, "high", f"Very short password ({length} characters)"
    elif length < 12:
        return length, "medium", f"Below-recommended length ({length} characters)"
    else:
        return length, None, None


def check_character_variety(password):
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])

    findings = []
    if not has_upper:
        findings.append(("No uppercase letters", "low"))
    if not has_lower:
        findings.append(("No lowercase letters", "low"))
    if not has_digit:
        findings.append(("No digits", "low"))
    if not has_symbol:
        findings.append(("No special characters", "medium"))

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 33

    return variety_count, charset_size, findings


def calculate_entropy(password, charset_size):
    if charset_size == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def check_patterns(password):
    findings = []
    lower_pw = password.lower()

    if re.search(r"(.)\1{3,}", password):
        findings.append(("Contains a long run of the same repeated character", "medium"))

    for run in SEQUENTIAL_RUNS:
        for i in range(len(run) - 3):
            chunk = run[i:i + 4]
            if chunk in lower_pw or chunk[::-1] in lower_pw:
                findings.append((f"Contains a predictable sequence ('{chunk}')", "medium"))
                break

    return findings


def check_rockyou(password):
    try:
        result = subprocess.run(
            ["grep", "-x", "-F", "-m", "1", password, ROCKYOU_PATH],
            capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def check_hibp(password, timeout=5):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        req = urllib.request.Request(
            HIBP_API_URL + prefix,
            headers={"User-Agent": "password-strength-checker-lab-project"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")

        for line in body.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0

    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def format_duration(seconds):
    """Convert seconds into a human-readable duration string."""
    if seconds < 1:
        return "instantly"

    units = [
        ("centuries", 100 * 365 * 24 * 3600),
        ("years", 365 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]

    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value > 1_000_000:
                return f"{value:.2e} {name}"
            return f"{value:,.1f} {name}"

    return "instantly"


def estimate_crack_times(entropy):
    """
    Estimate brute-force time at a few reference guess rates.
    Assumes on average half the keyspace must be searched (2^entropy / 2).
    Illustrative only — real-world cracking depends heavily on the
    attacker's method (dictionary, rules, masks) not just raw keyspace.
    """
    keyspace = 2 ** entropy
    estimates = {}
    for label, rate in CRACK_RATES.items():
        seconds = (keyspace / 2) / rate
        estimates[label] = format_duration(seconds)
    return estimates


def score_password(password, use_hibp=True):
    findings = []

    length, length_sev, length_msg = check_length(password)
    if length_msg:
        findings.append((length_msg, length_sev))

    variety_count, charset_size, variety_findings = check_character_variety(password)
    findings.extend(variety_findings)

    entropy = calculate_entropy(password, charset_size)

    pattern_findings = check_patterns(password)
    findings.extend(pattern_findings)

    in_rockyou = check_rockyou(password)
    if in_rockyou is True:
        findings.append(("Found in the rockyou.txt breach dump — this password is publicly known", "high"))
    elif in_rockyou is None:
        findings.append(("Could not check against rockyou.txt (wordlist unavailable)", "low"))

    hibp_count = None
    if use_hibp:
        hibp_count = check_hibp(password)
        if hibp_count and hibp_count > 0:
            findings.append((
                f"Found in Have I Been Pwned — seen in {hibp_count:,} breach record(s)", "high"
            ))
        elif hibp_count is None:
            findings.append(("Could not reach Have I Been Pwned (offline or API error)", "low"))

    severity_weight = {"high": 3, "medium": 2, "low": 1}
    penalty = sum(severity_weight.get(sev, 1) for _, sev in findings)

    breached = (in_rockyou is True) or (hibp_count and hibp_count > 0)

    if breached:
        strength = "VERY WEAK"
    elif entropy < 28 or penalty >= 6:
        strength = "VERY WEAK"
    elif entropy < 36 or penalty >= 4:
        strength = "WEAK"
    elif entropy < 60 or penalty >= 2:
        strength = "MODERATE"
    elif entropy < 80:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"

    crack_times = estimate_crack_times(entropy)

    return {
        "password": password,
        "length": length,
        "variety_count": variety_count,
        "entropy": round(entropy, 1),
        "in_rockyou": in_rockyou,
        "hibp_count": hibp_count,
        "findings": findings,
        "strength": strength,
        "crack_times": crack_times,
    }


def print_result(result):
    print(f"\n{'='*50}")
    print(f"Password strength: {result['strength']}")
    print(f"{'='*50}")
    print(f"Length: {result['length']} characters")
    print(f"Character variety: {result['variety_count']}/4 (upper/lower/digit/symbol)")
    print(f"Estimated entropy: {result['entropy']} bits")

    if result["findings"]:
        print(f"\nFindings ({len(result['findings'])}):")
        for desc, severity in result["findings"]:
            print(f"  [{severity.upper()}] {desc}")
    else:
        print("\nNo structural weaknesses found.")

    if not result.get("in_rockyou") and not result.get("hibp_count"):
        print(f"\nEstimated brute-force time (illustrative only):")
        for label, duration in result["crack_times"].items():
            print(f"  {label}: {duration}")

    print(f"{'='*50}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 checker.py <password>")
        sys.exit(1)

    password = sys.argv[1]
    result = score_password(password)
    print_result(result)
