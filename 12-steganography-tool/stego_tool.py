#!/usr/bin/env python3
"""
Project #12 - Steganography Tool
Hides and extracts data inside PNG images using LSB (Least Significant Bit)
encoding. Optionally layers AES-256 encryption on the payload via
crypto_tool.py (Project #8) before embedding it, so extracted bits are
ciphertext unless you also have the password.

Usage:
    python3 stego_tool.py encode -i cover.png -o stego.png -m "secret message"
    python3 stego_tool.py encode -i cover.png -o stego.png -f secret.txt --encrypt
    python3 stego_tool.py decode -i stego.png
    python3 stego_tool.py decode -i stego.png --decrypt
    python3 stego_tool.py capacity -i cover.png
    python3 stego_tool.py detect -i suspect.png
"""

import argparse
import getpass
import importlib.util
import struct
import sys
from pathlib import Path

from PIL import Image
import numpy as np
from scipy import stats

MAGIC = b"STG1"          # 4-byte header to identify our payloads on decode
LEN_BYTES = 4             # uint32 length prefix after the magic

# ---------------------------------------------------------------------------
# Optional integration with Project #8's crypto_tool.py
# ---------------------------------------------------------------------------

def _load_crypto_tool():
    """
    Try to import crypto_tool.py from ../crypto_tool/ (sibling project dir).
    Returns the module, or None if not found. Keeps this tool fully
    standalone when crypto_tool isn't available.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / "crypto_tool" / "crypto_tool.py",
        Path.home() / "crypto_tool" / "crypto_tool.py",
    ]
    for path in candidates:
        if path.exists():
            spec = importlib.util.spec_from_file_location("crypto_tool", path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                return module
            except Exception:
                return None
    return None


def _encrypt_payload(data: bytes, quiet: bool) -> bytes:
    """Encrypt data with crypto_tool if available, else raise."""
    crypto_tool = _load_crypto_tool()
    if crypto_tool is None:
        raise RuntimeError(
            "crypto_tool.py not found (looked in ../crypto_tool/ and ~/crypto_tool/). "
            "Cannot use --encrypt without it."
        )
    password = getpass.getpass("Encryption password: ")
    # crypto_tool from Project #8 is expected to expose an AES-256-CBC/PBKDF2
    # helper. We call the most likely function names defensively so this
    # keeps working even if that project's API shifts slightly.
    if hasattr(crypto_tool, "encrypt_bytes"):
        return crypto_tool.encrypt_bytes(data, password)
    elif hasattr(crypto_tool, "aes_encrypt"):
        return crypto_tool.aes_encrypt(data, password)
    else:
        raise RuntimeError(
            "crypto_tool.py found but no compatible encrypt function "
            "(expected encrypt_bytes() or aes_encrypt()). Check Project #8's API."
        )


def _decrypt_payload(data: bytes, quiet: bool) -> bytes:
    crypto_tool = _load_crypto_tool()
    if crypto_tool is None:
        raise RuntimeError(
            "crypto_tool.py not found. Cannot use --decrypt without it."
        )
    password = getpass.getpass("Decryption password: ")
    if hasattr(crypto_tool, "decrypt_bytes"):
        return crypto_tool.decrypt_bytes(data, password)
    elif hasattr(crypto_tool, "aes_decrypt"):
        return crypto_tool.aes_decrypt(data, password)
    else:
        raise RuntimeError(
            "crypto_tool.py found but no compatible decrypt function "
            "(expected decrypt_bytes() or aes_decrypt())."
        )


# ---------------------------------------------------------------------------
# Core LSB steganography
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def image_capacity_bytes(image_path: str) -> int:
    """Max payload bytes embeddable (using 1 LSB per RGB channel)."""
    img = Image.open(image_path)
    img = img.convert("RGB")
    w, h = img.size
    total_bits = w * h * 3
    return total_bits // 8


def embed_data(image_path: str, output_path: str, payload: bytes, quiet: bool = False):
    img = Image.open(image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")

    arr = np.array(img)
    flat = arr.reshape(-1)  # flatten to 1D array of channel values

    framed = MAGIC + struct.pack(">I", len(payload)) + payload
    bits = _bytes_to_bits(framed)

    capacity = flat.size
    if bits.size > capacity:
        raise ValueError(
            f"Payload too large: needs {bits.size} bits, image has capacity "
            f"for {capacity} bits ({capacity // 8} bytes, you need "
            f"{bits.size // 8 + 1} bytes)."
        )

    # Clear LSB of each channel value we're about to use, then OR in the bit
    flat = flat.copy()
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits

    stego_arr = flat.reshape(arr.shape)
    stego_img = Image.fromarray(stego_arr.astype(np.uint8))
    stego_img.save(output_path, format="PNG")  # PNG only -- lossless is mandatory

    if not quiet:
        used_pct = (bits.size / capacity) * 100
        print(f"[+] Embedded {len(payload)} bytes into {output_path}")
        print(f"[+] Capacity used: {used_pct:.4f}% ({bits.size // 8}/{capacity // 8} bytes)")


def extract_data(image_path: str, quiet: bool = False) -> bytes:
    img = Image.open(image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")

    arr = np.array(img)
    flat = arr.reshape(-1)
    lsbs = flat & 1

    header_bits_needed = (len(MAGIC) + LEN_BYTES) * 8
    if lsbs.size < header_bits_needed:
        raise ValueError("Image too small to contain a valid payload header.")

    header_bytes = _bits_to_bytes(lsbs[:header_bits_needed])
    magic = header_bytes[: len(MAGIC)]
    if magic != MAGIC:
        raise ValueError(
            "No valid steganography payload found (magic header mismatch). "
            "This image likely doesn't contain data hidden by this tool."
        )

    payload_len = struct.unpack(">I", header_bytes[len(MAGIC): len(MAGIC) + LEN_BYTES])[0]
    total_bits_needed = header_bits_needed + payload_len * 8
    if lsbs.size < total_bits_needed:
        raise ValueError("Declared payload length exceeds available image data (corrupted?).")

    payload_bits = lsbs[header_bits_needed:total_bits_needed]
    payload = _bits_to_bytes(payload_bits)

    if not quiet:
        print(f"[+] Found payload: {payload_len} bytes")

    return payload


# ---------------------------------------------------------------------------
# Chi-square steganalysis (basic LSB detection)
# ---------------------------------------------------------------------------

def _pov_pvalue(values: np.ndarray) -> tuple:
    """
    Westfeld & Pfitzmann-style Pairs-of-Values chi-square test on one
    segment of pixel channel values. Sequential LSB embedding equalizes the
    frequencies within each (2i, 2i+1) value pair, so a *high* p-value
    (observed frequencies closely matching the "flattened" expectation)
    is the signal that data is embedded in that segment -- not a low
    chi-square in isolation, which natural images can also produce.
    """
    hist = np.bincount(values, minlength=256).astype(float)
    chi_sq = 0.0
    dof = 0
    for i in range(0, 256, 2):
        even, odd = hist[i], hist[i + 1]
        expected = (even + odd) / 2.0
        if expected > 4:  # skip near-empty bins, they distort the test
            chi_sq += ((even - expected) ** 2) / expected
            dof += 1
    if dof == 0:
        return 0.0, 0.0
    p_value = stats.chi2.sf(chi_sq, dof)
    return chi_sq, p_value


def chi_square_analysis(image_path: str, windows: int = 20) -> dict:
    """
    Windowed chi-square (Pairs of Values) steganalysis. Splits the image's
    channel data into sequential segments and tests each one, since basic
    LSB tools (including this one) embed sequentially from the start of the
    image -- so partial-capacity payloads only "flatten" an early portion
    of the data, not the whole image. A single whole-image test would miss
    that.

    This is a heuristic based on a known-weak, well-documented attack. It
    works reasonably well against naive sequential LSB embedding (like this
    tool's own `encode`) but can be evaded by randomized bit placement,
    LSB matching instead of replacement, or low embedding rates. Treat any
    result as a signal to investigate, not proof.
    """
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img).reshape(-1)

    segment_size = max(len(arr) // windows, 256)
    segment_results = []
    for start in range(0, len(arr), segment_size):
        segment = arr[start:start + segment_size]
        if segment.size < 256:
            continue
        chi_sq, p_value = _pov_pvalue(segment)
        segment_results.append(p_value)

    high_p_threshold = 0.9
    flagged = [p for p in segment_results if p > high_p_threshold]
    fraction_flagged = len(flagged) / len(segment_results) if segment_results else 0.0

    # If a meaningful leading fraction of segments look "flattened," call it.
    likely_stego = fraction_flagged >= 0.15

    return {
        "segments_analyzed": len(segment_results),
        "segments_flagged": len(flagged),
        "fraction_flagged": round(fraction_flagged, 3),
        "likely_contains_lsb_data": likely_stego,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    # Shared -q/--quiet flag: defined on a parent parser so it works both
    # before AND after the subcommand (e.g. `stego_tool.py -q encode ...`
    # and `stego_tool.py encode ... -q` both work). A --quiet only on the
    # top-level parser would silently fail to parse in the second position.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="Suppress banner/status text (for shell capture)")

    parser = argparse.ArgumentParser(description="LSB Steganography Tool (Project #12)", parents=[common])
    sub = parser.add_subparsers(dest="command", required=True)

    p_encode = sub.add_parser("encode", help="Hide data inside an image", parents=[common])
    p_encode.add_argument("-i", "--input", required=True, help="Cover image path")
    p_encode.add_argument("-o", "--output", required=True, help="Output stego image path (.png)")
    group = p_encode.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--message", help="Text message to hide")
    group.add_argument("-f", "--file", help="Path to file whose contents to hide")
    p_encode.add_argument("--encrypt", action="store_true", help="Encrypt payload via crypto_tool.py before embedding")

    p_decode = sub.add_parser("decode", help="Extract hidden data from an image", parents=[common])
    p_decode.add_argument("-i", "--input", required=True, help="Stego image path")
    p_decode.add_argument("-o", "--output", help="Write extracted bytes to file instead of stdout")
    p_decode.add_argument("--decrypt", action="store_true", help="Decrypt extracted payload via crypto_tool.py")

    p_cap = sub.add_parser("capacity", help="Show max embeddable payload size for an image", parents=[common])
    p_cap.add_argument("-i", "--input", required=True, help="Image path")

    p_detect = sub.add_parser("detect", help="Run chi-square steganalysis on an image", parents=[common])
    p_detect.add_argument("-i", "--input", required=True, help="Image path to analyze")

    args = parser.parse_args()

    try:
        if args.command == "encode":
            if args.message:
                payload = args.message.encode("utf-8")
            else:
                payload = Path(args.file).read_bytes()

            if args.encrypt:
                payload = _encrypt_payload(payload, args.quiet)
                if not args.quiet:
                    print("[+] Payload encrypted with crypto_tool.py")

            embed_data(args.input, args.output, payload, quiet=args.quiet)

        elif args.command == "decode":
            payload = extract_data(args.input, quiet=args.quiet)

            if args.decrypt:
                payload = _decrypt_payload(payload, args.quiet)
                if not args.quiet:
                    print("[+] Payload decrypted with crypto_tool.py")

            if args.output:
                Path(args.output).write_bytes(payload)
                if not args.quiet:
                    print(f"[+] Written to {args.output}")
            else:
                try:
                    print(payload.decode("utf-8"))
                except UnicodeDecodeError:
                    print("[!] Payload is binary data; use -o to save it to a file instead of printing.")
                    sys.exit(1)

        elif args.command == "capacity":
            cap = image_capacity_bytes(args.input)
            if args.quiet:
                print(cap)
            else:
                print(f"[+] {args.input}: capacity ~{cap} bytes ({cap / 1024:.1f} KB) "
                      f"before accounting for the 8-byte header")

        elif args.command == "detect":
            result = chi_square_analysis(args.input)
            if args.quiet:
                print(result["likely_contains_lsb_data"])
            else:
                print(f"[*] Segments analyzed : {result['segments_analyzed']}")
                print(f"[*] Segments flagged  : {result['segments_flagged']} "
                      f"({result['fraction_flagged'] * 100:.1f}%)")
                verdict = "LIKELY contains LSB-hidden data" if result["likely_contains_lsb_data"] else "no strong LSB signal detected"
                print(f"[*] Verdict           : {verdict}")
                print("[!] Heuristic only -- reliable mainly against naive sequential LSB "
                      "embedding (like this tool's own encoder). Confirm with a known-clean "
                      "baseline image before trusting this.")

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
