#!/usr/bin/env python3
"""
FileGuard - simple defensive static file scanner.

IMPORTANT:
- This tool DOES NOT execute the file being scanned.
- It performs static checks: hashes, file type, entropy, suspicious strings/patterns,
  archive/script indicators, and basic PE checks.
- It is a triage tool, not a replacement for Microsoft Defender/antivirus or sandboxing.
"""

import argparse
import hashlib
import math
import re
import sys
from pathlib import Path

SUSPICIOUS_PATTERNS = {
    "PowerShell": [
        r"\bpowershell(?:\.exe)?\b",
        r"-enc(?:odedcommand)?\b",
        r"frombase64string",
        r"invoke-expression",
        r"\biex\b",
        r"downloadstring",
        r"invoke-webrequest",
        r"start-bitstransfer",
    ],
    "Command/Execution": [
        r"\bcmd(?:\.exe)?\s*/c\b",
        r"\bwscript(?:\.exe)?\b",
        r"\bcscript(?:\.exe)?\b",
        r"\bmshta(?:\.exe)?\b",
        r"\brundll32(?:\.exe)?\b",
        r"\bregsvr32(?:\.exe)?\b",
        r"\bcertutil(?:\.exe)?\b",
    ],
    "Persistence": [
        r"\\currentversion\\run\b",
        r"\bschtasks(?:\.exe)?\b",
        r"\btask scheduler\b",
        r"\bstartup\b",
    ],
    "Network/Download": [
        r"https?://",
        r"\bsocket\b",
        r"\burllib\b",
        r"\brequests\b",
        r"\bhttpclient\b",
        r"\bdownloadfile\b",
    ],
    "Credential/Browser Access": [
        r"login data",
        r"cookies",
        r"passwords?",
        r"credential",
        r"keylog",
        r"webbrowser",
        r"local state",
    ],
    "Obfuscation": [
        r"base64",
        r"rot13",
        r"xor",
        r"chr\s*\(",
        r"exec\s*\(",
        r"eval\s*\(",
    ],
}

RISKY_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".hta", ".jar", ".lnk", ".reg", ".com",
    ".cpl", ".pif", ".wsf", ".wsh", ".py", ".pyw"
}

PE_EXTENSIONS = {".exe", ".dll", ".scr", ".cpl", ".sys", ".ocx"}


def sha256_file(path: Path, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def read_sample(path: Path, limit=8 * 1024 * 1024):
    with path.open("rb") as f:
        return f.read(limit)


def detect_type(data: bytes):
    if data.startswith(b"MZ"):
        return "Windows PE/DOS executable header (MZ)"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP-based archive"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data.startswith(b"%PDF"):
        return "PDF document"
    if data.startswith(b"\x89PNG"):
        return "PNG image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if data.startswith(b"#!"):
        return "Script with shebang"
    return "Unknown/binary or ordinary document"


def printable_strings(data: bytes, minimum=4):
    # ASCII printable strings only; enough for a lightweight triage scanner.
    raw = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    return [x.decode("ascii", errors="ignore") for x in raw]


def scan(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")

    size = path.stat().st_size
    data = read_sample(path)
    text = "\n".join(printable_strings(data)).lower()
    ext = path.suffix.lower()
    file_type = detect_type(data)
    ent = entropy(data)

    findings = []
    score = 0

    if ext in RISKY_EXTENSIONS:
        findings.append(f"Executable/script-capable extension: {ext}")
        score += 1

    if ext in PE_EXTENSIONS and data.startswith(b"MZ"):
        findings.append("PE-style executable header detected (MZ).")
        score += 2

    if ent >= 7.2 and len(data) >= 4096:
        findings.append(f"High byte entropy in scanned sample: {ent:.2f}/8.00 (may indicate packing/encryption/compression).")
        score += 2

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        hits = []
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                hits.append(pattern)
        if hits:
            findings.append(f"{category} indicators found: {len(hits)} pattern(s).")
            score += min(3, len(hits))

    # Extra warning for double extensions commonly used in social engineering.
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|jpeg|png|txt)\.(exe|scr|bat|cmd|ps1|js|vbs)$", path.name, re.I):
        findings.append("Double-extension filename resembles a document/image but ends in an executable/script extension.")
        score += 3

    if score >= 8:
        verdict = "HIGH-RISK INDICATORS"
    elif score >= 4:
        verdict = "SUSPICIOUS"
    elif score >= 1:
        verdict = "LOW-RISK INDICATORS"
    else:
        verdict = "NO OBVIOUS STATIC INDICATORS"

    return {
        "path": path,
        "size": size,
        "sha256": sha256_file(path),
        "type": file_type,
        "entropy": ent,
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="FileGuard: static triage scanner. It never executes the target file."
    )
    parser.add_argument("file", help="Path to the file you want to inspect")
    args = parser.parse_args()

    try:
        result = scan(Path(args.file))
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1

    print("\n" + "=" * 64)
    print(" FileGuard - Static File Scanner")
    print("=" * 64)
    print(f"File     : {result['path'].resolve()}")
    print(f"Size     : {result['size']:,} bytes")
    print(f"Type     : {result['type']}")
    print(f"SHA-256  : {result['sha256']}")
    print(f"Entropy  : {result['entropy']:.2f}/8.00")
    print(f"Score    : {result['score']}")
    print(f"Verdict  : {result['verdict']}")
    print("-" * 64)

    if result["findings"]:
        print("Findings:")
        for finding in result["findings"]:
            print(f"  [!] {finding}")
    else:
        print("Findings:")
        print("  [+] No obvious static indicators were found.")

    print("-" * 64)
    print("SAFETY: The target file was NOT executed.")
    print("A clean result does NOT prove a file is safe.")
    print("=" * 64 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
