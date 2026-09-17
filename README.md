# FileGuard — Python Static File Scanner

A small defensive cybersecurity project that helps users **triage a suspicious file without executing it**.

## What it does

FileGuard performs static checks on a file:

- Calculates the **SHA-256 hash**
- Detects common file headers such as Windows PE (`MZ`), ZIP, PDF, PNG and JPEG
- Checks for executable/script-capable extensions
- Calculates approximate **byte entropy** to flag possible packing/encryption/compression
- Searches printable strings for indicators related to:
  - PowerShell
  - CMD and script execution
  - persistence
  - downloads/network activity
  - credential/browser access
  - common obfuscation techniques
- Detects suspicious double extensions such as `invoice.pdf.exe`
- Produces a simple triage verdict

### Important

**FileGuard never executes the file being scanned.**

It is a lightweight static-analysis/triage tool. A result such as `NO OBVIOUS STATIC INDICATORS` does **not** mean the file is guaranteed safe.

For stronger verification, compare the SHA-256 hash with a trusted source and scan the file with your endpoint security/antivirus solution or a reputable malware-analysis service.

---

## Requirements

- Python 3.8+
- No third-party Python packages required.

Check Python:

### Windows CMD

```cmd
python --version
```

or:

```cmd
py --version
```

### PowerShell

```powershell
python --version
```

---

## Run the scanner

Put `file_guard.py` in a folder.

### Windows CMD

Scan a file in the same folder:

```cmd
python file_guard.py suspicious.exe
```

Using the Python launcher:

```cmd
py file_guard.py suspicious.exe
```

Scan a file using its full path:

```cmd
python file_guard.py "C:\Users\YourName\Downloads\setup.exe"
```

### PowerShell

```powershell
python .\file_guard.py .\suspicious.exe
```

Full path:

```powershell
python .\file_guard.py "C:\Users\YourName\Downloads\setup.exe"
```

### Linux / macOS

```bash
python3 file_guard.py suspicious_file
```

---

## Example output

```text
================================================================
 FileGuard - Static File Scanner
================================================================
File     : C:\...\suspicious.exe
Size     : 125,440 bytes
Type     : Windows PE/DOS executable header (MZ)
SHA-256  : 0123456789abcdef...
Entropy  : 7.31/8.00
Score    : 7
Verdict  : SUSPICIOUS
----------------------------------------------------------------
Findings:
  [!] Executable/script-capable extension: .exe
  [!] PE-style executable header detected (MZ).
  [!] High byte entropy in scanned sample: 7.31/8.00
  [!] PowerShell indicators found: 2 pattern(s).
----------------------------------------------------------------
SAFETY: The target file was NOT executed.
A clean result does NOT prove a file is safe.
================================================================
```

The exact result depends on the file being scanned.

---

## How the score works

This is **not an antivirus detection score**.

It is only a heuristic used to make the output easier to understand.

- `0` → No obvious static indicators
- `1–3` → Low-risk indicators
- `4–7` → Suspicious indicators
- `8+` → High-risk indicators

A legitimate program can trigger indicators. Malware can also avoid them.

Therefore, **do not delete or execute a file solely because of this score**.

---

## Security design

The scanner intentionally avoids:

- `subprocess` execution of the target
- `os.system()` on the target
- `exec()` / `eval()` of target contents
- automatically opening suspicious files
- automatically installing anything
- automatically uploading files anywhere

The target is treated as **untrusted input**.

---

## Project structure

```text
FileGuard/
├── file_guard.py
└── README.md
```

---

## Safe testing

For testing, use files you own or intentionally created for analysis.

You can also test the scanner against harmless text/script samples to see how different strings affect the heuristic output.

Do **not** run unknown executable files just to test whether FileGuard detects them.

---

## Limitations

This project is intentionally lightweight.

It does not provide:

- full antivirus protection
- dynamic sandbox analysis
- YARA-level malware signatures
- behavioral monitoring
- kernel/rootkit detection
- guaranteed malware identification
- cloud reputation lookup

For a real malware-analysis workflow, use an isolated VM/sandbox and established security tooling.

---

## Why this is useful as a cybersecurity project

This project demonstrates practical concepts including:

- SHA-256 hashing
- file signatures / magic bytes
- static analysis
- entropy analysis
- suspicious string detection
- heuristic scoring
- defensive Python scripting
- safe handling of untrusted files

---

## License

MIT License
