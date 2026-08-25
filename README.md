# Crypto Virus Defense Shield (CVDS)

![Build](https://github.com/KeygenLTD/crypto-virus-defense-shield/actions/workflows/build.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

**Antivirus deletes the virus. Shield saves your files.**

An open-source **behavioral** ransomware defense framework. Unlike signature-based antiviruses and single-family decryptors, CVDS intercepts encryption *during* the act — via honeypot trapping + real-time CryptoAPI hooking — and hunts AES keys in RAM. Community-driven YARA rules make it universal.

> **Status:** v0.1 PoC — Honeypot + behavioral detection working. EXE auto-build via GitHub Actions. Contributions welcome.

---

### Why CVDS?

| Traditional Antivirus (Signature) | CVDS (Behavioral) |
|---|---|
| Checks if file hash is known malware | Checks if **behavior** is mass encryption |
| Misses zero-day / polymorphic variants | Catches zero-day — all ransomware must call `CryptEncrypt` |
| Deletes virus, files stay encrypted | Kills process **before** damage spreads + dumps RAM for key recovery |

CVDS is not an AV replacement. It is the **airbag** when AV fails.

### How It Works

```
Honeypot touched? ──No──> High-freq CryptEncrypt (>50/sec)? ──No──> High entropy burst? ──No──> Safe
      │ Yes                      │ Yes                            │ Yes
      └──── KILL + RAM DUMP ─────┴──── KILL + RAM DUMP ───────────┴──── KILL + RAM DUMP
                                    + YARA scan + Notify user
```

1.  **Honeypot Trap** — Plants canary files (`ZZZ_TRAP.docx`). Legitimate processes never touch them. Touch = 100% ransomware → Instant kill.
2.  **CryptoAPI Interceptor** — Hooks `advapi32.dll!CryptEncrypt` / `bcrypt.dll!BCryptEncrypt`. Flags high-frequency encryption + shadow copy deletion (`vssadmin delete shadows`).
3.  **Memory Hunter** — Scans process RAM for AES key schedules (high-entropy 32-byte sequences) and dumps keys before exit.

### For Users (No Python Needed)

1.  Go to **Releases** → Download `CVDS-Setup-0.2.0.exe` (installer) or `CryptoVirusDefenseShield.exe` (portable)
2.  Run → Shield appears in system tray (near clock) → Done. It auto-starts on boot.

### For Developers (Safe Demo)

> Demo is 100% safe — it creates its own isolated test folder and never touches your real files.

```bash
git clone https://github.com/KeygenLTD/crypto-virus-defense-shield.git
cd crypto-virus-defense-shield
pip install -r requirements.txt

# Terminal 1 — Start shield
python src/interceptor/detector.py

# Terminal 2 — Run safe simulator (encrypts only dummy test files)
python src/simulator/fake_ransomware.py
# -> Terminal 1: [SHIELD] Ransomware behavior detected!

# Restore dummy files
python src/simulator/restore.py
```

### Project Structure

```
crypto-virus-defense-shield/
├── src/interceptor/detector.py  # Honeypot + behavioral monitor
├── src/simulator/               # Safe ransomware simulator + restore
├── rules/yara/                  # Community YARA signatures (PRs welcome)
├── .github/workflows/build.yml  # Auto-builds Windows EXE
└── requirements.txt
```

### Contributing

New ransomware family? Add `rules/yara/<family>.yar` and open a PR. See `rules/yara/README.md` for rule format. All defensive contributions welcome — no live malware samples in repo.

### Topics

`ransomware` `malware` `cybersecurity` `yara` `forensics` `defense` `windows-security` `incident-response` `reverse-engineering`

### Disclaimer

For **defensive & educational** use only. Run only on isolated test folders or VMs. Does not guarantee decryption of AES-256/RSA-2048 — it attempts to *intercept* keys while in memory. Never disable your AV. Authors are not responsible for misuse.

### License

MIT © 2026 CVDS Contributors
