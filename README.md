# Crypto Virus Defense Shield (CVDS)

![Build](https://github.com/KeygenLTD/crypto-virus-defense-shield/actions/workflows/build.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Platform](https://img.shields.io/badge/Protection-Windows-blue.svg)

**A last-line ransomware containment layer for Windows.** CVDS watches real user-data
folders, plants randomized per-installation canaries, correlates suspicious file changes
with the responsible process, suspends a high-confidence suspect, and records an incident
before offering a guarded one-click quarantine action.

CVDS complements Microsoft Defender; it does not replace antivirus, patching, MFA,
tested offline backups, or an incident-response plan.

> **Current status:** v0.3.0 release candidate. Unit-tested on Python 3.11/3.12;
> Windows Defender policy, process suspension, minidump capture, installer, and packaged
> EXEs are tested by the Windows CI job. No live malware is stored in or executed by this
> project.

[Türkçe belge](README.tr.md)

## What v0.3 actually does

- Discovers Desktop, Documents, Downloads, Pictures, Music, Videos, OneDrive folders,
  configured roots, and non-system fixed/removable data drives. It no longer watches a
  hard-coded `%TEMP%` demo directory.
- Creates three hidden, randomized canaries in every protected root and removes only
  manifest-owned CVDS canaries during uninstall.
- Scores canary changes, mass file activity, extension changes, output entropy, recovery
  destruction commands, and curated family indicators.
- Attributes the event using an exact open-file handle first, then a known family process
  indicator, then correlated write rate. A suspect is suspended only when the combined
  confidence reaches the containment threshold.
- Captures a Windows minidump and searches readable private memory for structurally valid
  expanded AES-128/192/256 key schedules. Saved values are explicitly marked **unverified
  candidates** until they decrypt known data; key recovery is never guaranteed.
- Adds `CVDS Emergency Cleanup` to the desktop. It terminates only the recorded process
  identity, verifies the executable hash, refuses protected Windows, Program Files, and
  ProgramData paths, quarantines the file, removes an exact matching Run/RunOnce entry,
  and requests a Microsoft Defender custom scan.
- Optionally enables Defender Controlled Folder Access and the Defender **Entry Shield**
  controls described below.

There is no undocumented CryptoAPI hook and no claim that every ransomware family calls
one Windows API. The primary detector is family-independent behavior plus canaries.

## Where ransomware gets in, and what Entry Shield blocks

The installer offers a **balanced** Entry Shield. It enables Defender cloud protection,
block-at-first-sight, PUA protection, Network Protection, behavior/script/archive/removable
drive scanning, and merges 18 CVDS ASR actions with the existing policy without discarding
unrelated rules. `strict` changes the CVDS audit actions to block.

| Initial-access route | Balanced control | Remaining gap |
|---|---|---|
| Email/webmail attachment, ZIP, EXE, script | Blocks executable content from email/webmail; blocks Office and Outlook child processes | Password-protected archives or content opened outside supported clients can still require Defender/cloud detection |
| Malicious Office/PDF document | Blocks Office executable creation, Office injection, Office macro Win32 calls, and Adobe Reader child processes | Legitimate macro-heavy workflows should be compatibility-tested |
| Fake update, cracked software, malicious ad/link | Network Protection, PUA, cloud/block-at-first-sight; unknown/low-prevalence executables are audited in balanced and blocked in strict | A trusted/signed or newly compromised supplier can still evade reputation checks |
| JavaScript, VBScript, PowerShell loader | Blocks JS/VBS downloaded executable launches; keeps AMSI/script scanning on; obfuscated scripts are audited in balanced | Audit events need review; strict mode blocks the audited rule |
| USB/removable media | Blocks untrusted/unsigned USB processes and enables removable-drive scanning | Trusted/signed malicious files remain possible |
| Stolen credentials, LSASS dumping | Blocks LSASS credential theft | Already-stolen VPN/RDP credentials require MFA, access allowlists, and account monitoring outside CVDS |
| PsExec, WMI, RMM lateral movement | CVDS detects recovery-destruction commands; PsExec/WMI process creation and WMI persistence are audited in balanced, blocked in strict | Balanced mode intentionally avoids breaking legitimate administration tools |
| Exploited public VPN/firewall/web application | Network Protection and vulnerable-driver blocking reduce post-exploit options | CVDS is not a patch manager or perimeter firewall; exposed services still must be patched, restricted, and MFA-protected |

Entry Shield relies on Microsoft Defender Antivirus. Domain/Intune policy or Tamper
Protection can reject local changes; CVDS reports that failure instead of claiming the
control is active. Uninstall does not weaken Defender settings that may protect the host.

Official control reference: [Microsoft Defender ASR rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference).

## Ransomware-family engineering coverage

This table is **not a live-malware detection-rate certification**. “High/medium/limited”
describes the available Windows engineering signals in v0.3. Generic canary and mass-
encryption behavior can still detect an unknown family; a family name is attached only
when a curated indicator matches.

| Family | Curated signals | Expected Windows coverage | Important caveat / official source |
|---|---|---|---|
| Medusa | `.medusa`, `!!!READ_ME_MEDUSA!!!.txt`, `gaze.exe`, recovery destruction | **High** | Windows encryptor path; Linux/ESXi not protected. [CISA AA25-071A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| Gunra | `.CRYPT`, `R3ADM3` | **Medium** family attribution; **high** generic behavior | `.crypt` alone is ambiguous. [CISA AA26-222A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a) |
| Interlock | `.interlock`, `.1nt3rlock`, `!__README__!.txt` | **High** | Windows path only. [CISA AA25-203A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a) |
| Akira | `.akira`, `.akiranew`, family ransom notes | **High** | Windows path only; variants can change artifacts. [CISA AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) |
| Play | `.PLAY`, `ReadMe.txt` | **Medium** family attribution; **high** generic behavior | `ReadMe.txt` is too generic to act on alone. [CISA AA23-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a) |
| RansomHub | `How To Restore Your Files.txt`; generic behavior | **Medium** | Uses variable extensions, so family attribution may arrive late. [CISA AA24-242A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a) |
| Black Basta | `.basta`; generic ransom note | **Medium/High** | Generic `readme.txt` receives a low score by design. [CISA AA24-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a) |
| LockBit 3.0 | `*.README.txt`; generic behavior | **Medium** | Per-victim random extension/ID limits early family naming. [CISA AA23-075A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a) |
| Rhysida | `.rhysida`, `CriticalBreachDetected.pdf` | **High** | Windows encryptor path. [CISA AA23-319A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a) |
| BianLian | `.bianlian`; generic behavior | **Limited/High** | High when it encrypts; exfiltration-only extortion is outside a file-encryption shield. [CISA AA23-136A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a) |
| CL0P | `.Clop`/`.Cl0p` variants, `ClopReadMe.txt` | **Medium/High** | CVDS can contain local encryption, not undo server-side data theft. [FortiGuard Labs](https://www.fortinet.com/blog/threat-research/ransomware-roundup-cl0p) |
| Unknown/new family | Canary, burst, entropy, extension changes, writer correlation | **Behavior-dependent** | Slow, selective, remote, or data-theft-only attacks can avoid mass-encryption signals |

Profiles live in [`rules/ransomware_families.json`](rules/ransomware_families.json) and
include their source URLs. CVDS currently protects Windows endpoints only; platform names
in the profile are threat context, not a claim of Linux/ESXi protection.

## Install and operate

Download the published artifacts from **Releases** after the v0.3.0 workflow passes:

- `CVDS-Setup-0.3.0.exe` — installs the agent, desktop cleanup utility, startup entry,
  and optional Defender protections.
- `CryptoVirusDefenseShield.exe` — portable agent.
- `CVDSEmergencyCleanup.exe` — guarded cleanup utility.

Tray actions show status, incidents, emergency cleanup, Defender folder protection, Entry
Shield, language, and startup state. Incident data is stored under `%LOCALAPPDATA%\CVDS`.
Memory dumps and candidate keys are sensitive; protect them as incident-response evidence.

Command-line administration:

```powershell
CryptoVirusDefenseShield.exe --status
CryptoVirusDefenseShield.exe --enable-cfa
CryptoVirusDefenseShield.exe --enable-entry-shield balanced
CryptoVirusDefenseShield.exe --enable-entry-shield strict
```

## Safe developer test

The simulator refuses arbitrary directories. It only mutates verified dummy files under a
directory named `cvds-safe-simulation` containing the exact safety marker.

```powershell
python -m pip install -r requirements.txt pytest
python src/simulator/fake_ransomware.py --prepare

$env:CVDS_PROTECTED_ROOTS = "$env:TEMP\cvds-safe-simulation"
$env:CVDS_STATE_DIR = "$env:TEMP\cvds-safe-state"
python src/interceptor/detector.py --no-tray --response-mode alert

# In a second PowerShell window with the same CVDS_PROTECTED_ROOTS:
python src/simulator/fake_ransomware.py --run
python src/simulator/restore.py
python -m pytest -q
```

`--response-mode alert` is for harmless development simulation. Production defaults to
high-confidence process suspension.

## Known boundaries

- User-mode monitoring can be killed by an administrator-level attacker; Defender CFA/ASR
  adds a separate operating-system enforcement layer.
- Events can occur after some files are changed. CVDS is containment, not rollback.
- AES schedule capture works only when a supported expanded schedule remains in readable
  process memory. Modern ransomware can use ChaCha, custom crypto, hardware-backed keys,
  per-file keys, public-key wrapping, or erase the schedule before capture.
- A captured AES candidate is not automatically a decryptor. Preserve the dump, encrypted
  samples, originals, metadata, and incident JSON for forensic validation.
- Slow/selective encryption, network-side encryption, Linux/ESXi payloads, and pure data
  theft need other controls.

## Contributing and security

Run `python -m pytest -q`; do not upload live malware. Family-profile changes require an
authoritative public source. Report product vulnerabilities using the repository's private
GitHub Security Advisory flow.

MIT © 2026 CVDS Contributors
