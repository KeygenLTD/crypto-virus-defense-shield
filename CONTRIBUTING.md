# Contributing to Crypto Virus Defense Shield

Thanks for helping! This is a defensive-only framework.

## How to Contribute
1.  **YARA Rules:** Add `rules/yara/<family>.yar` for new ransomware families. Include reference link. Do not upload live samples.
2.  **Code:** Fork -> branch (`feat/my-feature`) -> PR. Run `python -m py_compile` before PR.
3.  **Translations:** Edit `locales/<code>.json` or select language in tray to auto-generate.

## Rules
- No live malware binaries in repo. Use hashes/references only.
- Keep `detector.py` safe: must only touch `crypto-test` by default. Real protection is opt-in.
- Tests: Use `src/simulator/fake_ransomware.py` for safe testing.

## Commit Style
`feat:`, `fix:`, `docs:`, `chore:` prefixes.

## Questions?
Open an Issue with `question` label.
