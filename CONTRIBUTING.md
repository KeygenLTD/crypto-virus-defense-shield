# Contributing to Crypto Virus Defense Shield

Thanks for helping! This is a defensive-only framework.

## How to Contribute
1. **Family profiles:** Update `rules/ransomware_families.json` with an authoritative public reference. Indicators must not trigger containment by themselves unless they are specific enough.
2. **YARA rules:** Add `rules/yara/<family>.yar` with a reference link. Do not upload live samples.
3. **Code:** Fork -> branch (`feat/my-feature`) -> PR. Run `python -m pytest -q` before the PR.
4. **Translations:** Edit a bundled `locales/<code>.json`; the endpoint agent never sends UI text to an online translation service.

## Rules
- No live malware binaries in repo. Use hashes/references only.
- Keep containment confidence-gated and preserve protected Windows/application paths.
- Tests may use only the marker-guarded `src/simulator/fake_ransomware.py`; never use a live sample.

## Commit Style
`feat:`, `fix:`, `docs:`, `chore:` prefixes.

## Questions?
Open an Issue with `question` label.
