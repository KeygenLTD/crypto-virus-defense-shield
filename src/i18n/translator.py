"""AI auto-translate generator - src/i18n/translator.py:1
If lang file missing, generate from en.json via template or LLM API.
For offline demo, copies en.json with TODO marker. Replace with real LLM call if OPENAI_API_KEY set.
"""
import json
import os
from pathlib import Path

LOCALES_DIR = Path(__file__).parent.parent.parent / "locales"

def auto_generate(lang: str):
    target = LOCALES_DIR / f"{lang}.json"
    if target.exists():
        return
    source = LOCALES_DIR / "en.json"
    if not source.exists():
        return
    data = json.loads(source.read_text(encoding="utf-8"))

    # If LLM key available, use it (optional)
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
    if api_key:
        try:
            # Example: call LLM to translate - keep minimal to avoid deps
            # You can replace with openai client
            import urllib.request
            # Fallback: just mark as auto
            pass
        except Exception:
            pass

    # Offline fallback: create file with en values + header
    # Real AI would translate values here
    new_data = {}
    for k, v in data.items():
        new_data[k] = f"[{lang}] {v}"  # placeholder - AI will replace

    LOCALES_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(new_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[i18n] Auto-generated placeholder for '{lang}' at {target} - replace with real translation")
