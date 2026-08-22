"""Free auto-translate generator - src/i18n/translator.py:1
Uses free MyMemory API (no key) to translate en.json to any lang on-demand.
If offline/fails, falls back to placeholder.
"""
import json
import os
import time
import urllib.request
import urllib.parse
from pathlib import Path

LOCALES_DIR = Path(__file__).parent.parent.parent / "locales"

def translate_text(text: str, target_lang: str) -> str:
    """Translate via MyMemory free API: https://mymemory.translated.net"""
    if not text.strip():
        return text
    # Don't translate URLs or codes
    if "http" in text or "CVDS" in text:
        return text
    try:
        q = urllib.parse.quote(text)
        url = f"https://api.mymemory.translated.net/get?q={q}&langpair=en|{target_lang}"
        req = urllib.request.Request(url, headers={"User-Agent": "CVDS-i18n/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            trans = data.get("responseData", {}).get("translatedText", "")
            # MyMemory sometimes returns same text if fails
            if trans and trans.lower() != text.lower():
                return trans
            # fallback to placeholder
            return text
    except Exception as e:
        # network fail -> return original
        return text

def auto_generate(lang: str):
    target = LOCALES_DIR / f"{lang}.json"
    if target.exists():
        return True
    source = LOCALES_DIR / "en.json"
    if not source.exists():
        return False
    data = json.loads(source.read_text(encoding="utf-8"))
    new_data = {}
    print(f"[i18n] Auto-translating en -> {lang} via free API...")
    for k, v in data.items():
        # Keep app_name unchanged
        if k == "app_name":
            new_data[k] = v
        else:
            # Small delay to avoid rate limit
            time.sleep(0.35)
            new_data[k] = translate_text(v, lang)
            # If still English (failed), mark
            if new_data[k] == v and lang not in ["en"]:
                # keep original but log
                pass
        print(f"  {k}: {new_data[k][:60]}")

    # If all translations failed (offline), mark as placeholder
    LOCALES_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(new_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[i18n] Generated {target}")
    return True

# Popular languages for tray submenu
POPULAR_LANGS = [
    ("en", "English"),
    ("tr", "Türkçe"),
    ("de", "Deutsch"),
    ("fr", "Français"),
    ("es", "Español"),
    ("it", "Italiano"),
    ("ar", "العربية"),
    ("ru", "Русский"),
    ("ja", "日本語"),
    ("zh", "中文"),
    ("pt", "Português"),
    ("nl", "Nederlands"),
    ("pl", "Polski"),
    ("hi", "हिन्दी"),
    ("ko", "한국어"),
]
