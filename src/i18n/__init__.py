"""i18n loader - src/i18n/__init__.py:1"""
import json
import os
import sys
from pathlib import Path

def _get_locales_dir():
    # PyInstaller support: files are in _MEIPASS
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return Path(sys._MEIPASS) / "locales"
    return Path(__file__).parent.parent.parent / "locales"

LOCALES_DIR = _get_locales_dir()
CONFIG_FILE = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "cvds_lang.txt"
DEFAULT_LANG = "en"

_cache = {}
_current = None

def get_available_languages():
    if not LOCALES_DIR.exists():
        return ["en"]
    return sorted([p.stem for p in LOCALES_DIR.glob("*.json")])

def load_lang(lang: str):
    global _cache
    if lang in _cache:
        return _cache[lang]
    path = LOCALES_DIR / f"{lang}.json"
    if not path.exists():
        # Try auto-generate via AI
        try:
            from src.i18n.translator import auto_generate
            auto_generate(lang)
        except Exception:
            pass
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        _cache[lang] = data
        return data
    # fallback to en
    en_path = LOCALES_DIR / "en.json"
    data = json.loads(en_path.read_text(encoding="utf-8")) if en_path.exists() else {}
    _cache[lang] = data
    return data

def get_current_lang():
    global _current
    if _current:
        return _current
    # 1. saved config 2. system locale 3. default
    if CONFIG_FILE.exists():
        try:
            lang = CONFIG_FILE.read_text(encoding="utf-8").strip()
            if (LOCALES_DIR / f"{lang}.json").exists():
                _current = lang
                return _current
        except:
            pass
    # system locale
    try:
        import locale
        loc = locale.getdefaultlocale()[0] or "en"
        cand = loc.split("_")[0].lower()
        if (LOCALES_DIR / f"{cand}.json").exists():
            _current = cand
            return _current
    except:
        pass
    _current = DEFAULT_LANG
    return _current

def set_lang(lang: str):
    global _current
    _current = lang
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(lang, encoding="utf-8")
    except:
        pass
    return load_lang(lang)

def t(key: str, lang: str = None):
    l = lang or get_current_lang()
    data = load_lang(l)
    return data.get(key, key)
