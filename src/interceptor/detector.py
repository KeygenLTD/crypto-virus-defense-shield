"""
Crypto Virus Defense Shield - Interceptor with System Tray
src/interceptor/detector.py:1
"""
import time
import sys
import os
import threading
import logging
from pathlib import Path
from datetime import datetime
try:
    from src.i18n import t, get_current_lang, set_lang, get_available_languages
    HAS_I18N = True
except ImportError:
    HAS_I18N = False
    def t(k, lang=None): return k
    def get_current_lang(): return "en"
    def set_lang(l): return
    def get_available_languages(): return ["en"]

# Safe isolated directory - NEVER monitor whole system in demo
TEST_DIR = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "crypto-test"
LOG_FILE = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "crypto-virus-defense-shield.log"
LOCK_FILE = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "cvds.lock"
HONEYPOT_FILES = ["ZZZ_TRAP.docx", "ZZZ_TRAP.xlsx", "DO_NOT_TOUCH.txt"]
THRESHOLD_MODS_PER_SEC = 3

def ensure_single_instance():
    """Prevent double-run via lock file + mutex"""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Try Windows mutex via msvcrt file lock
        import msvcrt
        global _lock_fh
        _lock_fh = open(LOCK_FILE, "w")
        msvcrt.locking(_lock_fh.fileno(), msvcrt.LK_NBLCK, 1)
        # Write pid
        _lock_fh.write(str(os.getpid()))
        _lock_fh.flush()
        return True
    except (ImportError, OSError, IOError):
        # msvcrt failed -> already locked
        already = t('tray_already_running') if HAS_I18N else "Already running"
        log.error(already)
        print(f"[!] {already} - check system tray near clock. Exiting.")
        sys.exit(0)

# Logging setup
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("shield")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    log.warning("watchdog not installed - polling fallback")

# Try tray imports - optional
HAS_TRAY = False
try:
    from PIL import Image, ImageDraw
    import pystray
    HAS_TRAY = True
except ImportError:
    log.warning("pystray/Pillow not installed - console mode only")

class ShieldHandler(FileSystemEventHandler):
    def __init__(self, on_alert=None):
        super().__init__()
        self.events = []
        self.triggered = False
        self.on_alert = on_alert
        self.detections = 0

    def on_modified(self, event):
        self._handle(event)
    def on_created(self, event):
        self._handle(event)

    def _handle(self, event):
        if event.is_directory:
            return
        name = Path(event.src_path).name
        now = time.time()
        self.events.append(now)
        self.events = [t for t in self.events if now - t < 2]
        if name in HONEYPOT_FILES:
            self._alert(f"HONEYPOT touched: {name} -> {event.src_path}")
        elif len(self.events) >= THRESHOLD_MODS_PER_SEC:
            self._alert(f"High-frequency file mods: {len(self.events)} in 2s -> {name}")

    def _alert(self, reason):
        # allow multiple alerts but rate-limit
        self.detections += 1
        msg = f"Ransomware behavior detected! Reason: {reason}"
        log.warning(msg)
        print("\n" + "="*60)
        print(f"[SHIELD] {msg}")
        print(f"[SHIELD] Action: Would KILL process + DUMP RAM (demo: alert only)")
        print(f"[SHIELD] Log: {LOG_FILE}")
        print("="*60 + "\n")
        if self.on_alert:
            self.on_alert(msg)

def setup_honeypot():
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    for fname in HONEYPOT_FILES:
        p = TEST_DIR / fname
        if not p.exists():
            p.write_text("CANARY - DO NOT MODIFY - Shield honeypot", encoding="utf-8")
    for i in range(5):
        p = TEST_DIR / f"dummy_doc_{i}.txt"
        if not p.exists():
            p.write_text(f"Important document {i} - lorem ipsum", encoding="utf-8")
    log.info(f"Honeypot ready at: {TEST_DIR}")

def create_icon_image():
    # Generate shield icon 64x64
    size = 64
    img = Image.new("RGBA", (size, size), (0,0,0,0))
    d = ImageDraw.Draw(img)
    # shield shape
    d.ellipse([4,4,60,60], fill="#0ea5e9", outline="#0369a1", width=3)
    d.rectangle([22,18,42,42], fill="white")
    d.text((26,22), "S", fill="#0ea5e9")
    return img

def run_tray(handler, observer):
    icon = None
    def get_status_text():
        lang = get_current_lang()
        return f"{t('status_active', lang)}\n{t('status_watching', lang)}: {TEST_DIR}\n{t('status_detections', lang)}: {handler.detections}\n{t('status_log', lang)}: {LOG_FILE}"

    def on_show_log(icon, item):
        os.startfile(str(LOG_FILE)) if os.path.exists(LOG_FILE) else log.info("Log not yet created")
        if os.path.exists(LOG_FILE):
            try:
                os.startfile(str(LOG_FILE.parent))
            except:
                pass

    def on_about(icon, item):
        try:
            icon.notify(t('about_text'), t('tray_about'))
        except:
            pass
        log.info(t('about_text'))

    def on_exit(icon, item):
        log.info("Exiting via tray")
        try:
            observer.stop()
            observer.join(timeout=2)
        except:
            pass
        icon.stop()
        os._exit(0)

    def on_status(icon, item):
        try:
            icon.notify(get_status_text(), t('tray_status'))
        except:
            log.info(get_status_text())

    def make_lang_handler(lang_code):
        def handler(icon, item):
            set_lang(lang_code)
            log.info(f"Language switched to {lang_code} - restart tray to apply")
            try:
                icon.notify(f"Language: {lang_code} - restart app to apply", t('tray_language'))
            except:
                pass
        return handler

    # Build language submenu dynamically
    langs = get_available_languages()
    lang_items = [pystray.MenuItem(f"{l} {'✓' if l==get_current_lang() else ''}", make_lang_handler(l)) for l in langs]
    # Extra: add AI generate for new lang
    def on_add_language(icon, item):
        # Simple: ask via log - user can create locales/xx.json and AI will fill
        log.info("To add language: create locales/<code>.json or set LLM_API_KEY and restart - AI will auto-generate")
        try:
            icon.notify("Create locales/<code>.json - AI will auto-fill on next start", "Add Language")
        except:
            pass

    menu = pystray.Menu(
        pystray.MenuItem(lambda item: t('tray_status'), on_status),
        pystray.MenuItem(lambda item: t('tray_open_log'), on_show_log),
        pystray.MenuItem(t('tray_language'), pystray.Menu(*lang_items, pystray.MenuItem("Add new...", on_add_language))),
        pystray.MenuItem(lambda item: t('tray_about'), on_about),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(lambda item: t('tray_exit'), on_exit)
    )
    icon = pystray.Icon("CVDS", create_icon_image(), "Crypto Virus Defense Shield - Active", menu)
    # notify on start
    def setup(icon):
        icon.visible = True
        try:
            icon.notify(t('tray_shield_active'), t('app_name'))
        except:
            pass
    threading.Thread(target=lambda: icon.run(setup), daemon=True).start()
    return icon

def main():
    setup_honeypot()
    if not HAS_WATCHDOG:
        log.error("watchdog required")
        return

    handler = ShieldHandler()
    observer = Observer()
    observer.schedule(handler, str(TEST_DIR), recursive=False)
    observer.start()
    log.info("Shield active. Monitoring: %s", TEST_DIR)

    # Try tray mode, fallback to console
    tray_icon = None
    if HAS_TRAY:
        try:
            # wrap alert to notify via tray
            orig_alert = handler._alert
            def tray_alert(reason):
                # will be called via handler.on_alert
                if tray_icon:
                    try:
                        tray_icon.notify(reason, "THREAT DETECTED!")
                    except:
                        pass
            handler.on_alert = tray_alert
            tray_icon = run_tray(handler, observer)
            log.info("Tray icon active - check system tray (near clock)")
        except Exception as e:
            log.warning(f"Tray failed, console mode: {e}")

    if tray_icon:
        # Keep main thread alive - tray runs in background
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        print("[*] Shield active (console). Press Ctrl+C to stop. Log: {}".format(LOG_FILE))
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

if __name__ == "__main__":
    if str(TEST_DIR).lower() in ["c:\\", "c:/", str(Path.home()).lower()]:
        print("[FATAL] Refusing to monitor system root")
        sys.exit(1)
    ensure_single_instance()
    main()
