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

# Safe isolated directory - NEVER monitor whole system in demo
TEST_DIR = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "crypto-test"
LOG_FILE = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "crypto-virus-defense-shield.log"
HONEYPOT_FILES = ["ZZZ_TRAP.docx", "ZZZ_TRAP.xlsx", "DO_NOT_TOUCH.txt"]
THRESHOLD_MODS_PER_SEC = 3

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
        return f"Shield Active\nWatching: {TEST_DIR}\nDetections: {handler.detections}\nLog: {LOG_FILE}"

    def on_show_log(icon, item):
        os.startfile(str(LOG_FILE)) if os.path.exists(LOG_FILE) else log.info("Log not yet created")
        if os.path.exists(LOG_FILE):
            try:
                os.startfile(str(LOG_FILE.parent))
            except:
                pass

    def on_about(icon, item):
        # Use notification if available
        try:
            icon.notify("Crypto Virus Defense Shield\nv0.1.0 - Honeypot + CryptoAPI interceptor\nhttps://github.com/KeygenLTD/crypto-virus-defense-shield", "About CVDS")
        except:
            pass
        log.info("About: https://github.com/KeygenLTD/crypto-virus-defense-shield")

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
            icon.notify(get_status_text(), "Shield Status")
        except:
            log.info(get_status_text())

    menu = pystray.Menu(
        pystray.MenuItem("Status", on_status),
        pystray.MenuItem("Open Log", on_show_log),
        pystray.MenuItem("About", on_about),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit", on_exit)
    )
    icon = pystray.Icon("CVDS", create_icon_image(), "Crypto Virus Defense Shield - Active", menu)
    # notify on start
    def setup(icon):
        icon.visible = True
        try:
            icon.notify("Shield active - watching honeypot files", "Crypto Virus Defense Shield")
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
    main()
