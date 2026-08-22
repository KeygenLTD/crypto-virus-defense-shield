"""
Crypto Virus Defense Shield - Interceptor
Safe honeypot + behavioral monitor. Only monitors TEST_DIR.
src/interceptor/detector.py:1
"""
import time
import sys
import os
from pathlib import Path

# Safe isolated directory - NEVER monitor whole system in demo
TEST_DIR = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "crypto-test"
HONEYPOT_FILES = ["ZZZ_TRAP.docx", "ZZZ_TRAP.xlsx", "DO_NOT_TOUCH.txt"]
THRESHOLD_MODS_PER_SEC = 3  # low for demo, real would be 20-50
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    print("[!] pip install watchdog psutil - running in polling fallback")

class ShieldHandler(FileSystemEventHandler):
    def __init__(self):
        self.events = []
        self.triggered = False

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
        # keep only last 2 seconds
        self.events = [t for t in self.events if now - t < 2]

        # 1. Honeypot check - instant kill
        if name in HONEYPOT_FILES:
            self._alert(f"HONEYPOT touched: {name} -> {event.src_path}")

        # 2. Frequency check - mass encryption behavior
        elif len(self.events) >= THRESHOLD_MODS_PER_SEC:
            self._alert(f"High-frequency file mods: {len(self.events)} in 2s -> {name}")

    def _alert(self, reason):
        if self.triggered:
            return
        self.triggered = True
        print("\n" + "="*60)
        print(f"[SHIELD] Ransomware behavior detected!")
        print(f"[SHIELD] Reason: {reason}")
        print(f"[SHIELD] Action: Would KILL process + DUMP RAM (demo: alert only)")
        print("="*60 + "\n")
        # In real version: psutil kill + RAM dump via winpmem
        # Here we just alert so we don't kill innocent processes

def setup_honeypot():
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    for fname in HONEYPOT_FILES:
        p = TEST_DIR / fname
        if not p.exists():
            p.write_text("CANARY - DO NOT MODIFY - Shield honeypot", encoding="utf-8")
    # create some dummy user files
    for i in range(5):
        p = TEST_DIR / f"dummy_doc_{i}.txt"
        if not p.exists():
            p.write_text(f"Important document {i} - lorem ipsum", encoding="utf-8")
    print(f"[+] Honeypot ready at: {TEST_DIR}")
    print(f"[+] Canaries: {HONEYPOT_FILES}")

def main():
    setup_honeypot()
    if not HAS_WATCHDOG:
        print("[*] Polling mode - watching via os.listdir loop")
        known = set(os.listdir(TEST_DIR))
        handler = ShieldHandler()
        print("[*] Shield active (polling). Leave running, then run fake_ransomware.py in another terminal. Ctrl+C to stop.")
        while True:
            time.sleep(0.5)
            cur = set(os.listdir(TEST_DIR))
            if cur != known:
                # crude detection
                handler.events.append(time.time())
                if len([t for t in handler.events if time.time()-t<2]) >= THRESHOLD_MODS_PER_SEC:
                    handler._alert("Polling: mass file change")
                known = cur
        return

    handler = ShieldHandler()
    observer = Observer()
    observer.schedule(handler, str(TEST_DIR), recursive=False)
    observer.start()
    print("[*] Shield active (watchdog). Leave running, then run fake_ransomware.py in another terminal.")
    print("[*] Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Safety guard: never allow monitoring C:\ or Documents
    if str(TEST_DIR).lower() in ["c:\\", "c:/", str(Path.home()).lower()]:
        print("[FATAL] Refusing to monitor system root for safety")
        sys.exit(1)
    main()
