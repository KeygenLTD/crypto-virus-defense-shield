"""
Safe Ransomware Simulator - ONLY touches TEST_DIR
src/simulator/fake_ransomware.py:1
DO NOT modify to touch other directories.
"""
import os
import time
from pathlib import Path

TEST_DIR = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "crypto-test"
# Safety: hard guard
ALLOWED_ROOT = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode"

def is_safe(path: Path) -> bool:
    try:
        path.resolve().relative_to(ALLOWED_ROOT.resolve())
        return True
    except ValueError:
        return False

def xor_encrypt(data: bytes, key: int = 0x5A) -> bytes:
    return bytes(b ^ key for b in data)

def main():
    if not TEST_DIR.exists():
        print(f"[!] Test dir not found: {TEST_DIR}")
        print(f"    Run detector.py first to create honeypot.")
        return
    if not is_safe(TEST_DIR):
        print("[FATAL] Safety guard blocked - not in allowed root")
        return

    files = [p for p in TEST_DIR.iterdir() if p.is_file()]
    print(f"[*] Simulator targeting ONLY: {TEST_DIR}")
    print(f"[*] Found {len(files)} files: {[p.name for p in files]}")
    print(f"[*] Starting fake encryption in 2s (Ctrl+C to abort)...")
    time.sleep(2)

    for p in files:
        if not is_safe(p):
            print(f"[SKIP] Unsafe path blocked: {p}")
            continue
        # Simulate ransomware: read -> xor -> write back + rename
        try:
            data = p.read_bytes()
            enc = xor_encrypt(data)
            # overwrite
            p.write_bytes(enc)
            # rename to .locked like real ransomware
            new_path = p.with_suffix(p.suffix + ".locked")
            # safety: ensure new path still safe
            if is_safe(new_path):
                p.rename(new_path)
                print(f"[SIM] Encrypted: {p.name} -> {new_path.name}")
            time.sleep(0.3)  # to trigger frequency detector
        except Exception as e:
            print(f"[ERR] {p.name}: {e}")

    print("\n[SIM] Done. To restore, run: python src/simulator/restore.py")
    print("[SIM] Detector should have fired: 'Ransomware behavior detected!'")

if __name__ == "__main__":
    main()
