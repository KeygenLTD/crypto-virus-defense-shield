"""Restore XOR-encrypted files in TEST_DIR"""
import os
from pathlib import Path
TEST_DIR = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode" / "crypto-test"
ALLOWED_ROOT = Path(os.environ.get("TEMP", "C:/Temp")) / "opencode"
def is_safe(p: Path):
    try: p.resolve().relative_to(ALLOWED_ROOT.resolve()); return True
    except: return False
def xor(b: bytes, k=0x5A): return bytes(x ^ k for x in b)
for p in list(TEST_DIR.iterdir()):
    if p.suffix == ".locked" and is_safe(p):
        data = xor(p.read_bytes())
        orig = p.with_suffix("")  # remove .locked
        # handles .txt.locked -> .txt
        if orig.suffix == "":
            orig = p.with_name(p.name.replace(".locked",""))
        orig.write_bytes(data)
        p.unlink(missing_ok=True)
        print(f"[RESTORE] {p.name} -> {orig.name}")
print("[RESTORE] Done")
