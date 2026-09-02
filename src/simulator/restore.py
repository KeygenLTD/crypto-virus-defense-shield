"""Restore files changed by the marker-guarded CVDS simulator."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

try:
    from .fake_ransomware import is_safe_root, xor_bytes
except ImportError:
    from fake_ransomware import is_safe_root, xor_bytes


def restore(root: Path) -> int:
    if not is_safe_root(root):
        print("[BLOCKED] Missing or invalid CVDS simulation marker.")
        return 2
    restored = 0
    for path in root.glob("*.cvdslocked"):
        if path.parent.resolve() != root.resolve():
            continue
        original = path.with_suffix("")
        original.write_bytes(xor_bytes(path.read_bytes()))
        path.unlink()
        restored += 1
        print(f"[RESTORE] {path.name} -> {original.name}")
    print(f"[RESTORE] Restored {restored} simulation file(s).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore CVDS safe simulation files")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(
            os.environ.get(
                "CVDS_SIMULATION_ROOT",
                Path(tempfile.gettempdir()) / "cvds-safe-simulation",
            )
        ),
    )
    return restore(parser.parse_args().root)


if __name__ == "__main__":
    raise SystemExit(main())
