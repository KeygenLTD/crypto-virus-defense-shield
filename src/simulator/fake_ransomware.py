"""Harmless CVDS behavior simulator with a hard, marker-based safety boundary."""

from __future__ import annotations

import argparse
import os
import tempfile
import time
from pathlib import Path

MARKER_NAME = ".cvds-safe-simulation"
MARKER_CONTENT = "CVDS SAFE SIMULATION ROOT v1\n"
DEFAULT_ROOT = Path(tempfile.gettempdir()) / "cvds-safe-simulation"


def xor_bytes(data: bytes, key: int = 0x5A) -> bytes:
    return bytes(value ^ key for value in data)


def is_safe_root(root: Path) -> bool:
    try:
        resolved = root.resolve()
        marker = resolved / MARKER_NAME
        forbidden = {Path(resolved.anchor), Path.home().resolve()}
        return (
            resolved not in forbidden
            and resolved.name == "cvds-safe-simulation"
            and marker.is_file()
            and marker.read_text(encoding="utf-8") == MARKER_CONTENT
        )
    except (OSError, RuntimeError):
        return False


def prepare(root: Path) -> int:
    resolved = root.resolve()
    if resolved.name != "cvds-safe-simulation" or resolved in {
        Path(resolved.anchor),
        Path.home().resolve(),
    }:
        print("[BLOCKED] Simulation root must end in 'cvds-safe-simulation'.")
        return 2
    resolved.mkdir(parents=True, exist_ok=True)
    (resolved / MARKER_NAME).write_text(MARKER_CONTENT, encoding="utf-8")
    for index in range(32):
        sample = resolved / f"sample-{index:02d}.txt"
        if not sample.exists():
            sample.write_bytes((f"CVDS harmless sample {index}\n".encode()) * 64)
    print(f"[READY] Safe simulation root: {resolved}")
    print(
        "[NEXT] Set CVDS_PROTECTED_ROOTS to this path, start CVDS, then run with --run."
    )
    return 0


def _is_cvds_canary(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes()[:12] == b"CVDS-CANARY\x00"
    except OSError:
        return False


def run(root: Path, delay: float) -> int:
    if not is_safe_root(root):
        print("[BLOCKED] Missing or invalid CVDS simulation marker.")
        return 2
    candidates = [
        path
        for path in root.iterdir()
        if path.is_file() and (path.name.startswith("sample-") or _is_cvds_canary(path))
    ]
    canaries = [path for path in candidates if _is_cvds_canary(path)]
    samples = [path for path in candidates if path.name.startswith("sample-")]
    targets = canaries + samples
    print(f"[SIM] Touching only {len(targets)} verified files under {root.resolve()}")
    time.sleep(max(0.0, delay))
    for path in targets:
        if not is_safe_root(root) or path.parent.resolve() != root.resolve():
            print(f"[BLOCKED] Safety boundary changed: {path}")
            return 2
        try:
            path.write_bytes(xor_bytes(path.read_bytes()))
            destination = path.with_suffix(path.suffix + ".cvdslocked")
            path.rename(destination)
            print(f"[SIM] {path.name} -> {destination.name}")
            time.sleep(0.03)
        except (OSError, PermissionError) as exc:
            print(f"[STOPPED] {path.name}: {exc}")
            return 0
    print("[SIM] Finished. If CVDS was active, inspect its incident record.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe CVDS behavior simulator")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--prepare", action="store_true", help="Create isolated dummy files"
    )
    action.add_argument(
        "--run", action="store_true", help="Mutate only verified simulation files"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(os.environ.get("CVDS_SIMULATION_ROOT", DEFAULT_ROOT)),
    )
    parser.add_argument("--delay", type=float, default=1.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return prepare(args.root) if args.prepare else run(args.root, args.delay)


if __name__ == "__main__":
    raise SystemExit(main())
