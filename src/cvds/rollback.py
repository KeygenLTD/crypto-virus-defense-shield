"""Bounded, local rollback copies for files touched by a high-confidence incident."""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

from .paths import ensure_state_dirs

MAX_FILE_BYTES = 64 * 1024 * 1024


def snapshot_file(path: str | Path, incident_id: str) -> dict | None:
    source = Path(path)
    try:
        if not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
            return None
        root = ensure_state_dirs()["base"] / "rollback" / incident_id
        root.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(str(source).encode()).hexdigest()[:16]
        target = root / f"{digest}-{source.name}"
        shutil.copy2(source, target)
        return {
            "source": str(source),
            "snapshot": str(target),
            "sha256": _sha256(target),
        }
    except OSError:
        return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def restore_snapshot(snapshot: str | Path, destination: str | Path) -> bool:
    try:
        source, target = Path(snapshot), Path(destination)
        if not source.is_file() or not source.resolve().is_relative_to(
            ensure_state_dirs()["base"].resolve()
        ):
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(target.suffix + ".cvds-restore")
        shutil.copy2(source, temp)
        os.replace(temp, target)
        return True
    except (OSError, RuntimeError):
        return False
