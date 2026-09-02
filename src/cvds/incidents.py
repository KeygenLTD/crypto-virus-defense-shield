"""Durable incident records consumed by the detector and cleanup tool."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from .paths import ensure_state_dirs, state_dir


def _atomic_write(path: Path, payload: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)


def create_incident(
    detection: dict,
    candidate: dict | None,
    response: dict,
    artifacts: dict | None = None,
) -> tuple[Path, dict]:
    directories = ensure_state_dirs()
    incident_id = (
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"
    )
    payload = {
        "schema": 1,
        "incident_id": incident_id,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "contained" if response.get("suspended") else "detected",
        "detection": detection,
        "candidate": candidate,
        "response": response,
        "artifacts": artifacts or {},
        "cleanup": None,
    }
    path = directories["incidents"] / f"{incident_id}.json"
    _atomic_write(path, payload)
    _atomic_write(state_dir() / "latest_incident.json", {"path": str(path)})
    return path, payload


def load_latest_incident() -> tuple[Path | None, dict | None]:
    pointer = state_dir() / "latest_incident.json"
    if not pointer.exists():
        return None, None
    try:
        path = Path(json.loads(pointer.read_text(encoding="utf-8"))["path"])
        payload = json.loads(path.read_text(encoding="utf-8"))
        return path, payload
    except (OSError, ValueError, KeyError, TypeError):
        return None, None


def update_incident(path: Path, payload: dict) -> None:
    _atomic_write(path, payload)
