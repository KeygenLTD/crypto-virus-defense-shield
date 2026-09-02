"""Create a sanitized incident evidence bundle without including file contents."""

from __future__ import annotations

import json
import zipfile

from .paths import ensure_state_dirs


def create_event_bundle(incident: dict) -> str | None:
    incident_id = str(incident.get("incident_id", "incident"))
    try:
        target = ensure_state_dirs()["base"] / f"{incident_id}-evidence.zip"
        safe = dict(incident)
        candidate = dict(safe.get("candidate") or {})
        candidate.pop("cmdline", None)
        safe["candidate"] = candidate
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "incident.json", json.dumps(safe, indent=2, ensure_ascii=False)
            )
        return str(target)
    except OSError:
        return None
