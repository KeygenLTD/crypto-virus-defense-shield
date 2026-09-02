"""One-action cleanup of the latest high-confidence contained incident."""

from __future__ import annotations

import argparse
import json
import os
import time

import psutil

from .defender import is_admin, launch_elevated
from .incidents import load_latest_incident, update_incident
from .paths import normalize_path, state_dir
from .process_guard import (
    quarantine_executable,
    remove_run_persistence,
    request_defender_scan,
    terminate_process_tree,
)


def _same_process(candidate: dict) -> bool:
    try:
        process = psutil.Process(int(candidate["pid"]))
        expected_time = candidate.get("create_time")
        if expected_time and abs(process.create_time() - float(expected_time)) > 0.5:
            return False
        expected_exe = candidate.get("exe")
        return not (
            expected_exe
            and normalize_path(process.exe()) != normalize_path(expected_exe)
        )
    except (psutil.Error, KeyError, TypeError, ValueError):
        return False


def cleanup_latest() -> tuple[bool, str, dict | None]:
    incident_path, incident = load_latest_incident()
    if not incident_path or not incident:
        return False, "No CVDS incident is available.", None
    candidate = incident.get("candidate") or {}
    detection = incident.get("detection") or {}
    response = incident.get("response") or {}
    attribution_score = int(candidate.get("attribution_score") or 0)
    detection_score = int(detection.get("score") or 0)
    combined_score = int(response.get("combined_confidence_score") or 0)
    was_contained = bool(response.get("suspended"))
    high_confidence = detection_score >= 90 and (
        attribution_score >= 90
        or (was_contained and combined_score >= 85 and attribution_score >= 68)
    )
    if not high_confidence:
        return (
            False,
            "Latest incident is not high-confidence; automatic removal was refused.",
            incident,
        )

    actions: list[dict] = []
    pid = candidate.get("pid")
    if pid and _same_process(candidate):
        ok, message = terminate_process_tree(int(pid))
        actions.append({"action": "terminate", "ok": ok, "message": message})
    else:
        actions.append(
            {
                "action": "terminate",
                "ok": True,
                "message": "process exited or identity changed",
            }
        )

    executable = candidate.get("exe")
    quarantine_path = None
    if executable:
        ok, message, quarantine_path = quarantine_executable(
            executable, candidate.get("sha256")
        )
        actions.append(
            {
                "action": "quarantine",
                "ok": ok,
                "message": message,
                "path": quarantine_path,
            }
        )
        if ok:
            removed = remove_run_persistence(executable)
            actions.append(
                {"action": "remove_run_persistence", "ok": True, "removed": removed}
            )
    else:
        actions.append(
            {
                "action": "quarantine",
                "ok": False,
                "message": "no executable path recorded",
            }
        )

    scan_target = quarantine_path or executable or str(state_dir())
    scan_ok, scan_message = request_defender_scan(scan_target)
    actions.append({"action": "defender_scan", "ok": scan_ok, "message": scan_message})
    quarantined = any(item["action"] == "quarantine" and item["ok"] for item in actions)
    terminated = any(item["action"] == "terminate" and item["ok"] for item in actions)
    success = terminated and (quarantined or not executable)
    incident["cleanup"] = {
        "completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "success": success,
        "actions": actions,
    }
    incident["status"] = "quarantined" if quarantined else "cleanup_partial"
    update_incident(incident_path, incident)
    message = (
        "Threat stopped and quarantined."
        if success
        else "Threat response completed with warnings."
    )
    return success, message, incident


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CVDS guarded emergency cleanup")
    parser.add_argument(
        "--status", action="store_true", help="Report whether an incident is available"
    )
    args = parser.parse_args(argv)
    if args.status:
        incident_path, incident = load_latest_incident()
        print(
            json.dumps(
                {
                    "incident_available": bool(incident_path and incident),
                    "incident_path": str(incident_path) if incident_path else None,
                    "status": incident.get("status") if incident else None,
                },
                indent=2,
            )
        )
        return 0
    if os.name == "nt" and not is_admin():
        launched, message = launch_elevated([], module="src.cvds.cleanup")
        if launched:
            return 0
        print(f"CVDS Emergency Cleanup: {message}")
        return 1
    success, message, _ = cleanup_latest()
    title = "CVDS Emergency Cleanup"
    try:
        import tkinter
        from tkinter import messagebox

        root = tkinter.Tk()
        root.withdraw()
        if success:
            messagebox.showinfo(title, message)
        else:
            messagebox.showwarning(title, message)
        root.destroy()
    except Exception:  # noqa: BLE001 - GUI failure must fall back to console output
        print(f"{title}: {message}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
