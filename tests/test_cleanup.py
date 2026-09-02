from pathlib import Path

from src.cvds import cleanup


def _contained_incident() -> dict:
    return {
        "candidate": {
            "pid": 4242,
            "exe": "/tmp/payload.exe",
            "sha256": "a" * 64,
            "attribution_score": 68,
        },
        "detection": {"score": 100},
        "response": {"suspended": True, "combined_confidence_score": 88},
    }


def test_cleanup_accepts_only_recorded_contained_identity(monkeypatch, tmp_path):
    incident_path = tmp_path / "incident.json"
    incident = _contained_incident()
    updated = {}
    monkeypatch.setattr(
        cleanup, "load_latest_incident", lambda: (incident_path, incident)
    )
    monkeypatch.setattr(cleanup, "_same_process", lambda candidate: False)
    monkeypatch.setattr(
        cleanup,
        "quarantine_executable",
        lambda path, digest: (True, "quarantined", "/tmp/quarantine/item"),
    )
    monkeypatch.setattr(cleanup, "remove_run_persistence", lambda path: [])
    monkeypatch.setattr(
        cleanup, "request_defender_scan", lambda path: (True, "scanned")
    )
    monkeypatch.setattr(
        cleanup, "update_incident", lambda path, payload: updated.update(payload)
    )

    success, _, _ = cleanup.cleanup_latest()
    assert success
    assert updated["status"] == "quarantined"
    assert updated["cleanup"]["success"] is True


def test_cleanup_refuses_low_confidence_incident(monkeypatch, tmp_path):
    incident = _contained_incident()
    incident["response"]["combined_confidence_score"] = 70
    monkeypatch.setattr(
        cleanup,
        "load_latest_incident",
        lambda: (Path(tmp_path / "incident.json"), incident),
    )
    success, message, _ = cleanup.cleanup_latest()
    assert not success
    assert "refused" in message
