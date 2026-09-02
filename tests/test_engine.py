import json
from pathlib import Path

from src.cvds.engine import BehaviorEngine, FileActivity
from src.cvds.paths import normalize_path
from src.cvds.profiles import FamilyProfiles


def profiles() -> FamilyProfiles:
    return FamilyProfiles(
        Path(__file__).parents[1] / "rules" / "ransomware_families.json"
    )


def test_canary_change_is_high_confidence(tmp_path):
    canary = tmp_path / ".canary.docx"
    canary.write_bytes(b"CVDS-CANARY\0test")
    engine = BehaviorEngine({normalize_path(canary)}, profiles())
    detection = engine.evaluate(FileActivity(100.0, "modified", str(canary)))
    assert detection is not None
    assert detection.score == 100
    assert detection.confidence == "high"


def test_family_extension_plus_rename_is_detected(tmp_path):
    source = tmp_path / "budget.xlsx"
    destination = tmp_path / "budget.xlsx.medusa"
    destination.write_bytes(bytes(range(256)) * 4)
    engine = BehaviorEngine(set(), profiles())
    detection = engine.evaluate(
        FileActivity(100.0, "moved", str(source), str(destination))
    )
    assert detection is not None
    assert detection.family == "Medusa"
    assert detection.score >= 90


def test_mass_high_entropy_outputs_are_family_agnostic(tmp_path):
    engine = BehaviorEngine(
        set(), profiles(), burst_threshold=4, burst_window_seconds=2
    )
    detection = None
    for index in range(4):
        path = tmp_path / f"unknown-{index}.bin"
        path.write_bytes(bytes(range(256)) * 4)
        detection = engine.evaluate(
            FileActivity(100 + index * 0.1, "created", str(path))
        )
    assert detection is not None
    assert detection.family is None
    assert detection.score >= 90
    assert detection.burst_files == 4
    extra = tmp_path / "unknown-extra.bin"
    extra.write_bytes(bytes(range(256)) * 4)
    assert engine.evaluate(FileActivity(100.5, "created", str(extra))) is None


def test_mass_rename_is_detected_even_without_extension_change(tmp_path):
    engine = BehaviorEngine(set(), profiles(), rename_threshold=4)
    detection = None
    for index in range(4):
        source = tmp_path / f"document-{index}.txt"
        destination = tmp_path / f"document-{index}-renamed.txt"
        source.write_text("ordinary content", encoding="utf-8")
        destination.write_text("ordinary content", encoding="utf-8")
        detection = engine.evaluate(
            FileActivity(200 + index * 0.1, "moved", str(source), str(destination))
        )
    assert detection is not None
    assert detection.renamed_files == 4
    assert "mass file renaming" in detection.reasons[-1]


def test_family_profile_schema_and_required_coverage():
    profile_path = Path(__file__).parents[1] / "rules" / "ransomware_families.json"
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    names = {family["name"] for family in payload["families"]}
    assert payload["schema"] == 1
    assert {"Medusa", "Gunra", "Interlock", "Akira", "Play", "RansomHub"} <= names
