"""Curated ransomware family indicators backed by public advisories."""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .paths import resource_path


@dataclass(frozen=True)
class IndicatorMatch:
    family: str
    kind: str
    value: str
    score: int
    source: str


class FamilyProfiles:
    def __init__(self, profile_path: str | Path | None = None):
        override = os.environ.get("CVDS_PROFILE_PATH")
        self.path = Path(
            profile_path or override or resource_path("rules/ransomware_families.json")
        )
        self.updated_utc = "unknown"
        self.families: list[dict] = []
        self._load()

    def _load(self) -> None:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if payload.get("schema") != 1 or not isinstance(payload.get("families"), list):
            raise ValueError(f"Unsupported ransomware profile schema: {self.path}")
        self.updated_utc = str(payload.get("updated_utc", "unknown"))
        self.families = payload["families"]

    def match_path(self, path: str | Path) -> list[IndicatorMatch]:
        name = Path(path).name.casefold()
        matches: list[IndicatorMatch] = []
        for family in self.families:
            source = str(family.get("source", ""))
            family_name = str(family["name"])
            for item in family.get("extensions", []):
                value = str(item["value"]).casefold()
                if name.endswith(value):
                    matches.append(
                        IndicatorMatch(
                            family_name, "extension", value, int(item["score"]), source
                        )
                    )
            for item in family.get("ransom_notes", []):
                pattern = str(item["pattern"])
                if fnmatch.fnmatch(name, pattern.casefold()):
                    matches.append(
                        IndicatorMatch(
                            family_name,
                            "ransom_note",
                            pattern,
                            int(item["score"]),
                            source,
                        )
                    )
        return sorted(matches, key=lambda match: match.score, reverse=True)

    def match_process(self, process_name: str) -> list[IndicatorMatch]:
        name = process_name.casefold()
        matches: list[IndicatorMatch] = []
        for family in self.families:
            for item in family.get("process_names", []):
                value = str(item["value"])
                if name == value.casefold():
                    matches.append(
                        IndicatorMatch(
                            str(family["name"]),
                            "process_name",
                            value,
                            int(item["score"]),
                            str(family.get("source", "")),
                        )
                    )
        return sorted(matches, key=lambda match: match.score, reverse=True)

    def coverage_rows(self) -> list[dict]:
        return [dict(family) for family in self.families]
