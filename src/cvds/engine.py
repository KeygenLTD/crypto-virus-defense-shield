"""Family-aware behavioral ransomware detection engine."""

from __future__ import annotations

import math
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from pathlib import Path

from .paths import is_excluded, normalize_path
from .profiles import FamilyProfiles, IndicatorMatch


@dataclass
class FileActivity:
    timestamp: float
    kind: str
    src_path: str
    dest_path: str | None = None

    @property
    def target_path(self) -> str:
        return self.dest_path or self.src_path


@dataclass
class Detection:
    detected_at: float
    score: int
    confidence: str
    reasons: list[str]
    activity: FileActivity
    family: str | None = None
    source: str | None = None
    entropy: float | None = None
    burst_files: int = 0
    renamed_files: int = 0
    indicator: dict | None = None

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["activity"] = asdict(self.activity)
        return payload


def shannon_entropy(path: str | Path, max_sample_bytes: int = 262_144) -> float | None:
    """Return sampled byte entropy without loading a large user file into memory."""
    try:
        target = Path(path)
        size = target.stat().st_size
        if size < 512 or not target.is_file():
            return None
        with target.open("rb") as handle:
            if size <= max_sample_bytes:
                sample = handle.read()
            else:
                chunk = max_sample_bytes // 3
                first = handle.read(chunk)
                handle.seek(max(0, size // 2 - chunk // 2))
                middle = handle.read(chunk)
                handle.seek(max(0, size - chunk))
                last = handle.read(chunk)
                sample = first + middle + last
        if not sample:
            return None
        counts = Counter(sample)
        length = len(sample)
        return -sum(
            (count / length) * math.log2(count / length) for count in counts.values()
        )
    except (OSError, ValueError):
        return None


class BehaviorEngine:
    def __init__(
        self,
        canary_paths: set[str],
        profiles: FamilyProfiles,
        burst_threshold: int = 18,
        burst_window_seconds: float = 2.0,
        entropy_threshold: float = 7.35,
        rename_threshold: int = 12,
    ):
        self.canary_paths = {normalize_path(path) for path in canary_paths}
        self.profiles = profiles
        self.burst_threshold = max(4, int(burst_threshold))
        self.burst_window_seconds = max(0.5, float(burst_window_seconds))
        self.entropy_threshold = float(entropy_threshold)
        self.rename_threshold = max(4, int(rename_threshold))
        self.activities: deque[FileActivity] = deque()
        self.last_alerts: dict[str, float] = {}

    def _trim(self, now: float) -> None:
        while (
            self.activities
            and now - self.activities[0].timestamp > self.burst_window_seconds
        ):
            self.activities.popleft()

    def _is_canary(self, path: str | None) -> bool:
        return bool(path and normalize_path(path) in self.canary_paths)

    def _best_match(self, paths: list[str]) -> IndicatorMatch | None:
        matches: list[IndicatorMatch] = []
        for path in paths:
            matches.extend(self.profiles.match_path(path))
        return max(matches, key=lambda match: match.score, default=None)

    def evaluate(self, activity: FileActivity) -> Detection | None:
        if is_excluded(activity.target_path):
            return None
        now = activity.timestamp or time.time()
        self.activities.append(activity)
        self._trim(now)

        paths = [activity.src_path]
        if activity.dest_path:
            paths.append(activity.dest_path)
        distinct_paths = {normalize_path(item.target_path) for item in self.activities}
        burst_count = len(distinct_paths)
        rename_paths = {
            normalize_path(item.dest_path)
            for item in self.activities
            if item.kind == "moved" and item.dest_path
        }
        rename_count = len(rename_paths)
        score = 0
        reasons: list[str] = []
        family = None
        source = None
        indicator = None

        if any(self._is_canary(path) for path in paths):
            score = 100
            reasons.append("installation canary changed")

        match = self._best_match(paths)
        if match:
            score = max(score, match.score)
            family = match.family
            source = match.source
            indicator = {
                "kind": match.kind,
                "value": match.value,
                "score": match.score,
            }
            reasons.append(f"{match.family} {match.kind}: {match.value}")

        if activity.kind == "moved" and activity.dest_path:
            old_suffix = Path(activity.src_path).suffix.casefold()
            new_suffix = Path(activity.dest_path).suffix.casefold()
            if old_suffix != new_suffix:
                score = min(100, score + 24)
                reasons.append("file extension changed")

        if rename_count >= self.rename_threshold:
            score = max(score, 84)
            reasons.append(
                f"mass file renaming: {rename_count} files/{self.burst_window_seconds:g}s"
            )

        if burst_count >= self.burst_threshold:
            score = max(score, 82)
            reasons.append(
                f"mass file activity: {burst_count} files/{self.burst_window_seconds:g}s"
            )

        entropy = None
        if score >= 35 or burst_count >= max(5, self.burst_threshold // 2):
            entropy = shannon_entropy(activity.target_path)
            if entropy is not None and entropy >= self.entropy_threshold:
                score = min(100, score + 16)
                reasons.append(f"high entropy output: {entropy:.2f} bits/byte")

        if score < 75:
            return None

        if family:
            signature = f"family:{family}"
        elif "installation canary changed" in reasons:
            signature = "canary"
        else:
            signature = "behavior"
        if now - self.last_alerts.get(signature, 0.0) < 3.0:
            return None
        self.last_alerts[signature] = now
        confidence = "high" if score >= 90 else "medium"
        return Detection(
            detected_at=now,
            score=score,
            confidence=confidence,
            reasons=reasons,
            activity=activity,
            family=family,
            source=source,
            entropy=entropy,
            burst_files=burst_count,
            renamed_files=rename_count,
            indicator=indicator,
        )
