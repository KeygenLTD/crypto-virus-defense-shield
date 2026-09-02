"""Process attribution and reversible ransomware containment."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

import psutil

from .paths import normalize_path, state_dir
from .profiles import FamilyProfiles

DESTRUCTIVE_COMMANDS = (
    re.compile(r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b", re.IGNORECASE),
    re.compile(r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b", re.IGNORECASE),
    re.compile(
        r"\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)\b", re.IGNORECASE
    ),
    re.compile(r"\bbcdedit(?:\.exe)?.*\brecoveryenabled\s+no\b", re.IGNORECASE),
    re.compile(
        r"\bbcdedit(?:\.exe)?.*\bbootstatuspolicy\s+ignoreallfailures\b", re.IGNORECASE
    ),
    re.compile(r"\bdisable-computerrestore\b", re.IGNORECASE),
)


@dataclass
class ProcessCandidate:
    pid: int
    name: str
    exe: str | None
    cmdline: list[str]
    username: str | None
    create_time: float | None
    attribution: str
    attribution_score: int
    write_bytes_delta: int = 0
    sha256: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def sha256_file(path: str | Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _is_recent_user_writable_process(
    proc: psutil.Process, max_age_seconds: int = 1800
) -> bool:
    """Conservative signal for freshly dropped payloads, never sufficient by itself."""
    try:
        executable = proc.exe()
        if not executable or time.time() - proc.create_time() > max_age_seconds:
            return False
        candidate = normalize_path(executable)
        roots = [
            tempfile.gettempdir(),
            os.environ.get("TEMP"),
            os.environ.get("TMP"),
            os.environ.get("LOCALAPPDATA"),
            os.environ.get("APPDATA"),
            os.environ.get("USERPROFILE"),
            os.environ.get("PUBLIC"),
        ]
        return any(
            candidate == normalize_path(root)
            or candidate.startswith(normalize_path(root) + os.sep)
            for root in roots
            if root
        )
    except (psutil.Error, OSError, ValueError):
        return False


def _snapshot(
    proc: psutil.Process, attribution: str, score: int, delta: int = 0
) -> ProcessCandidate:
    def safe(call, default=None):
        try:
            return call()
        except (psutil.Error, OSError):
            return default

    exe = safe(proc.exe)
    return ProcessCandidate(
        pid=proc.pid,
        name=safe(proc.name, f"pid-{proc.pid}"),
        exe=exe,
        cmdline=safe(proc.cmdline, []) or [],
        username=safe(proc.username),
        create_time=safe(proc.create_time),
        attribution=attribution,
        attribution_score=score,
        write_bytes_delta=delta,
        sha256=sha256_file(exe) if exe else None,
    )


class ProcessMonitor:
    """Tracks write-rate deltas and destructive process command lines."""

    def __init__(self, poll_seconds: float = 0.2):
        self.poll_seconds = max(0.1, poll_seconds)
        self._previous: dict[tuple[int, float], int] = {}
        self._deltas: dict[tuple[int, float], tuple[int, float]] = {}
        self._seen_commands: set[tuple[int, float]] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._callback: Callable[[ProcessCandidate, str], None] | None = None

    def start(
        self,
        destructive_callback: Callable[[ProcessCandidate, str], None] | None = None,
    ) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._callback = destructive_callback
        self._thread = threading.Thread(
            target=self._run, name="cvds-process-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.wait(self.poll_seconds):
            now = time.time()
            active: set[tuple[int, float]] = set()
            for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
                if proc.pid == os.getpid():
                    continue
                try:
                    create_time = float(
                        proc.info.get("create_time") or proc.create_time()
                    )
                    key = (proc.pid, create_time)
                    active.add(key)
                    io_counters = getattr(proc, "io_counters", None)
                    write_bytes = int(io_counters().write_bytes) if io_counters else 0
                    previous = self._previous.get(key, write_bytes)
                    self._previous[key] = write_bytes
                    self._deltas[key] = (max(0, write_bytes - previous), now)

                    if key not in self._seen_commands:
                        self._seen_commands.add(key)
                        cmdline = " ".join(proc.info.get("cmdline") or [])
                        for pattern in DESTRUCTIVE_COMMANDS:
                            if pattern.search(cmdline):
                                if self._callback:
                                    self._callback(
                                        _snapshot(
                                            proc, "recovery-destruction command", 100
                                        ),
                                        cmdline,
                                    )
                                break
                except (
                    AttributeError,
                    NotImplementedError,
                    psutil.Error,
                    OSError,
                    ValueError,
                ):
                    continue
            stale = set(self._previous) - active
            for key in stale:
                self._previous.pop(key, None)
                self._deltas.pop(key, None)
            self._seen_commands.intersection_update(active)

    def _write_delta(self, proc: psutil.Process) -> int:
        try:
            key = (proc.pid, float(proc.create_time()))
            delta, measured_at = self._deltas.get(key, (0, 0.0))
            return delta if time.time() - measured_at <= 2.0 else 0
        except psutil.Error:
            return 0

    def resolve(
        self, target_path: str, profiles: FamilyProfiles
    ) -> ProcessCandidate | None:
        normalized_target = normalize_path(target_path)
        processes = list(
            psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"])
        )

        # Exact open-file ownership is the safest user-mode attribution available.
        for proc in processes:
            if proc.pid == os.getpid():
                continue
            try:
                for opened in proc.open_files():
                    if normalize_path(opened.path) == normalized_target:
                        return _snapshot(
                            proc, "exact open file handle", 100, self._write_delta(proc)
                        )
            except (psutil.Error, OSError):
                continue

        # A family-specific process name is strong, but not enough by itself to delete a file.
        for proc in processes:
            if proc.pid == os.getpid():
                continue
            try:
                matches = profiles.match_process(proc.info.get("name") or "")
                if matches:
                    match = matches[0]
                    return _snapshot(
                        proc,
                        f"{match.family} process indicator",
                        match.score,
                        self._write_delta(proc),
                    )
            except (psutil.Error, OSError):
                continue

        # A fresh payload executing from a user-writable location plus concurrent
        # writes is stronger than write rate alone, but remains a combined signal.
        recent_writers: list[tuple[int, psutil.Process]] = []
        for proc in processes:
            if proc.pid == os.getpid():
                continue
            delta = self._write_delta(proc)
            if delta >= 16 * 1024 and _is_recent_user_writable_process(proc):
                recent_writers.append((delta, proc))
        if recent_writers:
            delta, proc = max(recent_writers, key=lambda item: item[0])
            score = (
                88 if delta >= 8 * 1024 * 1024 else 82 if delta >= 1024 * 1024 else 72
            )
            return _snapshot(
                proc,
                "recent user-writable executable with correlated writes",
                score,
                delta,
            )

        # Last resort: correlate the detector event with the top active writer.
        ranked: list[tuple[int, psutil.Process]] = []
        for proc in processes:
            if proc.pid == os.getpid():
                continue
            delta = self._write_delta(proc)
            if delta >= 64 * 1024:
                ranked.append((delta, proc))
        if not ranked:
            return None
        delta, proc = max(ranked, key=lambda item: item[0])
        # System-wide write rate is intentionally capped below containment confidence;
        # it can explain an alert but cannot suspend an unrelated busy system process.
        score = 55 if delta >= 8 * 1024 * 1024 else 48 if delta >= 1024 * 1024 else 40
        return _snapshot(proc, "highest correlated write rate", score, delta)


def suspend_process_tree(pid: int) -> tuple[bool, str]:
    try:
        process = psutil.Process(pid)
        for child in process.children(recursive=True):
            try:
                child.suspend()
            except psutil.Error:
                continue
        process.suspend()
        return True, "process tree suspended"
    except psutil.NoSuchProcess:
        return False, "process already exited"
    except psutil.AccessDenied:
        return False, "access denied while suspending process"
    except psutil.Error as exc:
        return False, f"suspend failed: {exc}"


def terminate_process_tree(pid: int, timeout: float = 3.0) -> tuple[bool, str]:
    try:
        process = psutil.Process(pid)
        targets = process.children(recursive=True) + [process]
        for target in targets:
            try:
                target.terminate()
            except psutil.NoSuchProcess:
                continue
        _, alive = psutil.wait_procs(targets, timeout=timeout)
        for target in alive:
            try:
                target.kill()
            except psutil.Error:
                continue
        _, still_alive = psutil.wait_procs(alive, timeout=1.0) if alive else ([], [])
        if still_alive:
            return (
                False,
                f"process termination incomplete: {[item.pid for item in still_alive]}",
            )
        return True, "process tree terminated"
    except psutil.NoSuchProcess:
        return True, "process already exited"
    except psutil.AccessDenied:
        return False, "access denied while terminating process"
    except psutil.Error as exc:
        return False, f"termination failed: {exc}"


def is_protected_executable(path: str | Path) -> bool:
    normalized = normalize_path(path)
    protected_roots = [
        os.environ.get("WINDIR", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramData", r"C:\ProgramData"),
        str(Path(sys.executable).parent),
    ]
    return any(
        normalized.startswith(normalize_path(root) + os.sep)
        for root in protected_roots
        if root
    )


def quarantine_executable(
    path: str | Path, expected_sha256: str | None
) -> tuple[bool, str, str | None]:
    source = Path(path)
    if not source.is_file():
        return False, "suspect executable no longer exists", None
    if not expected_sha256:
        return False, "no recorded executable hash; automatic quarantine refused", None
    actual_hash = sha256_file(source)
    if not actual_hash or actual_hash != expected_sha256:
        return False, "executable hash changed; quarantine refused", None
    if is_protected_executable(source):
        return (
            False,
            "protected Windows/application path; automatic quarantine refused",
            None,
        )

    quarantine_dir = state_dir() / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    suffix = actual_hash[:16] if actual_hash else f"pid-{int(time.time())}"
    target = quarantine_dir / f"{source.name}.{suffix}.cvds-quarantine"
    try:
        shutil.move(str(source), str(target))
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return True, "executable quarantined", str(target)
    except OSError as exc:
        return False, f"quarantine failed: {exc}", None


def request_defender_scan(path: str | Path) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Microsoft Defender scan is Windows-only"
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"Start-MpScan -ScanType CustomScan -ScanPath '{str(path).replace(chr(39), chr(39) * 2)}'",
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=120, check=False
        )
        if completed.returncode == 0:
            return True, "Microsoft Defender custom scan completed"
        return False, (
            completed.stderr or completed.stdout or "Defender scan failed"
        ).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Defender scan failed: {exc}"


def remove_run_persistence(executable_path: str | Path) -> list[str]:
    """Remove Run/RunOnce values only when they reference the exact quarantined executable."""
    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:
        return []
    target = normalize_path(executable_path)
    removed: list[str] = []
    locations = (
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    )
    for hive, key_path in locations:
        try:
            with winreg.OpenKey(
                hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE
            ) as key:
                values: list[tuple[str, str]] = []
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        values.append((name, str(value)))
                        index += 1
                    except OSError:
                        break
                for name, value in values:
                    expanded = os.path.expandvars(value).strip()
                    if expanded.startswith('"'):
                        closing_quote = expanded.find('"', 1)
                        command_executable = (
                            expanded[1:closing_quote] if closing_quote > 1 else ""
                        )
                    else:
                        command_executable = (
                            expanded.split(maxsplit=1)[0] if expanded else ""
                        )
                    if command_executable and target == normalize_path(
                        command_executable
                    ):
                        winreg.DeleteValue(key, name)
                        removed.append(f"{key_path}\\{name}")
        except OSError:
            continue
    return removed
