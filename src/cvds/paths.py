"""Persistent paths, protected-folder discovery, and installation canaries."""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Iterable
from pathlib import Path

DEFAULT_CONFIG = {
    "schema": 1,
    "response_mode": "suspend",
    "protected_roots": [],
    "include_data_drives": True,
    "burst_threshold": 18,
    "burst_window_seconds": 2.0,
    "entropy_threshold": 7.35,
    "capture_memory": True,
    "max_memory_scan_mb": 192,
}

EXCLUDED_PARTS = {
    "$recycle.bin",
    "system volume information",
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "appdata",
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
}


def resource_path(relative: str | Path) -> Path:
    """Resolve a bundled PyInstaller resource or a repository resource."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
    return base / relative


def state_dir() -> Path:
    override = os.environ.get("CVDS_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "CVDS"
    xdg = os.environ.get("XDG_STATE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "state") / "cvds"


def ensure_state_dirs() -> dict[str, Path]:
    base = state_dir()
    paths = {
        "base": base,
        "incidents": base / "incidents",
        "dumps": base / "dumps",
        "quarantine": base / "quarantine",
        "logs": base / "logs",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, path)


def load_config() -> dict:
    path = state_dir() / "config.json"
    config = dict(DEFAULT_CONFIG)
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config.update(loaded)
        except (OSError, ValueError):
            pass
    if not config.get("install_id"):
        config["install_id"] = secrets.token_hex(8)
    _atomic_json(path, config)
    return config


def save_config(config: dict) -> None:
    merged = dict(DEFAULT_CONFIG)
    merged.update(config)
    _atomic_json(state_dir() / "config.json", merged)


def _registry_user_folders() -> list[Path]:
    if os.name != "nt":
        return []
    try:
        import winreg

        key_path = (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        )
        value_names = (
            "Desktop",
            "Personal",
            "My Pictures",
            "My Music",
            "My Video",
            "{374DE290-123F-4565-9164-39C4925E467B}",  # Downloads
        )
        result: list[Path] = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            for value_name in value_names:
                try:
                    raw, _ = winreg.QueryValueEx(key, value_name)
                    result.append(Path(os.path.expandvars(raw)))
                except OSError:
                    continue
        return result
    except (ImportError, OSError):
        return []


def _windows_data_drives() -> list[Path]:
    """Return non-system fixed/removable drive roots on Windows."""
    if os.name != "nt":
        return []
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(512)
        ctypes.windll.kernel32.GetLogicalDriveStringsW(len(buffer), buffer)
        drives = [item for item in buffer[:].split("\x00") if item]
        system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/").casefold()
        result = []
        for drive in drives:
            kind = ctypes.windll.kernel32.GetDriveTypeW(drive)
            if kind in (2, 3) and drive.rstrip("\\/").casefold() != system_drive:
                result.append(Path(drive))
        return result
    except (AttributeError, OSError, TypeError, ValueError):
        return []


def _unique_existing(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for raw in paths:
        try:
            path = raw.expanduser().resolve()
        except (OSError, RuntimeError):
            path = raw.expanduser().absolute()
        key = os.path.normcase(str(path))
        if key in seen or not path.is_dir():
            continue
        seen.add(key)
        result.append(path)
    return result


def discover_protected_roots(config: dict | None = None) -> list[Path]:
    config = config or load_config()
    env_roots = os.environ.get("CVDS_PROTECTED_ROOTS")
    if env_roots:
        return _unique_existing(
            Path(item) for item in env_roots.split(os.pathsep) if item
        )

    home = Path.home()
    candidates: list[Path] = []
    candidates.extend(Path(item) for item in config.get("protected_roots", []) if item)
    candidates.extend(_registry_user_folders())
    candidates.extend(
        home / name
        for name in ("Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos")
    )
    for env_name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        if os.environ.get(env_name):
            candidates.append(Path(os.environ[env_name]))
    if config.get("include_data_drives", True):
        candidates.extend(_windows_data_drives())

    roots = _unique_existing(candidates)
    if not roots and home.is_dir():
        roots = [home.resolve()]
    return roots


def is_excluded(path: str | Path) -> bool:
    try:
        parts = {part.casefold() for part in Path(path).parts}
    except (TypeError, ValueError):
        return True
    return bool(parts & EXCLUDED_PARTS)


def normalize_path(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _set_file_attributes(path: Path, attributes: int) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.kernel32.SetFileAttributesW(str(path), attributes))
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _set_hidden(path: Path) -> None:
    _set_file_attributes(path, 0x2 | 0x4)


def install_canaries(roots: Iterable[Path], install_id: str) -> set[str]:
    """Create randomized, per-installation canaries across every protected root."""
    token = install_id[:10]
    names = (
        f".~{token}-invoice.docx",
        f".~{token}-photo.jpg",
        f".~{token}-archive.pdf",
    )
    manifest: list[dict[str, str]] = []
    normalized: set[str] = set()
    for root in roots:
        for index, name in enumerate(names):
            path = root / name
            try:
                if path.exists():
                    if not path.is_file() or not path.read_bytes().startswith(
                        b"CVDS-CANARY\x00"
                    ):
                        continue
                else:
                    payload = (
                        b"CVDS-CANARY\x00"
                        + install_id.encode("ascii", errors="ignore")
                        + bytes([index])
                        + secrets.token_bytes(96)
                    )
                    path.write_bytes(payload)
                _set_hidden(path)
                normalized.add(normalize_path(path))
                manifest.append({"root": str(root), "path": str(path)})
            except OSError:
                continue
    _atomic_json(state_dir() / "canaries.json", manifest)
    return normalized


def remove_canaries() -> int:
    manifest_path = state_dir() / "canaries.json"
    if not manifest_path.exists():
        return 0
    try:
        items = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    removed = 0
    for item in items if isinstance(items, list) else []:
        try:
            path = Path(item["path"])
            if path.is_file() and path.read_bytes().startswith(b"CVDS-CANARY\x00"):
                if os.name == "nt":
                    _set_file_attributes(path, 0x80)
                path.unlink()
                removed += 1
        except (KeyError, OSError):
            continue
    try:
        manifest_path.unlink()
    except OSError:
        pass
    return removed
