"""Windows process-memory capture and AES schedule candidate extraction."""

from __future__ import annotations

import ctypes
import json
import os
import threading
import time
from ctypes import wintypes
from pathlib import Path

from .aes_keys import AESKeyCandidate, scan_aes_key_schedules
from .paths import ensure_state_dirs

_dump_lock = threading.Lock()


def write_forensics_manifest(path: Path, payload: dict) -> Path:
    """Write a sidecar so cleanup and forensic capture never overwrite one another."""
    document = {
        "schema": 1,
        "completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **payload,
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _write_key_candidates(path: Path, candidates: list[AESKeyCandidate]) -> Path:
    payload = {
        "status": "unverified_candidates",
        "warning": "A schedule match is not proof that this key decrypts victim files.",
        "candidates": [candidate.to_dict() for candidate in candidates],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def capture_minidump(pid: int, incident_id: str) -> tuple[str | None, str | None]:
    if os.name != "nt":
        return None, "minidump capture is Windows-only"
    import msvcrt

    process_query_information = 0x0400
    process_vm_read = 0x0010
    process_dup_handle = 0x0040
    access = process_query_information | process_vm_read | process_dup_handle
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("DbgHelp", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    process_handle = kernel32.OpenProcess(access, False, pid)
    if not process_handle:
        return None, f"OpenProcess failed: {ctypes.get_last_error()}"
    dump_path = ensure_state_dirs()["dumps"] / f"{incident_id}-{pid}.dmp"
    flags = 0x00000001 | 0x00000004 | 0x00000020 | 0x00000100 | 0x00000200
    flags |= 0x00000800 | 0x00001000 | 0x00020000
    try:
        with _dump_lock, dump_path.open("wb") as handle:
            file_handle = wintypes.HANDLE(msvcrt.get_osfhandle(handle.fileno()))
            dbghelp.MiniDumpWriteDump.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.HANDLE,
                wintypes.DWORD,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL
            ok = dbghelp.MiniDumpWriteDump(
                process_handle,
                pid,
                file_handle,
                flags,
                None,
                None,
                None,
            )
            if not ok:
                error = ctypes.get_last_error()
                try:
                    dump_path.unlink()
                except OSError:
                    pass
                return None, f"MiniDumpWriteDump failed: {error}"
        return str(dump_path), None
    except OSError as exc:
        return None, f"minidump file failed: {exc}"
    finally:
        kernel32.CloseHandle(process_handle)


def scan_live_process_for_aes(
    pid: int,
    incident_id: str,
    max_scan_mb: int = 192,
) -> tuple[list[AESKeyCandidate], str | None, str | None]:
    """Scan readable private memory while the suspect process is suspended."""
    if os.name != "nt":
        return [], None, "live process scan is Windows-only"

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("PartitionId", wintypes.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    process_query_information = 0x0400
    process_vm_read = 0x0010
    mem_commit = 0x1000
    mem_private = 0x20000
    page_guard = 0x100
    page_noaccess = 0x01
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    process_handle = kernel32.OpenProcess(
        process_query_information | process_vm_read, False, pid
    )
    if not process_handle:
        return (
            [],
            None,
            f"OpenProcess for memory scan failed: {ctypes.get_last_error()}",
        )

    candidates: list[AESKeyCandidate] = []
    seen_keys: set[str] = set()
    address = 0
    scanned = 0
    max_bytes = min(max(16, max_scan_mb), 1024) * 1024 * 1024
    mbi = MEMORY_BASIC_INFORMATION()
    try:
        while scanned < max_bytes:
            queried = kernel32.VirtualQueryEx(
                process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not queried:
                break
            base = int(mbi.BaseAddress or 0)
            region_size = int(mbi.RegionSize)
            if region_size <= 0:
                break
            readable_private = (
                mbi.State == mem_commit
                and mbi.Type == mem_private
                and not (mbi.Protect & page_guard)
                and not (mbi.Protect & page_noaccess)
            )
            if readable_private:
                offset = 0
                overlap = b""
                while (
                    offset < region_size
                    and scanned < max_bytes
                    and len(candidates) < 32
                ):
                    chunk_size = min(
                        4 * 1024 * 1024, region_size - offset, max_bytes - scanned
                    )
                    if chunk_size <= 0:
                        break
                    buffer = ctypes.create_string_buffer(chunk_size)
                    bytes_read = ctypes.c_size_t()
                    ok = kernel32.ReadProcessMemory(
                        process_handle,
                        ctypes.c_void_p(base + offset),
                        buffer,
                        chunk_size,
                        ctypes.byref(bytes_read),
                    )
                    if ok and bytes_read.value:
                        raw = overlap + buffer.raw[: bytes_read.value]
                        raw_base = base + offset - len(overlap)
                        for candidate in scan_aes_key_schedules(
                            raw,
                            raw_base,
                            alignment=16,
                            max_candidates=32,
                        ):
                            if candidate.key_hex not in seen_keys:
                                seen_keys.add(candidate.key_hex)
                                candidates.append(candidate)
                        overlap = raw[-256:]
                        scanned += int(bytes_read.value)
                    offset += chunk_size
            address = base + region_size
            if address <= base:
                break
    except (OSError, ValueError) as exc:
        return candidates, None, f"memory scan interrupted: {exc}"
    finally:
        kernel32.CloseHandle(process_handle)

    keys_path = None
    if candidates:
        path = ensure_state_dirs()["dumps"] / f"{incident_id}-{pid}-aes-candidates.json"
        keys_path = str(_write_key_candidates(path, candidates))
    return candidates, keys_path, None
