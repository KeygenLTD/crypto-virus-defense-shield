import os
import subprocess
import sys
from pathlib import Path

import psutil
import pytest

from src.cvds.forensics import capture_minidump, scan_live_process_for_aes
from src.cvds.process_guard import suspend_process_tree

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows runtime validation")


def test_windows_suspend_aes_capture_and_minidump(tmp_path, monkeypatch):
    monkeypatch.setenv("CVDS_STATE_DIR", str(tmp_path / "state"))
    key_hex = "603deb1015ca71be2b73aef0857d7781"
    child_code = f"""
import ctypes
import time
from src.cvds.aes_keys import expand_aes_key
key = bytes.fromhex('{key_hex}')
expanded = expand_aes_key(key)
holders = []
for _ in range(1000):
    holder = ctypes.create_string_buffer(len(expanded) + 31)
    address = ctypes.addressof(holder)
    offset = (-address) % 16
    ctypes.memmove(address + offset, expanded, len(expanded))
    holders.append(holder)
print('READY', flush=True)
time.sleep(60)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "READY"
        suspended, message = suspend_process_tree(child.pid)
        assert suspended, message

        candidates, key_path, key_error = scan_live_process_for_aes(
            child.pid, "windows-test", max_scan_mb=64
        )
        assert key_error is None
        assert key_hex in {candidate.key_hex for candidate in candidates}
        assert key_path and Path(key_path).is_file()

        dump_path, dump_error = capture_minidump(child.pid, "windows-test")
        assert dump_error is None
        assert dump_path and Path(dump_path).stat().st_size > 0
    finally:
        try:
            psutil.Process(child.pid).resume()
        except psutil.Error:
            pass
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
