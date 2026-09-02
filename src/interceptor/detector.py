"""Crypto Virus Defense Shield Windows endpoint agent."""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

if __package__ in (None, ""):
    repo_root = Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

from src.cvds import __version__
from src.cvds.defender import (
    configure_cfa,
    configure_entry_shield,
    get_cfa_status,
    get_entry_shield_status,
    is_admin,
    launch_elevated,
)
from src.cvds.engine import BehaviorEngine, Detection, FileActivity
from src.cvds.forensics import (
    capture_minidump,
    scan_live_process_for_aes,
    write_forensics_manifest,
)
from src.cvds.incidents import create_incident
from src.cvds.paths import (
    discover_protected_roots,
    ensure_state_dirs,
    install_canaries,
    is_excluded,
    load_config,
    remove_canaries,
    state_dir,
)
from src.cvds.process_guard import (
    ProcessCandidate,
    ProcessMonitor,
    suspend_process_tree,
)
from src.cvds.profiles import FamilyProfiles

try:
    from src.i18n import get_available_languages, get_current_lang, set_lang, t
except ImportError:

    def get_current_lang():
        return "en"

    def set_lang(lang):
        return None

    def get_available_languages():
        return ["en"]

    def t(key):
        return key


from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

try:
    import pystray
    from PIL import Image, ImageDraw

    HAS_TRAY = True
except Exception:  # noqa: BLE001 - headless pystray backends raise nonstandard errors
    HAS_TRAY = False


DIRECTORIES = ensure_state_dirs()
LOG_FILE = DIRECTORIES["logs"] / "cvds.log"
LOCK_FILE = state_dir() / "cvds.lock"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("cvds")
_lock_handle = None


def ensure_single_instance() -> None:
    global _lock_handle
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        return
    import msvcrt

    try:
        _lock_handle = LOCK_FILE.open("a+")
        _lock_handle.seek(0)
        if not _lock_handle.read(1):
            _lock_handle.seek(0)
            _lock_handle.write("0")
            _lock_handle.flush()
        _lock_handle.seek(0)
        msvcrt.locking(_lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
        _lock_handle.seek(0)
        _lock_handle.truncate()
        _lock_handle.write(str(os.getpid()))
        _lock_handle.flush()
    except OSError:
        raise SystemExit("CVDS is already running in the system tray.")


class ShieldHandler(FileSystemEventHandler):
    def __init__(self, engine: BehaviorEngine, detections: queue.Queue[Detection]):
        super().__init__()
        self.engine = engine
        self.detections = detections

    def _evaluate(self, kind: str, src_path: str, dest_path: str | None = None) -> None:
        if is_excluded(dest_path or src_path):
            return
        detection = self.engine.evaluate(
            FileActivity(
                timestamp=time.time(),
                kind=kind,
                src_path=src_path,
                dest_path=dest_path,
            )
        )
        if detection:
            self.detections.put(detection)

    def on_modified(self, event):
        if not event.is_directory:
            self._evaluate("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._evaluate("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._evaluate("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._evaluate("moved", event.src_path, event.dest_path)


class IncidentResponder:
    def __init__(
        self,
        detection_queue: queue.Queue[Detection],
        process_monitor: ProcessMonitor,
        profiles: FamilyProfiles,
        config: dict,
    ):
        self.queue = detection_queue
        self.process_monitor = process_monitor
        self.profiles = profiles
        self.config = config
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run, name="cvds-responder", daemon=True
        )
        self.notify_callback = None
        self.detection_count = 0
        self._active_processes: set[tuple[int, float | None]] = set()
        self._state_lock = threading.Lock()
        self._contained_until = 0.0

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.queue.put(None)  # type: ignore[arg-type]
        self.thread.join(timeout=3)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                detection = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if detection is None:
                return
            try:
                self.handle_detection(detection)
            except Exception:
                log.exception("Incident response failed")

    def destructive_command_detected(
        self, candidate: ProcessCandidate, command: str
    ) -> None:
        detection = Detection(
            detected_at=time.time(),
            score=100,
            confidence="high",
            reasons=["system recovery destruction command", command],
            activity=FileActivity(
                timestamp=time.time(),
                kind="process_command",
                src_path=candidate.exe or candidate.name,
            ),
        )
        threading.Thread(
            target=self.handle_detection,
            args=(detection, candidate),
            name="cvds-command-response",
            daemon=True,
        ).start()

    def handle_detection(
        self,
        detection: Detection,
        forced_candidate: ProcessCandidate | None = None,
    ) -> None:
        with self._state_lock:
            if time.time() < self._contained_until:
                return
        candidate = forced_candidate or self.process_monitor.resolve(
            detection.activity.target_path,
            self.profiles,
        )
        candidate_key = (candidate.pid, candidate.create_time) if candidate else None
        if candidate_key:
            with self._state_lock:
                if candidate_key in self._active_processes:
                    return
        combined_score = detection.score
        if candidate:
            combined_score = round(
                detection.score * 0.62 + candidate.attribution_score * 0.38
            )

        response = {
            "mode": self.config.get("response_mode", "suspend"),
            "combined_confidence_score": combined_score,
            "suspended": False,
            "message": "candidate process was not attributable with sufficient confidence",
        }
        should_suspend = (
            candidate is not None
            and self.config.get("response_mode", "suspend") == "suspend"
            and combined_score >= 85
        )
        if should_suspend:
            suspended, message = suspend_process_tree(candidate.pid)
            response.update({"suspended": suspended, "message": message})
            if suspended:
                with self._state_lock:
                    if candidate_key:
                        self._active_processes.add(candidate_key)
                    self._contained_until = time.time() + 30.0

        token = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        artifacts: dict = {}
        capture_requested = bool(
            candidate
            and response["suspended"]
            and self.config.get("capture_memory", True)
        )
        forensics_path = DIRECTORIES["dumps"] / f"{token}-forensics.json"
        if capture_requested:
            artifacts["forensics"] = {
                "status": "scheduled",
                "result_path": str(forensics_path),
                "warning": "AES candidates require independent decryption validation",
            }

        incident_path, _ = create_incident(
            detection.to_dict(),
            candidate.to_dict() if candidate else None,
            response,
            artifacts,
        )
        self.detection_count += 1
        log.critical(
            "Ransomware response: score=%s family=%s candidate=%s suspended=%s incident=%s",
            detection.score,
            detection.family,
            candidate.name if candidate else "unresolved",
            response["suspended"],
            incident_path,
        )
        if self.notify_callback:
            self.notify_callback(
                "THREAT CONTAINED" if response["suspended"] else "THREAT DETECTED",
                "; ".join(detection.reasons[:2]),
            )
        if capture_requested and candidate:
            try:
                candidates, key_path, key_error = scan_live_process_for_aes(
                    candidate.pid,
                    token,
                    int(self.config.get("max_memory_scan_mb", 192)),
                )
                dump_path, dump_error = capture_minidump(candidate.pid, token)
                write_forensics_manifest(
                    forensics_path,
                    {
                        "status": "complete",
                        "pid": candidate.pid,
                        "aes_key_candidates": {
                            "count": len(candidates),
                            "status": "unverified" if candidates else "none_found",
                            "path": key_path,
                            "error": key_error,
                        },
                        "process_minidump": {"path": dump_path, "error": dump_error},
                    },
                )
            except Exception as exc:
                log.exception("Forensic capture failed")
                try:
                    write_forensics_manifest(
                        forensics_path,
                        {"status": "failed", "pid": candidate.pid, "error": str(exc)},
                    )
                except OSError:
                    log.exception("Cannot persist forensic capture failure")


def create_icon_image():
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.polygon(
        [(32, 3), (57, 13), (53, 43), (32, 61), (11, 43), (7, 13)], fill="#0284c7"
    )
    draw.rectangle((28, 17, 36, 45), fill="white")
    draw.rectangle((20, 25, 44, 33), fill="white")
    return image


def is_autostart_enabled() -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ) as key:
            winreg.QueryValueEx(key, "CryptoVirusDefenseShield")
        return True
    except OSError:
        return False


def set_autostart(enable: bool) -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_WRITE,
        ) as key:
            if enable:
                executable = sys.executable
                command = (
                    f'"{executable}"'
                    if getattr(sys, "frozen", False)
                    else f'"{executable}" "{Path(__file__).resolve()}"'
                )
                winreg.SetValueEx(
                    key, "CryptoVirusDefenseShield", 0, winreg.REG_SZ, command
                )
            else:
                try:
                    winreg.DeleteValue(key, "CryptoVirusDefenseShield")
                except FileNotFoundError:
                    pass
        return True
    except OSError as exc:
        log.error("Autostart update failed: %s", exc)
        return False


def open_path(path: Path) -> None:
    try:
        if os.name == "nt":
            os.startfile(str(path))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except OSError as exc:
        log.error("Cannot open %s: %s", path, exc)


def launch_cleanup() -> None:
    executable = Path(sys.executable)
    cleanup_exe = executable.with_name("CVDSEmergencyCleanup.exe")
    try:
        if getattr(sys, "frozen", False) and cleanup_exe.exists():
            subprocess.Popen([str(cleanup_exe)])
        else:
            subprocess.Popen([sys.executable, "-m", "src.cvds.cleanup"])
    except OSError as exc:
        log.error("Cleanup launch failed: %s", exc)


def run_tray(
    roots: list[Path],
    responder: IncidentResponder,
    observer: Observer,
    process_monitor: ProcessMonitor,
):
    icon_holder = {"icon": None}

    def notify(title: str, message: str) -> None:
        icon = icon_holder["icon"]
        if icon:
            try:
                icon.notify(message, title)
            except Exception as exc:  # noqa: BLE001 - notification backend is optional
                log.debug("Tray notification failed: %s", exc)

    responder.notify_callback = notify

    def status_text() -> str:
        cfa = get_cfa_status()
        entry_shield = get_entry_shield_status()
        return (
            f"CVDS v{__version__}\n"
            f"Protected roots: {len(roots)}\n"
            f"Detections: {responder.detection_count}\n"
            f"Defender CFA: {cfa.get('mode')}\n"
            f"Entry Shield: {entry_shield.get('mode')}"
        )

    def on_status(icon, item):
        notify("CVDS Status", status_text())

    def on_enable_cfa(icon, item):
        if is_admin():
            ok, message = configure_cfa(roots, sys.executable)
        else:
            ok, message = launch_elevated(["--enable-cfa"])
        notify("Controlled Folder Access", message)
        if not ok:
            log.warning(message)

    def on_enable_entry_shield(icon, item):
        if is_admin():
            ok, message = configure_entry_shield("balanced")
        else:
            ok, message = launch_elevated(["--enable-entry-shield", "balanced"])
        notify("Defender Entry Shield", message)
        if not ok:
            log.warning(message)

    def on_exit(icon, item):
        observer.stop()
        process_monitor.stop()
        responder.stop()
        icon.stop()

    language_items = [
        pystray.MenuItem(
            code.upper(),
            lambda icon, item, lang=code: set_lang(lang),
            checked=lambda item, lang=code: get_current_lang() == lang,
            radio=True,
        )
        for code in get_available_languages()
    ]
    menu = pystray.Menu(
        pystray.MenuItem(t("tray_status"), on_status),
        pystray.MenuItem(
            t("tray_open_log"), lambda icon, item: open_path(DIRECTORIES["incidents"])
        ),
        pystray.MenuItem(t("tray_cleanup"), lambda icon, item: launch_cleanup()),
        pystray.MenuItem(t("tray_enable_cfa"), on_enable_cfa),
        pystray.MenuItem(t("tray_enable_entry_shield"), on_enable_entry_shield),
        pystray.MenuItem(t("tray_language"), pystray.Menu(*language_items)),
        pystray.MenuItem(
            t("tray_autostart"),
            lambda icon, item: set_autostart(not is_autostart_enabled()),
            checked=lambda item: is_autostart_enabled(),
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(t("tray_exit"), on_exit),
    )
    icon = pystray.Icon(
        "CVDS", create_icon_image(), f"CVDS {__version__} - Active", menu
    )
    icon_holder["icon"] = icon
    icon.run()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Crypto Virus Defense Shield")
    parser.add_argument(
        "--enable-cfa", action="store_true", help="Enable Defender CFA in block mode"
    )
    parser.add_argument(
        "--enable-entry-shield",
        nargs="?",
        const="balanced",
        choices=("balanced", "strict"),
        help="Enable Defender entry controls (default: balanced)",
    )
    parser.add_argument(
        "--remove-canaries",
        action="store_true",
        help="Remove CVDS installation canaries",
    )
    parser.add_argument(
        "--status", action="store_true", help="Print protection status as JSON"
    )
    parser.add_argument("--no-tray", action="store_true", help="Run in console mode")
    parser.add_argument(
        "--response-mode",
        choices=("suspend", "alert"),
        help="Override response mode for this run (safe testing: alert)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config()
    if args.response_mode:
        config["response_mode"] = args.response_mode
    roots = discover_protected_roots(config)

    if args.enable_cfa:
        ok, message = configure_cfa(roots, sys.executable)
        print(message)
        return 0 if ok else 1
    if args.enable_entry_shield:
        ok, message = configure_entry_shield(args.enable_entry_shield)
        print(message)
        return 0 if ok else 1
    if args.remove_canaries:
        print(f"Removed {remove_canaries()} CVDS canary file(s).")
        return 0
    if args.status:
        profiles = FamilyProfiles()
        print(
            json.dumps(
                {
                    "version": __version__,
                    "protected_roots": [str(root) for root in roots],
                    "state_dir": str(state_dir()),
                    "cfa": get_cfa_status(),
                    "entry_shield": get_entry_shield_status(),
                    "family_profiles": {
                        "count": len(profiles.families),
                        "updated_utc": profiles.updated_utc,
                    },
                },
                indent=2,
            )
        )
        return 0

    ensure_single_instance()
    profiles = FamilyProfiles()
    canaries = install_canaries(roots, config["install_id"])
    if not canaries:
        log.error("No canaries could be installed; refusing to claim active protection")
        return 2
    detection_queue: queue.Queue[Detection] = queue.Queue()
    engine = BehaviorEngine(
        canaries,
        profiles,
        config.get("burst_threshold", 18),
        config.get("burst_window_seconds", 2.0),
        config.get("entropy_threshold", 7.35),
    )
    handler = ShieldHandler(engine, detection_queue)
    observer = Observer()
    scheduled: list[Path] = []
    for root in roots:
        try:
            observer.schedule(handler, str(root), recursive=True)
            scheduled.append(root)
        except OSError as exc:
            log.warning("Cannot monitor %s: %s", root, exc)
    if not scheduled:
        log.error("No protected roots could be monitored")
        return 2

    process_monitor = ProcessMonitor()
    responder = IncidentResponder(detection_queue, process_monitor, profiles, config)
    responder.start()
    process_monitor.start(responder.destructive_command_detected)
    observer.start()
    log.info("CVDS v%s active. Protected roots: %s", __version__, scheduled)

    try:
        if HAS_TRAY and not args.no_tray:
            run_tray(scheduled, responder, observer, process_monitor)
        else:
            print(
                f"CVDS active across {len(scheduled)} protected root(s). Ctrl+C to stop."
            )
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join(timeout=3)
        process_monitor.stop()
        responder.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
