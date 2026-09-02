"""Microsoft Defender ransomware-prevention integrations."""

from __future__ import annotations

import base64
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

CFA_MODES = {
    0: "Disabled",
    1: "Enabled",
    2: "AuditMode",
    3: "BlockDiskModificationOnly",
    4: "AuditDiskModificationOnly",
}

# Microsoft Defender Attack Surface Reduction rule IDs.  Numeric actions are
# the documented Defender values: 1 = Block, 2 = Audit.  Balanced mode blocks
# common initial-access paths while leaving administration-heavy rules in audit
# so CVDS does not silently break an existing management workflow.
ASR_RULES = {
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "advanced ransomware protection",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "executable content from email/webmail",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Office child processes",
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "abused vulnerable signed drivers",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "credential theft from LSASS",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "JavaScript/VBScript downloaded executables",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Office-created executable content",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Office code injection",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "obfuscated scripts",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": "PsExec/WMI child processes",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "safe-mode reboot",
    "01443614-cd74-433a-b99e-2ecdc07bfc25": "untrusted or low-prevalence executables",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "untrusted executables from USB",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Win32 API calls from Office macros",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Adobe Reader child processes",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "WMI event-subscription persistence",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Outlook child processes",
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "copied or impersonated system tools",
}

BALANCED_ASR_ACTIONS = {
    "c1db55ab-c21a-4637-bb3f-a12568109d35": 1,
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": 1,
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": 1,
    "56a863a9-875e-4185-98a7-b882c64b5ce5": 1,
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 1,
    "d3e037e1-3eb8-44c8-a917-57927947596d": 1,
    "3b576869-a4ec-4529-8536-b80a7769e899": 1,
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": 1,
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": 2,
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": 2,
    "33ddedf1-c6e0-47cb-833e-de6133960387": 1,
    "01443614-cd74-433a-b99e-2ecdc07bfc25": 2,
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": 1,
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": 1,
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": 1,
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": 2,
    "26190899-1602-49e8-8b27-eb1d0a1ce869": 1,
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": 2,
}


def _powershell(script: str, timeout: int = 60) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def get_cfa_status() -> dict:
    if os.name != "nt":
        return {"available": False, "mode": "Unsupported", "protected_folders": []}
    script = """
$ErrorActionPreference = 'Stop'
$p = Get-MpPreference
[pscustomobject]@{
  mode = [int]$p.EnableControlledFolderAccess
  protected_folders = @($p.ControlledFolderAccessProtectedFolders)
} | ConvertTo-Json -Compress
"""
    try:
        completed = _powershell(script)
        if completed.returncode != 0:
            return {
                "available": False,
                "mode": "Unavailable",
                "protected_folders": [],
                "error": (completed.stderr or completed.stdout).strip(),
            }
        payload = json.loads(completed.stdout.strip())
        mode_value = int(payload.get("mode", 0))
        return {
            "available": True,
            "mode": CFA_MODES.get(mode_value, f"Unknown({mode_value})"),
            "mode_value": mode_value,
            "protected_folders": payload.get("protected_folders") or [],
        }
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {
            "available": False,
            "mode": "Unavailable",
            "protected_folders": [],
            "error": str(exc),
        }


def get_entry_shield_status() -> dict:
    """Return the effective Defender prevention settings without changing them."""
    if os.name != "nt":
        return {"available": False, "mode": "Unsupported", "asr_rules": {}}
    script = """
$ErrorActionPreference = 'Stop'
$p = Get-MpPreference
$rules = @{}
$ids = @($p.AttackSurfaceReductionRules_Ids)
$actions = @($p.AttackSurfaceReductionRules_Actions)
for ($i = 0; $i -lt $ids.Count; $i++) {
  $rules[$ids[$i].ToString().ToLowerInvariant()] = [int]$actions[$i]
}
[pscustomobject]@{
  network_protection = [int]$p.EnableNetworkProtection
  pua_protection = [int]$p.PUAProtection
  cloud_reporting = [int]$p.MAPSReporting
  block_at_first_sight = -not [bool]$p.DisableBlockAtFirstSeen
  behavior_monitoring = -not [bool]$p.DisableBehaviorMonitoring
  script_scanning = -not [bool]$p.DisableScriptScanning
  archive_scanning = -not [bool]$p.DisableArchiveScanning
  removable_drive_scanning = -not [bool]$p.DisableRemovableDriveScanning
  asr_rules = $rules
} | ConvertTo-Json -Compress -Depth 4
"""
    try:
        completed = _powershell(script)
        if completed.returncode != 0:
            return {
                "available": False,
                "mode": "Unavailable",
                "asr_rules": {},
                "error": (completed.stderr or completed.stdout).strip(),
            }
        payload = json.loads(completed.stdout.strip())
        configured = {
            rule_id: {
                "name": name,
                "action": {0: "disabled", 1: "block", 2: "audit", 6: "warn"}.get(
                    int((payload.get("asr_rules") or {}).get(rule_id, 0)),
                    "unknown",
                ),
            }
            for rule_id, name in ASR_RULES.items()
        }
        core_enabled = (
            int(payload.get("network_protection", 0)) == 1
            and int(payload.get("pua_protection", 0)) == 1
            and int(payload.get("cloud_reporting", 0)) > 0
            and bool(payload.get("block_at_first_sight"))
            and bool(payload.get("behavior_monitoring"))
            and bool(payload.get("script_scanning"))
            and bool(payload.get("archive_scanning"))
            and bool(payload.get("removable_drive_scanning"))
        )
        desired_actions = [item["action"] for item in configured.values()]
        if (
            core_enabled
            and desired_actions
            and all(action == "block" for action in desired_actions)
        ):
            mode = "Strict"
        elif core_enabled and any(action == "block" for action in desired_actions):
            mode = "Balanced"
        else:
            mode = "NotConfigured"
        payload.update({"available": True, "mode": mode, "asr_rules": configured})
        return payload
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError) as exc:
        return {
            "available": False,
            "mode": "Unavailable",
            "asr_rules": {},
            "error": str(exc),
        }


def configure_entry_shield(mode: str = "balanced") -> tuple[bool, str]:
    """Enable Defender entry controls while preserving unrelated ASR rules."""
    if os.name != "nt":
        return False, "Defender Entry Shield is Windows-only"
    if not is_admin():
        return False, "administrator rights are required to enable Entry Shield"
    normalized_mode = mode.casefold()
    if normalized_mode not in {"balanced", "strict"}:
        return False, f"unsupported Entry Shield mode: {mode}"
    desired = {
        rule_id: (1 if normalized_mode == "strict" else action)
        for rule_id, action in BALANCED_ASR_ACTIONS.items()
    }
    desired_literals = "\n".join(
        f"$desired['{rule_id}'] = {action}" for rule_id, action in desired.items()
    )
    script = f"""
$ErrorActionPreference = 'Stop'

# Keep Defender's real-time and cloud inspection active for downloaded payloads.
Set-MpPreference `
  -PUAProtection Enabled `
  -EnableNetworkProtection Enabled `
  -MAPSReporting Advanced `
  -SubmitSamplesConsent SendSafeSamples `
  -DisableBlockAtFirstSeen $false `
  -DisableBehaviorMonitoring $false `
  -DisableScriptScanning $false `
  -DisableArchiveScanning $false `
  -DisableRemovableDriveScanning $false

# Merge CVDS rules with the existing ASR policy rather than replacing it.
$current = Get-MpPreference
$merged = @{{}}
$ids = @($current.AttackSurfaceReductionRules_Ids)
$actions = @($current.AttackSurfaceReductionRules_Actions)
for ($i = 0; $i -lt $ids.Count; $i++) {{
  $merged[$ids[$i].ToString().ToLowerInvariant()] = [int]$actions[$i]
}}
$desired = @{{}}
{desired_literals}
foreach ($item in $desired.GetEnumerator()) {{
  $merged[$item.Key] = [int]$item.Value
}}
$allIds = @($merged.Keys | Sort-Object)
$allActions = @($allIds | ForEach-Object {{ [int]$merged[$_] }})
Set-MpPreference `
  -AttackSurfaceReductionRules_Ids $allIds `
  -AttackSurfaceReductionRules_Actions $allActions
'CVDS_ENTRY_SHIELD_OK'
"""
    try:
        completed = _powershell(script, timeout=180)
        if completed.returncode == 0 and "CVDS_ENTRY_SHIELD_OK" in completed.stdout:
            return True, f"Defender Entry Shield enabled in {normalized_mode} mode"
        return False, (
            completed.stderr or completed.stdout or "Entry Shield configuration failed"
        ).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Entry Shield configuration failed: {exc}"


def configure_cfa(
    roots: list[Path], application_path: str | None = None
) -> tuple[bool, str]:
    """Enable CFA block mode and add roots without replacing existing policy values."""
    if os.name != "nt":
        return False, "Controlled Folder Access is Windows-only"
    if not is_admin():
        return (
            False,
            "administrator rights are required to enable Controlled Folder Access",
        )
    root_literals = ",".join("'" + str(root).replace("'", "''") + "'" for root in roots)
    app = application_path or sys.executable
    app_literal = str(app).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
Set-MpPreference -EnableControlledFolderAccess Enabled
$current = Get-MpPreference
$existingFolders = @($current.ControlledFolderAccessProtectedFolders)
$existingApps = @($current.ControlledFolderAccessAllowedApplications)
$folders = @({root_literals})
foreach ($folder in $folders) {{
  if ((Test-Path -LiteralPath $folder) -and ($existingFolders -notcontains $folder)) {{
    Add-MpPreference -ControlledFolderAccessProtectedFolders $folder
  }}
}}
if ((Test-Path -LiteralPath '{app_literal}') -and ($existingApps -notcontains '{app_literal}')) {{
  Add-MpPreference -ControlledFolderAccessAllowedApplications '{app_literal}'
}}
'CVDS_CFA_OK'
"""
    try:
        completed = _powershell(script, timeout=120)
        if completed.returncode == 0 and "CVDS_CFA_OK" in completed.stdout:
            return True, "Controlled Folder Access enabled in block mode"
        return False, (
            completed.stderr or completed.stdout or "CFA configuration failed"
        ).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"CFA configuration failed: {exc}"


def launch_elevated(
    arguments: list[str], module: str | None = None
) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "elevation is Windows-only"
    try:
        executable = sys.executable
        command_arguments = list(arguments)
        if not getattr(sys, "frozen", False):
            if module:
                command_arguments = ["-m", module, *command_arguments]
            else:
                command_arguments.insert(0, str(Path(sys.argv[0]).resolve()))
        params = subprocess.list2cmdline(command_arguments)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        if result > 32:
            return True, "elevated helper launched"
        return False, f"elevation was cancelled or failed ({result})"
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        return False, f"elevation failed: {exc}"
