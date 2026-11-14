"""Classify the FIRST failing nested .NET 4.0 MSI action in private Wine TEMP.

The bootstrapper's Windows 1603 is only a generic error. Do not introduce
DLL shims or service patches until we can identify the internal MSI stage.
Raw Microsoft logs remain in a marked disposable Wine prefix and NEVER
appear in reports, command output, public artifacts or error messages.

A Return value 3 marker identifies an MSI action failure but not its cause.
Only fixed, coarse-grained public categories may leave the runner.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

MAX_FILES = 36
MAX_DIRS = 144
MAX_DEPTH = 7
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_LINE = 8192
MAX_ACTIONS = 80

MSI_LOG = re.compile(
    r"(?i)^Microsoft \.NET Framework 4 Setup_[a-z0-9_(). -]{1,116}"
    r"-MSI_netfx_[a-z0-9_(). -]{1,65}\.msi\.(?:txt|log)$"
)
SETUP_LOG = re.compile(
    r"(?i)^Microsoft \.NET Framework 4 Setup_[a-z0-9_(). -]{1,116}\.(?:txt|log|html)$"
)
DD_LOG = re.compile(r"(?i)^dd_[a-z0-9_(). -]{1,110}\.(?:txt|log)$")
VERBOSE_MSI_LOG = re.compile(r"(?i)^msi[a-f0-9]{2,16}\.log$")
_ACTION_FAILED = re.compile(
    r"(?i)\bAction ended\s+\d{1,2}:\d{2}:\d{2}:\s*"
    r"([a-z][a-z0-9_. -]{0,90})\.\s*Return value 3\b"
)
_ERROR_NUMBER = re.compile(r"(?i)\b(?:Note:\s*1:\s*|Error\s+)(\d{4})\b")
_HEX_CODE = re.compile(r"(?i)(?<![a-z0-9])0x[0-9a-f]{8}(?![a-z0-9])")

ERROR_CODES = {
    "1402": "REGISTRY_ACCESS",
    "1603": "GENERIC_MSI_FAILURE",
    "1722": "EXTERNAL_ACTION_FAILURE",
    "1723": "CUSTOM_DLL_ACTION_FAILURE",
    "1935": "ASSEMBLY_INSTALL_FAILURE",
    "2502": "MSI_TRANSACTION_ORDER",
    "2503": "MSI_TRANSACTION_ORDER",
    "2755": "MSI_PACKAGE_ACCESS",
}
HEX_CODES = {
    "0X80070005": "ACCESS_DENIED",
    "0X80070002": "FILE_NOT_FOUND",
    "0X8007007E": "MISSING_MODULE",
    "0X800700C1": "INVALID_MODULE",
    "0X80070643": "GENERIC_MSI_FAILURE",
    "0X80131700": "CLR_ACTIVATION",
    "0X80040154": "COM_CLASS_NOT_REGISTERED",
    "0X80070422": "SERVICE_DISABLED",
    "0X80070424": "SERVICE_MISSING",
    "0X80004005": "UNSPECIFIED_FAILURE",
}
ERROR_CLASSES = set(ERROR_CODES.values()) | set(HEX_CODES.values())
ACTION_CLASSES = {
    "VERSION_GUARD", "SERVICE", "REGISTRY_COM", "ASSEMBLY_GAC",
    "FILESYSTEM", "CUSTOM_ACTION", "FINALIZE_CASCADE", "UNKNOWN",
}
STATUS = {"NO_LOG", "SCANNED", "PARTIAL_SCAN", "INVALID_ROOT"}
SOURCES = {"NONE", "NESTED_MSI", "VERBOSE_MSI", "BOOTSTRAPPER_TEMP"}
MSI_RESULT = {"NOT_FOUND", "FAILURE_MARKER", "NO_FAILURE_MARKER"}
CAUSALITY = {"NOT_ESTABLISHED", "ACTION_HINT_ONLY"}


def classify_action(name: str) -> str:
    """Map names to a fixed subsystem. Never return arbitrary action names."""
    action = name.lower().replace(" ", "")
    if any(x in action for x in ("blockolder", "launchcondition", "blocknewer")):
        return "VERSION_GUARD"
    if any(x in action for x in ("installservice", "startservice", "stopservice",
                                  "deleteservice", "servicemodel", "serviceconfig")):
        return "SERVICE"
    if any(x in action for x in ("registry", "regasm", "regsvr", "typelib",
                                  "registerclass", "registercom", "publishcomponent")):
        return "REGISTRY_COM"
    if any(x in action for x in ("assembl", "gac", "fusion", "ngen")):
        return "ASSEMBLY_GAC"
    if any(x in action for x in ("installfile", "copyfile", "movefile",
                                  "createfolder", "costfinalize")):
        return "FILESYSTEM"
    if action in {"install", "executeaction", "installfinalize", "installinitialize"}:
        return "FINALIZE_CASCADE"
    if action.startswith(("ca_", "customaction")):
        return "CUSTOM_ACTION"
    return "UNKNOWN"


def _decode(raw: bytes) -> str | None:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if raw.count(b"\x00") > max(16, len(raw) // 10):
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Logs on Windows can use an 8-bit legacy code page.
        return raw.decode("cp1252")


def classify_msi_log(raw: bytes) -> dict:
    """Find first non-cascade Return value 3, collect only allowlisted errors."""
    if len(raw) > MAX_FILE_BYTES:
        return {"readable": False, "failure": False,
                "action": "UNKNOWN", "errors": []}
    text = _decode(raw)
    if text is None:
        return {"readable": False, "failure": False,
                "action": "UNKNOWN", "errors": []}
    failures: list[str] = []
    errors: set[str] = set()
    for line in text.splitlines():
        if len(line) > MAX_LINE:
            continue
        action = _ACTION_FAILED.search(line)
        if action and len(failures) < MAX_ACTIONS:
            failures.append(classify_action(action.group(1)))
        for match in _ERROR_NUMBER.finditer(line):
            category = ERROR_CODES.get(match.group(1))
            if category:
                errors.add(category)
        if any(x in line.lower() for x in ("error", "failed", "hresult", "status")):
            for match in _HEX_CODE.finditer(line):
                category = HEX_CODES.get(match.group().upper())
                if category:
                    errors.add(category)
    first = next((x for x in failures if x != "FINALIZE_CASCADE"),
                 failures[0] if failures else "UNKNOWN")
    return {"readable": True, "failure": bool(failures),
            "action": first, "errors": sorted(errors)}


def empty(status: str = "NO_LOG") -> dict:
    if status not in STATUS:
        raise ValueError("Invalid diagnostic status")
    return {
        "status": status, "files_scanned": 0, "msi_files": 0,
        "primary_source": "NONE", "msi_result": "NOT_FOUND",
        "first_failed_action_class": "UNKNOWN", "errors": [],
        "causality": "NOT_ESTABLISHED",
    }


def _roots(prefix: Path) -> list[Path]:
    c = prefix / "drive_c"
    return [c / "users", c / "windows" / "Temp", c / "windows" / "temp",
            c / "Temp"]


def scan(prefix: Path) -> dict:
    """Inspect only short-lived original Microsoft .NET4 setup log files.

    The tool never follows directory or file symlinks, never saves/prints raw
    logs, and cannot access arbitrary paths outside the disposable prefix.
    """
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    result = empty()
    candidates: list[tuple[int, dict]] = []
    observed_files: set[Path] = set()
    directories = 0
    partial = False
    invalid = False
    for root in _roots(prefix):
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            invalid = True
            continue
        for base, subdirs, files in os.walk(root, topdown=True, followlinks=False):
            directories += 1
            current = Path(base)
            if directories > MAX_DIRS:
                partial = True
                break
            if len(current.relative_to(root).parts) >= MAX_DEPTH:
                subdirs.clear()
            else:
                subdirs[:] = sorted(
                    x for x in subdirs if not (current / x).is_symlink()
                )[:24]
            for filename in sorted(files):
                group = (3 if VERBOSE_MSI_LOG.fullmatch(filename) else
                         2 if MSI_LOG.fullmatch(filename) else
                         1 if SETUP_LOG.fullmatch(filename) or DD_LOG.fullmatch(filename)
                         else 0)
                if group == 0:
                    continue
                file = current / filename
                if file in observed_files or file.is_symlink() or not file.is_file():
                    continue
                observed_files.add(file)
                if result["files_scanned"] >= MAX_FILES:
                    partial = True
                    break
                result["files_scanned"] += 1
                if group >= 2:
                    result["msi_files"] += 1
                try:
                    with file.open("rb") as stream:
                        # Microsoft verbose MSI logs can exceed 4 MiB. Read
                        # only their tail, where the failing action and
                        # rollback summary are normally recorded. Never
                        # read or export unbounded logs.
                        if group == 3 and file.stat().st_size > MAX_FILE_BYTES:
                            partial = True
                            stream.seek(-MAX_FILE_BYTES, 2)
                        raw = stream.read(MAX_FILE_BYTES + 1)
                    classified = classify_msi_log(raw)
                    if not classified["readable"]:
                        partial = True
                        continue
                    candidates.append((group, classified))
                except OSError:
                    partial = True
            if result["files_scanned"] >= MAX_FILES:
                partial = True
                break

    # A failing MSI action is more authoritative than the outer setup log.
    # Prefer nested MSI with a Return value 3 over any setup summary.
    candidates.sort(key=lambda c: (c[1]["failure"], c[0]), reverse=True)
    if candidates:
        group, top = candidates[0]
        result.update({
            "primary_source": ("VERBOSE_MSI" if group == 3 else
                               "NESTED_MSI" if group == 2 else "BOOTSTRAPPER_TEMP"),
            "msi_result": "FAILURE_MARKER" if top["failure"] else "NO_FAILURE_MARKER",
            "first_failed_action_class": top["action"],
            "errors": sorted(set().union(*(set(c[1]["errors"]) for c in candidates))),
            "causality": "ACTION_HINT_ONLY" if top["failure"] else "NOT_ESTABLISHED",
        })
    result["status"] = ("PARTIAL_SCAN" if partial else
                        "SCANNED" if result["files_scanned"] else
                        "INVALID_ROOT" if invalid else "NO_LOG")
    return result


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {
        "status", "files_scanned", "msi_files", "primary_source",
        "msi_result", "first_failed_action_class", "errors", "causality"
    }:
        return False
    if (result["status"] not in STATUS
            or type(result["files_scanned"]) is not int
            or type(result["msi_files"]) is not int
            or not 0 <= result["msi_files"] <= result["files_scanned"] <= MAX_FILES
            or result["primary_source"] not in SOURCES
            or result["msi_result"] not in MSI_RESULT
            or result["first_failed_action_class"] not in ACTION_CLASSES
            or result["causality"] not in CAUSALITY
            or type(result["errors"]) is not list
            or result["errors"] != sorted(set(result["errors"]))
            or any(x not in ERROR_CLASSES for x in result["errors"])):
        return False
    if result["msi_result"] == "FAILURE_MARKER":
        return (result["primary_source"] != "NONE"
                and result["causality"] == "ACTION_HINT_ONLY")
    return result["first_failed_action_class"] == "UNKNOWN" and result["causality"] == "NOT_ESTABLISHED"


if __name__ == "__main__":
    raise SystemExit("Import this diagnostic only from the disposable original .NET4 trial")
