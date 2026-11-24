"""Privacy-safe classification of Wine MSI stderr from ORIGINAL .NET 4.8 MSP.

Only errors from Wine's err+msi channel are considered. Do not retain or
publish raw action names, vendor data, SID, GUID, command lines, paths, PIDs,
service names or Windows Installer logs. This diagnostic is not evidence of
successful Microsoft servicing, nor proof that a named action is causal.
"""
from __future__ import annotations

import re

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE = 8192
ERROR = re.compile(r"(?i)(?:^|\s)(?:[0-9a-f]{4,8}:)?err:msi:([a-z_]+)\b")
HALTED = re.compile(
    r'(?i)Execution of script\s+([0-9]{1,2})\s+halted;\s+'
    # Wine's deferred MSI actions can embed quoted executable and .tlb
    # paths inside L"[...]CA_Regtlb_amd64". Reject newlines and bound
    # length, but find the FINAL quote before returned, not the first.
    r'action\s+L"([^\r\n]{1,2048})"\s+returned\s+([0-9]{1,5})\b'
)
ACTION_CLASS = {
    "NGEN": re.compile(r"(?i)ngen|native.?image|optimiza"),
    "SERVICE": re.compile(r"(?i)service|schedservice|msdtc|svcctl"),
    "ASSEMBLY": re.compile(r"(?i)assembl|fusion|gac"),
    "CABINET": re.compile(r"(?i)cabinet|extract_cabinet|installfiles"),
    "REGISTRY": re.compile(r"(?i)registr|regsvcs|regasm|regsvr|regtlb|typelib"),
    "CUSTOM": re.compile(r"(?i)custom.?action|(?:^|[^a-z])ca_"),
}
ACTIONS = set(ACTION_CLASS) | {"UNKNOWN", "NOT_SEEN"}
STATUSES = {"NOT_RUN", "CLASSIFIED", "NO_MSI_ERRORS", "TOO_LARGE", "UNREADABLE"}
RETURNS = {"NOT_SEEN", "WIN32_1603", "OTHER_NONZERO", "ZERO"}
SIGNALS = {
    "INSTALL_SCRIPT_HALTED", "ROLLBACK_SCRIPT_HALTED",
    "MSI_CABINET_FAILURE", "MSI_CUSTOM_DLL_FAILURE",
    "MSI_SERVICE_OPERATION_FAILURE", "MSI_PATCH_FAILURE",
}
SIGNAL_MATCH = {
    "MSI_CABINET_FAILURE": re.compile(
        r"(?i)\b(?:extract_cabinet|extract_cabinet_stream|FDICopy|ready_media)\b"
    ),
    "MSI_CUSTOM_DLL_FAILURE": re.compile(
        r"(?i)\b(?:__wine_msi_call_dll_function|custom_action_server)\b"
    ),
    "MSI_SERVICE_OPERATION_FAILURE": re.compile(
        r"(?i)(?:servicecontrol|serviceconfig|startservices|installservices|schedservice)"
    ),
    "MSI_PATCH_FAILURE": re.compile(
        r"(?i)\b(?:apply_patch|patching|patch_package)\b"
    ),
}


def blank(status: str = "NOT_RUN") -> dict:
    if type(status) is not str or status not in STATUSES:
        raise ValueError("Invalid original Microsoft MSP Wine trace status")
    return {
        "status": status,
        "first_forward_action": "NOT_SEEN",
        "first_forward_return": "NOT_SEEN",
        "first_rollback_action": "NOT_SEEN",
        "first_rollback_return": "NOT_SEEN",
        "signals": [],
    }


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (type(report["status"]) is not str
            or report["status"] not in STATUSES
            or any(type(report[key]) is not str or report[key] not in ACTIONS
                   for key in ("first_forward_action", "first_rollback_action"))
            or any(type(report[key]) is not str or report[key] not in RETURNS
                   for key in ("first_forward_return", "first_rollback_return"))
            or type(report["signals"]) is not list
            or report["signals"] != sorted(set(report["signals"]))
            or any(type(item) is not str or item not in SIGNALS
                   for item in report["signals"])):
        return False
    if report["status"] != "CLASSIFIED":
        return report == blank(report["status"])
    if (report["first_forward_action"] == "NOT_SEEN") != (
            report["first_forward_return"] == "NOT_SEEN"):
        return False
    if (report["first_rollback_action"] == "NOT_SEEN") != (
            report["first_rollback_return"] == "NOT_SEEN"):
        return False
    if (report["first_forward_action"] != "NOT_SEEN"
            and "INSTALL_SCRIPT_HALTED" not in report["signals"]):
        return False
    if (report["first_rollback_action"] != "NOT_SEEN"
            and "ROLLBACK_SCRIPT_HALTED" not in report["signals"]):
        return False
    return True


def _action(raw: str) -> str:
    # Deferred CA actions may be represented as [private payload]CA_Name.
    # Classify ONLY the real trailing action identifier. A path/command
    # inside brackets is neither an MSI action nor causal evidence.
    name = raw.rsplit("]", 1)[-1] if "]" in raw else raw
    if not name:
        return "UNKNOWN"
    return next((kind for kind, rule in ACTION_CLASS.items()
                 if rule.search(name)), "UNKNOWN")


def _return(raw: str) -> str:
    if raw == "0":
        return "ZERO"
    return "WIN32_1603" if raw == "1603" else "OTHER_NONZERO"


def classify(raw: bytes) -> dict:
    if type(raw) is not bytes:
        return blank("UNREADABLE")
    if len(raw) > MAX_BYTES:
        return blank("TOO_LARGE")
    try:
        text = raw.decode("utf-8", errors="replace")
    except (ValueError, UnicodeError):
        return blank("UNREADABLE")
    report = blank("CLASSIFIED")
    signals: set[str] = set()
    found = False
    for line in text.splitlines():
        if len(line) > MAX_LINE:
            continue
        match = ERROR.search(line)
        if match is None:
            continue
        found = True
        for signal, rule in SIGNAL_MATCH.items():
            if rule.search(line):
                signals.add(signal)
        if match.group(1).casefold() == "execute_script":
            failure = HALTED.search(line)
            if failure:
                script, action, code = failure.groups()
                # Wine's script 0 is the forward execution; script 2 is
                # rollback in the observed Wine trace. Unknown scripts do
                # not get labeled as forward or causal.
                if script == "0" and report["first_forward_action"] == "NOT_SEEN":
                    report["first_forward_action"] = _action(action)
                    report["first_forward_return"] = _return(code)
                    signals.add("INSTALL_SCRIPT_HALTED")
                elif script == "2" and report["first_rollback_action"] == "NOT_SEEN":
                    report["first_rollback_action"] = _action(action)
                    report["first_rollback_return"] = _return(code)
                    signals.add("ROLLBACK_SCRIPT_HALTED")
    if not found:
        return blank("NO_MSI_ERRORS")
    report["signals"] = sorted(signals)
    assert valid(report)
    return report
