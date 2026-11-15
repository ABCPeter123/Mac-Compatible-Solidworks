"""Private, allowlisted WINEDEBUG=err+msi diagnosis of original .NET4 setup.

No raw Winetricks or Microsoft logs, paths, command lines, DLL names other
than the public .NET package hint, or license/media information leave CI.
A fixed error marker is only a hypothesis; it does not identify a root API.
"""
from __future__ import annotations

import re

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 4096
STATUS = {"NOT_REQUESTED", "SCANNED", "TRUNCATED", "UNREADABLE"}
CLASSES = {
    "CABINET_MEDIA_MISSING", "CABINET_EXTRACT_FAILED", "NETFX_CORE_CAB_MISSING", "CUSTOM_ACTION_BAD_EXE",
    "CUSTOM_ACTION_DLL_LOAD", "MSI_ACTION_INSTALLFILES", "MSI_ACTION_FINALIZE",
    "MSI_CUSTOM_ACTION_UNSUPPORTED", "OTHER_MSI_ERROR",
    "CUSTOM_ACTION_PIPE_FAILURE", "CUSTOM_ACTION_RETURN_FAILURE",
    "MSI_ACTION_CUSTOM", "MSI_ACTION_SERVICE", "MSI_ACTION_REGISTRY",
    "MSI_ACTION_ASSEMBLY", "MSI_ACTION_PATCHFILES",
    "MSI_COMPRESSED_FILE_MISSING", "MSI_TSAWARE_UNIMPLEMENTED",
}
_MSI_ERR = re.compile(rb"(?i)\berr:msi:[a-z_0-9]+\s")
_MSI_FIXME = re.compile(rb"(?i)\bfixme:msi:[a-z_0-9]+\s")
_CAB = re.compile(rb"(?i)\bready_media\s+cabinet\s+not\s+found")
_NETFX_CAB = re.compile(rb"(?i)\bnetfx_core\.mzz\b")
_EXTRACT = re.compile(rb"(?i)\b(?:FDICopy failed|failed to extract cabinet)\b")
_CUSTOM_DLL = re.compile(rb"(?i)\b__wine_msi_call_dll_function\s+failed\s+to\s+load\s+dll")
_BAD_EXE = re.compile(rb"(?i)\(193\)\s*$")
_INSTALLFILES = re.compile(rb"(?i)\b(?:ACTION_InstallFiles|action L[\"']?InstallFiles)\b")
_FINALIZE = re.compile(rb"(?i)\b(?:action L[\"']?InstallFinalize|InstallFinalize)\b")
_UNSUPPORTED = re.compile(rb"(?i)\b(?:msidbCustomActionTypeTSAware|custom action.*not handled)\b")
_SCRIPT_PHASE = re.compile(rb"(?i)\bExecution of script ([012]) halted;")
_SCRIPT_PHASE_LABELS = {b"0": "INSTALL", b"1": "COMMIT", b"2": "ROLLBACK"}
PHASES = {"INSTALL", "COMMIT", "ROLLBACK", "UNDETERMINED", "NOT_IDENTIFIED"}
_ACTION_STRING = re.compile(rb'(?i)\baction\s+L"([^"\r\n]{1,350})"\s+returned\s+1603\b')
_CUSTOM_PIPE = re.compile(rb"(?i)\bcustom_client_thread\b.*\bfailed to write\b.*\bpipe\b")
_CUSTOM_RETURN = re.compile(rb"(?i)\bcustom_get_thread_return\b.*\binvalid Return Code\b")
_MISSING_FILE = re.compile(rb"(?i)\bcompressed file wasn'?t installed\b")
_PATCHFILES = re.compile(rb"(?i)\b(?:ACTION_PatchFiles|action L[\"']?PatchFiles)\b")


# Interpret only Wine's explicit script action L"..." returned 1603 marker.
# Arbitrary vendor action text is NEVER included in the result.
FAILED_ACTIONS = {
    "INSTALL_SERVICES", "START_SERVICES", "STOP_SERVICES", "DELETE_SERVICES",
    "SERVICE_CONFIG", "INSTALL_FILES", "PATCH_FILES", "REGISTRY_COM",
    "ASSEMBLY_GAC", "CUSTOM_ACTION", "OTHER_ACTION", "FINALIZE_ONLY",
    "NOT_IDENTIFIED",
}
SERVICE_ACTIONS = {
    "INSTALL_SERVICES", "START_SERVICES", "STOP_SERVICES",
    "DELETE_SERVICES", "SERVICE_CONFIG",
}


def _failure_phase(line: bytes) -> str:
    if _ACTION_STRING.search(line) is None:
        return "NOT_IDENTIFIED"
    match = _SCRIPT_PHASE.search(line)
    return _SCRIPT_PHASE_LABELS[match.group(1)] if match else "UNDETERMINED"


def _failed_action_type(line: bytes) -> str | None:
    match = _ACTION_STRING.search(line)
    if not match:
        return None
    raw = match.group(1).lower().replace(b" ", b"")
    names = {
        b"installservices": "INSTALL_SERVICES",
        b"startservices": "START_SERVICES",
        b"stopservices": "STOP_SERVICES",
        b"deleteservices": "DELETE_SERVICES",
        b"serviceconfig": "SERVICE_CONFIG",
        b"installfiles": "INSTALL_FILES",
        b"copyfiles": "INSTALL_FILES",
        b"patchfiles": "PATCH_FILES",
        b"writeregistryvalues": "REGISTRY_COM",
        b"registertypelib": "REGISTRY_COM",
        b"registercom": "REGISTRY_COM",
        b"publishassemblies": "ASSEMBLY_GAC",
        b"installfinalize": "FINALIZE_ONLY",
        b"install": "FINALIZE_ONLY",
    }
    if raw in names:
        return names[raw]
    if raw.startswith((b"ca_", b"customaction")) or re.search(
            rb"(?i)\]ca_[a-z_0-9]{1,70}\Z", raw):
        return "CUSTOM_ACTION"
    return "OTHER_ACTION"


NONSTANDARD_NAME_HINTS = {
    "NOT_APPLICABLE", "SERVICE_TEXT_ONLY", "REGISTRY_TEXT_ONLY",
    "ASSEMBLY_TEXT_ONLY", "MSI_PROPERTY_EXPANSION", "OTHER_NONSTANDARD_NAME",
}


def _nonstandard_name_hint(line: bytes) -> str:
    """Name-only hint. Cannot justify a Wine service/API compatibility hook."""
    match = _ACTION_STRING.search(line)
    if not match:
        return "NOT_APPLICABLE"
    name = match.group(1).lower()
    if b"service" in name:
        return "SERVICE_TEXT_ONLY"
    if any(term in name for term in (b"regtlb", b"registry", b"typelib", b"regasm")):
        return "REGISTRY_TEXT_ONLY"
    if any(term in name for term in (b"fusion", b"assembl", b"ngen", b"gac_")):
        return "ASSEMBLY_TEXT_ONLY"
    if b"[" in name or b"]" in name:
        return "MSI_PROPERTY_EXPANSION"
    return "OTHER_NONSTANDARD_NAME"


def _classify_failed_script_action(line: bytes) -> str | None:
    """Classify a *standard* MSI action only by exact canonical name.

    A vendor action containing 'StartServices' is not StartServices. Unknown
    text is kept private; no service claim from a substring.
    """
    action = _failed_action_type(line)
    if action in SERVICE_ACTIONS:
        return "MSI_ACTION_SERVICE"
    return {
        "FINALIZE_ONLY": "MSI_ACTION_FINALIZE",
        "INSTALL_FILES": "MSI_ACTION_INSTALLFILES",
        "PATCH_FILES": "MSI_ACTION_PATCHFILES",
        "REGISTRY_COM": "MSI_ACTION_REGISTRY",
        "ASSEMBLY_GAC": "MSI_ACTION_ASSEMBLY",
        "CUSTOM_ACTION": "MSI_ACTION_CUSTOM",
    }.get(action)


def empty() -> dict:
    return {
        "status": "NOT_REQUESTED", "classes": [], "msi_error_lines": 0,
        "first_failed_action": "NOT_IDENTIFIED", "service_action_failures": [],
        "nonstandard_name_hint": "NOT_APPLICABLE",
        "first_failed_script_phase": "NOT_IDENTIFIED",
        "first_install_failed_action": "NOT_IDENTIFIED",
        "install_script_failures": 0,
        "rollback_script_failures": 0,
    }


def parse(raw: bytes, *, oversized: bool = False) -> dict:
    if not isinstance(raw, bytes):
        return {**empty(), "status": "UNREADABLE"}
    if len(raw) > MAX_BYTES or oversized:
        return {**empty(), "status": "TRUNCATED"}
    classes: set[str] = set()
    script_actions: list[str] = []
    script_hints: list[str] = []
    script_phases: list[str] = []
    service_failures: set[str] = set()
    lines = 0
    for line in raw.splitlines():
        if len(line) > MAX_LINE_BYTES:
            continue
        is_error = bool(_MSI_ERR.search(line))
        is_fixme = bool(_MSI_FIXME.search(line))
        if not (is_error or is_fixme):
            continue
        if is_fixme:
            # Wine fixme markers are NOT equivalent to a failed action.
            # Include only one known, relevant custom-action warning.
            if b"msidbCustomActionTypeTSAware" in line and b"not handled" in line:
                classes.add("MSI_TSAWARE_UNIMPLEMENTED")
            continue
        lines += 1
        precise_action = _failed_action_type(line)
        if precise_action is not None:
            if len(script_actions) < 64:
                script_actions.append(precise_action)
                script_phases.append(_failure_phase(line))
                script_hints.append(
                    _nonstandard_name_hint(line) if precise_action == "OTHER_ACTION"
                    else "NOT_APPLICABLE"
                )
            if precise_action in SERVICE_ACTIONS:
                service_failures.add(precise_action)
        category = _classify_failed_script_action(line)
        if _CAB.search(line):
            classes.add("CABINET_MEDIA_MISSING")
            if _NETFX_CAB.search(line):
                classes.add("NETFX_CORE_CAB_MISSING")
        elif _EXTRACT.search(line):
            classes.add("CABINET_EXTRACT_FAILED")
        elif _CUSTOM_DLL.search(line):
            classes.add("CUSTOM_ACTION_DLL_LOAD")
            if _BAD_EXE.search(line):
                classes.add("CUSTOM_ACTION_BAD_EXE")
        elif _CUSTOM_PIPE.search(line):
            classes.add("CUSTOM_ACTION_PIPE_FAILURE")
        elif _CUSTOM_RETURN.search(line):
            classes.add("CUSTOM_ACTION_RETURN_FAILURE")
        elif _MISSING_FILE.search(line):
            classes.add("MSI_COMPRESSED_FILE_MISSING")
        elif _PATCHFILES.search(line):
            classes.add("MSI_ACTION_PATCHFILES")
        elif _INSTALLFILES.search(line):
            classes.add("MSI_ACTION_INSTALLFILES")
        elif category:
            classes.add(category)
        elif _FINALIZE.search(line):
            classes.add("MSI_ACTION_FINALIZE")
        elif _UNSUPPORTED.search(line):
            classes.add("MSI_CUSTOM_ACTION_UNSUPPORTED")
        else:
            classes.add("OTHER_MSI_ERROR")
    first_index = next(
        (i for i, action in enumerate(script_actions) if action != "FINALIZE_ONLY"),
        0 if script_actions else None,
    )
    first = script_actions[first_index] if first_index is not None else "NOT_IDENTIFIED"
    hint = script_hints[first_index] if first_index is not None else "NOT_APPLICABLE"
    phase = script_phases[first_index] if first_index is not None else "NOT_IDENTIFIED"
    install_actions = [a for a, p in zip(script_actions, script_phases) if p == "INSTALL"]
    install_first = next((a for a in install_actions if a != "FINALIZE_ONLY"),
                         install_actions[0] if install_actions else "NOT_IDENTIFIED")
    return {
        "status": "SCANNED", "classes": sorted(classes),
        "msi_error_lines": min(lines, 9999),
        "first_failed_action": first,
        "service_action_failures": sorted(service_failures),
        "nonstandard_name_hint": hint,
        "first_failed_script_phase": phase,
        "first_install_failed_action": install_first,
        "install_script_failures": min(len(install_actions), 64),
        "rollback_script_failures": min(script_phases.count("ROLLBACK"), 64),
    }


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {
        "status", "classes", "msi_error_lines",
        "first_failed_action", "service_action_failures", "nonstandard_name_hint",
        "first_failed_script_phase", "first_install_failed_action",
        "install_script_failures", "rollback_script_failures",
    }:
        return False
    if (result["status"] not in STATUS or type(result["classes"]) is not list
            or result["classes"] != sorted(set(result["classes"]))
            or any(v not in CLASSES for v in result["classes"])
            or type(result["msi_error_lines"]) is not int
            or not 0 <= result["msi_error_lines"] <= 9999
            or result["first_failed_action"] not in FAILED_ACTIONS
            or result["first_install_failed_action"] not in FAILED_ACTIONS
            or result["first_failed_script_phase"] not in PHASES
            or any(type(result[k]) is not int or not 0 <= result[k] <= 64 for k in
                   ("install_script_failures", "rollback_script_failures"))
            or ((result["install_script_failures"] == 0) !=
                (result["first_install_failed_action"] == "NOT_IDENTIFIED"))
            or ((result["first_failed_action"] == "NOT_IDENTIFIED") !=
                (result["first_failed_script_phase"] == "NOT_IDENTIFIED"))
            or result["nonstandard_name_hint"] not in NONSTANDARD_NAME_HINTS
            or ((result["first_failed_action"] == "OTHER_ACTION")
                != (result["nonstandard_name_hint"] != "NOT_APPLICABLE"))
            or type(result["service_action_failures"]) is not list
            or result["service_action_failures"] != sorted(set(result["service_action_failures"]))
            or any(action not in SERVICE_ACTIONS for action in result["service_action_failures"])):

        return False
    if result["status"] != "SCANNED":
        return (result["classes"] == [] and result["msi_error_lines"] == 0
                and result["first_failed_action"] == "NOT_IDENTIFIED"
                and result["service_action_failures"] == []
                and result["nonstandard_name_hint"] == "NOT_APPLICABLE"
                and result["first_failed_script_phase"] == "NOT_IDENTIFIED"
                and result["first_install_failed_action"] == "NOT_IDENTIFIED"
                and result["install_script_failures"] == 0
                and result["rollback_script_failures"] == 0)
    # A targeted fixme category can appear even when err:msi is absent.
    if result["msi_error_lines"] == 0:
        return (result["classes"] in ([], ["MSI_TSAWARE_UNIMPLEMENTED"])
                and result["first_failed_action"] == "NOT_IDENTIFIED"
                and result["service_action_failures"] == []
                and result["nonstandard_name_hint"] == "NOT_APPLICABLE"
                and result["first_failed_script_phase"] == "NOT_IDENTIFIED"
                and result["first_install_failed_action"] == "NOT_IDENTIFIED"
                and result["install_script_failures"] == 0
                and result["rollback_script_failures"] == 0)
    if result["service_action_failures"] and "MSI_ACTION_SERVICE" not in result["classes"]:
        return False
    if result["first_failed_action"] in SERVICE_ACTIONS and (
            result["first_failed_action"] not in result["service_action_failures"]):
        return False
    if result["first_failed_action"] == "FINALIZE_ONLY" and (
            "MSI_ACTION_FINALIZE" not in result["classes"]):
        return False
    return True
