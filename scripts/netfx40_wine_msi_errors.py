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


def _classify_failed_script_action(line: bytes) -> str | None:
    """A script failure may precede the InstallFinalize rollback error.

    Never return raw action names: they can embed Windows paths, usernames,
    GUIDs or vendor-specific install properties.
    """
    m = _ACTION_STRING.search(line)
    if not m:
        return None
    action = m.group(1).lower().replace(b" ", b"")
    if b"installfinalize" == action or b"install" == action:
        return "MSI_ACTION_FINALIZE"
    if b"installfiles" == action or b"copyfiles" == action:
        return "MSI_ACTION_INSTALLFILES"
    if b"patchfiles" == action:
        return "MSI_ACTION_PATCHFILES"
    if any(x in action for x in (b"installservice", b"startservice",
                                   b"stopservice", b"serviceconfig")):
        return "MSI_ACTION_SERVICE"
    if any(x in action for x in (b"writeregistry", b"regasm",
                                   b"registertypelib", b"registercom")):
        return "MSI_ACTION_REGISTRY"
    if any(x in action for x in (b"publishassembl", b"ngen", b"fusion", b"gac")):
        return "MSI_ACTION_ASSEMBLY"
    if action.startswith((b"ca_", b"customaction")) or re.search(
            rb"(?i)\]ca_[a-z_0-9]{1,70}\Z", action):
        return "MSI_ACTION_CUSTOM"
    # Other execution-script action names are NOT evidence of a Wine API gap.
    return None



def empty() -> dict:
    return {
        "status": "NOT_REQUESTED", "classes": [], "msi_error_lines": 0,
        "first_failed_action": "NOT_IDENTIFIED", "service_action_failures": [],
    }


def parse(raw: bytes, *, oversized: bool = False) -> dict:
    if not isinstance(raw, bytes):
        return {**empty(), "status": "UNREADABLE"}
    if len(raw) > MAX_BYTES or oversized:
        return {**empty(), "status": "TRUNCATED"}
    classes: set[str] = set()
    script_actions: list[str] = []
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
    first = next(
        (action for action in script_actions if action != "FINALIZE_ONLY"),
        script_actions[0] if script_actions else "NOT_IDENTIFIED",
    )
    return {
        "status": "SCANNED", "classes": sorted(classes),
        "msi_error_lines": min(lines, 9999),
        "first_failed_action": first,
        "service_action_failures": sorted(service_failures),
    }


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {
        "status", "classes", "msi_error_lines",
        "first_failed_action", "service_action_failures",
    }:
        return False
    if (result["status"] not in STATUS or type(result["classes"]) is not list
            or result["classes"] != sorted(set(result["classes"]))
            or any(v not in CLASSES for v in result["classes"])
            or type(result["msi_error_lines"]) is not int
            or not 0 <= result["msi_error_lines"] <= 9999
            or result["first_failed_action"] not in FAILED_ACTIONS
            or type(result["service_action_failures"]) is not list
            or result["service_action_failures"] != sorted(set(result["service_action_failures"]))
            or any(action not in SERVICE_ACTIONS for action in result["service_action_failures"])):

        return False
    if result["status"] != "SCANNED":
        return (result["classes"] == [] and result["msi_error_lines"] == 0
                and result["first_failed_action"] == "NOT_IDENTIFIED"
                and result["service_action_failures"] == [])
    # A targeted fixme category can appear even when err:msi is absent.
    if result["msi_error_lines"] == 0:
        return (result["classes"] in ([], ["MSI_TSAWARE_UNIMPLEMENTED"])
                and result["first_failed_action"] == "NOT_IDENTIFIED"
                and result["service_action_failures"] == [])
    if result["service_action_failures"] and "MSI_ACTION_SERVICE" not in result["classes"]:
        return False
    if result["first_failed_action"] in SERVICE_ACTIONS and (
            result["first_failed_action"] not in result["service_action_failures"]):
        return False
    if result["first_failed_action"] == "FINALIZE_ONLY" and (
            "MSI_ACTION_FINALIZE" not in result["classes"]):
        return False
    return True
