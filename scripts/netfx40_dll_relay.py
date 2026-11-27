"""Private bounded Wine relay return-code census within native MSI DLL calls.

Public Win32 API names and numeric return classes only. No arguments,
private paths, handles, thread identifiers, vendor names or raw traces
are serialized. A failed DLL scope is evidence, not causal attribution.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re

from scripts.netfx40_msi_logging_policy import _reg
from scripts.netfx481_trial import validate_prefix

ENTRY = "__wine_msi_call_dll_function"
STATUS_APIS = (
    "RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW",
    "RegGetValueA", "RegGetValueW", "RegDeleteKeyA", "RegDeleteKeyW",
    "MsiGetPropertyA", "MsiGetPropertyW", "MsiSetPropertyA", "MsiSetPropertyW",
)
HANDLE_APIS = (
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
    "OpenSCManagerA", "OpenSCManagerW", "OpenServiceA", "OpenServiceW",
    "CreateServiceA", "CreateServiceW",
)
BOOL_APIS = (
    "StartServiceA", "StartServiceW", "ControlService", "DeleteService",
    "QueryServiceStatus", "QueryServiceStatusEx", "ChangeServiceConfigA",
    "ChangeServiceConfigW", "ChangeServiceConfig2A", "ChangeServiceConfig2W",
)
APIS = STATUS_APIS + HANDLE_APIS + BOOL_APIS
KEY = r"HKCU\Software\Wine\Debug"
VALUE = ";".join((ENTRY,) + APIS)
LINE = re.compile(rb"^((?:[0-9a-fA-F]{4,8}:){1,2})(?:trace:relay:)?\s*(Call|Ret)\s+[A-Za-z0-9_.-]+\.([A-Za-z_][A-Za-z0-9_]{0,80})\(")
RETURN = re.compile(rb"\)\s+retval=([0-9a-fA-F]{1,16})(?:\s|$)")
MAX_SCOPES = 256
MAX_EVENTS = 65536


class Capture:
    def __init__(self):
        self.active = {}
        self.failed = Counter()
        self.completed = 0
        self.failed_scopes = 0
        self.events = 0
        self.truncated = False

    def feed(self, line):
        event = LINE.match(line)
        if not event:
            return
        tid, verb, raw = event.groups()
        name = raw.decode("ascii")
        if name != ENTRY and name not in APIS:
            return
        if self.truncated or (name != ENTRY and tid not in self.active):
            return
        self.events += 1
        if self.events > MAX_EVENTS:
            self.truncated = True
            return
        if verb == b"Call":
            if name == ENTRY:
                if tid in self.active or len(self.active) >= MAX_SCOPES:
                    self.truncated = True
                    return
                self.active[tid] = Counter()
            return
        if tid not in self.active:
            if name == ENTRY:
                self.truncated = True
            return
        value = RETURN.search(line, event.end()-1)
        if not value:
            self.truncated = True
            return
        code = int(value.group(1), 16)
        if name == ENTRY:
            counts = self.active.pop(tid)
            self.completed += 1
            if code == 1603:
                self.failed_scopes += 1
                self.failed.update(counts)
        else:
            # Handles and BOOL return zero on failure; LSTATUS/UINT use
            # zero for success. Raw nonzero handles are never recorded.
            failed = (code != 0) if name in STATUS_APIS else (code == 0)
            self.active[tid][(name, "failure" if failed else "success")] += 1

    def report(self, complete):
        usable = complete and not self.truncated and not self.active
        status = ("INCOMPLETE" if not usable else
                  "FAILED_DLL_SCOPE_OBSERVED" if self.failed_scopes else
                  "NO_FAILED_DLL_SCOPE" if self.completed else "NO_DLL_SCOPE")
        return {"schema": 1, "status": status,
                "completed_scopes": self.completed,
                "failed_scopes": self.failed_scopes,
                "failed_scope_api_returns": {
                    name: {kind: self.failed[(name, kind)] for kind in ("success", "failure")}
                    for name in APIS if usable and any(self.failed[(name, kind)]
                        for kind in ("success", "failure"))},
                "causality": "NOT_ESTABLISHED"}


def apply(wine, prefix):
    validate_prefix(prefix)
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if os.name == "nt" or prefix.is_symlink() or prefix.resolve() != root / "netfx40-msxml3-prefix":
        raise ValueError("Relay diagnostics require isolated CI Wine")
    code, _ = _reg(wine, prefix, ["query", KEY, "/v", "RelayInclude"])
    if code != 1:
        raise ValueError("Cannot establish absent relay filter")
    code, _ = _reg(wine, prefix, ["add", KEY, "/v", "RelayInclude",
                                  "/t", "REG_SZ", "/d", VALUE, "/f"])
    if code != 0:
        raise ValueError("Cannot set bounded relay filter")
    code, raw = _reg(wine, prefix, ["query", KEY, "/v", "RelayInclude"])
    if code != 0 or VALUE.encode("ascii") not in raw:
        restore(wine, prefix)
        raise ValueError("Cannot verify bounded relay filter")


def restore(wine, prefix):
    code, _ = _reg(wine, prefix, ["delete", KEY, "/v", "RelayInclude", "/f"])
    checked, _ = _reg(wine, prefix, ["query", KEY, "/v", "RelayInclude"])
    if code != 0 or checked != 1:
        raise ValueError("Cannot restore relay filter")


def write_report(output, capture, complete):
    if output.is_symlink() or output.exists():
        raise ValueError("Relay report must be fresh")
    report = capture.report(complete)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="ascii")
    print("Original CLR4 failed DLL relay census " + json.dumps(report, sort_keys=True))
