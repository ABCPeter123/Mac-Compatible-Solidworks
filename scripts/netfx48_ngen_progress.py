"""Read-only, bounded progress heartbeat for authentic .NET Framework NGen.

Only metadata about two fixed original .NET 4.x ngen.log files is measured.
No raw Microsoft log text, assembly names, file contents, paths, process
arguments, PIDs, or extra shell commands enter public reports.
"""
from __future__ import annotations

from pathlib import Path

from scripts.netfx48_ngen_log_evidence import _file, _status

MAX_SAMPLES = 24  # 1200-second MSI budget at 60 seconds plus final read
SAMPLE_INTERVAL = 60
STATUSES = {"NOT_RUN", "OBSERVED"}
CHANNEL = {"NOT_RUN", "NO_LOG", "UNCHANGED", "GROWING", "RESET",
           "UNSAFE", "UNREADABLE", "TOO_LARGE"}


def blank() -> dict:
    return {
        "status": "NOT_RUN", "samples": 0,
        "x86_growth_windows": 0, "x64_growth_windows": 0,
        "x86_last": "NOT_RUN", "x64_last": "NOT_RUN",
    }


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if type(report["status"]) is not str or report["status"] not in STATUSES:
        return False
    for name in ("samples", "x86_growth_windows", "x64_growth_windows"):
        if type(report[name]) is not int or not 0 <= report[name] <= MAX_SAMPLES:
            return False
    if (report["x86_growth_windows"] > report["samples"]
            or report["x64_growth_windows"] > report["samples"]):
        return False
    if (any(type(report[key]) is not str for key in ("x86_last", "x64_last"))
            or report["x86_last"] not in CHANNEL
            or report["x64_last"] not in CHANNEL):
        return False
    if report["status"] == "NOT_RUN":
        return report == blank()
    return (report["samples"] >= 1
            and report["x86_last"] != "NOT_RUN"
            and report["x64_last"] != "NOT_RUN")


class NgenProgress:
    """Poll two fixed private log metadata values with no process interaction."""

    def __init__(self, prefix: Path):
        self.prefix = prefix
        self.report = blank()
        self.previous = {}
        for arch in ("X86", "X64"):
            self.previous[arch] = self._stat(arch)

    def _stat(self, arch: str) -> tuple[str, int]:
        if self.prefix.is_symlink() or not self.prefix.is_dir():
            return "UNSAFE", 0
        return _status(_file(self.prefix, arch), self.prefix)

    def sample(self) -> None:
        result = self.report
        if result["samples"] >= MAX_SAMPLES:
            return
        result["status"] = "OBSERVED"
        result["samples"] += 1
        for arch, key in (("X86", "x86"), ("X64", "x64")):
            previous_state, previous_size = self.previous[arch]
            state, current_size = self._stat(arch)
            if state != "CLASSIFIED":
                delta = state
            elif previous_state != "CLASSIFIED":
                delta = "GROWING" if current_size else "UNCHANGED"
            elif current_size > previous_size:
                delta = "GROWING"
            elif current_size < previous_size:
                delta = "RESET"
            else:
                delta = "UNCHANGED"
            if delta == "GROWING":
                result[key + "_growth_windows"] += 1
            result[key + "_last"] = delta
            self.previous[arch] = state, current_size
        assert valid(result)

    def snapshot(self) -> dict:
        return {**self.report}
