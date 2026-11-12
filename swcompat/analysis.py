"""Conservative classification of Wine diagnostics; never treats 'fixme' as fatal."""
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re

ERROR = re.compile(r"(?:^|\s)err:([\w]+):", re.I)
MISSING = re.compile(r"(?:library|module)\s+([\w.-]+\.dll)\s+(?:not found|failed)", re.I)
EXCEPTION = re.compile(r"(?:unhandled exception|page fault|access violation)", re.I)

@dataclass
class Report:
    lines: int
    errors: Counter
    missing_dlls: Counter
    exceptions: int
    samples: list[str]

def analyze(path: Path) -> Report:
    errors, missing = Counter(), Counter()
    n, exceptions, samples = 0, 0, []
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            n += 1
            error = ERROR.search(line)
            if error:
                errors[error.group(1).lower()] += 1
                if len(samples) < 8:
                    samples.append(line.strip()[:240])
            dll = MISSING.search(line)
            if dll:
                missing[dll.group(1).lower()] += 1
            if EXCEPTION.search(line):
                exceptions += 1
    return Report(n, errors, missing, exceptions, samples)

def recommendations(report: Report) -> list[str]:
    suggestions = []
    if report.missing_dlls:
        suggestions.append("Investigate missing Windows runtime DLLs and their legitimate redistributables.")
    if report.exceptions:
        suggestions.append("Reproduce with WINEDEBUG=+seh,+loaddll and inspect the failing module.")
    if report.errors.get("wgl") or report.errors.get("opengl"):
        suggestions.append("Check OpenGL/WGL context creation and graphics translation.")
    if not suggestions:
        suggestions.append("No recognized fatal Wine events; a passing probe does not prove SOLIDWORKS compatibility.")
    return suggestions
