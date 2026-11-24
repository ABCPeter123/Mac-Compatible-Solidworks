"""Only fixed, privacy-safe causes from an original Microsoft 4.8 MSI log.

Never copy any raw log line, service arguments, action name, path or vendor
text into a public artifact. A nearby service name is a *hint*, not proof
that its absence caused the reported 0x80070424.
"""
from __future__ import annotations
import re

from scripts.netfx40_msi_evidence import _decode, MAX_FILE_BYTES

MAX_LINE = 8192
CANDIDATES = {
    "BITS": r"BITS",
    "MSISERVER": r"msiserver",
    "TRUSTEDINSTALLER": r"TrustedInstaller",
    "WUAUSERV": r"wuauserv",
    "CLR_OPTIMIZATION_64": r"clr_optimization_v4\.0\.30319_64",
    "CLR_OPTIMIZATION_32": r"clr_optimization_v4\.0\.30319_32",
    "MSDTC": r"MSDTC",
}
SERVICE_CLASSES = set(CANDIDATES)
SERVICE_PATTERNS = {
    code: re.compile(r"(?i)(?<![a-z0-9_])" + pattern + r"(?![a-z0-9_])")
    for code, pattern in CANDIDATES.items()
}
START = re.compile(
    r"(?i)\b(?:Action start\s+\d{1,2}:\d{2}:\d{2}:\s*|"
    r"Doing action:\s*)([a-z][a-z0-9_. -]{0,90})\.?"
)
SERVICE_MISSING = re.compile(r"(?i)\b(?:0x80070424|error\s+1060)\b")
DETAILS = {"NOT_IDENTIFIED", "NGEN", "ASSEMBLY", "SERVICE_CONFIG",
           "REGISTRATION", "OTHER_CUSTOM"}
ARCHES = {"NOT_APPLICABLE", "NOT_IDENTIFIED", "X64", "X86", "AMBIGUOUS"}
NGEN_ARCH = {
    "X64": re.compile(r"(?i)(?<![a-z0-9])(?:x64|amd64)(?![a-z0-9])"),
    "X86": re.compile(r"(?i)(?<![a-z0-9])x86(?![a-z0-9])"),
}
EMPTY = {
    "services_mentioned": [],
    "services_near_missing_error": [],
    "custom_action_detail": "NOT_IDENTIFIED",
    "ngen_custom_action_arch": "NOT_APPLICABLE",
}
# The last action is captured independent of failed return markers. An MSI
# can stall indefinitely without emitting "Return value 3".
DETAIL_RULES = (
    ("NGEN", re.compile(r"(?i)(?:ngen|nativeimage|optimiz)")),
    ("ASSEMBLY", re.compile(r"(?i)(?:assembl|fusion|\bgac\b)")),
    ("SERVICE_CONFIG", re.compile(r"(?i)(?:servic|svcctl)")),
    ("REGISTRATION", re.compile(r"(?i)(?:regsvcs|regasm|regsvr|registr)")),
)


def blank() -> dict:
    return {"services_mentioned": [], "services_near_missing_error": [],
            "custom_action_detail": "NOT_IDENTIFIED",
    "ngen_custom_action_arch": "NOT_APPLICABLE"}


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(EMPTY):
        return False
    if type(report["custom_action_detail"]) is not str or (
            report["custom_action_detail"] not in DETAILS):
        return False
    if (type(report["ngen_custom_action_arch"]) is not str
            or report["ngen_custom_action_arch"] not in ARCHES
            or (report["custom_action_detail"] != "NGEN"
                and report["ngen_custom_action_arch"] != "NOT_APPLICABLE")
            or (report["custom_action_detail"] == "NGEN"
                and report["ngen_custom_action_arch"] == "NOT_APPLICABLE")):
        return False
    for key in ("services_mentioned", "services_near_missing_error"):
        values = report[key]
        if (type(values) is not list
                or any(type(x) is not str or x not in SERVICE_CLASSES for x in values)
                or values != sorted(set(values))):
            return False
    return set(report["services_near_missing_error"]).issubset(
        report["services_mentioned"]
    )


def classify(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_FILE_BYTES:
        return blank()
    decoded = _decode(raw)
    if decoded is None:
        return blank()
    lines = decoded.splitlines()
    # Scan only bounded length lines and keep no private line text in report.
    mentions: set[str] = set()
    near_error: set[str] = set()
    last_custom = "NOT_IDENTIFIED"
    last_ngen_arch = "NOT_APPLICABLE"
    context: list[set[str]] = []
    for line in lines:
        codes = ({code for code, pat in SERVICE_PATTERNS.items()
                  if pat.search(line)} if len(line) <= MAX_LINE else set())
        mentions.update(codes)
        context.append(codes)
        if len(context) > 5:
            context.pop(0)
        if len(line) <= MAX_LINE and SERVICE_MISSING.search(line):
            near_error.update(set().union(*context))
        if len(line) > MAX_LINE:
            continue
        match = START.search(line)
        if match:
            name = match.group(1).strip().rstrip(".")
            if name.casefold().startswith(("ca_", "customaction")):
                last_custom = next(
                    (tag for tag, pat in DETAIL_RULES if pat.search(name)),
                    "OTHER_CUSTOM",
                )
                if last_custom == "NGEN":
                    matched = {arch for arch, pattern in NGEN_ARCH.items()
                               if pattern.search(name)}
                    last_ngen_arch = (next(iter(matched)) if len(matched) == 1
                                      else "AMBIGUOUS" if matched
                                      else "NOT_IDENTIFIED")
                else:
                    last_ngen_arch = "NOT_APPLICABLE"
    report = {
        "services_mentioned": sorted(mentions),
        "services_near_missing_error": sorted(near_error),
        "custom_action_detail": last_custom,
        "ngen_custom_action_arch": last_ngen_arch,
    }
    assert valid(report)
    return report
