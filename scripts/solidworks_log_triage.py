"""Offline bounded classifier for SOLIDWORKS Installation Manager log files.

Never prints arbitrary log text, paths, serials, emails, UUIDs, or unknown codes.
Input: local .log/.txt, IM_Logs.zip, or an existing directory.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import zipfile

MAX_FILES = 300
MAX_LOG_BYTES = 3 * 1024 * 1024
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_DEPTH = 12
ALLOWED_EXT = {".txt", ".log"}

# Output identifiers are all fixed public diagnostic categories.
CODE_RULES = {
    "0x80040154": "com_class_not_registered",
    "0x80070005": "access_denied",
    "0x80070002": "file_not_found",
    "0x8007007e": "module_not_found",
    "0x80070424": "service_not_found",
    "0x80070422": "service_disabled",
    "0x80070643": "windows_installer_failure",
    "0x80004005": "generic_failure",
}
PATTERNS = {
    "msi_fatal_1603": re.compile(
        r"\b(?:error\s*1603|return(?:ing|ed)?\s*(?:code\s*)?1603|MainEngineThread\s+is\s+returning\s+1603)\b", re.I),
    "msi_busy_1618": re.compile(
        r"\b(?:error\s*1618|return(?:ing|ed)?\s*(?:code\s*)?1618)\b", re.I),
    "msi_package_unavailable_1619": re.compile(
        r"\b(?:error\s*1619|return(?:ing|ed)?\s*(?:code\s*)?1619)\b", re.I),
    "msi_action_failure": re.compile(r"\breturn\s+value\s+3\b", re.I),
    "installation_cancelled": re.compile(
        r"\binstall(?:ation)?\s+(?:was\s+)?cancelled\b|"
        r"\binstall(?:ation)?\s+(?:was\s+)?canceled\b", re.I),
    "com_class_not_registered": re.compile(r"\bclass\s+not\s+registered\b", re.I),
    "service_not_found": re.compile(r"\bservice\s+does\s+not\s+exist\b", re.I),
    "dotnet_runtime_error": re.compile(
        r"(?:\.net\s+framework|mscoree\.dll|clr\s+initialization).{0,130}"
        r"\b(?:failed|error|missing|not\s+found)\b", re.I),
    "vc_runtime_error": re.compile(
        r"(?:vcruntime140(?:_1)?\.dll|msvcp140\.dll).{0,130}"
        r"\b(?:failed|error|missing|not\s+found)\b", re.I),
    "webview2_error": re.compile(
        r"(?:webview2|microsoftedgewebview2).{0,130}"
        r"\b(?:failed|error|missing|not\s+found)\b", re.I),
}
HEX_CODE = re.compile(r"(?<![0-9a-f])0x[0-9a-f]{8}(?![0-9a-f])", re.I)


def classify(text: str) -> Counter:
    """Emit allowlisted public category IDs, never log text or arbitrary values."""
    categories: Counter[str] = Counter()
    for line in text.splitlines():
        line = line[:4096]
        for match in HEX_CODE.finditer(line):
            category = CODE_RULES.get(match.group(0).lower())
            if category:
                categories[category] += 1
        for name, expression in PATTERNS.items():
            if expression.search(line):
                categories[name] += 1
    return categories


def decode_log(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def analyze(source: Path) -> dict:
    """Read a log, directory or ZIP in memory. No ZIP extraction or execution."""
    source = source.expanduser().resolve(strict=True)
    if not source.is_file() and not source.is_dir():
        raise ValueError("Logs must be a regular file or directory")
    total = 0
    counts: Counter[str] = Counter()
    files = 0
    truncated = False
    zipped = 0
    invalid_zip = False
    skipped_symlinks = 0

    def process(data: bytes) -> None:
        nonlocal total, files, truncated
        if files >= MAX_FILES or total >= MAX_TOTAL_BYTES:
            truncated = True
            return
        limit = min(MAX_LOG_BYTES, MAX_TOTAL_BYTES - total)
        if len(data) > limit:
            truncated = True
            data = data[:limit]
        files += 1
        total += len(data)
        counts.update(classify(decode_log(data)))

    def process_zip(path: Path) -> None:
        nonlocal zipped, truncated, invalid_zip
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.is_dir() or Path(info.filename).suffix.casefold() not in ALLOWED_EXT:
                        continue
                    if files >= MAX_FILES or total >= MAX_TOTAL_BYTES:
                        truncated = True
                        break
                    zipped += 1
                    with archive.open(info) as reader:
                        process(reader.read(min(MAX_LOG_BYTES, MAX_TOTAL_BYTES - total) + 1))
        except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
            invalid_zip = True

    entries: list[tuple[Path, int]] = [(source, 0)]
    while entries:
        item, depth = entries.pop()
        if item.is_symlink():
            skipped_symlinks += 1
            continue
        if item.is_dir():
            if depth >= MAX_DEPTH:
                truncated = True
                continue
            try:
                children = sorted(item.iterdir(), key=lambda p: p.name.casefold(), reverse=True)
            except OSError:
                truncated = True
                continue
            entries.extend((child, depth + 1) for child in children)
            continue
        if not item.is_file():
            continue
        ext = item.suffix.casefold()
        if ext in ALLOWED_EXT:
            try:
                with item.open("rb") as stream:
                    process(stream.read(min(MAX_LOG_BYTES, MAX_TOTAL_BYTES - total) + 1))
            except OSError:
                truncated = True
        elif ext == ".zip":
            process_zip(item)
        elif item == source:
            raise ValueError("Supported input: .txt, .log, .zip or directory")

    return {
        "schema": 1,
        "input_type": "directory" if source.is_dir() else "local_file",
        "log_files_examined": files,
        "zip_members_examined": zipped,
        "bytes_examined": total,
        "scan_incomplete": truncated,
        "invalid_zip_encountered": invalid_zip,
        "symlinks_skipped": skipped_symlinks,
        "potential_issue_counts": dict(sorted(counts.items())),
        "no_recognized_indicators": not bool(counts),
        "interpretation": (
            "Allowlisted patterns are diagnostic indicators, not validated causes. "
            "No unknown error codes, raw log lines, file paths, filenames, "
            "serial numbers, email addresses, or license tokens are exported."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline sanitized SOLIDWORKS Installation Manager log triage")
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        source = args.logs.expanduser().resolve(strict=True)
        output = args.output.expanduser().resolve(strict=False)
        if (source.is_dir() and (output == source or source in output.parents)) or output == source:
            parser.error("Report output must be outside the source logs")
        report = analyze(source)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("SOLIDWORKS log triage: completed locally")
    print("Files examined:", report["log_files_examined"])
    print("Potential issue categories:", len(report["potential_issue_counts"]))
    print("Sanitized report:", output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
