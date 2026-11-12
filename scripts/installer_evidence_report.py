"""Correlate sanitized installer-media and log-triage reports without raw media.

Inputs must be outputs of the local offline scanners. Never emits source paths,
unknown source fields, log lines, binary names, or identifying information.
This is a triage aid, not proof of SOLIDWORKS installation or compatibility.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MAX_REPORT_BYTES = 1024 * 1024
MAX_COUNTER = 10_000_000

# These values are controlled by our existing log scanner, not by raw logs.
# Keep in sync when its allowlist changes. Unknown identifiers are rejected.
ISSUE_ACTIONS = {
    "com_class_not_registered": "inspect_com_registration",
    "service_not_found": "inspect_service_registration",
    "service_disabled": "inspect_service_registration",
    "dotnet_runtime_error": "inspect_managed_runtime",
    "vc_runtime_error": "inspect_visual_cpp_runtime",
    "webview2_error": "inspect_webview2_runtime",
    "module_not_found": "inspect_module_dependencies",
    "file_not_found": "inspect_media_completeness",
    "msi_package_unavailable_1619": "inspect_media_completeness",
    "msi_busy_1618": "resolve_installer_concurrency",
    "msi_action_failure": "inspect_msi_failure",
    "msi_fatal_1603": "inspect_msi_failure",
    "windows_installer_failure": "inspect_msi_failure",
    "access_denied": "inspect_install_permissions",
    "installation_cancelled": "inspect_cancelled_install",
    "generic_failure": "inspect_generic_failure",
}

# Fixed public diagnostic guidance. No untrusted text is copied to the output.
GUIDANCE = {
    "run_media_preflight": "Scan authorized local SOLIDWORKS installer media with installer_media_preflight.",
    "verify_complete_installer": "Locate complete official installation media; a bootstrapper or nested setup alone does not establish completeness.",
    "review_media_scan_limits": "Review media inventory limits and rerun the local scan if needed.",
    "collect_installer_logs": "After a licensed, controlled installer attempt, run the local IM_Logs triage utility.",
    "recollect_damaged_logs": "Regenerate the Installation Manager log archive if its ZIP could not be read.",
    "review_log_scan_limits": "Review log scan limits locally; a partial scan may omit relevant errors.",
    "inspect_com_registration": "Investigate COM registration and cross-process activation for the failing installer component.",
    "inspect_service_registration": "Check service registration, startup and cross-process visibility; Wine SCM tests cover only narrow scenarios.",
    "inspect_managed_runtime": "Validate the actual required .NET Framework APIs; Wine Mono execution does not establish .NET 4.8.1 compatibility.",
    "inspect_visual_cpp_runtime": "Check the relevant architecture and installed MSVC redistributable runtime dependencies.",
    "inspect_webview2_runtime": "Check WebView2 runtime presence and functional initialization in the target Wine prefix.",
    "inspect_module_dependencies": "Inspect imported and delay-loaded modules locally; a missing module is not necessarily an installer defect.",
    "inspect_media_completeness": "Check that the official Installation Manager has the packages it expects; do not manually install component MSIs.",
    "resolve_installer_concurrency": "Check for another active Windows Installer transaction before retrying.",
    "inspect_msi_failure": "MSI 1603 and Return Value 3 are generic indicators; inspect the originating custom action locally.",
    "inspect_install_permissions": "Review the failing operation's local filesystem or registry access permissions.",
    "inspect_cancelled_install": "Determine locally whether installation was intentionally cancelled.",
    "inspect_generic_failure": "A generic error code cannot identify the failing subsystem without further local evidence.",
}

# Order puts evidence acquisition first, then targeted blocker investigations.
ACTION_ORDER = tuple(GUIDANCE)


def _boolean(data: dict, key: str) -> bool:
    value = data.get(key)
    if type(value) is not bool:
        raise ValueError("Invalid sanitized report structure")
    return value


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise ValueError("Invalid sanitized report counter")
    return value


def _report(path: Path, expected: str) -> dict:
    # Reject oversized data before parsing. Never print input content or paths.
    with path.open("rb") as stream:
        payload = stream.read(MAX_REPORT_BYTES + 1)
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("Sanitized report exceeds input limit")
    try:
        parsed = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid sanitized JSON report") from exc
    if not isinstance(parsed, dict) or type(parsed.get("schema")) is not int or parsed["schema"] != 1:
        raise ValueError("Unsupported sanitized report schema")
    expected_keys = {"media": ("entrypoints", "files_examined"),
                     "logs": ("potential_issue_counts", "log_files_examined")}
    if not all(key in parsed for key in expected_keys[expected]):
        raise ValueError("Wrong sanitized report type")
    return parsed


def correlate(media: dict | None = None, logs: dict | None = None) -> dict:
    """Produce only fixed diagnostic IDs, fixed text, numeric counts, and booleans."""
    if media is None and logs is None:
        raise ValueError("At least one sanitized report is required")

    actions: set[str] = set()
    media_status = "not_provided"
    media_files = None
    observed_packages = None
    if media is None:
        actions.add("run_media_preflight")
    else:
        if media.get("schema") != 1 or media.get("input_kind") not in ("single_file", "directory"):
            raise ValueError("Invalid sanitized media report")
        media_files = _count(media.get("files_examined"))
        entries = media.get("entrypoints")
        if not isinstance(entries, dict):
            raise ValueError("Invalid sanitized media report")
        root = _boolean(entries, "root_setup_observed")
        nested = _boolean(entries, "nested_setup_observed")
        bootstrapper = _boolean(entries, "bootstrapper_observed")
        incomplete = _boolean(media, "scan_incomplete")
        packages = media.get("package_indicators")
        if not isinstance(packages, dict):
            raise ValueError("Invalid sanitized media report")
        # Aggregate a count rather than echoing package keys or vendor filenames.
        for indicator in packages.values():
            if not isinstance(indicator, dict):
                raise ValueError("Invalid sanitized media report")
            _boolean(indicator, "observed")
        observed_packages = sum(indicator["observed"] for indicator in packages.values())
        if root and media["input_kind"] == "directory":
            media_status = "root_setup_observed"
        elif root and media["input_kind"] == "single_file":
            media_status = "single_setup_executable"
        elif nested:
            media_status = "nested_setup_only"
        elif bootstrapper:
            media_status = "bootstrapper_only"
        else:
            media_status = "no_setup_entrypoint_observed"
        if media_status != "root_setup_observed":
            actions.add("verify_complete_installer")
        if incomplete:
            actions.add("review_media_scan_limits")

    issue_counts = {}
    logs_status = "not_provided"
    logs_examined = None
    if logs is None:
        actions.add("collect_installer_logs")
    else:
        if logs.get("schema") != 1:
            raise ValueError("Invalid sanitized log report")
        logs_examined = _count(logs.get("log_files_examined"))
        truncated = _boolean(logs, "scan_incomplete")
        invalid_zip = _boolean(logs, "invalid_zip_encountered")
        raw_counts = logs.get("potential_issue_counts")
        if not isinstance(raw_counts, dict) or any(key not in ISSUE_ACTIONS for key in raw_counts):
            raise ValueError("Unsupported diagnostic identifier in sanitized log report")
        issue_counts = {key: _count(value) for key, value in sorted(raw_counts.items()) if _count(value)}
        logs_status = "indicators_found" if issue_counts else "no_recognized_indicators"
        if truncated:
            actions.add("review_log_scan_limits")
        if invalid_zip:
            actions.add("recollect_damaged_logs")
        for key in issue_counts:
            actions.add(ISSUE_ACTIONS[key])

    return {
        "schema": 1,
        "reference_product": "SOLIDWORKS Design 2026",
        "installation_and_cad_compatibility": "NOT_DEMONSTRATED",
        "media": {"status": media_status, "files_examined": media_files,
                  "public_package_groups_observed": observed_packages},
        "logs": {"status": logs_status, "files_examined": logs_examined,
                 "potential_issue_counts": issue_counts},
        "recommended_next_actions": [
            {"id": key, "guidance": GUIDANCE[key]} for key in ACTION_ORDER if key in actions
        ],
        "interpretation": (
            "Evidence is limited to offline inventories and allowlisted log indicators. "
            "These signals do not establish root causes, installer success, license status, "
            "or SOLIDWORKS CAD compatibility."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline sanitized SOLIDWORKS installer evidence correlation")
    parser.add_argument("--media-report", type=Path)
    parser.add_argument("--log-report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.media_report and not args.log_report:
        parser.error("Provide --media-report or --log-report")
    try:
        inputs = [p.expanduser().resolve(strict=True) for p in (args.media_report, args.log_report) if p]
        output = args.output.expanduser().resolve(strict=False)
        if output in inputs:
            raise ValueError("Output cannot overwrite an input report")
        media = _report(args.media_report.expanduser(), "media") if args.media_report else None
        logs = _report(args.log_report.expanduser(), "logs") if args.log_report else None
        report = correlate(media, logs)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        # Do not embed arbitrary error messages from filesystem operations.
        parser.error(str(exc) if isinstance(exc, ValueError) else "Cannot read or write a report")
    print("SOLIDWORKS installer evidence correlation complete")
    print("Installer/CAD compatibility: NOT_DEMONSTRATED")
    print("Recommended actions:", len(report["recommended_next_actions"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
