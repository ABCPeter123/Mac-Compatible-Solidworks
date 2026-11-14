"""Read-only direct CBS registry/file inventory of a marked Wine prefix.

This avoids a Windows executable loader dependency when examining whether Wine
provides foundational Windows servicing components. The probe uses only
fixed registry keys, does not read values, and does not run DISM/servicing.
Never publish the real Wine prefix path or any raw registry output.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

RESULTS = {"PRESENT", "ABSENT", "UNAVAILABLE"}
FILE_RESULTS = {"PE_FILE", "NON_PE_FILE", "LINKED", "ABSENT", "UNAVAILABLE"}
CBS_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
SERVICE_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller"


def _reg(wine: Path, prefix: Path, key: str) -> str:
    from scripts.netfx481_trial import reg_code
    if key not in {CBS_KEY, SERVICE_KEY}:
        raise ValueError("Unsupported registry observation")
    code = reg_code(wine, prefix, "query", key)
    return "PRESENT" if code == 0 else "ABSENT" if code == 1 else "UNAVAILABLE"


def _directory(prefix: Path) -> str:
    path = prefix / "drive_c" / "windows"
    for segment in ("servicing", "Packages"):
        path = path / segment
        if path.is_symlink():
            return "UNAVAILABLE"
    if path.is_symlink():
        return "UNAVAILABLE"
    return "PRESENT" if path.is_dir() else "ABSENT"


def _dism(prefix: Path) -> str:
    path = prefix / "drive_c" / "windows" / "system32"
    if path.is_symlink():
        return "UNAVAILABLE"
    path = path / "dismapi.dll"
    if path.is_symlink():
        return "LINKED"
    if not path.exists():
        return "ABSENT"
    if not path.is_file():
        return "UNAVAILABLE"
    try:
        with path.open("rb") as source:
            header = source.read(8192)
    except OSError:
        return "UNAVAILABLE"
    from scripts.netfx481_payload_audit import pe_type
    return "NON_PE_FILE" if pe_type(header) == "NOT_PE" else "PE_FILE"


def inspect(wine: Path, prefix: Path) -> dict:
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    if wine.is_symlink() or not wine.is_file():
        raise ValueError("Invalid scoped Wine command")
    report = {
        "scope": "MARKED_DISPOSABLE_WINE_PREFIX",
        "cbs_registry": _reg(wine, prefix, CBS_KEY),
        "packages_directory": _directory(prefix),
        "trustedinstaller_service_registration": _reg(wine, prefix, SERVICE_KEY),
        "dismapi_disk_file": _dism(prefix),
    }
    if not validate(report):
        raise ValueError("Unsafe servicing inventory")
    return report


def validate(report: dict) -> bool:
    return (
        isinstance(report, dict)
        and set(report) == {
            "scope", "cbs_registry", "packages_directory",
            "trustedinstaller_service_registration", "dismapi_disk_file",
        }
        and report["scope"] == "MARKED_DISPOSABLE_WINE_PREFIX"
        and report["cbs_registry"] in RESULTS
        and report["packages_directory"] in RESULTS
        and report["trustedinstaller_service_registration"] in RESULTS
        and report["dismapi_disk_file"] in FILE_RESULTS
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only Windows servicing inventory in disposable Wine")
    ap.add_argument("--wine", type=Path, required=True)
    ap.add_argument("--prefix", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    if any(path.is_symlink() for path in (args.wine, args.prefix, args.output)):
        ap.error("Linked paths forbidden")
    if args.output.resolve() in {args.wine.resolve(), args.prefix.resolve()}:
        ap.error("Output cannot overwrite scoped inputs")
    result = inspect(args.wine, args.prefix)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for key in ("cbs_registry", "packages_directory",
                "trustedinstaller_service_registration", "dismapi_disk_file"):
        print("Read-only Wine servicing inventory", key, result[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
