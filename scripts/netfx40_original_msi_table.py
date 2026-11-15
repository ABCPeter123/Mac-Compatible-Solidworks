"""Read-only correlation of original Wine MSI failure to extracted Microsoft MSI.

The name of the failed action is transient, never emitted or serialized.
All extracted packages remain on the ephemeral GitHub runner. This experiment
does not install anything, modify MSI bytes, or claim CLR/CAD compatibility.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.netfx40_legacy import verify_media
from scripts.netfx40_offline_extract import (
    EXTRACT_FOLDER, MAX_BYTES, MAX_DEPTH, MAX_DIRS, MAX_FILES,
    MAX_MSIS, MSI_NAME, OLE_SIGNATURE,
)
from scripts.netfx40_private_action import consume
from scripts.msi_original_binary_imports import empty as empty_binary, inspect as inspect_binary, validate as validate_binary
from scripts.msi_custom_action_table_type import inspect as query, validate_detailed as validate_query
from scripts.netfx481_trial import validate_prefix

STATES = {
    "ACTION_FOUND", "ACTION_FOUND_PARTIAL", "ACTION_NOT_CAPTURED", "NO_EXTRACTED_MSI",
    "NOT_FOUND_IN_SCANNED_PACKAGES", "MULTIPLE_MATCHES",
    "QUERY_INCOMPLETE",
}


def blank() -> dict:
    return {"status": "ACTION_NOT_CAPTURED", "msis_queried": 0,
            "action_matches": 0, "family": "NOT_VERIFIED",
            "base_type": None, "execution": "NOT_VERIFIED",
            "impersonation": "NOT_VERIFIED", "asynchronous": "NOT_VERIFIED",
            "ts_aware": False,
            "binary_imports": empty_binary()}


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {
        "status", "msis_queried", "action_matches", "family", "base_type",
        "execution", "impersonation", "asynchronous", "ts_aware", "binary_imports",
    } or result["status"] not in STATES:
        return False
    n, matches = result["msis_queried"], result["action_matches"]
    if (type(result["ts_aware"]) is not bool
            or not validate_binary(result["binary_imports"])):
        return False
    if (result["binary_imports"]["status"] != "NOT_REQUESTED" and
            (result["status"] not in {"ACTION_FOUND", "ACTION_FOUND_PARTIAL"}
             or result["base_type"] != 1)):
        return False
    if type(n) is not int or type(matches) is not int or not 0 <= matches <= n <= MAX_MSIS:
        return False
    if result["status"] in {"ACTION_FOUND", "ACTION_FOUND_PARTIAL"}:
        return (result["execution"] in {"IMMEDIATE", "DEFERRED", "ROLLBACK", "COMMIT"}
                and result["impersonation"] in {"DEFAULT", "NO_IMPERSONATE"}
                and result["asynchronous"] in {"SYNCHRONOUS", "ASYNCHRONOUS"}
                and matches == 1 and type(result["base_type"]) is int
                and 0 <= result["base_type"] <= 63
                and type(result["family"]) is str
                and result["family"] not in {"NOT_VERIFIED", ""})
    if (result["base_type"] is not None or result["family"] != "NOT_VERIFIED"
            or any(result[k] != "NOT_VERIFIED" for k in
                   ("execution", "impersonation", "asynchronous"))
            or result["ts_aware"] is not False):
        return False
    if result["status"] == "ACTION_NOT_CAPTURED":
        return n == 0 and matches == 0
    if result["status"] == "NO_EXTRACTED_MSI":
        return n == 0 and matches == 0
    if result["status"] == "MULTIPLE_MATCHES":
        return matches > 1
    if result["status"] == "NOT_FOUND_IN_SCANNED_PACKAGES":
        return n > 0 and matches == 0
    return True


def _candidates(root: Path) -> tuple[list[Path], bool]:
    if root.is_symlink() or not root.is_dir():
        return [], True
    found: list[Path] = []
    n_dirs = n_files = 0
    incomplete = False
    for base, subdirs, names in os.walk(root, followlinks=False):
        here = Path(base)
        if n_dirs >= MAX_DIRS:
            incomplete = True
            subdirs.clear()
            break
        n_dirs += 1
        if len(here.relative_to(root).parts) >= MAX_DEPTH:
            if subdirs:
                incomplete = True
            subdirs.clear()
        else:
            eligible = sorted(n for n in subdirs if not (here / n).is_symlink())
            if len(eligible) > 16:
                incomplete = True
            subdirs[:] = eligible[:16]
        for name in sorted(names):
            if n_files >= MAX_FILES:
                incomplete = True
                break
            n_files += 1
            if not MSI_NAME.fullmatch(name):
                continue
            candidate = here / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                if not 4096 <= candidate.stat().st_size <= MAX_BYTES:
                    continue
                with candidate.open("rb") as f:
                    if f.read(8) != OLE_SIGNATURE:
                        continue
            except OSError:
                incomplete = True
                continue
            if len(found) >= MAX_MSIS:
                incomplete = True
                break
            found.append(candidate)
        if n_files >= MAX_FILES or len(found) >= MAX_MSIS:
            incomplete = True
            break
    return found, incomplete


def _is_wine_host() -> bool:
    return os.name != "nt"


def inspect(wine: Path, prefix: Path, helper: Path, installer: Path,
            *, binary_helper: Path | None = None) -> dict:
    if not _is_wine_host() or any(p.is_symlink() for p in (wine, prefix, helper, installer)):
        raise ValueError("Original MSI table query runs only on isolated Wine")
    wine, prefix, helper, installer = (
        p.resolve(strict=True) for p in (wine, prefix, helper, installer)
    )
    validate_prefix(prefix)
    verify_media(installer)
    # Consume before scanning, so even unsuccessful attempts delete the name.
    action = consume(prefix)
    if action is None:
        return blank()
    root = prefix / "drive_c" / EXTRACT_FOLDER
    candidates, partial = _candidates(root)
    if not candidates:
        return {**blank(), "status": "QUERY_INCOMPLETE" if partial else "NO_EXTRACTED_MSI"}
    hits: list[dict] = []
    matched_package: Path | None = None
    bad = partial
    for package in candidates:
        result = query(wine, prefix, helper, package, action,
                       allow_original_action=True, detailed=True)
        if not validate_query(result):
            bad = True
        elif result["status"] == "ACTION_FOUND":
            hits.append(result)
            matched_package = package
        elif result["status"] != "ACTION_ABSENT":
            bad = True
    if len(hits) > 1:
        return {**blank(), "status": "MULTIPLE_MATCHES",
                "msis_queried": len(candidates), "action_matches": len(hits)}
    if len(hits) == 1:
        binary = empty_binary()
        if binary_helper is not None and hits[0]["base_type"] == 1:
            assert matched_package is not None
            binary = inspect_binary(wine, prefix, binary_helper, matched_package, action)
            if not validate_binary(binary):
                raise ValueError("Unsafe authenticated MSI Binary census")
        return {"binary_imports": binary, "status": "ACTION_FOUND_PARTIAL" if bad else "ACTION_FOUND", "msis_queried": len(candidates),
                "action_matches": 1, "family": hits[0]["family"],
                "base_type": hits[0]["base_type"],
                "execution": hits[0]["execution"],
                "impersonation": hits[0]["impersonation"],
                "asynchronous": hits[0]["asynchronous"],
                "ts_aware": hits[0]["ts_aware"]}
    return {**blank(), "status": "QUERY_INCOMPLETE" if bad else
            "NOT_FOUND_IN_SCANNED_PACKAGES", "msis_queried": len(candidates),
            "action_matches": len(hits)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Private original Microsoft MSI Type query")
    for field in ("wine", "prefix", "helper", "installer", "output"):
        p.add_argument("--" + field, type=Path, required=True)
    p.add_argument("--agree-disposable-prefix", action="store_true")
    p.add_argument("--binary-helper", type=Path)
    args = p.parse_args(argv)
    if not args.agree_disposable_prefix:
        p.error("Disposable-prefix agreement required")
    result = inspect(args.wine, args.prefix, args.helper, args.installer,
                     binary_helper=args.binary_helper)
    if not validate(result):
        raise ValueError("Unsafe original Microsoft MSI metadata report")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for field in ("status", "msis_queried", "action_matches", "family", "base_type",
                  "execution", "impersonation", "asynchronous", "ts_aware"):
        print("Original Microsoft MSI action table", field, result[field])
    binary = result["binary_imports"]
    print("Original Microsoft deferred DLL import census status", binary["status"])
    print("Original Microsoft deferred DLL import census machine", binary["machine"])
    for family, count in binary["imports"].items():
        print("Original Microsoft deferred DLL imported", family, count)
    for family, count in binary["api_imports"].items():
        print("Original Microsoft deferred DLL Windows API import", family, count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
