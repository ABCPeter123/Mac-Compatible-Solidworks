"""Strict acceptance for the exact KB5011048 CIX payload.

Reference: native Windows Expand, CI run 45848826050. All 2446 files
were independently matched there; Apple Silicon yielded this same tree.
No filenames, executable bytes, or installer media are embedded here.
"""
import argparse
import json
from pathlib import Path

EXPECTED_TREE_SHA256 = "2f492b8e9cded7ca527860190fc7b6caa9ac25f86ebd6d521efd0dcaa429010b"
EXPECTED_COUNT = 2446


def require_complete(report: dict, *, windows_oracle: bool = False) -> None:
    if report.get("catalog_verified") is not True or report.get("ipd_cabs") != 1:
        raise ValueError("Original IPD cabinet not verified")
    for key in ("cix_entries", "cix_reconstructed"):
        if type(report.get(key)) is not int or report[key] != EXPECTED_COUNT:
            raise ValueError("Incomplete CIX reconstruction: " + key)
    for key in ("cix_delta_failed", "cix_basis_blocked", "cix_unresolved",
                "cix_unsupported", "cix_missing_source", "cix_size_mismatch",
                "cix_oracle_mismatches", "cix_oracle_missing"):
        if type(report.get(key)) is not int or report[key] != 0:
            raise ValueError("CIX acceptance failure: " + key)
    if report.get("cix_tree_sha256") != EXPECTED_TREE_SHA256:
        raise ValueError("Reconstructed tree differs from independent Windows reference")
    if windows_oracle and (report.get("oracle_available") is not True
                           or report.get("cix_oracle_matches") != EXPECTED_COUNT):
        raise ValueError("Missing complete native Windows comparison")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--windows-oracle", action="store_true")
    args = parser.parse_args()
    require_complete(json.loads(args.report.read_text(encoding="ascii")),
                     windows_oracle=args.windows_oracle)
    print("Verified 2446/2446 reconstructed CIX files against independent Windows tree digest")
