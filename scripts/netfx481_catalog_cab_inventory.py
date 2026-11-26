"""Inspect the exact failed catalog MSU for Wine WUSA's known delta limitation.

Only official catalog bytes are inspected on the native Windows runner.
No update is installed, no package member is modified, and no raw names,
manifests, package contents or hashes enter the public report.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import tempfile

from scripts.netfx481_catalog_wusa import verify_package
from scripts.netfx481_servicing_inventory import (
    MAX_LISTING, MAX_FILES, _invoke_sevenzip, _safe_embedded,
)


def classify_listing(raw: bytes) -> dict:
    result = {"cix": False, "psf": False, "mum": False,
              "manifest": False, "clr_file": False, "entries": 0, "complete": False}
    if len(raw) > MAX_LISTING:
        return result
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        return result
    # 7-Zip's technical listing includes an archive header Path row;
    # only inspect member rows after the archive header separator.
    members = False
    for line in lines:
        if line == "----------":
            members = True
            continue
        if not members or not line.startswith("Path = "):
            continue
        path = line[7:].replace("\\", "/")
        if len(path) > 1024 or any(ord(c) < 32 for c in path):
            return result
        result["entries"] += 1
        if result["entries"] > MAX_FILES:
            return result
        name = path.rsplit("/", 1)[-1].casefold()
        result["cix"] |= name == "_manifest_.cix.xml"
        result["psf"] |= name.endswith(".psf")
        result["mum"] |= name.endswith(".mum")
        result["manifest"] |= name.endswith(".manifest")
        result["clr_file"] |= name == "clr.dll"
    result["complete"] = members and result["entries"] > 0
    return result


def inspect(package: Path, manifest: Path, sevenzip: Path) -> dict:
    if os.name != "nt" or any(p.is_symlink() for p in (package, manifest, sevenzip)):
        raise ValueError("Native Windows reference only")
    package, manifest, sevenzip = (p.resolve(strict=True) for p in (package, manifest, sevenzip))
    verify_package(package, manifest)
    if sevenzip.name.casefold() not in {"7z.exe", "7za.exe"} or not sevenzip.is_file():
        raise ValueError("Expected native Windows archive reader")
    report = {"catalog_verified": True, "outer_complete": False,
              "nested_complete": False, "cab_count": 0,
              "cix_cabs": 0, "psf_cabs": 0, "mum_cabs": 0,
              "manifest_cabs": 0, "clr_named_cabs": 0,
              "servicing_performed": False}
    with tempfile.TemporaryDirectory(prefix="swcompat-catalog-inventory-") as td:
        root = Path(td)
        state, raw = _invoke_sevenzip(sevenzip, ["l", "-slt", str(package)], root)
        report["outer_complete"] = state == "OK" and classify_listing(raw)["complete"]
        if not report["outer_complete"]:
            return report
        dest = root / "cabs"
        dest.mkdir()
        state, _ = _invoke_sevenzip(sevenzip, ["x", "-y", "-r", "-o" + str(dest),
            str(package), "*.cab"], root, timeout=150)
        if state != "OK":
            return report
        packages, partial = _safe_embedded(dest)
        cabs = [cab for cab in packages if cab.suffix.casefold() == ".cab"]
        report["cab_count"] = len(cabs)
        all_complete = bool(cabs) and not partial
        for cab in cabs:
            state, raw = _invoke_sevenzip(sevenzip, ["l", "-slt", str(cab)], root)
            classified = classify_listing(raw)
            if state != "OK" or not classified["complete"]:
                all_complete = False
                continue
            for key, field in (("cix_cabs", "cix"), ("psf_cabs", "psf"),
                               ("mum_cabs", "mum"), ("manifest_cabs", "manifest"),
                               ("clr_named_cabs", "clr_file")):
                report[key] += int(classified[field])
        report["nested_complete"] = all_complete
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("package", "sha256-file", "sevenzip", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    args = parser.parse_args()
    if args.output.is_symlink():
        parser.error("Linked report forbidden")
    result = inspect(args.package, args.sha256_file, args.sevenzip)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key, value in result.items():
        print("Original catalog package inventory", key, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
