"""Read-only local inventory of legitimately obtained SOLIDWORKS installer media.

No execution, network access, registry edits, or uploads. The report excludes
user file paths, unknown file names, raw DLL names and binary contents.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import struct

MAX_FILES = 50000
MAX_DEPTH = 16
PE_READ_LIMIT = 32 * 1024 * 1024

# Published file names from SOLIDWORKS Design 2026 administrative-image docs.
PACKAGE_GROUPS = {
    "vcredist_x64": ("vc_redist.x64.exe",),
    "vcredist_x86": ("vc_redist.x86.exe",),
    "vba71": ("vba71.msi", "vba71_1033.msi"),
    "webview2": ("microsoftedgewebview2runtimeinstallerx64.exe",),
    "swcef": ("cef for solidworks applications.msi",),
    "dotnet481_server": ("ndp481-x86-x64-allos-enu.exe",),
    "wpt": ("wptx64-x86_en-us.msi",),
}

API_FAMILIES = {
    "msi.dll": "windows_installer",
    "ole32.dll": "com_automation", "oleaut32.dll": "com_automation",
    "combase.dll": "com_automation",
    "advapi32.dll": "services_and_registry",
    "sechost.dll": "services_and_registry",
    "mscoree.dll": "managed_runtime", "clr.dll": "managed_runtime",
    "vcruntime140.dll": "c_cpp_runtime",
    "vcruntime140_1.dll": "c_cpp_runtime",
    "msvcp140.dll": "c_cpp_runtime", "ucrtbase.dll": "c_cpp_runtime",
    "winhttp.dll": "networking", "wininet.dll": "networking",
    "ws2_32.dll": "networking",
    "opengl32.dll": "graphics", "d3d11.dll": "graphics",
    "d3d12.dll": "graphics", "dxgi.dll": "graphics",
    "user32.dll": "user_interface", "gdi32.dll": "user_interface",
    "shell32.dll": "shell_integration", "shlwapi.dll": "shell_integration",
    "kernel32.dll": "base_windows_api",
    "kernelbase.dll": "base_windows_api", "ntdll.dll": "base_windows_api",
}


def _u16(data: bytes, position: int) -> int:
    if position < 0 or position + 2 > len(data):
        raise ValueError("Truncated PE header")
    return struct.unpack_from("<H", data, position)[0]


def _u32(data: bytes, position: int) -> int:
    if position < 0 or position + 4 > len(data):
        raise ValueError("Truncated PE header")
    return struct.unpack_from("<I", data, position)[0]


def analyze_pe(path: Path) -> dict:
    """Read bounded PE headers and standard DLL import families only.

    Does not check delay imports, dynamic LoadLibrary calls, or runtime support.
    Unknown import DLL names must never be included in the JSON report.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(PE_READ_LIMIT)
        if len(data) < 64 or data[:2] != b"MZ":
            return {"format": "not_pe"}
        pe = _u32(data, 0x3C)
        if pe > len(data) - 24 or data[pe:pe + 4] != b"PE\x00\x00":
            return {"format": "unrecognized_pe"}
        machine, sections_count = _u16(data, pe + 4), _u16(data, pe + 6)
        opt_size, opt = _u16(data, pe + 20), pe + 24
        end_opt = opt + opt_size
        if sections_count > 96 or end_opt > len(data):
            return {"format": "invalid_pe"}
        magic = _u16(data, opt)
        if magic == 0x20B:
            data_dirs = opt + 112
        elif magic == 0x10B:
            data_dirs = opt + 96
        else:
            return {"format": "unsupported_pe"}
        result = {
            "format": "pe",
            "architecture": {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, "other"),
            "static_import_analysis": "limited",
            "api_families": [],
            "other_imported_dll_count": 0,
        }
        if data_dirs + 16 > end_opt:
            return result
        import_rva, import_size = _u32(data, data_dirs + 8), _u32(data, data_dirs + 12)
        sections = []
        for index in range(sections_count):
            section = end_opt + index * 40
            if section + 40 > len(data):
                return {"format": "invalid_pe"}
            sections.append((_u32(data, section + 12), _u32(data, section + 8),
                             _u32(data, section + 20), _u32(data, section + 16)))

        def offset(rva: int) -> int | None:
            for va, virtual_size, raw, raw_size in sections:
                if va <= rva < va + max(virtual_size, raw_size):
                    delta = rva - va
                    if delta >= raw_size:
                        return None
                    position = raw + delta
                    return position if position < len(data) else None
            return None

        if not import_rva or not import_size:
            return result
        start = offset(import_rva)
        if start is None:
            result["import_table_readable"] = False
            return result
        families = set()
        other = 0
        for i in range(min(512, import_size // 20)):
            desc = start + i * 20
            if desc + 20 > len(data):
                result["import_table_readable"] = False
                break
            if data[desc:desc + 20] == b"\x00" * 20:
                break
            name_offset = offset(_u32(data, desc + 12))
            if name_offset is None:
                other += 1
                continue
            terminator = data.find(b"\x00", name_offset, min(name_offset + 128, len(data)))
            if terminator == -1:
                other += 1
                continue
            name = data[name_offset:terminator].decode("ascii", errors="replace").casefold()
            family = API_FAMILIES.get(name)
            if family:
                families.add(family)
            else:
                other += 1
        result["api_families"] = sorted(families)
        result["other_imported_dll_count"] = other
        result.setdefault("import_table_readable", True)
        return result
    except (OSError, ValueError, struct.error):
        return {"format": "unreadable_or_invalid_pe"}


def inventory(media: Path, *, max_files: int = MAX_FILES) -> dict:
    """Inventory a local installer executable or extracted directory without following symlinks."""
    if max_files < 1:
        raise ValueError("max_files must be positive")
    media = media.expanduser().resolve(strict=True)
    if not media.is_file() and not media.is_dir():
        raise ValueError("Media must be a regular file or directory")
    count, skipped_symlinks = 0, 0
    groups_found: set[str] = set()
    kinds: Counter[str] = Counter()
    root_setup = nested_setup = bootstrapper = incomplete = False
    setup_file: Path | None = None
    one_file = media.is_file()
    queue = [(media, 0)]
    while queue:
        current, depth = queue.pop()
        if current.is_symlink():
            skipped_symlinks += 1
            continue
        if current.is_dir():
            if depth >= MAX_DEPTH:
                incomplete = True
                continue
            try:
                children = sorted(current.iterdir(), key=lambda p: p.name.casefold(), reverse=True)
            except OSError:
                incomplete = True
                continue
            queue.extend((child, depth + 1) for child in children)
            continue
        if not current.is_file():
            continue
        if count >= max_files:
            incomplete = True
            break
        count += 1
        extension = current.suffix.casefold()
        kinds[extension if extension in (".exe", ".dll", ".msi", ".cab", ".xml", ".zip")
              else "other"] += 1
        name = current.name.casefold()
        for component, filenames in PACKAGE_GROUPS.items():
            if name in filenames:
                groups_found.add(component)
        if name == "setup.exe":
            if one_file or current.parent == media:
                root_setup, setup_file = True, current
            else:
                nested_setup = True
                if setup_file is None:
                    setup_file = current
        elif name == "solidworkssetup.exe":
            bootstrapper = True
            if setup_file is None:
                setup_file = current
    return {
        "schema": 1,
        "reference_product": "SOLIDWORKS Design 2026",
        "input_kind": "single_file" if one_file else "directory",
        "files_examined": count,
        "extension_counts": dict(sorted(kinds.items())),
        "scan_incomplete": incomplete,
        "symlinks_skipped": skipped_symlinks,
        "entrypoints": {
            "root_setup_observed": root_setup,
            "nested_setup_observed": nested_setup,
            "bootstrapper_observed": bootstrapper,
        },
        "package_indicators": {
            component: {"observed": component in groups_found,
                        "expected_public_filenames": list(filenames)}
            for component, filenames in PACKAGE_GROUPS.items()
        },
        "entrypoint_pe": analyze_pe(setup_file) if setup_file else {"format": "not_observed"},
        "interpretation": [
            "Read-only local media inventory; no SOLIDWORKS installation or compatibility test.",
            "Unobserved files might be downloaded later or omitted from partial media.",
            "Use SOLIDWORKS Installation Manager; do not manually install component MSI files.",
            "PE imports are limited static indicators, not complete Windows API requirements.",
            "Report excludes paths, unknown file names, binary contents and licensing data.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline SOLIDWORKS media inventory, no execution")
    parser.add_argument("--media", type=Path, required=True,
                        help="Authorized local setup EXE or extracted installer directory")
    parser.add_argument("--output", type=Path, required=True, help="Sanitized JSON report")
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    args = parser.parse_args(argv)
    try:
        source = args.media.expanduser().resolve(strict=True)
        output = args.output.expanduser().resolve(strict=False)
        if source.is_dir() and (output == source or source in output.parents):
            parser.error("Report output must be outside the read-only installation media directory")
        if source.is_file() and output == source:
            parser.error("Report output cannot overwrite installation media")
        report = inventory(source, max_files=args.max_files)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("SOLIDWORKS media preflight: completed (no installation attempted)")
    print("Files examined:", report["files_examined"])
    print("Root setup.exe observed:", report["entrypoints"]["root_setup_observed"])
    print("Scan incomplete:", report["scan_incomplete"])
    print("Sanitized report:", output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
