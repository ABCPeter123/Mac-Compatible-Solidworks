"""Read-only audit of exact KB5011048 staged manifests against Wine WUSA.

This is an independent host-side classifier, not a CBS installer. It reports
only aggregate counts and known manifest feature names, never payloads,
registry values, arbitrary XML strings, or private paths.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from scripts.netfx481_ipd_stage import inventory, digest_tree
from scripts.netfx481_native_delta_gate import EXPECTED_COUNT, EXPECTED_TREE_SHA256

MAX_XML = 16 * 1024 * 1024
MAX_ELEMENTS = 200000
IDENTITY_KEYS = ("name", "processorArchitecture", "language", "publicKeyToken", "version")
KNOWN_ROOT_TAGS = {"assemblyIdentity", "dependency", "package", "file", "registryKeys",
                   "trustInfo", "configuration", "deployment", "asmv3", "description",
                   "serviceData", "directories", "security", "memberships", "instrumentation",
                   "migration", "COM", "comClass", "fileAssociation", "tasks",
                   "categoryMembership", "categoryInstance", "events", "customInformation"}
WUSA_EXPRESSIONS = {
    "runtime.system32", "runtime.drivers", "runtime.wbem", "runtime.windows",
    "runtime.inf", "runtime.programfiles", "runtime.commonfiles", "runtime.syswow64",
    "runtime.programfilesx86", "runtime.commonfilesx86", "runtime.programdata",
    "runtime.fonts",
}
REG_TYPES = {"REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_DWORD", "REG_BINARY"}


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].split(":")[-1]


def children(node, name):
    return [x for x in node if local(x.tag) == name]


def parse_xml(path: Path):
    if path.stat().st_size > MAX_XML:
        return "oversized", None
    raw = path.read_bytes()
    if raw.startswith(b"DCM\x01"):
        return "dcm", None
    sanitized = raw.replace(b"\0", b"").upper()
    if b"<!DOCTYPE" in sanitized or b"<!ENTITY" in sanitized:
        return "unsafe_xml", None
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        return "non_xml", None
    if sum(1 for _ in root.iter()) > MAX_ELEMENTS:
        return "oversized", None
    return "xml", root


def identity(node):
    if node is None:
        return None
    fields = tuple(node.get(k) for k in IDENTITY_KEYS)
    return tuple(v.casefold() for v in fields) if all(fields) else None


def compatible(candidate, needed, *, version=True):
    return (candidate[0] == needed[0]
            and all(a == b or "*" in (a, b) for a, b in zip(candidate[1:4], needed[1:4]))
            and (not version or candidate[4] == needed[4] or "*" in (candidate[4], needed[4])))


@dataclass
class Assembly:
    identity: tuple[str, ...]
    deps: list[tuple[str, ...]]


def audit_members(members: dict[str, Path]) -> dict:
    counts = Counter()
    features = Counter()
    assemblies = []
    index = defaultdict(list)
    for name, path in sorted(members.items()):
        if "/" in name or not name.endswith((".manifest", ".mum")):
            continue
        counts["root_documents"] += 1
        kind, root = parse_xml(path)
        counts[kind] += 1
        if root is None:
            continue
        if local(root.tag) != "assembly":
            counts["unexpected_root"] += 1
            continue
        top = children(root, "assemblyIdentity")
        ident = identity(top[0]) if len(top) == 1 else None
        if ident is None:
            counts["incomplete_identity"] += 1
            continue
        record = Assembly(ident, [])
        assemblies.append(record)
        index[ident[0]].append(record)
        counts["complete_identity"] += 1
        parent = name.rsplit(".", 1)[0]
        for element in root:
            tag = local(element.tag)
            features[tag if tag in KNOWN_ROOT_TAGS else "other"] += 1
            if tag == "dependency":
                for dep in children(element, "dependentAssembly"):
                    counts["assembly_dependencies"] += 1
                    if dep.get("dependencyType") not in (None, "install", "prerequisite"):
                        counts["unsupported_dependency_type"] += 1
                    ids = [n for n in dep.iter() if local(n.tag) == "assemblyIdentity"]
                    ref = identity(ids[0]) if ids else None
                    if ref is None:
                        counts["incomplete_dependency_identity"] += 1
                    else:
                        record.deps.append(ref)
            if tag == "package":
                for update in children(element, "update"):
                    for item in update:
                        if local(item.tag) not in ("component", "package", "applicable"):
                            counts["unsupported_update_child"] += 1
                        if local(item.tag) not in ("component", "package"):
                            continue
                        for child in children(item, "assemblyIdentity"):
                            counts["package_dependencies"] += 1
                            ref = identity(child)
                            if ref is None:
                                counts["incomplete_dependency_identity"] += 1
                            else:
                                record.deps.append(ref)
            if tag == "file":
                counts["file_operations"] += 1
                source = element.get("sourceName")
                target = element.get("destinationPath")
                if not source:
                    counts["missing_source_name"] += 1
                else:
                    key = (parent + "/" + source.replace("\\", "/")).casefold()
                    if key not in members:
                        counts["missing_wusa_source"] += 1
                if not target:
                    counts["missing_destination_path"] += 1
                else:
                    for expr in re.findall(r"\$\(([^)]+)\)", target):
                        if expr.casefold() not in WUSA_EXPRESSIONS:
                            counts["unknown_destination_expression"] += 1
            if tag == "registryKeys":
                for node in element.iter():
                    if local(node.tag) != "registryValue":
                        continue
                    counts["registry_values"] += 1
                    typ = node.get("valueType")
                    val = node.get("value")
                    if typ not in REG_TYPES:
                        counts["unsupported_registry_type"] += 1
                    if typ == "REG_DWORD":
                        counts["dword_values"] += 1
                        if val is None or not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,8}", val):
                            counts["invalid_dword_value"] += 1
                    if typ == "REG_BINARY" and val is not None:
                        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", val):
                            counts["invalid_binary_value"] += 1
                    if typ in ("REG_SZ", "REG_EXPAND_SZ") and val:
                        for expr in re.findall(r"\$\(([^)]+)\)", val):
                            if expr.casefold() not in WUSA_EXPRESSIONS:
                                counts["unknown_registry_expression"] += 1
    for assembly in assemblies:
        for ref in assembly.deps:
            candidates = index.get(ref[0], ())
            exact = sum(compatible(c.identity, ref) for c in candidates)
            loose = sum(compatible(c.identity, ref, version=False) for c in candidates)
            if exact == 1:
                counts["dependency_exact"] += 1
            elif exact > 1:
                counts["dependency_ambiguous"] += 1
            elif loose:
                counts["dependency_version_only"] += 1
            else:
                counts["dependency_absent"] += 1
    keys = ("root_documents", "xml", "dcm", "unsafe_xml", "non_xml", "oversized",
            "unexpected_root", "incomplete_identity", "complete_identity",
            "assembly_dependencies", "package_dependencies", "unsupported_dependency_type",
            "incomplete_dependency_identity", "unsupported_update_child", "file_operations",
            "missing_source_name", "missing_wusa_source", "missing_destination_path",
            "unknown_destination_expression", "registry_values", "unsupported_registry_type",
            "dword_values", "invalid_dword_value", "invalid_binary_value",
            "unknown_registry_expression", "dependency_exact", "dependency_ambiguous",
            "dependency_version_only", "dependency_absent")
    return {"counts": {k: counts[k] for k in keys},
            "root_features": dict(sorted(features.items())), "servicing_performed": False}


def inspect(stage: Path):
    members = inventory(stage)
    if len(members) != EXPECTED_COUNT or digest_tree(members) != EXPECTED_TREE_SHA256:
        raise ValueError("Manifest audit requires exact verified CIX tree")
    return audit_members(members)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if a.output.exists() or a.output.is_symlink():
        raise ValueError("Report must be fresh")
    report = inspect(a.stage)
    a.output.write_text(json.dumps(report, sort_keys=True), encoding="ascii")
    print("Verified IPD manifest audit", json.dumps(report, sort_keys=True))
