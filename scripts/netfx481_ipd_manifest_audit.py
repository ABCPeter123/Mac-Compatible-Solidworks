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


def audit_members(members: dict[str, Path], update_roots: list[tuple[str, ...]] | None = None) -> dict:
    counts = Counter()
    features = Counter()
    assemblies = []
    index = defaultdict(list)
    missing_files = Counter()
    missing_dependencies = Counter()
    expression_tokens = Counter()
    dep_kinds = defaultdict(Counter)
    dep_metadata = defaultdict(list)
    missing_resource_metadata = Counter()
    version_resource_metadata = Counter()
    version_conflicts = []
    component_metadata = {}
    ignored_features = Counter()
    deployment_features = Counter()
    deployment_attributes = Counter()
    file_targets = defaultdict(set)
    runtime_payloads = Counter()
    destination_classes = Counter()
    managed_framework_names = Counter()
    gac_registration_features = Counter()
    runtime_image_versions = Counter()
    release_registry = Counter()
    runtime_directives = Counter()
    runtime_attributes = Counter()
    runtime_architectures = Counter()
    directory_expressions = Counter()
    directory_flags = Counter()
    resource_name_relations = Counter()
    absent_names = Counter()
    absent_arch = Counter()
    absent_language = Counter()
    absent_versions = Counter()
    file_shapes = Counter()
    empty_shapes = Counter()
    basenames = defaultdict(list)
    for key in members:
        basenames[key.rsplit("/", 1)[-1]].append(key)
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
        component_metadata[ident] = {
            "version_scope": top[0].get("versionScope"),
            "build_type": top[0].get("buildType"),
            "root_file_count": len(children(root, "file")),
            "root_registry_count": len(children(root, "registryKeys")),
            "deployment_count": len(children(root, "deployment")),
        }
        record = Assembly(ident, [])
        assemblies.append(record)
        index[ident[0]].append(record)
        counts["complete_identity"] += 1
        parent = name.rsplit(".", 1)[0]
        for element in root:
            tag = local(element.tag)
            if tag not in {"assemblyIdentity", "dependency", "package", "file",
                           "registryKeys", "trustInfo", "configuration", "deployment"}:
                ignored_features[tag if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,64}", tag) else "other"] += 1
            if tag == "runtime":
                runtime_architectures[ident[1] if ident[1] in {"amd64", "x86", "wow64", "msil", "neutral"} else "other"] += 1
                for node in element.iter():
                    feature = local(node.tag)
                    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,64}", feature):
                        feature = "other"
                    runtime_directives[feature] += 1
                    if feature == "runtime":
                        value = node.get("imageVersion", "")
                        runtime_image_versions[value if re.fullmatch(r"v?[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}", value) else "other"] += 1
                    for attr in node.attrib:
                        attr = local(attr)
                        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,64}", attr):
                            runtime_attributes[feature + "/" + attr] += 1
            if tag == "directories":
                for directory in children(element, "directory"):
                    value = directory.get("destinationPath", "")
                    tokens = re.findall(r"\$\(([^)]+)\)", value)
                    for token in tokens:
                        token = token.casefold()
                        directory_expressions[token if re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", token) else "other"] += 1
                    if not value:
                        directory_flags["missing_path"] += 1
                    elif not tokens:
                        directory_flags["no_expression"] += 1
                    if directory.get("owner"):
                        directory_flags["explicit_owner"] += 1
                    if children(directory, "securityDescriptor"):
                        directory_flags["security_descriptor"] += 1
            if tag in {"deployment", "configuration", "directories"}:
                for node in element.iter():
                    feature = local(node.tag)
                    if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,64}", feature):
                        deployment_features[tag + "/" + feature] += 1
                    for attr in node.attrib:
                        attr = local(attr)
                        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,64}", attr):
                            deployment_attributes[feature + "/" + attr] += 1
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
                        dep_kinds[(ident, ref)][dep.get("dependencyType") if dep.get("dependencyType") in {"install", "prerequisite"} else "unspecified"] += 1
                        dep_metadata[(ident, ref)].append((element.get("resourceType"), element.get("optional"),
                                                            element.get("discoverable"), dep.get("dependencyType")))
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
                                dep_kinds[(ident, ref)]["package_component"] += 1
            if tag == "file":
                counts["file_operations"] += 1
                source = element.get("sourceName")
                target = element.get("destinationPath")
                for field, value in (("source", source), ("name", element.get("name"))):
                    if value and ("/" in value or "\\" in value):
                        file_shapes[field + "_relative_path"] += 1
                    if value and value.endswith((".", " ")):
                        file_shapes[field + "_trailing_dot_space"] += 1
                    if value and any(c in value for c in '<>"|?*:'):
                        file_shapes[field + "_invalid_character"] += 1
                if not source:
                    counts["missing_source_name"] += 1
                else:
                    key = (parent + "/" + source.replace("\\", "/")).casefold()
                    if key not in members:
                        counts["missing_wusa_source"] += 1
                        dest_name = element.get("name", "").replace("\\", "/").casefold()
                        if dest_name and parent + "/" + dest_name in members:
                            missing_files["same_assembly_destination_name"] += 1
                        else:
                            options = basenames[source.replace("\\", "/").casefold().rsplit("/", 1)[-1]]
                            category = ("unique_source_basename_elsewhere" if len(options) == 1
                                        else "ambiguous_source_basename" if options
                                        else "source_basename_absent")
                            missing_files[category] += 1
                if source and target:
                    dest_name = element.get("name") or source
                    normalized = (target.rstrip("\\/") + "\\" + dest_name).replace("/", "\\").casefold()
                    # Preserve architecture-specific registry and filesystem views.
                    view = "32" if ident[1] in ("x86", "wow64") else "64"
                    file_targets[(view, normalized)].add((parent, source.casefold()))
                    base = dest_name.replace("\\", "/").rsplit("/", 1)[-1].casefold()
                    if re.search(r"(?:^|\\)(?:gac(?:_32|_64|_msil)?|nativeimages[^\\]*)\\", normalized):
                        dest_class = "native_images" if "\\nativeimages" in normalized else "gac"
                    elif "\\microsoft.net\\framework64\\" in normalized:
                        dest_class = "framework64"
                    elif "\\microsoft.net\\framework\\" in normalized:
                        dest_class = "framework32"
                    elif "\\microsoft.net\\assembly\\" in normalized or "\\assembly\\" in normalized:
                        dest_class = "assembly_other"
                    elif base.endswith(".config"):
                        dest_class = "configuration"
                    else:
                        dest_class = "other"
                    destination_classes[dest_class] += 1
                    if base in {"mscorlib.dll", "system.dll", "system.core.dll", "system.xml.dll",
                                "system.configuration.dll", "system.security.dll", "system.data.dll",
                                "system.windows.forms.dll", "presentationframework.dll", "windowsbase.dll",
                                "system.xaml.dll", "fusion.dll", "mscoree.dll", "mscoreei.dll", "clr.dll",
                                "clrjit.dll", "machine.config", "machine.config.default"}:
                        managed_framework_names[dest_class + "/" + base] += 1
                    for node in element.iter():
                        tagname = local(node.tag).casefold()
                        if tagname in {"assemblyidentity", "gac", "managedassembly", "assemblyregistration"}:
                            gac_registration_features[tagname] += 1
                    if base in ("clr.dll", "mscorlib.dll", "mscoree.dll", "ngen.exe", "servicemodelreg.exe"):
                        runtime_payloads[view + "/" + base] += 1
                if not target:
                    counts["missing_destination_path"] += 1
                else:
                    for expr in re.findall(r"\$\(([^)]+)\)", target):
                        if expr.casefold() not in WUSA_EXPRESSIONS:
                            counts["unknown_destination_expression"] += 1
            if tag == "registryKeys":
                for registry_key in element.iter():
                    if local(registry_key.tag) != "registryKey":
                        continue
                    name = registry_key.get("keyName", "").casefold()
                    if not name.endswith(r"\ndp\v4\full"):
                        continue
                    for value in children(registry_key, "registryValue"):
                        if value.get("name", "").casefold() == "release":
                            release_registry["release_declarations"] += 1
                            if value.get("valueType") == "REG_DWORD":
                                release_registry["release_dword"] += 1
                                try:
                                    if int(value.get("value", ""), 16) >= 533320:
                                        release_registry["release_at_least_481"] += 1
                                except ValueError:
                                    release_registry["invalid_release"] += 1
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
                                # Only bounded public CBS runtime identifiers,
                                # never registry strings or their values.
                                token = expr.casefold()
                                if token == "assembly.empty":
                                    empty_shapes["whole_value" if val.casefold() == "$(assembly.empty)" else "embedded"] += 1
                                    empty_shapes[typ] += 1
                                expression_tokens[token if re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", token) else "other"] += 1
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
                def public_identity(value):
                    return value if re.fullmatch(r"[a-z0-9_.-]{1,120}", value) else "other"
                if len(version_conflicts) < 16:
                    version_conflicts.append({
                        "parent": public_identity(assembly.identity[0]),
                        "parent_architecture": public_identity(assembly.identity[1]),
                        "parent_version": public_identity(assembly.identity[4]),
                        "parent_language": public_identity(assembly.identity[2]),
                        "needed": public_identity(ref[0]),
                        "architecture": public_identity(ref[1]),
                        "language": ref[2] if ref[2] == "*" else public_identity(ref[2]),
                        "required_version": public_identity(ref[4]),
                        "available_versions": sorted({public_identity(c.identity[4]) for c in candidates
                                                      if compatible(c.identity, ref, version=False)}),
                        "kinds": sorted(dep_kinds[(assembly.identity, ref)]),
                        "all_same_name_candidates": [
                            {"architecture": public_identity(c.identity[1]),
                             "language": c.identity[2] if c.identity[2] == "*" else public_identity(c.identity[2]),
                             "version": public_identity(c.identity[4]),
                             "version_scope": (component_metadata[c.identity]["version_scope"]
                                 if component_metadata[c.identity]["version_scope"] in {"nonSxS", "SxS"} else "other_or_absent"),
                             "root_file_count": component_metadata[c.identity]["root_file_count"],
                             "root_registry_count": component_metadata[c.identity]["root_registry_count"],
                             "deployment_count": component_metadata[c.identity]["deployment_count"],
                             "direct_package_component_refs": sum(
                                 dep_kinds[(owner.identity, need)]["package_component"]
                                 for owner in assemblies for need in owner.deps
                                 if compatible(c.identity, need))}
                            for c in candidates],
                        "parent_file_count": component_metadata[assembly.identity]["root_file_count"],
                        "parent_registry_count": component_metadata[assembly.identity]["root_registry_count"],
                        "parent_deployment_count": component_metadata[assembly.identity]["deployment_count"],
                    })
                for resource, optional, discoverable, kind in dep_metadata[(assembly.identity, ref)]:
                    version_resource_metadata["resource_" + (resource if resource in {"Resources", "LanguagePack", "Neutral"} else "other_or_absent")] += 1
            else:
                counts["dependency_absent"] += 1
                for resource, optional, discoverable, kind in dep_metadata[(assembly.identity, ref)]:
                    missing_resource_metadata["resource_" + (resource if resource in {"Resources", "LanguagePack", "Neutral"} else "other_or_absent")] += 1
                    missing_resource_metadata["optional_" + (optional if optional in {"true", "false"} else "absent_or_other")] += 1
                    missing_resource_metadata["discoverable_" + (discoverable if discoverable in {"true", "false"} else "absent_or_other")] += 1
                    if resource == "Resources" and kind == "prerequisite" and ref[2] == "*":
                        missing_resource_metadata["wildcard_resource_prerequisite"] += 1
                    if ref[0] == assembly.identity[0] + ".resources":
                        resource_name_relations["parent_dot_resources"] += 1
                    elif ref[0].endswith(".resources"):
                        resource_name_relations["other_dot_resources"] += 1
                    else:
                        resource_name_relations["other_name"] += 1
                absent_arch[ref[1] if ref[1] in {"amd64", "x86", "wow64", "msil", "neutral", "arm64", "*"} else "other"] += 1
                absent_language[ref[2] if re.fullmatch(r"[a-z0-9*-]{1,20}", ref[2]) else "other"] += 1
                absent_versions[ref[4] if re.fullmatch(r"[0-9.]{1,32}|\*", ref[4]) else "other"] += 1
                for kind in dep_kinds[(assembly.identity, ref)]:
                    counts["absent_" + kind] += 1
                # Public Windows assembly identifiers, not arbitrary XML,
                # payload bytes, registry values or host file paths.
                if re.fullmatch(r"microsoft[-.][a-z0-9_.-]{1,115}", ref[0]):
                    absent_names[ref[0]] += 1
                else:
                    absent_names["other"] += 1
                if candidates:
                    if any(c.identity[1] == ref[1] for c in candidates):
                        missing_dependencies["same_name_arch_identity_mismatch"] += 1
                    else:
                        missing_dependencies["same_name_other_arch"] += 1
                else:
                    missing_dependencies["name_not_packaged"] += 1
    reachable = Counter()
    if update_roots is not None:
        pending = list(update_roots)
        visited = set()
        while pending:
            ref = pending.pop()
            if ref in visited:
                continue
            visited.add(ref)
            exact = [c for c in index.get(ref[0], ()) if compatible(c.identity, ref)]
            if len(exact) == 1:
                reachable["resolved"] += 1
                pending.extend(exact[0].deps)
            elif exact:
                reachable["ambiguous"] += 1
            else:
                reachable["unresolved"] += 1
        reachable["update_roots"] = len(update_roots)
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
            "root_features": dict(sorted(features.items())),
            "wine_ignored_root_features": dict(sorted(ignored_features.items())),
            "deployment_features": dict(sorted(deployment_features.items())),
            "deployment_attribute_names": dict(sorted(deployment_attributes.items())),
            "file_destination_collisions": sum(len(v) > 1 for v in file_targets.values()),
            "runtime_payload_operations": dict(sorted(runtime_payloads.items())),
            "destination_classes": dict(sorted(destination_classes.items())),
            "managed_framework_placement": dict(sorted(managed_framework_names.items())),
            "file_child_registration_features": dict(sorted(gac_registration_features.items())),
            "runtime_image_versions": dict(sorted(runtime_image_versions.items())),
            "release_registry": dict(sorted(release_registry.items())),
            "runtime_directives": dict(sorted(runtime_directives.items())),
            "runtime_directive_attributes": dict(sorted(runtime_attributes.items())),
            "runtime_directive_architectures": dict(sorted(runtime_architectures.items())),
            "directory_expressions": dict(sorted(directory_expressions.items())),
            "directory_flags": dict(sorted(directory_flags.items())),
            "missing_source_categories": dict(sorted(missing_files.items())),
            "missing_dependency_categories": dict(sorted(missing_dependencies.items())),
            "absent_dependency_kinds": {k: counts["absent_" + k] for k in ("install", "prerequisite", "unspecified", "package_component")},
            "absent_public_assembly_names": dict(sorted(absent_names.items())),
            "absent_architectures": dict(sorted(absent_arch.items())),
            "absent_resource_metadata": dict(sorted(missing_resource_metadata.items())),
            "version_only_resource_metadata": dict(sorted(version_resource_metadata.items())),
            "version_conflicts": version_conflicts,
            "resource_name_relations": dict(sorted(resource_name_relations.items())),
            "absent_languages": dict(sorted(absent_language.items())),
            "absent_versions": dict(sorted(absent_versions.items())),
            "file_name_shapes": dict(sorted(file_shapes.items())),
            "assembly_empty_shapes": dict(sorted(empty_shapes.items())),
            "unknown_runtime_tokens": dict(sorted(expression_tokens.items())),
            "reachable": dict(sorted(reachable.items())),
            "servicing_performed": False}


def inspect(stage: Path):
    members = inventory(stage)
    if len(members) != EXPECTED_COUNT or digest_tree(members) != EXPECTED_TREE_SHA256:
        raise ValueError("Manifest audit requires exact verified CIX tree")
    return audit_members(members)


def inspect_windows(package: Path, digest: Path, sevenzip: Path, expand: Path):
    """Use the original Windows Expand oracle directly, avoiding an extra Rust
    build or dependency on the queued Mac runner. Only the pinned graph is
    passed to the audit, with its full independently verified tree digest."""
    import os
    import tempfile
    from scripts.netfx481_catalog_wusa import verify_package
    from scripts.netfx481_servicing_inventory import _invoke_sevenzip, _safe_embedded
    from scripts.netfx481_native_delta import files, run_private
    from scripts.netfx481_cix_graph import parse, path_key

    if os.name != "nt" or any(p.is_symlink() for p in (package, digest, sevenzip, expand)):
        raise ValueError("Native Windows reference audit requires original inputs")
    package, digest, sevenzip, expand = (p.resolve(strict=True) for p in (package, digest, sevenzip, expand))
    verify_package(package, digest)
    with tempfile.TemporaryDirectory(prefix="swcompat-ipd-audit-") as d:
        root = Path(d)
        cabs = root / "cabs"
        cabs.mkdir()
        state, _ = _invoke_sevenzip(sevenzip, ["x", "-y", "-r", "-o" + str(cabs),
                                              str(package), "*.cab"], root, timeout=150)
        packages, partial = _safe_embedded(cabs)
        if state != "OK" or partial:
            raise ValueError("Original cabinet extraction failed")
        outer = root / "outer-xml"
        outer.mkdir()
        state, _ = _invoke_sevenzip(sevenzip, ["x", "-y", "-o" + str(outer),
                                               str(package), "*.xml"], root, timeout=150)
        if state != "OK":
            raise ValueError("Original outer update XML extraction failed")
        update_roots = []
        for p in files(outer):
            kind, doc = parse_xml(p)
            if doc is None or local(doc.tag) != "unattend":
                continue
            for servicing in children(doc, "servicing"):
                for pkg in children(servicing, "package"):
                    if pkg.get("action") != "install":
                        continue
                    for node in children(pkg, "assemblyIdentity"):
                        ref = identity(node)
                        if ref is None:
                            raise ValueError("Incomplete original update identity")
                        update_roots.append(ref)
        result = None
        for i, cab in enumerate(packages):
            if cab.suffix.casefold() != ".cab":
                continue
            raw = root / f"raw-{i}"
            raw.mkdir()
            state, _ = _invoke_sevenzip(sevenzip, ["x", "-y", "-o" + str(raw), str(cab)], root, timeout=150)
            if state != "OK":
                raise ValueError("Original inner cabinet extraction failed")
            matches = [p for p in files(raw) if p.relative_to(raw).as_posix().casefold() == "_manifest_.cix.xml"]
            if not matches:
                continue
            if len(matches) != 1 or result is not None:
                raise ValueError("Unexpected IPD cabinet count")
            entries, unsupported = parse(matches[0].read_bytes())
            if unsupported or len(entries) != EXPECTED_COUNT:
                raise ValueError("Unexpected CIX graph")
            expanded = root / "expanded"
            expanded.mkdir()
            if not run_private([str(expand), "-F:*", str(cab), str(expanded)], root, 150):
                raise ValueError("Native Windows IPD expansion failed")
            index = {}
            for p in files(expanded):
                key = path_key(p.relative_to(expanded).as_posix())
                if key in index:
                    raise ValueError("Ambiguous Windows reference")
                index[key] = p
            members = {e.name: index[e.name] for e in entries.values() if e.name in index}
            if len(members) != EXPECTED_COUNT or digest_tree(members) != EXPECTED_TREE_SHA256:
                raise ValueError("Windows reference tree differs from validated CIX tree")
            result = audit_members(members, update_roots)
        if result is None:
            raise ValueError("Missing original IPD cabinet")
        return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", type=Path)
    for name in ("package", "sha256-file", "sevenzip", "expand"):
        p.add_argument("--" + name, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if a.output.exists() or a.output.is_symlink():
        raise ValueError("Report must be fresh")
    args = (a.package, a.sha256_file, a.sevenzip, a.expand)
    if a.stage is not None and not any(args):
        report = inspect(a.stage)
    elif a.stage is None and all(args):
        report = inspect_windows(*args)
    else:
        p.error("Choose either verified stage or all four Windows oracle inputs")
    a.output.write_text(json.dumps(report, sort_keys=True), encoding="ascii")
    print("Verified IPD manifest audit", json.dumps(report, sort_keys=True))
