"""Bounded, read-only CBS MUM operation-shape preflight.

This is NOT a CBS implementation. It never applies updates, exports package
identities, or claims that an actual .NET Framework runtime was installed.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

MAX_BYTES = 512 * 1024
MAX_NODES = 30000
ALLOWED_ARCH = {"amd64", "x86", "arm64", "neutral"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def preflight(raw: bytes) -> dict:
    """Summarize servicing operations without releasing Microsoft identifiers."""
    result = {
        "status": "INVALID",
        "target_arch": "UNDETERMINED",
        "root_identity_arch": "UNDETERMINED",
        "updates": 0,
        "parents": 0,
        "dependencies": 0,
        "files": 0,
        "registry_values": 0,
        "unsupported_operations": 0,
        "installer_assembly": 0,
        "custom_information": 0,
        "security_descriptor": 0,
        "other_unsupported": 0,
        "safe_to_apply": False,
    }
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        return result
    # ElementTree must not accept DTD/entity declarations from package data.
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        return result
    try:
        root = ET.fromstring(raw)
    except (ValueError, UnicodeError, ET.ParseError):
        return result
    if _local(root.tag) != "assembly":
        return result

    arch = set()
    root_identity = next((node for node in root if _local(node.tag) == "assemblyIdentity"), None)
    if root_identity is not None:
        root_arch = root_identity.attrib.get("processorArchitecture", "").casefold()
        if root_arch in ALLOWED_ARCH:
            result["root_identity_arch"] = root_arch
    nodes = 0
    for node in root.iter():
        nodes += 1
        if nodes > MAX_NODES:
            return result
        tag = _local(node.tag)
        if tag == "assemblyIdentity":
            a = node.attrib.get("processorArchitecture", "").casefold()
            if a in ALLOWED_ARCH:
                arch.add(a)
        elif tag == "update":
            result["updates"] += 1
        elif tag == "parent":
            result["parents"] += 1
        elif tag == "dependency":
            result["dependencies"] += 1
        elif tag == "file":
            result["files"] += 1
        elif tag == "registryValue":
            result["registry_values"] += 1
        elif tag in {"installerAssembly", "customInformation", "securityDescriptor",
                     "driver", "serviceData", "scheduledTasks"}:
            result["unsupported_operations"] += 1
            category = {
                "installerAssembly": "installer_assembly",
                "customInformation": "custom_information",
                "securityDescriptor": "security_descriptor",
            }.get(tag, "other_unsupported")
            result[category] += 1

    result["target_arch"] = next(iter(arch)) if len(arch) == 1 else (
        "MIXED" if arch else "UNDETERMINED")
    result["status"] = "PARSED"
    # This classifier can never approve application. CBS transactional
    # semantics, applicability, signatures and trusted ownership are missing.
    return result


def summarize_many(payloads: list[bytes]) -> dict:
    """Return count-only high-level diagnostics, with no package names."""
    if len(payloads) > 48:
        raise ValueError("Too many MUM documents")
    output = {"documents": len(payloads), "parsed": 0, "invalid": 0,
              "amd64_only": 0, "mixed_arch": 0, "other_arch": 0,
              "root_amd64": 0, "root_x86": 0, "root_arm64": 0,
              "root_neutral": 0, "root_unknown": 0,
              "updates": 0, "parents": 0, "dependencies": 0,
              "files": 0, "registry_values": 0,
              "unsupported_operations": 0, "installer_assembly": 0,
              "custom_information": 0, "security_descriptor": 0,
              "other_unsupported": 0,
              "root_amd64_updates": 0, "root_amd64_parents": 0,
              "root_amd64_dependencies": 0, "root_amd64_unsupported": 0,
              "safe_to_apply": False}
    for raw in payloads:
        r = preflight(raw)
        if r["status"] != "PARSED":
            output["invalid"] += 1
            continue
        output["parsed"] += 1
        root_arch = r["root_identity_arch"]
        output["root_" + root_arch if root_arch in ALLOWED_ARCH else "root_unknown"] += 1
        if root_arch == "amd64":
            for source, target in (
                ("updates", "root_amd64_updates"),
                ("parents", "root_amd64_parents"),
                ("dependencies", "root_amd64_dependencies"),
                ("unsupported_operations", "root_amd64_unsupported"),
            ):
                output[target] += r[source]
        if r["target_arch"] == "amd64":
            output["amd64_only"] += 1
        elif r["target_arch"] == "MIXED":
            output["mixed_arch"] += 1
        else:
            output["other_arch"] += 1
        for key in ("updates", "parents", "dependencies", "files",
                    "registry_values", "unsupported_operations",
                    "installer_assembly", "custom_information",
                    "security_descriptor", "other_unsupported"):
            output[key] += r[key]
    assert output["unsupported_operations"] == sum(
        output[k] for k in ("installer_assembly", "custom_information",
                            "security_descriptor", "other_unsupported")
    )
    return output
