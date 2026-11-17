"""Strict x64-compatible PE check for authenticated Framework64 DLL payloads.

A .NET managed AnyCPU assembly can be PE_I386 while still executing under an
AMD64 CLR. Never accept arbitrary 32-bit native PE code as AMD64-compatible.
No file paths, hashes, headers or vendor bytes are exported from this module.
"""
from __future__ import annotations
import struct

from scripts.netfx481_payload_audit import pe_type

MAX_HEADER = 65536
MAX_SECTIONS = 96
IL_ONLY = 0x1
BIT32_REQUIRED = 0x2
BIT32_PREFERRED = 0x20000


def compatible_x64(data: bytes, *, allow_anycpu: bool = False) -> bool:
    """Return True for PE_AMD64, or strictly proved PE32 ILONLY AnyCPU.

    Short/invalid headers, unsupported layouts, section aliasing, native
    x86 DLLs and 32BITREQUIRED/PREFERRED managed images fail closed.
    """
    kind = pe_type(data)
    if kind == "PE_AMD64":
        return True
    if not allow_anycpu or kind != "PE_I386" or len(data) > MAX_HEADER:
        return False
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        nsects = struct.unpack_from("<H", data, pe + 6)[0]
        optsz = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        if not 1 <= nsects <= MAX_SECTIONS or optsz < 224:
            return False
        if opt + optsz + 40 * nsects > len(data):
            return False
        if struct.unpack_from("<I", data, opt + 92)[0] < 15:
            return False
        cli_entry = opt + 96 + 14 * 8
        cli_rva, cli_size = struct.unpack_from("<II", data, cli_entry)
        if not cli_rva or cli_size < 0x48:
            return False
        cli_position = None
        for i in range(nsects):
            section = opt + optsz + i * 40
            virtual_size, rva, raw_size, offset = struct.unpack_from(
                "<IIII", data, section + 8)
            span = min(virtual_size or raw_size, raw_size)
            if (rva <= cli_rva and cli_rva + 20 <= rva + span
                    and offset + cli_rva - rva + 20 <= len(data)):
                if cli_position is not None:
                    return False
                cli_position = offset + cli_rva - rva
        if cli_position is None:
            return False
        # IMAGE_COR20_HEADER Flags at byte +16.
        header_size = struct.unpack_from("<I", data, cli_position)[0]
        if header_size < 0x48:
            return False
        flags = struct.unpack_from("<I", data, cli_position + 16)[0]
        return bool(flags & IL_ONLY) and not bool(
            flags & (BIT32_REQUIRED | BIT32_PREFERRED))
    except (struct.error, ValueError, OverflowError):
        return False
