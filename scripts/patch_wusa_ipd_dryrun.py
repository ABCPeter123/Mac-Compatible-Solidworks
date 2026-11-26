"""Prepare a dry-run-only WUSA probe from the pinned LGPL Wine 11.13 source.

The host verifies the original MSU and reconstructed tree before invoking
the probe. Only the IPD extraction boundary changes; no Microsoft manifest
or registry contents are altered. Do not replace the installed Wine WUSA.
"""
from pathlib import Path
import argparse
import hashlib

BLOBS = {
    "main.c": "26e83e4fc2036c8c424c6254fbf17b2ea4aab477",
    "manifest.c": "986bda27cd85d528419b0f584cc4839b73131866",
    "wusa.h": "dcc4850f10eb7d9ef0817866641bdb6aaabd5d20",
    "wine/list.h": "2e1d95f3fd449a6dcf73dc0ca87b0ebe34b11905",
}

DEBUG = r'''
#ifndef SWCOMPAT_WUSA_DEBUG_H
#define SWCOMPAT_WUSA_DEBUG_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif
void swcompat_wusa_event(const char *format);
#define WINE_DEFAULT_DEBUG_CHANNEL(x)
#define TRACE_ON(x) 0
#define TRACE(...) ((void)0)
#define ERR(format, ...) swcompat_wusa_event(format)
#define FIXME(format, ...) swcompat_wusa_event(format)
#define WARN(format, ...) swcompat_wusa_event(format)
#endif
'''

EVENTS = r'''
static unsigned swcompat_counts[11];
static const WCHAR *swcompat_stage;
static unsigned swcompat_ipd_count;
void swcompat_wusa_event(const char *format)
{
    unsigned category = 10;
    if (strstr(format, "Assembly %s not found")) category = 0;
    else if (strstr(format, "Required file %s not found")) category = 1;
    else if (strstr(format, "expression")) category = 2;
    else if (strstr(format, "Unsupported registry value type")) category = 3;
    else if (strstr(format, "circular dependency")) category = 4;
    else if (strstr(format, "No updates found")) category = 5;
    else if (strstr(format, "Failed to extract")) category = 6;
    else if (strstr(format, "version difference")) category = 7;
    else if (strstr(format, "unexpected tag") || strstr(format, "dependency type")) category = 8;
    else if (strstr(format, "Failed to load all")) category = 9;
    if (swcompat_counts[category] < 1000000) swcompat_counts[category]++;
}
'''

OLD_IPD = r'''        FIXME("Cabinet uses proprietary msdelta file compression which is not (yet) supported\n");
        FIXME("Installation of msu file will most likely fail\n");'''
NEW_IPD = r'''        /* Host has verified the complete tree against the pinned Windows
         * reference digest. Use the external read-only directory for manifest
         * discovery; the original raw cabinet remains in its private temp dir.
         */
        if (++swcompat_ipd_count != 1 || !is_directory(swcompat_stage))
        {
            free(path);
            return FALSE;
        }
        temp_path = swcompat_stage;'''

OLD_INSTALL = r'''    /* installation */
    set_assembly_status(&state->assemblies, ASSEMBLY_STATUS_NONE);
    if (!install_updates(state, FALSE))
    {
        ERR("Installation failed\n");
        goto done;
    }

    TRACE("Installation finished\n");
    ret = TRUE;'''
NEW_INSTALL = r'''    /* This research executable has no installation mode. */
    ret = swcompat_ipd_count == 1;'''

ENTRY = r'''int __cdecl wmain(int argc, WCHAR *argv[])
{
    struct installer_state state;
    BOOL passed;
    unsigned i;
    if (argc != 3 || !is_directory(argv[2])) return 2;
    swcompat_stage = argv[2];
    state.norestart = TRUE;
    state.quiet = TRUE;
    passed = install_msu(argv[1], &state);
    printf("SWCOMPAT_IPD_DRYRUN_SCHEMA=1\n");
    printf("SWCOMPAT_IPD_DRYRUN_RESULT=%s\n", passed ? "PASS" : "FAIL");
    printf("SWCOMPAT_IPD_DRYRUN_IPD=%u\n", swcompat_ipd_count);
    for (i = 0; i < ARRAY_SIZE(swcompat_counts); i++)
        printf("SWCOMPAT_IPD_DRYRUN_C%u=%u\n", i, swcompat_counts[i]);
    return passed ? 0 : 1;
}
'''


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError("Unexpected Wine 11.13 source anchor")
    return text.replace(old, new)


def patch_main(text: str) -> str:
    text = replace_once(text, "WINE_DEFAULT_DEBUG_CHANNEL(wusa);", "WINE_DEFAULT_DEBUG_CHANNEL(wusa);\n" + EVENTS)
    text = replace_once(text, OLD_IPD, NEW_IPD)
    text = replace_once(text, OLD_INSTALL, NEW_INSTALL)
    # The upstream parser's dry-run branch passes an uninitialized HKEY to
    # its no-write registry routines. Initialize it for defined C behavior.
    text = replace_once(text, "    HKEY root, subkey;", "    HKEY root, subkey = NULL;")
    marker = "static void restart_as_x86_64(void)"
    if text.count(marker) != 1 or text.count("int __cdecl wmain(") != 1:
        raise ValueError("Unexpected WUSA entrypoint")
    return text[:text.index(marker)] + ENTRY


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def prepare(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("Probe source destination must be fresh")
    original = {}
    for name, digest in BLOBS.items():
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing pinned Wine source")
        raw = path.read_bytes()
        if git_blob(raw) != digest:
            raise ValueError("Wine source blob identity mismatch")
        original[name] = raw
    destination.mkdir()
    (destination / "wine").mkdir()
    for name, data in original.items():
        if name == "main.c":
            data = patch_main(data.decode("utf-8")).encode("utf-8")
        (destination / name).write_bytes(data)
    (destination / "wine/debug.h").write_text(DEBUG, encoding="ascii")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    a = p.parse_args()
    prepare(a.source, a.destination)
