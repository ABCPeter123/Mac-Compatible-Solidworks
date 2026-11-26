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
static unsigned swcompat_counts[14];
static const WCHAR *swcompat_stage;
static unsigned swcompat_ipd_count;
void swcompat_wusa_event(const char *format)
{
    unsigned category = 10;
    if (strstr(format, "Assembly %s not found")) category = 0;
    else if (strstr(format, "Required file %s not found")) category = 1;
    else if (strstr(format, "expression")) category = 2;
    else if (strstr(format, "Unsupported registry value type") || strstr(format, "Invalid registry numeric data")) category = 3;
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
    ret = swcompat_ipd_count == 1 && !swcompat_counts[12] && !swcompat_counts[13];'''

OLD_DWORD = r'''    DWORD value = registrykv->value_type ? wcstoul(registrykv->value_type, NULL, 16) : 0;
    BOOL ret = TRUE;'''
NEW_DWORD = r'''    DWORD value;
    BOOL ret = TRUE;

    if (!swcompat_parse_dword(registrykv->value, &value))
    {
        ERR("Invalid registry numeric data\n");
        return FALSE;
    }'''

NUMERIC = r'''
static int swcompat_hex_digit(WCHAR c)
{
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

/* Match Wine's intended hexadecimal interpretation, but use the manifest's
 * actual value field and reject overflow, missing and malformed input. */
static BOOL swcompat_parse_dword(const WCHAR *text, DWORD *out)
{
    DWORD value = 0;
    unsigned count = 0;
    int digit;
    if (!text || !out) return FALSE;
    if (text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) text += 2;
    while (*text)
    {
        if (count == 8 || (digit = swcompat_hex_digit(*text++)) < 0) return FALSE;
        value = (value << 4) | (DWORD)digit;
        count++;
    }
    if (!count) return FALSE;
    *out = value;
    return TRUE;
}

static BOOL swcompat_numeric_selftest(void)
{
    DWORD value;
    return swcompat_parse_dword(L"0x00000001", &value) && value == 1
        && swcompat_parse_dword(L"FFFFFFFF", &value) && value == 0xffffffff
        && swcompat_parse_dword(L"0", &value) && value == 0
        && !swcompat_parse_dword(L"REG_DWORD", &value)
        && !swcompat_parse_dword(L"0x", &value)
        && !swcompat_parse_dword(L"100000000", &value)
        && !swcompat_parse_dword(L"-1", &value)
        && !swcompat_parse_dword(L"1g", &value)
        && !swcompat_parse_dword(NULL, &value);
}
'''

ENTRY = r'''int __cdecl wmain(int argc, WCHAR *argv[])
{
    struct installer_state state;
    BOOL passed;
    unsigned i;
    if (argc == 2 && !wcscmp(argv[1], L"--selftest"))
    {
        BOOL ok = swcompat_numeric_selftest();
        printf("SWCOMPAT_WUSA_REGISTRY_SELFTEST=%s\n", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }
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
    text = replace_once(text, OLD_DWORD, NEW_DWORD)
    text = replace_once(text, "static BOOL install_registry_dword(", NUMERIC + "static BOOL install_registry_dword(")
    # The upstream parser's dry-run branch passes an uninitialized HKEY to
    # its no-write registry routines. Initialize it for defined C behavior.
    text = replace_once(text, "    HKEY root, subkey;", "    HKEY root, subkey = NULL;")
    text = replace_once(text, "    if (!(output = malloc(length))) return NULL;",
                        "    if (!(output = malloc(length ? length : 1))) return NULL;")
    text = replace_once(text, "        *p++ = wcstoul(number, 0, 16);",
                        "        if (swcompat_hex_digit(number[0]) < 0 || swcompat_hex_digit(number[1]) < 0)\n"
                        "        {\n            free(output);\n            return NULL;\n        }\n"
                        "        *p++ = (swcompat_hex_digit(number[0]) << 4) | swcompat_hex_digit(number[1]);")
    marker = "static void restart_as_x86_64(void)"
    if text.count(marker) != 1 or text.count("int __cdecl wmain(") != 1:
        raise ValueError("Unexpected WUSA entrypoint")
    return text[:text.index(marker)] + ENTRY


def patch_manifest(text: str) -> str:
    # MinGW's msxml.h can expose interfaces before COBJMACROS is defined
    # by upstream Wine's source. Use the identical COM ABI explicitly,
    # not implicit function declarations or stubbed parser calls.
    import re
    pattern = r"\b(IXMLDOM(?:Element|NodeList|Node|Document))_([A-Za-z0-9_]+)\(([A-Za-z_][A-Za-z0-9_]*)(?=\s*[,)]|\s*$)"
    converted, count = re.subn(pattern, lambda m: f"{m[3]}->lpVtbl->{m[2]}({m[3]}", text)
    if count != 18:
        raise ValueError("Unexpected pinned Wine COM call count")
    return converted


def patch_file_names(main: str, manifest: str, header: str) -> tuple[str, str, str]:
    # CBS sourceName is the original build-source name, while name is the
    # destination name. IPD expands renamed payloads under the latter.
    # The full CIX tree is authenticated by the host; never search elsewhere.
    header = replace_once(header, "    WCHAR       *source;\n    WCHAR       *target;",
                          "    WCHAR       *source;\n    WCHAR       *target;\n    WCHAR       *name;")
    manifest = replace_once(manifest, "    free(entry->source);\n    free(entry->target);",
                            "    free(entry->source);\n    free(entry->target);\n    free(entry->name);")
    manifest = replace_once(manifest, '    if (!(entry->source = get_xml_attribute(root, L"sourceName"))) goto error;',
                            '    if (!(entry->source = get_xml_attribute(root, L"sourceName"))) goto error;\n'
                            '    if (!(entry->name = get_xml_attribute(root, L"name")))\n'
                            '        if (!(entry->name = wcsdup(entry->source))) goto error;')
    main = replace_once(main, "    if (!(target = path_combine(target_path, fileop->source))) goto error;",
                        "    target = NULL;\n"
                        "    if (!swcompat_file_name(fileop->source) || !swcompat_file_name(fileop->name)) goto error;\n"
                        "    if (!(target = path_combine(target_path, fileop->name))) goto error;")
    main = replace_once(main, "    if (!(source = path_combine(source_path, fileop->source))) goto error;",
                        r'''    if (!(source = path_combine(source_path, fileop->source))) goto error;
    if (swcompat_ipd_count == 1 && GetFileAttributesW(source) == INVALID_FILE_ATTRIBUTES
        && wcsicmp(fileop->source, fileop->name))
    {
        free(source);
        if (!(source = path_combine(source_path, fileop->name))) goto error;
        if (swcompat_regular_file(source)) swcompat_counts[11]++;
    }''')
    main = replace_once(main, "if (!(ret = PathFileExistsW(source)))",
                        "if (!(ret = swcompat_regular_file(source)))")
    main = replace_once(main, "static BOOL install_files_copy(",
                        r'''static BOOL swcompat_file_name(const WCHAR *name)
{
    size_t n;
    if (!name || !(n = wcslen(name)) || !wcscmp(name, L".") || !wcscmp(name, L".."))
        return FALSE;
    return !wcspbrk(name, L"\\/:*?\"<>|") && name[n-1] != L'.' && name[n-1] != L' ';
}

static BOOL swcompat_regular_file(const WCHAR *path)
{
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES &&
        !(attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

static BOOL install_files_copy(''')
    return main, manifest, header


def patch_full_preflight(main: str) -> str:
    # WUSA stops at the first missing dependency. Independently exercise every
    # parsed component's file and registry dry-run paths before graph traversal.
    # A successful report still requires the original dependency traversal.
    return replace_once(main, "    /* perform dry run */", r'''    {
        struct assembly_entry *item;
        LIST_FOR_EACH_ENTRY(item, &state->assemblies, struct assembly_entry, entry)
        {
            if (!item->identity.name || !item->identity.architecture)
            {
                swcompat_counts[12]++;
                continue;
            }
            if (!install_files(item, TRUE)) swcompat_counts[12]++;
            if (!install_registry(item, TRUE)) swcompat_counts[13]++;
        }
    }
    /* perform dry run */''')


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
    main, manifest, header = patch_file_names(
        patch_main(original["main.c"].decode("utf-8")),
        patch_manifest(original["manifest.c"].decode("utf-8")),
        original["wusa.h"].decode("utf-8"))
    original["main.c"] = patch_full_preflight(main).encode("utf-8")
    original["manifest.c"] = manifest.encode("utf-8")
    original["wusa.h"] = header.encode("utf-8")
    destination.mkdir()
    (destination / "wine").mkdir()
    for name, data in original.items():
        (destination / name).write_bytes(data)
    (destination / "wine/debug.h").write_text(DEBUG, encoding="ascii")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    a = p.parse_args()
    prepare(a.source, a.destination)
