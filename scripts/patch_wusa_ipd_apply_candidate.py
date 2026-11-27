"""Build a separate, explicitly enabled experimental IPD apply candidate.

The normal WUSA probe remains read-only. This patch is not used by existing
CI. It enables a disposable-prefix trial only after the full package-local
dry-run gate in the SAME process, using the unchanged verified MSU/tree.
It does not implement complete Windows CBS or prove servicing equivalence.
"""
from pathlib import Path
import argparse
from scripts.patch_wusa_ipd_dryrun import prepare, replace_once

# A process launched as an apply candidate must explicitly request that mode.
# The dry-run executable produced by the normal build is unchanged.
def instrument_writes(main: str) -> str:
    """Capture only first operation/error and bounded progress counters."""
    main = replace_once(main, "static BOOL swcompat_apply_completed;",
        r'''static BOOL swcompat_apply_completed;
static DWORD swcompat_write_error;
static unsigned swcompat_write_phase, swcompat_written_files;
static unsigned swcompat_written_keys, swcompat_written_values, swcompat_written_assemblies;
static unsigned swcompat_deferred_files;

/* Only sharing violations can take this path. Use the Windows pending
 * rename mechanism, not force-delete or a host-side overwrite. The host
 * verifies the private queue and every replacement after wineboot. */
static BOOL swcompat_defer_locked_file(const WCHAR *source, const WCHAR *target)
{
    static const WCHAR dir[] = L"C:\\swcompat-ipd-pending";
    static const WCHAR journal[] = L"C:\\swcompat-ipd-pending\\queue.bin";
    WCHAR tmp[MAX_PATH], full_source[32768], full_target[32768];
    const WCHAR *fields[3];
    DWORD n, bytes, written;
    HANDLE file;
    unsigned i;
    BOOL ok = FALSE;
    if (swcompat_deferred_files >= 1044) return FALSE;
    n = GetFullPathNameW(source, ARRAY_SIZE(full_source), full_source, NULL);
    if (!n || n >= ARRAY_SIZE(full_source)) return FALSE;
    n = GetFullPathNameW(target, ARRAY_SIZE(full_target), full_target, NULL);
    if (!n || n >= ARRAY_SIZE(full_target) || wcsnicmp(full_target, L"C:\\", 3) ||
        wcsnicmp(full_source, L"Z:\\", 3)) return FALSE;
    if (!GetTempFileNameW(dir, L"ipd", 0, tmp)) return FALSE;
    if (!CopyFileExW(full_source, tmp, NULL, NULL, NULL, 0)) goto done;
    file = CreateFileW(journal, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) goto done;
    fields[0] = full_source;
    fields[1] = full_target;
    fields[2] = tmp;
    for (i = 0; i < ARRAY_SIZE(fields); i++)
    {
        bytes = (lstrlenW(fields[i]) + 1) * sizeof(WCHAR);
        if (!WriteFile(file, fields[i], bytes, &written, NULL) || written != bytes) break;
    }
    if (i == ARRAY_SIZE(fields) && FlushFileBuffers(file))
        ok = MoveFileExW(tmp, full_target, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
    CloseHandle(file);
    if (ok) swcompat_deferred_files++;
done:
    if (!ok) DeleteFileW(tmp);
    return ok;
}

static void swcompat_write_failure(unsigned phase, DWORD error)
{
    if (!swcompat_write_phase)
    {
        swcompat_write_phase = phase;
        swcompat_write_error = error;
    }
}

static LONG swcompat_registry_result(LONG result, unsigned phase)
{
    if (result) swcompat_write_failure(phase, result);
    else if (phase == 3) swcompat_written_keys++;
    else swcompat_written_values++;
    return result;
}''')
    main = replace_once(main, r'''        if (!create_parent_directory(target))
        {
            ERR("Failed to create parent directory for %s\n", debugstr_w(target));''',
        r'''        if (!create_parent_directory(target))
        {
            swcompat_write_failure(1, GetLastError());
            ERR("Failed to create parent directory for %s\n", debugstr_w(target));''')
    main = replace_once(main, r'''        if (!(ret = CopyFileExW(source, target, NULL, NULL, NULL, 0)))
        {
            ERR("Failed to copy %s to %s\n", debugstr_w(source), debugstr_w(target));
            goto error;
        }''', r'''        if (!(ret = CopyFileExW(source, target, NULL, NULL, NULL, 0)))
        {
            DWORD failure = GetLastError();
            if (failure == ERROR_SHARING_VIOLATION && swcompat_defer_locked_file(source, target))
            {
                ret = TRUE;
                goto error;
            }
            swcompat_write_failure(2, failure);
            ERR("Failed to copy %s to %s\n", debugstr_w(source), debugstr_w(target));
            goto error;
        }
        swcompat_written_files++;''')
    for call in (
        "RegSetValueExW(key, registrykv->name, 0, type, (void *)value, value_size)",
        "RegSetValueExW(key, registrykv->name, 0, REG_MULTI_SZ, (void *)value, value_size)",
        "RegSetValueExW(key, registrykv->name, 0, REG_DWORD, (void *)&value, sizeof(value))",
        "RegSetValueExW(key, registrykv->name, 0, REG_BINARY, value, value_size)",
        "RegCreateKeyExW(root, path, 0, NULL, 0, sam, NULL, &subkey, NULL)",
    ):
        main = replace_once(main, call, "swcompat_registry_result(" + call +
                            (", 3)" if call.startswith("RegCreate") else ", 4)"))
    main = replace_once(main, "    assembly->status = ASSEMBLY_STATUS_INSTALLED;",
                        "    if (!dryrun) swcompat_written_assemblies++;\n"
                        "    assembly->status = ASSEMBLY_STATUS_INSTALLED;")
    main = replace_once(main, r'''    printf("SWCOMPAT_IPD_APPLY_SCHEMA=1\n");''',
        r'''    printf("SWCOMPAT_IPD_APPLY_SCHEMA=3\n");''')
    main = replace_once(main, r'''    printf("SWCOMPAT_IPD_DRYRUN_SCHEMA=1\n");''',
        r'''    printf("SWCOMPAT_IPD_APPLY_PHASE=%u\n", swcompat_write_phase);
    printf("SWCOMPAT_IPD_APPLY_WIN32=%08lX\n", (unsigned long)swcompat_write_error);
    printf("SWCOMPAT_IPD_APPLY_FILES=%u\n", swcompat_written_files);
    printf("SWCOMPAT_IPD_APPLY_DEFERRED=%u\n", swcompat_deferred_files);
    printf("SWCOMPAT_IPD_APPLY_KEYS=%u\n", swcompat_written_keys);
    printf("SWCOMPAT_IPD_APPLY_VALUES=%u\n", swcompat_written_values);
    printf("SWCOMPAT_IPD_APPLY_ASSEMBLIES=%u\n", swcompat_written_assemblies);
    printf("SWCOMPAT_IPD_DRYRUN_SCHEMA=1\n");''')
    return main


def enable_apply(main: str) -> str:
    main = replace_once(main, "static BOOL swcompat_package_local;",
                        "static BOOL swcompat_package_local;\nstatic BOOL swcompat_apply_requested;\nstatic BOOL swcompat_apply_started;\nstatic BOOL swcompat_apply_completed;")
    main = replace_once(main,
        "if (dryrun && swcompat_neutral && dependency->resource_prerequisite &&",
        "if ((dryrun || (swcompat_apply_requested && swcompat_apply_started)) &&\n            swcompat_neutral && dependency->resource_prerequisite &&")
    main = replace_once(main,
        "if (dryrun && swcompat_neutral && swcompat_package_local &&",
        "if ((dryrun || (swcompat_apply_requested && swcompat_apply_started)) &&\n            swcompat_neutral && swcompat_package_local &&")
    main = replace_once(main,
        "            if (!install_assembly(manifest_list, &alternate, TRUE)) return FALSE;",
        "            if (!install_assembly(manifest_list, &alternate, dryrun)) return FALSE;")
    main = replace_once(main,
        "                swcompat_neutral = swcompat_package_local = FALSE;\n            }\n        }\n        goto done;",
        r'''                swcompat_neutral = swcompat_package_local = FALSE;
                if (swcompat_apply_requested && swcompat_counts[26] &&
                    swcompat_ipd_count == 1 && swcompat_counts[16] == 1410 &&
                    swcompat_counts[17] == 1 && swcompat_counts[18] == 141 &&
                    swcompat_counts[19] == 0 && swcompat_counts[23] == 1 &&
                    swcompat_counts[20] == 141 && !swcompat_counts[12] &&
                    !swcompat_counts[13] && !swcompat_counts[6] &&
                    !swcompat_counts[9] && !swcompat_counts[14])
                {
                    /* Strict CBS acceptance is still false. The following
                     * is an explicitly requested experimental transaction
                     * on an independently guarded disposable prefix. */
                    swcompat_apply_started = TRUE;
                    set_assembly_status(&state->assemblies, ASSEMBLY_STATUS_NONE);
                    swcompat_neutral = swcompat_package_local = TRUE;
                    swcompat_counts[20] = swcompat_counts[23] = 0;
                    swcompat_apply_completed = install_updates(state, FALSE) &&
                        swcompat_counts[20] == 141 && swcompat_counts[23] == 1;
                    swcompat_neutral = swcompat_package_local = FALSE;
                }
            }
        }
        goto done;''')
    main = replace_once(main,
        "    if (argc != 3 || !is_directory(argv[2])) return 2;",
        r'''    if (argc != 4 || wcscmp(argv[3], L"--experimental-apply") ||
        !is_directory(argv[2])) return 2;
    swcompat_apply_requested = TRUE;''')
    main = replace_once(main,
        '    printf("SWCOMPAT_IPD_DRYRUN_SCHEMA=1\\n");',
        r'''    printf("SWCOMPAT_IPD_APPLY_SCHEMA=1\n");
    printf("SWCOMPAT_IPD_APPLY_STARTED=%u\n", (unsigned)swcompat_apply_started);
    printf("SWCOMPAT_IPD_APPLY_COMPLETED=%u\n", (unsigned)swcompat_apply_completed);
    printf("SWCOMPAT_IPD_DRYRUN_SCHEMA=1\n");''')
    main = replace_once(main, "    return passed ? 0 : 1;",
                        "    return swcompat_apply_completed ? 0 : 1;")
    return instrument_writes(main)


def build(source: Path, destination: Path) -> None:
    prepare(source, destination)
    main = destination / "main.c"
    main.write_text(enable_apply(main.read_text(encoding="utf-8")), encoding="utf-8")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    a = p.parse_args()
    build(a.source, a.destination)
