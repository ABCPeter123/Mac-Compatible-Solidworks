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
    return main


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
