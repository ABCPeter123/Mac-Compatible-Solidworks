# CI policy: authenticated servicing and native package reconstruction

## Code-only regression jobs

Every pull request and push to `main` runs [Compatibility foundation](../.github/workflows/compatibility-ci.yml), including the cross-platform Python safety tests, independent Windows build probes, Apple Metal tests, and the .NET Framework compatibility classifiers. Specialized contract workflows, including [signed 4.8 MSI source contract](../.github/workflows/netfx48-signed-msi-contract-ci.yml), run only for their scoped source changes.

These code-only jobs cannot demonstrate a completed Microsoft installer or working SOLIDWORKS. A green infrastructure workflow is not proof of installation.

## Authenticated installer jobs

The reusable [original .NET 4.0 / 4.8 servicing workflow](../.github/workflows/netfx40-legacy-ci.yml) is `workflow_dispatch` and `workflow_call` gated. The single current, main-only, **self-path-triggered** authentic x64 .NET 4.8 test is [Wiage NGen preflight and signed MSI/MSP](../.github/workflows/netfx48-wiage-ngen-progress-msi-once-ci.yml). It calls the same reusable workflow with pinned Wine, macOS 26, Microsoft media authentication, genuine original x64/x86 NGen preflight, bounded progress-gated retry, unmodified vendor signed MSI/MSP, and independent full Win32 MSP exit capture.

The [fresh-prefix .NET 4.8.1 trial](../.github/workflows/netfx481-wine-ci.yml) and original Microsoft setup variants remain separately gated. A separately measured partial-4.8 recovery may attempt original 4.8.1 but cannot claim complete 4.8. The independent [catalog WUSA arm](../.github/workflows/netfx481-catalog-wusa-ci.yml) failed with Win32 exit 1; the original CAB inventory confirms an IPD CIX package. Do not rerun the same servicing experiments without a new hypothesis.

The one-shot workflow only starts when its own file changes on `main`. Updating a README, an ordinary script, a Python unit test, or the reusable CI workflow does not restart that authenticated test. Changes to the one-shot caller must be deliberate. GitHub's runner queue can delay the test. Never infer installation from a queued/cancelled run.

## Retired experiments

Historical self-triggered Winetricks, direct-4.8 bootstrapper, NGen drain and service-discovery variants were replaced by the current authenticated signed-MSI/MSP path. Seventeen superseded one-shot workflow files were removed in [PR #252](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/252) (nine orphaned callers) and [PR #254](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/254) (eight historical signed-MSI callers). Their old filename-only assertions were replaced by contract tests of the active authenticated signed MSI/MSP workflow and its reusable safety gates. Past source, runs, and evidence remain in Git history and GitHub Actions. Keep actively referenced tests, protocols, SOLIDWORKS bootstrap/GUI checks, and independently verified Windows binaries.

Seven more superseded callers (three original WoW64 fault/host-stack comparisons and four Winetricks baseline, settle, native40 reuse and complete-verb callers) are retired. Their reusable experimental switches, actual probe implementations and safety regression coverage remain. This brings the cumulative retired one-shot count to 24.

Routine foundation PR artifacts now expire after 3 days instead of 14; main and manually requested evidence retain existing retention. The existing run-report workflow can prune superseded generated foundation PR artifacts older than three days, protecting the newest completed and successful run per branch and leaving all installer artifacts, main evidence, run records and logs untouched. It only runs this cleanup on a main push to its own file or explicit manual main dispatch, never from a workflow_run event.

Before scheduling another expensive signed Microsoft installer test, identify the new hypothesis and check [Issue #115](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/115) and the [roadmap](ROADMAP.md). Prioritize full original MSP Windows Installer failure evidence, then genuine .NET 4.8.1, then licensed SOLIDWORKS testing.
