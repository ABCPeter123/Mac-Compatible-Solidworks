# Scoped CI checks

The universal **Compatibility foundation** workflow runs on every pull request and every push to `main`. It covers Python unit tests and the primary macOS hardware/portability probes.

Specialized workflows now use **the same source-file path filters for pull requests and pushes**. A change to the MSVC probe, for example, triggers the MSVC runtime workflow but does not automatically rerun expensive COM, Windows Installer, or x86 compatibility jobs.

The specialized workflow's own YAML file is included in its filter, so changes to its CI definition still trigger verification.

This reduces duplicate Apple Silicon CI jobs, queued runners, and artifacts. It does **not** waive the universal compatibility checks. Any specialized workflow can still be started manually with `workflow_dispatch`. Direct pushes to `main` run relevant specialized workflows based on the paths changed.

The Service Control Manager experiment in [PR #14](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/14) remains separate and unfinished. These workflow filters do not change its experimental compatibility results.
