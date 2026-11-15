# CI policy: one active compatibility path

Every pull request and push to `main` runs [Compatibility foundation](../.github/workflows/compatibility-ci.yml). This includes all Python regression tests, including the native .NET 4.0, 4.8.1 prerequisite classifier, and CBS parser safety tests.

The signed, multi-minute Microsoft installer experiments are **manual-only**:
- [Original .NET 4.0 and authenticated 4.8.1 upgrade](../.github/workflows/netfx40-legacy-ci.yml)
- [Genuine .NET 4.8.1 fresh-prefix baseline](../.github/workflows/netfx481-wine-ci.yml)

Run a new signed-installer experiment only after changing one targeted hypothesis or validating a previously unseen defect. Do not rerun the same installation for documentation, parser changes, or cosmetic CI updates. Distinguish test infrastructure success from successful framework installation.

The one-off Python-only CI workflows for prerequisite OS bands and CBS preflight were removed because universal unit testing already covers them. The production servicing inventory still imports and tests the actual CBS operation preflight parser. Other specialized workflows continue to use their own narrow path filters or manual dispatch. They are not prerequisites for the current .NET investigation.

**Priority:** independently verified Microsoft .NET 4.0 execution and restart persistence, then resolve authentic .NET 4.8.1 return code 5100 using installer-observed prerequisites and servicing evidence. See [Roadmap](ROADMAP.md) and [Issue #115](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/115).

Keep old successful evidence in GitHub Actions and PR history. Historical results do not need repeated validation unless the affected runtime changes.
